//! The BCJ2 encoder: x86 code split into four streams, as 7-Zip's `Bcj2Enc` splits it.
//!
//! The main stream keeps every byte except the four-byte operands of the calls and jumps that
//! are converted; those operands go to the call stream (`E8`) or the jump stream (`E9` and the
//! `0F 8x` conditional jumps) as absolute addresses in big-endian order; and a range-coded bit
//! per opcode says whether its operand was converted. The decoder in `lzma-rust2` reads the
//! four streams back; this encoder mirrors its scanning exactly, so an opcode it would see (an
//! `E8` or `E9` byte, or an `8x` byte after `0F`, wherever it lies, operand bytes of an
//! unconverted branch included) gets a bit here too.

use std::io::Write;

const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

/// The range coder of the decision stream, LZMA's.
struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    fn encode_bit(&mut self, prob: &mut u16, bit: bool) {
        let bound = (self.range >> NUM_MODEL_BITS) * u32::from(*prob);
        if bit {
            self.low += u64::from(bound);
            self.range -= bound;
            *prob -= *prob >> NUM_MOVE_BITS;
        } else {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - u32::from(*prob)) >> NUM_MOVE_BITS) as u16;
        }
        while self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

/// The three byte streams an encoder writes into, and the decision stream it keeps until the
/// end (it is small: a bit per branch opcode).
pub struct Bcj2Streams<'a> {
    pub main: &'a mut dyn Write,
    pub call: &'a mut dyn Write,
    pub jump: &'a mut dyn Write,
}

/// Splits x86 code into BCJ2's streams. Feed it with [`Bcj2Encoder::write`], then take the
/// decision stream with [`Bcj2Encoder::finish`].
pub struct Bcj2Encoder {
    rc: RangeEncoder,
    probs: [u16; 2 + 256],
    /// Bytes of the input consumed so far: the position the decoder computes addresses from.
    ip: u32,
    /// The input byte before the next one to scan.
    prev: u8,
    /// Input held back: a branch opcode whose operand has not fully arrived.
    pending: Vec<u8>,
    /// A branch is converted when its relative target is within this many bytes either way.
    relative_limit: u32,
}

impl Default for Bcj2Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcj2Encoder {
    /// An encoder with 7-Zip's default relative limit, 64 MiB.
    pub fn new() -> Self {
        Self {
            rc: RangeEncoder::new(),
            probs: [(BIT_MODEL_TOTAL >> 1) as u16; 2 + 256],
            ip: 0,
            prev: 0,
            pending: Vec::with_capacity(8),
            relative_limit: 1 << 26,
        }
    }

    /// Encodes `data`, writing to the main, call and jump streams.
    pub fn write(&mut self, data: &[u8], streams: &mut Bcj2Streams<'_>) -> std::io::Result<()> {
        if self.pending.is_empty() {
            let rest = self.scan(data, streams, false)?;
            self.pending.extend_from_slice(rest);
        } else {
            let mut buffer = std::mem::take(&mut self.pending);
            buffer.extend_from_slice(data);
            let rest = self.scan(&buffer, streams, false)?;
            self.pending = rest.to_vec();
        }
        Ok(())
    }

    /// Encodes what was held back, and returns the decision stream.
    pub fn finish(mut self, streams: &mut Bcj2Streams<'_>) -> std::io::Result<Vec<u8>> {
        let pending = std::mem::take(&mut self.pending);
        let rest = self.scan(&pending, streams, true)?;
        debug_assert!(rest.is_empty());
        Ok(self.rc.finish())
    }

    /// Scans `data`, encoding every complete decision; returns the tail that needs more input
    /// (an opcode with fewer than four bytes after it), which `finishing` encodes as unconverted.
    fn scan<'d>(
        &mut self,
        data: &'d [u8],
        streams: &mut Bcj2Streams<'_>,
        finishing: bool,
    ) -> std::io::Result<&'d [u8]> {
        let mut i = 0;
        let mut plain_from = 0;
        while i < data.len() {
            let b = data[i];
            let is_branch = (b & 0xFE) == 0xE8 || (self.prev == 0x0F && (b & 0xF0) == 0x80);
            if !is_branch {
                self.prev = b;
                self.ip = self.ip.wrapping_add(1);
                i += 1;
                continue;
            }
            let Some(operand) = data.get(i + 1..i + 5) else {
                if !finishing {
                    // Flush the plain bytes before the opcode; hold the rest back.
                    streams.main.write_all(&data[plain_from..i])?;
                    return Ok(&data[i..]);
                }
                // Too close to the end to carry an operand: kept as it is.
                self.encode_decision(b, false);
                self.prev = b;
                self.ip = self.ip.wrapping_add(1);
                i += 1;
                continue;
            };
            let relative = u32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]);
            // The address the decoder rebuilds: relative to the byte after the operand.
            let absolute = relative.wrapping_add(self.ip.wrapping_add(5));
            let convert = relative.wrapping_add(self.relative_limit) < self.relative_limit << 1;
            self.encode_decision(b, convert);
            if convert {
                // The opcode stays in the main stream; the operand goes to its own.
                streams.main.write_all(&data[plain_from..=i])?;
                let target = if b == 0xE8 {
                    &mut *streams.call
                } else {
                    &mut *streams.jump
                };
                target.write_all(&absolute.to_be_bytes())?;
                self.prev = operand[3];
                self.ip = self.ip.wrapping_add(5);
                i += 5;
                plain_from = i;
            } else {
                self.prev = b;
                self.ip = self.ip.wrapping_add(1);
                i += 1;
            }
        }
        streams.main.write_all(&data[plain_from..])?;
        Ok(&[])
    }

    /// The decision for the opcode `b`, in the context the decoder uses: the previous byte for
    /// a call, one context for every jump, another for every conditional jump.
    fn encode_decision(&mut self, b: u8, convert: bool) {
        let index = if b == 0xE8 {
            2 + usize::from(self.prev)
        } else if b == 0xE9 {
            1
        } else {
            0
        };
        self.rc.encode_bit(&mut self.probs[index], convert);
    }
}

#[cfg(test)]
mod tests {
    use lzma_rust2::filter::bcj2::Bcj2Reader;

    use super::*;

    fn round_trip(data: &[u8], chunk: usize) {
        let mut main = Vec::new();
        let mut call = Vec::new();
        let mut jump = Vec::new();
        let mut encoder = Bcj2Encoder::new();
        for piece in data.chunks(chunk.max(1)) {
            let mut streams = Bcj2Streams {
                main: &mut main,
                call: &mut call,
                jump: &mut jump,
            };
            encoder.write(piece, &mut streams).unwrap();
        }
        let mut streams = Bcj2Streams {
            main: &mut main,
            call: &mut call,
            jump: &mut jump,
        };
        let rc = encoder.finish(&mut streams).unwrap();
        let inputs: Vec<std::io::Cursor<Vec<u8>>> = vec![
            std::io::Cursor::new(main),
            std::io::Cursor::new(call),
            std::io::Cursor::new(jump),
            std::io::Cursor::new(rc),
        ];
        let mut reader = Bcj2Reader::new(inputs, data.len() as u64);
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut decoded).unwrap();
        assert_eq!(decoded, data, "chunk size {chunk}");
    }

    /// Code with calls and jumps in it, near and far, opcodes inside operands, and branches
    /// cut off by the end.
    fn code() -> Vec<u8> {
        let mut v = Vec::new();
        let mut x: u32 = 0x1234_5678;
        for i in 0..40_000u32 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            match i % 23 {
                0 => {
                    v.push(0xE8);
                    v.extend_from_slice(&(i.wrapping_mul(37) % 5000).to_le_bytes());
                }
                5 => {
                    v.push(0xE9);
                    v.extend_from_slice(&0xFFFF_FF00u32.wrapping_sub(i).to_le_bytes());
                }
                9 => {
                    v.push(0x0F);
                    v.push(0x84);
                    v.extend_from_slice(&(i % 300).to_le_bytes());
                }
                13 => {
                    v.push(0xE8);
                    v.extend_from_slice(&x.to_le_bytes());
                }
                17 => {
                    v.push(0xE8);
                    v.push(0xE8);
                    v.push(0x0F);
                    v.push(0x85);
                }
                _ => v.push((x >> 24) as u8),
            }
        }
        v.push(0xE8);
        v.push(0x01);
        v
    }

    #[test]
    fn the_decoder_reads_back_what_the_encoder_split() {
        let data = code();
        for chunk in [usize::MAX, 4096, 100, 7, 1] {
            round_trip(&data, chunk);
        }
        round_trip(&[], 16);
        round_trip(&[0xE8], 16);
        round_trip(&[0x0F, 0x80, 1, 2], 16);
        round_trip(b"plain text with no branches at all", 5);
    }

    #[test]
    fn calls_go_to_the_call_stream_as_absolute_addresses() {
        let mut data = vec![0x90u8; 16];
        data.push(0xE8);
        data.extend_from_slice(&100u32.to_le_bytes());
        let mut main = Vec::new();
        let mut call = Vec::new();
        let mut jump = Vec::new();
        let mut encoder = Bcj2Encoder::new();
        let mut streams = Bcj2Streams {
            main: &mut main,
            call: &mut call,
            jump: &mut jump,
        };
        encoder.write(&data, &mut streams).unwrap();
        let _ = encoder.finish(&mut streams).unwrap();
        // The opcode at 16, the operand relative to 21: absolute 121.
        assert_eq!(call, 121u32.to_be_bytes());
        assert!(jump.is_empty());
        assert_eq!(main.len(), 17);
    }
}
