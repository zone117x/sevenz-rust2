use std::{io::Write, sync::Arc};

use super::*;
use crate::EncoderConfiguration;
#[derive(Debug, Clone, Default)]
pub(crate) struct UnpackInfo {
    pub(crate) blocks: Vec<BlockInfo>,
}

impl UnpackInfo {
    pub(crate) fn add(
        &mut self,
        methods: Arc<Vec<EncoderConfiguration>>,
        sizes: Vec<u64>,
        crc: u32,
    ) {
        self.blocks.push(BlockInfo {
            folder: Folder::Chain(methods),
            sizes,
            crc,
            num_sub_unpack_streams: 1,
            ..Default::default()
        })
    }

    pub(crate) fn add_multiple(
        &mut self,
        folder: Folder,
        sizes: Vec<u64>,
        crc: u32,
        num_sub_unpack_streams: u64,
        sub_stream_sizes: Vec<u64>,
        sub_stream_crcs: Vec<u32>,
    ) {
        self.blocks.push(BlockInfo {
            folder,
            sizes,
            crc,
            num_sub_unpack_streams,
            sub_stream_crcs,
            sub_stream_sizes,
        })
    }

    pub(crate) fn write_to<H: Write>(&mut self, header: &mut H) -> std::io::Result<()> {
        header.write_u8(K_UNPACK_INFO)?;
        header.write_u8(K_FOLDER)?;
        write_u64(header, self.blocks.len() as u64)?;
        header.write_u8(0)?;
        let mut cache = Vec::with_capacity(32);
        for block in self.blocks.iter() {
            block.write_to(header, &mut cache)?;
        }
        header.write_u8(K_CODERS_UNPACK_SIZE)?;
        for block in self.blocks.iter() {
            for size in block.sizes.iter().copied() {
                write_u64(header, size)?;
            }
        }
        // 7zip doesn't write CRC values in the folder section of the unpack info. Instead,
        // it writes it only in the substreams info (even for non-solid archives).
        header.write_u8(K_END)?;
        Ok(())
    }

    pub(crate) fn write_substreams<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        header.write_u8(K_SUB_STREAMS_INFO)?;

        // Only write K_NUM_UNPACK_STREAM if any folder has != 1 substream.
        let needs_num_unpack_stream = self.blocks.iter().any(|f| f.num_sub_unpack_streams != 1);

        if needs_num_unpack_stream {
            header.write_u8(K_NUM_UNPACK_STREAM)?;
            for f in &self.blocks {
                write_u64(header, f.num_sub_unpack_streams)?;
            }
        }

        // Only write K_SIZE if there are folders with > 1 substream.
        let needs_sizes = self.blocks.iter().any(|f| f.sub_stream_sizes.len() > 1);

        if needs_sizes {
            header.write_u8(K_SIZE)?;
            for f in &self.blocks {
                if f.sub_stream_sizes.len() > 1 {
                    debug_assert_eq!(f.sub_stream_sizes.len(), f.num_sub_unpack_streams as usize);

                    // Write N-1 sizes (last size is calculated).
                    for i in 0..f.sub_stream_sizes.len() - 1 {
                        let size = f.sub_stream_sizes[i];
                        write_u64(header, size)?;
                    }
                }
            }
        }

        // We always write the CRC values in the substreams info.
        let mut crcs_to_write = Vec::new();
        for f in &self.blocks {
            if f.num_sub_unpack_streams > 1 {
                // Multiple substreams - write all CRCs.
                for &crc in &f.sub_stream_crcs {
                    crcs_to_write.push(crc);
                }
            } else if f.num_sub_unpack_streams == 1 {
                // Single substream - write CRC here and not in the folder section.
                match f.sub_stream_crcs.first() {
                    None => {
                        crcs_to_write.push(f.crc);
                    }
                    Some(crc) => {
                        crcs_to_write.push(*crc);
                    }
                };
            }
        }

        if !crcs_to_write.is_empty() {
            header.write_u8(K_CRC)?;
            header.write_u8(1)?; // all CRCs defined.
            for crc in crcs_to_write {
                header.write_u32(crc)?;
            }
        }

        header.write_u8(K_END)?;
        Ok(())
    }
}

/// One coder of a folder that is a graph rather than a chain: its method id and properties,
/// and the number of streams it takes (four for BCJ2, one for everything else).
#[derive(Debug, Clone)]
pub(crate) struct GraphCoder {
    pub(crate) id: Vec<u8>,
    pub(crate) properties: Vec<u8>,
    pub(crate) num_in_streams: u64,
}

/// How a folder's coders are wired: a chain, where each coder feeds the next and one packed
/// stream enters at the first, or a graph with its bind pairs and packed streams spelled out.
#[derive(Debug, Clone)]
pub(crate) enum Folder {
    Chain(Arc<Vec<EncoderConfiguration>>),
    Graph {
        coders: Vec<GraphCoder>,
        /// (input stream index, output stream index) pairs.
        bind_pairs: Vec<(u64, u64)>,
        /// The input stream indices fed by packed streams, in the order the streams are written.
        packed_streams: Vec<u64>,
    },
}

impl Default for Folder {
    fn default() -> Self {
        Self::Chain(Arc::new(Vec::new()))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockInfo {
    pub(crate) folder: Folder,
    pub(crate) sizes: Vec<u64>,
    pub(crate) crc: u32,
    pub(crate) num_sub_unpack_streams: u64,
    pub(crate) sub_stream_sizes: Vec<u64>,
    pub(crate) sub_stream_crcs: Vec<u32>,
}

impl BlockInfo {
    pub(crate) fn write_to<W: Write>(
        &self,
        header: &mut W,
        cache: &mut Vec<u8>,
    ) -> std::io::Result<()> {
        cache.clear();
        match &self.folder {
            Folder::Chain(methods) => {
                let mut num_coders = 0;
                for mc in methods.iter() {
                    num_coders += 1;
                    Self::write_single_codec(mc, cache)?;
                }
                write_u64(header, num_coders as u64)?;
                header.write_all(cache)?;
                for i in 0..num_coders - 1 {
                    write_u64(header, i as u64 + 1)?;
                    write_u64(header, i as u64)?;
                }
            }
            Folder::Graph {
                coders,
                bind_pairs,
                packed_streams,
            } => {
                write_u64(header, coders.len() as u64)?;
                for coder in coders {
                    let mut flags = coder.id.len() as u8;
                    if coder.num_in_streams != 1 {
                        flags |= 0x10;
                    }
                    if !coder.properties.is_empty() {
                        flags |= 0x20;
                    }
                    header.write_u8(flags)?;
                    header.write_all(&coder.id)?;
                    if coder.num_in_streams != 1 {
                        write_u64(header, coder.num_in_streams)?;
                        write_u64(header, 1)?;
                    }
                    if !coder.properties.is_empty() {
                        write_u64(header, coder.properties.len() as u64)?;
                        header.write_all(&coder.properties)?;
                    }
                }
                for (in_index, out_index) in bind_pairs {
                    write_u64(header, *in_index)?;
                    write_u64(header, *out_index)?;
                }
                if packed_streams.len() > 1 {
                    for index in packed_streams {
                        write_u64(header, *index)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn write_single_codec<H: Write>(mc: &EncoderConfiguration, out: &mut H) -> std::io::Result<()> {
        let id = mc.method.id();
        let mut temp = [0u8; 256];
        let props = encoder::get_options_as_properties(mc.method, mc.options.as_ref(), &mut temp);
        let mut codec_flags = id.len() as u8;
        if !props.is_empty() {
            codec_flags |= 0x20;
        }
        out.write_u8(codec_flags)?;
        out.write_all(id)?;
        if !props.is_empty() {
            out.write_u8(props.len() as u8)?;
            out.write_all(props)?;
        }
        Ok(())
    }
}
