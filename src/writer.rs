mod counting_writer;
#[cfg(all(feature = "util", not(target_arch = "wasm32")))]
mod lazy_file_reader;
mod pack_info;
mod seq_reader;
mod source_reader;
mod unpack_info;

use std::{
    cell::Cell,
    io::{Read, Seek, Write},
    rc::Rc,
    sync::Arc,
};
#[cfg(not(target_arch = "wasm32"))]
use std::{fs::File, path::Path};

pub(crate) use counting_writer::CountingWriter;
use crc32fast::Hasher;

#[cfg(all(feature = "util", not(target_arch = "wasm32")))]
pub(crate) use self::lazy_file_reader::LazyFileReader;
pub(crate) use self::seq_reader::SeqReader;
pub use self::source_reader::SourceReader;
use self::{
    pack_info::PackInfo,
    unpack_info::{Folder, GraphCoder, UnpackInfo},
};
#[cfg(feature = "aes256")]
use crate::encoder_options::AesEncoderOptions;
use crate::{
    ArchiveEntry, AutoFinish, AutoFinisher, ByteWriter, Error, Password,
    archive::*,
    bitset::{BitSet, write_bit_set},
    codec, encoder,
};

macro_rules! write_times {
    //write_i64
    ($fn_name:tt, $nid:expr, $has_time:tt, $time:tt) => {
        write_times!($fn_name, $nid, $has_time, $time, write_u64);
    };
    ($fn_name:tt, $nid:expr, $has_time:tt, $time:tt, $write_fn:tt) => {
        fn $fn_name<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
            let mut num = 0;
            for entry in self.files.iter() {
                if entry.$has_time {
                    num += 1;
                }
            }
            if num > 0 {
                header.write_u8($nid)?;
                let mut temp: Vec<u8> = Vec::with_capacity(128);
                let mut out = &mut temp;
                if num != self.files.len() {
                    out.write_u8(0)?;
                    let mut times = BitSet::with_capacity(self.files.len());
                    for i in 0..self.files.len() {
                        if self.files[i].$has_time {
                            times.insert(i);
                        }
                    }
                    write_bit_set(&mut out, &times)?;
                } else {
                    out.write_u8(1)?;
                }
                out.write_u8(0)?;
                for file in self.files.iter() {
                    if file.$has_time {
                        out.$write_fn((file.$time).into())?;
                    }
                }
                out.flush()?;
                write_u64(header, temp.len() as u64)?;
                header.write_all(&temp)?;
            }
            Ok(())
        }
    };
}

type Result<T> = std::result::Result<T, Error>;

/// Writes a 7z archive file.
pub struct ArchiveWriter<W: Write> {
    output: W,
    files: Vec<ArchiveEntry>,
    content_methods: Arc<Vec<EncoderConfiguration>>,
    pack_info: PackInfo,
    unpack_info: UnpackInfo,
    encrypt_header: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl ArchiveWriter<File> {
    /// Creates a file to write a 7z archive to.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::create(path.as_ref())
            .map_err(|e| Error::file_open(e, path.as_ref().to_string_lossy().to_string()))?;
        Self::new(file)
    }
}

/// Names of the entries in a block, for an error message. Truncated at ~512 bytes, since a solid
/// block can hold many thousands.
fn entries_names(entries: &[ArchiveEntry]) -> String {
    let mut names = String::with_capacity(512);
    for ele in entries.iter() {
        names.push_str(&ele.name);
        names.push(';');
        if names.len() > 512 {
            break;
        }
    }
    names
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Prepares writer to write a 7z archive to.
    pub fn new(mut writer: W) -> Result<Self> {
        writer.seek(std::io::SeekFrom::Start(SIGNATURE_HEADER_SIZE))?;

        Ok(Self {
            output: writer,
            files: Default::default(),
            content_methods: Arc::new(vec![EncoderConfiguration::new(EncoderMethod::LZMA2)]),
            pack_info: Default::default(),
            unpack_info: Default::default(),
            encrypt_header: true,
        })
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Sets the default compression methods to use for entry data. Default is LZMA2.
    pub fn set_content_methods(&mut self, content_methods: Vec<EncoderConfiguration>) -> &mut Self {
        if content_methods.is_empty() {
            return self;
        }
        self.content_methods = Arc::new(content_methods);
        self
    }

    /// Whether to enable the encryption of the -header. Default is `true`.
    pub fn set_encrypt_header(&mut self, enabled: bool) {
        self.encrypt_header = enabled;
    }

    /// Non-solid compression - Adds an archive `entry` with data from `reader`.
    ///
    /// # Example
    /// ```no_run
    /// use std::{fs::File, path::Path};
    ///
    /// use sevenz_rust2::*;
    /// let mut sz = ArchiveWriter::create("path/to/dest.7z").expect("create writer ok");
    /// let src = Path::new("path/to/source.txt");
    /// let name = "source.txt".to_string();
    /// let entry = sz
    ///     .push_archive_entry(
    ///         ArchiveEntry::from_path(&src, name),
    ///         Some(File::open(src).unwrap()),
    ///     )
    ///     .expect("ok");
    /// let compressed_size = entry.compressed_size;
    /// sz.finish().expect("done");
    /// ```
    pub fn push_archive_entry<R: Read>(
        &mut self,
        mut entry: ArchiveEntry,
        reader: Option<R>,
    ) -> Result<&ArchiveEntry> {
        if !entry.is_directory
            && let Some(mut r) = reader
        {
            let mut compressed_len = 0;
            let mut compressed = CompressWrapWriter::new(&mut self.output, &mut compressed_len);

            let mut more_sizes: Vec<Rc<Cell<usize>>> =
                Vec::with_capacity(self.content_methods.len() - 1);

            let (crc, size) = {
                let mut w =
                    Self::create_writer(&self.content_methods, &mut compressed, &mut more_sizes)?;
                let mut write_len = 0;
                let mut w = CompressWrapWriter::new(&mut w, &mut write_len);
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf) {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                            w.write_all(&buf[..n]).map_err(|e| {
                                Error::io_msg(e, format!("Encode entry:{}", entry.name()))
                            })?;
                        }
                        Err(e) => {
                            return Err(Error::io_msg(e, format!("Encode entry:{}", entry.name())));
                        }
                    }
                }
                w.flush()
                    .map_err(|e| Error::io_msg(e, format!("Encode entry:{}", entry.name())))?;
                w.write(&[])
                    .map_err(|e| Error::io_msg(e, format!("Encode entry:{}", entry.name())))?;

                (w.crc_value(), write_len)
            };
            let compressed_crc = compressed.crc_value();
            entry.has_stream = true;
            entry.size = size as u64;
            entry.crc = crc as u64;
            entry.has_crc = true;
            entry.compressed_crc = compressed_crc as u64;
            entry.compressed_size = compressed_len as u64;
            self.pack_info
                .add_stream(compressed_len as u64, compressed_crc);

            let mut sizes = Vec::with_capacity(more_sizes.len() + 1);
            sizes.extend(more_sizes.iter().map(|s| s.get() as u64));
            sizes.push(size as u64);

            self.unpack_info
                .add(self.content_methods.clone(), sizes, crc);

            self.files.push(entry);
            return Ok(self.files.last().unwrap());
        }
        entry.has_stream = false;
        entry.size = 0;
        entry.compressed_size = 0;
        entry.has_crc = false;
        self.files.push(entry);
        Ok(self.files.last().unwrap())
    }

    /// Append a block compressed elsewhere by [`prepare_block`].
    ///
    /// Only the parts that must happen in output order: write the bytes, record the pack and block
    /// metadata, take the entries. Everything expensive already happened on whatever thread built
    /// the [`PreparedBlock`].
    ///
    /// A block holding no entries is dropped rather than written, so an empty batch does not put a
    /// junk pack stream and a zero-substream block into the archive.
    pub fn push_prepared_block(&mut self, block: PreparedBlock) -> Result<&mut Self> {
        if block.is_empty() {
            return Ok(self);
        }

        let PreparedBlock {
            packed,
            entries,
            folder,
            sizes,
            crc,
            sub_stream_sizes,
            sub_stream_crcs,
        } = block;

        for (compressed, compressed_crc) in packed {
            self.output
                .write_all(&compressed)
                .map_err(|e| Error::io_msg(e, "push_prepared_block: write".to_string()))?;
            self.pack_info
                .add_stream(compressed.len() as u64, compressed_crc);
        }
        self.unpack_info.add_multiple(
            folder,
            sizes,
            crc,
            entries.len() as u64,
            sub_stream_sizes,
            sub_stream_crcs,
        );
        self.files.extend(entries);
        Ok(self)
    }

    /// Solid compression - packs `entries` into one pack.
    ///
    /// # Panics
    /// * If `entries`'s length not equals to `reader.reader_len()`
    pub fn push_archive_entries<R: Read>(
        &mut self,
        entries: Vec<ArchiveEntry>,
        reader: Vec<SourceReader<R>>,
    ) -> Result<&mut Self> {
        let mut entries = entries;
        let mut r = SeqReader::new(reader);
        assert_eq!(r.reader_len(), entries.len());
        let mut compressed_len = 0;
        let mut compressed = CompressWrapWriter::new(&mut self.output, &mut compressed_len);
        let content_methods = &self.content_methods;
        let mut more_sizes: Vec<Rc<Cell<usize>>> = Vec::with_capacity(content_methods.len() - 1);

        let (crc, size) = {
            let mut w = Self::create_writer(content_methods, &mut compressed, &mut more_sizes)?;
            let mut write_len = 0;
            let mut w = CompressWrapWriter::new(&mut w, &mut write_len);
            let mut buf = [0u8; 4096];

            loop {
                match r.read(&mut buf) {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        w.write_all(&buf[..n]).map_err(|e| {
                            Error::io_msg(e, format!("Encode entries:{}", entries_names(&entries)))
                        })?;
                    }
                    Err(e) => {
                        return Err(Error::io_msg(
                            e,
                            format!("Encode entries:{}", entries_names(&entries)),
                        ));
                    }
                }
            }
            w.flush().map_err(|e| {
                let mut names = String::with_capacity(512);
                for ele in entries.iter() {
                    names.push_str(&ele.name);
                    names.push(';');
                    if names.len() > 512 {
                        break;
                    }
                }
                Error::io_msg(e, format!("Encode entry:{names}"))
            })?;
            w.write(&[]).map_err(|e| {
                Error::io_msg(e, format!("Encode entry:{}", entries_names(&entries)))
            })?;

            (w.crc_value(), write_len)
        };
        let compressed_crc = compressed.crc_value();
        let mut sub_stream_crcs = Vec::with_capacity(entries.len());
        let mut sub_stream_sizes = Vec::with_capacity(entries.len());
        for i in 0..entries.len() {
            let entry = &mut entries[i];
            let ri = &r[i];
            entry.crc = ri.crc_value() as u64;
            entry.size = ri.read_count() as u64;
            sub_stream_crcs.push(entry.crc as u32);
            sub_stream_sizes.push(entry.size);
            entry.has_crc = true;
        }

        self.pack_info
            .add_stream(compressed_len as u64, compressed_crc);

        let mut sizes = Vec::with_capacity(more_sizes.len() + 1);
        sizes.extend(more_sizes.iter().map(|s| s.get() as u64));
        sizes.push(size as u64);

        self.unpack_info.add_multiple(
            Folder::Chain(content_methods.clone()),
            sizes,
            crc,
            entries.len() as u64,
            sub_stream_sizes,
            sub_stream_crcs,
        );

        self.files.extend(entries);
        Ok(self)
    }

    fn create_writer<'a, O: Write + 'a>(
        methods: &[EncoderConfiguration],
        out: O,
        more_sized: &mut Vec<Rc<Cell<usize>>>,
    ) -> Result<Box<dyn Write + 'a>> {
        let mut encoder: Box<dyn Write> = Box::new(out);
        let mut first = true;
        for mc in methods.iter() {
            if !first {
                let counting = CountingWriter::new(encoder);
                more_sized.push(counting.counting());
                encoder = Box::new(encoder::add_encoder(counting, mc)?);
            } else {
                let counting = CountingWriter::new(encoder);
                encoder = Box::new(encoder::add_encoder(counting, mc)?);
            }
            first = false;
        }
        Ok(encoder)
    }

    /// Finishes the compression.
    pub fn finish(mut self) -> std::io::Result<W> {
        let mut header: Vec<u8> = Vec::with_capacity(64 * 1024);
        self.write_encoded_header(&mut header)?;
        let header_pos = self.output.stream_position()?;
        self.output.write_all(&header)?;
        let crc32 = crc32fast::hash(&header);
        let mut hh = [0u8; SIGNATURE_HEADER_SIZE as usize];
        {
            let mut hhw = hh.as_mut_slice();
            //sig
            hhw.write_all(SEVEN_Z_SIGNATURE)?;
            //version
            hhw.write_u8(0)?;
            hhw.write_u8(4)?;
            //placeholder for crc: index = 8
            hhw.write_u32(0)?;

            // start header
            hhw.write_u64(header_pos - SIGNATURE_HEADER_SIZE)?;
            hhw.write_u64(0xFFFFFFFF & header.len() as u64)?;
            hhw.write_u32(crc32)?;
        }
        let crc32 = crc32fast::hash(&hh[12..]);
        hh[8..12].copy_from_slice(&crc32.to_le_bytes());

        self.output.seek(std::io::SeekFrom::Start(0))?;
        self.output.write_all(&hh)?;
        self.output.flush()?;
        Ok(self.output)
    }

    fn write_header<H: Write>(&mut self, header: &mut H) -> std::io::Result<()> {
        header.write_u8(K_HEADER)?;
        header.write_u8(K_MAIN_STREAMS_INFO)?;
        self.write_streams_info(header)?;
        self.write_files_info(header)?;
        header.write_u8(K_END)?;
        Ok(())
    }

    fn write_encoded_header<H: Write>(&mut self, header: &mut H) -> std::io::Result<()> {
        let mut raw_header = Vec::with_capacity(64 * 1024);
        self.write_header(&mut raw_header)?;
        let mut pack_info = PackInfo::default();

        let position = self.output.stream_position()?;
        let pos = position - SIGNATURE_HEADER_SIZE;
        pack_info.pos = pos;

        let mut more_sizes = vec![];
        let size = raw_header.len() as u64;
        let crc32 = crc32fast::hash(&raw_header);
        let mut methods = vec![];

        let mut must_encrypt_header = false;

        if self.encrypt_header {
            for conf in self.content_methods.iter() {
                if conf.method.id() == EncoderMethod::AES256_SHA256.id() {
                    methods.push(conf.clone());
                    must_encrypt_header = true;
                    break;
                }
            }
        }

        methods.push(EncoderConfiguration::new(EncoderMethod::LZMA));

        let methods = Arc::new(methods);

        let mut encoded_data = Vec::with_capacity(size as usize / 2);

        let mut compress_size = 0;
        let mut compressed = CompressWrapWriter::new(&mut encoded_data, &mut compress_size);
        {
            let mut encoder = Self::create_writer(&methods, &mut compressed, &mut more_sizes)
                .map_err(std::io::Error::other)?;
            encoder.write_all(&raw_header)?;
            encoder.flush()?;
            let _ = encoder.write(&[])?;
        }

        let compress_crc = compressed.crc_value();
        let compress_size = *compressed.bytes_written;

        if !must_encrypt_header && compress_size as u64 + 20 >= size {
            // We have an unencrypted header and the compression made increased the data size,
            // so we write the raw header data without compressing it to save space.
            header.write_all(&raw_header)?;
            return Ok(());
        }
        self.output.write_all(&encoded_data[..compress_size])?;

        pack_info.add_stream(compress_size as u64, compress_crc);

        let mut unpack_info = UnpackInfo::default();
        let mut sizes = Vec::with_capacity(1 + more_sizes.len());
        sizes.extend(more_sizes.iter().map(|s| s.get() as u64));
        sizes.push(size);
        unpack_info.add(methods, sizes, crc32);

        header.write_u8(K_ENCODED_HEADER)?;

        pack_info.write_to(header)?;
        unpack_info.write_to(header)?;
        unpack_info.write_substreams(header)?;

        header.write_u8(K_END)?;

        Ok(())
    }

    fn write_streams_info<H: Write>(&mut self, header: &mut H) -> std::io::Result<()> {
        if self.pack_info.len() > 0 {
            self.pack_info.write_to(header)?;
            self.unpack_info.write_to(header)?;
        }
        self.unpack_info.write_substreams(header)?;

        header.write_u8(K_END)?;
        Ok(())
    }

    fn write_files_info<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        header.write_u8(K_FILES_INFO)?;
        write_u64(header, self.files.len() as u64)?;
        self.write_file_empty_streams(header)?;
        self.write_file_empty_files(header)?;
        self.write_file_anti_items(header)?;
        self.write_file_names(header)?;
        self.write_file_ctimes(header)?;
        self.write_file_atimes(header)?;
        self.write_file_mtimes(header)?;
        self.write_file_windows_attrs(header)?;
        header.write_u8(K_END)?;
        Ok(())
    }

    fn write_file_empty_streams<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        let mut has_empty = false;
        for entry in self.files.iter() {
            if !entry.has_stream {
                has_empty = true;
                break;
            }
        }
        if has_empty {
            header.write_u8(K_EMPTY_STREAM)?;
            let mut bitset = BitSet::with_capacity(self.files.len());
            for (i, entry) in self.files.iter().enumerate() {
                if !entry.has_stream {
                    bitset.insert(i);
                }
            }
            let mut temp: Vec<u8> = Vec::with_capacity(bitset.len() / 8 + 1);
            write_bit_set(&mut temp, &bitset)?;
            write_u64(header, temp.len() as u64)?;
            header.write_all(temp.as_slice())?;
        }
        Ok(())
    }

    fn write_file_empty_files<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        let mut has_empty = false;
        let mut empty_stream_counter = 0;
        let mut bitset = BitSet::new();
        for entry in self.files.iter() {
            if !entry.has_stream {
                let is_dir = entry.is_directory();
                has_empty |= !is_dir;
                if !is_dir {
                    bitset.insert(empty_stream_counter);
                }
                empty_stream_counter += 1;
            }
        }
        if has_empty {
            header.write_u8(K_EMPTY_FILE)?;

            let mut temp: Vec<u8> = Vec::with_capacity(bitset.len() / 8 + 1);
            write_bit_set(&mut temp, &bitset)?;
            write_u64(header, temp.len() as u64)?;
            header.write_all(&temp)?;
        }
        Ok(())
    }

    fn write_file_anti_items<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        let mut has_anti = false;
        let mut counter = 0;
        let mut bitset = BitSet::new();
        for entry in self.files.iter() {
            if !entry.has_stream {
                let is_anti = entry.is_anti_item();
                has_anti |= is_anti;
                if is_anti {
                    bitset.insert(counter);
                }
                counter += 1;
            }
        }
        if has_anti {
            header.write_u8(K_ANTI)?;

            let mut temp: Vec<u8> = Vec::with_capacity(bitset.len() / 8 + 1);
            write_bit_set(&mut temp, &bitset)?;
            write_u64(header, temp.len() as u64)?;
            header.write_all(temp.as_slice())?;
        }
        Ok(())
    }

    fn write_file_names<H: Write>(&self, header: &mut H) -> std::io::Result<()> {
        header.write_u8(K_NAME)?;
        let mut temp: Vec<u8> = Vec::with_capacity(128);
        let out = &mut temp;
        out.write_u8(0)?;
        for file in self.files.iter() {
            for c in file.name().encode_utf16() {
                let buf = c.to_le_bytes();
                out.write_all(&buf)?;
            }
            out.write_all(&[0u8; 2])?;
        }
        write_u64(header, temp.len() as u64)?;
        header.write_all(temp.as_slice())?;
        Ok(())
    }

    write_times!(
        write_file_ctimes,
        K_C_TIME,
        has_creation_date,
        creation_date
    );
    write_times!(write_file_atimes, K_A_TIME, has_access_date, access_date);
    write_times!(
        write_file_mtimes,
        K_M_TIME,
        has_last_modified_date,
        last_modified_date
    );
    write_times!(
        write_file_windows_attrs,
        K_WIN_ATTRIBUTES,
        has_windows_attributes,
        windows_attributes,
        write_u32
    );
}

impl<W: Write + Seek> AutoFinish for ArchiveWriter<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}

pub(crate) fn write_u64<W: Write>(header: &mut W, mut value: u64) -> std::io::Result<()> {
    let mut first = 0;
    let mut mask = 0x80;
    let mut i = 0;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= value >> (8 * i);
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    header.write_u8((first & 0xFF) as u8)?;
    while i > 0 {
        header.write_u8((value & 0xFF) as u8)?;
        value >>= 8;
        i -= 1;
    }
    Ok(())
}

struct CompressWrapWriter<'a, W> {
    writer: W,
    crc: Hasher,
    cache: Vec<u8>,
    bytes_written: &'a mut usize,
}

impl<'a, W: Write> CompressWrapWriter<'a, W> {
    pub fn new(writer: W, bytes_written: &'a mut usize) -> Self {
        Self {
            writer,
            crc: Hasher::new(),
            cache: Vec::with_capacity(8192),
            bytes_written,
        }
    }

    pub fn crc_value(&mut self) -> u32 {
        let crc = std::mem::replace(&mut self.crc, Hasher::new());
        crc.finalize()
    }
}

impl<W: Write> Write for CompressWrapWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.cache.resize(buf.len(), Default::default());
        let len = self.writer.write(buf)?;
        self.crc.update(&buf[..len]);
        *self.bytes_written += len;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// A solid block compressed away from any writer, ready to be appended by
/// [`ArchiveWriter::push_prepared_block`].
///
/// **This holds the entire compressed block in memory** until it is pushed, where
/// [`ArchiveWriter::push_archive_entries`] streams into the output as it encodes. That is inherent
/// to preparing a block off-thread, and it is what a caller sizing its batches is signing up for:
/// peak memory is roughly the compressed size of every block in flight at once.
#[derive(Debug)]
pub struct PreparedBlock {
    /// The packed streams with their CRCs: one for a chain of coders, four for BCJ2.
    packed: Vec<(Vec<u8>, u32)>,
    entries: Vec<ArchiveEntry>,
    folder: Folder,
    sizes: Vec<u64>,
    crc: u32,
    sub_stream_sizes: Vec<u64>,
    sub_stream_crcs: Vec<u32>,
}

impl PreparedBlock {
    /// Compressed size in bytes, before it is appended.
    pub fn compressed_len(&self) -> usize {
        self.packed.iter().map(|(bytes, _)| bytes.len()).sum()
    }

    /// Number of entries in the block.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the block holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compress `entries` into one solid block using `methods`, without a writer.
///
/// Mirrors the encoding half of [`ArchiveWriter::push_archive_entries`], writing into memory instead
/// of the archive. Safe to call on a worker thread; the result is appended later with
/// [`ArchiveWriter::push_prepared_block`], which is what fixes the order.
///
/// Returns an error if `methods` is empty, or if `entries` and `reader` differ in length.
pub fn prepare_block<R: Read>(
    methods: Arc<Vec<EncoderConfiguration>>,
    entries: Vec<ArchiveEntry>,
    reader: Vec<SourceReader<R>>,
) -> Result<PreparedBlock> {
    if methods.is_empty() {
        return Err(Error::other("prepare_block: `methods` must not be empty"));
    }

    let mut entries = entries;
    let mut r = SeqReader::new(reader);
    if r.reader_len() != entries.len() {
        return Err(Error::other(format!(
            "prepare_block: {} entries against {} readers",
            entries.len(),
            r.reader_len()
        )));
    }

    let mut out: Vec<u8> = Vec::new();
    let mut more_sizes: Vec<Rc<Cell<usize>>> = Vec::with_capacity(methods.len() - 1);

    let (crc, size, compressed_crc) = {
        // Outer wrapper: the CRC of the compressed bytes, computed as they are produced on this
        // thread. `push_prepared_block` would otherwise have to make a second pass over the whole
        // buffer on the serialized side, which is the work this function exists to move off it.
        let mut compressed_len = 0;
        let mut compressed = CompressWrapWriter::new(&mut out, &mut compressed_len);
        let (crc, size) = {
            let mut w = ArchiveWriter::<std::io::Cursor<Vec<u8>>>::create_writer(
                &methods,
                &mut compressed,
                &mut more_sizes,
            )?;
            let mut write_len = 0;
            let mut w = CompressWrapWriter::new(&mut w, &mut write_len);
            let mut buf = [0u8; 4096];
            loop {
                let n = r.read(&mut buf).map_err(|e| {
                    Error::io_msg(
                        e,
                        format!("prepare_block: read source:{}", entries_names(&entries)),
                    )
                })?;
                if n == 0 {
                    break;
                }
                w.write_all(&buf[..n]).map_err(|e| {
                    Error::io_msg(
                        e,
                        format!("prepare_block: encode:{}", entries_names(&entries)),
                    )
                })?;
            }
            w.flush().map_err(|e| {
                Error::io_msg(
                    e,
                    format!("prepare_block: flush:{}", entries_names(&entries)),
                )
            })?;
            w.write(&[]).map_err(|e| {
                Error::io_msg(
                    e,
                    format!("prepare_block: finish:{}", entries_names(&entries)),
                )
            })?;
            (w.crc_value(), write_len)
        };
        (crc, size, compressed.crc_value())
    };

    let mut sub_stream_crcs = Vec::with_capacity(entries.len());
    let mut sub_stream_sizes = Vec::with_capacity(entries.len());
    for i in 0..entries.len() {
        let entry = &mut entries[i];
        let ri = &r[i];
        entry.crc = ri.crc_value() as u64;
        entry.size = ri.read_count() as u64;
        sub_stream_crcs.push(entry.crc as u32);
        sub_stream_sizes.push(entry.size);
        entry.has_crc = true;
    }

    let mut sizes = Vec::with_capacity(more_sizes.len() + 1);
    sizes.extend(more_sizes.iter().map(|s| s.get() as u64));
    sizes.push(size as u64);

    Ok(PreparedBlock {
        packed: vec![(out, compressed_crc)],
        entries,
        folder: Folder::Chain(methods),
        sizes,
        crc,
        sub_stream_sizes,
        sub_stream_crcs,
    })
}

/// How a BCJ2 block's four streams are compressed: the coder for the main stream (what the
/// files mostly are), the coder for the call and jump streams (32-bit addresses, which 7-Zip
/// gives LZMA with `lc0 lp2` and a 1 MiB dictionary), and AES around every stream when a
/// password is given.
#[derive(Debug, Clone)]
pub struct Bcj2Methods {
    /// The coder for the main stream: the code with its branch operands taken out.
    pub main: EncoderConfiguration,
    /// The coder for the call and jump streams: big-endian 32-bit addresses.
    pub addresses: EncoderConfiguration,
    /// AES-256 around every stream, when set.
    pub password: Option<Password>,
}

/// Compress `entries` into one solid block behind the BCJ2 filter, as 7-Zip's `-mf=BCJ2`
/// does for x86 executables: the code split into a main stream, a call stream, a jump stream
/// and the range-coded decisions, the first three compressed with `methods`, and the folder
/// written as a graph of four packed streams (eight coders when encrypted, AES on each).
///
/// Like [`prepare_block`], safe on a worker thread; the result is appended with
/// [`ArchiveWriter::push_prepared_block`].
pub fn prepare_bcj2_block<R: Read>(
    methods: &Bcj2Methods,
    entries: Vec<ArchiveEntry>,
    reader: Vec<SourceReader<R>>,
) -> Result<PreparedBlock> {
    let mut entries = entries;
    let mut r = SeqReader::new(reader);
    if r.reader_len() != entries.len() {
        return Err(Error::other(format!(
            "prepare_bcj2_block: {} entries against {} readers",
            entries.len(),
            r.reader_len()
        )));
    }
    // One compressed stream, its CRC, the bytes fed into its coders (the last is the
    // plain size), and the AES configuration when there is one.
    struct Stream {
        packed: Vec<u8>,
        packed_crc: u32,
        sizes: Vec<u64>,
        aes: Option<EncoderConfiguration>,
    }
    fn compress(
        chain: Vec<EncoderConfiguration>,
        aes: Option<EncoderConfiguration>,
        feed: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<Stream> {
        let mut methods: Vec<EncoderConfiguration> = Vec::with_capacity(chain.len() + 1);
        methods.extend(aes.iter().cloned());
        methods.extend(chain);
        let mut out: Vec<u8> = Vec::new();
        let mut more_sizes: Vec<Rc<Cell<usize>>> = Vec::new();
        let mut compressed_len = 0;
        let (packed_crc, size) = {
            let mut compressed = CompressWrapWriter::new(&mut out, &mut compressed_len);
            let size = if methods.is_empty() {
                let mut plain = 0;
                let mut w = CompressWrapWriter::new(&mut compressed, &mut plain);
                feed(&mut w)?;
                w.flush()
                    .map_err(|e| Error::io_msg(e, "prepare_bcj2_block: flush".to_string()))?;
                plain
            } else {
                let mut w = ArchiveWriter::<std::io::Cursor<Vec<u8>>>::create_writer(
                    &methods,
                    &mut compressed,
                    &mut more_sizes,
                )?;
                let mut plain = 0;
                let mut w = CompressWrapWriter::new(&mut w, &mut plain);
                feed(&mut w)?;
                w.flush()
                    .map_err(|e| Error::io_msg(e, "prepare_bcj2_block: flush".to_string()))?;
                w.write(&[])
                    .map_err(|e| Error::io_msg(e, "prepare_bcj2_block: finish".to_string()))?;
                plain
            };
            (compressed.crc_value(), size)
        };
        let mut sizes: Vec<u64> = more_sizes.iter().map(|s| s.get() as u64).collect();
        sizes.push(size as u64);
        Ok(Stream {
            packed: out,
            packed_crc,
            sizes,
            aes,
        })
    }
    #[cfg(feature = "aes256")]
    let aes = |password: &Option<Password>| -> Option<EncoderConfiguration> {
        password
            .as_ref()
            .map(|p| AesEncoderOptions::new(p.clone()).into())
    };
    #[cfg(not(feature = "aes256"))]
    let aes = |password: &Option<Password>| -> Option<EncoderConfiguration> {
        let _ = password;
        None
    };
    #[cfg(not(feature = "aes256"))]
    if methods.password.is_some() {
        return Err(Error::unsupported(
            "prepare_bcj2_block: a password needs the aes256 feature",
        ));
    }

    // The filter runs once over the input, feeding three encoders; the fourth stream is what
    // it keeps. Each encoder is driven through a buffer so the four can be built in turn.
    let mut main_plain: Vec<u8> = Vec::new();
    let mut call_plain: Vec<u8> = Vec::new();
    let mut jump_plain: Vec<u8> = Vec::new();
    let (crc, size, rc) = {
        let mut encoder = codec::bcj2::Bcj2Encoder::new();
        let mut hasher = Hasher::new();
        let mut size = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            let n = r.read(&mut buf).map_err(|e| {
                Error::io_msg(
                    e,
                    format!(
                        "prepare_bcj2_block: read source:{}",
                        entries_names(&entries)
                    ),
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
            let mut streams = codec::bcj2::Bcj2Streams {
                main: &mut main_plain,
                call: &mut call_plain,
                jump: &mut jump_plain,
            };
            encoder.write(&buf[..n], &mut streams).map_err(|e| {
                Error::io_msg(
                    e,
                    format!("prepare_bcj2_block: filter:{}", entries_names(&entries)),
                )
            })?;
        }
        let mut streams = codec::bcj2::Bcj2Streams {
            main: &mut main_plain,
            call: &mut call_plain,
            jump: &mut jump_plain,
        };
        let rc = encoder.finish(&mut streams).map_err(|e| {
            Error::io_msg(
                e,
                format!("prepare_bcj2_block: filter:{}", entries_names(&entries)),
            )
        })?;
        (hasher.finalize(), size, rc)
    };
    let feed_all = |bytes: Vec<u8>| {
        move |w: &mut dyn Write| -> Result<()> {
            w.write_all(&bytes)
                .map_err(|e| Error::io_msg(e, "prepare_bcj2_block: encode".to_string()))
        }
    };
    let main = compress(
        vec![methods.main.clone()],
        aes(&methods.password),
        feed_all(main_plain),
    )?;
    let call = compress(
        vec![methods.addresses.clone()],
        aes(&methods.password),
        feed_all(call_plain),
    )?;
    let jump = compress(
        vec![methods.addresses.clone()],
        aes(&methods.password),
        feed_all(jump_plain),
    )?;
    let decisions = compress(Vec::new(), aes(&methods.password), feed_all(rc))?;

    // The folder, laid out as 7-Zip lays it out: the coders for the jump, call and main
    // streams, then BCJ2 with its four inputs (main, call, jump, decisions), and before them
    // an AES coder per stream when encrypting; the packed streams in the order main,
    // decisions, call, jump. Streams are numbered in coder order.
    let coder_of = |configuration: &EncoderConfiguration| -> GraphCoder {
        let mut temp = [0u8; 256];
        let properties = encoder::get_options_as_properties(
            configuration.method,
            configuration.options.as_ref(),
            &mut temp,
        )
        .to_vec();
        GraphCoder {
            id: configuration.method.id(),
            properties,
            num_in_streams: 1,
        }
    };
    let bcj2 = GraphCoder {
        id: EncoderMethod::ID_BCJ2,
        properties: Vec::new(),
        num_in_streams: 4,
    };
    let plain_size = |stream: &Stream| stream.sizes[stream.sizes.len() - 1];
    let (coders, sizes, bind_pairs, packed_streams) = if methods.password.is_some() {
        let aes_of = |stream: &Stream| -> Result<GraphCoder> {
            let configuration = stream
                .aes
                .as_ref()
                .ok_or_else(|| Error::other("prepare_bcj2_block: a stream without its AES"))?;
            Ok(coder_of(configuration))
        };
        (
            vec![
                aes_of(&jump)?,
                aes_of(&call)?,
                aes_of(&decisions)?,
                aes_of(&main)?,
                coder_of(&methods.addresses),
                coder_of(&methods.addresses),
                coder_of(&methods.main),
                bcj2,
            ],
            // What each coder unpacks to: AES to the packed bytes it hides, the
            // compressors to their streams, BCJ2 to the whole.
            vec![
                jump.sizes[0],
                call.sizes[0],
                decisions.sizes[0],
                main.sizes[0],
                plain_size(&jump),
                plain_size(&call),
                plain_size(&main),
                size,
            ],
            vec![(4, 0), (5, 1), (10, 2), (6, 3), (9, 4), (8, 5), (7, 6)],
            vec![3, 2, 1, 0],
        )
    } else {
        (
            vec![
                coder_of(&methods.addresses),
                coder_of(&methods.addresses),
                coder_of(&methods.main),
                bcj2,
            ],
            vec![
                plain_size(&jump),
                plain_size(&call),
                plain_size(&main),
                size,
            ],
            vec![(5, 0), (4, 1), (3, 2)],
            vec![2, 6, 1, 0],
        )
    };
    let packed = vec![
        (main.packed, main.packed_crc),
        (decisions.packed, decisions.packed_crc),
        (call.packed, call.packed_crc),
        (jump.packed, jump.packed_crc),
    ];

    let mut sub_stream_crcs = Vec::with_capacity(entries.len());
    let mut sub_stream_sizes = Vec::with_capacity(entries.len());
    for i in 0..entries.len() {
        let entry = &mut entries[i];
        let ri = &r[i];
        entry.crc = ri.crc_value() as u64;
        entry.size = ri.read_count() as u64;
        sub_stream_crcs.push(entry.crc as u32);
        sub_stream_sizes.push(entry.size);
        entry.has_crc = true;
    }

    Ok(PreparedBlock {
        packed,
        entries,
        folder: Folder::Graph {
            coders,
            bind_pairs,
            packed_streams,
        },
        sizes,
        crc,
        sub_stream_sizes,
        sub_stream_crcs,
    })
}
