//! Writes a BCJ2 archive of the files given, for checking with 7-Zip.
use std::{fs::File, io::BufReader};

use sevenz_rust2::{encoder_options::LzmaOptions, *};

fn main() {
    let mut args = std::env::args().skip(1);
    let dest = args.next().expect("destination");
    let password = std::env::var("BCJ2_PASSWORD").ok();
    let mut entries = Vec::new();
    let mut readers = Vec::new();
    for path in args {
        let name = std::path::Path::new(&path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        entries.push(ArchiveEntry::new_file(&name));
        readers.push(SourceReader::new(BufReader::new(
            File::open(&path).unwrap(),
        )));
    }
    let mut addresses = LzmaOptions::from_level(5);
    addresses.set_literal_bits(0, 2, 2);
    addresses.set_dictionary_size(1 << 20);
    let methods = Bcj2Methods {
        main: EncoderConfiguration::new(EncoderMethod::LZMA2),
        addresses: addresses.into(),
        password: password.as_deref().map(Password::new),
    };
    let block = prepare_bcj2_block(&methods, entries, readers).unwrap();
    let mut writer = ArchiveWriter::create(&dest).unwrap();
    writer.push_prepared_block(block).unwrap();
    writer.finish().unwrap();
}
