#[cfg(feature = "compress")]
use sevenz_rust2::*;
#[cfg(all(feature = "compress", feature = "util"))]
use tempfile::*;

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn compress_multi_files_solid() {
    let temp_dir = tempdir().unwrap();
    let folder = temp_dir.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let mut files = Vec::with_capacity(100);
    let mut contents = Vec::with_capacity(100);
    for i in 1..=10000 {
        let name = format!("file{i}.txt");
        let content = format!("file{i} with content");
        std::fs::write(folder.join(&name), &content).unwrap();
        files.push(name);
        contents.push(content);
    }
    let dest = temp_dir.path().join("folder.7z");

    let mut sz = ArchiveWriter::create(&dest).unwrap();
    sz.push_source_path(&folder, |_| true).unwrap();
    sz.finish().expect("compress ok");

    let decompress_dest = temp_dir.path().join("decompress");
    decompress_file(dest, &decompress_dest).expect("decompress ok");
    assert!(decompress_dest.exists());
    for i in 0..files.len() {
        let name = &files[i];
        let content = &contents[i];
        let decompress_file = decompress_dest.join(name);
        assert!(decompress_file.exists());
        assert_eq!(&std::fs::read_to_string(&decompress_file).unwrap(), content);
    }
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn compress_multi_files_mix_solid_and_non_solid() {
    use std::fs::File;

    let temp_dir = tempdir().unwrap();
    let folder = temp_dir.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let mut files = Vec::with_capacity(100);
    let mut contents = Vec::with_capacity(100);
    for i in 1..=100 {
        let name = format!("file{i}.txt");
        let content = format!("file{i} with content");
        std::fs::write(folder.join(&name), &content).unwrap();
        files.push(name);
        contents.push(content);
    }
    let dest = temp_dir.path().join("folder.7z");

    let mut sz = ArchiveWriter::create(&dest).unwrap();

    // solid compression
    sz.push_source_path(&folder, |_| true).unwrap();

    // non solid compression
    for i in 101..=200 {
        let name = format!("file{i}.txt");
        let content = format!("file{i} with content");
        std::fs::write(folder.join(&name), &content).unwrap();
        files.push(name.clone());
        contents.push(content);

        let src = folder.join(&name);
        sz.push_archive_entry(
            ArchiveEntry::from_path(&src, name),
            Some(File::open(src).unwrap()),
        )
        .expect("ok");
    }

    sz.finish().expect("compress ok");

    let decompress_dest = temp_dir.path().join("decompress");
    decompress_file(dest, &decompress_dest).expect("decompress ok");
    assert!(decompress_dest.exists());
    for i in 0..files.len() {
        let name = &files[i];
        let content = &contents[i];
        let decompress_file = decompress_dest.join(name);
        assert!(decompress_file.exists());
        assert_eq!(&std::fs::read_to_string(&decompress_file).unwrap(), content);
    }
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn prepare_block_round_trips_through_push_prepared_block() {
    use std::{io::Cursor, sync::Arc};

    let temp_dir = tempdir().unwrap();
    let dest = temp_dir.path().join("prepared.7z");

    let contents: Vec<String> = (1..=200).map(|i| format!("file{i} with content")).collect();
    let entries: Vec<ArchiveEntry> = (1..=200)
        .map(|i| ArchiveEntry::new_file(&format!("file{i}.txt")))
        .collect();
    let readers: Vec<SourceReader<Cursor<Vec<u8>>>> = contents
        .iter()
        .map(|c| SourceReader::new(Cursor::new(c.clone().into_bytes())))
        .collect();

    let methods = Arc::new(vec![EncoderConfiguration::new(EncoderMethod::LZMA2)]);
    let block = prepare_block(methods, entries, readers).expect("prepare ok");
    assert_eq!(block.len(), 200);
    assert!(!block.is_empty());
    assert!(block.compressed_len() > 0);

    let mut sz = ArchiveWriter::create(&dest).unwrap();
    sz.push_prepared_block(block).expect("push ok");
    sz.finish().expect("finish ok");

    let out = temp_dir.path().join("out");
    decompress_file(&dest, &out).expect("decompress ok");
    for (i, content) in contents.iter().enumerate() {
        let f = out.join(format!("file{}.txt", i + 1));
        assert!(f.exists(), "missing {}", f.display());
        assert_eq!(&std::fs::read_to_string(&f).unwrap(), content);
    }
}

#[cfg(feature = "compress")]
#[test]
fn prepare_block_refuses_an_empty_method_list() {
    use std::{io::Cursor, sync::Arc};

    // A block with no coders writes an archive that no reader can open, and `finish()` reports
    // success while doing it, so this has to fail at the point the caller can still act on it.
    let err = prepare_block(
        Arc::new(Vec::new()),
        vec![ArchiveEntry::new_file("a.txt")],
        vec![SourceReader::new(Cursor::new(b"hello".to_vec()))],
    )
    .expect_err("an empty method list must be refused");
    assert!(
        format!("{err}").contains("must not be empty"),
        "unexpected error: {err}"
    );
}

#[cfg(feature = "compress")]
#[test]
fn prepare_block_refuses_mismatched_entries_and_readers() {
    use std::{io::Cursor, sync::Arc};

    let err = prepare_block(
        Arc::new(vec![EncoderConfiguration::new(EncoderMethod::LZMA2)]),
        vec![
            ArchiveEntry::new_file("a.txt"),
            ArchiveEntry::new_file("b.txt"),
        ],
        vec![SourceReader::new(Cursor::new(b"only one".to_vec()))],
    )
    .expect_err("a length mismatch must be refused");
    assert!(
        format!("{err}").contains("against"),
        "unexpected error: {err}"
    );
}

/// Bytes that look like x86 code: calls and jumps with near and far targets between plain bytes.
#[cfg(feature = "compress")]
fn x86_like_code() -> Vec<u8> {
    let mut code = Vec::new();
    let mut x: u32 = 7;
    for i in 0..60_000u32 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        match i % 19 {
            0 => {
                code.push(0xE8);
                code.extend_from_slice(&(i.wrapping_mul(13) % 4000).to_le_bytes());
            }
            7 => {
                code.push(0xE9);
                code.extend_from_slice(&0xFFFF_FE00u32.to_le_bytes());
            }
            11 => {
                code.push(0x0F);
                code.push(0x85);
                code.extend_from_slice(&(i % 100).to_le_bytes());
            }
            _ => code.push((x >> 16) as u8),
        }
    }
    code
}

#[cfg(all(feature = "compress", feature = "util"))]
fn bcj2_round_trip(password: Option<&str>) {
    use std::io::Cursor;

    let temp_dir = tempdir().unwrap();
    let dest = temp_dir.path().join("bcj2.7z");
    let code = x86_like_code();
    let text = b"a text file in the same block\n".repeat(200);
    let entries = vec![
        ArchiveEntry::new_file("program.exe"),
        ArchiveEntry::new_file("readme.txt"),
    ];
    let readers = vec![
        SourceReader::new(Cursor::new(code.clone())),
        SourceReader::new(Cursor::new(text.clone())),
    ];
    let mut addresses = encoder_options::LzmaOptions::from_level(5);
    addresses.set_literal_bits(0, 2, 2);
    addresses.set_dictionary_size(1 << 20);
    let methods = Bcj2Methods {
        main: EncoderConfiguration::new(EncoderMethod::LZMA2),
        addresses: addresses.into(),
        password: password.map(Password::new),
    };
    let block = prepare_bcj2_block(&methods, entries, readers).expect("prepare ok");
    assert_eq!(block.len(), 2);
    assert!(
        block.compressed_len() < code.len() + text.len(),
        "the block compresses"
    );

    let mut sz = ArchiveWriter::create(&dest).unwrap();
    sz.push_prepared_block(block).expect("push ok");
    sz.finish().expect("finish ok");

    let out = temp_dir.path().join("out");
    match password {
        Some(password) => decompress_file_with_password(&dest, &out, Password::new(password))
            .expect("decompress ok"),
        None => decompress_file(&dest, &out).expect("decompress ok"),
    }
    assert_eq!(std::fs::read(out.join("program.exe")).unwrap(), code);
    assert_eq!(std::fs::read(out.join("readme.txt")).unwrap(), text);

    // The folder is a graph of four packed streams ending in BCJ2, laid out as 7-Zip lays
    // its own out.
    let archive = Archive::open_with_password(&dest, &Password::empty()).unwrap();
    assert_eq!(archive.blocks.len(), 1);
    let block = &archive.blocks[0];
    let last = block.coders.last().unwrap();
    assert_eq!(last.encoder_method_id(), EncoderMethod::ID_BCJ2);
    assert_eq!(last.num_in_streams(), 4);
    let (bind_pairs, packed_streams) = block.graph();
    if password.is_some() {
        assert_eq!(
            bind_pairs,
            [(4, 0), (5, 1), (10, 2), (6, 3), (9, 4), (8, 5), (7, 6)]
        );
        assert_eq!(packed_streams, [3, 2, 1, 0]);
    } else {
        assert_eq!(bind_pairs, [(5, 0), (4, 1), (3, 2)]);
        assert_eq!(packed_streams, [2, 6, 1, 0]);
    }
    assert_eq!(
        block.coders.len(),
        if password.is_some() { 8 } else { 4 },
        "AES on every stream when encrypted"
    );
}

#[cfg(all(feature = "compress", feature = "util"))]
#[test]
fn a_bcj2_block_round_trips_as_a_folder_of_four_streams() {
    bcj2_round_trip(None);
}

#[cfg(all(feature = "compress", feature = "util", feature = "aes256"))]
#[test]
fn a_bcj2_block_round_trips_encrypted_on_every_stream() {
    bcj2_round_trip(Some("secret"));
}
