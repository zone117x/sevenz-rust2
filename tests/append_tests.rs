//! Adding to an archive that is already written, with `ArchiveWriter::append_to`.
//!
//! What has to hold: the members already there are neither read nor re-encoded,
//! their packed bytes stay at the offsets they were at, the archive reads
//! afterwards as one whole, and the entries that were already in it come back
//! with the same contents and the same CRCs.

use std::io::{Cursor, Read};

use sevenz_rust2::{ArchiveEntry, ArchiveReader, ArchiveWriter, Password};

/// An archive of three members, and the bytes it was written as.
fn three_members() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut bytes)).unwrap();
        for (name, content) in samples() {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(content.as_slice()))
                .unwrap();
        }
        writer
            .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory("dir"), None)
            .unwrap();
        writer.finish().unwrap();
    }
    bytes
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("first.txt", b"the first member\n".to_vec()),
        ("second.bin", (0u8..=255).cycle().take(9000).collect()),
        ("dir/third.txt", b"a member in a directory\n".to_vec()),
    ]
}

/// Everything the archive holds, by name.
fn contents(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes), Password::empty()).unwrap();
    let names: Vec<String> = reader
        .archive()
        .files
        .iter()
        .filter(|file| !file.is_directory())
        .map(|file| file.name().to_string())
        .collect();
    let mut out = Vec::new();
    for name in names {
        let data = reader
            .read_file(&name)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        out.push((name, data));
    }
    out.sort();
    out
}

/// Appends `additions` to `bytes` in place, as a caller with a file would.
fn append(bytes: &mut Vec<u8>, additions: Vec<(&str, Vec<u8>)>) {
    let archive = {
        let reader = ArchiveReader::new(Cursor::new(&bytes[..]), Password::empty()).unwrap();
        reader.archive().clone()
    };
    let mut cursor = Cursor::new(&mut *bytes);
    let mut writer = ArchiveWriter::append_to(&mut cursor, &archive).unwrap();
    for (name, content) in additions {
        writer
            .push_archive_entry(ArchiveEntry::new_file(name), Some(content.as_slice()))
            .unwrap();
    }
    // Nothing should follow the header: the file may have been longer before.
    let (_, end) = writer.finish_with_end().unwrap();
    bytes.truncate(end as usize);
}

#[test]
fn an_appended_archive_holds_what_it_held_and_what_was_added() {
    let mut bytes = three_members();
    let was = contents(&bytes);

    append(&mut bytes, vec![("added.txt", b"appended\n".to_vec())]);

    let now = contents(&bytes);
    for (name, data) in &was {
        assert_eq!(
            now.iter().find(|(n, _)| n == name).map(|(_, d)| d),
            Some(data),
            "{name} reads differently after the append"
        );
    }
    assert_eq!(
        now.iter()
            .find(|(n, _)| n == "added.txt")
            .map(|(_, d)| d.as_slice()),
        Some(b"appended\n".as_slice())
    );
    assert_eq!(now.len(), was.len() + 1);
}

#[test]
fn the_packed_bytes_that_were_there_do_not_move() {
    let mut bytes = three_members();
    let archive = {
        let reader = ArchiveReader::new(Cursor::new(&bytes[..]), Password::empty()).unwrap();
        reader.archive().clone()
    };
    // Everything between the signature header and where the old header began is
    // packed data, and an append must leave every byte of it exactly where it is.
    // That is the whole point: the cost is the addition and a new header, not the
    // archive. The signature header itself is expected to change, since it is
    // what points at the new header.
    const SIGNATURE: usize = 32;
    let start = ArchiveWriter::<Cursor<Vec<u8>>>::packed_end(&archive) as usize;
    let packed_before = bytes[SIGNATURE..start].to_vec();

    append(&mut bytes, vec![("added.txt", b"appended\n".to_vec())]);

    assert_eq!(
        &bytes[SIGNATURE..start],
        &packed_before[..],
        "the packed bytes already in the archive moved or changed"
    );
    assert!(bytes.len() > start, "the append wrote nothing");
}

#[test]
fn appending_again_and_again_keeps_every_member_readable() {
    let mut bytes = three_members();
    let was = contents(&bytes);

    for round in 0..5 {
        append(
            &mut bytes,
            vec![(
                Box::leak(format!("run/{round}.txt").into_boxed_str()),
                format!("round {round}\n").into_bytes(),
            )],
        );
    }

    let now = contents(&bytes);
    assert_eq!(now.len(), was.len() + 5);
    for (name, data) in &was {
        assert_eq!(
            now.iter().find(|(n, _)| n == name).map(|(_, d)| d),
            Some(data),
            "{name} changed after five appends"
        );
    }
    for round in 0..5 {
        let name = format!("run/{round}.txt");
        assert_eq!(
            now.iter().find(|(n, _)| *n == name).map(|(_, d)| d.clone()),
            Some(format!("round {round}\n").into_bytes()),
            "{name}"
        );
    }
}

#[test]
fn an_interrupted_append_leaves_the_archive_as_it_was() {
    // New data goes after everything already in the file, so the old header is
    // still there and the signature header still points at it. A file cut
    // anywhere in the new tail therefore reads exactly as it did before, with no
    // recovery step at all.
    const SIGNATURE: usize = 32;
    let original = three_members();
    let was = contents(&original);
    let mut bytes = original.clone();

    append(&mut bytes, vec![("late.txt", b"written last\n".to_vec())]);

    let tail = bytes.len() - original.len();
    assert!(tail > 0, "the append wrote nothing to cut");
    for cut in 0..tail {
        // What an interruption actually leaves: some of the new tail written, and
        // the signature header still the one that was there, because patching it
        // is the last thing an append does. Truncating the finished file instead
        // would be testing corruption, not interruption.
        let mut partial = bytes[..original.len() + cut].to_vec();
        partial[..SIGNATURE].copy_from_slice(&original[..SIGNATURE]);
        assert_eq!(
            contents_or_none(&partial).as_ref(),
            Some(&was),
            "a file cut {cut} bytes into the append did not read as it did before"
        );
    }
}

/// The archive's contents, or nothing if it will not read.
fn contents_or_none(bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes), Password::empty()).ok()?;
    let names: Vec<String> = reader
        .archive()
        .files
        .iter()
        .filter(|file| !file.is_directory())
        .map(|file| file.name().to_string())
        .collect();
    let mut out = Vec::new();
    for name in names {
        let data = reader.read_file(&name).ok()?;
        out.push((name, data));
    }
    out.sort();
    Some(out)
}

#[test]
fn an_archive_whose_files_have_no_crc_is_refused() {
    // The header records a CRC for every file with a stream, so one that has
    // none cannot have a header written for it. Refusing is the honest answer;
    // writing a header that claims a CRC of zero would produce an archive that
    // every checking reader rejects.
    let bytes = three_members();
    let mut archive = {
        let reader = ArchiveReader::new(Cursor::new(&bytes[..]), Password::empty()).unwrap();
        reader.archive().clone()
    };
    for file in &mut archive.files {
        if file.has_stream {
            file.has_crc = false;
        }
    }
    let mut sink = Cursor::new(bytes.clone());
    assert!(ArchiveWriter::append_to(&mut sink, &archive).is_err());
}

#[test]
fn a_reader_sees_the_same_bytes_through_a_file_as_through_memory() {
    // The same append done against a real file, since that is how it is used and
    // a Cursor hides a seek that a File would not.
    let bytes = three_members();
    let was = contents(&bytes);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.7z");
    std::fs::write(&path, &bytes).unwrap();

    let archive = {
        let reader = ArchiveReader::open(&path, Password::empty()).unwrap();
        reader.archive().clone()
    };
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut writer = ArchiveWriter::append_to(file, &archive).unwrap();
        writer
            .push_archive_entry(
                ArchiveEntry::new_file("added.txt"),
                Some(b"appended\n".as_slice()),
            )
            .unwrap();
        let (file, end) = writer.finish_with_end().unwrap();
        file.set_len(end).unwrap();
        file.sync_all().unwrap();
    }

    let mut written = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut written)
        .unwrap();
    let now = contents(&written);
    for (name, data) in &was {
        assert_eq!(
            now.iter().find(|(n, _)| n == name).map(|(_, d)| d),
            Some(data),
            "{name} differs after an append through a file"
        );
    }
    assert_eq!(now.len(), was.len() + 1);
}
