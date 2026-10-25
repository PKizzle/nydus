// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Sequential reader for the members of a layer tar.
//!
//! containerd's `archive.Apply` reads layers with Go's `archive/tar`, so this reader follows it
//! where the `tar` crate does not: PAX records are framed by their length and may hold newlines,
//! a second PAX header replaces the first, nothing after the end-of-archive marker is a member,
//! and a GNU sparse file described by PAX records is recognised instead of being taken for a
//! regular file holding the sparse map. Header fields are still decoded by [`tar::Header`].
//!
//! Member data is read straight from the underlying reader with no buffering of its own, so the
//! position of that reader is the offset of the data in the tar stream. The tar-ref and zran
//! conversions take chunk offsets from exactly that position.

use std::io::{self, Read, Seek, SeekFrom};

use tar::Header;

const BLOCK: u64 = 512;
/// Largest member size accepted; Go rejects sizes of 2^63 and above, and a skip of
/// `size + padding` must fit a `SeekFrom::Current` offset.
const MAX_SIZE: u64 = i64::MAX as u64 - BLOCK;

/// Errors from reading a layer tar.
#[derive(Debug, thiserror::Error)]
pub enum TarError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("malformed tar archive: {0}")]
    Malformed(String),
    #[error("unsupported tar member: {0}")]
    Unsupported(String),
}

type Result<T> = std::result::Result<T, TarError>;

/// A member of the archive with its GNU long name and PAX records applied.
pub struct Member {
    /// The member's own header, for its type, mode, mtime and device numbers.
    pub header: Header,
    pub path: Vec<u8>,
    /// Target of a symlink or hard link, empty for other members.
    pub link: Vec<u8>,
    pub size: u64,
    pub uid: u64,
    pub gid: u64,
    /// The PAX records describing this member, in archive order.
    pub pax: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Iterates the members of a tar stream; see the module documentation.
pub struct Members<R> {
    inner: R,
    seekable: bool,
    /// Unread data of the current member.
    data_left: u64,
    /// Padding after the data of the current member.
    pad: u64,
}

impl<R: Read + Seek> Members<R> {
    /// `seekable` selects skipping unread member data by seeking instead of reading.
    pub fn new(inner: R, seekable: bool) -> Self {
        Members {
            inner,
            seekable,
            data_left: 0,
            pad: 0,
        }
    }

    /// Returns the next member, or `None` after the end-of-archive marker. Everything after
    /// the marker is read and discarded, so a digest over the stream covers all of it.
    pub fn next_member(&mut self) -> Result<Option<Member>> {
        let mut pax: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
        let mut long_name = None;
        let mut long_link = None;
        loop {
            self.skip_rest()?;
            let Some(header) = self.read_header()? else {
                if pax.is_some() || long_name.is_some() || long_link.is_some() {
                    return Err(malformed("extension header without a member"));
                }
                return Ok(None);
            };
            let size = check_size(header.entry_size()?)?;
            self.data_left = size;
            self.pad = (BLOCK - size % BLOCK) % BLOCK;
            match header.entry_type().as_byte() {
                b'x' => {
                    pax = Some(parse_pax(&self.read_body(size)?)?);
                    continue;
                }
                b'L' => {
                    long_name = Some(cut_nul(self.read_body(size)?));
                    continue;
                }
                b'K' => {
                    long_link = Some(cut_nul(self.read_body(size)?));
                    continue;
                }
                _ => {}
            }

            let mut member = Member {
                path: header.path_bytes().into_owned(),
                link: header
                    .link_name_bytes()
                    .map(|l| l.into_owned())
                    .unwrap_or_default(),
                size,
                // An unset id field reads as 0, as Go reads an all-NUL number.
                uid: header.uid().unwrap_or_default(),
                gid: header.gid().unwrap_or_default(),
                pax: Vec::new(),
                header,
            };
            // A global header carries records for the whole archive, which Go's reader hands
            // out as they are instead of applying them to later members.
            if member.header.entry_type().is_pax_global_extensions() {
                return Ok(Some(member));
            }
            if let Some(records) = pax {
                apply_pax(&mut member, records)?;
                check_size(member.size)?;
            }
            if let Some(name) = long_name {
                member.path = name;
            }
            if let Some(link) = long_link {
                member.link = link;
            }
            // Legacy archives mark a directory with a trailing slash on a type '\0' member.
            if member.header.as_bytes()[156] == 0 && member.path.ends_with(b"/") {
                member.header.set_entry_type(tar::EntryType::Directory);
            }
            // Go's `isHeaderOnlyType`: these members have no data, whatever their size field
            // says, and the next header follows right after theirs.
            if matches!(
                member.header.entry_type().as_byte(),
                b'1' | b'2' | b'3' | b'4' | b'5' | b'6'
            ) {
                member.size = 0;
            }
            self.data_left = member.size;
            self.pad = (BLOCK - member.size % BLOCK) % BLOCK;
            return Ok(Some(member));
        }
    }

    /// Reader over the data of the member last returned by [`Self::next_member`].
    pub fn data(&mut self) -> MemberData<'_, R> {
        MemberData {
            inner: &mut self.inner,
            left: &mut self.data_left,
        }
    }

    fn skip_rest(&mut self) -> Result<()> {
        let n = self.data_left.checked_add(self.pad);
        (self.data_left, self.pad) = (0, 0);
        let n = n
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| malformed("member size overflows the archive"))?;
        if n == 0 {
            return Ok(());
        }
        if self.seekable {
            self.inner.seek(SeekFrom::Current(n))?;
        } else if io::copy(&mut (&mut self.inner).take(n as u64), &mut io::sink())? != n as u64 {
            return Err(truncated());
        }
        Ok(())
    }

    fn read_body(&mut self, size: u64) -> Result<Vec<u8>> {
        // Extension headers live in memory; bound what a hostile archive can make us allocate.
        if size > 1 << 20 {
            return Err(malformed(format!("extension header of {} bytes", size)));
        }
        let mut buf = vec![0u8; size as usize];
        self.inner.read_exact(&mut buf).map_err(eof_is_truncated)?;
        self.data_left = 0;
        Ok(buf)
    }

    /// Reads the next header, `None` at the end of the archive: an end-of-file at a block
    /// boundary or two zero blocks. A zero block followed by anything else is malformed.
    fn read_header(&mut self) -> Result<Option<Header>> {
        let mut header = Header::new_old();
        if !self.read_block(header.as_mut_bytes())? {
            return Ok(None);
        }
        if header.as_bytes().iter().all(|&b| b == 0) {
            if self.read_block(header.as_mut_bytes())? && header.as_bytes().iter().any(|&b| b != 0)
            {
                return Err(malformed("zero block followed by a header"));
            }
            io::copy(&mut self.inner, &mut io::sink())?;
            return Ok(None);
        }
        verify_checksum(&header)?;
        Ok(Some(header))
    }

    /// Fills `buf`, returning false at a clean end-of-file.
    fn read_block(&mut self, buf: &mut [u8]) -> Result<bool> {
        let mut read = 0;
        while read < buf.len() {
            match self.inner.read(&mut buf[read..]) {
                Ok(0) if read == 0 => return Ok(false),
                Ok(0) => return Err(truncated()),
                Ok(n) => read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }
}

/// Data of one member; it ends where the member's data ends.
pub struct MemberData<'a, R> {
    inner: &'a mut R,
    left: &'a mut u64,
}

impl<R: Read> Read for MemberData<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let max = buf
            .len()
            .min(usize::try_from(*self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        if n == 0 && max > 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        *self.left -= n as u64;
        Ok(n)
    }
}

fn malformed(msg: impl Into<String>) -> TarError {
    TarError::Malformed(msg.into())
}

fn truncated() -> TarError {
    malformed("unexpected end of archive")
}

fn check_size(size: u64) -> Result<u64> {
    if size > MAX_SIZE {
        return Err(malformed(format!("member size {size} out of range")));
    }
    Ok(size)
}

fn eof_is_truncated(e: io::Error) -> TarError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        truncated()
    } else {
        e.into()
    }
}

fn cut_nul(mut b: Vec<u8>) -> Vec<u8> {
    if let Some(i) = b.iter().position(|&c| c == 0) {
        b.truncate(i);
    }
    b
}

/// Go accepts a checksum computed over the header bytes as unsigned or as signed values.
fn verify_checksum(header: &Header) -> Result<()> {
    let stored = header
        .cksum()
        .map_err(|_| malformed("unreadable header checksum"))?;
    let (mut unsigned, mut signed) = (0u32, 0i32);
    for (i, &b) in header.as_bytes().iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u32;
        signed += b as i8 as i32;
    }
    if stored != unsigned && stored as i64 != signed as i64 {
        return Err(malformed("header checksum mismatch"));
    }
    Ok(())
}

/// Splits a PAX header body into its records, `<len> <key>=<value>\n` each, where `<len>`
/// counts the whole record. The value runs up to the final newline and may contain more.
fn parse_pax(mut buf: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let bad = || malformed("bad PAX record");
    let mut records = Vec::new();
    while !buf.is_empty() {
        let space = buf.iter().position(|&c| c == b' ').ok_or_else(bad)?;
        let len = std::str::from_utf8(&buf[..space])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > space + 1 && n <= buf.len())
            .ok_or_else(bad)?;
        let (record, rest) = buf.split_at(len);
        let record = record[space + 1..].strip_suffix(b"\n").ok_or_else(bad)?;
        let eq = record.iter().position(|&c| c == b'=').ok_or_else(bad)?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        let nul_in_name = matches!(key, b"path" | b"linkpath") && value.contains(&0);
        if key.is_empty() || key.contains(&0) || nul_in_name {
            return Err(bad());
        }
        records.push((key.to_vec(), value.to_vec()));
        buf = rest;
    }
    Ok(records)
}

/// Applies the PAX records Go's reader interprets; an empty value keeps the header's.
fn apply_pax(member: &mut Member, records: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    for (key, value) in &records {
        if key.starts_with(b"GNU.sparse.") {
            // shortcut: sparse members are rejected, not expanded; they also cannot be served
            // from offsets into the original stream as tar-ref and zran conversions do.
            return Err(TarError::Unsupported(format!(
                "GNU sparse file {} (PAX record {})",
                String::from_utf8_lossy(&member.path),
                String::from_utf8_lossy(key)
            )));
        }
        if value.is_empty() {
            continue;
        }
        let int = || {
            std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| {
                    malformed(format!(
                        "bad PAX {} value {}",
                        String::from_utf8_lossy(key),
                        String::from_utf8_lossy(value)
                    ))
                })
        };
        match key.as_slice() {
            b"path" => member.path = value.clone(),
            b"linkpath" => member.link = value.clone(),
            b"size" => member.size = int()?,
            b"uid" => member.uid = int()?,
            b"gid" => member.gid = int()?,
            _ => {}
        }
    }
    member.pax = records;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A USTAR header block with `size` written as given (octal or base-256).
    fn raw_header(typeflag: u8, name: &[u8], size: &[u8; 12]) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(size);
        h[156] = typeflag;
        h[257..265].copy_from_slice(b"ustar\x0000");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        h
    }

    #[test]
    fn test_member_size_beyond_i64_is_rejected_not_seeked() {
        // Base-256 sizes a seekable skip would turn into a negative or wrapped seek:
        // 2^64 - 512 re-reads the same header forever, u64::MAX wraps the padding sum.
        for size in [
            &[
                0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00,
            ],
            &[
                0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let mut tar = raw_header(b'g', b"pax_global_header", size).to_vec();
            tar.extend_from_slice(&raw_header(b'0', b"a", b"00000000001\0"));
            tar.extend_from_slice(&[b'x'; 512]);
            tar.extend_from_slice(&[0u8; 1024]);
            for seekable in [true, false] {
                let mut members = Members::new(io::Cursor::new(&tar), seekable);
                assert!(
                    matches!(members.next_member(), Err(TarError::Malformed(_))),
                    "size {size:02x?} seekable {seekable}"
                );
            }
        }
        // A PAX `size` record is bounded the same way.
        let records = b"28 size=9223372036854775296\n";
        let mut tar = raw_header(b'x', b"pax", b"00000000034\0").to_vec();
        tar.extend_from_slice(records);
        tar.resize(1024, 0);
        tar.extend_from_slice(&raw_header(b'0', b"a", b"00000000000\0"));
        tar.extend_from_slice(&[0u8; 1024]);
        let mut members = Members::new(io::Cursor::new(&tar), true);
        assert!(matches!(members.next_member(), Err(TarError::Malformed(_))));
    }

    #[test]
    fn test_parse_pax_keeps_newlines_in_values() {
        let records = parse_pax(b"12 path=a\nb\n17 comment=x y=z\n").unwrap();
        assert_eq!(
            records,
            [
                (b"path".to_vec(), b"a\nb".to_vec()),
                (b"comment".to_vec(), b"x y=z".to_vec()),
            ]
        );
    }

    #[test]
    fn test_parse_pax_rejects_bad_framing() {
        for body in [
            &b"99 path=a\n"[..],
            b"11 path=a\n",
            b"9 path=a\nb",
            b"x path=a\n",
            b"9 patha\n\n",
            b"11 path=a\0\n",
        ] {
            assert!(
                parse_pax(body).is_err(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
