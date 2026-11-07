//! zstd random access: frame-boundary tracking while a layer is converted
//! (`ZstdFrameGenerator`), and decoding through `ZstdStreamCursor` / `decompress_context` with
//! both generated contexts and contexts taken verbatim from (untrusted) blob metadata.
//!
//! Input: `n` (1 byte), `n` little-endian u16 chunk sizes, an untrusted context
//! (`in_offset` u64, `in_len` u32), four reads (`offset` u32, `len` u16), then the zstd stream.
#![no_main]

use std::io::{Cursor, Read};

use libfuzzer_sys::fuzz_target;
use nydus_utils::compress::zlib_random::ZranContext;
use nydus_utils::compress::zstd_frames::{
    ZstdFrameGenerator, ZstdFrameReader, ZstdStreamCursor, decompress_context,
};

const MAX_CHUNKS: usize = 8;
const READS: usize = 4;
/// Bound on a read's offset into the untrusted context, so a compression bomb costs at most
/// this much decoding per read.
const MAX_SKIP: u64 = 1 << 24;

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// The blob reader: serve `buf` from `stream` at absolute offset `off`, short at the end.
fn read_at(stream: &[u8], buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    let Some(src) = usize::try_from(off).ok().and_then(|o| stream.get(o..)) else {
        return Ok(0);
    };
    let n = src.len().min(buf.len());
    buf[..n].copy_from_slice(&src[..n]);
    Ok(n)
}

fn context(in_offset: u64, in_len: u32, out_len: u32) -> ZranContext {
    ZranContext {
        in_offset,
        out_offset: 0,
        in_len,
        out_len,
        ctx_byte: 0,
        ctx_bits: 0,
        dict: Vec::new(),
    }
}

fn run(mut input: Input) -> Option<()> {
    let n = (input.take(1)?[0] as usize % MAX_CHUNKS) + 1;
    let sizes = (0..n).map(|_| input.u16()).collect::<Option<Vec<_>>>()?;
    let (raw_in_offset, raw_in_len) = (input.u64()?, input.u32()?);
    let reads = (0..READS)
        .map(|_| Some((input.u32()?, input.u16()?)))
        .collect::<Option<Vec<_>>>()?;
    let stream = input.0;

    // Contexts from blob metadata are not validated before reaching the cursor.
    let untrusted = context(raw_in_offset, raw_in_len, u32::MAX);
    let mut cursor = None;
    for &(offset, len) in &reads {
        let mut out = vec![0u8; len as usize];
        let offset = offset as u64 % MAX_SKIP;
        let _ = ZstdStreamCursor::read(&mut cursor, &untrusted, offset, &mut out, |b, o| {
            read_at(stream, b, o)
        });
    }

    // Conversion: split the decoded stream into chunks and record their contexts.
    let mut reader = ZstdFrameReader::new(Cursor::new(stream), &[]).ok()?;
    let mut generator = ZstdFrameGenerator::new(reader.clone());
    let mut chunks = Vec::new();
    for size in sizes {
        generator.begin_read().ok()?;
        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data).ok()?;
        chunks.push((generator.end_read().ok()?, data));
    }
    generator.finish().ok()?;
    let contexts = generator.get_compression_ctx_array();

    // Serving: every chunk must decode back to the bytes the converter read, both through the
    // in-memory path and through the streaming cursor.
    let mut cursor = None;
    for (info, data) in &chunks {
        let ctx = &contexts[info.ci_index as usize];
        let start = ctx.in_offset as usize;
        let compressed = &stream[start..start + ctx.in_len as usize];
        let mut whole = vec![0u8; ctx.out_len as usize];
        decompress_context(compressed, &mut whole).expect("generated context decodes");
        let range = info.ci_offset as usize..(info.ci_offset + info.ci_len) as usize;
        assert_eq!(&whole[range], &data[..], "in-memory decode differs");

        let mut out = vec![0u8; info.ci_len as usize];
        ZstdStreamCursor::read(&mut cursor, ctx, info.ci_offset as u64, &mut out, |b, o| {
            read_at(stream, b, o)
        })
        .expect("generated context streams");
        assert_eq!(out, *data, "cursor decode differs");
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(Input(data));
});
