// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Random access into zstd streams at frame boundaries.
//!
//! A zstd decoder can only start at a frame boundary: inside a frame it needs the whole history
//! window (up to 8 MiB for typical image layers) and entropy state, which libzstd cannot save.
//! Frames, however, are independent, and concatenated frames decode as one stream. So the
//! random-access unit is "decode from a frame start until the requested output is covered".
//!
//! The types mirror [`super::zlib_random`]: [`ZstdFrameReader`] decodes a layer while recording
//! where the current frame started, and [`ZstdFrameGenerator`] turns chunk boundaries into
//! [`ZranContext`] records whose dictionary is empty. Multi-frame layers (zstd:chunked, the
//! seekable format) get small contexts; a single-frame layer gets one context spanning the
//! layer, which [`ZstdStreamCursor`] serves by decoding forward.

use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zstd::zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer, get_error_name};

use super::zlib_random::{ZRAN_MAX_CI_ENTRIES, ZranChunkInfo, ZranContext};

const INPUT_BUF_SIZE: usize = 64 * 1024;

/// Largest window accepted, as `log2`: libzstd's default limit for streaming decoders.
const WINDOW_LOG_MAX: u32 = 27;

/// Whether `buf` starts with a zstd frame or a zstd skippable frame.
pub fn is_zstd_magic(buf: &[u8]) -> bool {
    match buf {
        [0x28, 0xb5, 0x2f, 0xfd, ..] => true,
        [b0, 0x2a, 0x4d, 0x18, ..] => b0 & 0xf0 == 0x50,
        _ => false,
    }
}

fn new_dctx() -> io::Result<DCtx<'static>> {
    let mut dctx = DCtx::create();
    dctx.set_parameter(DParameter::WindowLogMax(WINDOW_LOG_MAX))
        .map_err(zstd_error)?;
    Ok(dctx)
}

fn zstd_error(code: usize) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, get_error_name(code))
}

/// One decode step: feed `input`, fill `output`. Returns `(consumed, produced, frame_done)`.
fn decode_step(
    dctx: &mut DCtx<'static>,
    input: &[u8],
    output: &mut [u8],
) -> io::Result<(usize, usize, bool)> {
    let mut inb = InBuffer::around(input);
    let mut outb = OutBuffer::around(output);
    let hint = dctx
        .decompress_stream(&mut outb, &mut inb)
        .map_err(zstd_error)?;
    Ok((inb.pos(), outb.pos(), hint == 0))
}

struct ReaderState<R> {
    reader: R,
    dctx: DCtx<'static>,
    input: Vec<u8>,
    in_start: usize,
    in_end: usize,
    reader_hash: Sha256,
    reader_size: u64,
    eof: bool,
    /// Compressed bytes consumed by the decoder.
    in_pos: u64,
    /// Decompressed bytes produced.
    out_pos: u64,
    /// `(in_pos, out_pos)` where the frame being decoded started, while one is in progress.
    frame: Option<(u64, u64)>,
    /// Compressed end offset of every completed frame, by frame number.
    frame_ends: Vec<u64>,
}

impl<R: Read> ReaderState<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_start == self.in_end && !self.eof {
                let n = self.reader.read(&mut self.input)?;
                self.reader_hash.update(&self.input[..n]);
                self.reader_size += n as u64;
                (self.in_start, self.in_end, self.eof) = (0, n, n == 0);
            }
            let exhausted = self.in_start == self.in_end;
            if exhausted && self.frame.is_none() {
                return Ok(0);
            }
            self.frame.get_or_insert((self.in_pos, self.out_pos));
            // With the input exhausted the decoder may still hold decoded bytes to flush.
            let (consumed, produced, frame_done) =
                decode_step(&mut self.dctx, &self.input[self.in_start..self.in_end], buf)?;
            if exhausted && produced == 0 && !frame_done {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zstd stream ends inside a frame",
                ));
            }
            self.in_start += consumed;
            self.in_pos += consumed as u64;
            self.out_pos += produced as u64;
            if frame_done {
                self.frame = None;
                self.frame_ends.push(self.in_pos);
            }
            // Skippable frames and header bytes produce nothing; keep decoding.
            if produced > 0 {
                return Ok(produced);
            }
        }
    }
}

/// A zstd decoding reader for OCI layer tarballs that tracks frame boundaries. Clones share
/// the same decoder.
pub struct ZstdFrameReader<R> {
    inner: Arc<Mutex<ReaderState<R>>>,
}

impl<R> Clone for ZstdFrameReader<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R> ZstdFrameReader<R> {
    /// Create a reader decoding `reader`, whose first bytes are `initial` (already read by a
    /// format sniffer).
    pub fn new(reader: R, initial: &[u8]) -> io::Result<Self> {
        let mut input = vec![0u8; INPUT_BUF_SIZE.max(initial.len())];
        input[..initial.len()].copy_from_slice(initial);
        let mut reader_hash = Sha256::new();
        reader_hash.update(initial);
        let state = ReaderState {
            reader,
            dctx: new_dctx()?,
            input,
            in_start: 0,
            in_end: initial.len(),
            reader_hash,
            reader_size: initial.len() as u64,
            eof: false,
            in_pos: 0,
            out_pos: 0,
            frame: None,
            frame_ends: Vec::new(),
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
        })
    }

    /// Size of the compressed data read so far.
    pub fn get_data_size(&self) -> u64 {
        self.inner.lock().unwrap().reader_size
    }

    /// SHA-256 of the compressed data read so far.
    pub fn get_data_digest(&self) -> Sha256 {
        self.inner.lock().unwrap().reader_hash.clone()
    }

    /// `(in_pos, out_pos)`: compressed bytes consumed and decompressed bytes produced.
    fn position(&self) -> (u64, u64) {
        let state = self.inner.lock().unwrap();
        (state.in_pos, state.out_pos)
    }

    /// Start of the frame the next decompressed byte belongs to, as `(in_pos, out_pos)`.
    fn frame_start(&self) -> (u64, u64) {
        let state = self.inner.lock().unwrap();
        state.frame.unwrap_or((state.in_pos, state.out_pos))
    }

    /// Number of the frame holding the last decompressed byte produced.
    fn last_output_frame(&self) -> usize {
        let state = self.inner.lock().unwrap();
        match state.frame {
            Some(_) => state.frame_ends.len(),
            None => state.frame_ends.len().saturating_sub(1),
        }
    }

    /// Compressed end offset of frame `frame`, once it completed.
    fn frame_end(&self, frame: usize) -> Option<u64> {
        self.inner.lock().unwrap().frame_ends.get(frame).copied()
    }
}

impl<R: Read> Read for ZstdFrameReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
}

/// Generates random-access contexts for a zstd stream: each context starts at a frame boundary
/// and extends to the end of the last chunk assigned to it.
pub struct ZstdFrameGenerator<R> {
    reader: ZstdFrameReader<R>,
    ci_array: Vec<ZranContext>,
    /// Per context, the frame holding the end of its last chunk. A context's compressed range
    /// ends with that frame: libzstd may report input as consumed only after it already
    /// returned the output it decodes to, so the consumed count at a chunk end can fall short.
    ci_last_frame: Vec<usize>,
    finished: bool,
    curr_ci_idx: Option<usize>,
    curr_out_offset: u64,
    curr_in_offset: u64,
}

impl<R: Read> ZstdFrameGenerator<R> {
    pub fn new(reader: ZstdFrameReader<R>) -> Self {
        Self {
            reader,
            ci_array: Vec::new(),
            ci_last_frame: Vec::new(),
            finished: false,
            curr_ci_idx: None,
            curr_out_offset: 0,
            curr_in_offset: 0,
        }
    }

    /// Begin a chunk at the current read position; returns its context index.
    pub fn begin_read(&mut self) -> io::Result<u32> {
        let (frame_in, frame_out) = self.reader.frame_start();
        let idx = match self.curr_ci_idx {
            Some(idx) if self.ci_array[idx].in_offset == frame_in => idx,
            _ => {
                if self.ci_array.len() >= ZRAN_MAX_CI_ENTRIES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many zstd context entries",
                    ));
                }
                self.ci_array.push(ZranContext {
                    in_offset: frame_in,
                    out_offset: frame_out,
                    in_len: 0,
                    out_len: 0,
                    ctx_byte: 0,
                    ctx_bits: 0,
                    dict: Vec::new(),
                });
                self.ci_last_frame.push(0);
                self.ci_array.len() - 1
            }
        };
        self.curr_ci_idx = Some(idx);
        (self.curr_in_offset, self.curr_out_offset) = self.reader.position();
        Ok(idx as u32)
    }

    /// Finish the chunk begun by [`Self::begin_read`] at the current read position.
    pub fn end_read(&mut self) -> io::Result<ZranChunkInfo> {
        let idx = self.curr_ci_idx.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid compression state")
        })?;
        let (in_pos, out_pos) = self.reader.position();
        let too_large = |_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "zstd frame decodes to more than 4 GiB; random access needs smaller frames",
            )
        };
        let ctx = &mut self.ci_array[idx];
        let info = ZranChunkInfo {
            ci_index: idx as u32,
            ci_offset: u32::try_from(self.curr_out_offset - ctx.out_offset).map_err(too_large)?,
            ci_len: u32::try_from(out_pos - self.curr_out_offset).map_err(too_large)?,
            in_pos: self.curr_in_offset,
            in_len: u32::try_from(in_pos - self.curr_in_offset).map_err(too_large)?,
        };
        ctx.out_len = u32::try_from(out_pos - ctx.out_offset).map_err(too_large)?;
        self.ci_last_frame[idx] = self.reader.last_output_frame();
        Ok(info)
    }

    /// Read the stream to its end and fix every context's compressed size, so the reader's
    /// digest and size cover the whole input. Idempotent.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        io::copy(&mut self.reader, &mut io::sink())?;
        for (ctx, &frame) in self.ci_array.iter_mut().zip(&self.ci_last_frame) {
            let end = self.reader.frame_end(frame).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "zstd frame never completed")
            })?;
            ctx.in_len = u32::try_from(end - ctx.in_offset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "zstd context spans more than 4 GiB of compressed data",
                )
            })?;
        }
        self.finished = true;
        Ok(())
    }

    /// The generated contexts; complete only after [`Self::finish`].
    pub fn get_compression_ctx_array(&self) -> &[ZranContext] {
        &self.ci_array
    }

    /// Reader decoding the stream for the tar parser.
    pub fn reader(&self) -> ZstdFrameReader<R> {
        self.reader.clone()
    }
}

/// Decode a whole context: `input` holds the context's compressed bytes (starting at a frame
/// start), and `output` is filled completely.
pub fn decompress_context(input: &[u8], output: &mut [u8]) -> io::Result<()> {
    let mut dctx = new_dctx()?;
    let (mut in_pos, mut out_pos) = (0, 0);
    while out_pos < output.len() {
        let (consumed, produced, _) =
            decode_step(&mut dctx, &input[in_pos..], &mut output[out_pos..])?;
        // No progress with the input exhausted: nothing is left to flush either.
        if consumed == 0 && produced == 0 && in_pos == input.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zstd context ends before its decoded size",
            ));
        }
        in_pos += consumed;
        out_pos += produced;
    }
    Ok(())
}

/// A forward-only decoding position inside one zstd context, for contexts too large to decode
/// in memory at once. Reads at or after the position continue from it; earlier reads restart
/// at the context start.
pub struct ZstdStreamCursor {
    ctx_in_offset: u64,
    ctx_in_end: u64,
    dctx: DCtx<'static>,
    /// Absolute compressed position of the next byte to read from the backend.
    in_pos: u64,
    /// Decompressed position, relative to the context start.
    out_pos: u64,
    input: Vec<u8>,
    in_start: usize,
    in_end: usize,
    scratch: Vec<u8>,
}

impl ZstdStreamCursor {
    const READ_SIZE: usize = 1024 * 1024;

    fn new(ctx: &ZranContext) -> io::Result<Self> {
        Ok(Self {
            ctx_in_offset: ctx.in_offset,
            ctx_in_end: ctx.in_offset + ctx.in_len as u64,
            dctx: new_dctx()?,
            in_pos: ctx.in_offset,
            out_pos: 0,
            input: vec![0u8; Self::READ_SIZE],
            in_start: 0,
            in_end: 0,
            scratch: vec![0u8; Self::READ_SIZE],
        })
    }

    /// Fill `output` with the context's decompressed bytes at `offset` (relative to the context
    /// start), reading compressed bytes with `read_at(buf, blob_offset)`.
    pub fn read(
        cursor: &mut Option<Self>,
        ctx: &ZranContext,
        offset: u64,
        output: &mut [u8],
        mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        let reusable = cursor
            .as_ref()
            .is_some_and(|c| c.ctx_in_offset == ctx.in_offset && c.out_pos <= offset);
        if !reusable {
            *cursor = Some(Self::new(ctx)?);
        }
        let this = cursor.as_mut().unwrap();
        let result = this.read_forward(offset, output, &mut read_at);
        if result.is_err() {
            // The decoder state is unknown after a failure.
            *cursor = None;
        }
        result
    }

    fn read_forward(
        &mut self,
        offset: u64,
        output: &mut [u8],
        read_at: &mut impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        let mut scratch = std::mem::take(&mut self.scratch);
        let mut skipped = Ok(());
        while skipped.is_ok() && self.out_pos < offset {
            let want = ((offset - self.out_pos) as usize).min(scratch.len());
            skipped = self.decode_into(&mut scratch[..want], read_at);
        }
        self.scratch = scratch;
        skipped?;
        self.decode_into(output, read_at)
    }

    /// Decode exactly `output.len()` bytes at the current position.
    fn decode_into(
        &mut self,
        output: &mut [u8],
        read_at: &mut impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        let mut filled = 0;
        while filled < output.len() {
            let want = ((self.ctx_in_end - self.in_pos) as usize).min(self.input.len());
            if self.in_start == self.in_end && want > 0 {
                let n = read_at(&mut self.input[..want], self.in_pos)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "backend returned no data inside a zstd context",
                    ));
                }
                (self.in_start, self.in_end) = (0, n);
                self.in_pos += n as u64;
            }
            let (consumed, produced, _) = decode_step(
                &mut self.dctx,
                &self.input[self.in_start..self.in_end],
                &mut output[filled..],
            )?;
            // No progress with the context exhausted: nothing is left to flush either.
            if consumed == 0 && produced == 0 && self.in_start == self.in_end {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zstd context ends before the requested data",
                ));
            }
            self.in_start += consumed;
            filled += produced;
            self.out_pos += produced as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap()
    }

    fn skippable(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x50, 0x2a, 0x4d, 0x18];
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Reads `chunks` (sizes) through a generator, returning the chunk infos and contexts.
    fn chunk_stream(stream: &[u8], chunks: &[usize]) -> (Vec<ZranChunkInfo>, Vec<ZranContext>) {
        let mut reader = ZstdFrameReader::new(Cursor::new(stream.to_vec()), &[]).unwrap();
        let mut generator = ZstdFrameGenerator::new(reader.clone());
        let mut infos = Vec::new();
        for &size in chunks {
            generator.begin_read().unwrap();
            let mut buf = vec![0u8; size];
            reader.read_exact(&mut buf).unwrap();
            infos.push(generator.end_read().unwrap());
        }
        generator.finish().unwrap();
        let contexts = generator
            .get_compression_ctx_array()
            .iter()
            .map(|c| ZranContext {
                in_offset: c.in_offset,
                out_offset: c.out_offset,
                in_len: c.in_len,
                out_len: c.out_len,
                ctx_byte: 0,
                ctx_bits: 0,
                dict: Vec::new(),
            })
            .collect();
        (infos, contexts)
    }

    /// Decode chunk `info` from `stream` through its context.
    fn decode_chunk(stream: &[u8], ctx: &ZranContext, info: &ZranChunkInfo) -> Vec<u8> {
        let input = &stream[ctx.in_offset as usize..(ctx.in_offset + ctx.in_len as u64) as usize];
        let mut out = vec![0u8; ctx.out_len as usize];
        decompress_context(input, &mut out).unwrap();
        out[info.ci_offset as usize..(info.ci_offset + info.ci_len) as usize].to_vec()
    }

    #[test]
    fn detects_frame_and_skippable_magics() {
        assert!(is_zstd_magic(&frame(b"x")));
        assert!(is_zstd_magic(&skippable(b"meta")));
        assert!(is_zstd_magic(&[0x5f, 0x2a, 0x4d, 0x18]));
        assert!(!is_zstd_magic(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(!is_zstd_magic(b"ustar"));
    }

    #[test]
    fn contexts_start_at_frame_boundaries_and_extend_within_a_frame() {
        let (a, b, c) = (pattern(3000, 1), pattern(5000, 2), pattern(2000, 3));
        let (fa, fb) = (frame(&a), frame(&b));
        let mut stream = fa.clone();
        stream.extend_from_slice(&skippable(b"toc"));
        stream.extend_from_slice(&fb);
        stream.extend_from_slice(&frame(&c));
        let plain = [a, b, c].concat();

        // Two chunks inside frame a, one spanning a→b, one inside b, one spanning b→c.
        let (infos, contexts) = chunk_stream(&stream, &[1000, 1000, 2000, 3000, 3000]);
        let indexes: Vec<u32> = infos.iter().map(|i| i.ci_index).collect();
        assert_eq!(indexes, vec![0, 0, 0, 1, 1]);
        assert_eq!(contexts[0].in_offset, 0);
        // Frame b's context starts after the skippable frame.
        assert_eq!(
            contexts[1].in_offset,
            (fa.len() + skippable(b"toc").len()) as u64
        );
        assert_eq!(contexts[1].out_offset, 3000);

        let mut pos = 0;
        for info in &infos {
            let got = decode_chunk(&stream, &contexts[info.ci_index as usize], info);
            assert_eq!(got, plain[pos..pos + info.ci_len as usize]);
            pos += info.ci_len as usize;
        }
    }

    #[test]
    fn reader_digest_and_size_cover_the_consumed_input() {
        let stream = frame(&pattern(10_000, 7));
        let mut reader =
            ZstdFrameReader::new(Cursor::new(stream[4..].to_vec()), &stream[..4]).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, pattern(10_000, 7));
        assert_eq!(reader.get_data_size(), stream.len() as u64);
        assert_eq!(
            reader.get_data_digest().finalize().as_slice(),
            Sha256::digest(&stream).as_slice()
        );
    }

    #[test]
    fn truncated_frames_fail() {
        let stream = frame(&pattern(100_000, 9));
        let mut reader =
            ZstdFrameReader::new(Cursor::new(stream[..stream.len() - 8].to_vec()), &[]).unwrap();
        let mut out = Vec::new();
        assert!(reader.read_to_end(&mut out).is_err());
    }

    #[test]
    fn stream_cursor_reads_forward_and_restarts_behind_its_position() {
        let plain = pattern(3 * 1024 * 1024, 5);
        let stream = frame(&plain);
        let ctx = ZranContext {
            in_offset: 0,
            out_offset: 0,
            in_len: stream.len() as u32,
            out_len: plain.len() as u32,
            ctx_byte: 0,
            ctx_bits: 0,
            dict: Vec::new(),
        };
        let reads = std::cell::Cell::new(0u64);
        let read_at = |buf: &mut [u8], off: u64| {
            reads.set(reads.get() + buf.len() as u64);
            let off = off as usize;
            let n = buf.len().min(stream.len() - off);
            buf[..n].copy_from_slice(&stream[off..off + n]);
            io::Result::Ok(n)
        };

        let mut cursor = None;
        let mut buf = vec![0u8; 4096];
        for offset in [2 * 1024 * 1024, 2 * 1024 * 1024 + 4096, 100, 2_500_000] {
            ZstdStreamCursor::read(&mut cursor, &ctx, offset, &mut buf, read_at).unwrap();
            assert_eq!(buf, plain[offset as usize..offset as usize + 4096]);
        }
        // Forward reads reuse the decoder: the first two reads fetch the input once, the
        // backward read restarts at the context start.
        assert!(reads.get() < 3 * stream.len() as u64);

        let mut past_end = vec![0u8; 4096];
        let end = plain.len() as u64 - 100;
        assert!(ZstdStreamCursor::read(&mut cursor, &ctx, end, &mut past_end, read_at).is_err());
        assert!(cursor.is_none(), "a failed read drops the decoder state");
    }
}
