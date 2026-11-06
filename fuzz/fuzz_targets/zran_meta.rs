//! Blob compression-context (`<blob>.blob.meta`) tables of a zran blob: the chunk-info array,
//! the zran inflate-context table and its dictionary table, as loaded by
//! `BlobCompressionContextInfo::new`, then every chunk's context decoded with `ZranDecoder` the
//! way the storage layer does.
//!
//! Input: a 24-byte prefix of knobs followed by the uncompressed table area. The harness builds
//! the 4 KiB trailing header (and the matching `BlobInfo`) from the knobs, so inputs reach the
//! table parsers instead of failing the header's equality checks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nydus_storage::RAFS_MAX_CHUNK_SIZE;
use nydus_storage::device::{BlobFeatures, BlobInfo};
use nydus_storage::meta::BlobCompressionContextInfo;
use nydus_utils::compress::zlib_random::ZranDecoder;

mod common;

const BLOB_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEADER_SIZE: usize = 4096;
const CCT_MAGIC: u32 = 0xb10b_b10b;
const CHUNK_INFO_V2_SIZE: u64 = 24;
/// Chunks resolved per input.
const MAX_CHUNKS: u32 = 256;
/// Largest context decoded; production allows `RAFS_MAX_CHUNK_SIZE`, which is too slow per run.
const MAX_DECODE: u64 = 1 << 20;

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let (knobs, table) = data.split_at(24);
    let chunk_count = le_u32(&knobs[0..]);
    let features = (BlobFeatures::from_bits_truncate(le_u32(&knobs[4..]))
        | BlobFeatures::ZRAN
        | BlobFeatures::CHUNK_INFO_V2)
        .difference(BlobFeatures::BATCH | BlobFeatures::IS_CHUNKDICT_GENERATED);
    let zran_count = le_u32(&knobs[8..]);
    let zran_size = le_u32(&knobs[12..]) as u64;
    let blob_size = le_u64(&knobs[16..]);

    // Header layout: `BlobCompressionContextHeader` in storage/src/meta/mod.rs.
    let info_size = table.len() as u64;
    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(&CCT_MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&features.bits().to_le_bytes());
    header[12..16].copy_from_slice(&chunk_count.to_le_bytes());
    header[24..32].copy_from_slice(&info_size.to_le_bytes());
    header[32..40].copy_from_slice(&info_size.to_le_bytes());
    let zran_offset = chunk_count as u64 * CHUNK_INFO_V2_SIZE;
    header[40..48].copy_from_slice(&zran_offset.to_le_bytes());
    header[48..56].copy_from_slice(&zran_size.to_le_bytes());
    header[56..60].copy_from_slice(&zran_count.to_le_bytes());
    header[HEADER_SIZE - 4..].copy_from_slice(&CCT_MAGIC.to_le_bytes());

    let mut file = table.to_vec();
    file.resize(table.len().div_ceil(4096) * 4096, 0);
    file.extend_from_slice(&header);
    let meta_path = common::write_input(&format!("{BLOB_ID}.blob.meta"), &file);
    let blob_path = meta_path.with_file_name(BLOB_ID);

    let mut blob_info = BlobInfo::new(
        0,
        BLOB_ID.to_string(),
        blob_size,
        blob_size,
        0x10_0000,
        chunk_count,
        features,
    );
    blob_info.set_blob_meta_info(0, info_size, info_size, 0);

    let Ok(meta) =
        BlobCompressionContextInfo::new(blob_path.to_str().unwrap(), &blob_info, None, false)
    else {
        return;
    };
    let _ = meta.get_chunks_uncompressed(0, blob_size, 0);
    let _ = meta.get_chunks_compressed(0, blob_size, 0, false);

    let mut decoded = None;
    for idx in 0..(meta.get_chunk_count() as u32).min(MAX_CHUNKS) {
        let _ = meta.get_uncompressed_offset(idx as usize);
        let _ = meta.get_compressed_size(idx);
        let _ = meta.get_zran_offset(idx);
        let Ok(zran_idx) = meta.get_zran_index(idx) else {
            continue;
        };
        if decoded == Some(zran_idx) {
            continue;
        }
        decoded = Some(zran_idx);
        let Ok((ctx, dict)) = meta.get_zran_context(zran_idx) else {
            continue;
        };
        // The guards `decompress_zran` applies before decoding; the table bytes stand in for
        // the compressed blob.
        let end = ctx.in_offset.checked_add(ctx.in_len as u64);
        if end.is_none_or(|end| end > table.len() as u64)
            || ctx.out_len as u64 > RAFS_MAX_CHUNK_SIZE.min(MAX_DECODE)
        {
            continue;
        }
        let input = &table[ctx.in_offset as usize..end.unwrap() as usize];
        let mut output = vec![0u8; ctx.out_len as usize];
        if let Ok(mut decoder) = ZranDecoder::new() {
            let _ = decoder.uncompress(&ctx, Some(dict), input, &mut output);
        }
    }
});
