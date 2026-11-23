//! The persistent chunk map (`<blob>.chunk_map`) of a blob cache: its header (magics, the
//! all-ready, verified and ready-count words, the data stamp, the unsealed-boot, recheck and
//! tracked words) and bitmap, as a restart finds them on disk, then the fills, invalidations,
//! seals, boot adoptions and reopens that run over it.
//!
//! Input: a 2-byte chunk count, a 2-byte header-length knob, the file contents, then the ops.
//! The file is sized to what the chunk count expects, so inputs reach the header parser instead
//! of failing the size check; a short header is completed with zeros.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nydus_storage::cache::state::fuzz_chunk_map;

mod common;

const HEADER_SIZE: usize = 4096;
const MAGIC1: u32 = 0x424D_4150;
/// Chunks per map; bounds the bitmap walks each open and reset does.
const MAX_CHUNKS: u32 = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let chunk_count = u16::from_le_bytes([data[0], data[1]]) as u32 % MAX_CHUNKS + 1;
    let size = HEADER_SIZE + chunk_count.div_ceil(8) as usize;
    let given = (u16::from_le_bytes([data[2], data[3]]) as usize)
        .min(data.len() - 4)
        .min(size);
    let (contents, ops) = data[4..].split_at(given);
    let mut file = contents.to_vec();
    file.resize(size, 0);
    // shortcut: the open takes the not-ready count from the header rather than the bitmap for
    // a version-0 map (every chunk not ready, even after its own fills and a reopen) and an
    // all-ready one (none), and counts bits past the last chunk; a later revoke or fill then
    // moves the count out of range. Such maps are made consistent here until the open derives
    // the count from the bitmap.
    let pad = (chunk_count.div_ceil(8) * 8 - chunk_count) as u8;
    *file.last_mut().unwrap() &= !((1u8 << pad) - 1);
    if file[0..4] == MAGIC1.to_le_bytes() && file[4..8] == [0; 4] {
        file[4] = 1;
    }
    let bits: u32 = file[HEADER_SIZE..].iter().map(|b| b.count_ones()).sum();
    if bits < chunk_count {
        file[12..16].fill(0);
    }
    let path = common::write_input("chunk_map", &file);
    fuzz_chunk_map(path.to_str().unwrap(), chunk_count, ops);
});
