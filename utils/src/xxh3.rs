// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Fast non-cryptographic chunk integrity checks based on XXH3.

use xxhash_rust::xxh3::xxh3_64;

/// Compute an XXH3-64 checksum for `buf`.
#[inline]
pub fn checksum(buf: &[u8]) -> u64 {
    xxh3_64(buf)
}

/// Check whether `buf` matches the expected XXH3-64 checksum.
#[inline]
pub fn verify(buf: &[u8], expected: u64) -> bool {
    checksum(buf) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxh3_checksum_is_stable() {
        let data = b"The quick brown fox jumps over the lazy dog";

        assert_eq!(checksum(data), checksum(data));
        assert_ne!(
            checksum(data),
            checksum(b"The quick brown fox jumps over the lazy cog")
        );
        assert!(verify(data, checksum(data)));
    }

    #[test]
    fn test_xxh3_empty_input_matches_reference_vector() {
        assert_eq!(checksum(b""), 0x2d06800538d394c2);
        assert!(verify(b"", 0x2d06800538d394c2));
    }

    #[test]
    fn test_xxh3_verify_rejects_mismatched_checksum() {
        let data = b"nydus chunk payload";
        let expected = checksum(data);

        assert!(!verify(data, expected ^ 1));
        assert!(!verify(b"nydus chunk payloaD", expected));
    }
}
