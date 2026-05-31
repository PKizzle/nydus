// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use libc::dev_t;

// RAFS images are consumed by Linux runtimes even when the image is built on macOS, so encode
// device IDs with the Linux kernel dev_t layout instead of the build host's libc layout.
pub fn makedev(major: u64, minor: u64) -> dev_t {
    let dev = ((major & 0x0000_0fff) << 8)
        | ((major & 0xffff_f000) << 32)
        | (minor & 0x0000_00ff)
        | ((minor & 0xffff_ff00) << 12);
    dev as dev_t
}

pub fn major_dev(dev: u64) -> u64 {
    ((dev >> 8) & 0x0000_0fff) | ((dev >> 32) & 0xffff_f000)
}

pub fn minor_dev(dev: u64) -> u64 {
    (dev & 0x0000_00ff) | ((dev >> 12) & 0xffff_ff00)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dev() {
        let major: u64 = 0xffff_ffff_ffff_abcd;
        let minor: u64 = 0xffff_ffff_abcd_ffff;
        let dev = makedev(major, minor) as u64;
        assert_eq!(major_dev(dev), 0xffff_abcd);
        assert_eq!(minor_dev(dev), 0xabcd_ffff);
    }

    #[test]
    fn test_makedev() {
        let major: u64 = 8;
        let minor: u64 = 1;
        let dev = makedev(major, minor) as u64;
        assert_eq!(major_dev(dev), major);
        assert_eq!(minor_dev(dev), minor);
    }

    #[test]
    fn test_makedev_linux_encoding_on_all_hosts() {
        let dev = makedev(255, 33) as u32;
        assert_eq!(dev, 65313);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_makedev_large_values() {
        let major: u64 = 0xfff;
        let minor: u64 = 0xfffff;
        let dev = makedev(major, minor) as u64;
        assert_eq!(major_dev(dev), major & 0xfff);
        assert_eq!(minor_dev(dev), minor & 0xfffff);
    }
}
