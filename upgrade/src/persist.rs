// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::{any::TypeId, collections::HashMap};

use dbs_snapshot::Snapshot;
use versionize::{VersionMap, Versionize};

/// A list of versions.
type Versions = Vec<HashMap<TypeId, u16>>;

/// Error codes for snapshotting daemon state across a hot upgrade.
///
/// `dbs_snapshot`'s error type does not implement `std::error::Error`, so it cannot be a
/// `#[source]`; its `Debug` rendering is carried in the message instead -- which is what the
/// previous `io::Error::other(format!("...{:?}", e))` did, minus the `io::Error` in the middle.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// The state could not be serialized into a snapshot.
    #[error("Failed to save snapshot: {0}")]
    Save(String),
    /// The snapshot could not be deserialized back into state.
    #[error("Failed to load snapshot: {0}")]
    Restore(String),
}

/// Specialized `Result` for state snapshotting.
pub type PersistResult<T> = std::result::Result<T, PersistError>;

/// A trait for snapshotting.
/// This trait is used to save and restore a struct
/// which implements `versionize::Versionize`.
pub trait Snapshotter: Versionize + Sized + Debug {
    /// Returns a list of versions.
    fn get_versions() -> Versions;

    /// Returns a `VersionMap` with the versions defined by `get_versions`.
    fn new_version_map() -> VersionMap {
        let mut version_map = VersionMap::new();
        for (idx, map) in Self::get_versions().into_iter().enumerate() {
            if idx > 0 {
                version_map.new_version();
            }
            for (type_id, version) in map {
                version_map.set_type_version(type_id, version);
            }
        }
        version_map
    }

    /// Returns a new `Snapshot` with the versions defined by `get_versions`.
    fn new_snapshot() -> Snapshot {
        let vm = Self::new_version_map();
        let target_version = vm.latest_version();
        Snapshot::new(vm, target_version)
    }

    /// Saves the struct to a `Vec<u8>`.
    fn save(&self) -> PersistResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut snapshot = Self::new_snapshot();
        snapshot
            .save(&mut buf, self)
            .map_err(|e| PersistError::Save(format!("{:?}", e)))?;

        Ok(buf)
    }

    /// Restores the struct from a `Vec<u8>`.
    fn restore(buf: &mut Vec<u8>) -> PersistResult<Self> {
        match Snapshot::load(&mut buf.as_slice(), buf.len(), Self::new_version_map()) {
            Ok((o, _)) => Ok(o),
            Err(e) => Err(PersistError::Restore(format!("{:?}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use versionize::VersionizeResult;
    use versionize_derive::Versionize;

    // Create a simple test struct that implements Snapshotter
    #[derive(Debug, Clone, PartialEq, Versionize)]
    struct TestStruct {
        #[version(start = 1, default_fn = "default_value")]
        value: u64,
        #[version(start = 1, default_fn = "default_name")]
        name: String,
    }

    impl TestStruct {
        #[allow(dead_code)]
        fn default_value(_: u16) -> u64 {
            0
        }

        #[allow(dead_code)]
        fn default_name(_: u16) -> String {
            String::new()
        }
    }

    impl Snapshotter for TestStruct {
        fn get_versions() -> Versions {
            vec![HashMap::new()]
        }
    }

    #[test]
    fn test_snapshotter_new_version_map() {
        let version_map = TestStruct::new_version_map();
        assert_eq!(version_map.latest_version(), 1);
    }

    #[test]
    fn test_snapshotter_new_version_map_multiple_versions() {
        // Create a struct with multiple version maps
        #[derive(Debug, Clone, PartialEq, Versionize)]
        struct MultiVersionStruct {
            #[version(start = 1, default_fn = "default_value")]
            value: u64,
        }

        impl MultiVersionStruct {
            #[allow(dead_code)]
            fn default_value(_: u16) -> u64 {
                0
            }
        }

        impl Snapshotter for MultiVersionStruct {
            fn get_versions() -> Versions {
                vec![HashMap::new(), HashMap::new(), HashMap::new()]
            }
        }

        let version_map = MultiVersionStruct::new_version_map();
        assert_eq!(version_map.latest_version(), 3);
    }

    #[test]
    fn test_snapshotter_new_snapshot() {
        let _snapshot = TestStruct::new_snapshot();
        // Just verify it creates without panicking
    }

    #[test]
    fn test_snapshotter_save_and_restore() {
        let original = TestStruct {
            value: 42,
            name: "test".to_string(),
        };

        let buf = original.save().unwrap();
        assert!(!buf.is_empty());

        let mut restore_buf = buf.clone();
        let restored = TestStruct::restore(&mut restore_buf).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_snapshotter_save_empty_values() {
        let original = TestStruct {
            value: 0,
            name: String::new(),
        };

        let buf = original.save().unwrap();
        assert!(!buf.is_empty());

        let mut restore_buf = buf.clone();
        let restored = TestStruct::restore(&mut restore_buf).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_snapshotter_save_large_values() {
        let original = TestStruct {
            value: u64::MAX,
            name: "a".repeat(1000),
        };

        let buf = original.save().unwrap();
        assert!(!buf.is_empty());

        let mut restore_buf = buf.clone();
        let restored = TestStruct::restore(&mut restore_buf).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_snapshotter_restore_invalid_data() {
        let mut invalid_buf = vec![0xFF; 10];
        let result = TestStruct::restore(&mut invalid_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshotter_restore_empty_buffer() {
        let mut empty_buf = Vec::new();
        let result = TestStruct::restore(&mut empty_buf);
        assert!(result.is_err());
    }
}
