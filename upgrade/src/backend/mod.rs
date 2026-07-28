// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::{io, os::fd::RawFd};

pub mod unix_domain_socket;

#[derive(thiserror::Error, Debug)]
pub enum StorageBackendErr {
    #[error("failed to create UnixStream, {0}")]
    CreateUnixStream(#[source] io::Error),
    #[error("failed to send fd over UnixStream, {0}")]
    SendFd(#[source] io::Error),
    #[error("failed to receive fd over UnixStream, {0}")]
    RecvFd(#[source] io::Error),
    #[error("no enough fds")]
    NoEnoughFds,
}

/// Specialized `Result` for the hot-upgrade state backends.
///
/// Deliberately not named `Result`: a module-level alias of that name shadows
/// `std::result::Result` for every item in the file, so a signature reading `Result<T>` says
/// nothing about which error it carries.
pub type StorageBackendResult<T> = std::result::Result<T, StorageBackendErr>;

/// StorageBackend trait is used to save and restore the dev fds and daemon state data for online upgrade.
pub trait StorageBackend: Send + Sync {
    /// Save the dev fds and daemon state data for online upgrade.
    /// Returns the length of bytes of state data.
    fn save(&mut self, fds: &[RawFd], data: &[u8]) -> StorageBackendResult<usize>;

    /// Restore the dev fds and daemon state data for online upgrade.
    /// Returns the fds and state data
    fn restore(&mut self) -> StorageBackendResult<(Vec<RawFd>, Vec<u8>)>;
}

#[cfg(test)]
mod test {

    #[test]
    fn test_storage_backend() {
        use std::os::fd::RawFd;

        use crate::backend::{StorageBackend, StorageBackendResult};

        #[derive(Default)]
        struct TestStorageBackend {
            fds: Vec<RawFd>,
            data: Vec<u8>,
        }

        impl StorageBackend for TestStorageBackend {
            fn save(&mut self, fds: &[RawFd], data: &[u8]) -> StorageBackendResult<usize> {
                self.fds = Vec::new();
                fds.iter().for_each(|fd| self.fds.push(*fd));

                self.data = vec![0u8; data.len()];
                self.data.clone_from_slice(data);

                Ok(self.data.len())
            }

            fn restore(&mut self) -> StorageBackendResult<(Vec<RawFd>, Vec<u8>)> {
                Ok((self.fds.clone(), self.data.clone()))
            }
        }

        const FDS_LEN: usize = 10;
        const DATA_LEN: usize = 5;
        let fds = [5 as RawFd; FDS_LEN];
        let data: [u8; DATA_LEN] = [7, 8, 9, 10, 12];

        let mut backend: Box<dyn StorageBackend> = Box::<TestStorageBackend>::default();
        let saved_data_len = backend.save(&fds, &data).unwrap();
        assert_eq!(saved_data_len, DATA_LEN);

        let (restored_fds, restored_data) = backend.restore().unwrap();
        assert_eq!(restored_data, data);
        assert_eq!(restored_fds, fds);
    }
}
