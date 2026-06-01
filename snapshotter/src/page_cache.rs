// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! EROFS page-cache sharing primitives.
//!
//! The production mount path is feature-gated and Linux-only. This module owns
//! the deterministic, testable pieces that must be correct before privileged
//! mount execution is enabled: a content-addressed backing store and mount plan
//! generation for EROFS metadata + shared backing data.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

/// Shared content-addressed backing store for page-cache sharing.
#[derive(Clone, Debug)]
pub struct SharedContentStore {
    root: PathBuf,
}

/// Stored shared artifact metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SharedContentObject {
    pub digest: String,
    pub path: PathBuf,
    pub size: u64,
}

/// Deterministic mount plan for one EROFS page-cache-sharing mount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErofsPageCacheMountPlan {
    /// EROFS metadata image. This is mounted read-only.
    pub metadata_image: PathBuf,
    /// Directory containing content-addressed backing data shared by mounts.
    pub data_dir: PathBuf,
    /// Directory where the EROFS image should be mounted.
    pub erofs_mountpoint: PathBuf,
    /// Final overlay mountpoint exposed to the container runtime.
    pub overlay_mountpoint: PathBuf,
    /// Overlay workdir for writable snapshots.
    pub work_dir: Option<PathBuf>,
    /// Overlay upperdir for writable snapshots.
    pub upper_dir: Option<PathBuf>,
}

/// One mount/umount command produced by a page-cache sharing mount plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MountCommandPlan {
    pub program: String,
    pub args: Vec<String>,
}

impl SharedContentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store `bytes` by SHA-256 digest and return the stable backing object.
    pub fn put_bytes(&self, bytes: &[u8]) -> Result<SharedContentObject> {
        let digest = sha256_hex(bytes);
        let path = self.object_path(&digest);
        if path.exists() {
            return Ok(SharedContentObject {
                digest,
                path,
                size: bytes.len() as u64,
            });
        }
        let parent = path
            .parent()
            .context("shared content object path has no parent")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create shared content directory {}",
                parent.display()
            )
        })?;
        let tmp = parent.join(format!(".{}.{}.tmp", digest, std::process::id()));
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .with_context(|| format!("failed to create temp object {}", tmp.display()))?;
            file.write_all(bytes)
                .with_context(|| format!("failed to write temp object {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync temp object {}", tmp.display()))?;
        }
        if path.exists() {
            fs::remove_file(&tmp).ok();
        } else {
            fs::rename(&tmp, &path).with_context(|| {
                format!("failed to publish shared content object {}", path.display())
            })?;
        }
        Ok(SharedContentObject {
            digest,
            path,
            size: bytes.len() as u64,
        })
    }

    pub fn object_path(&self, digest: &str) -> PathBuf {
        let prefix = digest.get(..2).unwrap_or("00");
        let suffix = digest.get(2..).unwrap_or(digest);
        self.root.join("sha256").join(prefix).join(suffix)
    }
}

impl ErofsPageCacheMountPlan {
    pub fn new(
        metadata_image: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
        erofs_mountpoint: impl Into<PathBuf>,
        overlay_mountpoint: impl Into<PathBuf>,
    ) -> Self {
        Self {
            metadata_image: metadata_image.into(),
            data_dir: data_dir.into(),
            erofs_mountpoint: erofs_mountpoint.into(),
            overlay_mountpoint: overlay_mountpoint.into(),
            work_dir: None,
            upper_dir: None,
        }
    }

    pub fn with_writable_overlay(
        mut self,
        upper_dir: impl Into<PathBuf>,
        work_dir: impl Into<PathBuf>,
    ) -> Self {
        self.upper_dir = Some(upper_dir.into());
        self.work_dir = Some(work_dir.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        require_absolute("metadata image", &self.metadata_image)?;
        require_absolute("data directory", &self.data_dir)?;
        require_absolute("EROFS mountpoint", &self.erofs_mountpoint)?;
        require_absolute("overlay mountpoint", &self.overlay_mountpoint)?;
        match (&self.upper_dir, &self.work_dir) {
            (Some(upper), Some(work)) => {
                require_absolute("overlay upperdir", upper)?;
                require_absolute("overlay workdir", work)?;
            }
            (None, None) => {}
            _ => bail!("overlay upperdir and workdir must be configured together"),
        }
        Ok(())
    }

    pub fn erofs_mount_options(&self) -> Vec<String> {
        vec!["ro".to_string(), "loop".to_string()]
    }

    pub fn overlay_mount_options(&self) -> Result<Vec<String>> {
        self.validate()?;
        let mut options = vec![
            format!("lowerdir={}", self.erofs_mountpoint.display()),
            "redirect_dir=on".to_string(),
            "metacopy=on".to_string(),
        ];
        if let (Some(upper), Some(work)) = (&self.upper_dir, &self.work_dir) {
            options.push(format!("upperdir={}", upper.display()));
            options.push(format!("workdir={}", work.display()));
        } else {
            options.push("ro".to_string());
        }
        Ok(options)
    }

    pub fn mount_commands(&self) -> Result<Vec<MountCommandPlan>> {
        self.validate()?;
        Ok(vec![
            MountCommandPlan {
                program: "mount".to_string(),
                args: vec![
                    "-t".to_string(),
                    "erofs".to_string(),
                    "-o".to_string(),
                    self.erofs_mount_options().join(","),
                    self.metadata_image.display().to_string(),
                    self.erofs_mountpoint.display().to_string(),
                ],
            },
            MountCommandPlan {
                program: "mount".to_string(),
                args: vec![
                    "-t".to_string(),
                    "overlay".to_string(),
                    "overlay".to_string(),
                    "-o".to_string(),
                    self.overlay_mount_options()?.join(","),
                    self.overlay_mountpoint.display().to_string(),
                ],
            },
        ])
    }

    pub fn unmount_commands(&self) -> Result<Vec<MountCommandPlan>> {
        self.validate()?;
        Ok(vec![
            MountCommandPlan {
                program: "umount".to_string(),
                args: vec![self.overlay_mountpoint.display().to_string()],
            },
            MountCommandPlan {
                program: "umount".to_string(),
                args: vec![self.erofs_mountpoint.display().to_string()],
            },
        ])
    }

    /// Execute the mount plan. This requires Linux privileges and returns a
    /// deterministic unsupported error on non-Linux platforms.
    pub fn mount(&self) -> Result<()> {
        self.validate()?;
        #[cfg(target_os = "linux")]
        {
            self.prepare_mount_dirs()?;
            run_commands(self.mount_commands()?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("EROFS page-cache sharing mounts require Linux")
        }
    }

    /// Unmount the overlay and EROFS mountpoints in dependency order.
    pub fn unmount(&self) -> Result<()> {
        self.validate()?;
        #[cfg(target_os = "linux")]
        {
            run_commands(self.unmount_commands()?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("EROFS page-cache sharing unmounts require Linux")
        }
    }

    #[cfg(target_os = "linux")]
    fn prepare_mount_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("failed to create data dir {}", self.data_dir.display()))?;
        fs::create_dir_all(&self.erofs_mountpoint).with_context(|| {
            format!(
                "failed to create EROFS mountpoint {}",
                self.erofs_mountpoint.display()
            )
        })?;
        fs::create_dir_all(&self.overlay_mountpoint).with_context(|| {
            format!(
                "failed to create overlay mountpoint {}",
                self.overlay_mountpoint.display()
            )
        })?;
        if let Some(upper) = &self.upper_dir {
            fs::create_dir_all(upper)
                .with_context(|| format!("failed to create upperdir {}", upper.display()))?;
        }
        if let Some(work) = &self.work_dir {
            fs::create_dir_all(work)
                .with_context(|| format!("failed to create workdir {}", work.display()))?;
        }
        Ok(())
    }
}

fn require_absolute(name: &str, path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        bail!("{name} must be absolute: {}", path.display())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(target_os = "linux")]
fn run_commands(commands: Vec<MountCommandPlan>) -> Result<()> {
    for command in commands {
        let status = Command::new(&command.program)
            .args(&command.args)
            .status()
            .with_context(|| format!("failed to execute {}", command.program))?;
        if !status.success() {
            bail!(
                "{} {:?} failed with {}",
                command.program,
                command.args,
                status
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_store_deduplicates_by_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = SharedContentStore::new(dir.path().join("shared"));

        let first = store.put_bytes(b"same-content").unwrap();
        let second = store.put_bytes(b"same-content").unwrap();

        assert_eq!(first.digest, second.digest);
        assert_eq!(first.path, second.path);
        assert!(first.path.exists());
        assert_eq!(std::fs::read(first.path).unwrap(), b"same-content");
    }

    #[test]
    fn mount_plan_generates_readonly_overlay_options() {
        let plan = ErofsPageCacheMountPlan::new(
            "/var/lib/nydus/meta/app.erofs",
            "/var/lib/nydus/shared",
            "/run/nydus/erofs/app",
            "/run/nydus/overlay/app",
        );
        assert_eq!(plan.erofs_mount_options(), vec!["ro", "loop"]);
        let options = plan.overlay_mount_options().unwrap();
        assert!(options.contains(&"lowerdir=/run/nydus/erofs/app".to_string()));
        assert!(options.contains(&"ro".to_string()));
    }

    #[test]
    fn mount_plan_generates_linux_mount_commands() {
        let plan = ErofsPageCacheMountPlan::new(
            "/var/lib/nydus/meta/app.erofs",
            "/var/lib/nydus/shared",
            "/run/nydus/erofs/app",
            "/run/nydus/overlay/app",
        );
        let commands = plan.mount_commands().unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].program, "mount");
        assert_eq!(commands[0].args[0..4], ["-t", "erofs", "-o", "ro,loop"]);
        assert_eq!(commands[1].args[0..4], ["-t", "overlay", "overlay", "-o"]);
        assert!(commands[1].args[4].contains("lowerdir=/run/nydus/erofs/app"));

        let unmount = plan.unmount_commands().unwrap();
        assert_eq!(unmount[0].args, vec!["/run/nydus/overlay/app"]);
        assert_eq!(unmount[1].args, vec!["/run/nydus/erofs/app"]);
    }

    #[test]
    fn mount_plan_requires_absolute_paths() {
        let plan = ErofsPageCacheMountPlan::new(
            "relative.erofs",
            "/var/lib/nydus/shared",
            "/run/nydus/erofs/app",
            "/run/nydus/overlay/app",
        );
        assert!(plan.validate().is_err());
    }

    #[test]
    fn writable_overlay_requires_upper_and_work() {
        let plan = ErofsPageCacheMountPlan::new(
            "/var/lib/nydus/meta/app.erofs",
            "/var/lib/nydus/shared",
            "/run/nydus/erofs/app",
            "/run/nydus/overlay/app",
        )
        .with_writable_overlay("/run/nydus/upper/app", "/run/nydus/work/app");

        let options = plan.overlay_mount_options().unwrap();
        assert!(options.contains(&"upperdir=/run/nydus/upper/app".to_string()));
        assert!(options.contains(&"workdir=/run/nydus/work/app".to_string()));
    }
}
