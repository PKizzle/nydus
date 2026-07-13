// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! `nydusify mount`: pull a nydus image's bootstrap, spawn a foreground
//! `nydusd` FUSE daemon backed by the image's registry, and hold the mount
//! until the process receives SIGINT/SIGTERM — then unmount and stop nydusd.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use registry_client::types::Manifest;
use registry_client::{ImageReference, RegistryClient};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::cli::{BackendType, MountArgs};
use crate::engine::manifest::validate_nydus_manifest;
use crate::engine::oci::{client_options, fetch_platform_manifest};

use super::common::resolve_backend_config;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MountPlan {
    pub target: String,
    pub backend_type: String,
    pub mount_path: PathBuf,
    pub prefetch: bool,
    pub platform: String,
}

pub async fn run(args: MountArgs) -> Result<()> {
    let plan = plan(&args)?;
    if plan.backend_type != "registry" {
        bail!(
            "--backend-type {} is not yet supported by `nydusify mount`; only `registry` is implemented (follow-up)",
            plan.backend_type
        );
    }

    let target_ref = ImageReference::parse(&plan.target)
        .with_context(|| format!("parse --target {}", plan.target))?;
    let client = RegistryClient::new(
        &target_ref.api_host,
        client_options(args.target_insecure, false),
    )
    .context("build registry client")?;

    // Resolve to a single-platform nydus image manifest and locate the bootstrap.
    let fetched = fetch_platform_manifest(
        &client,
        &target_ref.repo,
        target_ref.manifest_reference(),
        &plan.platform,
    )
    .await
    .with_context(|| format!("fetch manifest {target_ref}"))?;
    let manifest: Manifest =
        serde_json::from_slice(&fetched.bytes).context("parse image manifest")?;
    let bootstrap = validate_nydus_manifest(&manifest)
        .with_context(|| format!("{target_ref} is not a valid nydus image"))?;

    // Stage: bootstrap file, nydusd config, and a cache dir.
    ensure_dir(&args.work_dir)?;
    let cache_dir = args.work_dir.join("cache");
    ensure_dir(&cache_dir)?;
    let bootstrap_path = args.work_dir.join("bootstrap");
    client
        .get_blob_to_file(&target_ref.repo, &bootstrap.digest, &bootstrap_path)
        .await
        .with_context(|| format!("download bootstrap {}", bootstrap.digest))?;

    // Resolve the target registry's docker-config credentials so nydusd's
    // registry backend can authenticate its on-demand blob fetches; without
    // this the daemon does anonymous GETs and 401s at first read on any private
    // repo. Same source of truth (`~/.docker/config.json`) the RegistryClient
    // uses to pull the bootstrap above.
    let auth = registry_client::auth::docker_config_auth(None, &target_ref.api_host);
    if auth.is_none() {
        warn!(
            host = %target_ref.api_host,
            "no docker-config credentials found for target; nydusd will fetch blobs anonymously"
        );
    }

    let config = build_nydusd_config(
        &target_ref.api_host,
        &target_ref.repo,
        &cache_dir,
        args.target_insecure,
        args.prefetch,
        auth.as_deref(),
    );
    let config_path = args.work_dir.join("nydusd-config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)
        .with_context(|| format!("write nydusd config {}", config_path.display()))?;

    ensure_dir(&plan.mount_path)?;

    info!(
        target = %target_ref,
        mount_path = %plan.mount_path.display(),
        nydusd = %args.nydusd.display(),
        "mounting nydus image (Ctrl-C to unmount and exit)"
    );

    let mut child = spawn_nydusd(
        &args.nydusd,
        &config_path,
        &plan.mount_path,
        &bootstrap_path,
        auth.as_deref(),
    )?;

    #[cfg(unix)]
    signal::install();

    // Foreground: hold the mount until a signal arrives or nydusd exits.
    let exit = supervise(&mut child).await;

    // Best-effort teardown regardless of how we got here.
    unmount(&plan.mount_path);
    let _ = child.kill();
    let _ = child.wait();

    match exit {
        Supervised::Signalled => {
            info!("received termination signal; unmounted and stopped nydusd");
            Ok(())
        }
        Supervised::ChildExited(status) => {
            // A child death observed just after a termination signal is part of
            // the deliberate teardown, not a failure — report success.
            #[cfg(unix)]
            if signal::terminated() {
                info!("received termination signal; unmounted and stopped nydusd");
                return Ok(());
            }
            if status.success() {
                Ok(())
            } else {
                bail!("nydusd exited unexpectedly: {status}")
            }
        }
        Supervised::PollFailed(e) => bail!("failed to poll nydusd: {e}"),
    }
}

pub fn plan(args: &MountArgs) -> Result<MountPlan> {
    let _ = resolve_backend_config(
        args.backend_type,
        args.backend_config.as_deref(),
        args.backend_config_file.as_deref(),
        "",
    )?;
    let backend_type = args.backend_type.unwrap_or(BackendType::Registry).as_str();

    Ok(MountPlan {
        target: args.target.clone(),
        backend_type: backend_type.to_string(),
        mount_path: args.mount_path.clone(),
        prefetch: args.prefetch,
        platform: args.platform.clone(),
    })
}

/// Build the nydusd fusedev config (legacy `device` shape) for a registry
/// backend serving the image's own repo. The bootstrap is supplied to nydusd
/// via `--bootstrap` on the command line, not embedded here.
fn build_nydusd_config(
    host: &str,
    repo: &str,
    cache_dir: &Path,
    skip_verify: bool,
    prefetch: bool,
    auth: Option<&str>,
) -> Value {
    let mut backend_config = json!({
        // Empty scheme lets nydusd auto-detect https/http (and, with
        // skip_verify, fall back to http on TLS errors).
        "scheme": "",
        "host": host,
        "repo": repo,
        "skip_verify": skip_verify
    });
    // base64 `user:password` for the registry backend's Basic auth. Matches how
    // the Go nydusify mount injects credentials into the backend config.
    if let Some(auth) = auth {
        backend_config["auth"] = json!(auth);
    }
    json!({
        "device": {
            "backend": {
                "type": "registry",
                "config": backend_config
            },
            "cache": {
                "type": "blobcache",
                "config": { "work_dir": cache_dir.display().to_string() }
            }
        },
        "mode": "direct",
        "digest_validate": false,
        "iostats_files": false,
        "enable_xattr": true,
        "fs_prefetch": {
            "enable": prefetch,
            "threads_count": 4,
            "merging_size": 1048576,
            "prefetch_all": true
        }
    })
}

fn spawn_nydusd(
    nydusd: &Path,
    config: &Path,
    mountpoint: &Path,
    bootstrap: &Path,
    auth: Option<&str>,
) -> Result<Child> {
    let mut command = Command::new(nydusd);
    command
        .arg("--config")
        .arg(config)
        .arg("--mountpoint")
        .arg(mountpoint)
        .arg("--bootstrap")
        .arg(bootstrap)
        .arg("--log-level")
        .arg("info");
    // Also surface the credential via the env var nydusd reads for registry
    // auth, belt-and-suspenders with the config `auth` field.
    if let Some(auth) = auth {
        command.env("IMAGE_PULL_AUTH", auth);
    }
    // Run nydusd in its own process group so a Ctrl-C delivered to the terminal
    // reaches nydusify (which tears the mount down deliberately) and does not
    // also race a SIGINT straight into the daemon.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setsid() is async-signal-safe and only detaches the child
        // into a new session/process group before exec.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    command
        .spawn()
        .with_context(|| format!("spawn nydusd `{}`", nydusd.display()))
}

/// Outcome of supervising the nydusd child.
enum Supervised {
    /// A termination signal was received; the mount should be torn down.
    Signalled,
    /// nydusd exited on its own.
    ChildExited(std::process::ExitStatus),
    /// Polling the child failed (distinct from a clean signal shutdown).
    PollFailed(std::io::Error),
}

/// Poll the child and the signal flag until either fires. Uses a short async
/// sleep so the compio runtime stays responsive without busy-spinning.
async fn supervise(child: &mut Child) -> Supervised {
    loop {
        // Check the signal flag BEFORE polling the child: a pending termination
        // request must win over (and correctly attribute) nydusd's own
        // signal-induced exit.
        #[cfg(unix)]
        if signal::terminated() {
            return Supervised::Signalled;
        }
        match child.try_wait() {
            Ok(Some(status)) => return Supervised::ChildExited(status),
            Ok(None) => {}
            // A failed poll is an error in its own right, never mapped to a
            // clean signal shutdown.
            Err(e) => return Supervised::PollFailed(e),
        }
        compio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Best-effort unmount of a FUSE mountpoint, trying the usual tools in order.
fn unmount(mountpoint: &Path) {
    for (prog, args) in [
        ("fusermount3", vec!["-u", "-z"]),
        ("fusermount", vec!["-u", "-z"]),
        ("umount", vec!["-l"]),
    ] {
        let ok = Command::new(prog)
            .args(&args)
            .arg(mountpoint)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
    }
    warn!(mountpoint = %mountpoint.display(), "could not unmount cleanly; may need a manual `umount`");
}

fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))
}

/// SIGINT/SIGTERM handling for the foreground mount. A tiny async-signal-safe
/// handler flips an atomic flag that [`supervise`] polls.
#[cfg(unix)]
mod signal {
    use std::sync::atomic::{AtomicBool, Ordering};

    static TERMINATED: AtomicBool = AtomicBool::new(false);

    extern "C" fn handle(_sig: libc::c_int) {
        TERMINATED.store(true, Ordering::SeqCst);
    }

    pub fn install() {
        // SAFETY: `handle` only performs an atomic store, which is
        // async-signal-safe.
        let handler = handle as *const () as libc::sighandler_t;
        unsafe {
            libc::signal(libc::SIGINT, handler);
            libc::signal(libc::SIGTERM, handler);
        }
    }

    pub fn terminated() -> bool {
        TERMINATED.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::{BackendType, default_platform};

    fn base_args() -> MountArgs {
        MountArgs {
            target: "registry.example.com/base:latest-nydus".to_string(),
            target_insecure: false,
            backend_type: None,
            backend_config: None,
            backend_config_file: None,
            prefetch: false,
            mount_path: PathBuf::from("./image-fs"),
            platform: default_platform(),
            work_dir: PathBuf::from("./tmp"),
            nydusd: PathBuf::from("nydusd"),
        }
    }

    #[test]
    fn defaults_to_registry_backend() {
        let mut args = base_args();
        args.prefetch = true;

        let plan = plan(&args).unwrap();

        assert_eq!(plan.target, "registry.example.com/base:latest-nydus");
        assert_eq!(plan.backend_type, "registry");
        assert!(plan.prefetch);
    }

    #[test]
    fn rejects_non_registry_backend_without_config() {
        let mut args = base_args();
        args.backend_type = Some(BackendType::Localfs);

        let err = plan(&args).unwrap_err();

        assert!(err.to_string().contains("--backend-config"));
    }

    #[test]
    fn nydusd_config_has_registry_backend_and_cache() {
        let config = build_nydusd_config(
            "registry.example.com",
            "team/app",
            Path::new("/w/cache"),
            true,
            true,
            Some("dXNlcjpwYXNz"),
        );
        let backend = &config["device"]["backend"];
        assert_eq!(backend["type"], "registry");
        assert_eq!(backend["config"]["host"], "registry.example.com");
        assert_eq!(backend["config"]["repo"], "team/app");
        assert_eq!(backend["config"]["skip_verify"], true);
        // Empty scheme -> nydusd auto-detects https/http.
        assert_eq!(backend["config"]["scheme"], "");
        // Credentials are injected so nydusd's blob fetches authenticate.
        assert_eq!(backend["config"]["auth"], "dXNlcjpwYXNz");
        assert_eq!(config["device"]["cache"]["config"]["work_dir"], "/w/cache");
        assert_eq!(config["device"]["cache"]["type"], "blobcache");
        assert_eq!(config["fs_prefetch"]["enable"], true);
        assert_eq!(config["mode"], "direct");
    }

    #[test]
    fn nydusd_config_prefetch_toggles_off() {
        let config = build_nydusd_config("r.io", "a/b", Path::new("/c"), false, false, None);
        assert_eq!(config["fs_prefetch"]["enable"], false);
        assert_eq!(config["device"]["backend"]["config"]["skip_verify"], false);
    }

    #[test]
    fn nydusd_config_omits_auth_when_no_credentials() {
        let config = build_nydusd_config("r.io", "a/b", Path::new("/c"), false, false, None);
        assert!(config["device"]["backend"]["config"].get("auth").is_none());
    }
}
