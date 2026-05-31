# Nydus on macOS

Nydus supports macOS as a **build host** (producing RAFS images) and as a **runtime host**
(mounting RAFS images via FUSE). The fanotify/EROFS direct-mount path is Linux-only.

## Prerequisites

- **macFUSE ≥ 4.2.4** — Install from <https://osxfuse.github.io>.
  Tested versions: 4.2.4 (macOS 11–12), 5.2.0 (macOS 26).
  On macOS 26+ macFUSE uses the FSKit backend; no kernel extension is needed.
- **Rust toolchain** — See `rust-toolchain.toml` for the pinned version.
- **OpenSSL** (Homebrew) — `brew install openssl@3`

## Supported binaries

| Binary | macOS support | Notes |
|--------|---------------|-------|
| `nydus-image` | ✅ since v2.4.4 | Build RAFS v5/v6 bootstraps from directories, tar files, or OCI images. The `--block-size` flag supports cross-architecture targets (4 KiB / 16 KiB / 64 KiB). macOS extended attributes (`com.apple.*`) are silently skipped. |
| `nydusd` (fusedev) | ✅ since v2.x | Mounts RAFS images as a regular directory via macFUSE. The passthrough filesystem mode is **not** supported (uses Linux-specific syscalls). |
| `nydusd` (fanotify) | ❌ | Linux kernel ≥ 6.14 required. |
| `nydusd` (EROFS direct) | ❌ | EROFS is a Linux kernel filesystem. |
| `nydusctl` | ❌ (planned) | Go binary; PRs welcome. |
| `nydusify` | ❌ (planned) | Go binary; PRs welcome. |

## Quick start

```bash
# Install macFUSE (if not already present)
# https://osxfuse.github.io

# Build
OPENSSL_NO_VENDOR=1 cargo build --release --bin nydus-image --bin nydusd

# Create a test RAFS image (from any directory)
./target/release/nydus-image create \
  --type directory \
  --bootstrap my-image.boot \
  --blob-dir ./blobs \
  /path/to/some/directory

# Mount it via FUSE
mkdir -p /tmp/nydus-mnt
./target/release/nydusd fuse \
  --mountpoint /tmp/nydus-mnt \
  --bootstrap my-image.boot \
  --localfs-dir ./blobs &

ls /tmp/nydus-mnt    # browse the filesystem

# Unmount
umount /tmp/nydus-mnt
```

## Known build issues

### OpenSSL vendored build fails ("cp: ... Not a directory")

The vendored OpenSSL build (`openssl-src` crate) fails when the workspace path contains
spaces. Workarounds (pick one):

1. **Use Homebrew OpenSSL** (recommended):
   ```bash
   OPENSSL_NO_VENDOR=1 OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl cargo build ...
   ```

2. **Symlink the workspace** to a path without spaces:
   ```bash
   ln -s "/path/with spaces/nydus" /tmp/nydus && cd /tmp/nydus && cargo build ...
   ```

### macOS extended attributes warning

When building from a directory, macOS-specific xattrs (`com.apple.*`) are skipped with
a debug-level log. This is expected — RAFS only supports Linux xattr namespaces
(`user.*`, `security.*`, `trusted.*`). The build succeeds; the warning is informational.

## Limitations

- **Cross-architecture block size**: Bootstraps built with `--block-size 16384` or `65536`
  require a **Linux host with matching page size** to mount via EROFS. The FUSE path on
  macOS works with any block size since FUSE abstracts the page cache.
- **No fanotify / EROFS mount** on macOS — use `nydusd fuse` instead.
- **macFUSE must be installed separately** — it is not bundled with nydus.
- FUSE daemon runs as a regular user process; `sudo` is not required for mounting.
