#!/usr/bin/env bash
# Block-device export verification.
# Builds a RAFS v6 image at BLOCK_SIZE, exports it with `nydus-image export --block` into a raw
# EROFS disk image, loop-mounts that image with the kernel EROFS driver and compares every file
# with its source. The kernel follows only block addresses and the device table here, so this
# catches layout errors that FUSE reads (chunk-table offsets) do not, and confirms that
# `nydus-image check` agrees with the kernel.
# It then mounts the image through the snapshotter's blockdev mount and checks ro,nosuid,nodev.
set -u

# Requirements: Linux with EROFS, cargo, run as root (mount(2), loop devices). The kernel mounts block
# sizes up to its page size, so BLOCK_SIZE above the page size fails at mount time.
# Override via env, e.g. NYDUS_IMAGE=... ROOT=... BLOCK_SIZE=16384
NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/export-block}"
BLOCK_SIZE="${BLOCK_SIZE:-4096}"

step() { echo; echo "### $* ###"; }
cleanup() { sudo umount "$ROOT/mnt" 2>/dev/null; }
fail() { echo "FAIL: $*"; cleanup; exit 1; }

step "reset dirs"
cleanup
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src/sub,out,mnt}

step "build source rootfs"
# A small file ahead of a large one: with block sizes above 4 KiB the large file's chunk starts
# behind block padding, which a 4 KiB-only layout misplaces.
head -c 5000 /dev/urandom > "$ROOT/src/a-small.bin"
head -c 200000 /dev/urandom > "$ROOT/src/b-large.bin"
perl -e 'print "EXPORT_BLOCK_OK_0123456789ABCDEF" x 4096' > "$ROOT/src/hello.txt"
echo "subdir-small-file-marker" > "$ROOT/src/sub/small.txt"

step "nydus-image create (RAFS v6, compressor none, block-size $BLOCK_SIZE)"
"$NI" create --fs-version 6 --compressor none --block-size "$BLOCK_SIZE" \
  -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" || fail "nydus-image create"
"$NI" check -B "$ROOT/out/bootstrap" --blob-dir "$ROOT/out" >/dev/null || fail "nydus-image check"

step "nydus-image export --block"
"$NI" export --block --bootstrap "$ROOT/out/bootstrap" --localfs-dir "$ROOT/out" \
  --output "$ROOT/disk.img" || fail "nydus-image export --block"
ls -la "$ROOT/disk.img"

step "loop-mount the exported image"
sudo mount -t erofs -o loop,ro "$ROOT/disk.img" "$ROOT/mnt" || fail "EROFS loop mount"
mount | grep -F "$ROOT/mnt type erofs"

step "compare file contents"
SRC_SUMS=$(cd "$ROOT/src" && find . -type f | sort | xargs sha256sum)
MNT_SUMS=$(cd "$ROOT/mnt" && find . -type f | sort | xargs sha256sum 2>&1)
echo "$MNT_SUMS"
if [ "$SRC_SUMS" = "$MNT_SUMS" ]; then
  cleanup
  step "snapshotter blockdev mount flags (ro,nosuid,nodev)"
  NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
    daemon::tests::blockdev_erofs_mount_is_nosuid_nodev -- --ignored --exact --nocapture \
    || fail "blockdev EROFS mount flags"
  echo; echo "==== EXPORT BLOCK ($BLOCK_SIZE): PASS (reads match source) ===="
  exit 0
fi
diff <(echo "$SRC_SUMS") <(echo "$MNT_SUMS")
echo; echo "==== EXPORT BLOCK ($BLOCK_SIZE): FAIL ===="
cleanup; exit 1
