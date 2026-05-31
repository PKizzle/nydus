#!/usr/bin/env bash
# Fanotify on-demand runtime verification (Workstream A).
# Builds a RAFS v6 image, lays out a staging dir where the EROFS device file (blob_0)
# is a HARDLINK to the blob cache's .blob.data file (same inode), points a localfs
# backend at the full blob, runs nydusd --fanotify, mounts, and reads files back.
# A correct fetch path => reads return the ORIGINAL bytes (not zeros).
set -u

# Requirements: Linux >= 6.14 with CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y, run as root (mount(2)),
# and ROOT on a fs that supports fanotify pre-content (ext4 works; tmpfs returns ENOTSUP).
# Override the binaries via env, e.g. NYDUS_IMAGE=... NYDUSD=... ROOT=...
NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fan-rt}"   # must NOT be tmpfs
LOG=$ROOT/nydusd.log

step() { echo; echo "### $* ###"; }
fail() { echo "FAIL: $*"; CLEANUP=1; finish 1; }

finish() {
  rc=${1:-0}
  step "cleanup"
  sudo umount "$ROOT/mnt" 2>/dev/null
  sudo pkill -f "nydusd singleton" 2>/dev/null
  sleep 1
  exit "$rc"
}

step "reset dirs"
sudo umount "$ROOT/mnt" 2>/dev/null
sudo pkill -f "nydusd singleton" 2>/dev/null
sleep 1
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src,src/sub,out,backend,stage,mnt}

step "build source rootfs with distinctive content"
# A multi-block distinctive file + a random file + a small file in a subdir.
perl -e 'print "FANOTIFY_FETCH_OK_0123456789ABCDEF" x 4096' > "$ROOT/src/hello.txt"   # ~128 KiB
head -c 262144 /dev/urandom > "$ROOT/src/random.bin"                                    # 256 KiB
echo "subdir-small-file-marker" > "$ROOT/src/sub/small.txt"
SRC_HELLO=$(sha256sum "$ROOT/src/hello.txt"  | awk '{print $1}')
SRC_RAND=$(sha256sum  "$ROOT/src/random.bin" | awk '{print $1}')
SRC_SMALL=$(sha256sum "$ROOT/src/sub/small.txt" | awk '{print $1}')
echo "src hello=$SRC_HELLO rand=$SRC_RAND small=$SRC_SMALL"

step "nydus-image create (RAFS v6, compressor none, block-size 4096)"
"$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" || fail "nydus-image create"
ls -la "$ROOT/out"

BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)   # exclude bootstrap AND bootstrap.external
[ -n "$BLOB" ] || fail "no data blob produced"
echo "blob_id=$BLOB  size=$(stat -c%s "$ROOT/out/$BLOB")"

step "lay out backend (full blob) + stage (bootstrap only; daemon self-stages cache + device link)"
cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"
cp "$ROOT/out/bootstrap" "$ROOT/stage/bootstrap"

step "write BlobCacheList config (cache_type=fanotify, localfs backend)"
cat > "$ROOT/config.json" <<EOF
{ "blobs": [ {
  "type": "bootstrap", "id": "bootstrap1", "domain_id": "d1",
  "config": {
    "id": "factory1",
    "backend_type": "localfs",
    "backend_config": { "dir": "$ROOT/backend" },
    "cache_type": "fanotify",
    "cache_config": { "work_dir": "$ROOT/stage" },
    "metadata_path": "$ROOT/stage/bootstrap"
  } } ] }
EOF
cat "$ROOT/config.json"

step "launch nydusd singleton --fanotify (root for mount)"
sudo "$ND" singleton --config "$ROOT/config.json" \
  --fanotify "$ROOT/stage" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
  --log-level info > "$LOG" 2>&1 &
sleep 4

step "mount table"
mount | grep -i erofs || { echo "--- nydusd.log ---"; cat "$LOG"; fail "EROFS not mounted"; }

step "post-mount stage inode/blocks (blob_0 should now be sized; data starts sparse)"
stat -c '%n ino=%i size=%s blocks=%b' "$ROOT/stage/blob_0" "$ROOT/stage/$BLOB.blob.data"

step "READ BACK files from the EROFS mount (this drives FAN_PRE_ACCESS fetches)"
ls -la "$ROOT/mnt"
echo "--- first 64 bytes of hello.txt ---"
head -c 64 "$ROOT/mnt/hello.txt"; echo
MNT_HELLO=$(sha256sum "$ROOT/mnt/hello.txt"   2>/dev/null | awk '{print $1}')
MNT_RAND=$(sha256sum  "$ROOT/mnt/random.bin"  2>/dev/null | awk '{print $1}')
MNT_SMALL=$(sha256sum "$ROOT/mnt/sub/small.txt" 2>/dev/null | awk '{print $1}')

step "RESULTS"
echo "hello : src=$SRC_HELLO mnt=$MNT_HELLO"
echo "random: src=$SRC_RAND mnt=$MNT_RAND"
echo "small : src=$SRC_SMALL mnt=$MNT_SMALL"

step "post-read stage blocks (should be non-zero => bytes were fetched into the sparse file)"
stat -c '%n size=%s blocks=%b' "$ROOT/stage/blob_0"

PASS=1
[ "$SRC_HELLO" = "$MNT_HELLO" ] || { echo "MISMATCH hello"; PASS=0; }
[ "$SRC_RAND"  = "$MNT_RAND"  ] || { echo "MISMATCH random"; PASS=0; }
[ "$SRC_SMALL" = "$MNT_SMALL" ] || { echo "MISMATCH small"; PASS=0; }

echo; echo "--- tail nydusd.log ---"; tail -25 "$LOG"
echo
if [ "$PASS" = 1 ]; then echo "==== FANOTIFY FETCH PATH: PASS (reads match source) ===="; else echo "==== FANOTIFY FETCH PATH: FAIL ===="; fi
finish $([ "$PASS" = 1 ] && echo 0 || echo 1)
