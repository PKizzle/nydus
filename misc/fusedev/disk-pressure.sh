#!/usr/bin/env bash
# What a full blob-cache filesystem does to the fusedev path.
#
# The fanotify/EROFS path and the fusedev path answer disk pressure in opposite ways,
# because the cache file means something different in each:
#
#   fanotify: the blob cache file IS the EROFS device. A failed cache write means the
#             bytes are not there, so the event must be DENIED -- see
#             misc/fanotify/precontent-cases.sh case C13.
#   fusedev:  the cache is only an accelerator. `delay_persist_chunk_data` writes it from
#             a DETACHED task while the read is served from the in-memory buffer, so a
#             failed cache write is invisible to the reader and must stay that way.
#
# Which makes the risk here the opposite of C13's. Not "does the reader get the right
# errno" -- the reader gets no error at all -- but:
#
#   F1  the read still returns correct data while the cache disk is full;
#   F2  a LATER read of the same range also returns correct data. This is the one that
#       could really break: if a chunk whose write failed were still marked ready, the
#       next read would be served out of the sparse cache file as a hole full of zeros.
#       (`_update_chunk_pending_status` is handed `res.is_ok()`, so it clears pending
#       instead of setting ready -- F2 is what proves that.)
#   F3  the daemon says WHY it could not persist. On this path the log is the only
#       signal an operator gets that caching has stopped, so "Failed to persist data"
#       without an errno is not enough.
#   F4  once there is room again, the cache actually materialises.
#
# Requirements: root (mount(2)), a loopback ext4, and FUSE. Notably NOT kernel >= 6.14 --
# unlike the fanotify suite this runs anywhere FUSE does.
# Override the binaries via env, e.g. NYDUS_IMAGE=... NYDUSD=... ROOT=...
set -u

NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fusedev-disk-pressure}"

FAILURES=0
step() { echo; echo "### $* ###"; }
note() { echo "  - $*"; }
case_fail() { echo "  !! FAIL: $*"; FAILURES=$((FAILURES + 1)); }
case_pass() { echo "  ok: $*"; }

teardown() {
  sudo umount "$ROOT/mnt" 2>/dev/null
  sudo pkill -f 'nydusd fuse' 2>/dev/null
  sleep 1
  sudo umount "$ROOT/loop" 2>/dev/null
}
finish() { teardown; exit "${1:-0}"; }
trap 'finish 1' INT TERM

# Force the next read to re-enter nydusd instead of being answered from the kernel's
# page cache -- without this F2 re-reads its own first result and proves nothing.
drop_caches() { sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1; }

step "reset dirs"
teardown
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src,out,backend,mnt,loop}

step "build source rootfs"
perl -e 'print "FUSEDEV_DISK_PRESSURE_MARKER_0123" x 8192' > "$ROOT/src/hello.txt"   # ~256 KiB
SRC=$(sha256sum "$ROOT/src/hello.txt" | awk '{print $1}')
note "src sha256=$SRC"

step "nydus-image create (RAFS v6, compressor none, block-size 4096)"
"$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" >/dev/null 2>&1 \
  || { echo "nydus-image create failed"; finish 1; }
BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || { echo "no data blob produced"; finish 1; }
cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"
note "blob_id=$BLOB"

step "small ext4 as the blob cache work dir"
if ! command -v mkfs.ext4 >/dev/null; then
  echo "SKIP: mkfs.ext4 not installed"; finish 0
fi
dd if=/dev/zero of="$ROOT/cache.ext4" bs=1M count=32 status=none
mkfs.ext4 -q -F "$ROOT/cache.ext4"
sudo mount -o loop "$ROOT/cache.ext4" "$ROOT/loop" || { echo "SKIP: cannot mount loopback ext4"; finish 0; }
sudo mkdir -p "$ROOT/loop/cache"

cat > "$ROOT/config.json" <<EOF
{
  "version": 2,
  "backend": { "type": "localfs", "localfs": { "dir": "$ROOT/backend" } },
  "cache":   { "type": "filecache", "filecache": { "work_dir": "$ROOT/loop/cache" } },
  "rafs":    { "mode": "direct", "enable_xattr": true }
}
EOF

step "start nydusd (fusedev)"
sudo "$ND" fuse --config "$ROOT/config.json" --bootstrap "$ROOT/out/bootstrap" \
  --mountpoint "$ROOT/mnt" --fuse-threads 2 --log-level info > "$ROOT/nydusd.log" 2>&1 &
sleep 5
if ! mount | grep -q "on $ROOT/mnt "; then
  echo "--- nydusd.log ---"; tail -30 "$ROOT/nydusd.log"
  case_fail "FUSE not mounted"; finish 1
fi
note "$(mount | grep "on $ROOT/mnt " | head -1)"

step "fill the cache filesystem"
# Only after the mount is up, so startup succeeds and the sole failing operation is the
# cache write. conv=fsync settles ext4's delayed allocation, otherwise the balloon's
# blocks are merely reserved and the disk is not really full yet.
sudo dd if=/dev/zero of="$ROOT/loop/balloon" bs=1M conv=fsync status=none 2>/dev/null
sudo dd if=/dev/zero of="$ROOT/loop/balloon.tail" bs=4096 conv=fsync status=none 2>/dev/null
avail=$(df --output=avail -k "$ROOT/loop" | tail -1 | tr -d ' ')
note "cache fs free after balloon: ${avail} KiB"
[ "${avail:-1}" -le 8 ] || note "WARNING: ${avail} KiB still free — the cache write may not fail at all"

step "F1: a cold read with the cache disk full"
timeout 60 dd if="$ROOT/mnt/hello.txt" of="$ROOT/read1.out" bs=4096 status=none 2>"$ROOT/read1.err"
rc1=$?
got1=$(sha256sum "$ROOT/read1.out" 2>/dev/null | awk '{print $1}')
note "exit=$rc1 $(head -1 "$ROOT/read1.err")"
if [ "$got1" = "$SRC" ]; then
  case_pass "F1: read served correctly from memory despite the full cache disk"
else
  case_fail "F1: read wrong or short ($(stat -c%s "$ROOT/read1.out" 2>/dev/null) bytes, exit $rc1)"
fi

step "F2: read the same range again — the un-persisted chunks must not look ready"
drop_caches
timeout 60 dd if="$ROOT/mnt/hello.txt" of="$ROOT/read2.out" bs=4096 status=none 2>"$ROOT/read2.err"
rc2=$?
got2=$(sha256sum "$ROOT/read2.out" 2>/dev/null | awk '{print $1}')
nonzero2=$(LC_ALL=C tr -d '\0' < "$ROOT/read2.out" 2>/dev/null | wc -c | tr -d ' ')
note "exit=$rc2 non-zero bytes=$nonzero2"
if [ "$got2" = "$SRC" ]; then
  case_pass "F2: second read still correct — failed writes did not mark chunks ready"
elif [ "$nonzero2" = "0" ]; then
  case_fail "F2: second read returned ZEROS — a sparse hole was served as data"
else
  case_fail "F2: second read wrong (exit $rc2)"
fi

step "F3: the daemon reported WHY it could not persist"
# The read cannot fail, so this log line is the operator's only signal. It has to name
# the errno: a full disk and a read-only cache dir are different problems.
if grep -qi 'Failed to persist data for chunk at offset [0-9]*: .*No space left on device' "$ROOT/nydusd.log"; then
  case_pass "F3: persist failure logged with its errno"
  note "$(grep -i -m1 'Failed to persist data' "$ROOT/nydusd.log" | sed 's/\x1b\[[0-9;]*m//g' | tail -c 120)"
elif grep -qi 'Failed to persist data' "$ROOT/nydusd.log"; then
  case_fail "F3: persist failure logged WITHOUT a reason — the errno was dropped before the log"
  note "$(grep -i -m1 'Failed to persist data' "$ROOT/nydusd.log" | sed 's/\x1b\[[0-9;]*m//g' | tail -c 120)"
else
  case_fail "F3: no persist failure logged at all — did the cache write actually fail?"
fi

step "F4: with room again, the cache materialises"
sudo rm -f "$ROOT/loop/balloon" "$ROOT/loop/balloon.tail"
drop_caches
timeout 60 dd if="$ROOT/mnt/hello.txt" of="$ROOT/read3.out" bs=4096 status=none 2>"$ROOT/read3.err"
got3=$(sha256sum "$ROOT/read3.out" 2>/dev/null | awk '{print $1}')
cached=$(du -k "$ROOT/loop/cache/$BLOB.blob.data" 2>/dev/null | awk '{print $1}')
note "cache file now occupies ${cached:-0} KiB"
if [ "$got3" != "$SRC" ]; then
  case_fail "F4: read wrong after freeing space"
elif [ "${cached:-0}" -gt 0 ]; then
  case_pass "F4: read correct and the cache absorbed it (${cached} KiB)"
else
  case_fail "F4: read correct but nothing was cached — the entry never recovered"
fi

step "SUMMARY"
if [ "$FAILURES" = 0 ]; then
  echo "==== FUSEDEV DISK PRESSURE: PASS ===="
  finish 0
else
  echo "==== FUSEDEV DISK PRESSURE: FAIL ($FAILURES failing check(s)) ===="
  finish 1
fi
