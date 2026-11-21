#!/usr/bin/env bash
# File handles on a nydusd FUSE mount survive dentry eviction.
#
# name_to_handle_at(2) encodes a FUSE node id. Once the kernel has evicted the dentry,
# open_by_handle_at(2) resolves the id by asking nydusd to look up "." on it, and reconnects a
# directory by looking up ".." up to the root. That needs FUSE EXPORT_SUPPORT and "." / ".."
# answered with the node ids the kernel already has; without either, the reopen fails ESTALE.
# NFS export and overlayfs `index=on` over a nydus mount depend on the same path.
#
#   H1  a file in a subdirectory reopens with the same inode and content;
#   H2  a top-level directory reopens (".." answers the FUSE root);
#   H3  a nested directory reopens (".." answers each parent up to the root).
#
# Requirements: root (mount(2), drop_caches), FUSE and a C compiler. Any kernel with FUSE.
# Override the binaries via env, e.g. NYDUS_IMAGE=... NYDUSD=... ROOT=... CC=...
set -u

NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fusedev-file-handles}"
HERE="$(cd "$(dirname "$0")" && pwd)"

step() { echo; echo "### $* ###"; }
note() { echo "  - $*"; }

teardown() {
  if [ -n "${NYDUSD_PID:-}" ]; then
    kill "$NYDUSD_PID" 2>/dev/null
    for _ in $(seq 25); do kill -0 "$NYDUSD_PID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$NYDUSD_PID" 2>/dev/null
    wait "$NYDUSD_PID" 2>/dev/null
    NYDUSD_PID=
  fi
  umount "$ROOT/mnt" 2>/dev/null || umount -l "$ROOT/mnt" 2>/dev/null
}
finish() { teardown; exit "${1:-0}"; }
trap 'finish 1' INT TERM

step "reset dirs"
teardown
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src/d1/d2/d3,out,backend,mnt}

step "build the handle helper"
"${CC:-cc}" -O2 -Wall -o "$ROOT/fh-reopen" "$HERE/fh-reopen.c" || { echo "cannot compile fh-reopen.c"; finish 1; }

step "build source rootfs"
echo top > "$ROOT/src/top.txt"
echo one > "$ROOT/src/d1/f1.txt"
perl -e 'print "FILE_HANDLE_MARKER" x 4096' > "$ROOT/src/d1/d2/f2.txt"
echo three > "$ROOT/src/d1/d2/d3/f3.txt"

step "nydus-image create (RAFS v6)"
"$NI" create --fs-version 6 -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" >/dev/null 2>&1 \
  || { echo "nydus-image create failed"; finish 1; }
BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || { echo "no data blob produced"; finish 1; }
cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"

cat > "$ROOT/config.json" <<CFG
{
  "version": 2,
  "backend": { "type": "localfs", "localfs": { "dir": "$ROOT/backend" } },
  "cache":   { "type": "filecache", "filecache": { "work_dir": "$ROOT/cache" } },
  "rafs":    { "mode": "direct" }
}
CFG
mkdir -p "$ROOT/cache"

step "start nydusd (fusedev)"
"$ND" fuse --config "$ROOT/config.json" --bootstrap "$ROOT/out/bootstrap" \
  --mountpoint "$ROOT/mnt" --log-level info > "$ROOT/nydusd.log" 2>&1 &
NYDUSD_PID=$!
for _ in $(seq 50); do mountpoint -q "$ROOT/mnt" && break; sleep 0.2; done
if ! mountpoint -q "$ROOT/mnt"; then
  echo "--- nydusd.log ---"; tail -30 "$ROOT/nydusd.log"
  echo "FAIL: FUSE not mounted"; finish 1
fi
note "$(grep " $ROOT/mnt " /proc/mounts)"

step "H1-H3: take handles, drop dentries, reopen"
"$ROOT/fh-reopen" "$ROOT/mnt" d1/d2/f2.txt d1 d1/d2/d3
rc=$?

echo
if [ "$rc" -eq 0 ]; then
  echo "PASS: every handle reopened after dentry eviction"
else
  echo "FAIL: some handles did not reopen (see above)"
fi
finish "$rc"
