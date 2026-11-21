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
#   H3  a nested directory reopens (".." answers each parent up to the root);
#   H4  the reopens reached nydusd: its Lookup counter grows by at least one per handle. A
#       reopen served from a dentry that was never evicted passes H1-H3 without testing the
#       export path, so H4 is what makes them count. CONTROL=1 skips dropping the caches and
#       must fail H4.
#
# Requirements: root (mount(2), drop_caches), FUSE, a C compiler, curl and python3.
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
  --mountpoint "$ROOT/mnt" --apisock "$ROOT/api.sock" --log-level info > "$ROOT/nydusd.log" 2>&1 &
NYDUSD_PID=$!
for _ in $(seq 50); do mountpoint -q "$ROOT/mnt" && break; sleep 0.2; done
if ! mountpoint -q "$ROOT/mnt"; then
  echo "--- nydusd.log ---"; tail -30 "$ROOT/nydusd.log"
  echo "FAIL: FUSE not mounted"; finish 1
fi
note "$(grep " $ROOT/mnt " /proc/mounts)"

# Prints the lookups nydusd has served, from its global FOP counters (index 9 is
# StatsFop::Lookup). A script, so fh-reopen's hook can run it between eviction and reopen.
cat > "$ROOT/lookups.sh" <<SH
#!/bin/sh
curl -sf --unix-socket "$ROOT/api.sock" http://localhost/api/v1/metrics |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["fop_hits"][9])'
SH
chmod +x "$ROOT/lookups.sh"

step "H1-H3: take handles, drop dentries, reopen"
HANDLES=(d1/d2/f2.txt d1 d1/d2/d3)
[ "${CONTROL:-0}" = 1 ] && export FH_NO_DROP=1 && note "CONTROL: caches are not dropped"
FH_REOPEN_HOOK="'$ROOT/lookups.sh' > '$ROOT/lookups.before'" "$ROOT/fh-reopen" "$ROOT/mnt" "${HANDLES[@]}"
rc=$?

step "H4: the reopens looked the node ids up in nydusd"
before=$(cat "$ROOT/lookups.before" 2>/dev/null)
after=$("$ROOT/lookups.sh")
note "Lookup counter ${before:-?} -> ${after:-?} for ${#HANDLES[@]} handles"
if [ -z "$before" ] || [ -z "$after" ]; then
  echo "  !! FAIL: H4: cannot read nydusd's Lookup counter"; rc=1
elif [ $((after - before)) -lt ${#HANDLES[@]} ]; then
  echo "  !! FAIL: H4: the reopens did not reach nydusd, so H1-H3 tested cached dentries"; rc=1
else
  echo "  ok: H4: $((after - before)) lookups served the reopens"
fi

echo
if [ "$rc" -eq 0 ]; then
  echo "PASS: every handle reopened through nydusd after dentry eviction"
else
  echo "FAIL: see above"
fi
finish "$rc"
