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
#       must fail H4 and H6.
#   H5  nydusd exits on its own within 10 s of the mount being unmounted.
#   H6  H1-H4 again on a nydusd started without a bootstrap, with the image mounted at /img
#       through the API, so the FUSE root is the Vfs pseudo fs and ".." from the image root
#       answers it.
#   H7  on that daemon, a file handle taken on /img fails ESTALE after /img is unmounted and an
#       image with the same layout but other content takes its place under the same file
#       system index (the index is cycled until the Vfs hands it out again). Only the RAFS
#       generation tells the two images apart; without it the handle opens the other file.
#   H8  a handle to a directory of the Vfs pseudo fs (`a` above a mount at /a/img) reopens that
#       directory, without hanging.
#   H9  on a daemon with a bootstrap, a handle below an image mounted at /sub through the API
#       stays valid when the same bootstrap is mounted again into that image's file system index
#       (Vfs indexes are reused once all 255 have been handed out);
#   H10 a handle there fails ESTALE when another image, with the same inode numbers, gets that
#       index: the generation is what tells the two apart.
#
# Requirements: root (mount(2), drop_caches), FUSE, a C compiler, curl and python3.
# Override the binaries via env, e.g. NYDUS_IMAGE=... NYDUSD=... ROOT=... CC=...
set -u

NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fusedev-file-handles}"
HERE="$(cd "$(dirname "$0")" && pwd)"

FAILURES=0
step() { echo; echo "### $* ###"; }
note() { echo "  - $*"; }
case_fail() { echo "  !! FAIL: $*"; FAILURES=$((FAILURES + 1)); }
case_pass() { echo "  ok: $*"; }

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
mkdir -p "$ROOT"/{src/d1/d2/d3,src2/d1/d2/d3,out,out2,backend,mnt}

step "build the handle helper"
"${CC:-cc}" -O2 -Wall -o "$ROOT/fh-reopen" "$HERE/fh-reopen.c" \
  || { echo "cannot compile fh-reopen.c"; finish 1; }

step "build source rootfs"
echo top > "$ROOT/src/top.txt"
echo one > "$ROOT/src/d1/f1.txt"
perl -e 'print "FILE_HANDLE_MARKER" x 4096' > "$ROOT/src/d1/d2/f2.txt"
echo three > "$ROOT/src/d1/d2/d3/f3.txt"
# The same tree with f2.txt's content changed but not its size, so both images have one layout.
cp -a "$ROOT/src/." "$ROOT/src2/"
perl -e 'print "SECOND_IMAGE_BYTES" x 4096' > "$ROOT/src2/d1/d2/f2.txt"

step "nydus-image create (RAFS v6)"
"$NI" create --fs-version 6 -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" >/dev/null 2>&1 \
  || { echo "nydus-image create failed"; finish 1; }
"$NI" create --fs-version 6 -B "$ROOT/out2/bootstrap" -D "$ROOT/out2" "$ROOT/src2" >/dev/null 2>&1 \
  || { echo "nydus-image create (second image) failed"; finish 1; }
for out in out out2; do
  BLOB=$(ls "$ROOT/$out" | grep -vE '^bootstrap' | head -1)
  [ -n "$BLOB" ] || { echo "no data blob produced in $out"; finish 1; }
  cp "$ROOT/$out/$BLOB" "$ROOT/backend/$BLOB"
done

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
  case_fail "FUSE not mounted"; finish 1
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

# Takes a handle for each path under the mount, drops the caches, reopens every handle (H1-H3)
# and checks that the reopens were looked up in nydusd (H4). $1 labels the checks.
reopen_handles() {
  local label=$1; shift
  FH_REOPEN_HOOK="'$ROOT/lookups.sh' > '$ROOT/lookups.before'" \
    "$ROOT/fh-reopen" "$ROOT/mnt" "$@" \
    || case_fail "$label: not every handle reopened (fh-reopen exit $?)"
  local before after
  before=$(cat "$ROOT/lookups.before" 2>/dev/null)
  after=$("$ROOT/lookups.sh")
  note "Lookup counter ${before:-?} -> ${after:-?} for $# handles"
  if [ -z "$before" ] || [ -z "$after" ]; then
    case_fail "$label: cannot read nydusd's Lookup counter"
  elif [ $((after - before)) -lt $# ]; then
    case_fail "$label: the reopens did not reach nydusd, so they tested cached dentries"
  else
    case_pass "$label: $((after - before)) lookups served the reopens"
  fi
}

step "H1-H4: take handles, drop dentries, reopen through nydusd"
[ "${CONTROL:-0}" = 1 ] && export FH_NO_DROP=1 && note "CONTROL: caches are not dropped"
reopen_handles H1-H4 d1/d2/f2.txt d1 d1/d2/d3

step "H5: nydusd exits after umount"
umount "$ROOT/mnt" || case_fail "H5: umount failed"
for _ in $(seq 50); do kill -0 "$NYDUSD_PID" 2>/dev/null || break; sleep 0.2; done
if kill -0 "$NYDUSD_PID" 2>/dev/null; then
  case_fail "H5: nydusd still running 10 s after umount"
else
  wait "$NYDUSD_PID" 2>/dev/null
  NYDUSD_PID=
  case_pass "H5: nydusd exited after umount"
fi

# Mounts bootstrap $1 at Vfs path $2 through the API; api_umount unmounts Vfs path $1.
api_mount() {
  python3 -c 'import json, sys; print(json.dumps({"source": sys.argv[1], "fs_type": "rafs",
    "config": open(sys.argv[2]).read()}))' "$1" "$ROOT/config.json" |
    curl -sf --unix-socket "$ROOT/api.sock" -X POST -H 'Content-Type: application/json' \
      --data-binary @- "http://localhost/api/v1/mount?mountpoint=$2" >/dev/null
}
api_umount() {
  curl -sf --unix-socket "$ROOT/api.sock" -X DELETE \
    "http://localhost/api/v1/mount?mountpoint=$1" >/dev/null
}

step "H6: an image mounted through the API of a daemon without a bootstrap"
teardown # a nydusd that failed H5 must not hold the mountpoint
rm -f "$ROOT/api.sock"
"$ND" fuse --mountpoint "$ROOT/mnt" --apisock "$ROOT/api.sock" --log-level info \
  > "$ROOT/nydusd-api.log" 2>&1 &
NYDUSD_PID=$!
for _ in $(seq 50); do [ -S "$ROOT/api.sock" ] && mountpoint -q "$ROOT/mnt" && break; sleep 0.2; done
api_mount "$ROOT/out/bootstrap" /img
if [ -f "$ROOT/mnt/img/top.txt" ]; then
  reopen_handles H6 img/d1/d2/f2.txt img/d1 img/d1/d2/d3
else
  echo "--- nydusd-api.log ---"; tail -30 "$ROOT/nydusd-api.log"
  case_fail "H6: the API mount is not visible at $ROOT/mnt/img"
fi

step "H7: a handle on an unmounted image never opens its successor's file"
# The hook runs once the handle is taken: unmount /img (file system index 1), mount and
# unmount the second image until the Vfs has handed out every other index (2-255) once, mount
# it at /img, which takes index 1 again, and evict the dentries.
cat > "$ROOT/swap-image.sh" <<SH
#!/bin/bash
set -e
$(declare -f api_mount api_umount)
ROOT='$ROOT'
api_umount /img
for _ in \$(seq 254); do api_mount "\$ROOT/out2/bootstrap" /cycle; api_umount /cycle; done
api_mount "\$ROOT/out2/bootstrap" /img
grep -q SECOND_IMAGE_BYTES "\$ROOT/mnt/img/d1/d2/f2.txt"
sync; echo 2 > /proc/sys/vm/drop_caches
SH
chmod +x "$ROOT/swap-image.sh"
if FH_NO_DROP=1 FH_EXPECT_STALE=1 FH_REOPEN_HOOK="'$ROOT/swap-image.sh'" \
    "$ROOT/fh-reopen" "$ROOT/mnt" img/d1/d2/f2.txt; then
  case_pass "H7: the handle is stale"
else
  case_fail "H7: the handle did not fail ESTALE (fh-reopen exit $?)"
fi

step "H8: a handle to a pseudo fs directory"
api_mount "$ROOT/out/bootstrap" /a/img
if timeout 30 "$ROOT/fh-reopen" "$ROOT/mnt" a; then
  case_pass "H8: the pseudo fs directory reopened"
else
  case_fail "H8: the pseudo fs directory did not reopen (fh-reopen exit $?, 124 is a hang)"
fi
teardown

# Umounts /sub, fills every other Vfs index, then mounts bootstrap $1 at /sub, which gets the
# freed index back. Index 1 is /base and 2 was /sub: 253 fillers take 3-255, the next wraps to 2.
cat > "$ROOT/reuse.sh" <<SH
#!/bin/bash
set -e
$(declare -f api_mount api_umount)
ROOT='$ROOT'
api_umount /sub
for i in \$(seq 253); do api_mount "\$ROOT/out/bootstrap" /f\$i; done
api_mount "\$1" /sub
stat -c %i "\$ROOT/mnt/sub" > "\$ROOT/ino.after"
SH
chmod +x "$ROOT/reuse.sh"

# Mounts the image at /sub in a fresh nydusd, takes handles below it, and once the caches are
# dropped lets reuse.sh put bootstrap $1 into its index. $2 non-empty: the reopens must fail ESTALE.
reuse_index() {
  rm -f "$ROOT/api.sock" "$ROOT/ino.after"
  "$ND" fuse --config "$ROOT/config.json" --bootstrap "$ROOT/out/bootstrap" \
    --virtual-mountpoint /base --mountpoint "$ROOT/mnt" --apisock "$ROOT/api.sock" \
    --log-level info > "$ROOT/nydusd.log" 2>&1 &
  NYDUSD_PID=$!
  for _ in $(seq 50); do [ -S "$ROOT/api.sock" ] && mountpoint -q "$ROOT/mnt" && break; sleep 0.2; done
  if ! api_mount "$ROOT/out/bootstrap" /sub; then
    case_fail "$3: cannot mount /sub"; teardown; return
  fi
  stat -c %i "$ROOT/mnt/sub" > "$ROOT/ino.before"
  if ! env ${2:+FH_EXPECT_STALE=1} FH_REOPEN_HOOK="'$ROOT/reuse.sh' '$1'" \
    "$ROOT/fh-reopen" "$ROOT/mnt" sub/d1/d2/f2.txt sub/d1/d2/d3; then
    case_fail "$3"
  elif ! cmp -s "$ROOT/ino.before" "$ROOT/ino.after"; then
    case_fail "$3: /sub did not get its file system index back, so nothing was tested"
  else
    case_pass "$3"
  fi
  teardown
}

step "H9: the same bootstrap in the reused index keeps the handles valid"
reuse_index "$ROOT/out/bootstrap" "" "H9: same bootstrap, handles reopen"

step "H10: another image in the reused index makes the handles stale"
reuse_index "$ROOT/out2/bootstrap" 1 "H10: other image, handles fail ESTALE"

echo
if [ "$FAILURES" = 0 ]; then
  echo "==== FUSEDEV FILE HANDLES: PASS ===="
  finish 0
else
  echo "==== FUSEDEV FILE HANDLES: FAIL ($FAILURES failing check(s)) ===="
  finish 1
fi
