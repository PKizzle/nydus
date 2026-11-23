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
#   H5  nydusd exits on its own within 10 s of the mount being unmounted.
#   H6  a handle stays valid when the same bootstrap is mounted again into the image's file
#       system index (Vfs indexes are reused once all 255 have been handed out);
#   H7  a handle fails ESTALE when another image, with the same inode numbers, gets that index:
#       the generation is what tells the two apart.
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
mkdir -p "$ROOT"/{src/d1/d2/d3,out,backend,mnt}

step "build the handle helper"
"${CC:-cc}" -O2 -Wall -o "$ROOT/fh-reopen" "$HERE/fh-reopen.c" \
  || { echo "cannot compile fh-reopen.c"; finish 1; }

step "build source rootfs"
echo top > "$ROOT/src/top.txt"
echo one > "$ROOT/src/d1/f1.txt"
perl -e 'print "FILE_HANDLE_MARKER" x 4096' > "$ROOT/src/d1/d2/f2.txt"
echo three > "$ROOT/src/d1/d2/d3/f3.txt"
# The same tree with other bytes of the same length, so the inode numbers match.
cp -a "$ROOT/src" "$ROOT/src-b"
perl -e 'print "OTHER_IMAGE_MARKER" x 4096' > "$ROOT/src-b/d1/d2/f2.txt"

step "nydus-image create (RAFS v6)"
"$NI" create --fs-version 6 -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" >/dev/null 2>&1 \
  || { echo "nydus-image create failed"; finish 1; }
BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || { echo "no data blob produced"; finish 1; }
cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"
mkdir -p "$ROOT/out-b"
"$NI" create --fs-version 6 -B "$ROOT/out-b/bootstrap" -D "$ROOT/out-b" "$ROOT/src-b" >/dev/null 2>&1 \
  || { echo "nydus-image create (second image) failed"; finish 1; }
for b in $(ls "$ROOT/out-b" | grep -vE '^bootstrap'); do cp "$ROOT/out-b/$b" "$ROOT/backend/$b"; done

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

step "H1-H3: take handles, drop dentries, reopen"
HANDLES=(d1/d2/f2.txt d1 d1/d2/d3)
[ "${CONTROL:-0}" = 1 ] && export FH_NO_DROP=1 && note "CONTROL: caches are not dropped"
FH_REOPEN_HOOK="'$ROOT/lookups.sh' > '$ROOT/lookups.before'" \
  "$ROOT/fh-reopen" "$ROOT/mnt" "${HANDLES[@]}" \
  || case_fail "H1-H3: not every handle reopened (fh-reopen exit $?)"

step "H4: the reopens looked the node ids up in nydusd"
before=$(cat "$ROOT/lookups.before" 2>/dev/null)
after=$("$ROOT/lookups.sh")
note "Lookup counter ${before:-?} -> ${after:-?} for ${#HANDLES[@]} handles"
if [ -z "$before" ] || [ -z "$after" ]; then
  case_fail "H4: cannot read nydusd's Lookup counter"
elif [ $((after - before)) -lt ${#HANDLES[@]} ]; then
  case_fail "H4: the reopens did not reach nydusd, so H1-H3 tested cached dentries"
else
  case_pass "H4: $((after - before)) lookups served the reopens"
fi

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

# Mounts bootstrap $2 at virtual path $1 through nydusd's API. A script, for reuse.sh below.
cat > "$ROOT/mount.sh" <<SH
#!/bin/sh
python3 -c 'import json, sys; print(json.dumps({"source": sys.argv[1], "fs_type": "rafs",
  "config": open(sys.argv[2]).read()}))' "\$2" "$ROOT/config.json" |
  curl -sf --unix-socket "$ROOT/api.sock" -X POST -d @- \
    "http://localhost/api/v1/mount?mountpoint=\$1" >/dev/null
SH
# Umounts /sub, fills every other Vfs index, then mounts bootstrap $1 at /sub, which gets the
# freed index back. Index 1 is /base and 2 was /sub: 253 fillers take 3-255, the next wraps to 2.
cat > "$ROOT/reuse.sh" <<SH
#!/bin/sh
set -e
curl -sf --unix-socket "$ROOT/api.sock" -X DELETE "http://localhost/api/v1/mount?mountpoint=/sub"
for i in \$(seq 253); do "$ROOT/mount.sh" /f\$i "$ROOT/out/bootstrap"; done
"$ROOT/mount.sh" /sub "\$1"
stat -c %i "$ROOT/mnt/sub" > "$ROOT/ino.after"
SH
chmod +x "$ROOT/mount.sh" "$ROOT/reuse.sh"

# Mounts the image at /sub in a fresh nydusd, takes handles below it, and once the caches are
# dropped lets reuse.sh put bootstrap $1 into its index. $2 non-empty: the reopens must fail ESTALE.
reuse_index() {
  rm -f "$ROOT/api.sock" "$ROOT/ino.after"
  "$ND" fuse --config "$ROOT/config.json" --bootstrap "$ROOT/out/bootstrap" \
    --virtual-mountpoint /base --mountpoint "$ROOT/mnt" --apisock "$ROOT/api.sock" \
    --log-level info > "$ROOT/nydusd.log" 2>&1 &
  NYDUSD_PID=$!
  for _ in $(seq 50); do [ -S "$ROOT/api.sock" ] && mountpoint -q "$ROOT/mnt" && break; sleep 0.2; done
  if ! "$ROOT/mount.sh" /sub "$ROOT/out/bootstrap"; then
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

step "H6: the same bootstrap in the reused index keeps the handles valid"
reuse_index "$ROOT/out/bootstrap" "" "H6: same bootstrap, handles reopen"

step "H7: another image in the reused index makes the handles stale"
reuse_index "$ROOT/out-b/bootstrap" 1 "H7: other image, handles fail ESTALE"

echo
if [ "$FAILURES" = 0 ]; then
  echo "==== FUSEDEV FILE HANDLES: PASS ===="
  finish 0
else
  echo "==== FUSEDEV FILE HANDLES: FAIL ($FAILURES failing check(s)) ===="
  finish 1
fi
