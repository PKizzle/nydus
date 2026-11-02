#!/usr/bin/env bash
# Snapshotter restart over the fanotify path: a successor process takes over a running
# auto-accel daemon from the fanotify group fd parked in systemd's fd store, then reads file
# data the predecessor never fetched. Builds a zran artifact (gzip layer + zran index +
# bootstrap) and runs the root-only `fanotify_takeover_serves_uncached_file_data` test, which
# plays systemd's fd store and kills the predecessor while its marks are live.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/takeover}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src/bin,out,artifact/backend}
head -c 3000000 /dev/urandom > "$ROOT/src/bin/tool"
echo "root:x:0:0:root:/root:/bin/sh" > "$ROOT/src/passwd"
tar -C "$ROOT/src" -czf "$ROOT/layer.tar.gz" .
DATA=$(sha256sum "$ROOT/layer.tar.gz" | awk '{print $1}')

OUT=$("$NI" create --type targz-ref --fs-version 6 -D "$ROOT/out" "$ROOT/layer.tar.gz" 2>&1)
BOOTSTRAP=$(echo "$OUT" | sed -n 's/^meta blob path: //p' | tr -d ' ')
[ -f "$BOOTSTRAP" ] || fail "no bootstrap: $OUT"
META=$(ls "$ROOT/out" | grep -v "^$(basename "$BOOTSTRAP")\$" | head -1)
cp "$ROOT/layer.tar.gz" "$ROOT/artifact/backend/$DATA"
cp "$ROOT/out/$META" "$ROOT/artifact/backend/$META"
cp "$BOOTSTRAP" "$ROOT/artifact/bootstrap"

NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::tests::fanotify_takeover_serves_uncached_file_data -- --ignored --exact --nocapture
rc=$?
grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
[ $rc = 0 ] || fail "the successor did not serve the taken-over mount"
echo "==== FANOTIFY TAKEOVER: PASS ===="
