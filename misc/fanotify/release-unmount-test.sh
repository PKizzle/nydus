#!/usr/bin/env bash
# Snapshotter daemon release over the fanotify path: an auto-accel daemon whose last holder is
# released must leave no EROFS mount behind. Builds a zran artifact (gzip layer + zran index +
# bootstrap), then runs the root-only `release_unmounts_fanotify_erofs` test, which starts the
# daemon through `DaemonSupervisor::ensure_instance_local`, releases it, and checks /proc/mounts,
# and `shutdown_keeps_busy_fanotify_mounts_live`, which stops three busy mounts without an fd
# store: they stop together, keep live records, and the next start re-arms them.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/release-unmount}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src,out,artifact/backend,artifact/stage}
perl -e 'print "RELEASE_OK_0123456789" x 6000' > "$ROOT/src/hello.txt"
tar -C "$ROOT/src" -czf "$ROOT/layer.tar.gz" .
DATA=$(sha256sum "$ROOT/layer.tar.gz" | awk '{print $1}')

OUT=$("$NI" create --type targz-ref --fs-version 6 -D "$ROOT/out" "$ROOT/layer.tar.gz" 2>&1)
BOOTSTRAP=$(echo "$OUT" | sed -n 's/^meta blob path: //p' | tr -d ' ')
[ -f "$BOOTSTRAP" ] || fail "no bootstrap: $OUT"
META=$(ls "$ROOT/out" | grep -v "^$(basename "$BOOTSTRAP")\$" | head -1)
cp "$ROOT/layer.tar.gz" "$ROOT/artifact/backend/$DATA"
cp "$ROOT/out/$META" "$ROOT/artifact/backend/$META"
cp "$BOOTSTRAP" "$ROOT/artifact/bootstrap"
cp "$BOOTSTRAP" "$ROOT/artifact/stage/bootstrap"

# A test filter that matches nothing passes with "0 passed": require each test to have run.
for test in release_unmounts_fanotify_erofs shutdown_keeps_busy_fanotify_mounts_live; do
  OUT=$(NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
    "daemon::tests::$test" -- --ignored --exact --nocapture 2>&1)
  echo "$OUT" | tail -5
  echo "$OUT" | grep -q "test result: ok. 1 passed" || fail "$test failed or did not run"
done
if grep -q " $ROOT/snapshotter" /proc/self/mounts; then
  grep " $ROOT/snapshotter" /proc/self/mounts
  fail "mount still present under $ROOT/snapshotter*"
fi
echo "==== RELEASE-UNMOUNT: PASS ===="
