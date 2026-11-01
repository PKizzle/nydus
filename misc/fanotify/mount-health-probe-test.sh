#!/usr/bin/env bash
# Snapshotter mount-health probe against mounts that list their directories but cannot serve
# file data. Builds a RAFS v6 bootstrap, drops its data blob, and runs the root-only
# `mount_health_probe_reports_mounts_without_data_dead` test: a FUSE daemon whose registry
# refuses every fetch, and an EROFS mount of the bootstrap without `device=`, must both
# report dead.
#
# Needs root, FUSE, EROFS and cargo. No pre-content marks are involved, so any ROOT works.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/mount-health-probe}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src,probe,blobs}
perl -e 'print "PROBE_DATA_0123456789" x 6000' > "$ROOT/src/hello.txt"
OUT=$("$NI" create --type dir-rafs --fs-version 6 -B "$ROOT/probe/bootstrap" -D "$ROOT/blobs" \
  "$ROOT/src" 2>&1) || fail "build: $OUT"
rm -rf "$ROOT/blobs"

NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::tests::mount_health_probe_reports_mounts_without_data_dead -- --ignored --exact --nocapture \
  || fail "a mount without data reported healthy"
if grep -q " $ROOT/" /proc/self/mounts; then
  grep " $ROOT/" /proc/self/mounts
  fail "mount still present under $ROOT"
fi
echo "==== MOUNT-HEALTH PROBE: PASS ===="
