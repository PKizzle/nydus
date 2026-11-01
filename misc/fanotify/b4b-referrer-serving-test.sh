#!/usr/bin/env bash
# B4b: serve a nydus image whose bootstrap came from an OCI referrer artifact (the nydusify /
# Go-snapshotter model) the way the snapshotter's Prepare path does: through
# `DaemonSupervisor::ensure_instance` with the fanotify driver selected, its data blob fetched on
# demand from a registry. Builds the image, then runs the root-only
# `referrer_daemon_serves_every_file` test, which serves the blob from a local HTTP registry and
# compares every file of the mount with the source. Detection, the cosign trust policy and
# bootstrap materialization are covered by `misc/referrer/trust-e2e.sh`.
#
# Needs root, FUSE and cargo.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/b4b-rt}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src/sub,blobs}
perl -e 'print "B4B_REFERRER_SERVING_OK_0123456789AB" x 4096' > "$ROOT/src/hello.txt"
head -c 180000 /dev/urandom > "$ROOT/src/random.bin"
echo "b4b-subdir-marker" > "$ROOT/src/sub/small.txt"

OUT=$("$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/bootstrap" -D "$ROOT/blobs" "$ROOT/src" 2>&1) || fail "nydus-image create: $OUT"
[ -n "$(ls "$ROOT/blobs")" ] || fail "no data blob"

NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::e2e_tests::referrer_daemon_serves_every_file -- --ignored --exact --nocapture \
  || fail "the referrer daemon did not serve every file"
if grep -q " $ROOT/" /proc/self/mounts; then
  grep " $ROOT/" /proc/self/mounts
  fail "mount still present under $ROOT"
fi
echo "==== B4b REFERRER SERVING: PASS ===="
