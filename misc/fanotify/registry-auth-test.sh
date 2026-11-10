#!/usr/bin/env bash
# Registry-backed images on the fanotify path behind credentials: builds a RAFS v6 image and
# runs the root-only `registry_credentials_survive_restart_and_heal` test, which serves its
# data blob from local mock registries demanding Basic auth and the bearer-token flow, feeds
# credentials through the `PUT /api/v1/auth` handler, and checks a pull, an in-place heal, a
# takeover with credentials, and a takeover without them (EIO, never zeros, and a warning).
# No credential may reach a log line or a file under ROOT.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/registry-auth}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src/sub,blobs}
perl -e 'print "REGISTRY_AUTH_OK_0123456789ABCDEF" x 4096' > "$ROOT/src/hello.txt"
head -c 300000 /dev/urandom > "$ROOT/src/random.bin"
head -c 70000 /dev/urandom > "$ROOT/src/sub/other.bin"
echo "registry-auth-subdir-marker" > "$ROOT/src/sub/small.txt"

OUT=$("$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/bootstrap" -D "$ROOT/blobs" "$ROOT/src" 2>&1) || fail "nydus-image create: $OUT"
[ -n "$(ls "$ROOT/blobs")" ] || fail "no data blob"

NYDUS_E2E_ROOT="$ROOT" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::e2e_tests::registry_credentials_survive_restart_and_heal -- --ignored --exact --nocapture \
  || fail "registry credentials on the fanotify path"
grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
echo "==== REGISTRY AUTH: PASS ===="
