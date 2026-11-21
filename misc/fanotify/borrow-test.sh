#!/usr/bin/env bash
# Cache borrowing (docs/nydus-fanotify.md, "Borrowing"):
#   0. the nydus-storage borrowing unit tests (from STORAGE_TEST_BIN, the
#      `cargo test -p nydus-storage --lib --no-run` binary, or through cargo when unset), so
#      they also run on the kernels and page sizes the VM jobs boot;
#   1. the kernel behaviour it rests on: a lender cache file carrying a live FAN_PRE_ACCESS mark
#      is read by a borrowing image without raising a single event on the marking group, and
#      SEEK_DATA raises none either (the root-only nydus-service test, run from
#      SERVICE_TEST_BIN, the `cargo test -p nydus-service --lib --no-run` binary, or through
#      cargo when unset);
#   2. end to end through the snapshotter: two images share a blob served by a local registry;
#      after the first has read every file, the second reads them with at most one registry
#      request of its own per blob and borrows the rest.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI=$(realpath "${NYDUS_IMAGE:-./target/release/nydus-image}")
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/borrow-rt}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{unit,kernel,e2e/src/sub,e2e/blobs}

echo "== case 0: storage unit tests"
if [ -n "${STORAGE_TEST_BIN:-}" ]; then TEST=("$STORAGE_TEST_BIN"); else TEST=(cargo test -q -p nydus-storage --lib --); fi
# On ROOT: the hole test needs a filesystem whose SEEK_DATA sees holes.
OUT=$(TMPDIR="$ROOT/unit" "${TEST[@]}" cache::cachedfile::borrow_tests cache::borrow::tests 2>&1)
echo "$OUT" | grep -E "panicked|error" -A2
echo "$OUT" | tail -3
echo "$OUT" | grep -qE "test result: ok\. [1-9][0-9]* passed; 0 failed" || fail "the storage borrow tests failed"

echo "== case 1: no lender events"
if [ -n "${SERVICE_TEST_BIN:-}" ]; then TEST=("$SERVICE_TEST_BIN"); else TEST=(cargo test -q -p nydus-service --lib --); fi
OUT=$(NYDUS_FANOTIFY_TEST_DIR="$ROOT/kernel" "${TEST[@]}" \
  fanotify::tests::borrowing_raises_no_event_on_a_marked_lender --exact --nocapture 2>&1)
echo "$OUT" | grep -E "BORROW EVENTS|panicked" -A2
echo "$OUT" | tail -3
# The test prints SKIP and passes when it cannot run; here it must run.
echo "$OUT" | grep -q SKIP && fail "the lender event test did not run"
echo "$OUT" | grep -q "test result: ok. 1 passed" || fail "the lender event test failed"

echo "== case 2: a second image borrows"
# 4 KiB chunks, so one file spans many chunks and many reads.
yes BORROW_E2E_0123456789ABCDEF | head -c 458752 > "$ROOT/e2e/src/big.txt"
head -c 300000 /dev/urandom > "$ROOT/e2e/src/random.bin"
echo "borrow-subdir-marker" > "$ROOT/e2e/src/sub/small.txt"
OUT=$("$NI" create --fs-version 6 --compressor none --chunk-size 0x1000 \
  -B "$ROOT/e2e/bootstrap" -D "$ROOT/e2e/blobs" "$ROOT/e2e/src" 2>&1) || fail "nydus-image create: $OUT"
NYDUS_IMAGE="$NI" NYDUS_E2E_ROOT="$ROOT/e2e" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::e2e_tests::a_second_image_borrows_a_shared_blob -- --ignored --exact --nocapture \
  || fail "the second image did not borrow"
if grep -q " $ROOT/" /proc/self/mounts; then
  grep " $ROOT/" /proc/self/mounts
  fail "mount still present under $ROOT"
fi
echo "==== CACHE BORROWING: PASS ===="
