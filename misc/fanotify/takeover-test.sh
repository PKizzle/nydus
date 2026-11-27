#!/usr/bin/env bash
# Snapshotter restart over the fanotify path: a successor process takes over a running
# auto-accel daemon from the fanotify group fd parked in systemd's fd store, then reads file
# data the predecessor never fetched. Builds a zran artifact (gzip layer + zran index +
# bootstrap) and runs the root-only `fanotify_takeover_serves_uncached_file_data` test, which
# plays systemd's fd store and kills the predecessor while its marks are live, once on all CPUs
# and once pinned to one. Before the successor starts, a child reads an event of a cold read and
# exits without answering it, as a predecessor killed mid-fill does; the read must complete.
# After a graceful stop instead, the predecessor's events-answered token spares its group the
# sweep, and the successor evicts the token from the fd store before it serves. First, the
# driver probe must select fanotify with an fd store and FUSE without one.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/takeover}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src/bin,out,artifact/backend,artifact/stage,unit}

# The sweep on its own (SERVICE_TEST_BIN, the `cargo test -p nydus-service --lib --no-run`
# binary, or through cargo when unset).
if [ -n "${SERVICE_TEST_BIN:-}" ]; then TEST=("$SERVICE_TEST_BIN"); else TEST=(cargo test -q -p nydus-service --lib --); fi
OUT=$(NYDUS_FANOTIFY_TEST_DIR="$ROOT/unit" "${TEST[@]}" \
  fanotify::tests::a_dead_readers_event_is_denied_by_the_sweep --exact --nocapture 2>&1)
echo "$OUT" | tail -3
echo "$OUT" | grep -q SKIP && fail "the stranded event test did not run"
echo "$OUT" | grep -q "test result: ok. 1 passed" || fail "the stranded event test failed"
# The driver probe selects fanotify only when systemd's fd store would hold its group: with
# FDSTORE set, as systemd >= 254 sets it for a unit with FileDescriptorStoreMax=, and FUSE
# without. The tests below play the fd store themselves and construct fanotify daemons directly.
for case in "fanotify env FDSTORE=16" "fusedev env -u FDSTORE -u NOTIFY_SOCKET"; do
  read -r expect launcher <<<"$case"
  OUT=$(NYDUS_E2E_ROOT="$ROOT" NYDUS_EXPECT_DRIVER="$expect" $launcher "$CARGO" test -p nydus-snapshotter --lib \
    probe::tests::probe_selects_the_expected_driver -- --ignored --exact --nocapture 2>&1)
  echo "$OUT" | grep -q "selected driver: $expect" || { echo "$OUT" | tail -20; fail "the probe did not select $expect"; }
  echo "the probe selected $expect"
done
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
cp "$BOOTSTRAP" "$ROOT/artifact/stage/bootstrap"

# Once as is and once on a single CPU: with one CPU, libtest runs tests serially and its
# output differs, and the daemon's threads compete for that CPU. A third run starts the
# successor from a state without the blob list, as releases up to 3.3.0 saved it. A fourth
# stops the predecessor gracefully: its events-answered token spares the group the sweep.
for run in "" "taskset -c 0" "env NYDUS_TAKEOVER_STATE_WITHOUT_BLOB_LIST=1" "env NYDUS_TAKEOVER_GRACEFUL=1"; do
  rm -rf "$ROOT/snapshotter"
  NYDUS_E2E_ROOT="$ROOT" $run "$CARGO" test -p nydus-snapshotter --lib \
    daemon::tests::fanotify_takeover_serves_uncached_file_data -- --ignored --exact --nocapture
  rc=$?
  grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
  [ $rc = 0 ] || fail "the successor did not serve the taken-over mount${run:+ ($run)}"
done
echo "==== FANOTIFY TAKEOVER: PASS ===="
