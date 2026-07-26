#!/usr/bin/env bash
# Behavioural cases for the fanotify pre-content path that runtime-test.sh does not cover.
#
#   C11 fail-closed     — with the backend unreachable, a cold read must ERROR. It must not
#                         hang, and it must not quietly return the sparse file's zeros. This
#                         is the single most important property of the whole subsystem: the
#                         entire point of pre-content marks is that unfetched bytes are never
#                         observable.
#   C12 ground truth    — run the daemon under strace and prove mechanically that it is on
#                         the read path: fanotify_init succeeded, the daemon read events off
#                         the group fd, wrote responses back, and pwrite(2)'d into the blob
#                         cache file. Byte-comparison alone cannot distinguish "the daemon
#                         served this" from "the data happened to already be there".
#
# Both cases are adapted from upstream v3's tests/integration/fanotify_test.go (caseFailClosed,
# caseStraceGroundTruth); see docs/upstream-v3-evaluation.md.
set -u

# Requirements: Linux >= 6.14 with CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y, run as root (mount(2)),
# ROOT on a fs that supports fanotify pre-content (ext4 works; tmpfs returns ENOTSUP), and
# strace(1) for C12.
# Override the binaries via env, e.g. NYDUS_IMAGE=... NYDUSD=... ROOT=...
NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fan-precontent}"   # must NOT be tmpfs

# A port with nothing listening: every backend fetch fails fast and deterministically,
# with no registry container to manage.
DEAD_PORT="${DEAD_PORT:-1}"

FAILURES=0

step() { echo; echo "### $* ###"; }
note() { echo "  - $*"; }
case_fail() { echo "  !! FAIL: $*"; FAILURES=$((FAILURES + 1)); }
case_pass() { echo "  ok: $*"; }

teardown() {
  sudo umount "$ROOT/mnt" 2>/dev/null
  sudo pkill -f "nydusd singleton" 2>/dev/null
  sleep 1
}

finish() {
  teardown
  exit "${1:-0}"
}

trap 'finish 1' INT TERM

# ---------------------------------------------------------------------------
# Shared fixture: build a RAFS v6 image once and reuse it for both cases.
# ---------------------------------------------------------------------------
step "reset dirs"
teardown
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src,out,backend,mnt}

step "build source rootfs"
# Large enough that reads span many blocks, and distinctive enough that a zero-filled
# result is unmistakable.
perl -e 'print "PRECONTENT_CASE_MARKER_0123456789" x 8192' > "$ROOT/src/hello.txt"   # ~256 KiB
SRC_HELLO=$(sha256sum "$ROOT/src/hello.txt" | awk '{print $1}')
note "src hello sha256=$SRC_HELLO"

step "nydus-image create (RAFS v6, compressor none, block-size 4096)"
"$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" || { echo "nydus-image create failed"; finish 1; }

BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || { echo "no data blob produced"; finish 1; }
note "blob_id=$BLOB size=$(stat -c%s "$ROOT/out/$BLOB")"

# Write a BlobCacheList config. $1 = stage dir, $2 = backend stanza.
write_config() {
  cat > "$ROOT/config.json" <<EOF
{ "blobs": [ {
  "type": "bootstrap", "id": "bootstrap1", "domain_id": "d1",
  "config": {
    "id": "factory1",
    $2,
    "cache_type": "fanotify",
    "cache_config": { "work_dir": "$1" },
    "metadata_path": "$1/bootstrap"
  } } ] }
EOF
}

# ===========================================================================
# C11 — fail closed when the backend is unreachable
# ===========================================================================
step "C11: fail-closed (backend unreachable)"

rm -rf "$ROOT/stage-c11"; mkdir -p "$ROOT/stage-c11"
cp "$ROOT/out/bootstrap" "$ROOT/stage-c11/bootstrap"

# The bootstrap is local, so the mount succeeds; only data-blob fetches go to the
# backend, and every one of them fails against a dead port.
write_config "$ROOT/stage-c11" \
  "\"backend_type\": \"registry\",
    \"backend_config\": {
      \"scheme\": \"http\",
      \"host\": \"127.0.0.1:$DEAD_PORT\",
      \"repo\": \"nydus/precontent-fail-closed\",
      \"timeout\": 5,
      \"connect_timeout\": 5,
      \"retry_limit\": 0
    }"

sudo "$ND" singleton --config "$ROOT/config.json" \
  --fanotify "$ROOT/stage-c11" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
  --log-level info > "$ROOT/nydusd-c11.log" 2>&1 &
sleep 4

if ! mount | grep -qi "on $ROOT/mnt .*erofs"; then
  echo "--- nydusd-c11.log ---"; tail -40 "$ROOT/nydusd-c11.log"
  case_fail "C11: EROFS not mounted"
else
  # A cold read of a range that has never been fetched. Three outcomes:
  #   exit 124        -> the read hung (timeout killed it)          => FAIL
  #   exit 0 + zeros  -> unfetched sparse holes leaked to the caller => FAIL (the bug)
  #   non-zero exit   -> the fetch failure surfaced as a read error  => PASS
  timeout 30 dd if="$ROOT/mnt/hello.txt" of="$ROOT/c11.out" bs=4096 count=16 \
    2>"$ROOT/c11.err"
  rc=$?
  note "read exit status = $rc"

  if [ "$rc" = 124 ]; then
    case_fail "C11: read HUNG with the backend down (must fail closed, not block forever)"
  elif [ "$rc" = 0 ]; then
    # It returned successfully — the only acceptable way that happens is if the bytes
    # were genuinely there, which they cannot be with the backend unreachable.
    nonzero=$(LC_ALL=C tr -d '\0' < "$ROOT/c11.out" | wc -c | tr -d ' ')
    if [ "$nonzero" -gt 0 ]; then
      case_fail "C11: read SUCCEEDED with the backend down ($nonzero non-zero bytes)"
    else
      case_fail "C11: read returned ZEROS — unfetched sparse holes leaked to the caller"
    fi
  else
    case_pass "C11: read failed closed (exit $rc): $(head -1 "$ROOT/c11.err")"
  fi
fi

echo "--- nydusd-c11.log (tail) ---"; tail -15 "$ROOT/nydusd-c11.log"
teardown

# ===========================================================================
# C12 — strace ground truth: the daemon really is on the read path
# ===========================================================================
step "C12: strace ground truth"

if ! command -v strace >/dev/null; then
  note "SKIP: strace not installed"
else
  rm -rf "$ROOT/stage-c12"; mkdir -p "$ROOT/stage-c12"
  cp "$ROOT/out/bootstrap" "$ROOT/stage-c12/bootstrap"
  cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"

  write_config "$ROOT/stage-c12" \
    "\"backend_type\": \"localfs\",
    \"backend_config\": { \"dir\": \"$ROOT/backend\" }"

  STRACE_LOG="$ROOT/strace-c12.log"
  # -y annotates each fd with its path, which is what lets us tell a write to the
  # fanotify group apart from any other write, and a pwrite into the blob cache file
  # apart from any other pwrite.
  sudo strace -f -y -o "$STRACE_LOG" \
    -e trace=fanotify_init,fanotify_mark,read,write,pwrite64 \
    "$ND" singleton --config "$ROOT/config.json" \
    --fanotify "$ROOT/stage-c12" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
    --log-level info > "$ROOT/nydusd-c12.log" 2>&1 &
  sleep 6

  if ! mount | grep -qi "on $ROOT/mnt .*erofs"; then
    echo "--- nydusd-c12.log ---"; tail -40 "$ROOT/nydusd-c12.log"
    case_fail "C12: EROFS not mounted"
  else
    MNT_HELLO=$(timeout 60 sha256sum "$ROOT/mnt/hello.txt" 2>/dev/null | awk '{print $1}')
    sleep 1
    teardown   # flush strace output

    [ "$MNT_HELLO" = "$SRC_HELLO" ] \
      && case_pass "C12: content matches source" \
      || case_fail "C12: content mismatch (src=$SRC_HELLO mnt=$MNT_HELLO)"

    # fanotify_init must have succeeded — a negative return means we silently fell
    # back to some other path.
    if grep -qE 'fanotify_init\(.*\)[[:space:]]*=[[:space:]]*[0-9]+' "$STRACE_LOG"; then
      case_pass "C12: fanotify_init succeeded"
    else
      case_fail "C12: no successful fanotify_init in strace output"
      grep -m3 'fanotify_init' "$STRACE_LOG" || true
    fi

    # Marks were actually placed on the device files.
    grep -qE 'fanotify_mark\(.*\)[[:space:]]*=[[:space:]]*0' "$STRACE_LOG" \
      && case_pass "C12: fanotify_mark placed" \
      || case_fail "C12: no successful fanotify_mark in strace output"

    # Events were read off the group fd, and responses written back to it. With -y the
    # fanotify group fd renders as anon_inode:[fanotify].
    grep -qE 'read\([0-9]+<anon_inode:\[fanotify\]>.*\)[[:space:]]*=[[:space:]]*[1-9]' "$STRACE_LOG" \
      && case_pass "C12: daemon read pre-content events off the group fd" \
      || case_fail "C12: no successful read() on the fanotify group fd"

    grep -qE 'write\([0-9]+<anon_inode:\[fanotify\]>.*\)[[:space:]]*=[[:space:]]*[1-9]' "$STRACE_LOG" \
      && case_pass "C12: daemon wrote permission responses back" \
      || case_fail "C12: no successful write() to the fanotify group fd"

    # And the fetched bytes landed in the blob cache file, which *is* the EROFS device.
    grep -qE "pwrite64\([0-9]+<[^>]*${BLOB}\.blob\.data>.*\)[[:space:]]*=[[:space:]]*[1-9]" "$STRACE_LOG" \
      && case_pass "C12: fetched bytes pwrite(2)'d into the blob cache file" \
      || case_fail "C12: no successful pwrite64() into ${BLOB}.blob.data"
  fi
fi

# ===========================================================================
step "SUMMARY"
if [ "$FAILURES" = 0 ]; then
  echo "==== FANOTIFY PRE-CONTENT CASES: PASS ===="
  finish 0
else
  echo "==== FANOTIFY PRE-CONTENT CASES: FAIL ($FAILURES failing check(s)) ===="
  finish 1
fi
