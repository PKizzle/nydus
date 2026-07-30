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
#   C13 ENOSPC end-to-end — with a healthy backend but a full cache filesystem, a cold read
#                         must fail with ENOSPC, not EIO. Unit tests pin the errno's whole
#                         journey up our own call stack; only a real disk can show whether
#                         the kernel delivers it to read(2) through FAN_DENY_ERRNO.
#
# C11 and C12 are adapted from upstream v3's tests/integration/fanotify_test.go (caseFailClosed,
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
# C13 — a full cache filesystem is answered with FAN_DENY_ERRNO(ENOSPC)
# ===========================================================================
# Unit tests pin the errno's whole journey up our own call stack: a cache `pwrite` failing
# with ENOSPC becomes StorageError::CacheIo, travels up through the typed errors, and
# `deny_errno_for` recovers ENOSPC from the chain (storage/src/cache/cachedfile.rs,
# service/src/fanotify.rs, rafs/src/lib.rs). What they cannot reach is a real full disk, so
# this case starves one and checks two separate things:
#
#   1. the read fails CLOSED — no hang, no zero-filled holes. This is the property callers
#      actually depend on, and it holds whatever errno comes out.
#   2. the daemon answered the permission event with FAN_DENY_ERRNO(ENOSPC) on the wire.
#      That is the boundary we own, and the last point at which the errno is ours to get
#      right; asserting the response bytes rather than a log line proves what reached the
#      kernel, not what we meant to send.
#
# What the READER sees is reported, not asserted, and it is worth knowing why. Measured on
# Linux 7.0.11 (2026-07-28): responding FAN_DENY_ERRNO(ENOSPC) to a process reading the
# marked file DIRECTLY delivers ENOSPC to its read(2) — likewise EDQUOT — so the kernel
# mechanism works exactly as this code assumes. Through the EROFS mount it arrives as EIO:
# EROFS pulls the marked backing file through the page cache and the outer read only learns
# that the folio is not uptodate, which is EIO. The errno is lost in EROFS, above anything
# nydus controls. Assert the half we own; report the half we do not.
#
# Unlike C11 the backend here is HEALTHY: the fetch succeeds and the only operation that
# can fail is the cache write, so the failure is unambiguously the disk-full path.
step "C13: disk-full answered with FAN_DENY_ERRNO(ENOSPC)"

teardown

LOOP_IMG="$ROOT/c13.ext4"
LOOP_MNT="$ROOT/loop-c13"
STAGE_C13="$LOOP_MNT/stage"
# `struct fanotify_response { __s32 fd; __u32 response; }`. FAN_DENY_ERRNO(ENOSPC) is
# FAN_DENY | (28 << 24) == 0x1c000002, which strace renders little-endian as these four
# bytes after the (variable) event fd. Matched as a fixed string — every byte is
# non-printable, so strace's escaping of it is stable.
DENY_ENOSPC_BYTES='\2\0\0\34", 8)'

c13_cleanup() {
  sudo umount "$LOOP_MNT" 2>/dev/null
  rm -f "$LOOP_IMG"
}

if ! command -v mkfs.ext4 >/dev/null; then
  note "SKIP: mkfs.ext4 not installed"
else
  # A small, private ext4 so exhausting it cannot touch anything outside this case.
  # It must be a real ext4 for two independent reasons: tmpfs has no pre-content marks,
  # and only a filesystem we own can be filled to genuine exhaustion.
  rm -rf "$LOOP_MNT"; mkdir -p "$LOOP_MNT"
  dd if=/dev/zero of="$LOOP_IMG" bs=1M count=32 status=none
  mkfs.ext4 -q -F "$LOOP_IMG"

  if ! sudo mount -o loop "$LOOP_IMG" "$LOOP_MNT" 2>"$ROOT/c13.mount.err"; then
    note "SKIP: cannot mount a loopback ext4: $(head -1 "$ROOT/c13.mount.err")"
    c13_cleanup
  else
    sudo mkdir -p "$STAGE_C13"
    sudo cp "$ROOT/out/bootstrap" "$STAGE_C13/bootstrap"
    cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"

    write_config "$STAGE_C13" \
      "\"backend_type\": \"localfs\",
      \"backend_config\": { \"dir\": \"$ROOT/backend\" }"

    # -y so the fanotify group fd is identifiable; without strace the case still runs and
    # checks fail-closed, it just cannot see the response bytes.
    if command -v strace >/dev/null; then
      C13_STRACE="$ROOT/strace-c13.log"
      sudo strace -f -y -o "$C13_STRACE" -e trace=write \
        "$ND" singleton --config "$ROOT/config.json" \
        --fanotify "$STAGE_C13" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
        --log-level info > "$ROOT/nydusd-c13.log" 2>&1 &
    else
      C13_STRACE=""
      sudo "$ND" singleton --config "$ROOT/config.json" \
        --fanotify "$STAGE_C13" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
        --log-level info > "$ROOT/nydusd-c13.log" 2>&1 &
    fi
    sleep 6

    if ! mount | grep -qi "on $ROOT/mnt .*erofs"; then
      echo "--- nydusd-c13.log ---"; tail -40 "$ROOT/nydusd-c13.log"
      case_fail "C13: EROFS not mounted"
      c13_cleanup
    else
      # Exhaust the filesystem only NOW, after the device files are staged and the mount
      # is armed, so setup succeeds and the one remaining operation that needs a fresh
      # block is the cache pwrite. The blob cache file is sized with ftruncate
      # (storage/src/cache/filecache/mod.rs), so it is sparse — every fetched chunk
      # allocates. conv=fsync forces ext4's delayed allocation to settle before we read,
      # otherwise the balloon's blocks are still only reserved and the disk is not
      # actually full yet.
      sudo dd if=/dev/zero of="$LOOP_MNT/balloon" bs=1M conv=fsync status=none 2>/dev/null
      sudo dd if=/dev/zero of="$LOOP_MNT/balloon.tail" bs=4096 conv=fsync status=none 2>/dev/null
      avail=$(df --output=avail -k "$LOOP_MNT" | tail -1 | tr -d ' ')
      note "cache fs free after balloon: ${avail} KiB"
      [ "${avail:-1}" -le 8 ] || note "WARNING: ${avail} KiB still free — the cache write may not fail at all"

      # A cold read of a range that has never been fetched, against a working backend
      # and a full cache disk. dd renders the failing read's errno via strerror, which is
      # what lets us tell ENOSPC from EIO without a helper binary.
      timeout 30 dd if="$ROOT/mnt/hello.txt" of="$ROOT/c13.out" bs=4096 count=16 \
        2>"$ROOT/c13.err"
      rc=$?
      errmsg=$(sed -n 's/^dd: error reading [^:]*: //p' "$ROOT/c13.err" | head -1)
      note "read exit status = $rc, error = ${errmsg:-<none>}"

      # --- (1) fail closed: asserted, and independent of which errno comes out ---------
      if [ "$rc" = 124 ]; then
        case_fail "C13: read HUNG on a full cache disk (must fail closed, not block forever)"
      elif [ "$rc" = 0 ]; then
        nonzero=$(LC_ALL=C tr -d '\0' < "$ROOT/c13.out" | wc -c | tr -d ' ')
        if [ "$nonzero" = 0 ]; then
          case_fail "C13: read returned ZEROS — unfetched sparse holes leaked to the caller"
        else
          # Not a pass: the range was served from cache, so the disk-full path was never
          # taken and the case proved nothing.
          case_fail "C13: read SUCCEEDED — the range was already cached before the balloon; case inconclusive"
        fi
      else
        case_pass "C13: read failed closed on a full cache disk (exit $rc, ${errmsg:-<none>})"
      fi

      # --- (2) the boundary we own: what the daemon actually put on the wire -----------
      sleep 1
      teardown   # flush strace output
      if [ -z "$C13_STRACE" ]; then
        note "SKIP the on-wire check: strace not installed"
      elif grep -qF "$DENY_ENOSPC_BYTES" "$C13_STRACE"; then
        case_pass "C13: daemon answered FAN_DENY_ERRNO(ENOSPC) — errno intact to the kernel"
      else
        case_fail "C13: daemon did NOT answer FAN_DENY_ERRNO(ENOSPC); the errno was lost inside nydus"
        note "responses actually written to the fanotify group fd:"
        grep -E 'write\([0-9]+<anon_inode:\[fanotify\]>' "$C13_STRACE" \
          | sed 's/.*write(/write(/' | sort | uniq -c | head -5
        note "and the daemon's own view of the failure:"
        grep -i 'no space\|enospc\|failed to serve' "$ROOT/nydusd-c13.log" | tail -3
      fi

      # --- (3) what the reader saw: reported, because it is not ours to control --------
      case "$errmsg" in
        "No space left on device")
          note "reader saw ENOSPC — EROFS now propagates the fanotify errno on this kernel" ;;
        "Input/output error")
          note "reader saw EIO — expected: EROFS flattens the denial errno of its backing file" ;;
        *)
          note "reader saw an unexpected error: ${errmsg:-<none>}" ;;
      esac

      # Whatever the errno, no unfetched byte may ever be observable.
      if [ -s "$ROOT/c13.out" ]; then
        zeros=$(LC_ALL=C tr -d '\0' < "$ROOT/c13.out" | wc -c | tr -d ' ')
        [ "$zeros" -gt 0 ] \
          && case_pass "C13: the bytes dd did get before the error were real, not holes" \
          || case_fail "C13: dd received $(stat -c%s "$ROOT/c13.out") bytes of ZEROS before the error"
      fi

      echo "--- nydusd-c13.log (tail) ---"; tail -15 "$ROOT/nydusd-c13.log"
      c13_cleanup   # the daemon is already down: teardown ran to flush strace
    fi
  fi
fi

# ===========================================================================
# C14 — a fully-cached blob loses its mark, and warm reads stop reaching the daemon
# ===========================================================================
# A `FAN_PRE_ACCESS` mark suppresses kernel readahead on the file it guards, so leaving one
# armed over a blob that is already complete costs every later read both a round trip through
# the daemon and the readahead it would otherwise have had. `disarm_if_complete` drops the
# mark once the cache holds every byte.
#
# The failure mode this guards against is silence: if `is_all_data_ready()` never actually
# latches in practice, nothing breaks and no test notices -- the optimisation simply never
# happens. So this case measures the effect rather than the intent:
#
#   1. a FAN_MARK_REMOVE really is issued after the blob fills;
#   2. a subsequent cold-page read delivers NO further pre-content events. That is the whole
#      point: warm reads served straight from the device with the daemon uninvolved.
#
# Ordering, not sampling, is what makes (2) trustworthy -- strace's output is only reliably
# flushed at teardown, so the check is "no successful group-fd read appears after the last
# FAN_MARK_REMOVE line" rather than a count taken mid-run.
step "C14: a fully-cached blob is unmarked"

teardown

if ! command -v strace >/dev/null; then
  note "SKIP: strace not installed"
else
  rm -rf "$ROOT/stage-c14"; mkdir -p "$ROOT/stage-c14"
  cp "$ROOT/out/bootstrap" "$ROOT/stage-c14/bootstrap"
  cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"

  write_config "$ROOT/stage-c14" \
    "\"backend_type\": \"localfs\",
    \"backend_config\": { \"dir\": \"$ROOT/backend\" }"

  C14_STRACE="$ROOT/strace-c14.log"
  sudo strace -f -y -o "$C14_STRACE" -e trace=fanotify_mark,read \
    "$ND" singleton --config "$ROOT/config.json" \
    --fanotify "$ROOT/stage-c14" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
    --log-level info > "$ROOT/nydusd-c14.log" 2>&1 &
  sleep 6

  if ! mount | grep -qi "on $ROOT/mnt .*erofs"; then
    echo "--- nydusd-c14.log ---"; tail -40 "$ROOT/nydusd-c14.log"
    case_fail "C14: EROFS not mounted"
  else
    # Cold read of the whole file: every chunk of the blob is fetched, which is what
    # latches the all-ready flag and triggers the unmark.
    C14_COLD=$(timeout 60 sha256sum "$ROOT/mnt/hello.txt" 2>/dev/null | awk '{print $1}')
    [ "$C14_COLD" = "$SRC_HELLO" ] \
      && case_pass "C14: cold read correct (blob now fully cached)" \
      || case_fail "C14: cold read mismatch (src=$SRC_HELLO mnt=$C14_COLD)"

    sleep 1
    # Evict the page cache so the warm read really goes back to the device; without this
    # it is answered from cache and would raise no events whether or not we unmarked.
    # A failure here is fatal, not a warning: without the eviction the warm read is answered
    # from the page cache and raises no events whether or not the unmark worked, so the two
    # checks below would pass for the wrong reason.
    sync
    if ! echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1; then
      case_fail "C14: could not drop the page cache; the warm-read checks would be vacuous"
    fi

    C14_WARM=$(timeout 60 sha256sum "$ROOT/mnt/hello.txt" 2>/dev/null | awk '{print $1}')
    [ "$C14_WARM" = "$SRC_HELLO" ] \
      && case_pass "C14: warm read still correct after the mark was dropped" \
      || case_fail "C14: warm read mismatch (src=$SRC_HELLO mnt=$C14_WARM)"

    sleep 1
    teardown   # flush strace

    # (1) The unmark happened. FAN_MARK_REMOVE is 0x2; strace renders the flags symbolically.
    if grep -qE 'fanotify_mark\([0-9]+[^,]*, *FAN_MARK_REMOVE' "$C14_STRACE"; then
      case_pass "C14: FAN_MARK_REMOVE issued once the blob was complete"
    else
      case_fail "C14: no FAN_MARK_REMOVE — the blob never latched all-ready, so the mark was never dropped"
      note "fanotify_mark calls seen:"
      grep -oE 'fanotify_mark\([0-9]+[^)]*\)' "$C14_STRACE" | sed 's/,.*AT_FDCWD.*//' | sort -u | head -4
    fi

    # (2) And nothing reached the daemon afterwards. Successful reads only: the workers poll
    # the non-blocking group fd continuously and those EAGAIN returns are not events.
    last_remove=$(grep -nE 'fanotify_mark\([0-9]+[^,]*, *FAN_MARK_REMOVE' "$C14_STRACE" \
      | tail -1 | cut -d: -f1)
    if [ -n "$last_remove" ]; then
      # With `-f` and two workers a read can be split across two lines --
      #   PID read(4<anon_inode:[fanotify]>, <unfinished ...>
      #   PID <... read resumed>0x..., 8192) = 72
      # -- and the resumed half carries the return value but not the fd annotation. Counting
      # only the single-line form would silently miss exactly the events this check exists to
      # catch, so pair the halves by pid instead. Only the group fd is counted: the daemon
      # reads plenty of other descriptors, and a bare `read resumed` says nothing about which.
      after=$(tail -n "+$((last_remove + 1))" "$C14_STRACE" | awk '
        /read\([0-9]+<anon_inode:\[fanotify\]>/ && /<unfinished \.\.\.>/ { pending[$1] = 1; next }
        /read\([0-9]+<anon_inode:\[fanotify\]>/ { if ($0 ~ /=[[:space:]]*[1-9]/) n++; next }
        /<\.\.\. read resumed>/ {
          if (pending[$1] && $0 ~ /=[[:space:]]*[1-9]/) n++
          delete pending[$1]; next
        }
        END { print n+0 }')
      note "pre-content events delivered after the unmark: $after"
      [ "$after" = "0" ] \
        && case_pass "C14: warm reads bypassed the daemon entirely" \
        || case_fail "C14: $after event(s) still reached the daemon after unmarking"
    fi
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
