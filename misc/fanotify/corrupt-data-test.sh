#!/usr/bin/env bash
# Fill validation on the fanotify path, through a real EROFS mount:
#   1. a backend blob with one flipped byte: reading the file fails with EIO instead of
#      returning the bad bytes, and once the backend is repaired the same read succeeds (the
#      failed fill never marked the chunk ready);
#   2. a cache file corrupted while no daemon ran: the next daemon's one-time check of the
#      chunks already marked ready revokes the bad chunk, and the read fetches it again.
# Requirements as for runtime-test.sh: Linux >= 6.14, root, ROOT on ext4 (not tmpfs).
set -u

NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
ROOT="${ROOT:-/var/tmp/fan-corrupt}"
LOG=$ROOT/nydusd.log
DAEMON="[s]ingleton --config $ROOT/config.json"
MARK=FANOTIFY_VALIDATE_0123456789ABCDEF

step() { echo; echo "### $* ###"; }
stop_daemon() {
  sudo umount "$ROOT/mnt" 2>/dev/null
  sudo pkill -f "$DAEMON" 2>/dev/null
  sleep 1
}
fail() { echo "FAIL: $*"; echo "--- nydusd.log ---"; tail -30 "$LOG"; stop_daemon; exit 1; }
start_daemon() {
  sudo "$ND" singleton --config "$ROOT/config.json" \
    --fanotify "$ROOT/stage" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
    --log-level info > "$LOG" 2>&1 &
  for _ in $(seq 50); do
    mount | grep -qF "$ROOT/mnt type erofs" && return 0
    sleep 0.2
  done
  fail "EROFS not mounted"
}
# Flip the byte at offset $2 of file $1 in place.
flip() {
  local b
  b=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "$(printf '\\%03o' $((b ^ 0xff)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

step "build image (compressor none, so the marker is visible in the blob)"
stop_daemon
rm -rf "$ROOT"
mkdir -p "$ROOT"/{src,out,backend,stage,mnt}
perl -e "print '$MARK' x 4096" > "$ROOT/src/hello.txt"
head -c 262144 /dev/urandom > "$ROOT/src/random.bin"
SRC_HELLO=$(sha256sum "$ROOT/src/hello.txt" | awk '{print $1}')
SRC_RAND=$(sha256sum "$ROOT/src/random.bin" | awk '{print $1}')
"$NI" create --fs-version 6 --compressor none -B "$ROOT/out/bootstrap" -D "$ROOT/out" \
  "$ROOT/src" >/dev/null || fail "nydus-image create"
BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || fail "no data blob produced"
cp "$ROOT/out/$BLOB" "$ROOT/backend/$BLOB"
cp "$ROOT/out/bootstrap" "$ROOT/stage/bootstrap"
cat > "$ROOT/config.json" <<EOF
{ "blobs": [ {
  "type": "bootstrap", "id": "bootstrap1", "domain_id": "d1",
  "config": {
    "id": "factory1",
    "backend_type": "localfs",
    "backend_config": { "dir": "$ROOT/backend" },
    "cache_type": "fanotify",
    "cache_config": { "work_dir": "$ROOT/stage" },
    "metadata_path": "$ROOT/stage/bootstrap"
  } } ] }
EOF
OFF=$(grep -abo "$MARK" "$ROOT/backend/$BLOB" | head -1 | cut -d: -f1)
[ -n "$OFF" ] || fail "marker not found in the blob"
OFF=$((OFF + 4))
echo "blob=$BLOB marker byte at $OFF"

step "case 1: corrupted backend byte"
flip "$ROOT/backend/$BLOB" "$OFF"
start_daemon
ERR=$(cat "$ROOT/mnt/hello.txt" 2>&1 >/dev/null)
echo "read hello.txt: ${ERR:-<no error>}"
case "$ERR" in *"Input/output error"*) ;; *) fail "corrupted chunk was not refused with EIO";; esac
MNT_RAND=$(sha256sum "$ROOT/mnt/random.bin" | awk '{print $1}')
[ "$MNT_RAND" = "$SRC_RAND" ] || fail "an intact file stopped reading correctly"
grep -q "digest value of chunk" "$LOG" || fail "no validation failure logged"
flip "$ROOT/backend/$BLOB" "$OFF"
MNT_HELLO=$(sha256sum "$ROOT/mnt/hello.txt" | awk '{print $1}')
[ "$MNT_HELLO" = "$SRC_HELLO" ] || fail "repaired backend still reads wrong ($MNT_HELLO)"
echo "case 1: EIO while corrupt, correct once repaired"

step "case 2: corrupted cache file, checked by the next daemon"
cat "$ROOT/mnt/random.bin" > /dev/null
stop_daemon
CACHE="$ROOT/stage/$BLOB.blob.data"
COFF=$(grep -abo "$MARK" "$CACHE" | head -1 | cut -d: -f1)
[ -n "$COFF" ] || fail "marker not found in the cache file"
flip "$CACHE" $((COFF + 4))
# As left by a daemon that did not validate: without the digest record, the next daemon cannot
# trust its ready chunks and checks them all.
rm "$CACHE.digests"
start_daemon
for _ in $(seq 100); do
  grep -q "checked every cached chunk of blob $BLOB against its digest" "$LOG" && break
  sleep 0.1
done
grep -q "checked every cached chunk of blob $BLOB against its digest" "$LOG" || fail "verification did not finish"
grep -q "fails validation" "$LOG" || fail "the corrupted cached chunk was not reported"
MNT_HELLO=$(sha256sum "$ROOT/mnt/hello.txt" | awk '{print $1}')
[ "$MNT_HELLO" = "$SRC_HELLO" ] || fail "revoked chunk reads wrong ($MNT_HELLO)"
echo "case 2: corrupted cached chunk revoked and fetched again"

stop_daemon
echo
echo "==== FANOTIFY FILL VALIDATION: PASS ===="
