#!/usr/bin/env bash
# A fanotify cache a daemon stopped cleanly is sealed, and the next daemon serves it without a
# backend read; a cache another boot left unsealed keeps its bytes, which the next daemon checks
# against their digests before it serves them, fetching only what fails.
#
#   1. Serve a fresh image, read every file, stop nydusd with SIGTERM: the chunk map is sealed.
#   2. Replace the backend blob with zeros and serve again: every file reads intact, so nothing
#      was fetched; on a kernel with EROFS page cache sharing the mount joins its domain.
#   3. Kill that daemon with SIGKILL: having filled nothing, it leaves the map sealed. Record a
#      foreign boot in it, as a crash would, and serve again, still from zeros: the daemon
#      forgets the ready chunks, and every file reads intact, rechecked from the cache file.
#   4. Kill it again, record a foreign boot, damage the first cached chunk and restore the
#      backend: every file reads intact, the damaged chunk fetched again.
#
#   NYDUS_IMAGE, NYDUSD  binaries
#   ROOT                 work dir on a fs with pre-content marks (ext4, not tmpfs)
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/reuse}"
DAEMON="[s]ingleton --config $R/cfg.json"

finish() {
  umount "$R/mnt" 2>/dev/null
  pkill -9 -f "$DAEMON" 2>/dev/null
  exit "$1"
}
fail() {
  echo "FAIL: $*"
  sed 's/\x1b\[[0-9;]*m//g' "$R/log" 2>/dev/null | tail -20
  echo "==== CACHE REUSE: FAIL ===="
  finish 1
}

umount "$R/mnt" 2>/dev/null
pkill -9 -f "$DAEMON" 2>/dev/null
rm -rf "$R"
mkdir -p "$R"/{src/sub,out,backend,stage,mnt,probe}

yes CACHE_REUSE_0123456789ABCDEF | head -n 8192 | tr -d '\n' > "$R/src/text.txt"
head -c 524288 /dev/urandom > "$R/src/random.bin"
for i in $(seq 0 15); do head -c $((i * 1111 + 7)) /dev/urandom > "$R/src/sub/f$i"; done
FILES=$(cd "$R/src" && find . -type f | sort)

"$NI" create --fs-version 6 --compressor none -B "$R/out/bootstrap" -D "$R/out" "$R/src" \
  > "$R/create.log" 2>&1 || fail "nydus-image create"
BLOB=$(ls "$R/out" | grep -vE '^bootstrap' | head -1)
[ -n "$BLOB" ] || fail "no data blob"
cp "$R/out/$BLOB" "$R/backend/$BLOB"
cp "$R/out/bootstrap" "$R/stage/bootstrap"
MAP="$R/stage/$BLOB.blob.data.chunk_map"
DATA="$R/stage/$BLOB.blob.data"

# With EROFS page cache sharing compiled in, `inode_share` without `domain_id` is refused.
SHARE=0
if ! mount -t erofs -o ro,inode_share "$R/stage/bootstrap" "$R/probe" 2>/dev/null; then
  mount -t erofs -o ro "$R/stage/bootstrap" "$R/probe" 2>/dev/null && SHARE=1
fi
umount "$R/probe" 2>/dev/null
DOMAIN=""
[ "$SHARE" = 1 ] && DOMAIN=', "erofs_inode_share_domain": "reuse-test"'
echo "page cache sharing: $([ "$SHARE" = 1 ] && echo supported || echo not supported)"

cat > "$R/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$R/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$R/stage"$DOMAIN},
  "metadata_path":"$R/stage/bootstrap" }}]}
EOF

serve() {
  "$ND" singleton --config "$R/cfg.json" --fanotify "$R/stage" --fanotify-mountpoint "$R/mnt" \
    --fanotify-threads 2 --log-level info > "$R/log" 2>&1 &
  PID=$!
  for _ in $(seq 120); do grep -q " $R/mnt erofs " /proc/mounts && return; sleep 1; done
  fail "EROFS not mounted"
}
# Stop the daemon with <signal> and wait for it, then unmount.
stop() {
  kill "-$1" "$PID"
  for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
  kill -0 "$PID" 2>/dev/null && fail "nydusd did not exit on SIG$1"
  umount "$R/mnt" 2>/dev/null
}
check() { # <label>
  sync && echo 3 > /proc/sys/vm/drop_caches
  for f in $FILES; do
    cmp -s "$R/mnt/$f" "$R/src/$f" || fail "$1: $f differs or failed to read"
  done
  echo "$1: $(echo "$FILES" | wc -l) files intact"
}
unsealed_boot() { od -An -tx1 -j32 -N8 "$MAP" | tr -d ' \n'; }
foreign_boot() { printf '\001\002\003\004\005\006\007\010' | dd of="$MAP" bs=1 seek=32 conv=notrunc 2>/dev/null; }
denied() { grep -E "failed to serve pre-content|no digest" "$R/log"; }

echo "### 1. fresh cache, clean stop"
serve
check "cold read"
[ "$(unsealed_boot)" != 0000000000000000 ] || fail "filled without unsealing the chunk map"
denied && fail "events were denied"
stop TERM
[ "$(unsealed_boot)" = 0000000000000000 ] || fail "stopped cleanly but not sealed ($(unsealed_boot))"
echo "sealed at clean stop"

echo "### 2. sealed cache, zero backend"
SIZE=$(stat -c %s "$R/backend/$BLOB")
mv "$R/backend/$BLOB" "$R/blob.good"
truncate -s "$SIZE" "$R/backend/$BLOB"
serve
if [ "$SHARE" = 1 ]; then
  grep " $R/mnt erofs " /proc/mounts | grep -q inode_share ||
    fail "the sealed, verified cache was kept out of page cache sharing"
  echo "mounted with inode_share"
fi
check "warm read without backend"
denied && fail "events were denied"

echo "### 3. killed, then another boot: recheck from the cache file"
stop KILL
[ "$(unsealed_boot)" = 0000000000000000 ] || fail "a warm run that filled nothing unsealed the map"
foreign_boot
BLOCKS=$(stat -c %b "$DATA")
serve
grep -q "not sealed before the last reboot" "$R/log" || fail "the cache unsealed by another boot was trusted"
check "rechecked read without backend"
[ "$(stat -c %b "$DATA")" -ge "$BLOCKS" ] || fail "the reset dropped cached data"
denied && fail "events were denied"
echo "rechecked from the cache file"

echo "### 4. damaged chunk after another boot: fetched again"
stop KILL
[ "$(unsealed_boot)" != 0000000000000000 ] || fail "rechecking fills did not unseal the chunk map"
foreign_boot
B0=$(dd if="$DATA" bs=1 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
printf "\\$(printf %o $((B0 ^ 255)))" | dd of="$DATA" bs=1 count=1 conv=notrunc 2>/dev/null
mv "$R/blob.good" "$R/backend/$BLOB"
serve
check "read with a damaged chunk"
[ "$(dd if="$DATA" bs=1 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')" = "$B0" ] ||
  fail "the damaged chunk was not fetched again"
denied && fail "events were denied"
stop TERM
[ "$(unsealed_boot)" = 0000000000000000 ] || fail "not sealed after the recheck run"

echo "==== CACHE REUSE: PASS ===="
finish 0
