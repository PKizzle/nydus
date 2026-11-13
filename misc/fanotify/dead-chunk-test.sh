#!/usr/bin/env bash
# Two zran layers where the upper one deletes and replaces small files of the lower, so the lower
# layer blob keeps chunks the merged image no longer references between ones it does, several to a
# 16K or 64K page. Served through fanotify, every file must read back intact: by read(2) cold, again
# after dropping the page cache, and by mmap(2) when MMAP_CAT is given, with no event denied. On a
# kernel with pages larger than the EROFS block, a read of a live file raises events that span the
# dead chunks next to it.
#
#   NYDUS_IMAGE, NYDUSD  binaries
#   ROOT                 work dir on a fs with pre-content marks (ext4, not tmpfs)
#   MMAP_CAT             optional: a program printing the file it is given through mmap(2)
#                        (misc/fanotify/mmap-cat.c)
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/dead-chunk}"
DAEMON="[s]ingleton --config $R/cfg.json"

finish() {
  umount "$R/mnt" 2>/dev/null
  pkill -f "$DAEMON" 2>/dev/null
  exit "$1"
}
fail() {
  echo "FAIL: $*"
  tail -20 "$R/log" 2>/dev/null
  echo "==== DEAD CHUNKS: FAIL ===="
  finish 1
}

umount "$R/mnt" 2>/dev/null
pkill -f "$DAEMON" 2>/dev/null
rm -rf "$R"
mkdir -p "$R"/{l1,l2,o1,o2,backend,stage,mnt,want}
PAGE=$(sed -n 's/^KernelPageSize: *\([0-9]*\) kB/\1/p' /proc/self/smaps | head -1)
echo "host page size: ${PAGE:-?} KiB"

# Sizes ending inside, at and past 4K boundaries; with 4K blocks every chunk starts on one, so
# neighbouring chunks share each 16K and 64K page.
for i in $(seq 0 47); do head -c $(((i * 2731) % 9000 + 1)) /dev/urandom > "$R/l1/f$i"; done
for i in $(seq 0 3 47); do : > "$R/l2/.wh.f$i"; done
for i in $(seq 1 3 47); do head -c 777 /dev/urandom > "$R/l2/f$i"; done
for i in $(seq 0 47); do
  if [ -f "$R/l2/f$i" ]; then cp "$R/l2/f$i" "$R/want/"; elif [ ! -e "$R/l2/.wh.f$i" ]; then cp "$R/l1/f$i" "$R/want/"; fi
done
tar -C "$R/l1" -czf "$R/L1.tar.gz" . && tar -C "$R/l2" -czf "$R/L2.tar.gz" . || fail "tar"
D1=$(sha256sum "$R/L1.tar.gz" | awk '{print $1}')
D2=$(sha256sum "$R/L2.tar.gz" | awk '{print $1}')

B1=$("$NI" create --type targz-ref --fs-version 6 -D "$R/o1" "$R/L1.tar.gz" 2>&1 | sed -n 's/^meta blob path: //p')
B2=$("$NI" create --type targz-ref --fs-version 6 -D "$R/o2" "$R/L2.tar.gz" 2>&1 | sed -n 's/^meta blob path: //p')
[ -f "$B1" ] && [ -f "$B2" ] || fail "nydus-image create"
M1=$(ls "$R/o1" | grep -v "$(basename "$B1")")
M2=$(ls "$R/o2" | grep -v "$(basename "$B2")")
cp "$R/L1.tar.gz" "$R/backend/$D1"
cp "$R/L2.tar.gz" "$R/backend/$D2"
cp "$R/o1/$M1" "$R/o2/$M2" "$R/backend/"
"$NI" merge -B "$R/stage/bootstrap" --original-blob-ids "$D1,$D2" "$B1" "$B2" >/dev/null 2>&1 ||
  fail "nydus-image merge"
"$NI" check -B "$R/stage/bootstrap" --blob-dir "$R/backend" >/dev/null || fail "nydus-image check"

cat > "$R/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$R/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$R/stage"},
  "metadata_path":"$R/stage/bootstrap" }}]}
EOF
"$ND" singleton --config "$R/cfg.json" --fanotify "$R/stage" --fanotify-mountpoint "$R/mnt" \
  --fanotify-threads 2 --log-level info > "$R/log" 2>&1 &
for _ in $(seq 120); do grep -q " $R/mnt erofs " /proc/mounts && break; sleep 1; done
grep -q " $R/mnt erofs " /proc/mounts || fail "EROFS not mounted"

LIVE=$(ls "$R/want")
[ "$(echo "$LIVE" | wc -l)" = 32 ] || fail "expected 32 live files"
check() { # <pass name> <reader>
  bad=0
  for f in $LIVE; do
    $2 "$R/mnt/$f" | cmp -s - "$R/want/$f" || { echo "$1: $f differs or failed to read"; bad=1; }
  done
  [ "$bad" = 0 ] || fail "$1"
  echo "$1: 32 files intact"
}
check "cold read" cat
sync && echo 3 > /proc/sys/vm/drop_caches
check "read after drop_caches" cat
if [ -n "${MMAP_CAT:-}" ]; then
  echo 3 > /proc/sys/vm/drop_caches
  check "mmap read" "$MMAP_CAT"
else
  echo "mmap read: skipped (MMAP_CAT unset)"
fi
for f in $(seq 0 3 47); do [ ! -e "$R/mnt/f$f" ] || fail "deleted file f$f is visible"; done
if grep -E "no digest|failed to serve pre-content" "$R/log"; then fail "events were denied"; fi
echo "==== DEAD CHUNKS: PASS (page size ${PAGE:-?} KiB) ===="
finish 0
