#!/usr/bin/env bash
# ZRAN-over-fanotify serving test (Workstream C foundation).
# Converts a gzip tar layer with `--type targz-ref` (zran: references the ORIGINAL gzip layer +
# emits a tiny zran index), then serves it via the fanotify on-demand path with a localfs backend =
# the gzip layer. A correct path decompresses gzip ranges on demand into the sparse cache file, so
# reads return the ORIGINAL file bytes. This is the serving foundation for node-local acceleration.
set -u
NI="${NYDUS_IMAGE:-/home/philippkolberg.linux/nydus-target/debug/nydus-image}"
ND="${NYDUSD:-/home/philippkolberg.linux/nydus-target/debug/nydusd}"
ROOT="${ROOT:-/var/tmp/zran-rt}"   # ext4, not tmpfs
LOG=$ROOT/nydusd.log

step(){ echo; echo "### $* ###"; }
finish(){ sudo umount -l "$ROOT/mnt" 2>/dev/null; sudo pkill -9 -f "nydusd singleton" 2>/dev/null; sleep 1; exit "${1:-0}"; }
fail(){ echo "FAIL: $*"; echo "--- log ---"; tail -30 "$LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'; finish 1; }

step "reset"
sudo umount -l "$ROOT/mnt" 2>/dev/null; sudo pkill -9 -f "nydusd singleton" 2>/dev/null; sleep 1
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src,src/sub,out,backend,stage,mnt}

step "source rootfs + gzip tar layer"
perl -e 'print "ZRAN_OK_0123456789ABCDEF" x 6000' > "$ROOT/src/hello.txt"   # ~138 KiB, multi-chunk
head -c 300000 /dev/urandom > "$ROOT/src/random.bin"
echo "zran-subdir-marker" > "$ROOT/src/sub/small.txt"
SRC_HELLO=$(sha256sum "$ROOT/src/hello.txt"|awk '{print $1}')
SRC_RAND=$(sha256sum "$ROOT/src/random.bin"|awk '{print $1}')
SRC_SMALL=$(sha256sum "$ROOT/src/sub/small.txt"|awk '{print $1}')
tar -C "$ROOT/src" -czf "$ROOT/layer.tar.gz" .
DATA=$(sha256sum "$ROOT/layer.tar.gz"|awk '{print $1}')   # OCI gzip-layer digest == nydus zran blob id
echo "gzip layer digest (DATA blob id) = $DATA"

step "nydus-image create --type targz-ref (zran)"
OUT=$("$NI" create --type targz-ref --fs-version 6 -D "$ROOT/out" "$ROOT/layer.tar.gz" 2>&1)
echo "$OUT" | grep -iE "meta blob path|data blobs"
BOOTSTRAP=$(echo "$OUT" | sed -n 's/^meta blob path: //p' | tr -d ' ')
[ -f "$BOOTSTRAP" ] || fail "no bootstrap"
BOOTNAME=$(basename "$BOOTSTRAP")
# the meta/index blob is the out/ file that is NOT the bootstrap
META=$(ls "$ROOT/out" | grep -v "^${BOOTNAME}\$" | head -1)
echo "bootstrap=$BOOTNAME  zran-meta=$META  ($(stat -c%s "$ROOT/out/$META") bytes)"

step "stage backend (gzip layer + zran meta) and cache layout"
cp "$ROOT/layer.tar.gz" "$ROOT/backend/$DATA"     # backend serves the gzip layer by its digest
cp "$ROOT/out/$META"    "$ROOT/backend/$META"      # ...and the zran meta/toc blob
cp "$BOOTSTRAP"         "$ROOT/stage/bootstrap"
# NOTE: no .blob.data / blob_0 pre-staging — the daemon now self-creates the cache file and the
# EROFS device hardlink from the blob cache. The staging dir only needs the bootstrap.
echo "backend:"; ls -la "$ROOT/backend" | awk '{print $5, $9}'

step "config + launch"
cat > "$ROOT/config.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$ROOT/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$ROOT/stage"},
  "metadata_path":"$ROOT/stage/bootstrap" }}]}
EOF
sudo "$ND" singleton --config "$ROOT/config.json" --fanotify "$ROOT/stage" \
  --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 --log-level info > "$LOG" 2>&1 &
sleep 4
mount | grep -q "$ROOT/mnt" || fail "EROFS not mounted"
echo "mounted OK"

step "read back (drives zran on-demand decompression)"
ls -la "$ROOT/mnt"
MNT_HELLO=$(sha256sum "$ROOT/mnt/hello.txt" 2>/dev/null|awk '{print $1}')
MNT_RAND=$(sha256sum "$ROOT/mnt/random.bin" 2>/dev/null|awk '{print $1}')
MNT_SMALL=$(sha256sum "$ROOT/mnt/sub/small.txt" 2>/dev/null|awk '{print $1}')

step "RESULTS"
echo "hello : src=$SRC_HELLO mnt=$MNT_HELLO"
echo "random: src=$SRC_RAND mnt=$MNT_RAND"
echo "small : src=$SRC_SMALL mnt=$MNT_SMALL"
echo "cache blocks: $(stat -c%b "$ROOT/stage/blob_0") (non-zero => fetched+decompressed)"
P=1
[ "$SRC_HELLO" = "$MNT_HELLO" ] || { echo MISMATCH hello; P=0; }
[ "$SRC_RAND"  = "$MNT_RAND"  ] || { echo MISMATCH random; P=0; }
[ "$SRC_SMALL" = "$MNT_SMALL" ] || { echo MISMATCH small; P=0; }
echo; [ $P = 1 ] && echo "==== ZRAN-OVER-FANOTIFY: PASS ====" || { echo "==== ZRAN-OVER-FANOTIFY: FAIL ===="; tail -25 "$LOG"|sed 's/\x1b\[[0-9;]*m//g'; }
finish $([ $P = 1 ] && echo 0 || echo 1)
