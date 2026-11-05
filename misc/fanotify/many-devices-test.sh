#!/usr/bin/env bash
# An image with more devices than mount(2)'s one-page option string can name: 64 layers merged
# into one bootstrap, served through fanotify from a deep cache directory so the joined
# `device=` list is well over 4096 bytes. Every layer's file must read back intact.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/many-devices}"
LAYERS="${LAYERS:-64}"
BLOCK_SIZE="${BLOCK_SIZE:-4096}"
# ~150-byte device paths: 64 of them join to ~10 KiB of mount options.
STAGE="$R/$(printf 'cache%.0s' $(seq 24))/stage"
DAEMON="[s]ingleton --config $R/cfg.json"
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "$DAEMON" 2>/dev/null; sleep 1
rm -rf "$R"; mkdir -p "$R"/{backend,mnt} "$STAGE"

BOOTSTRAPS=(); IDS=()
for i in $(seq 0 $((LAYERS - 1))); do
  mkdir -p "$R/l$i/layer$i" "$R/o$i"
  head -c $((4096 + i * 512)) /dev/urandom > "$R/l$i/layer$i/data.bin"
  "$NI" create --fs-version 6 --compressor none --block-size "$BLOCK_SIZE" \
    -B "$R/o$i/bootstrap" -D "$R/o$i" "$R/l$i" >/dev/null 2>&1 || { echo "create layer $i failed"; exit 1; }
  B=$(ls "$R/o$i" | grep -v '^bootstrap'); cp "$R/o$i/$B" "$R/backend/$B"
  BOOTSTRAPS+=("$R/o$i/bootstrap"); IDS+=("$B")
done
"$NI" merge -B "$STAGE/bootstrap" --original-blob-ids "$(IFS=,; echo "${IDS[*]}")" "${BOOTSTRAPS[@]}" >/dev/null 2>&1 || { echo "merge failed"; exit 1; }
"$NI" check -B "$STAGE/bootstrap" --blob-dir "$R/backend" >/dev/null || { echo "check failed"; exit 1; }
BLOBS=$(ls "$R/backend" | wc -l)
OPTS=0; for i in $(seq 0 $((BLOBS - 1))); do OPTS=$((OPTS + ${#STAGE} + 14 + ${#i})); done  # "device=<stage>/blob_<i>,"
echo "layers=$LAYERS blobs=$BLOBS joined device options $OPTS bytes"
[ "$BLOBS" = "$LAYERS" ] && [ "$OPTS" -gt 4096 ] || { echo "image too small to exercise the one-page limit"; exit 1; }

cat > "$R/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$R/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$STAGE"},
  "metadata_path":"$STAGE/bootstrap" }}]}
EOF
"$ND" singleton --config "$R/cfg.json" --fanotify "$STAGE" --fanotify-mountpoint "$R/mnt" \
  --fanotify-threads 2 --log-level info > "$R/log" 2>&1 &
for _ in $(seq 30); do mount | grep -qF "$R/mnt type erofs" && break; sleep 1; done
P=1
mount | grep -qF "$R/mnt type erofs" || { echo "NOT MOUNTED"; tail -15 "$R/log"; P=0; }
STAGED=$(ls "$STAGE" | grep -c '^blob_')
echo "self-staged devices: $STAGED"
[ "$STAGED" = "$BLOBS" ] || { echo "MISMATCH staged devices"; P=0; }
BAD=0
for i in $(seq 0 $((LAYERS - 1))); do
  S=$(sha256sum "$R/l$i/layer$i/data.bin" | awk '{print $1}')
  M=$(sha256sum "$R/mnt/layer$i/data.bin" 2>/dev/null | awk '{print $1}')
  [ "$S" = "$M" ] || { echo "MISMATCH layer $i"; BAD=$((BAD + 1)); }
done
[ "$BAD" = 0 ] || P=0
echo "layers read back: $((LAYERS - BAD))/$LAYERS"
echo; [ $P = 1 ] && echo "==== MANY DEVICES: PASS ====" || echo "==== MANY DEVICES: FAIL ===="
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "$DAEMON" 2>/dev/null
[ $P = 1 ]
