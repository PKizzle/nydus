#!/usr/bin/env bash
# Multi-layer ZRAN node-local serve: convert 2 gzip layers (targz-ref), merge, serve via fanotify
# with self-staging, and verify files from BOTH layers (multi-device EROFS) read back correctly.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/zran-ml}"
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null; sleep 1
rm -rf "$R"; mkdir -p "$R"/{l1,l2,o1,o2,backend,stage,mnt}

mkdir -p "$R/l1/bin"; echo "APP_FROM_LAYER1" > "$R/l1/bin/app"; echo base > "$R/l1/base.txt"
mkdir -p "$R/l2/data"; head -c 90000 /dev/urandom > "$R/l2/data/payload.bin"; echo top > "$R/l2/top.txt"
tar -C "$R/l1" -czf "$R/L1.tar.gz" .; tar -C "$R/l2" -czf "$R/L2.tar.gz" .
D1=$(sha256sum "$R/L1.tar.gz"|awk '{print $1}'); D2=$(sha256sum "$R/L2.tar.gz"|awk '{print $1}')

B1=$("$NI" create --type targz-ref --fs-version 6 -D "$R/o1" "$R/L1.tar.gz" 2>&1 | sed -n 's/^meta blob path: //p')
B2=$("$NI" create --type targz-ref --fs-version 6 -D "$R/o2" "$R/L2.tar.gz" 2>&1 | sed -n 's/^meta blob path: //p')
M1=$(ls "$R/o1" | grep -v "$(basename "$B1")"); M2=$(ls "$R/o2" | grep -v "$(basename "$B2")")
echo "layer1=$D1 layer2=$D2"; echo "meta1=$M1 meta2=$M2"

# backend = both gzip layers (by digest) + both zran meta blobs
cp "$R/L1.tar.gz" "$R/backend/$D1"; cp "$R/L2.tar.gz" "$R/backend/$D2"
cp "$R/o1/$M1" "$R/backend/$M1"; cp "$R/o2/$M2" "$R/backend/$M2"
# merged bootstrap (lower L1 -> upper L2) into the staging dir
"$NI" merge -B "$R/stage/bootstrap" --original-blob-ids "$D1,$D2" "$B1" "$B2" >/dev/null 2>&1
echo "merged bootstrap: $(stat -c%s "$R/stage/bootstrap" 2>/dev/null) bytes; backend files: $(ls "$R/backend"|wc -l)"

cat > "$R/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$R/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$R/stage"},
  "metadata_path":"$R/stage/bootstrap" }}]}
EOF
"$ND" singleton --config "$R/cfg.json" --fanotify "$R/stage" --fanotify-mountpoint "$R/mnt" \
  --fanotify-threads 2 --log-level info > "$R/log" 2>&1 &
sleep 4
mount | grep -q "$R/mnt" && echo "MOUNTED" || { echo "NOT MOUNTED"; tail -15 "$R/log"|sed 's/\x1b\[[0-9;]*m//g'; }
echo "tree:"; find "$R/mnt" -type f 2>/dev/null | sed "s#$R/mnt##"
APP_S=$(sha256sum "$R/l1/bin/app"|awk '{print $1}');     APP_M=$(sha256sum "$R/mnt/bin/app" 2>/dev/null|awk '{print $1}')
PAY_S=$(sha256sum "$R/l2/data/payload.bin"|awk '{print $1}'); PAY_M=$(sha256sum "$R/mnt/data/payload.bin" 2>/dev/null|awk '{print $1}')
echo "layer1 /bin/app:        src=$APP_S mnt=$APP_M"
echo "layer2 /data/payload:   src=$PAY_S mnt=$PAY_M"
echo "self-staged devices: $(ls "$R/stage" | grep -c '^blob_') ($(ls "$R/stage"|grep '^blob_'|tr '\n' ' '))"
P=1; [ "$APP_S" = "$APP_M" ] || { echo MISMATCH app; P=0; }; [ "$PAY_S" = "$PAY_M" ] || { echo MISMATCH payload; P=0; }
echo; [ $P = 1 ] && echo "==== MULTI-LAYER ZRAN: PASS ====" || echo "==== MULTI-LAYER ZRAN: FAIL ===="
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null
