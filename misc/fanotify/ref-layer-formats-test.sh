#!/usr/bin/env bash
# Node-local serve of every referenced layer encoding: gzip (zran), uncompressed tar,
# multi-frame zstd (frame-aligned contexts decoded in memory) and single-frame zstd larger than
# RAFS_MAX_CHUNK_SIZE (decoded by the forward stream cursor). Each layer is converted with
# `targz-ref`, the four are merged and served through fanotify/EROFS, and every file is compared
# with its source. The single-frame layer is read last-file-first, so the cursor decodes forward
# and then has to restart behind its position.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/ref-formats}"
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null; sleep 1
rm -rf "$R"; mkdir -p "$R"/{src,out,backend,stage,mnt}

# Source trees, one per layer, with distinct paths so every file comes from exactly one layer.
mkdir -p "$R/src/gz/etc" "$R/src/tar/opt" "$R/src/zmulti/srv" "$R/src/zsingle/var"
echo gzip-layer > "$R/src/gz/etc/gz.txt"
head -c 300000 /dev/urandom > "$R/src/gz/etc/gz.bin"
echo tar-layer > "$R/src/tar/opt/tar.txt"
head -c 2500000 /dev/urandom > "$R/src/tar/opt/tar.bin"
for i in 1 2 3 4 5; do head -c $((700000 * i)) /dev/urandom | base64 > "$R/src/zmulti/srv/f$i.txt"; done
# Compressible, so ~54 MiB decompressed fits in a few MiB of zstd: one frame, far beyond 16 MiB.
head -c 40000000 /dev/urandom | base64 > "$R/src/zsingle/var/big.txt"
echo last-member > "$R/src/zsingle/var/zz-last.txt"

tar -C "$R/src/gz" -czf "$R/gz.tar.gz" .
tar -C "$R/src/tar" -cf "$R/plain.tar" .
# Multi-frame zstd: the tar cut into 1 MiB pieces, each its own frame, with a skippable frame
# (as zstd:chunked writes its metadata) between two of them. Cuts land inside file data.
tar -C "$R/src/zmulti" -cf "$R/zmulti.tar" .
split -b 1048576 -d -a 3 "$R/zmulti.tar" "$R/zmulti.part."
: > "$R/zmulti.tar.zst"; n=0
for part in "$R"/zmulti.part.*; do
  zstd -q -c "$part" >> "$R/zmulti.tar.zst"
  n=$((n + 1))
  [ $n = 2 ] && printf '\x50\x2a\x4d\x18\x04\x00\x00\x00meta' >> "$R/zmulti.tar.zst"
done
echo "multi-frame zstd layer: $n frames + 1 skippable"
# Single-frame zstd with an 8 MiB window, like real image layers.
tar -C "$R/src/zsingle" -cf - ./var/big.txt ./var/zz-last.txt | zstd -q -3 --long=23 -o "$R/zsingle.tar.zst"

LAYERS="gz.tar.gz plain.tar zmulti.tar.zst zsingle.tar.zst"
IDS=""; BOOTS=""
for layer in $LAYERS; do
  out="$R/out/$layer"; mkdir -p "$out"
  boot=$("$NI" create --type targz-ref --fs-version 6 -D "$out" "$R/$layer" 2>&1 | tee "$out.log" | sed -n 's/^meta blob path: //p')
  [ -n "$boot" ] || { echo "create failed for $layer"; tail -5 "$out.log"; exit 1; }
  "$NI" check -B "$boot" >/dev/null 2>&1 || { echo "check failed for $layer"; exit 1; }
  digest=$(sha256sum "$R/$layer" | awk '{print $1}')
  cp "$R/$layer" "$R/backend/$digest"
  for meta in "$out"/*; do [ "$meta" = "$boot" ] || cp "$meta" "$R/backend/"; done
  IDS="$IDS,$digest"; BOOTS="$BOOTS $boot"
  echo "$layer: $(stat -c%s "$R/$layer") bytes -> $digest"
done
"$NI" merge -B "$R/stage/bootstrap" --original-blob-ids "${IDS#,}" $BOOTS >/dev/null 2>&1 \
  || { echo "merge failed"; exit 1; }

cat > "$R/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"b1","domain_id":"d1","config":{
  "id":"f1","backend_type":"localfs","backend_config":{"dir":"$R/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$R/stage"},
  "metadata_path":"$R/stage/bootstrap" }}]}
EOF
"$ND" singleton --config "$R/cfg.json" --fanotify "$R/stage" --fanotify-mountpoint "$R/mnt" \
  --fanotify-threads 2 --log-level info > "$R/log" 2>&1 &
for _ in $(seq 40); do mount | grep -q "$R/mnt" && break; sleep 0.25; done
mount | grep -q "$R/mnt" || { echo "NOT MOUNTED"; tail -15 "$R/log" | sed 's/\x1b\[[0-9;]*m//g'; exit 1; }

P=1
compare() { # <layer dir> <path>
  local want got
  want=$(sha256sum "$R/src/$1/$2" | awk '{print $1}')
  got=$(sha256sum "$R/mnt/$2" 2>/dev/null | awk '{print $1}')
  if [ "$want" = "$got" ]; then echo "ok    $1 /$2"; else echo "FAIL  $1 /$2 (want $want got $got)"; P=0; fi
}
# Last member of the single-frame layer first: the cursor decodes forward through big.txt.
start=$(date +%s.%N); compare zsingle var/zz-last.txt; end=$(date +%s.%N)
echo "      cold read at the end of the single-frame layer: $(echo "$start $end" | awk '{printf "%.2f s", $2 - $1}')"
compare zsingle var/big.txt   # behind the cursor: restart at the frame start
compare gz etc/gz.txt; compare gz etc/gz.bin
compare tar opt/tar.txt; compare tar opt/tar.bin
for i in 5 1 3 2 4; do compare zmulti srv/f$i.txt; done
grep -i "error\|panic" "$R/log" | sed 's/\x1b\[[0-9;]*m//g' | head -5

echo; [ $P = 1 ] && echo "==== REF LAYER FORMATS: PASS ====" || echo "==== REF LAYER FORMATS: FAIL ===="
umount -l "$R/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null
[ $P = 1 ]
