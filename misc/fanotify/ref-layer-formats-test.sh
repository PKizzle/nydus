#!/usr/bin/env bash
# Node-local serve of every referenced layer encoding: gzip (zran), uncompressed tar,
# multi-frame zstd (frame-aligned contexts decoded in memory), multi-frame zstd whose duplicate
# files leave more contexts than chunks after deduplication, and single-frame zstd larger than
# RAFS_MAX_CHUNK_SIZE (decoded by the forward stream cursor). The root-only
# `auto_accel_sidecar_serves_converted_layers` test runs the snapshotter's auto-accel path on
# them: `local_accel::convert`, the content-store sidecar layout, `SidecarLocator::stage` and
# `DaemonSupervisor::ensure_instance_local`, then compares every file of the fanotify/EROFS mount
# with its source. It reads in reverse path order, so the single-frame layer's last member is
# read first: the cursor decodes forward and then has to restart behind its position.
#
# Needs root, Linux >= 6.14, cargo, zstd, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
# Absolute: cargo runs the test from the crate directory.
NI=$(realpath "${NYDUS_IMAGE:-./target/release/nydus-image}")
CARGO="${CARGO:-cargo}"
R="${ROOT:-/var/tmp/ref-formats}"
grep " $R/" /proc/self/mounts | awk '{print $2}' | xargs -r -n1 umount -l
rm -rf "$R"; mkdir -p "$R"/{src,layers,expected}

# Source trees, one per layer, with distinct paths so every file comes from exactly one layer.
mkdir -p "$R/src/gz/etc" "$R/src/tar/opt" "$R/src/zmulti/srv" "$R/src/zdedup/dup" "$R/src/zsingle/var"
echo gzip-layer > "$R/src/gz/etc/gz.txt"
head -c 300000 /dev/urandom > "$R/src/gz/etc/gz.bin"
echo tar-layer > "$R/src/tar/opt/tar.txt"
head -c 2500000 /dev/urandom > "$R/src/tar/opt/tar.bin"
for i in 1 2 3 4 5; do head -c $((700000 * i)) /dev/urandom | base64 > "$R/src/zmulti/srv/f$i.txt"; done
for i in $(seq 1 60); do echo "same content" > "$R/src/zdedup/dup/f$i.txt"; done
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
# Duplicate files in 2 KiB frames: deduplication keeps one chunk, but every frame a file starts
# in gets a context, so contexts outnumber chunks.
tar -C "$R/src/zdedup" -cf "$R/zdedup.tar" .
split -b 2048 -d -a 4 "$R/zdedup.tar" "$R/zdedup.part."
: > "$R/zdedup.tar.zst"
for part in "$R"/zdedup.part.*; do zstd -q -c "$part" >> "$R/zdedup.tar.zst"; done
# Single-frame zstd with an 8 MiB window, like real image layers.
tar -C "$R/src/zsingle" -cf - ./var/big.txt ./var/zz-last.txt | zstd -q -3 --long=23 -o "$R/zsingle.tar.zst"

# Layers apply in file-name order; each source tree has distinct paths, so the merged tree is
# their union.
n=0
for layer in gz.tar.gz plain.tar zmulti.tar.zst zdedup.tar.zst zsingle.tar.zst; do
  n=$((n + 1)); mv "$R/$layer" "$R/layers/$n-$layer"
done
for tree in gz tar zmulti zdedup zsingle; do cp -a "$R/src/$tree/." "$R/expected/"; done

NYDUS_IMAGE="$NI" NYDUS_E2E_ROOT="$R" "$CARGO" test -p nydus-snapshotter --lib \
  daemon::e2e_tests::auto_accel_sidecar_serves_converted_layers -- --ignored --exact --nocapture \
  || { echo "==== REF LAYER FORMATS: FAIL ===="; exit 1; }
if grep -q " $R/" /proc/self/mounts; then
  grep " $R/" /proc/self/mounts; echo "==== REF LAYER FORMATS: FAIL (mount left behind) ===="; exit 1
fi
echo "==== REF LAYER FORMATS: PASS ===="
