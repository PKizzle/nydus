#!/usr/bin/env bash
# EROFS page cache sharing (`inode_share`, Linux 7.0+) between two different images, each mounted
# through its node view (`nydus-image node-view`), as the snapshotter mounts every fanotify image.
#
# Image A is an auto-accel style zran image (targz-ref per layer, then merge) holding one file.
# Image B is a nydus-format image with its own data blob, as pulled from a registry; it holds the
# same file under another path and a same-size file with one byte changed. B's own bootstrap ships
# a forged copy of A's fingerprint on both files. The views must carry node-computed fingerprints
# only: equal for the identical files, different for the changed one. That part is checked on any
# kernel; the rest needs page cache sharing in the kernel.
#
# Each image is served by its own nydusd with `erofs_inode_share_domain` set, so both EROFS mounts
# join one sharing domain. Sharing is measured on B's blob cache: B's `.blob.data` is the device
# its EROFS mount reads, so it only gains blocks when B's own inode has to fill the page cache.
# After the shared file was read through A, reading it through B must not grow B's cache; the
# changed file (the control, whose forged fingerprint names A's file) must, and must read its own
# content. Content is checked by hash every time. On >= 7.4 a file is also read through a mapping
# that outlives its fd while its inodes are evicted (the "erofs: hold real inodes for shared
# files" fix); older kernels skip that case.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/inode-share}"
cleanup() { umount -l "$R/a/mnt" "$R/b/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null; }
cleanup; sleep 1
rm -rf "$R"; mkdir -p "$R"

KREL=$(uname -r); KVER=$(echo "$KREL" | grep -oE '^[0-9]+\.[0-9]+')
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SIZE=$((8 << 20))
head -c "$SIZE" /dev/urandom > "$R/shared.bin"
cp "$R/shared.bin" "$R/changed.bin"
printf '\xff' | dd of="$R/changed.bin" bs=1 seek=$((SIZE / 2)) conv=notrunc status=none
mkdir -p "$R/la/usr/lib" "$R/lb/opt"
cp "$R/shared.bin" "$R/la/usr/lib/libshared.so"
cp "$R/shared.bin" "$R/lb/opt/libshared.so"; cp "$R/changed.bin" "$R/lb/opt/libchanged.so"

# Fingerprint values stored in a bootstrap: xattr entries naming long prefix 0, 32-byte value.
fingerprints() {
  python3 - "$1" <<'EOF'
import sys
d = open(sys.argv[1], "rb").read()
e = b"\x00\x80\x20\x00"
i = d.find(e)
while i >= 0:
    print(d[i + 4:i + 36].hex())
    i = d.find(e, i + 1)
EOF
}

# Build image <name> from layer dir <src> as <kind> (zran or native) into "$R/<name>/source".
build() {
  local n=$1 src=$2 kind=$3 d="$R/$1" boot blob
  mkdir -p "$d"/{out,backend,stage,mnt}
  if [ "$kind" = zran ]; then
    tar -C "$src" -czf "$d/layer.tar.gz" .
    blob=$(sha256sum "$d/layer.tar.gz" | awk '{print $1}')
    boot=$("$NI" create --type targz-ref --fs-version 6 -D "$d/out" "$d/layer.tar.gz" 2>&1 \
      | sed -n 's/^meta blob path: //p')
    cp "$d/layer.tar.gz" "$d/backend/$blob"
    local meta; meta=$(ls "$d/out" | grep -v "$(basename "$boot")"); cp "$d/out/$meta" "$d/backend/$meta"
  else
    boot="$d/out/bootstrap"
    "$NI" create --fs-version 6 --digester sha256 -B "$boot" -D "$d/out" "$src" >"$d/create.log" 2>&1 \
      || { echo "create $n failed"; cat "$d/create.log"; return 1; }
    blob=$(ls "$d/out" | grep -vE '^bootstrap' | head -1); cp "$d/out/$blob" "$d/backend/$blob"
  fi
  "$NI" merge --inode-share-fingerprint -B "$d/source" --original-blob-ids "$blob" "$boot" \
    >"$d/merge.log" 2>&1 || { echo "merge $n failed"; cat "$d/merge.log"; return 1; }
}

# Stage image <name>'s node view and serve it.
serve() {
  local n=$1 d="$R/$1"
  "$NI" node-view -B "$d/stage/bootstrap" "$d/source" >"$d/view.log" 2>&1 \
    || { echo "node-view $n failed"; cat "$d/view.log"; return 1; }
  cat > "$d/cfg.json" <<EOF
{ "blobs": [ { "type":"bootstrap","id":"$n","domain_id":"$n","config":{
  "id":"$n","backend_type":"localfs","backend_config":{"dir":"$d/backend"},
  "cache_type":"fanotify","cache_config":{"work_dir":"$d/stage",
    "erofs_inode_share_domain":"inode-share-test"},
  "metadata_path":"$d/stage/bootstrap" }}]}
EOF
  "$ND" singleton --config "$d/cfg.json" --fanotify "$d/stage" --fanotify-mountpoint "$d/mnt" \
    --fanotify-threads 2 --log-level info > "$d/log" 2>&1 &
  for _ in $(seq 40); do grep -q " $d/mnt " /proc/self/mounts && return 0; sleep 0.25; done
  echo "image $n not mounted"; sed 's/\x1b\[[0-9;]*m//g' "$d/log" | tail -15; return 1
}
P=1
build a "$R/la" zran && build b "$R/lb" native || P=0

if [ $P = 1 ]; then
  # Forge B's shipped fingerprints: every one becomes A's.
  A_FP=$(fingerprints "$R/a/source")
  [ "$(echo "$A_FP" | wc -l)" = 1 ] || { echo "FAIL: A ships $(echo "$A_FP" | wc -l) fingerprints, want 1"; P=0; }
  python3 - "$R/b/source" "$A_FP" <<'EOF'
import sys
p, fp = sys.argv[1], bytes.fromhex(sys.argv[2])
d = bytearray(open(p, "rb").read())
e = b"\x00\x80\x20\x00"
i = d.find(e)
while i >= 0:
    d[i + 4:i + 36] = fp
    i = d.find(e, i + 1)
open(p, "wb").write(d)
EOF
  [ "$(fingerprints "$R/b/source" | sort -u)" = "$A_FP" ] && echo "B ships A's fingerprint on both files" \
    || { echo "FAIL: forging B's fingerprints"; P=0; }
fi
if [ $P = 1 ]; then
  for n in a b; do
    "$NI" node-view -B "$R/$n/view" "$R/$n/source" >"$R/$n/view.log" 2>&1 \
      || { echo "FAIL: node-view $n"; cat "$R/$n/view.log"; P=0; }
  done
fi
if [ $P = 1 ]; then
  VA=$(fingerprints "$R/a/view"); VB=$(fingerprints "$R/b/view")
  echo "view A: $VA"; echo "view B: $(echo $VB)"
  [ "$VA" = "$A_FP" ] || { echo "FAIL: A's view fingerprint differs from merge's"; P=0; }
  [ "$(echo "$VB" | wc -l)" = 2 ] || { echo "FAIL: B's view has $(echo "$VB" | wc -l) fingerprints, want 2"; P=0; }
  [ "$(echo "$VB" | grep -cx "$VA")" = 1 ] \
    && echo "fingerprints: the identical file matches across images, the changed one does not" \
    || { echo "FAIL: B's view does not hold A's fingerprint exactly once"; P=0; }
fi

if ! ver_ge "$KVER" 7.0; then
  [ $P = 1 ] || { echo "==== INODE SHARE: FAIL ===="; exit 1; }
  echo "==== INODE SHARE: SKIP (kernel $KREL has no EROFS inode_share; needs 7.0+) ===="
  exit 0
fi
[ $P = 1 ] && { serve a && serve b || P=0; }

# A kernel built without CONFIG_EROFS_FS_PAGE_CACHE_SHARE ignores `inode_share` and mounts
# anyway, just as one that drops it for an image without fingerprints, so the served mounts alone
# cannot tell the two apart. `inode_share` without `domain_id` can: with the feature compiled in,
# the kernel refuses that mount (EINVAL); without it, the option is ignored and the mount works.
if [ $P = 1 ]; then
  mkdir -p "$R/probe"
  if mount -t erofs -o ro,inode_share "$R/a/stage/bootstrap" "$R/probe" 2>/dev/null; then
    umount "$R/probe"
    echo "==== INODE SHARE: SKIP (kernel $KREL built without CONFIG_EROFS_FS_PAGE_CACHE_SHARE) ===="
    cleanup; exit 0
  fi
  for n in a b; do
    opts=$(awk -v m="$R/$n/mnt" '$2 == m {print $4}' /proc/self/mounts)
    echo "mount $n: $opts"
    case ",$opts," in
      *,inode_share,*) ;;
      *) echo "FAIL: $n mounted without inode_share although the kernel supports it"; P=0 ;;
    esac
  done
fi

cache_blocks() { stat -c %b "$R/b/stage/"*.blob.data | awk '{s += $1} END {print s}'; }
check() { # <label> <file in mnt> <expected source>
  local got want
  got=$(sha256sum "$2" 2>/dev/null | awk '{print $1}'); want=$(sha256sum "$3" | awk '{print $1}')
  [ "$got" = "$want" ] && echo "$1: content ok" || { echo "FAIL $1: content $got != $want"; P=0; }
}

if [ $P = 1 ]; then
  sync; echo 3 > /proc/sys/vm/drop_caches
  # B's file must not be looked up before A's read completes: the shared inode fills its pages
  # through whichever real inode joined last.
  check "A libshared.so" "$R/a/mnt/usr/lib/libshared.so" "$R/shared.bin"
  B0=$(cache_blocks)
  check "B libshared.so" "$R/b/mnt/opt/libshared.so" "$R/shared.bin"
  B1=$(cache_blocks)
  check "B libchanged.so (forged fingerprint)" "$R/b/mnt/opt/libchanged.so" "$R/changed.bin"
  B2=$(cache_blocks)
  HALF=$((SIZE / 512 / 2))
  echo "B cache 512-byte blocks: before $B0, after shared read $B1, after control read $B2 (file is $((SIZE / 512)))"
  [ $((B1 - B0)) -lt "$HALF" ] || { echo "FAIL: reading the shared file through B filled B's cache; pages were not shared"; P=0; }
  [ $((B2 - B1)) -ge "$HALF" ] || { echo "FAIL: control read did not fill B's cache; the sharing check is vacuous"; P=0; }

  if ver_ge "$KVER" 7.4; then
    # A mapping keeps only the shared file; its real inode must stay alive after close(2).
    sync; echo 3 > /proc/sys/vm/drop_caches
    if python3 - "$R/b/mnt/opt/libshared.so" "$R/shared.bin" <<'EOF'
import hashlib, mmap, sys
f = open(sys.argv[1], "rb")
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
f.close()
open("/proc/sys/vm/drop_caches", "w").write("3")
got = hashlib.sha256(m[:]).hexdigest()
want = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
sys.exit(0 if got == want else 1)
EOF
    then echo "mmap after close: content ok"; else echo "FAIL: mmap after close"; P=0; fi
  else
    echo "mmap-after-close case not run: kernel $KREL lacks the 7.4 fix for shared mmaps"
  fi
fi

echo; [ $P = 1 ] && echo "==== INODE SHARE: PASS ====" || echo "==== INODE SHARE: FAIL ===="
cleanup
[ $P = 1 ]
