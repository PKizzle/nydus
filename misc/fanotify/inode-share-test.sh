#!/usr/bin/env bash
# EROFS page cache sharing (`inode_share`, Linux 7.0+) between two node-local images.
#
# Two gzip layers are converted the way local_accel does (targz-ref per layer, then
# `merge --inode-share-fingerprint`); both hold the same file under different paths, and image B
# also a same-size file with one byte changed. Each image is served by its own nydusd with
# `erofs_inode_share_domain` set, so both EROFS mounts join one sharing domain.
#
# Sharing is measured on B's blob cache: B's `.blob.data` is the device its EROFS mount reads, so
# it only gains blocks when B's own inode has to fill the page cache. After the shared file was
# read through A, reading it through B must not grow B's cache; the changed file (the control)
# must, which shows the measurement can see a fill at all. Content is checked by hash every time.
# On >= 7.4 a file is also read through a mapping that outlives its fd while its inodes are
# evicted (the "erofs: hold real inodes for shared files" fix); older kernels skip that case.
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"
R="${ROOT:-/var/tmp/inode-share}"
cleanup() { umount -l "$R/a/mnt" "$R/b/mnt" 2>/dev/null; pkill -9 -f "nydusd singleton" 2>/dev/null; }
cleanup; sleep 1
rm -rf "$R"; mkdir -p "$R"

KREL=$(uname -r); KVER=$(echo "$KREL" | grep -oE '^[0-9]+\.[0-9]+')
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
if ! ver_ge "$KVER" 7.0; then
  echo "==== INODE SHARE: SKIP (kernel $KREL has no EROFS inode_share; needs 7.0+) ===="
  exit 0
fi

SIZE=$((8 << 20))
head -c "$SIZE" /dev/urandom > "$R/shared.bin"
cp "$R/shared.bin" "$R/changed.bin"
printf '\xff' | dd of="$R/changed.bin" bs=1 seek=$((SIZE / 2)) conv=notrunc status=none
mkdir -p "$R/la/usr/lib" "$R/lb/opt"
cp "$R/shared.bin" "$R/la/usr/lib/libshared.so"; echo a > "$R/la/a.txt"
cp "$R/shared.bin" "$R/lb/opt/libshared.so"; cp "$R/changed.bin" "$R/lb/opt/libchanged.so"

# Build, stage and serve image <name> from layer dir <src>.
serve() {
  local n=$1 src=$2 d="$R/$1"
  mkdir -p "$d"/{out,backend,stage,mnt}
  tar -C "$src" -czf "$d/layer.tar.gz" .
  local dig boot meta
  dig=$(sha256sum "$d/layer.tar.gz" | awk '{print $1}')
  boot=$("$NI" create --type targz-ref --fs-version 6 -D "$d/out" "$d/layer.tar.gz" 2>&1 \
    | sed -n 's/^meta blob path: //p')
  meta=$(ls "$d/out" | grep -v "$(basename "$boot")")
  cp "$d/layer.tar.gz" "$d/backend/$dig"; cp "$d/out/$meta" "$d/backend/$meta"
  "$NI" merge --inode-share-fingerprint -B "$d/stage/bootstrap" --original-blob-ids "$dig" \
    "$boot" >"$d/merge.log" 2>&1 || { echo "merge $n failed"; cat "$d/merge.log"; return 1; }
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
serve a "$R/la" && serve b "$R/lb" || P=0

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
  check "B libchanged.so" "$R/b/mnt/opt/libchanged.so" "$R/changed.bin"
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
