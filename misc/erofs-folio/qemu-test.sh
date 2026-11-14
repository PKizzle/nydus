#!/usr/bin/env bash
# Boots an arm64 kernel in QEMU and runs the file-backed EROFS partial-folio self-test
# (`nydus_service::erofs_folio`) and the page-cache-sharing self-test (`nydus_service::erofs_ishare`)
# in it, on a loop-mounted ext4 like the snapshotter's work dir.
# Use it to check how a kernel build classifies, e.g. an unpatched 7.3 against one carrying the
# upstream fix 52dceb88082b. Needs qemu-system-aarch64, a static busybox, mkfs.ext4 and cpio;
# no root on the host.
#
#   KERNEL       arm64 kernel Image, or an EFI zboot vmlinuz (gzip or zstd payload, as in Ubuntu's
#                kernel packages)
#   PROBE        static aarch64 build of the probe:
#                  cargo build --release -p nydus-service --example erofs_folio_probe \
#                    --target aarch64-unknown-linux-musl
#   MODULES_TAR  optional tarball holding .../kernel/fs/erofs/erofs.ko[.xz|.zst] (modular EROFS),
#                e.g. `dpkg-deb --fsys-tarfile linux-modules-*.deb`
#   DEMO_IMAGE   optional EROFS image to mount as is and padded, e.g. from `demo-image.sh`
#   EXPECT       optional affected|unaffected; the script fails unless the probe says so and,
#                with DEMO_IMAGE, the image reads as `expect.sh` requires
#   EXPECT_ISHARE  optional unsupported|fix_absent|fix_present|inconclusive, likewise
#   BUSYBOX      static busybox (default: the one on PATH)
#   FANOTIFY_TESTS  optional misc/fanotify scripts to run in the guest after the probes, e.g.
#                "dead-chunk-test runtime-test zran-multilayer-test"; the script fails unless each
#                prints its PASS line. Needs NYDUSD and NYDUS_IMAGE (static aarch64 builds),
#                BASH_STATIC (e.g. Debian's bash-static) and optionally MMAP_CAT (a static
#                build of misc/fanotify/mmap-cat.c)
#   EXPECT_PAGE_SIZE  optional page size in KiB the guest kernel must use
#   QEMU_TIMEOUT seconds the guest may run (default 300)
#
# Prints the guest console and ends with "==== EROFS FOLIO PROBE: <status> ====" and
# "==== EROFS ISHARE PROBE: <status> ====".
set -euo pipefail
: "${KERNEL:?}" "${PROBE:?}"
BUSYBOX="${BUSYBOX:-$(command -v busybox)}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ROOT="$WORK/root"
mkdir -p "$ROOT"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,ext}
cp "$BUSYBOX" "$ROOT/bin/busybox"
for applet in sh mount umount insmod mkdir cat echo dmesg grep poweroff sync; do
  ln -s busybox "$ROOT/bin/$applet"
done
cp "$PROBE" "$ROOT/probe"
if [ -n "${FANOTIFY_TESTS:-}" ]; then
  : "${NYDUSD:?}" "${NYDUS_IMAGE:?}" "${BASH_STATIC:?}"
  mkdir -p "$ROOT"/{tests,var/tmp}
  cp "$NYDUSD" "$ROOT/bin/nydusd"
  cp "$NYDUS_IMAGE" "$ROOT/bin/nydus-image"
  cp "$BASH_STATIC" "$ROOT/bin/bash"
  [ -z "${MMAP_CAT:-}" ] || cp "$MMAP_CAT" "$ROOT/bin/mmap-cat"
  # The guest runs as root; the scripts' `sudo` is a pass-through.
  printf '#!/bin/sh\nexec "$@"\n' > "$ROOT/bin/sudo"
  chmod +x "$ROOT/bin/sudo"
  for t in $FANOTIFY_TESTS; do cp "$(dirname "$0")/../fanotify/$t.sh" "$ROOT/tests/"; done
  echo "$FANOTIFY_TESTS" > "$ROOT/tests/list"
fi
if [ -n "${MODULES_TAR:-}" ]; then
  ko=$(tar tf "$MODULES_TAR" | grep '/kernel/fs/erofs/erofs\.ko')
  ko=${ko%%$'\n'*}
  tar xOf "$MODULES_TAR" "$ko" > "$WORK/erofs.ko.raw"
  case "$ko" in
    *.xz) xz -dc "$WORK/erofs.ko.raw" > "$ROOT/erofs.ko" ;;
    *.zst) zstd -dc "$WORK/erofs.ko.raw" > "$ROOT/erofs.ko" ;;
    *) cp "$WORK/erofs.ko.raw" "$ROOT/erofs.ko" ;;
  esac
fi
# QEMU's -kernel loader does not unpack zboot payloads compressed with zstd.
if [ "$(dd if="$KERNEL" bs=1 skip=4 count=4 2>/dev/null)" = zimg ]; then
  off=$(($(od -An -tu4 -j8 -N4 "$KERNEL"))) size=$(($(od -An -tu4 -j12 -N4 "$KERNEL")))
  comp=$(dd if="$KERNEL" bs=1 skip=24 count=32 2>/dev/null | tr -d '\0')
  case "$comp" in gzip | zstd) ;; *) echo "unsupported zboot compression: $comp" >&2; exit 1 ;; esac
  dd if="$KERNEL" iflag=skip_bytes,count_bytes skip="$off" count="$size" status=none |
    "$comp" -dc > "$WORK/Image"
  KERNEL="$WORK/Image"
fi
[ -n "${DEMO_IMAGE:-}" ] && cp "$DEMO_IMAGE" "$ROOT/demo.erofs"
truncate -s "$([ -n "${FANOTIFY_TESTS:-}" ] && echo 512M || echo 16M)" "$ROOT/ext4.img"
mkfs.ext4 -q -F "$ROOT/ext4.img"

cat > "$ROOT/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
/bin/busybox --install -s
[ -f /erofs.ko ] && insmod /erofs.ko
mount -o loop /ext4.img /ext
echo "==== kernel $(cat /proc/sys/kernel/osrelease)"
if [ -f /demo.erofs ]; then /probe /ext /demo.erofs; else /probe /ext; fi
echo "==== probe exit $?"
echo "==== page size $(sed -n 's/^KernelPageSize: *\([0-9]*\) kB/\1/p' /proc/self/smaps | head -1) KiB"
for t in $(cat /tests/list 2>/dev/null); do
  case $t in
    dead-chunk-test) pass="==== DEAD CHUNKS: PASS" ;;
    runtime-test) pass="==== FANOTIFY FETCH PATH: PASS" ;;
    zran-multilayer-test) pass="==== MULTI-LAYER ZRAN: PASS ====" ;;
    *) pass="unknown test $t" ;;
  esac
  ROOT=/ext/$t NYDUSD=/bin/nydusd NYDUS_IMAGE=/bin/nydus-image \
    MMAP_CAT=$([ -x /bin/mmap-cat ] && echo /bin/mmap-cat) bash /tests/$t.sh > /ext/$t.log 2>&1
  cat /ext/$t.log
  if grep -qF "$pass" /ext/$t.log && ! grep -q SKIP /ext/$t.log; then r=PASS; else r=FAIL; fi
  echo "==== FANOTIFY $t: $r ===="
done
dmesg | grep -m5 'erofs.*failed' || true
sync
poweroff -f
INIT
chmod +x "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet) | gzip > "$WORK/initrd.gz"

# Neoverse-N1 has the 4K, 16K and 64K granules; QEMU 8.2 (Ubuntu 24.04) hangs booting Ubuntu's
# 7.3/7.4 arm64 kernels with `-cpu max`.
timeout "${QEMU_TIMEOUT:-300}" qemu-system-aarch64 -machine virt -cpu neoverse-n1 -smp 2 -m 2048 -nographic -no-reboot \
  -kernel "$KERNEL" -initrd "$WORK/initrd.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=-1 quiet" </dev/null | tee "$WORK/console.log"

ishare=$(sed -n 's/.*erofs-ishare-probe: status=\([a-z_]*\).*/\1/p' "$WORK/console.log" | tr -d '\r')
rc=0
bash "$(dirname "$0")/expect.sh" "$WORK/console.log" "${EXPECT:-}" "${DEMO_IMAGE:+image}" || rc=$?
echo "==== EROFS ISHARE PROBE: ${ishare:-none} ===="
[ "$rc" = 0 ]
[ -z "${EXPECT_ISHARE:-}" ] || [ "$ishare" = "$EXPECT_ISHARE" ]
page=$(sed -n 's/^==== page size \([0-9]*\) KiB.*/\1/p' "$WORK/console.log" | tr -d '\r')
[ -z "${EXPECT_PAGE_SIZE:-}" ] || [ "$page" = "$EXPECT_PAGE_SIZE" ] ||
  { echo "::error::guest page size '${page:-none}' KiB, expected $EXPECT_PAGE_SIZE"; exit 1; }
for t in ${FANOTIFY_TESTS:-}; do
  grep -q "==== FANOTIFY $t: PASS ====" "$WORK/console.log" ||
    { echo "::error::fanotify $t did not pass in the guest"; rc=1; }
done
[ "$rc" = 0 ]
