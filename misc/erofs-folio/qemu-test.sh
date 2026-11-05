#!/usr/bin/env bash
# Boots an arm64 kernel in QEMU and runs the file-backed EROFS partial-folio self-test
# (`nydus_service::erofs_folio`) in it, on a loop-mounted ext4 like the snapshotter's work dir.
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
#   BUSYBOX      static busybox (default: the one on PATH)
#
# Prints the guest console and ends with "==== EROFS FOLIO PROBE: <status> ====".
set -euo pipefail
: "${KERNEL:?}" "${PROBE:?}"
BUSYBOX="${BUSYBOX:-$(command -v busybox)}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ROOT="$WORK/root"
mkdir -p "$ROOT"/{bin,proc,sys,dev,ext}
cp "$BUSYBOX" "$ROOT/bin/busybox"
for applet in sh mount umount insmod mkdir cat echo dmesg grep poweroff sync; do
  ln -s busybox "$ROOT/bin/$applet"
done
cp "$PROBE" "$ROOT/probe"
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
truncate -s 16M "$ROOT/ext4.img"
mkfs.ext4 -q -F "$ROOT/ext4.img"

cat > "$ROOT/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
[ -f /erofs.ko ] && insmod /erofs.ko
mount -o loop /ext4.img /ext
echo "==== kernel $(cat /proc/sys/kernel/osrelease)"
if [ -f /demo.erofs ]; then /probe /ext /demo.erofs; else /probe /ext; fi
echo "==== probe exit $?"
dmesg | grep -m5 'erofs.*failed' || true
sync
poweroff -f
INIT
chmod +x "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet) | gzip > "$WORK/initrd.gz"

timeout 300 qemu-system-aarch64 -machine virt -cpu max -m 1024 -nographic -no-reboot \
  -kernel "$KERNEL" -initrd "$WORK/initrd.gz" \
  -append "console=ttyAMA0 rdinit=/init panic=-1 quiet" </dev/null | tee "$WORK/console.log"

bash "$(dirname "$0")/expect.sh" "$WORK/console.log" "${EXPECT:-}" "${DEMO_IMAGE:+image}"
