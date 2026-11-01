#!/usr/bin/env bash
# Runs the fanotify/EROFS integration scripts one after another on a loop-mounted ext4 and
# fails unless each one printed its PASS line and skipped no case. Used by the fanotify-vm CI
# workflow inside a virtme-ng guest; works the same on any root shell of a >= 6.14 host.
#
#   NYDUS_IMAGE, NYDUSD    release builds
#   SNAPSHOTTER_TEST_BIN   `cargo test -p nydus-snapshotter --lib --no-run` binary; unset runs
#                          the snapshotter tests through cargo instead
#   IMG                    ext4 image file to create (must not live on tmpfs in a small VM)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
: "${NYDUS_IMAGE:?}" "${NYDUSD:?}"
IMG="${IMG:-/var/tmp/fanotify-ci.img}"
FS=/var/tmp/fanotify-ci

echo "kernel $(uname -r)"
umount "$FS" 2>/dev/null
rm -f "$IMG"; truncate -s 4G "$IMG"; mkfs.ext4 -q -F "$IMG" || exit 1
mkdir -p "$FS"; mount -o loop "$IMG" "$FS" || exit 1

# The scripts call sudo; a guest without a usable one gets a pass-through, since this is root.
if ! sudo -n true 2>/dev/null; then
  mkdir -p "$FS/bin"; printf '#!/bin/sh\nexec "$@"\n' > "$FS/bin/sudo"; chmod +x "$FS/bin/sudo"
  export PATH="$FS/bin:$PATH"
fi
# The snapshotter scripts run `$CARGO test -p nydus-snapshotter --lib <test> -- <args>`.
if [ -n "${SNAPSHOTTER_TEST_BIN:-}" ]; then
  cat > "$FS/cargo-prebuilt" <<'EOF'
#!/bin/sh
while [ "$1" != "--lib" ]; do shift; done
test=$2; shift 3
exec "$SNAPSHOTTER_TEST_BIN" "$test" "$@"
EOF
  chmod +x "$FS/cargo-prebuilt"; export CARGO="$FS/cargo-prebuilt"
fi

FAILED=""
run() { # <script> <PASS line>
  echo; echo "======== $1 ========"
  ROOT="$FS/$1" bash "$HERE/$1.sh" 2>&1 | tee "$FS/$1.log"
  if ! grep -qF "$2" "$FS/$1.log" || grep -q "SKIP" "$FS/$1.log"; then FAILED="$FAILED $1"; fi
}
run runtime-test "==== FANOTIFY FETCH PATH: PASS"
run zran-multilayer-test "==== MULTI-LAYER ZRAN: PASS ===="
run ref-layer-formats-test "==== REF LAYER FORMATS: PASS ===="
run release-unmount-test "==== RELEASE-UNMOUNT: PASS ===="
run auto-accel-restart-test "==== AUTO-ACCEL RESTART: PASS ===="
run mount-health-probe-test "==== MOUNT-HEALTH PROBE: PASS ===="
run precontent-cases "==== FANOTIFY PRE-CONTENT CASES: PASS ===="
run export-block-test "==== EXPORT BLOCK (4096): PASS"

umount -l "$FS"
echo
[ -z "$FAILED" ] && echo "==== ALL FANOTIFY SUITES: PASS ====" && exit 0
echo "==== FAILED:$FAILED ===="; exit 1
