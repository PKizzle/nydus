#!/usr/bin/env bash
# Snapshotter auto-accel daemon over the fanotify path, end to end through `DaemonSupervisor`:
# builds a two-layer zran artifact the way `local_accel::convert` does (targz-ref per layer,
# merge, a localfs backend holding the gzip layers and zran index blobs), and checks that
# `nydus-image optimize` refuses to repack it. For the artifact, and for an optimized copy if
# optimize does write one, it runs the root-only
# `auto_accel_daemon_serves_file_data_across_restarts` test, which reads every file of the
# mount three times: on the first start, after the daemon dir was swept, and over a leftover
# EROFS mount without data devices, releasing the daemon in between.
#
# Needs root, Linux >= 6.14, cargo, and ROOT on ext4 (tmpfs has no pre-content marks).
set -u
NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
CARGO="${CARGO:-cargo}"
ROOT="${ROOT:-/var/tmp/auto-accel-restart}"

fail(){ echo "FAIL: $*"; exit 1; }

grep " $ROOT/" /proc/self/mounts | awk '{print $2}' | grep "/snapshotter/daemons/" |
  xargs -r -n1 umount -l
rm -rf "$ROOT"; mkdir -p "$ROOT"/{l1/bin,l2/etc,o1,o2,base/artifact/backend}

# Layer 1 holds a large file spanning several chunks, layer 2 a small file in a tiny layer.
head -c 3000000 /dev/urandom > "$ROOT/l1/bin/tool"; echo base > "$ROOT/l1/etc-release"
echo "root:x:0:0:root:/root:/bin/sh" > "$ROOT/l2/etc/passwd"
tar -C "$ROOT/l1" -czf "$ROOT/L1.tar.gz" .
tar -C "$ROOT/l2" -czf "$ROOT/L2.tar.gz" .
A="$ROOT/base/artifact"
ids=()
for i in 1 2; do
  D=$(sha256sum "$ROOT/L$i.tar.gz" | awk '{print $1}'); ids+=("$D")
  "$NI" create --type targz-ref --fs-version 6 -B "$ROOT/o$i/bootstrap" -D "$ROOT/o$i" \
    "$ROOT/L$i.tar.gz" >/dev/null 2>&1 || fail "targz-ref convert of layer $i"
  INDEX=$(ls "$ROOT/o$i" | grep -v '^bootstrap$')
  [ -n "$INDEX" ] || fail "layer $i produced no zran index blob"
  ln -s "$ROOT/L$i.tar.gz" "$A/backend/$D"
  mv "$ROOT/o$i/$INDEX" "$A/backend/$INDEX"
done
"$NI" merge -B "$A/bootstrap" --original-blob-ids "${ids[0]},${ids[1]}" \
  "$ROOT/o1/bootstrap" "$ROOT/o2/bootstrap" >/dev/null 2>&1 || fail "merge"

# `nydus-image optimize` packs a prefetch blob by copying chunk bytes. A zran chunk decodes only
# with its layer's zran index, so optimize must refuse this artifact rather than write one whose
# packed blob cannot be read; if it does write one, that artifact must serve every file too.
O="$ROOT/optimized/artifact"
mkdir -p "$ROOT/optimized" "$ROOT/optimize-out" && cp -a "$A" "$O"
echo '{"version":"v1","files":[{"path":"/bin/tool","ranges":null},{"path":"/etc/passwd","ranges":null}]}' \
  > "$ROOT/prefetch.json"
shapes="base"
if "$NI" optimize --bootstrap "$O/bootstrap" --prefetch-files "$ROOT/prefetch.json" \
  --blob-dir "$O/backend" --output-bootstrap "$ROOT/bootstrap.optimized" \
  --output-blob-dir "$ROOT/optimize-out" > "$ROOT/optimize.log" 2>&1; then
  mv "$ROOT/bootstrap.optimized" "$O/bootstrap"
  [ "$(ls "$ROOT/optimize-out" | wc -l)" = 1 ] || fail "optimize did not write one prefetch blob"
  mv "$ROOT/optimize-out"/* "$O/backend/"
  shapes="base optimized"
else
  grep -q "cannot repack" "$ROOT/optimize.log" || { cat "$ROOT/optimize.log"; fail "optimize failed"; }
  [ -z "$(ls "$ROOT/optimize-out")" ] || fail "a refused optimize left a prefetch blob behind"
  echo "optimize refused the zran artifact"
fi

for shape in $shapes; do
  echo "---- $shape artifact ----"
  NYDUS_E2E_ROOT="$ROOT/$shape" "$CARGO" test -p nydus-snapshotter --lib \
    daemon::tests::auto_accel_daemon_serves_file_data_across_restarts -- --ignored --exact --nocapture \
    || fail "the auto-accel daemon did not serve every file of the $shape artifact"
  if grep -q " $ROOT/$shape/snapshotter/daemons/" /proc/self/mounts; then
    grep " $ROOT/$shape/snapshotter/daemons/" /proc/self/mounts
    fail "mount still present under $ROOT/$shape/snapshotter/daemons"
  fi
done
echo "==== AUTO-ACCEL RESTART: PASS ===="
