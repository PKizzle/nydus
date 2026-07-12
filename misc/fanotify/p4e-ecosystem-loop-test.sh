#!/usr/bin/env bash
# P4e ecosystem-loop e2e: plain OCI image -> nydusify convert --oci-ref
# --with-referrer -> snapshotter discovery-driven detect+materialize (gated
# rust test) -> nydusd registry-backend serve -> file comparison vs source.
set -u
REG="${REG:-127.0.0.1:5000}"; REPO=loop/app; TAG=v1
SRCREF="$REG/$REPO:$TAG"
ROOT="${ROOT:-/var/tmp/p4e-loop}"; NI="${NYDUS_IMAGE:-./target/release/nydus-image}"
ND="${NYDUSD:-./target/release/nydusd}"; NYF="${NYDUSIFY:-./target/release/nydusify}"
C="curl -sk"
step() { echo; echo "#### $* ####"; }
fail() { echo "P4E-FAIL: $*"; exit 1; }

step "0. ext4 loopback for the fanotify-capable workdir"
if ! mountpoint -q /mnt/ext4 2>/dev/null; then
  mkdir -p /mnt/ext4 && dd if=/dev/zero of=/ext4.img bs=1M count=512 status=none \
    && mkfs.ext4 -q /ext4.img && mount -o loop /ext4.img /mnt/ext4 || fail "ext4 setup"
fi
umount "$ROOT/mnt" 2>/dev/null; pkill -f "nydusd singleton" 2>/dev/null; sleep 1
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src/sub,l1,l2,stage,mnt,boot}

step "1. build 2-layer source rootfs + push PLAIN OCI image to $SRCREF"
perl -e 'print "P4E_LOOP_LAYER1_" . ("x" x 100000)' > "$ROOT/src/app.bin"
echo "layer2 marker" > "$ROOT/src/sub/conf.txt"
head -c 90000 /dev/urandom > "$ROOT/src/data.rand"
# layer1: app.bin ; layer2: sub/ + data.rand  (2 gzip layers = 2 data blobs)
tar -C "$ROOT/src" -czf "$ROOT/l1/layer.tar.gz" app.bin
tar -C "$ROOT/src" -czf "$ROOT/l2/layer.tar.gz" sub data.rand
L1=$(sha256sum "$ROOT/l1/layer.tar.gz"|awk '{print $1}'); L2=$(sha256sum "$ROOT/l2/layer.tar.gz"|awk '{print $1}')
D1=$(gzip -dc "$ROOT/l1/layer.tar.gz"|sha256sum|awk '{print $1}'); D2=$(gzip -dc "$ROOT/l2/layer.tar.gz"|sha256sum|awk '{print $1}')
cat > "$ROOT/config.json" <<CFG
{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:$D1","sha256:$D2"]},"config":{}}
CFG
CS=$(sha256sum "$ROOT/config.json"|awk '{print $1}'); CL=$(stat -c%s "$ROOT/config.json")
push_blob() { local loc path sep
  loc=$($C -X POST -D - -o /dev/null "https://$REG/v2/$REPO/blobs/uploads/" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  path="${loc#https://$REG}"; sep='?'; echo "$path" | grep -q '?' && sep='&'
  $C -o /dev/null -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$1" "https://$REG${path}${sep}digest=sha256:$2"; }
push_blob "$ROOT/l1/layer.tar.gz" "$L1"; push_blob "$ROOT/l2/layer.tar.gz" "$L2"; push_blob "$ROOT/config.json" "$CS"
S1=$(stat -c%s "$ROOT/l1/layer.tar.gz"); S2=$(stat -c%s "$ROOT/l2/layer.tar.gz")
cat > "$ROOT/manifest.json" <<MAN
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:$CS","size":$CL},
"layers":[
 {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:$L1","size":$S1},
 {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:$L2","size":$S2}]}
MAN
$C -o /dev/null -w "  manifest push http=%{http_code}\n" -X PUT -H "Content-Type: application/vnd.oci.image.manifest.v1+json" --data-binary @"$ROOT/manifest.json" "https://$REG/v2/$REPO/manifests/$TAG"

step "2. nydusify convert --oci-ref --with-referrer (Rust converter, real push)"
"$NYF" convert --source "$SRCREF" --target "$REG/$REPO:$TAG-nydus" \
  --oci-ref --with-referrer --source-insecure --target-insecure \
  --nydus-image "$NI" --work-dir "$ROOT/nydusify-work" --fs-version 6 \
  || fail "nydusify convert"

step "3. snapshotter DISCOVERY-driven detect + materialize (gated rust test)"

P4E_E2E=1 P4E_IMAGE_REF="$SRCREF" P4E_MATERIALIZE_DIR="$ROOT/boot" \
  cargo test -p nydus-snapshotter --test p4e_ecosystem_loop_e2e -- --nocapture 2>&1 \
  | grep -vE "Compiling|Blocking|warning" | tail -8
grep -q . <(ls "$ROOT/boot"/referrer-bootstraps/*.boot 2>/dev/null) || fail "no materialized bootstrap"
BOOT=$(ls "$ROOT/boot"/referrer-bootstraps/*.boot | head -1)

step "4. SERVE: nydusd fanotify singleton, registry backend on the SOURCE repo"
cp "$BOOT" "$ROOT/stage/bootstrap"
cat > "$ROOT/nydusd.json" <<CFG
{ "blobs": [ { "type": "bootstrap", "id": "b1", "domain_id": "d1",
  "config": { "id": "f1", "backend_type": "registry",
    "backend_config": { "scheme": "https", "host": "$REG", "repo": "$REPO", "skip_verify": true },
    "cache_type": "fanotify", "cache_config": { "work_dir": "$ROOT/stage" },
    "metadata_path": "$ROOT/stage/bootstrap" } } ] }
CFG
"$ND" singleton --config "$ROOT/nydusd.json" --fanotify "$ROOT/stage" \
  --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 --log-level warn > "$ROOT/nydusd.log" 2>&1 &
sleep 4
mount | grep -q "$ROOT/mnt" || { tail -12 "$ROOT/nydusd.log"; fail "EROFS not mounted"; }

step "5. VERIFY: files served from the registry == source rootfs"
rc=0
for f in app.bin sub/conf.txt data.rand; do
  s=$(sha256sum "$ROOT/src/$f"|awk '{print $1}'); m=$(sha256sum "$ROOT/mnt/$f" 2>/dev/null|awk '{print $1}')
  [ "$s" = "$m" ] && echo "  OK  $f" || { echo "  MISMATCH $f src=$s mnt=$m"; rc=1; }
done
umount "$ROOT/mnt" 2>/dev/null; pkill -f "nydusd singleton" 2>/dev/null
[ $rc -eq 0 ] && echo "==== P4E ECOSYSTEM LOOP: PASS (nydusify -> referrers discovery -> materialize -> registry-backend serve) ====" || fail "content mismatch"
