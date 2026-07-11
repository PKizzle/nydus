#!/usr/bin/env bash
# B4b: serve a PUBLISHED nydus image (bootstrap distributed as an OCI referrer
# artifact, the nydusify / Go-snapshotter model) from a registry, on demand.
#
# Two halves, verified end-to-end (both PASS on Linux 7.0 + a self-signed HTTPS
# `registry:2`, kernel >= 6.14 required for the fanotify path):
#   1. FETCH   — `snapshotter/tests/b4b_referrer_e2e.rs` drives the actual
#                `materialize_bootstrap_blocking` against a live registry for
#                BOTH digest shapes (artifact-manifest and direct bootstrap-blob),
#                incl. the data-blob-before-bootstrap layer ordering that the
#                loose selection predicate used to mishandle.
#   2. SERVE   — THIS script: build a nydus image, push its data blob + a
#                referrer artifact manifest to a registry, then mount via nydusd
#                with a REGISTRY backend and verify reads reproduce the source.
#
# A nydus data-blob id == the blob's content sha256, so it is addressable at
# /v2/<repo>/blobs/sha256:<blob_id>; the daemon fetches ranges on demand.
#
# Requirements: Linux >= 6.14, root, ROOT on a fanotify-pre-content fs (ext4;
# tmpfs/overlay return ENOTSUP), and an OCI registry reachable at $REG.
set -u
NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
ND="${NYDUSD:-$(command -v nydusd || echo ./target/release/nydusd)}"
REG="${REG:-127.0.0.1:5000}"      # OCI registry endpoint (host:port)
SCHEME="${SCHEME:-https}"          # https (self-signed => set SKIP_VERIFY=true) or http
SKIP_VERIFY="${SKIP_VERIFY:-true}"
REPO="${REPO:-b4bimg}"
ROOT="${ROOT:-/var/tmp/b4b-rt}"    # must NOT be tmpfs
C="curl -s"; [ "$SKIP_VERIFY" = true ] && C="curl -sk"

step() { echo; echo "### $* ###"; }
fail() { echo "FAIL: $*"; umount "$ROOT/mnt" 2>/dev/null; pkill -f "nydusd singleton" 2>/dev/null; exit 1; }

umount "$ROOT/mnt" 2>/dev/null; pkill -f "nydusd singleton" 2>/dev/null; sleep 1
rm -rf "$ROOT"; mkdir -p "$ROOT"/{src,src/sub,out,stage,mnt}

step "build source rootfs"
perl -e 'print "B4B_REFERRER_SERVING_OK_0123456789AB" x 4096' > "$ROOT/src/hello.txt"
head -c 180000 /dev/urandom > "$ROOT/src/random.bin"
echo "b4b-subdir-marker" > "$ROOT/src/sub/small.txt"

step "nydus-image create (RAFS v6)"
"$NI" create --fs-version 6 --compressor none --block-size 4096 \
  -B "$ROOT/out/bootstrap" -D "$ROOT/out" "$ROOT/src" >/dev/null 2>&1 || fail "nydus-image create"
BLOB=$(ls "$ROOT/out" | grep -vE '^bootstrap' | head -1); [ -n "$BLOB" ] || fail "no data blob"
DATA_SHA=$(sha256sum "$ROOT/out/$BLOB" | awk '{print $1}')
BOOT_SHA=$(sha256sum "$ROOT/out/bootstrap" | awk '{print $1}')

push_blob() { # file digest
  local loc path sep
  loc=$($C -X POST -D - -o /dev/null "$SCHEME://$REG/v2/$REPO/blobs/uploads/" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  path="${loc#$SCHEME://$REG}"; sep='?'; echo "$path" | grep -q '?' && sep='&'
  $C -o /dev/null -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$1" "$SCHEME://$REG${path}${sep}digest=sha256:$2"
}

step "push data blob + referrer artifact manifest to $SCHEME://$REG/$REPO"
push_blob "$ROOT/out/$BLOB" "$DATA_SHA"
push_blob "$ROOT/out/bootstrap" "$BOOT_SHA"
echo -n '{}' > "$ROOT/config.json"; CFG_SHA=$(sha256sum "$ROOT/config.json"|awk '{print $1}'); CFG_LEN=$(stat -c%s "$ROOT/config.json")
push_blob "$ROOT/config.json" "$CFG_SHA"
DATA_LEN=$(stat -c%s "$ROOT/out/$BLOB"); BOOT_LEN=$(stat -c%s "$ROOT/out/bootstrap")
# Data-blob layer listed BEFORE the annotated bootstrap layer (the realistic,
# selection-stressing ordering).
cat > "$ROOT/artifact.json" <<MAN
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.oci.image.layer.nydus.blob.v1",
"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:$CFG_SHA","size":$CFG_LEN},
"layers":[
{"mediaType":"application/vnd.oci.image.layer.nydus.blob.v1","digest":"sha256:$DATA_SHA","size":$DATA_LEN},
{"mediaType":"application/vnd.oci.image.bootstrap.nydus.v1","digest":"sha256:$BOOT_SHA","size":$BOOT_LEN,"annotations":{"containerd.io/snapshot/nydus-bootstrap":"true"}}
]}
MAN
ART_SHA=$(sha256sum "$ROOT/artifact.json"|awk '{print $1}')
$C -o /dev/null -X PUT -H "Content-Type: application/vnd.oci.image.manifest.v1+json" --data-binary @"$ROOT/artifact.json" "$SCHEME://$REG/v2/$REPO/manifests/sha256:$ART_SHA"
echo "  data=$DATA_SHA bootstrap=$BOOT_SHA artifact-manifest=$ART_SHA"

step "mount via nydusd REGISTRY backend (serves data blobs from /v2/$REPO/blobs/<id>)"
cp "$ROOT/out/bootstrap" "$ROOT/stage/bootstrap"
cat > "$ROOT/config.toml.json" <<CFG
{ "blobs": [ {
  "type": "bootstrap", "id": "bootstrap1", "domain_id": "d1",
  "config": {
    "id": "factory1",
    "backend_type": "registry",
    "backend_config": { "scheme": "$SCHEME", "host": "$REG", "repo": "$REPO", "skip_verify": $SKIP_VERIFY },
    "cache_type": "fanotify",
    "cache_config": { "work_dir": "$ROOT/stage" },
    "metadata_path": "$ROOT/stage/bootstrap"
  } } ] }
CFG
"$ND" singleton --config "$ROOT/config.toml.json" \
  --fanotify "$ROOT/stage" --fanotify-mountpoint "$ROOT/mnt" --fanotify-threads 2 \
  --log-level info > "$ROOT/nydusd.log" 2>&1 &
sleep 4
mount | grep -iq erofs || { tail -15 "$ROOT/nydusd.log"; fail "EROFS not mounted"; }

step "read back + verify against source"
rc=0
for f in hello.txt random.bin sub/small.txt; do
  s=$(sha256sum "$ROOT/src/$f" | awk '{print $1}')
  m=$(sha256sum "$ROOT/mnt/$f" 2>/dev/null | awk '{print $1}')
  [ "$s" = "$m" ] && echo "  OK  $f" || { echo "  MISMATCH $f: src=$s mnt=$m"; rc=1; }
done
umount "$ROOT/mnt" 2>/dev/null; pkill -f "nydusd singleton" 2>/dev/null
[ $rc -eq 0 ] && echo "==== B4b REFERRER SERVING: PASS ====" || fail "content mismatch"
