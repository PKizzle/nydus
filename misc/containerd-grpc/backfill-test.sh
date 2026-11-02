#!/usr/bin/env bash
# Runs the layer-backfill integration test (containerd_transfer::tests, ignored) against a
# private containerd >= 2.0 (Transfer service) and a local registry that requires basic auth.
# It first reproduces the state backfill exists for: an image whose layer snapshots exist but
# whose layer blobs containerd skipped on pull. Needs Docker and network access (containerd
# release download, one alpine pull from Docker Hub); the container is privileged because
# unpacking layers into snapshots mounts them.
set -euo pipefail
cd "$(dirname "$0")/../.."
CONTAINERD_VERSION="${CONTAINERD_VERSION:-2.2.2}"
docker run --rm --privileged -e CONTAINERD_VERSION="$CONTAINERD_VERSION" -v "$PWD":/work \
  -v nydus-cargo-registry:/usr/local/cargo/registry \
  -v "${NYDUS_TARGET_VOLUME:-nydus-target-containerd-grpc}":/work/target -w /work \
  rust:1.96-bookworm bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null
  apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler docker-registry \
    apache2-utils curl >/dev/null 2>&1
  arch=$(dpkg --print-architecture)
  curl -fsSL "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-${arch}.tar.gz" \
    | tar -xz -C /usr/local
  containerd --version

  bf=/tmp/backfill
  mkdir -p "$bf/hosts/localhost:5000" "$bf/registry"
  htpasswd -Bbn backfill s3cret > "$bf/htpasswd"
  cat > "$bf/registry.yml" <<YML
version: 0.1
storage:
  filesystem:
    rootdirectory: $bf/registry
http:
  addr: 127.0.0.1:5000
auth:
  htpasswd:
    realm: backfill
    path: $bf/htpasswd
YML
  cat > "$bf/hosts/localhost:5000/hosts.toml" <<TOML
server = "http://localhost:5000"
[host."http://localhost:5000"]
  capabilities = ["pull", "resolve", "push"]
TOML
  # The Transfer service unpacks only for snapshotters listed here (default: overlayfs, which
  # cannot stack on the overlay root of this container).
  cat > "$bf/containerd.toml" <<TOML
version = 3
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux/$arch"
  snapshotter = "native"
TOML
  docker-registry serve "$bf/registry.yml" >"$bf/registry.log" 2>&1 &
  containerd --root "$bf/root" --state "$bf/state" --address "$bf/containerd.sock" \
    --config "$bf/containerd.toml" >"$bf/containerd.log" 2>&1 &
  for _ in $(seq 50); do [ -S "$bf/containerd.sock" ] && break; sleep 0.2; done

  ctr() { command ctr -a "$bf/containerd.sock" -n backfill "$@"; }
  image=localhost:5000/test/alpine:3.20
  creds=backfill:s3cret
  # Seed the registry with every platform, so a later host-platform pull resolves.
  ctr images pull --local --all-platforms --snapshotter native docker.io/library/alpine:3.20 >/dev/null
  ctr images tag docker.io/library/alpine:3.20 "$image" >/dev/null
  ctr images push --plain-http -u "$creds" "$image" >/dev/null
  ctr images rm --sync docker.io/library/alpine:3.20 "$image" >/dev/null

  # Pull, pin the layer snapshots with a container, delete the image (its blobs are collected,
  # the snapshots stay), and pull again: containerd skips the layer fetch. Only an unpacking
  # pull (CRI, or ctr through the Transfer service) skips; `ctr pull --local` fetches first.
  pull=(images pull --platform "linux/$arch" --plain-http -u "$creds" --snapshotter native)
  ctr "${pull[@]}" "$image" >/dev/null
  ctr containers create --snapshotter native "$image" holder >/dev/null
  ctr images rm --sync "$image" >/dev/null
  ctr "${pull[@]}" "$image" >/dev/null

  BACKFILL_CONTAINERD_ADDRESS="$bf/containerd.sock" BACKFILL_CONTAINERD_NAMESPACE=backfill \
  BACKFILL_CONTENT_ROOT="$bf/root/io.containerd.content.v1.content" \
  BACKFILL_HOSTS_DIR="$bf/hosts" BACKFILL_IMAGE="$image" BACKFILL_REGISTRY=localhost:5000 \
  BACKFILL_AUTH=$(printf %s "$creds" | base64) \
    cargo test -j2 -p nydus-snapshotter --lib containerd_transfer::tests::backfill_restores -- \
      --ignored --nocapture | tee /tmp/backfill-test.log
  # A filter or #[ignore] change that leaves nothing to run must not pass.
  grep -q "test result: ok\. [1-9][0-9]* passed" /tmp/backfill-test.log'
