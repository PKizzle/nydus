#!/usr/bin/env bash
# Runs the ContentStoreClient integration test (snapshotter/tests/containerd_client.rs) against a
# containerd the test starts itself. Needs Docker; the test runs as root inside the container so
# containerd can start.
set -euo pipefail
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/work -v nydus-cargo-registry:/usr/local/cargo/registry \
  -v "${NYDUS_TARGET_VOLUME:-nydus-target-containerd-grpc}":/work/target -w /work rust:1.96-bookworm bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null
  apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler containerd >/dev/null 2>&1
  containerd --version
  cargo test -j2 -p nydus-snapshotter --test containerd_client -- --ignored --nocapture'
