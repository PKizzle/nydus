#!/bin/bash
# End-to-end correctness gate for the containerd -> gRPC -> containerd-nydus
# mount loop. Assumes `misc/prepare.sh` has run: containerd with the nydus
# proxy plugin registered, the Rust snapshotter as a systemd service
# (config: misc/performance/snapshotter_config.toml — fusedev pinned, sysctl
# socket /run/containerd-nydus/system.sock, plain-http registry backend), and
# nerdctl 1.7.x + CNI installed.
#
# Covered here:
#   1. proxy-plugin dial + Stat/List           (ctr snapshot ls)
#   2. readiness probe                         (containerd-nydus healthcheck --ready)
#   3. plain-OCI image: Prepare -> Commit -> Mounts -> runc, no nydus daemon
#   4. nydus image (fusedev): lazy mount through the in-process daemon
#   5. teardown: image removal leaves no active snapshots, service stays up
#
# Out of scope (kernel >= 6.14 required, so lima or the k3s canary, not GH
# runners): the fanotify/EROFS on-demand path and node-local auto-accel —
# see misc/fanotify/*.sh. Spegel/P2P is cluster-only.

set -euxo pipefail

readonly REGISTRY_PORT=5077
readonly FIXTURE_SRC=alpine:3.20
readonly FIXTURE=localhost:${REGISTRY_PORT}/alpine:3.20
readonly FIXTURE_NYDUS=localhost:${REGISTRY_PORT}/alpine:nydus-e2e
readonly SYSCTL_SOCKET=/run/containerd-nydus/system.sock
readonly WORK_DIR=$(mktemp -d /tmp/snapshotter-e2e.XXXXXX)

CTR="ctr --address /run/containerd/containerd.sock"
NERDCTL="nerdctl --snapshotter nydus --insecure-registry"

cleanup() {
    $NERDCTL rmi -f "$FIXTURE" "$FIXTURE_NYDUS" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# --- 1. containerd reaches the snapshotter over the proxy-plugin socket ----
timeout 30 $CTR snapshot --snapshotter nydus ls

# --- 2. the snapshotter reports ready over the sysctl API ------------------
timeout 10 /usr/local/bin/containerd-nydus healthcheck --socket "$SYSCTL_SOCKET"
timeout 10 /usr/local/bin/containerd-nydus healthcheck --ready --socket "$SYSCTL_SOCKET"

# --- fixture registry + image ----------------------------------------------
# docker treats localhost registries as insecure out of the box, so it stages
# the fixture; everything after this line exercises the nydus stack instead.
docker ps --format '{{.Names}}' | grep -q '^e2e-registry$' || \
    docker run -d --name e2e-registry -p ${REGISTRY_PORT}:5000 registry:2
timeout 60 sh -c "until curl -sf http://localhost:${REGISTRY_PORT}/v2/; do sleep 1; done"
docker pull "$FIXTURE_SRC"
docker tag "$FIXTURE_SRC" "$FIXTURE"
docker push "$FIXTURE"

# --- 3. plain-OCI path: Prepare/Commit/Mounts loop without any daemon ------
output=$(timeout 300 $NERDCTL run --rm --net=none "$FIXTURE" sh -c 'echo E2E_OK && cat /etc/alpine-release')
echo "$output" | grep -q "E2E_OK"
echo "$output" | grep -q "^3\.20"

# --- 4. nydus image over the in-process fusedev daemon ---------------------
timeout 300 nydusify convert \
    --source "$FIXTURE" \
    --target "$FIXTURE_NYDUS" \
    --plain-http \
    --nydus-image /usr/local/bin/nydus-image \
    --work-dir "$WORK_DIR"
output=$(timeout 300 $NERDCTL run --rm --net=none "$FIXTURE_NYDUS" cat /etc/alpine-release)
echo "$output" | grep -q "^3\.20"

# The nydus image must have gone through a daemon mount, not the plain
# overlay path: the supervisor's records list it.
curl -sf --unix-socket "$SYSCTL_SOCKET" http://localhost/api/v1/daemons/records | grep -q "alpine"

# --- 5. teardown leaves no residue ------------------------------------------
$NERDCTL rmi -f "$FIXTURE" "$FIXTURE_NYDUS"
if $CTR snapshot --snapshotter nydus ls | grep -w Active; then
    echo "leaked active snapshots after image removal" >&2
    exit 1
fi
systemctl is-active nydus-snapshotter

echo "snapshotter-e2e: all checks passed"
