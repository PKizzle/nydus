#!/usr/bin/env bash
# The chart's hostSystemd installer (deploy/helm/nydus-snapshotter/files/host-systemd.sh) against
# a real systemd: a privileged container runs systemd as PID 1 and plays the node. The installer
# runs inside it exactly as in the DaemonSet pod (nsenter into PID 1), with the unit, config and
# script rendered by `helm template` and the binaries taken from a snapshotter image.
#
#   H1  install: the unit is enabled and active, the files are in place
#   H2  a second install with nothing changed does not restart the unit (same InvocationID)
#   H3  a changed config restarts it, and a changed binary is swapped by rename (new inode)
#   H4  a restart marker left by an interrupted run restarts the unit on the next run
#   H5  a binary that does not run on the host is never swapped in
#   H6  the snapshotter runs with FDSTORE set; a build whose driver probe checks the fd store
#       (snapshotter/src/probe/mod.rs) reports it present
#   H7  the pod probes and `run` (journal follow) work against the host unit
#   H8  uninstall leaves no unit, files or process; a unit the chart did not install is left alone
#
# Requirements: docker (privileged containers, cgroup v2 host), helm, yq (mikefarah).
#   IMAGE=ghcr.io/pkizzle/nydus:v3.6.0 misc/helm/host-systemd-test.sh
# SNAPSHOTTER_BIN=<linux containerd-nydus> replaces the image's snapshotter binary, e.g. a local build.
set -euo pipefail

IMAGE=${IMAGE:-ghcr.io/pkizzle/nydus:v3.6.0}
CHART=${CHART:-$(cd "$(dirname "$0")/../.." && pwd)/deploy/helm/nydus-snapshotter}
NODE_IMAGE=nydus-host-systemd-node:test
NAME=nydus-host-systemd-$$
WORK=$(mktemp -d)
UNIT=nydus-snapshotter.service

FAILURES=0
step() { echo; echo "### $* ###"; }
pass() { echo "  ok: $*"; }
fail() { echo "  !! FAIL: $*"; FAILURES=$((FAILURES + 1)); }
lacks() { ! grep -q "$1" <<< "$2"; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

node() { docker exec "$NAME" "$@"; }
installer() {
  docker exec -e SRC_BIN_DIR=/src/bin -e SRC_CONFIG=/src/config.toml \
    -e SRC_UNIT=/src/$UNIT "$NAME" sh /src/host-systemd.sh "$@"
}
invocation() { node systemctl show -p InvocationID --value $UNIT; }

cleanup() {
  docker rm -f "$NAME" > /dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step "render the chart (deploymentMode=hostSystemd)"
helm template t "$CHART" --set deploymentMode=hostSystemd \
  --set config.profile=containerd --set config.peerMirror.preset=none > "$WORK/chart.yaml"
cm() { yq ea "select(.kind == \"ConfigMap\" and .metadata.name == \"$1\") | .data[\"$2\"]" "$WORK/chart.yaml"; }
cm t-nydus-snapshotter-host-systemd host-systemd.sh > "$WORK/host-systemd.sh"
cm t-nydus-snapshotter-host-systemd $UNIT > "$WORK/$UNIT"
cm t-nydus-snapshotter-config config.toml > "$WORK/config.toml"
for f in host-systemd.sh $UNIT config.toml; do [ -s "$WORK/$f" ] || { echo "empty $f"; exit 1; }; done

step "start a systemd node"
docker build -q -t $NODE_IMAGE - > /dev/null << 'EOF'
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends systemd util-linux e2fsprogs \
 && rm -rf /var/lib/apt/lists/* && systemctl mask getty.target systemd-logind.service
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
docker run -d --name "$NAME" --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock $NODE_IMAGE > /dev/null
for _ in $(seq 60); do
  state=$(node systemctl is-system-running 2> /dev/null || true)
  case $state in running | degraded) break ;; esac
  sleep 1
done
echo "  systemd: $state, $(node systemctl --version | head -1)"
# The snapshotter root on ext4, which supports fanotify pre-content marks (overlayfs does not).
node sh -c 'truncate -s 1G /var/tmp/root.img && mkfs.ext4 -q /var/tmp/root.img &&
  mkdir -p /var/lib/containerd-nydus && mount -o loop /var/tmp/root.img /var/lib/containerd-nydus'
node mkdir -p /src/bin
for f in host-systemd.sh $UNIT config.toml; do docker cp "$WORK/$f" "$NAME:/src/$f"; done
cid=$(docker create "$IMAGE")
for b in containerd-nydus nydus-image; do docker cp "$cid:/usr/local/bin/$b" "$WORK/$b"; docker cp "$WORK/$b" "$NAME:/src/bin/$b"; done
docker rm "$cid" > /dev/null
if [ -n "${SNAPSHOTTER_BIN:-}" ]; then docker cp "$SNAPSHOTTER_BIN" "$NAME:/src/bin/containerd-nydus"; fi

step "H1 install"
installer install
check "unit active" test "$(node systemctl is-active $UNIT)" = active
check "unit enabled" test "$(node systemctl is-enabled $UNIT)" = enabled
for f in /usr/local/bin/containerd-nydus /usr/local/bin/nydus-image /etc/nydus/config.toml /etc/systemd/system/$UNIT; do
  check "$f installed" node test -f "$f"
done
check "no restart marker left" node test ! -e /run/containerd-nydus/host-systemd.restart-required

step "H2 unchanged second run"
before=$(invocation)
out=$(installer install)
printf '    %s\n' "$out"
check "InvocationID unchanged" test "$(invocation)" = "$before"
check "reported unchanged" grep -q "files unchanged" <<< "$out"

step "H3 changed config restarts, binary swapped by rename"
before=$(invocation)
node sh -c 'echo "# changed" >> /src/config.toml'
installer install > /dev/null
check "InvocationID changed after config change" test "$(invocation)" != "$before"
check "unit active after restart" test "$(node systemctl is-active $UNIT)" = active
before=$(invocation)
inode=$(node stat -c %i /usr/local/bin/nydus-image)
node sh -c 'printf "\n" >> /src/bin/nydus-image'
installer install > /dev/null
check "InvocationID changed after binary change" test "$(invocation)" != "$before"
check "binary replaced by rename (new inode)" test "$(node stat -c %i /usr/local/bin/nydus-image)" != "$inode"
check "host binary matches source" node cmp -s /src/bin/nydus-image /usr/local/bin/nydus-image

step "H4 restart marker from an interrupted run"
before=$(invocation)
node touch /run/containerd-nydus/host-systemd.restart-required
installer install > /dev/null
check "InvocationID changed" test "$(invocation)" != "$before"
check "marker removed" node test ! -e /run/containerd-nydus/host-systemd.restart-required

step "H5 a binary that does not run is not swapped in"
before=$(invocation)
node cp /src/bin/nydus-image /src/nydus-image.good
node sh -c 'printf "not an executable\n" > /src/bin/nydus-image'
if installer install > /dev/null 2>&1; then fail "install with a broken binary succeeded"; else pass "install failed"; fi
check "host binary still the good one" node cmp -s /src/nydus-image.good /usr/local/bin/nydus-image
check "unit not restarted" test "$(invocation)" = "$before"
node mv /src/nydus-image.good /src/bin/nydus-image
installer install > /dev/null
check "the next good run clears the marker" node test ! -e /run/containerd-nydus/host-systemd.restart-required

step "H6 fd store"
pid=$(node systemctl show -p MainPID --value $UNIT)
check "FDSTORE=512 in the snapshotter's environment" \
  node sh -c "tr '\0' '\n' < /proc/$pid/environ | grep -qx FDSTORE=512"
check "unit FileDescriptorStoreMax=512" test "$(node systemctl show -p FileDescriptorStoreMax --value $UNIT)" = 512
check "unit FileDescriptorStorePreserve=restart" \
  test "$(node systemctl show -p FileDescriptorStorePreserve --value $UNIT)" = restart
if node grep -q "fanotify can be selected" /src/bin/containerd-nydus; then
  journal=$(node journalctl -u $UNIT --invocation=0 -o cat)
  if grep -q "fanotify .*failed\|fanotify.*unavailable" <<< "$journal" && ! grep -q "fd store" <<< "$journal"; then
    echo "  skip: fanotify failed an earlier probe on this kernel, so the fd store was not consulted"
  else
    check "driver probe reports the fd store present" grep -q "systemd fd store present" <<< "$journal"
    check "driver probe does not reject fanotify for a missing fd store" lacks "no systemd fd store" "$journal"
  fi
else
  echo "  skip: this snapshotter build does not check the fd store in its driver probe"
fi

step "H7 pod probes and journal follow"
for _ in $(seq 30); do installer probe ready > /dev/null 2>&1 && break; sleep 1; done
check "liveness probe" installer probe
check "readiness probe" installer probe ready
out=$(docker exec -e SRC_BIN_DIR=/src/bin -e SRC_CONFIG=/src/config.toml -e SRC_UNIT=/src/$UNIT \
  "$NAME" timeout 5 sh /src/host-systemd.sh run 2>&1 || true)
check "run shows the unit's journal" grep -q "driver probe result" <<< "$out"
node systemctl stop $UNIT
if installer probe > /dev/null 2>&1; then fail "liveness passed with the unit stopped"; else pass "liveness fails with the unit stopped"; fi
installer install > /dev/null
check "install starts a stopped unit" test "$(node systemctl is-active $UNIT)" = active

step "H8 uninstall"
pid=$(node systemctl show -p MainPID --value $UNIT)
installer uninstall
check "snapshotter process $pid gone" node test ! -e "/proc/$pid"
check "unit unknown to systemd" test "$(node systemctl show -p LoadState --value $UNIT)" = not-found
for f in /usr/local/bin/containerd-nydus /usr/local/bin/nydus-image /etc/nydus /etc/systemd/system/$UNIT \
  /etc/systemd/system/multi-user.target.wants/$UNIT; do
  check "$f removed" node test ! -e "$f"
done
check "uninstall again is a no-op" installer uninstall
node sh -c "printf '[Service]\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/$UNIT"
installer uninstall > /dev/null
check "a unit the chart did not install is left alone" node test -f /etc/systemd/system/$UNIT
if installer install > /dev/null 2>&1; then fail "install replaced a foreign unit"; else pass "install refuses a foreign unit"; fi

echo
if [ "$FAILURES" -gt 0 ]; then echo "FAILED: $FAILURES check(s)"; exit 1; fi
echo "PASSED"
