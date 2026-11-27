#!/usr/bin/env bash
# Lints and renders deploy/helm/nydus-snapshotter in both deployment modes and checks the fields
# each mode depends on. Requirements: helm, yq (mikefarah), jq.
set -euo pipefail

CHART=${CHART:-$(cd "$(dirname "$0")/../.." && pwd)/deploy/helm/nydus-snapshotter}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
pass() { echo "  ok: $*"; }
fail() { echo "  !! FAIL: $*"; FAILURES=$((FAILURES + 1)); }
# expect <description> <file> <yq expression> <expected output>
expect() {
  local got
  got=$(yq ea "$3" "$WORK/$2")
  if [ "$got" = "$4" ]; then pass "$1"; else fail "$1: got '$got', want '$4'"; fi
}
render() { local out=$1; shift; helm template t "$CHART" "$@" > "$WORK/$out"; }

DS='select(.kind == "DaemonSet")'
POD="$DS | .spec.template.spec"
CM='select(.metadata.name == "t-nydus-snapshotter-host-systemd")'
UNIT="$CM | .data[\"nydus-snapshotter.service\"]"
JOB='select(.kind == "Job")'

echo "### lint"
helm lint "$CHART"
helm lint "$CHART" --set deploymentMode=hostSystemd

echo "### pod mode (default)"
render pod.yaml
expect "snapshotter runs in the pod" pod.yaml "$POD | .containers[0].name" containerd-nydus
expect "Bidirectional mounts" pod.yaml \
  "[$POD | .containers[0].volumeMounts[] | select(.mountPropagation == \"Bidirectional\")] | length" 2
expect "init container removes a hostSystemd unit" pod.yaml \
  "$POD | .initContainers[0].command | join(\" \")" "/bin/sh /host-systemd/host-systemd.sh uninstall"
expect "no uninstall hook" pod.yaml '[select(.metadata.annotations["helm.sh/hook"] == "pre-delete")] | length' 0
render pod-nohostpid.yaml --set daemonset.hostPID=false
expect "hostPID=false: no init container" pod-nohostpid.yaml "$POD | .initContainers | length" 0
expect "hostPID=false: no host-systemd ConfigMap" pod-nohostpid.yaml "[$CM] | length" 0

echo "### hostSystemd mode"
render host.yaml --set deploymentMode=hostSystemd --set daemonset.hostPID=false \
  --set 'daemonset.env[0].name=RUST_LOG' --set 'daemonset.env[0].value=debug' \
  --set-string 'hostSystemd.serviceExtra=MemoryMax=2G' --set containerd.install.enable=true
expect "installer container" host.yaml "$POD | .containers[0].name" host-systemd
expect "installer command" host.yaml "$POD | .containers[0].command | join(\" \")" \
  "/bin/sh /host-systemd/host-systemd.sh run"
expect "hostPID forced on" host.yaml "$POD | .hostPID" true
expect "no Bidirectional mounts" host.yaml \
  "[$POD | .. | select(tag == \"!!map\" and has(\"mountPropagation\"))] | length" 0
expect "only the containerd-config init container" host.yaml \
  "$POD | [.initContainers[].name] | join(\",\")" containerd-config-installer
expect "readiness probes the host unit" host.yaml \
  "$POD | .containers[0].readinessProbe.exec.command | join(\" \")" "/bin/sh /host-systemd/host-systemd.sh probe ready"
expect "rolls on unit changes" host.yaml \
  "$DS | .spec.template.metadata.annotations | has(\"checksum/host-systemd\")" true
for line in Type=notify FileDescriptorStoreMax=512 FileDescriptorStorePreserve=restart Restart=always \
  KillMode=process 'Environment=\"RUST_LOG=debug\"' MemoryMax=2G \
  'ExecStart=/usr/local/bin/containerd-nydus --config /etc/nydus/config.toml --log-level=info'; do
  expect "unit has $line" host.yaml "$UNIT | split(\"\\n\") | any_c(. == \"$line\")" true
done
expect "unit ordered before containerd" host.yaml "$UNIT | test(\"(?m)^Before=containerd.service \")" true
if [ "$(yq ea "$CM | .data[\"host-systemd.sh\"]" "$WORK/host.yaml")" = "$(cat "$CHART/files/host-systemd.sh")" ]; then
  pass "script shipped verbatim"
else
  fail "script differs"
fi
tag=$(sed -n "s/^OWNER_TAG='\(.*\)'$/\1/p" "$CHART/files/host-systemd.sh")
if [ -n "$tag" ] && yq ea "$UNIT" "$WORK/host.yaml" | grep -qxF "$tag"; then
  pass "unit carries the script's OWNER_TAG"
else
  fail "unit lacks the script's OWNER_TAG"
fi
if diff <(yq ea 'select(.metadata.name == "t-nydus-snapshotter-config") | .data' "$WORK/pod.yaml") \
  <(yq ea 'select(.metadata.name == "t-nydus-snapshotter-config") | .data' "$WORK/host.yaml") > /dev/null; then
  pass "same snapshotter config in both modes"
else
  fail "snapshotter config differs between modes"
fi

echo "### hostSystemd uninstall hook"
expect "pre-delete hook" host.yaml "$JOB | .metadata.annotations[\"helm.sh/hook\"]" pre-delete
expect "Job pods do not match the DaemonSet selector" host.yaml \
  "$JOB | .spec.template.metadata.labels[\"app.kubernetes.io/name\"]" t-nydus-snapshotter-uninstall
expect "waits for the rollout" host.yaml "$JOB | .spec.template.spec.containers[0].args | join(\" \")" \
  "rollout status daemonset/t-nydus-snapshotter --namespace=default --timeout=600s"
patch=$(yq ea "$JOB | .spec.template.spec.initContainers[0].args[-1]" "$WORK/host.yaml")
for q in '.spec.template.spec.containers[] | select(.name == "host-systemd") | .env[0].value' \
  '.spec.template.spec.initContainers[] | select(.name == "containerd-config-installer") | .env[0].value' \
  '.spec.updateStrategy.rollingUpdate.maxUnavailable'; do
  got=$(jq -r "$q" <<< "$patch" 2> /dev/null || true)
  case $got in uninstall | 100%) pass "patch: $q = $got" ;; *) fail "patch: $q = $got" ;; esac
done
render host-noinit.yaml --set deploymentMode=hostSystemd
expect "no remove-host-service init container in hostSystemd mode" host-noinit.yaml "$POD | .initContainers | length" 0
if jq -e '.spec.template.spec | has("initContainers")' \
  <<< "$(yq ea "$JOB | .spec.template.spec.initContainers[0].args[-1]" "$WORK/host-noinit.yaml")" > /dev/null; then
  fail "patch adds an initContainers entry without containerd.install.enable"
else
  pass "patch leaves initContainers alone without containerd.install.enable"
fi
expect "containerd installer skips the uninstall rollout" host.yaml \
  'select(.metadata.name == "t-nydus-snapshotter-installer") | .data["install.sh"] | test("HOST_SYSTEMD_ACTION:-}\" = uninstall \\] && exit 0")' true

echo
if [ "$FAILURES" -gt 0 ]; then echo "FAILED: $FAILURES check(s)"; exit 1; fi
echo "PASSED"
