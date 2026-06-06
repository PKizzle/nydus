#!/usr/bin/env bash
# End-to-end test for the node-local auto-accel pipeline.
#
# Drives a deployed nydus-snapshotter through one full loop:
#   1. Verify the snapshotter is up + auto-zran is enabled in its config.
#   2. Pull a standard OCI image (no nydus tag suffix).
#   3. Start a pod from it via crictl.
#   4. Wait for the access tracer to settle and the conversion to land in
#      containerd's content store, asserting the expected labels.
#   5. Delete the pod + verify the sidecar artifact survives (per the
#      `containerd.io/gc.ref.content.subject` label keeping it alive).
#
# Requires root on a Linux ≥ 6.14 node where the snapshotter is configured
# with `auto_zran.enable = true`. Intended to run on one of the Pis.
#
# Usage: sudo bash misc/fanotify/auto-accel-end-to-end.sh [image]
#
# Defaults:
#   image    : docker.io/library/nginx:1.27
#   namespace: k8s.io
#   timeout  : 180 seconds for conversion (4 layers + nydus-image fork +
#              optimize step takes ~20s on a Pi 4; bumped for safety)

set -euo pipefail

IMAGE="${1:-docker.io/library/nginx:1.27}"
NAMESPACE="${NAMESPACE:-k8s.io}"
TIMEOUT_SEC="${TIMEOUT_SEC:-180}"
CTR="${CTR:-k3s ctr}"
CRICTL="${CRICTL:-crictl}"
SNAPSHOTTER_API_SOCK="${SNAPSHOTTER_API_SOCK:-/run/containerd-nydus/containerd-nydus-api.sock}"

LABEL_SUBJECT="containerd.io/gc.ref.content.subject"
LABEL_ROLE="containerd.io/snapshot/nydus.auto-accel.role"
LABEL_LAYER="containerd.io/snapshot/nydus.auto-accel.layer-digest"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m→\033[0m %s\n' "$*"; }

bold "=== Auto-accel end-to-end test ==="
info "Image: $IMAGE"
info "Namespace: $NAMESPACE"
info "Timeout: ${TIMEOUT_SEC}s"
echo

# ── Preflight ────────────────────────────────────────────────────────────────
bold "Preflight"
[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -S "$SNAPSHOTTER_API_SOCK" ]] || \
    fail "snapshotter API socket missing at $SNAPSHOTTER_API_SOCK"
systemctl is-active --quiet nydus-snapshotter || \
    fail "nydus-snapshotter service is not active"
ok "snapshotter service active"

KERNEL="$(uname -r | awk -F. '{print $1"."$2}')"
awk -v kv="$KERNEL" 'BEGIN { split(kv, p, "."); if (p[1] < 6 || (p[1] == 6 && p[2] < 14)) exit 1 }' \
    || fail "kernel $KERNEL too old (need ≥ 6.14 for fanotify pre-content + FAN_CLASS_NOTIF capture)"
ok "kernel $(uname -r) ≥ 6.14"

# Verify auto_zran is enabled in the live config. We don't parse TOML here —
# just grep the file. (Config path resolution lives in the systemd unit.)
SNAPSHOTTER_CONFIG="$(systemctl cat nydus-snapshotter | awk '/--config/ {print $2; exit}')"
SNAPSHOTTER_CONFIG="${SNAPSHOTTER_CONFIG:-/etc/nydus/snapshotter-config.toml}"
if [[ -r "$SNAPSHOTTER_CONFIG" ]]; then
    grep -qE '^\s*enable\s*=\s*true' "$SNAPSHOTTER_CONFIG" \
        && grep -q 'auto_zran' "$SNAPSHOTTER_CONFIG" \
        && ok "auto_zran block present in $SNAPSHOTTER_CONFIG" \
        || info "WARN: couldn't verify auto_zran.enable=true in $SNAPSHOTTER_CONFIG"
fi
echo

# ── Pull image ───────────────────────────────────────────────────────────────
bold "Pull image (CRI path; bypasses Transfer-API quirks)"
$CRICTL pull "$IMAGE" >/dev/null
ok "pulled $IMAGE"
MANIFEST_DIGEST="$($CTR -n "$NAMESPACE" images ls -q | grep -F "$IMAGE@sha256:" | head -1 | sed 's/.*@//')"
[[ -n "$MANIFEST_DIGEST" ]] || \
    MANIFEST_DIGEST="$($CTR -n "$NAMESPACE" image ls 2>/dev/null \
        | awk -v img="$IMAGE" '$1 == img { print $3; exit }')"
[[ -n "$MANIFEST_DIGEST" ]] || fail "could not resolve manifest digest for $IMAGE"
info "Image manifest digest: $MANIFEST_DIGEST"
echo

# ── Start a pod ──────────────────────────────────────────────────────────────
bold "Run pod"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/pod.json" <<EOF
{
    "metadata": { "name": "nydus-auto-accel-smoke", "namespace": "default", "uid": "auto-accel-$(date +%s)", "attempt": 0 },
    "linux": {},
    "log_directory": "$WORK"
}
EOF
cat > "$WORK/container.json" <<EOF
{
    "metadata": { "name": "main", "attempt": 0 },
    "image":   { "image": "$IMAGE" },
    "command": [ "sleep", "120" ],
    "linux":   {},
    "log_path": "main.log"
}
EOF
POD_ID="$($CRICTL runp "$WORK/pod.json")"
ok "pod sandbox $POD_ID"
CTR_ID="$($CRICTL create "$POD_ID" "$WORK/container.json" "$WORK/pod.json")"
$CRICTL start "$CTR_ID" >/dev/null
ok "container $CTR_ID started"
echo

# ── Wait for sidecar to land in the content store ────────────────────────────
bold "Wait for auto-accel sidecar (timeout ${TIMEOUT_SEC}s)"
deadline=$(( $(date +%s) + TIMEOUT_SEC ))
SIDECAR_FOUND=0
while [[ $(date +%s) -lt $deadline ]]; do
    # Look for any content blob with our auto-accel subject label pointing
    # at this image's manifest digest. `ctr content ls` shows labels in
    # the "LABELS" column for each entry.
    if $CTR -n "$NAMESPACE" content ls 2>/dev/null \
        | grep -F "$LABEL_SUBJECT=$MANIFEST_DIGEST" \
        | grep -q "$LABEL_ROLE=manifest"; then
        SIDECAR_FOUND=1
        break
    fi
    sleep 5
done
(( SIDECAR_FOUND == 1 )) || fail "no auto-accel manifest landed within ${TIMEOUT_SEC}s"
ok "auto-accel sidecar manifest present in content store"

# ── Assert all 4 artifact roles ──────────────────────────────────────────────
bold "Verify all artifact roles"
for role in bootstrap index manifest; do
    n=$($CTR -n "$NAMESPACE" content ls 2>/dev/null \
        | grep -F "$LABEL_SUBJECT=$MANIFEST_DIGEST" \
        | grep -c "$LABEL_ROLE=$role" || true)
    if [[ "$role" == "index" ]]; then
        (( n >= 1 )) || fail "expected ≥1 index blob, found $n"
    else
        (( n == 1 )) || fail "expected exactly 1 $role blob, found $n"
    fi
    ok "$role: $n blob(s) with subject=$MANIFEST_DIGEST"
done
# prefetch-blob is optional (present iff prefetch_files was non-empty at convert time)
n_prefetch=$($CTR -n "$NAMESPACE" content ls 2>/dev/null \
    | grep -F "$LABEL_SUBJECT=$MANIFEST_DIGEST" \
    | grep -c "$LABEL_ROLE=prefetch-blob" || true)
ok "prefetch-blob: $n_prefetch (0 = no prefetch files captured, ≥1 = optimize ran)"

# ── Survives pod removal ─────────────────────────────────────────────────────
bold "Cleanup pod, verify sidecar persists"
$CRICTL stop "$CTR_ID" >/dev/null || true
$CRICTL rm "$CTR_ID" >/dev/null || true
$CRICTL stopp "$POD_ID" >/dev/null || true
$CRICTL rmp "$POD_ID" >/dev/null || true
sleep 2
$CTR -n "$NAMESPACE" content ls 2>/dev/null \
    | grep -F "$LABEL_SUBJECT=$MANIFEST_DIGEST" \
    | grep -q "$LABEL_ROLE=manifest" \
    || fail "sidecar manifest disappeared after pod cleanup (gc.ref.content.subject not honored?)"
ok "sidecar survives pod cleanup"
echo
bold "All checks passed ✓"
