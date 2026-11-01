#!/usr/bin/env bash
# Referrer trust end-to-end: start a plain-HTTP registry, then run
# snapshotter/tests/referrer_trust_e2e.rs, which pushes a subject image, a
# nydus referrer (fallback tag) and a cosign-layout signature itself and checks
# that only a signed, subject-bound, blob-bound referrer is served.
#
# Needs `docker-registry` (Debian package; distribution registry:2) and a
# nydus-image binary. No root, no kernel requirement.
#   NYDUS_IMAGE=./target/release/nydus-image misc/referrer/trust-e2e.sh
set -euo pipefail
NI="${NYDUS_IMAGE:-$(command -v nydus-image || echo ./target/release/nydus-image)}"
PORT="${PORT:-5055}"
work=$(mktemp -d)
trap 'kill "$reg" 2>/dev/null; rm -rf "$work"' EXIT

cat > "$work/registry.yml" <<YML
version: 0.1
storage:
  filesystem:
    rootdirectory: $work/data
http:
  addr: 127.0.0.1:$PORT
YML
docker-registry serve "$work/registry.yml" >"$work/registry.log" 2>&1 &
reg=$!
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$PORT/v2/" >/dev/null && break; sleep 0.2; done

REFERRER_E2E_REGISTRY="127.0.0.1:$PORT" NYDUS_IMAGE="$(realpath "$NI")" \
  cargo test -p nydus-snapshotter --test referrer_trust_e2e -- --nocapture 2>&1 | tee "$work/test.log"
grep -q REFERRER-TRUST-E2E-PASS "$work/test.log"
