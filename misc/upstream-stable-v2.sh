#!/bin/bash
# Print the newest stable v2.x release tag of upstream dragonflyoss/nydus.
#
# The compatibility and performance tests download upstream's released static
# binaries to check that images built by them still work with ours and the
# reverse. Those binaries must come from the v2 line: upstream's v3 is a
# separate, format-incompatible rewrite (no RAFS, no v5), so the moment one of
# its releases became "latest" a plain `releases/latest` lookup would hand the
# tests binaries that cannot read or write our images at all.
#
# Reads GITHUB_TOKEN when set, to stay clear of the anonymous API rate limit.
set -euo pipefail

auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

tag=$(curl -sSf ${auth[@]+"${auth[@]}"} "https://api.github.com/repos/dragonflyoss/nydus/releases?per_page=100" |
    jq -r '.[] | select(.draft == false and .prerelease == false) | .tag_name' |
    grep -E '^v2\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1) || true

if [ -z "${tag}" ]; then
    echo "could not resolve the upstream stable v2 release tag (rate limited?)" >&2
    exit 1
fi
echo "${tag}"
