# Fork image + Helm chart release for nydus

**Date:** 2026-06-02
**Status:** Approved

## Goal

Port the release automation pattern from `dynamic-prefix-operator` (DPO) to this
nydus fork (`PKizzle/nydus`): build and publish a multi-arch container image and
release the Helm chart on every GitHub Release. Adapt references to the fork
without breaking existing functional CI.

## Source pattern (DPO)

- `docker.yaml`: per-arch build → multi-arch manifest on `ghcr.io`.
- `release.yaml` (on `v*` tag): render chart version, package chart, push to OCI,
  attach `.tgz` to the GitHub Release, publish a classic Helm repo via GitHub Pages.

## Decisions

- **Two new workflow files**, both triggered on `release: [published]` (+ `workflow_dispatch`).
  The existing `release.yml` already creates the GitHub Release on tag push; the new
  workflows fire afterwards and augment that same release.
- **Image name:** `ghcr.io/pkizzle/nydus` (the multi-arch manifest). The Helm chart's
  `image.repository` default is set to the same value.
- **No nydusify step.** Converting the snapshotter image to a nydus image is circular
  and out of scope.
- **Chart version:** rendered from `Chart.template.yaml` at release time (DPO approach), setting
  `version`/`appVersion` to the release tag (with leading `v`; helm strips it). The image tag is
  not pinned in `values.yaml` — the chart's image helper falls back to `.Chart.AppVersion`, which
  now equals the release tag and matches the image published by `docker.yml`. Prerelease detected
  by a hyphen in the tag (DPO parity) and surfaced via the `artifacthub.io/prerelease` annotation.
- **No CHANGELOG dependency.** nydus has no `CHANGELOG.md`; rely on the auto-generated
  release notes produced by the existing `release.yml`.
- **Minimal fork rewrites.** Only what the new image+chart release needs to target the
  fork. Existing `smoke.yml`, `e2e-dragonfly.yml`, `convert.yml`, and the `release.yml`
  npmmirror note and `ghcr.io/dragonflyoss/image-service/...` test-image pulls are left
  untouched.

## Components

### `.github/workflows/docker.yml` — "Build and Push Snapshotter Image"
- Trigger: `release: [published]`, `workflow_dispatch`.
- `build` job: per-arch on a **native runner** (amd64 → `ubuntu-latest`, arm64 →
  `ubuntu-24.04-arm`) — no QEMU. Mirrors `musl-static.yml`: install musl-tools + protoc, add the
  musl target, then `cargo build --release --target <musl> -p nydus-snapshotter --bin
  containerd-nydus` and `--bin nydus-image` (fully-static, pure-Rust crypto — no `cross`, no
  OpenSSL). The static binaries are staged into `dist/` and built into a runtime-only image
  ([deploy/docker/Dockerfile.release](../../../deploy/docker/Dockerfile.release), `context: dist`,
  just `COPY` + runtime tools) on the same native runner. Per-arch suffix tags + digest export.
- `manifest` job: assemble multi-arch manifest → `ghcr.io/pkizzle/nydus:<version>`,
  `:vMAJOR.MINOR`, `:vMAJOR` from `docker/metadata-action` semver off the release tag.
- `deploy/docker/Dockerfile` (compile-from-source) is kept for local/manual builds; CI uses the
  prebuilt `Dockerfile.release`.

### `.github/workflows/helm-release.yml` — "Release Helm Chart"
- Trigger: `release: [published]`, `workflow_dispatch`.
- `release` job: setup-helm → prerelease detection → render `Chart.yaml` from
  `Chart.template.yaml` → `helm lint` → `helm package` →
  `helm push` to `oci://ghcr.io/pkizzle/nydus/helm` → `gh release upload <tag> *.tgz --clobber`
  → build GitHub Pages Helm repo index (release download URLs, backfilled from all releases)
  → upload Pages artifact.
- `deploy-pages` job: `actions/deploy-pages` → `https://pkizzle.github.io/nydus`.

### Chart fork-targeting edits
- `deploy/helm/nydus-snapshotter/values.yaml`: `image.repository` → `ghcr.io/pkizzle/nydus`.
- `deploy/helm/nydus-snapshotter/Chart.yaml`: `home`/`sources` → `https://github.com/PKizzle/nydus`.

### `artifacthub-repo.yml`
- Added with a placeholder `repositoryID` (`REPLACE_WITH_ARTIFACT_HUB_REPOSITORY_ID`) that the
  user updates after registering on Artifact Hub. The Pages step copies it only if present.

## Manual follow-ups
- GitHub Pages: already configured for GitHub Actions (confirmed by user).
- Register the repo on Artifact Hub and replace the placeholder `repositoryID`.
- Tag the fork as `v3.x` so the chart `appVersion` (currently `3.0.0`) stays meaningful.
