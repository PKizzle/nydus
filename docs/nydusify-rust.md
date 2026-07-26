# Nydusify (Rust)

`nydusify/` is the Rust rewrite of the Nydus image conversion utility, and is now **the** nydusify:
the **registry-side push/convert tool**. The Go `nydusify` (formerly `contrib/nydusify/`) has been
removed from this repository. `nydusify` is unrelated to *transparent* node-local acceleration
(`snapshotter/src/local_accel.rs`, see [ARCHITECTURE.md](../ARCHITECTURE.md) Decision 7), which
never pushes anything to a registry.

Every subcommand — `convert`, `check`, `copy`, `mount`, `commit`, `chunkdict generate` — is a real,
working implementation built on the new `registry-client/` crate (a compio-native OCI distribution
client: bearer auth, manifest/blob GET, blob push, `HEAD`-based dedup, mount-blob). They drive
`nydus-image` (and, for `mount`, `nydusd`) as subprocesses, the same convention
`snapshotter/src/local_accel.rs` uses for node-local conversion; `commit` additionally shells out to
containerd's `ctr` to inspect the container it is snapshotting.

> **Platform:** `nydusify convert`/`check`/`copy` are pure networking + subprocess orchestration
> and build/run anywhere `nydus-image` runs (including macOS for `check`/`convert` tooling). `mount`
> spawns `nydusd` as a foreground FUSE daemon, which is part of the Linux-only runtime surface (see
> the platform note at the top of [CLAUDE.md](../CLAUDE.md)) — treat it as Linux-only in practice.

## `nydusify convert`

Two modes, selected by `--oci-ref`:

```shell
# oci-ref / zran mode: data blobs are the ORIGINAL gzip layers (mounted from the
# source repo when source == target, else re-pushed) plus tiny zran index blobs.
# This is the artifact shape the snapshotter's referrer path (B4b) consumes.
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --oci-ref

# standard mode: nydus-image builds new RAFS data blobs (no gzip reuse).
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

Close the loop with the snapshotter's referrer serving (default-on, ARCHITECTURE.md Decision 8) by
also pushing a referrer artifact attached to the *source* image:

```shell
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --oci-ref \
  --with-referrer
```

`--with-referrer` pushes an OCI 1.1 referrer artifact (`subject` = the source image manifest
descriptor captured at pull time) to the *source* repo, both by digest (native referrers-API
registries) and under the `sha256-<subject-hex>` fallback tag (registries such as Zot/older Harbor
without native support). A node running the snapshotter with `referrer_detect` enabled (the
default) will detect and serve it transparently the next time that source tag is pulled — no
change to the tag itself, no separate mount.

## Layer shapes in the produced image

The manifest carries the nydus data blobs first and the bootstrap last:

| layer | media type | annotation |
|---|---|---|
| data blob | `application/vnd.oci.image.layer.nydus.blob.v1` | `containerd.io/snapshot/nydus-blob` |
| bootstrap | `application/vnd.oci.image.layer.v1.tar+gzip` | `containerd.io/snapshot/nydus-bootstrap` |

The **bootstrap is an ordinary gzip'd tar** whose single entry is `image/image.boot` — the same
shape the Go nydusify and upstream's v3 converter publish. That matters in both directions:
containerd unpacks it through its normal tar path with **no stream processor registered**, and the
snapshotter then finds the bootstrap at `<snapshot>/fs/image/image.boot`, which is exactly where
`snapshotter/src/overlay` looks for it. Publishing the raw bootstrap under a bespoke
`…layer.nydus.bootstrap.v1` media type instead — as this tool did before 2026-07 — yields an image
no standard nydus deployment can pull (`no processor for media-type: unknown`).

Every layer also carries `containerd.io/uncompressed`, its **diff id**, and the image config's
`rootfs.diff_ids` is built from those. For a data blob the diff id is the blob digest (blobs are
uncompressed at the layer level); for the bootstrap it is the digest of the *uncompressed* tar,
which containerd recomputes while unpacking and rejects the image if it disagrees.

Referrer artifacts are the exception: there the bootstrap travels **raw** under
`application/vnd.oci.image.bootstrap.nydus.v1`, because the snapshotter fetches that blob itself
rather than having containerd unpack it.

Useful flags (see `--help` for the full list; `nydusify/src/cli.rs` is the source of truth):

- `--target-suffix <suffix>` — derive `--target` from `--source` by appending a suffix, instead of
  specifying `--target` explicitly (mutually exclusive with `--target`).
- `--fs-version {5,6}` (default `6`), `--compressor` (default `zstd`), `--fs-chunk-size` /
  `--chunk-size` (default `0x100000`).
- `--prefetch-dir` / `--prefetch-patterns` (read patterns from stdin) — honored via `nydus-image
  optimize --prefetch-files` in both modes, baking prefetch hints into the bootstrap.
- `--backend-type {registry,oss,s3,localfs}` + `--backend-config`/`--backend-config-file` — **only
  `registry` (the default) is implemented today**; other backend types are validated but rejected
  with an honest "not yet supported" error, not silently ignored.
- `--source-insecure` / `--target-insecure` — skip TLS verification (still HTTPS).
- `--plain-http` — speak plain HTTP to **both** registries; `--source-plain-http` /
  `--target-plain-http` set one side only, for when the two ends disagree (pulling an upstream
  image over HTTPS into a local HTTP test registry, say). Available on `convert`, `check` and
  `copy`, and settable via the `PLAIN_HTTP` / `SOURCE_PLAIN_HTTP` / `TARGET_PLAIN_HTTP`
  environment variables.

  > Unlike the Go nydusify, this tool **never silently falls back** from HTTPS to HTTP when the
  > TLS handshake fails. That fallback is an automatic downgrade to plaintext, which is precisely
  > the exposure the plain-http notes elsewhere in this repo warn about, so HTTP has to be asked
  > for. Scripts carried over from the Go tool against a plain-HTTP registry need one of these
  > flags added.
- `--work-dir` (default `./tmp`), `--nydus-image` (default `nydus-image` on `$PATH`).
- `--push-retry-count` (default `3`) / `--push-retry-delay` (default `5s`).
- `--platform <os/arch[/variant]>` — a single selector, or a comma-separated list to convert
  several architectures of a multi-arch source. `--all-platforms` converts every
  platform-tagged manifest in the source index. Converting more than one platform requires
  `--merge-platform`, which publishes the per-platform manifests (by digest) under one pushed
  OCI image index / docker manifest list at the target tag; a single platform pushes the manifest
  directly at the tag with no index wrapper.
- `--output-json <path>` — write a conversion summary. Fields: `target`, `manifest_digest`,
  `manifest_size`, `data_blobs` (the primary/first platform), plus the Go-parity metrics
  `SourceImageSize` / `TargetImageSize` (byte totals across converted platforms),
  `ConversionElapsed` (formatted seconds, e.g. `"12.480s"`), and a `platforms[]` breakdown.

- `--source-archive` / `--target-archive` — read the source from, or write the result to, a local
  OCI image-layout tarball instead of a registry (`engine::oci_archive`). Imported archives are
  digest-verified and unpacked with a path-traversal guard.

**Not yet implemented** (the CLI parses these flags but `convert` rejects them with an explicit
error rather than mis-converting):

- `--reverse` (nydus → OCI conversion).
- `--source-backend-type` / non-`registry` `--backend-type`.

## `nydusify check`

```shell
nydusify check --target myregistry/repo:tag-nydus
```

Validates the target image manifest/media-types/annotations, downloads the bootstrap, and runs
`nydus-image check --bootstrap <path>` on it (subprocess, `--nydus-image` to override the binary).
If the target was pushed with `--with-referrer`, `check` also verifies the referrer linkage back to
the source image: it queries the **native OCI 1.1 referrers API first** (`GET
/v2/<repo>/referrers/<digest>` via `registry-client`, filtered — server-side and client-side — for
the nydus artifactType) and falls back to the `sha256-<hex>` fallback tag when the registry lacks
the API or has nothing indexed for the subject. Pass `--source` to also request linkage verification:

```shell
nydusify check --source myregistry/repo:tag --target myregistry/repo:tag-nydus
```

A referrer only exists when the image was converted with `--with-referrer`, so **finding none is
not a failure** — the linkage check is skipped with an informational log. An artifact that *is*
present is validated strictly: it must classify as a nydus artifact and its `subject` must be the
source manifest digest, or `check` fails.

There is no mount-diff / rootfs-comparison in this version (that needs a live `nydusd` mount of
both images) — `check` validates manifest, bootstrap, and (when applicable) referrer linkage only.

## `nydusify copy`

```shell
nydusify copy \
  --source myregistry/repo:tag-nydus \
  --target otherregistry/repo:tag-nydus
```

Pulls the manifest/config/blobs and re-pushes them to `--target`, `HEAD`-deduping blobs that
already exist there and using registry-native `mount_blob` when source and target share a
registry. `--all-platforms` is parsed but rejected today ("copy one platform at a time with
`--platform`" — same v1 scope cut as `convert`).

Either side may be a **local OCI image-layout tarball** instead of a registry, written as
`file://<path>.tar` — that is how an image is saved and loaded without a second registry:

```shell
nydusify copy --source myregistry/repo:tag-nydus --target file://./saved.tar   # save
nydusify copy --source file://./saved.tar --target otherregistry/repo:tag      # load
```

Note that `file://` is understood only where a local archive is a documented input (`copy`, and
`convert`'s `--source-archive`/`--target-archive`); `ImageReference::parse` rejects a scheme
outright everywhere else rather than reading `file` as a registry host.

## `nydusify mount`

```shell
nydusify mount --target myregistry/repo:tag-nydus --mount-path ./image-fs
```

Pulls the bootstrap via `registry-client`, writes a `nydusd` fusedev config pointing at a registry
backend for the target image, and spawns `nydusd` (override with `--nydusd`) in the foreground
until SIGINT/SIGTERM, then unmounts and stops it. Only `--backend-type registry` (the default) is
implemented; `oss`/`s3`/`localfs` are validated but rejected as follow-up work. This subcommand
requires a working `nydusd` FUSE mount, i.e. a Linux host.

## `nydusify commit`

```shell
sudo nydusify commit \
  --container 0d1c9f1a \
  --target myregistry/repo:tag-nydus-committed
```

Snapshots a **running container** back into a nydus image: the container's read-write layer becomes
one more RAFS layer stacked on the image it was started from, and the result is published under a
new reference. Only the bytes the container actually wrote are uploaded — the base image's data
blobs are reused (mounted cross-repo, or copied when the registries differ).

How it works, and where each piece lives:

| step | what happens | code |
|---|---|---|
| inspect | `ctr container info` + `ctr snapshot mounts` yield the image ref and the overlay `upperdir` | `engine/containerd_inspect.rs` |
| diff | the upperdir is walked into an OCI layer tar, translating overlayfs' markers | `engine/overlay_diff.rs` |
| build | `nydus-image create --type tar-rafs` (base's fs-version + compressor) | `commands/commit.rs` |
| merge | `nydus-image merge --parent-bootstrap <base>` | `commands/commit.rs` |
| push | reused base blobs + the new blob + bootstrap + rewritten config + manifest | `commands/commit.rs` |

The overlayfs→OCI translation is the part worth knowing about: a character device with device
number 0/0 becomes `.wh.<name>`, a directory carrying `overlay.opaque=y` gets a `.wh..wh..opq`
inside it, `overlay.*` bookkeeping xattrs are stripped, and every other xattr travels as a
`SCHILY.xattr.*` PAX record — but only in the namespaces RAFS can store (`user.`, `security.`,
`trusted.`, `system.posix_acl_*`), because `nydus-image` rejects anything else with a bare
"invalid xattr key" and fails the whole build. Two overlayfs features cannot be reconstructed from
the upperdir alone — `overlay.redirect` (a renamed directory) and `overlay.metacopy` (contents
still in a lower layer) — so hitting either fails the commit loudly instead of publishing a wrong
layer. containerd's overlay snapshotter enables neither.

Useful flags:

- `--container` takes a containerd id, an unambiguous id prefix, or a nerdctl `--name`.
- `--containerd-namespace` (default `default`; Kubernetes uses `k8s.io`),
  `--containerd-address`, `--containerd-cli` (default `ctr`).
- `--source <ref>` overrides the base image, which otherwise comes from what containerd recorded
  for the container.
- `--maximum-times` (default 400) refuses to commit onto an image that already carries that many
  committed layers. The count comes from the bootstrap layer's
  `containerd.io/snapshot/nydus-commit-blobs` annotation, which this tool **accumulates** across
  commits — the Go nydusify overwrites it with only the current commit's blobs, so its own limit
  never engages.
- `--plain-http` / `--source-plain-http` / `--target-plain-http`, `--platform`, `--work-dir`,
  `--nydus-image`, `--push-retry-count` / `--push-retry-delay` behave as they do elsewhere.

Not implemented: `--with-path`, the Go tool's option for committing extra bind-mounted paths by
entering the container's mount namespace with `nsenter`. `commit` covers the container's own
writable layer.

> Needs root (the upperdir lives under containerd's state directory) and a container on an overlay
> snapshot with a writable layer — a read-only view has nothing to commit and is rejected as such.

## `nydusify chunkdict generate`

```shell
nydusify chunkdict generate \
  --sources myregistry/repo:v1,myregistry/repo:v2,myregistry/repo:v3 \
  --target myregistry/repo:chunkdict
```

Trains a shared chunk dictionary across several nydus images and publishes it as its own image, so
later conversions can dedup against it via `nydus-image --chunk-dict`. Each source bootstrap is
staged under a directory named after its reference (with `/` rewritten to `:` so `nydus-image`
recovers the name and tag from the parent directory), `nydus-image chunkdict generate` is run over
the set, and the resulting image is pushed with its source blobs cross-repo-mounted rather than
re-uploaded.

## The ecosystem loop

```
nydusify convert --oci-ref --with-referrer   (push side: publishes the referrer artifact)
            │
            ▼
snapshotter Prepare() detects the referrer (referrer_detect = true, default)
            │
            ▼
fetches + digest-verifies the bootstrap, mounts via DaemonSupervisor::ensure_instance
            │
            ▼
pod gets the accelerated mount — same tag, no client-visible change
```

`nydusify check` and `nydusify mount` are the operator-facing tools to verify a pushed artifact
independently of the snapshotter (`check` validates the artifact; `mount` proves it is servable at
all without a cluster).
