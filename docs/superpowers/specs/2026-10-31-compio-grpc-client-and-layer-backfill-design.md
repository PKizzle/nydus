# compio-native containerd gRPC client and auto-accel layer backfill

**Date:** 2026-10-31
**Status:** Approved

## Goal

Two changes, delivered as two PRs against `production` in this order:

1. **compio-native gRPC client.** The snapshotter talks to containerd's gRPC services over a
   hyper HTTP/2 connection driven by compio, keeping tonic only for generated clients and codec.
   This removes the isolated tokio runtime in `content_store.rs`, the last tokio runtime in the
   snapshotter's production code.
2. **Layer backfill.** Before a node-local zran conversion, the snapshotter has containerd fetch
   any gzip layer blob that is missing from the content store, so images whose layers containerd
   never downloaded can be accelerated.

## Background

### Why layer blobs are missing

containerd's unpacker fetches a layer blob only when it has to create that layer's snapshot. In
`core/unpack/unpacker.go` (containerd v2.3.4), layer descriptors are split off the normal fetch
path, and for each layer the unpacker calls `Prepare` on the snapshotter. If that returns
`AlreadyExists` because a snapshot with the layer's chain ID exists, it logs
`snapshot … already exists skip fetch blob` and moves on without fetching.

A snapshot outlives its blob whenever the image that brought the blob is removed while a running
container (or another image's snapshot chain) still holds the snapshot. The garbage collector
deletes the unreferenced blob; the next image with the same layer is pulled without it.

Evidence:

- On `raspberrypi-5-1`, 25 images lack at least one layer blob. Every missing blob belongs to a
  layer whose snapshot was created before the image now referencing it was pulled. One example
  is Home Assistant's base layer: its snapshot dates from 2026-07-16, and the four manifests that
  reference it arrived between 2026-08-29 and 2026-10-12.
- Reproduced with a private containerd 2.2.2. The steps are: pull `alpine:3.20`, create a
  container, run `images rm --sync` (the layer blob is deleted, the snapshots remain), then pull
  again. The second pull transfers about 30 KB and the layer blob stays absent.

`local_accel` builds the zran artifact from these gzip blobs, so `gzip_layers_from_manifest`
fails with `layer … not present … (content store out of sync?)`. A manual
`ctr content fetch --platform linux/arm64 <ref>` restores the blob. The design below automates
that through containerd itself.

### Why change the gRPC client first

`content_store.rs` uses tonic's `transport::Channel`, which only runs on a tokio reactor. That is
why the snapshotter builds a 2-worker tokio runtime and bridges every RPC with
`blocking::unblock` and `handle.block_on`. The backfill adds two more services (Transfer and
Streaming), one of them bidirectional, and should not grow that bridge.

The server side already avoids tonic's transport: tonic service types are served by cyper-axum,
which is hyper HTTP/2 on compio. The client side adopts the same split. Replacing tonic as a
whole (codec, status mapping, streaming, codegen) was rejected: it would put protocol code we do
not need to own into this repository.

## Part 1: compio-native gRPC client

### Components

- **`snapshotter/src/containerd_grpc.rs`** (new). `ContainerdChannel` is a cloneable handle to
  one HTTP/2 connection to containerd's Unix socket:
  `compio::net::UnixStream` → `cyper_core::HyperStream` → `hyper::client::conn::http2::handshake`
  with cyper's `CompioExecutor` and `CompioTimer` (both in `third_party/cyper-core`). The
  connection task runs on the compio runtime. The timer is what hyper's HTTP/2 keep-alive pings
  and handshake timeout need; without one, hyper panics as soon as either is enabled (the gap
  reported in grpc/grpc-rust#2040). Keep-alive pings are enabled so that a containerd that went
  away is noticed before the next call.
  - It implements tower's `Service<http::Request<tonic::body::Body>>`, so tonic's generated
    clients (`ContentClient<ContainerdChannel>` and so on) run on it unchanged.
  - The connection is established lazily and shared by all calls (HTTP/2 multiplexing). Today a
    new connection is opened per call.
  - If the connection is closed or the send fails with a connection-level error, the handle drops
    it, and the next call establishes a new one. A failed call is reported to its caller and not
    retried inside the channel, so a real containerd fault stays visible.
  - Every request carries the `containerd-namespace` metadata, set once per client instead of at
    every call site.
- **`content_store.rs`** keeps its public API (`info`, `write_blob`, `write_bytes`,
  `fetch_bytes`, `images_*`, …). The tokio runtime field, `Drop`, `connect`, `connect_channel`
  and all 27 `blocking::unblock`/`block_on` bridges are removed. The methods become plain
  `async fn`s on the compio runtime. CPU-bound work, such as hashing a bootstrap before upload,
  stays in `blocking::unblock`.

### Dependencies

- `tonic`: the `transport` feature is dropped; the default codec and codegen are kept.
- `tokio`: `features = ["full"]` shrinks to what the remaining code needs for types, and nothing
  starts a tokio runtime. `tokio-stream` and `hyper-util` are dropped wherever they served only
  the transport.
- `hyper` gains the `http2` and `client` features if they are not already enabled.

### Documentation

CLAUDE.md (async runtime convention and gotcha #1), ARCHITECTURE.md Decision 3, and the
`snapshotter/Cargo.toml` comments describe "the one sanctioned tokio runtime" in
`content_store.rs`. They are rewritten to state that the snapshotter runs on compio alone and
reaches containerd through `containerd_grpc.rs`.

### Testing

- The existing `content_store` unit tests pass unchanged.
- New unit tests cover the namespace metadata and the drop-on-failure reconnect state machine,
  using an in-process HTTP/2 server on a compio Unix socket.
- New Linux integration test `misc/containerd-grpc/client-test.sh` (root, private containerd in
  a temporary root):
  - write and read back a blob, including one larger than tonic's 4 MiB default frame;
  - create, get, list and delete an image record;
  - containerd is restarted between two calls, and the second call must succeed through a new
    connection;
  - a call against a stopped containerd fails with a connection error instead of hanging.

## Part 2: layer backfill

### Hook point

- `containerd_lookup::gzip_layers_from_manifest` returns a typed error,
  `MissingLayers { manifest, digests }` (thiserror), naming every absent blob instead of the
  first one. The other failures keep today's messages.
- `auto_zran::run_conversion` handles `Missing`:
  - call the backfill once;
  - resolve the manifest again;
  - continue with the conversion.

  If blobs are still missing, or the backfill fails, the job fails through the existing strike
  and backoff path, and its error names the missing digests.
- Backfill runs only for a conversion, never on the pull or `Prepare` path.

### Component: `snapshotter/src/containerd_transfer.rs` (new)

`fetch_image_content(reference, platform) -> Result<BackfillReport>` issues
`Transfer.Transfer` on the Part 1 channel:

- **Source:** `OCIRegistry { reference, resolver { host_dir, auth_stream } }`.
- **Destination:** `ImageStore` with:
  - name `nydus.layer-backfill.local/image:<manifest hex>`, outside the
    `nydus.auto-accel.local/` prefix that the reconciler and the peer-mirror self-check treat
    as sidecars;
  - `platforms` set to the host platform only;
  - no `unpacks`.

  Without unpacks, containerd's transfer pull (`core/transfer/local/pull.go`) runs its plain
  fetch handler over every descriptor, skipping content that is already present.
- **Reference:** the image's repository pinned to the resolved manifest digest, so a tag that
  moved since the pull cannot change what is fetched.
- **Temporary record:** a dedicated name keeps CRI's own image record and its labels untouched.
  The temporary record also roots the fetched blobs while the transfer runs. Once the transfer
  finishes, the record is deleted (also when the transfer fails); the worker deletes records a
  crash left behind when it starts. The blobs then stay referenced
  by the real image's manifest (`containerd.io/gc.ref.content.l.<n>`).
- **Routing:** `host_dir` is the containerd hosts directory, so the fetch takes the same route as
  a normal pull on that node. On the k3s cluster, that means the embedded registry mirror for
  registries routed through it, and the upstream registry otherwise.
- **Report:** `BackfillReport { blobs, bytes, duration }`, computed by comparing content-store
  presence of the manifest's layers before and after the transfer.

### Credentials

containerd keeps no credentials for the Transfer service; it asks the client. The module opens a
`Streaming.Stream`, registers its ID as `auth_stream`, and answers each `AuthRequest { host,
reference }`:

- it builds an `ImageRef` and calls `daemon::auth::resolve_auth`;
- a stored Docker-style `user:password` is returned as an `AuthResponse` with type
  `CREDENTIALS`;
- if nothing is stored, it returns an empty response, and the fetch continues anonymously.

The stream is closed when the transfer ends. Credential values are never logged.

### Configuration

`[snapshotter.containerd] hosts_dir` (new, `Option<PathBuf>`, `#[serde(default)]`):

- the `k3s` profile preset sets `/var/lib/rancher/k3s/agent/etc/containerd/certs.d`;
- the stock profile leaves it unset, so containerd uses its default resolver.

No change is needed in k3s-config.

### Observability

- One `info!` per backfill: image, manifest, blobs fetched, bytes, duration.
- A failed backfill is part of the existing `auto-zran conversion failed` warning.

### Testing

- **Unit tests:**
  - type URLs and field mapping of the `OCIRegistry` and `ImageStore` Any payloads;
  - the mapping from `AuthRequest` through `resolve_auth` to `AuthResponse`, with and without
    stored credentials;
  - `gzip_layers_from_manifest` returns `Missing` with the exact digests;
  - `run_conversion` calls the backfill exactly once and re-resolves the manifest.
- **Linux integration test `misc/containerd-grpc/backfill-test.sh`** (root, private containerd):
  - reproduce the missing-blob state as in Background, run the backfill, and assert every layer
    blob is present with a matching digest and the temporary record is gone;
  - repeat against a local `registry:2` with htpasswd: without stored credentials the transfer
    fails with an authorization error, with them it succeeds.

## Out of scope

- Node-local acceleration of zstd layers (checkpoint index): separate spec.
- PKizzle/nydus#24 (stale sidecars, accurate `enqueued`, non-gzip rejection): independent.
- Proactively filling content-store gaps for images that are not being converted.

## Deployment

- **Part 1:** canary on `raspberrypi-4-1`. Check that `Prepare`, sidecar upload and peer sidecar
  resolution work, and that no containerd errors appear over a soak, before the other nodes.
- **Part 2:** on `raspberrypi-5-1`, the existing gaps in gzip images (cert-manager, coredns,
  cloudnative-pg) exercise the backfill. Home Assistant is zstd, so the non-gzip check
  (PKizzle/nydus#24) rejects it before any blob lookup; it is not a backfill case until zstd
  support exists.
