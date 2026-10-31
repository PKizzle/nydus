# compio-native containerd gRPC client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The snapshotter talks to containerd's gRPC services over a hyper HTTP/2 connection
driven by compio, so the isolated tokio runtime in `content_store.rs` (the last tokio runtime in
production code) is removed.

**Architecture:** A new `ContainerdChannel` implements tower's `Service<http::Request<tonic::body::Body>>`
over one cached HTTP/2 connection per thread: `compio::net::UnixStream` → `cyper_core::HyperStream`
→ `hyper::client::conn::http2`, with `CompioExecutor` and `CompioTimer`. tonic's generated
clients (`ContentClient<ContainerdChannel>`, `ImagesClient<ContainerdChannel>`) run on it
unchanged. The channel also sets the request origin and the `containerd-namespace` header, so
call sites lose their per-call setup.

**Tech Stack:** Rust 2024, compio 0.19, hyper 1.10 (`client`, `http2`), cyper-core 0.9
(vendored in `third_party/cyper-core`), tonic 0.14 (codegen and codec only), tower 0.5,
thiserror.

**Spec:** `docs/superpowers/specs/2026-10-31-compio-grpc-client-and-layer-backfill-design.md`,
Part 1. Part 2 (layer backfill) gets its own plan once this lands.

**Worktree:** `.claude/worktrees/compio-grpc`, branch `feat/compio-grpc-client` (based on
`origin/production`). Run every command from the worktree root.

**Linux gate.** The snapshotter only builds and lints fully on Linux. "Run the Linux gate" means:

```bash
docker run --rm -v "$PWD":/work -v nydus-cargo-registry:/usr/local/cargo/registry \
  -v nydus-target-compio-grpc:/work/target -w /work rust:1.96-bookworm bash -c '
  apt-get update -qq >/dev/null && apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler >/dev/null 2>&1
  rustup component add clippy rustfmt >/dev/null 2>&1
  set -o pipefail
  cargo fmt -p nydus-snapshotter --check && echo FMT-OK
  cargo clippy -p nydus-snapshotter --all-targets -- -D warnings 2>&1 | tail -3
  cargo test -p nydus-snapshotter 2>&1 | grep -E "test result|FAILED|panicked|error(\[|:)"'
```

Expected when green: `FMT-OK`, clippy `Finished` with no warnings, and every `test result:`
line reading `ok` with `0 failed`. To run a subset, replace the last line with
`cargo test -p nydus-snapshotter <filter>`.

---

## File Structure

| File | Responsibility |
|---|---|
| `snapshotter/src/containerd_grpc.rs` (create) | `ContainerdChannel`: per-thread cached HTTP/2 connection, origin and namespace on every request, reconnect after the connection closes, typed `ChannelError`. |
| `snapshotter/src/lib.rs` (modify) | Register `pub mod containerd_grpc`. |
| `snapshotter/src/content_store.rs` (modify) | Same public API. The tokio runtime, `Drop`, `connect`, `connect_images`, `connect_channel`, `attach_namespace` and the `blocking::unblock`/`block_on` bridges are removed; the methods use `ContainerdChannel` directly. |
| `snapshotter/src/grpc/mod.rs` (modify) | The transport round-trip test runs tonic's client on `ContainerdChannel` over a Unix socket instead of tonic's tokio transport over TCP. |
| `snapshotter/Cargo.toml` (modify) | Add `hyper` (`client`, `http2`) and `cyper-core`; drop tonic's `transport` feature, `tokio`, `tokio-stream` and `hyper-util`; rewrite the dependency comments. |
| `snapshotter/tests/containerd_client.rs` (create) | Integration test against a real containerd started by the test: blobs, image records, a containerd restart, a stopped containerd. |
| `misc/containerd-grpc/client-test.sh` (create) | Runs that integration test as root inside a container that has containerd installed. |
| `CLAUDE.md`, `ARCHITECTURE.md` (modify) | Replace "the one sanctioned tokio runtime" with the compio-only rule and point at `containerd_grpc.rs`. |

---

### Task 1: Dependencies for the compio HTTP/2 client

**Files:**
- Modify: `snapshotter/Cargo.toml` (the `[dependencies]` block around the `tokio`, `tonic` and `hyper-util` lines)

This task only adds dependencies. Nothing is removed yet, so the crate keeps compiling.

- [ ] **Step 1: Add hyper and cyper-core**

  In `snapshotter/Cargo.toml`, directly below the `tower = { version = "0.5", features = ["util"] }` line, add:

```toml
# HTTP/2 client connection to containerd's gRPC socket, driven by compio through cyper-core's
# executor, timer and stream adapter (see containerd_grpc.rs). The root manifest patches
# cyper-core to the vendored copy in third_party/cyper-core.
hyper = { version = "1.10", features = ["client", "http2"] }
cyper-core = { version = "0.9", default-features = false }
```

- [ ] **Step 2: Check that it resolves**

Run: `cargo metadata --format-version 1 --no-deps -q >/dev/null && echo OK`
Expected: `OK`.

Run: `grep -n '^name = "cyper-core"' -A2 Cargo.lock`
Expected: version `0.9.0`, no `source =` line (the vendored path copy).

- [ ] **Step 3: Commit**

```bash
git add snapshotter/Cargo.toml Cargo.lock
git commit -m "snapshotter: depend on hyper's HTTP/2 client and cyper-core

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `ContainerdChannel`, round trip over a Unix socket

**Files:**
- Create: `snapshotter/src/containerd_grpc.rs`
- Modify: `snapshotter/src/lib.rs` (after `pub mod containerd_lookup;`)

The tests serve tonic-health (already a dependency) through cyper-axum on a compio
`UnixListener` in a background thread. That's the same server stack the snapshotter uses in
production, so these tests need no containerd.

- [ ] **Step 1: Write the failing test**

Create `snapshotter/src/containerd_grpc.rs` with only the test module:

```rust
// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::{HealthCheckRequest, health_client::HealthClient};

    /// A tonic-health server on `socket`, run by cyper-axum on its own compio runtime. Dropping
    /// the returned guard stops it: the runtime ends, which closes every accepted connection.
    pub(super) struct TestServer {
        stop: Option<async_channel::Sender<()>>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestServer {
        pub(super) fn start(socket: &Path) -> Self {
            Self::start_with(socket, axum::Router::new)
        }

        /// Like `start`, but lets the test wrap the router (e.g. to capture headers).
        pub(super) fn start_with(
            socket: &Path,
            wrap: impl FnOnce() -> axum::Router + Send + 'static,
        ) -> Self {
            let _ = std::fs::remove_file(socket);
            let socket = socket.to_path_buf();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
            let thread = std::thread::spawn(move || {
                compio::runtime::Runtime::new().unwrap().block_on(async move {
                    let listener = compio::net::UnixListener::bind(&socket).await.unwrap();
                    ready_tx.send(()).unwrap();
                    let (_reporter, health) = tonic_health::server::health_reporter();
                    let app = wrap().merge(
                        tonic::service::Routes::new(health).into_axum_router(),
                    );
                    futures::select! {
                        r = futures::FutureExt::fuse(cyper_axum::serve(listener, app.into_make_service())) => r.unwrap(),
                        _ = futures::FutureExt::fuse(stop_rx.recv()) => {}
                    }
                });
            });
            ready_rx.recv().unwrap();
            Self {
                stop: Some(stop_tx),
                thread: Some(thread),
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.try_send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    pub(super) async fn check(channel: &ContainerdChannel) -> Result<ServingStatus, tonic::Status> {
        let mut client = HealthClient::new(channel.clone());
        let response = client
            .check(HealthCheckRequest {
                service: String::new(),
            })
            .await?;
        Ok(response.into_inner().status())
    }

    #[test]
    fn unary_call_round_trips_over_a_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("grpc.sock");
        let _server = TestServer::start(&socket);
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let channel = ContainerdChannel::new(&socket, "k8s.io");
            assert_eq!(check(&channel).await.unwrap(), ServingStatus::Serving);
        });
    }
}
```

Add to `snapshotter/src/lib.rs` after `pub mod containerd_lookup;`:

```rust
pub mod containerd_grpc;
```

- [ ] **Step 2: Run the test to verify it fails**

Run the Linux gate with the last line replaced by `cargo test -p nydus-snapshotter containerd_grpc 2>&1 | tail -15`.
Expected: compile error `cannot find type ContainerdChannel in this scope`.

- [ ] **Step 3: Implement `ContainerdChannel`**

Insert above the test module in `snapshotter/src/containerd_grpc.rs`:

```rust
//! gRPC channel to containerd, driven by the compio runtime.
//!
//! tonic's generated clients only need a tower service that sends `http::Request`s with a
//! tonic body. [`ContainerdChannel`] is that service: it speaks HTTP/2 over containerd's Unix
//! socket with hyper's client connection, using cyper-core's compio executor, timer and stream
//! adapter. That is the same stack the snapshotter's own gRPC server runs on, so the snapshotter
//! needs no tokio runtime to reach containerd.
//!
//! One connection per (thread, socket) is cached and multiplexed by HTTP/2. The connection task
//! runs on the calling thread's compio runtime (cyper's `HyperStream` is pinned to the thread
//! that created it), so the cache is thread-local rather than shared. A closed connection is
//! dropped and replaced on the next call; a failed call is reported, not retried, so a containerd
//! fault stays visible to the caller.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use cyper_core::{CompioExecutor, CompioTimer, HyperStream};
use http::header::HeaderValue;
use hyper::body::Incoming;
use hyper::client::conn::http2::{self, SendRequest};
use tracing::debug;

/// HTTP/2 PING interval. With `keep_alive_while_idle`, a containerd that went away is noticed
/// between calls instead of on the next one.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long a PING may go unanswered before the connection is considered dead.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// `:authority` of every request. containerd ignores it, but HTTP/2 requires one.
const AUTHORITY: &str = "containerd";

type Sender = SendRequest<tonic::body::Body>;

thread_local! {
    /// Live connections of this thread, keyed by socket path.
    static CONNECTIONS: RefCell<HashMap<PathBuf, Sender>> = RefCell::new(HashMap::new());
}

/// Why a request to containerd failed before a gRPC status was received.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("failed to connect to containerd at {socket}")]
    Connect {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP/2 handshake with containerd at {socket} failed")]
    Handshake {
        socket: PathBuf,
        #[source]
        source: hyper::Error,
    },
    #[error("request to containerd at {socket} failed")]
    Request {
        socket: PathBuf,
        #[source]
        source: hyper::Error,
    },
    #[error("invalid containerd namespace {0:?}")]
    Namespace(String),
    #[error("invalid gRPC request URI")]
    Uri(#[source] http::Error),
}

/// A tower service that sends tonic requests to containerd over a cached HTTP/2 connection.
/// Cheap to clone; every clone shares the calling thread's connection.
#[derive(Clone, Debug)]
pub struct ContainerdChannel {
    socket: Arc<Path>,
    namespace: Arc<str>,
}

impl ContainerdChannel {
    /// A channel to containerd's socket that tags every request with `namespace`
    /// (`containerd-namespace` metadata; `k8s.io` for CRI/k3s).
    pub fn new(socket: impl AsRef<Path>, namespace: &str) -> Self {
        Self {
            socket: Arc::from(socket.as_ref()),
            namespace: Arc::from(namespace),
        }
    }

    /// The containerd socket this channel connects to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    async fn send(
        socket: Arc<Path>,
        namespace: Arc<str>,
        request: http::Request<tonic::body::Body>,
    ) -> Result<http::Response<Incoming>, ChannelError> {
        let request = prepare(request, &namespace)?;
        let mut sender = sender(&socket).await?;
        let result = match sender.ready().await {
            Ok(()) => sender.send_request(request).await,
            Err(source) => Err(source),
        };
        if result.is_err() && sender.is_closed() {
            forget(&socket);
        }
        result.map_err(|source| ChannelError::Request {
            socket: socket.to_path_buf(),
            source,
        })
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for ContainerdChannel {
    type Response = http::Response<Incoming>;
    type Error = ChannelError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness is checked per request on the shared connection inside `call`.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        Box::pin(Self::send(
            self.socket.clone(),
            self.namespace.clone(),
            request,
        ))
    }
}

/// Give a tonic request the absolute URI HTTP/2 needs and the containerd namespace header.
fn prepare(
    request: http::Request<tonic::body::Body>,
    namespace: &str,
) -> Result<http::Request<tonic::body::Body>, ChannelError> {
    let (mut parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
    parts.uri = http::Uri::builder()
        .scheme("http")
        .authority(AUTHORITY)
        .path_and_query(path_and_query)
        .build()
        .map_err(ChannelError::Uri)?;
    let value = HeaderValue::from_str(namespace)
        .map_err(|_| ChannelError::Namespace(namespace.to_string()))?;
    parts.headers.insert("containerd-namespace", value);
    Ok(http::Request::from_parts(parts, body))
}

/// This thread's open connection to `socket`, establishing one if there is none or it closed.
async fn sender(socket: &Path) -> Result<Sender, ChannelError> {
    let cached = CONNECTIONS.with(|c| c.borrow().get(socket).cloned());
    if let Some(sender) = cached.filter(|s| !s.is_closed()) {
        return Ok(sender);
    }
    let sender = connect(socket).await?;
    CONNECTIONS.with(|c| {
        c.borrow_mut()
            .insert(socket.to_path_buf(), sender.clone())
    });
    Ok(sender)
}

fn forget(socket: &Path) {
    CONNECTIONS.with(|c| c.borrow_mut().remove(socket));
}

async fn connect(socket: &Path) -> Result<Sender, ChannelError> {
    let stream = compio::net::UnixStream::connect(socket)
        .await
        .map_err(|source| ChannelError::Connect {
            socket: socket.to_path_buf(),
            source,
        })?;
    let (sender, connection) = http2::Builder::new(CompioExecutor)
        .timer(CompioTimer)
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .handshake(HyperStream::new_plain(stream))
        .await
        .map_err(|source| ChannelError::Handshake {
            socket: socket.to_path_buf(),
            source,
        })?;
    let socket_display = socket.display().to_string();
    compio::runtime::spawn(async move {
        if let Err(error) = connection.await {
            debug!(socket = %socket_display, %error, "containerd connection closed");
        }
    })
    .detach();
    Ok(sender)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run the Linux gate with the last line replaced by `cargo test -p nydus-snapshotter containerd_grpc 2>&1 | grep -E "test |test result"`.
Expected: `test containerd_grpc::tests::unary_call_round_trips_over_a_unix_socket ... ok`.

If the compiler rejects `cyper_axum::serve` with a `UnixListener`, check how `grpc/mod.rs`
serves its production socket (search for `UnixListener` there) and use the same listener type
and call. Do not switch the test to TCP: the channel speaks only Unix sockets.

- [ ] **Step 5: Commit**

```bash
git add snapshotter/src/containerd_grpc.rs snapshotter/src/lib.rs
git commit -m "snapshotter: add a compio-native gRPC channel to containerd

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Channel behaviour: namespace header, reconnect, connect errors

**Files:**
- Modify: `snapshotter/src/containerd_grpc.rs` (test module)

- [ ] **Step 1: Write the tests**

Append inside `mod tests` in `snapshotter/src/containerd_grpc.rs`:

```rust
    #[test]
    fn every_request_carries_the_containerd_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("grpc.sock");
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = seen.clone();
        let _server = TestServer::start_with(&socket, move || {
            axum::Router::new().layer(tower::util::MapRequestLayer::new(
                move |request: http::Request<axum::body::Body>| {
                    if let Some(ns) = request.headers().get("containerd-namespace") {
                        recorder.lock().unwrap().push(ns.to_str().unwrap().to_string());
                    }
                    request
                },
            ))
        });
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let channel = ContainerdChannel::new(&socket, "k8s.io");
            check(&channel).await.unwrap();
            check(&channel).await.unwrap();
        });
        assert_eq!(*seen.lock().unwrap(), vec!["k8s.io", "k8s.io"]);
    }

    #[test]
    fn a_restarted_server_is_reached_through_a_new_connection() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("grpc.sock");
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let channel = ContainerdChannel::new(&socket, "k8s.io");
            let server = TestServer::start(&socket);
            assert_eq!(check(&channel).await.unwrap(), ServingStatus::Serving);
            drop(server);
            // Let this runtime poll the connection task so it observes the server's EOF, as it
            // does in production long before the next call.
            compio::time::sleep(Duration::from_millis(200)).await;
            let _server = TestServer::start(&socket);
            assert_eq!(check(&channel).await.unwrap(), ServingStatus::Serving);
        });
    }

    #[test]
    fn a_missing_socket_fails_with_a_connect_error() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("absent.sock");
        compio::runtime::Runtime::new().unwrap().block_on(async {
            let channel = ContainerdChannel::new(&socket, "k8s.io");
            let status = check(&channel).await.unwrap_err();
            let chain = format!("{:?}", std::error::Error::source(&status));
            assert!(
                chain.contains("failed to connect to containerd"),
                "unexpected error chain: {chain}"
            );
        });
    }

    #[test]
    fn an_invalid_namespace_is_rejected_before_connecting() {
        let request = http::Request::new(tonic::body::Body::empty());
        let err = prepare(request, "bad\nnamespace").unwrap_err();
        assert!(matches!(err, ChannelError::Namespace(_)));
    }
```

- [ ] **Step 2: Run the tests**

Run the Linux gate with the last line replaced by `cargo test -p nydus-snapshotter containerd_grpc 2>&1 | grep -E "test |test result"`.
Expected: all five `containerd_grpc::tests::*` tests `ok`.

Expected failure modes and what they mean:
- `a_missing_socket_fails_with_a_connect_error` failing on the chain text means tonic wraps
  transport errors differently than assumed. Print `status` and the full source chain, then
  assert on the `ChannelError::Connect` variant by downcasting the source
  (`source.downcast_ref::<ChannelError>()`), not on text.
- `a_restarted_server_is_reached_through_a_new_connection` failing on the second `check`
  means the closed connection was reused. Check that `sender()` filters on `is_closed()`.

- [ ] **Step 3: Commit**

```bash
git add snapshotter/src/containerd_grpc.rs
git commit -m "snapshotter: test namespace, reconnect and connect errors of the containerd channel

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Move `content_store.rs` onto `ContainerdChannel`

**Files:**
- Modify: `snapshotter/src/content_store.rs`

The public API stays identical, so no caller changes. Every method is converted in one commit,
because the tokio runtime can only be deleted once nothing uses it.

- [ ] **Step 1: Replace the module doc's cross-runtime note**

Replace the paragraph starting `//! Cross-runtime note:` (to the end of the module doc) with:

```rust
//! Transport: the gRPC clients run on [`ContainerdChannel`] (`containerd_grpc.rs`), an HTTP/2
//! connection driven by the snapshotter's compio runtime. The channel also sets the
//! `containerd-namespace` header, so no method here handles it.
```

- [ ] **Step 2: Replace the client state**

Replace the `ContentStoreClient` doc comment through the end of `ContentStoreClient::new` (the
`Inner` struct, `impl Drop for Inner` and the tokio-runtime constructor) with:

```rust
/// Containerd content-store client. Cheap to clone; every clone shares the calling thread's
/// connection to containerd.
#[derive(Clone, Debug)]
pub struct ContentStoreClient {
    channel: ContainerdChannel,
    content_root: Arc<Path>,
}

impl ContentStoreClient {
    /// Construct a client from configuration. Connects lazily on the first call.
    pub fn new(config: &ContainerdConfig) -> Result<Self> {
        Ok(Self {
            channel: ContainerdChannel::new(config.address(), &config.namespace),
            content_root: Arc::from(config.content_root().as_path()),
        })
    }

    fn content(&self) -> ContentClient<ContainerdChannel> {
        ContentClient::new(self.channel.clone())
    }

    fn images(&self) -> ImagesClient<ContainerdChannel> {
        ImagesClient::new(self.channel.clone())
    }
```

`new` keeps returning `Result` so callers don't change; it can no longer fail.

In `blob_path`, change `self.inner.content_root.join(…)` to `self.content_root.join(…)`.

- [ ] **Step 3: Convert each RPC method with this one transformation**

Every RPC method currently has this shape:

```rust
let inner = self.inner.clone();
// owned copies of the arguments
blocking::unblock(move || {
    inner.handle.block_on(async {
        let mut client = connect(&inner).await?;            // or connect_images
        let mut request = tonic::Request::new(SomeRequest { … });
        attach_namespace(&mut request, &inner.namespace)?;
        … client.some_rpc(request).await …
    })
})
.await
```

It becomes:

```rust
let mut client = self.content();                             // or self.images()
let request = tonic::Request::new(SomeRequest { … });
… client.some_rpc(request).await …
```

That means:
- drop the `inner` clone, the owned argument copies that only existed to move into the closure,
  the `blocking::unblock` and `block_on` wrappers, and the `attach_namespace` call;
- keep every request field, every `map_err` message, every `NotFound` and `AlreadyExists`
  branch, and the `max_encoding_message_size(64 * 1024 * 1024)` calls exactly as they are;
- where `?` inside the old closure had type annotations such as `Ok::<_, anyhow::Error>(())`,
  return `Ok(())` directly.

Apply it to every method:
- `info`, `apply_labels`, `list_with_filters`, `read_bytes` (`ContentClient`);
- `images_create`, `images_upsert`, `images_get`, `images_list`, `images_delete` (`ImagesClient`);
- `write_blob` and `write_bytes`, with the rules below.

Example, `info` after conversion:

```rust
    #[instrument(level = "debug", skip(self), err)]
    pub async fn info(&self, digest: &str) -> Result<Option<ContentInfo>> {
        let mut client = self.content();
        let request = tonic::Request::new(InfoRequest {
            digest: digest.to_string(),
        });
        match client.info(request).await {
            Ok(response) => {
                let info = response
                    .into_inner()
                    .info
                    .context("containerd InfoResponse missing info field")?;
                Ok(Some(ContentInfo {
                    digest: info.digest,
                    size: info.size as u64,
                    labels: info.labels,
                }))
            }
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(anyhow::anyhow!(
                "containerd Info({digest}) failed: {status}"
            )),
        }
    }
```

`write_blob`: the file read and SHA-256 stay in their existing `blocking::unblock` (CPU and disk
work). Only the second `blocking::unblock(move || inner.handle.block_on(async { … }))` (the gRPC
part) is unwrapped:

```rust
        let ref_hint = format!("nydus-auto-accel-{digest}");
        let mut client = self
            .content()
            // Merged bootstraps for multi-layer images exceed tonic's default 4 MiB frame.
            .max_encoding_message_size(64 * 1024 * 1024);
        let request = tonic::Request::new(futures::stream::once(async move {
            WriteContentRequest {
                action: WriteAction::Commit as i32,
                r#ref: ref_hint,
                total: bytes.len() as i64,
                expected: digest_with_prefix.clone(),
                offset: 0,
                data: bytes,
                labels,
            }
        }));
        let mut responses = client
            .write(request)
            .await
            .map_err(|status| anyhow::anyhow!("containerd Write failed: {status}"))?
            .into_inner();
        while responses
            .message()
            .await
            .map_err(|status| anyhow::anyhow!("containerd Write response failed: {status}"))?
            .is_some()
        {}
        Ok(digest_with_prefix)
```

The `async move` block takes ownership of `digest_with_prefix` through its clone. If the borrow
checker complains, bind `let expected = digest_with_prefix.clone();` before the stream and move
`expected` in.

`write_bytes`: the same as `write_blob`'s gRPC part, with its own `ref` format
`format!("nydus-auto-accel-{ref_hint}-{digest}")` and the comment about peers routing
bootstrap-sized blobs kept above `max_encoding_message_size`.

- [ ] **Step 4: Delete the transport helpers and fix the imports**

Delete `connect`, `connect_images`, `connect_channel` and `attach_namespace` at the end of the
`impl` block. Add `use crate::containerd_grpc::ContainerdChannel;` and remove the now-unused
`use tonic::metadata::MetadataValue;` (and `std::path::PathBuf` if only `blob_path`'s return
type uses it, in which case keep it).

Run: `grep -nE "block_on|tokio|attach_namespace|connect_channel|inner\." snapshotter/src/content_store.rs`
Expected: no output.

- [ ] **Step 5: Run the gate**

Run the Linux gate.
Expected: green. In particular `content_store::tests::blob_path_strips_sha256_prefix` passes
unchanged, and every `auto_zran`, `auto_accel_sidecar` and `containerd_lookup` test still passes.

- [ ] **Step 6: Commit**

```bash
git add snapshotter/src/content_store.rs
git commit -m "snapshotter: reach containerd's content and image services over the compio channel

Drop the isolated tokio runtime and the blocking::unblock/block_on bridge
around every RPC. The public API is unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Run the server round-trip test on the compio channel

**Files:**
- Modify: `snapshotter/src/grpc/mod.rs` (test `grpc_transport_round_trips_a_real_client_over_compio`, around line 2057)

This test is the last user of tonic's tokio transport. It now checks our server against our
client, over a Unix socket as in production.

- [ ] **Step 1: Rewrite the test body**

Replace the body of `grpc_transport_round_trips_a_real_client_over_compio` from
`let dir = tempdir().unwrap();` up to and including the tokio `rt.block_on(async move { … });`
block with:

```rust
        let dir = tempdir().unwrap();
        let server_root = dir.path().to_path_buf();
        let socket = dir.path().join("snapshotter.sock");
        let server_socket = socket.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            compio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = compio::net::UnixListener::bind(&server_socket).await.unwrap();
                    ready_tx.send(()).unwrap();
                    let snapshotter = test_snapshotter(&server_root);
                    let grpc = snapshots::server(Arc::new(snapshotter));
                    let app = snapshots::tonic::service::Routes::new(grpc).into_axum_router();
                    cyper_axum::serve(listener, app.into_make_service())
                        .await
                        .unwrap();
                });
        });
        ready_rx.recv().unwrap();

        compio::runtime::Runtime::new().unwrap().block_on(async move {
            let channel = crate::containerd_grpc::ContainerdChannel::new(&socket, "k8s.io");
            let mut client = SnapshotsClient::new(channel);
            let status = client
                .stat(StatSnapshotRequest {
                    snapshotter: String::new(),
                    key: "does-not-exist".to_string(),
                })
                .await
                .expect_err("stat of a missing snapshot should return a gRPC error");
```

Keep the assertions that follow `expect_err` in the original test unchanged, and close the
`block_on` the same way the original closed the tokio one. Update the test's doc comment to say
it runs the compio channel against the compio server over a Unix socket.

- [ ] **Step 2: Run the test**

Run the Linux gate with the last line replaced by `cargo test -p nydus-snapshotter grpc_transport_round_trips 2>&1 | grep -E "test |test result"`.
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add snapshotter/src/grpc/mod.rs
git commit -m "snapshotter: round-trip the gRPC server with the compio channel over a Unix socket

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Remove tokio and tonic's transport

**Files:**
- Modify: `snapshotter/Cargo.toml`

- [ ] **Step 1: Confirm nothing uses them**

Run: `grep -rnE "tokio|tonic::transport|hyper_util|tokio_stream" snapshotter/src snapshotter/tests snapshotter/build.rs`
Expected: only comments, e.g. the tonic-health comment in `grpc/mod.rs`. Any code hit means an
earlier task is incomplete; fix it before continuing.

- [ ] **Step 2: Edit the dependencies**

In `snapshotter/Cargo.toml`, replace the comment block that starts `# The snapshotter's own event
loop runs on compio; the ONE sanctioned tokio` and the lines up to `tonic-prost = "0.14"` with:

```toml
# Everything in the snapshotter runs on compio, including its gRPC client to containerd
# (containerd_grpc.rs: hyper HTTP/2 over a compio Unix socket via cyper-core). tonic supplies the
# generated clients and the codec only; its tokio transport is not built. tokio still appears in
# `cargo tree` as a type dependency of h2/hyper/tonic, but nothing starts a tokio runtime. See
# ARCHITECTURE.md Decision 3.
tonic = { version = "0.14", default-features = false, features = ["codegen"] }
tonic-prost = "0.14"
```

Delete the `hyper-util = { version = "0.1", features = ["client-legacy"] }` line.

- [ ] **Step 3: Check what features remain**

Run (inside the Linux gate container, replacing the last line):
`cargo tree -p nydus-snapshotter -e features -i tonic 2>&1 | grep -E "tonic feature" | sort -u`
Expected: `codegen`, plus whatever `containerd-snapshots` and `tonic-health` enable. If
`transport` still shows up, it comes from one of those crates through feature unification. That
is acceptable (it isn't used), but note in the PR which crate enables it.

Run: `cargo tree -p nydus-snapshotter -i tokio -e normal 2>&1 | head -20`
Record the output for the PR description. It shows the remaining type-only paths.

- [ ] **Step 4: Run the gate**

Run the Linux gate. Expected: green.

- [ ] **Step 5: Commit**

```bash
git add snapshotter/Cargo.toml Cargo.lock
git commit -m "snapshotter: drop tokio, tokio-stream, hyper-util and tonic's transport

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Integration test against a real containerd

**Files:**
- Create: `snapshotter/tests/containerd_client.rs`
- Create: `misc/containerd-grpc/client-test.sh`

The test starts its own containerd (temporary root, state and socket), so it never touches a
system containerd. It is `#[ignore]` because it needs root and a `containerd` binary.

- [ ] **Step 1: Write the integration test**

Create `snapshotter/tests/containerd_client.rs`:

```rust
// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! ContentStoreClient against a real containerd it starts itself. Needs root and `containerd`
//! on PATH; run through misc/containerd-grpc/client-test.sh.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nydus_snapshotter::config::ContainerdConfig;
use nydus_snapshotter::content_store::ContentStoreClient;

struct Containerd {
    child: Child,
    root: PathBuf,
}

impl Containerd {
    fn start(root: &Path) -> Self {
        let socket = root.join("containerd.sock");
        let _ = std::fs::remove_file(&socket);
        let child = Command::new("containerd")
            .arg("--root")
            .arg(root.join("root"))
            .arg("--state")
            .arg(root.join("state"))
            .arg("--address")
            .arg(&socket)
            .arg("--config")
            .arg("/dev/null")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start containerd (is it on PATH and are we root?)");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "containerd socket never appeared");
            std::thread::sleep(Duration::from_millis(100));
        }
        Self {
            child,
            root: root.to_path_buf(),
        }
    }

    fn config(&self) -> ContainerdConfig {
        ContainerdConfig {
            address: Some(self.root.join("containerd.sock")),
            namespace: "nydus-test".to_string(),
            content_root: Some(self.root.join("root/io.containerd.content.v1.content")),
        }
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Containerd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn labels() -> HashMap<String, String> {
    HashMap::from([("nydus.test/role".to_string(), "fixture".to_string())])
}

#[test]
#[ignore = "needs root and containerd; run misc/containerd-grpc/client-test.sh"]
fn content_and_images_round_trip_and_survive_a_containerd_restart() {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::start(dir.path());
    let client = ContentStoreClient::new(&containerd.config()).unwrap();

    compio::runtime::Runtime::new().unwrap().block_on(async {
        // Small blob: write, info, read back, labels applied.
        let small = client
            .write_bytes(b"hello containerd", "small", labels())
            .await
            .unwrap();
        let info = client.info(&small).await.unwrap().expect("blob present");
        assert_eq!(info.size, 16);
        assert_eq!(info.labels.get("nydus.test/role").unwrap(), "fixture");
        assert_eq!(client.fetch_bytes(&small).await.unwrap(), b"hello containerd");

        // Larger than tonic's 4 MiB default frame: exercises the raised encoding limit and a
        // multi-chunk Read stream.
        let big_path = dir.path().join("big.bin");
        let big: Vec<u8> = (0..6 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&big_path, &big).unwrap();
        let big_digest = client.write_blob(&big_path, labels()).await.unwrap();
        assert_eq!(client.fetch_bytes(&big_digest).await.unwrap(), big);

        // Image records.
        client
            .images_create("nydus.test/image:1", &small, 16, labels())
            .await
            .unwrap();
        let image = client
            .images_get("nydus.test/image:1")
            .await
            .unwrap()
            .expect("image present");
        assert_eq!(image.digest, small);
        assert!(
            client
                .images_list()
                .await
                .unwrap()
                .iter()
                .any(|r| r.name == "nydus.test/image:1")
        );
        client.images_delete("nydus.test/image:1").await.unwrap();
        assert!(client.images_get("nydus.test/image:1").await.unwrap().is_none());

        // An absent digest is NotFound, not an error.
        assert!(
            client
                .info("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .await
                .unwrap()
                .is_none()
        );
    });

    // Restart containerd: the cached connection dies, the next call must reconnect.
    containerd.stop();
    let containerd = Containerd::start(dir.path());
    compio::runtime::Runtime::new().unwrap().block_on(async {
        assert!(client.info(&small_digest_of(b"hello containerd")).await.unwrap().is_some());
    });

    // Stopped containerd: a prompt connection error, no hang.
    containerd.stop();
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let started = Instant::now();
        let err = client
            .info(&small_digest_of(b"hello containerd"))
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5), "call hung: {err:#}");
    });
}

fn small_digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}
```

Before running, check `images_create`'s actual signature in `content_store.rs` (the name, target
digest, size and labels parameters) and match the call above to it exactly. Also check that
`ContainerdConfig`'s fields are public (they are as of this plan: `address`, `namespace`,
`content_root`). If `sha2` is not a dev-dependency of the snapshotter, it is already a normal
dependency (content_store uses it), so the test can use it directly.

The restart phase uses a fresh compio runtime, as a real snapshotter restart of containerd would
look to the caller. The thread-local cache still holds the dead connection, so this also checks
that `is_closed()` is detected once the old runtime is gone.

- [ ] **Step 2: Write the runner script**

Create `misc/containerd-grpc/client-test.sh`:

```bash
#!/usr/bin/env bash
# Runs the ContentStoreClient integration test against a containerd the test starts itself.
# Needs Docker; runs as root inside the container so containerd can start.
set -euo pipefail
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/work -v nydus-cargo-registry:/usr/local/cargo/registry \
  -v nydus-target-containerd-grpc:/work/target -w /work rust:1.96-bookworm bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null
  apt-get install -y -qq pkg-config liblz4-dev uuid-dev cmake protobuf-compiler containerd >/dev/null 2>&1
  containerd --version
  cargo test -p nydus-snapshotter --test containerd_client -- --ignored --nocapture'
```

Run: `chmod +x misc/containerd-grpc/client-test.sh`

- [ ] **Step 3: Run it**

Run: `misc/containerd-grpc/client-test.sh 2>&1 | tail -15`
Expected: `containerd github.com/containerd/containerd …` then
`test content_and_images_round_trip_and_survive_a_containerd_restart ... ok`.

If the restart assertion fails with a request error, the dead connection was reused: confirm
`ContainerdChannel::send` forgets a closed sender and `sender()` filters `is_closed()`. Do not
add a retry loop; the spec rules it out.

- [ ] **Step 4: Commit**

```bash
git add snapshotter/tests/containerd_client.rs misc/containerd-grpc/client-test.sh
git commit -m "snapshotter: integration-test the content store client against a real containerd

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Documentation

**Files:**
- Modify: `CLAUDE.md` (the "Async runtime" coding convention and Key Gotcha 1)
- Modify: `ARCHITECTURE.md` (Decision 3)

- [ ] **Step 1: Find every description of the old exception**

Run: `grep -rn "sanctioned\|content_store.rs\|isolated 2-worker\|tokio runtime" CLAUDE.md ARCHITECTURE.md docs/*.md`
Every hit that describes a tokio runtime in `content_store.rs` is rewritten in the next steps.

- [ ] **Step 2: CLAUDE.md**

In the "Async runtime" convention, replace the sentence that starts
`**The one place a tokio runtime is deliberately spawned** is snapshotter/src/content_store.rs`
through `…compio still drives the snapshotter's own event loop.` with:

```markdown
**The snapshotter reaches containerd without tokio**: `snapshotter/src/containerd_grpc.rs`
provides `ContainerdChannel`, a tower service that speaks HTTP/2 over containerd's Unix socket
with hyper's client connection on compio (`cyper_core::{HyperStream, CompioExecutor,
CompioTimer}`). tonic contributes only generated clients and the codec (its `transport` feature
is off). Use `ContentClient::new(channel)`-style clients on that channel for any new containerd
service. The channel caches one connection per thread and sets the `containerd-namespace` header.
```

In the same paragraph, replace "none of it is tokio-driven — with **one sanctioned exception**
(below)" with "none of it is tokio-driven". Replace "Apart from that, the tokio crate in
`cargo tree` is only a type-compat dependency" with "The tokio crate in `cargo tree` is only a
type-compat dependency". Replace the final sentence "Do not hand any nydusd session thread a
tokio runtime handle of any kind, and do not add a second tokio runtime elsewhere without the
same quarantine." with "Do not start a tokio runtime anywhere in the snapshotter or nydusd."

- [ ] **Step 3: ARCHITECTURE.md Decision 3**

In Decision 3, replace the description of the quarantined tokio runtime in `content_store.rs`
with the same facts as the CLAUDE.md paragraph above: compio only, `containerd_grpc.rs`, tonic
codegen and codec without transport, one connection per thread, reconnect after close, no retry.
Keep the decision's rationale for avoiding tokio unchanged.

- [ ] **Step 4: Verify nothing stale remains**

Run: `grep -rn "sanctioned\|isolated 2-worker\|handle.block_on" CLAUDE.md ARCHITECTURE.md docs snapshotter/src`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md ARCHITECTURE.md
git commit -m "docs: the snapshotter reaches containerd over a compio gRPC channel

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Final gate, PR and canary

- [ ] **Step 1: Full workspace gate**

Run the Linux gate with the clippy and test lines changed to `--workspace`:
`cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`.
Expected: green. Run `make .no-error-macros` as well. Expected: success.

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin feat/compio-grpc-client
gh pr create -R PKizzle/nydus --base production --head feat/compio-grpc-client \
  --title "snapshotter: reach containerd over a compio-native gRPC channel"
```

The PR body covers:
- what changed: `ContainerdChannel`, `content_store.rs` without a runtime, and the dependencies
  removed;
- the spec link;
- the `cargo tree -i tokio` output from Task 6;
- the test evidence: unit tests, the server round-trip and the containerd integration script;
- the canary plan from the spec.

End the body with:
`🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

- [ ] **Step 3: Canary (after merge and release, with the user's go-ahead)**

On `raspberrypi-4-1` only, check over a soak of at least an hour:

```bash
sudo journalctl -u nydus-snapshotter --since "-1h" -o cat | grep -ciE "containerd (Info|Read|Write|Images)|failed to connect to containerd"
```

Expected: `0`. Also confirm that an auto-zran conversion uploads a sidecar ("auto-zran sidecar
uploaded") and that a pod start resolves a peer sidecar ("auto-accel sidecar discovered").
Only then roll out to the other nodes.
