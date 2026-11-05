// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! gRPC channel to containerd, driven by the compio runtime.
//!
//! tonic's generated clients only need a tower service that sends `http::Request`s with a tonic
//! body. [`ContainerdChannel`] is that service: it speaks HTTP/2 over containerd's Unix socket
//! with hyper's client connection, using cyper-core's compio executor, timer and stream adapter.
//! That is the stack the snapshotter's own gRPC server runs on, so reaching containerd needs no
//! tokio runtime.
//!
//! One connection per (thread, socket) is cached and multiplexed by HTTP/2. The connection task
//! runs on the calling thread's compio runtime (cyper's `HyperStream` is pinned to the thread
//! that created it), so the cache is thread-local rather than shared. A closed connection is
//! dropped and replaced on the next call; a failed call is reported, not retried, so a
//! containerd fault stays visible to the caller.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use cyper_core::{CompioExecutor, CompioTimer, HyperStream};
use http::header::HeaderValue;
use hyper::body::Incoming;
use hyper::client::conn::http2::{self, SendRequest};
use send_wrapper::SendWrapper;
use tracing::debug;

/// HTTP/2 PING interval. With `keep_alive_while_idle`, a containerd that went away is noticed
/// between calls instead of on the next one.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long a PING may go unanswered before the connection is considered dead.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// `:authority` of every request. containerd ignores it, but HTTP/2 requires one.
const AUTHORITY: &str = "containerd";

type Sender = SendRequest<tonic::body::Body>;

/// Outcome of the latest request to containerd from any channel: [`UNKNOWN`] before the first,
/// then [`REACHED`] if containerd answered (whatever the gRPC status) or [`UNREACHED`] if the
/// request failed with a [`ContainerdFault`], the same classification
/// [`containerd_fault`] gives callers. A stream that breaks after containerd's response
/// headers is seen only by the caller. Read by [`containerd_reachable`].
static REACHABLE: AtomicU8 = AtomicU8::new(UNKNOWN);
const UNKNOWN: u8 = 0;
const UNREACHED: u8 = 1;
const REACHED: u8 = 2;

/// Whether the latest request to containerd reached it; `None` before the first request.
pub fn containerd_reachable() -> Option<bool> {
    match REACHABLE.load(Ordering::Relaxed) {
        REACHED => Some(true),
        UNREACHED => Some(false),
        _ => None,
    }
}

thread_local! {
    /// Live connections of this thread, keyed by socket path.
    static CONNECTIONS: RefCell<HashMap<PathBuf, Sender>> = RefCell::new(HashMap::new());
}

/// What a failed containerd call says about containerd itself, as opposed to about the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerdFault {
    /// No answer: containerd's socket refuses connections or does not exist yet (its directory
    /// does), or the connection broke. Worth retrying once containerd is back.
    Unreachable,
    /// The configured socket path cannot work however long we wait: no permission, not a
    /// socket, or its directory does not exist.
    Misconfigured(PathBuf),
}

/// Classify a failed containerd call by its error chain. Only failures that never got an answer
/// from containerd count; a gRPC status containerd itself sent (decoded from its headers or
/// trailers, so with no source in the chain) is about the request, whatever its code, including
/// `Unavailable` and `DeadlineExceeded`. A status tonic builds from a transport error keeps that
/// error as its source, which is what this finds: a [`ChannelError`], or a `hyper::Error` other
/// than one about our own request body.
pub fn containerd_fault(error: &(dyn std::error::Error + 'static)) -> Option<ContainerdFault> {
    let mut cause = Some(error);
    while let Some(e) = cause {
        if let Some(channel) = e.downcast_ref::<ChannelError>() {
            return channel.fault();
        }
        if let Some(hyper) = e.downcast_ref::<hyper::Error>() {
            return (!hyper.is_user()).then_some(ContainerdFault::Unreachable);
        }
        cause = e.source();
    }
    None
}

/// Why a request to containerd failed before a gRPC status was received.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("failed to connect to containerd at {}", socket.display())]
    Connect {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP/2 handshake with containerd at {} failed", socket.display())]
    Handshake {
        socket: PathBuf,
        #[source]
        source: hyper::Error,
    },
    #[error("request to containerd at {} failed", socket.display())]
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

impl ChannelError {
    /// What this failure says about containerd; `None` for a local error about the request.
    pub fn fault(&self) -> Option<ContainerdFault> {
        match self {
            Self::Connect { socket, source } if connect_is_permanent(socket, source) => {
                Some(ContainerdFault::Misconfigured(socket.clone()))
            }
            Self::Connect { .. } => Some(ContainerdFault::Unreachable),
            Self::Handshake { source, .. } | Self::Request { source, .. } => {
                (!source.is_user()).then_some(ContainerdFault::Unreachable)
            }
            Self::Namespace(_) | Self::Uri(_) => None,
        }
    }
}

/// Whether connecting to `socket` failed in a way waiting cannot fix. A missing socket in an
/// existing directory, or one that refuses connections, is containerd not (yet) running; a
/// missing directory, a path that is not a socket, or no permission is configuration.
fn connect_is_permanent(socket: &Path, error: &std::io::Error) -> bool {
    match error.kind() {
        std::io::ErrorKind::NotFound => !socket.parent().is_some_and(Path::is_dir),
        // Also a path longer than `sun_path`, rejected before connect(2) with no errno.
        std::io::ErrorKind::InvalidInput => true,
        // connect(2) on a path that is not a socket fails ECONNREFUSED on Linux.
        std::io::ErrorKind::ConnectionRefused => {
            use std::os::unix::fs::FileTypeExt;
            std::fs::metadata(socket).is_ok_and(|m| !m.file_type().is_socket())
        }
        _ => matches!(
            error.raw_os_error(),
            Some(
                libc::EACCES
                    | libc::EPERM
                    | libc::ENOTSOCK
                    | libc::ENOTDIR
                    | libc::EINVAL
                    | libc::ENAMETOOLONG
                    | libc::ELOOP
                    | libc::EPROTOTYPE
            )
        ),
    }
}

/// The [`REACHABLE`] value a request's outcome sets; `None` leaves it, for a local error.
fn reachability<T>(result: &Result<T, ChannelError>) -> Option<u8> {
    match result {
        Ok(_) => Some(REACHED),
        Err(e) => e.fault().map(|_| UNREACHED),
    }
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
        let result = Self::exchange(&socket, request).await;
        if let Some(reachable) = reachability(&result) {
            REACHABLE.store(reachable, Ordering::Relaxed);
        }
        result
    }

    async fn exchange(
        socket: &Path,
        request: http::Request<tonic::body::Body>,
    ) -> Result<http::Response<Incoming>, ChannelError> {
        let mut sender = sender(socket).await?;
        let result = match sender.ready().await {
            Ok(()) => sender.send_request(request).await,
            Err(source) => Err(source),
        };
        if result.is_err() && sender.is_closed() {
            forget(socket);
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
    // `Send` because containerd-snapshots' handler futures must be `Send`, while compio's socket
    // future is not. `SendWrapper` asserts at poll time that the future stays on the thread that
    // created it, which compio guarantees (tasks never migrate) and the thread-local connection
    // cache already relies on. cyper-core wraps its stream the same way.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness is checked per request on the shared connection inside `call`.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        Box::pin(SendWrapper::new(Self::send(
            self.socket.clone(),
            self.namespace.clone(),
            request,
        )))
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
    CONNECTIONS.with(|c| c.borrow_mut().insert(socket.to_path_buf(), sender.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn connect_error(socket: &Path, error: std::io::Error) -> ChannelError {
        ChannelError::Connect {
            socket: socket.to_path_buf(),
            source: error,
        }
    }

    /// containerd not running yet (socket missing in its existing dir, or refusing) is an
    /// outage; a path that cannot work is configuration, and names the socket.
    #[test]
    fn connect_failures_split_into_outage_and_misconfiguration() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("containerd.sock");
        let enoent = || std::io::Error::from_raw_os_error(libc::ENOENT);
        let refused = || std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert_eq!(
            connect_error(&socket, enoent()).fault(),
            Some(ContainerdFault::Unreachable)
        );
        assert_eq!(
            connect_error(&socket, refused()).fault(),
            Some(ContainerdFault::Unreachable)
        );

        let misconfigured = |socket: &Path, error| {
            assert_eq!(
                connect_error(socket, error).fault(),
                Some(ContainerdFault::Misconfigured(socket.to_path_buf()))
            )
        };
        misconfigured(&dir.path().join("missing/containerd.sock"), enoent());
        for errno in [libc::EACCES, libc::ENOTSOCK, libc::EINVAL] {
            misconfigured(&socket, std::io::Error::from_raw_os_error(errno));
        }
        misconfigured(
            &socket,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path must be shorter than SUN_LEN",
            ),
        );
        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, b"").unwrap();
        misconfigured(&file, refused());

        assert_eq!(ChannelError::Namespace("bad".into()).fault(), None);
    }

    /// The gauge follows the same classification: a local error says nothing about containerd.
    #[test]
    fn reachability_follows_the_fault_classification() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("containerd.sock");
        assert_eq!(reachability::<()>(&Ok(())), Some(REACHED));
        let refused = connect_error(
            &socket,
            std::io::Error::from_raw_os_error(libc::ECONNREFUSED),
        );
        assert_eq!(reachability::<()>(&Err(refused)), Some(UNREACHED));
        let eacces = connect_error(&socket, std::io::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(reachability::<()>(&Err(eacces)), Some(UNREACHED));
        assert_eq!(
            reachability::<()>(&Err(ChannelError::Namespace("bad".into()))),
            None
        );
    }
    use std::thread::JoinHandle;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::{HealthCheckRequest, health_client::HealthClient};

    /// A tonic-health server on `socket`, run by cyper-axum on its own compio runtime as in
    /// production. Dropping the guard stops it: its runtime ends, closing every connection.
    struct TestServer {
        stop: Option<async_channel::Sender<()>>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestServer {
        fn start(socket: &Path) -> Self {
            Self::start_with(socket, |router| router)
        }

        /// Like `start`, with a hook to wrap the router (e.g. to capture request headers).
        fn start_with(
            socket: &Path,
            wrap: impl FnOnce(axum::Router) -> axum::Router + Send + 'static,
        ) -> Self {
            let _ = std::fs::remove_file(socket);
            let socket = socket.to_path_buf();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
            let thread = std::thread::spawn(move || {
                compio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(async move {
                        let listener = compio::net::UnixListener::bind(&socket).await.unwrap();
                        let (reporter, health) = tonic_health::server::health_reporter();
                        reporter
                            .set_service_status("", tonic_health::ServingStatus::Serving)
                            .await;
                        let app = wrap(tonic::service::Routes::new(health).into_axum_router());
                        ready_tx.send(()).unwrap();
                        let serve = std::future::IntoFuture::into_future(cyper_axum::serve(
                            listener,
                            app.into_make_service(),
                        ));
                        futures::future::select(Box::pin(serve), Box::pin(stop_rx.recv())).await;
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

    async fn check(channel: &ContainerdChannel) -> Result<ServingStatus, tonic::Status> {
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

    #[test]
    fn every_request_carries_the_containerd_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("grpc.sock");
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorder = seen.clone();
        let _server = TestServer::start_with(&socket, move |router| {
            router.layer(tower::util::MapRequestLayer::new(
                move |request: http::Request<axum::body::Body>| {
                    if let Some(ns) = request.headers().get("containerd-namespace") {
                        recorder
                            .lock()
                            .unwrap()
                            .push(ns.to_str().unwrap().to_string());
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
            let mut source = std::error::Error::source(&status);
            let mut found = false;
            while let Some(err) = source {
                if matches!(
                    err.downcast_ref::<ChannelError>(),
                    Some(ChannelError::Connect { .. })
                ) {
                    found = true;
                }
                source = err.source();
            }
            assert!(found, "no ChannelError::Connect in {status:?}");
        });
    }

    #[test]
    fn an_invalid_namespace_is_rejected_before_connecting() {
        let request = http::Request::new(tonic::body::Body::empty());
        let err = prepare(request, "bad\nnamespace").unwrap_err();
        assert!(matches!(err, ChannelError::Namespace(_)));
    }
}
