// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Help library to manage network connections.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Result};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI16, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fmt, thread};

use log::{Level, max_level};

use cyper::{Client, RequestBuilder};
use futures_util::StreamExt;
use http::{Method, StatusCode, header::HeaderMap};
use url::Url;

use nydus_api::{HttpProxyConfig, OssConfig, ProxyConfig, RegistryConfig, S3Config};
use url::ParseError;

const HEADER_AUTHORIZATION: &str = "Authorization";

const RATE_LIMITED_LOG_TIME: u8 = 2;

/// Monotonic id assigned to each `Connection`, used to key its per-thread cyper
/// clients in `HTTP_CLIENTS`.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Per-thread compio runtime to drive cyper's async HTTP on the synchronous
    /// backend read path. `Connection::call` is always invoked from a blocking
    /// pool thread (cache prefetch via `blocking::unblock`, on-demand reads via
    /// compio `spawn_blocking`), so this thread-local `block_on` never nests
    /// inside another compio runtime.
    static HTTP_RUNTIME: compio::runtime::Runtime =
        compio::runtime::Runtime::new().expect("storage: failed to create compio HTTP runtime");

    /// Per-thread cyper clients, keyed by `(connection id, is_proxy)`. cyper's
    /// `Client` is `!Send` (thread-per-core, `Rc`-based), so it cannot live in
    /// the `Arc`-shared `Connection`. Each worker/blocking thread instead builds
    /// and pools its own client lazily - the natural thread-per-core model.
    static HTTP_CLIENTS: RefCell<HashMap<(u64, bool), Client>> = RefCell::new(HashMap::new());
}

/// Drive a cyper future to completion on the thread-local HTTP runtime.
///
/// Also reused by the http-proxy backend so all backends share one compio HTTP
/// runtime per thread.
pub(crate) fn block_on_http<F: std::future::Future>(fut: F) -> F::Output {
    HTTP_RUNTIME.with(|rt| rt.block_on(fut))
}

thread_local! {
    pub static LAST_FALLBACK_AT: RefCell<SystemTime> = const { RefCell::new(UNIX_EPOCH) };
}

/// Error codes related to network communication.
#[derive(Debug)]
pub enum ConnectionError {
    Disconnected,
    ErrorWithMsg(String),
    Common(cyper::Error),
    Url(String, ParseError),
    Scheme(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::Disconnected => write!(f, "network connection disconnected"),
            ConnectionError::ErrorWithMsg(s) => write!(f, "network error, {}", s),
            ConnectionError::Common(e) => write!(f, "network error, {}", e),
            ConnectionError::Url(s, e) => write!(f, "failed to parse URL {}, {}", s, e),
            ConnectionError::Scheme(s) => write!(f, "invalid scheme {}", s),
        }
    }
}

/// Specialized `Result` for network communication.
type ConnectionResult<T> = std::result::Result<T, ConnectionError>;

/// Generic configuration for storage backends.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionConfig {
    pub proxy: ProxyConfig,
    pub skip_verify: bool,
    pub timeout: u32,
    pub connect_timeout: u32,
    pub retry_limit: u8,
    /// Paths to PEM-encoded CA certificate files to trust in addition to the system CA store.
    pub ca_cert_files: Vec<String>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            skip_verify: false,
            timeout: 5,
            connect_timeout: 5,
            retry_limit: 0,
            ca_cert_files: Vec::new(),
        }
    }
}

impl From<OssConfig> for ConnectionConfig {
    fn from(c: OssConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
            ca_cert_files: c.ca_cert_files,
        }
    }
}

impl From<S3Config> for ConnectionConfig {
    fn from(c: S3Config) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
            ca_cert_files: c.ca_cert_files,
        }
    }
}

impl From<RegistryConfig> for ConnectionConfig {
    fn from(c: RegistryConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
            ca_cert_files: c.ca_cert_files,
        }
    }
}

impl From<HttpProxyConfig> for ConnectionConfig {
    fn from(c: HttpProxyConfig) -> ConnectionConfig {
        ConnectionConfig {
            proxy: c.proxy,
            skip_verify: c.skip_verify,
            timeout: c.timeout,
            connect_timeout: c.connect_timeout,
            retry_limit: c.retry_limit,
            ca_cert_files: c.ca_cert_files,
        }
    }
}

/// HTTP request data with progress callback.
#[derive(Clone)]
pub struct Progress<R> {
    inner: R,
    current: usize,
    total: usize,
    callback: fn((usize, usize)),
}

impl<R> Progress<R> {
    /// Create a new `Progress` object.
    pub fn new(r: R, total: usize, callback: fn((usize, usize))) -> Progress<R> {
        Progress {
            inner: r,
            current: 0,
            total,
            callback,
        }
    }
}

impl<R: Read + Send + 'static> Read for Progress<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf).inspect(|&count| {
            self.current += count;
            (self.callback)((self.current, self.total));
        })
    }
}

/// HTTP request data to send to server.
#[derive(Clone)]
pub enum ReqBody<R: Clone> {
    Read(Progress<R>, usize),
    Buf(Vec<u8>),
    Form(HashMap<String, String>),
}

#[derive(Debug)]
struct ProxyHealth {
    status: AtomicBool,
    ping_url: Option<Url>,
    check_interval: Duration,
    check_pause_elapsed: u64,
}

impl ProxyHealth {
    fn new(check_interval: u64, check_pause_elapsed: u64, ping_url: Option<Url>) -> Self {
        ProxyHealth {
            status: AtomicBool::from(true),
            ping_url,
            check_interval: Duration::from_secs(check_interval),
            check_pause_elapsed,
        }
    }

    fn ok(&self) -> bool {
        self.status.load(Ordering::Relaxed)
    }

    fn set(&self, health: bool) {
        self.status.store(health, Ordering::Relaxed);
    }
}

const SCHEME_REVERSION_CACHE_UNSET: i16 = 0;
const SCHEME_REVERSION_CACHE_REPLACE: i16 = 1;
const SCHEME_REVERSION_CACHE_RETAIN: i16 = 2;

#[derive(Debug)]
struct Proxy {
    health: ProxyHealth,
    fallback: bool,
    use_http: bool,
    // Cache whether should try to replace scheme for proxy url.
    replace_scheme: AtomicI16,
}

#[derive(Debug, Default)]
struct HealthCheckerStop {
    stopped: Mutex<bool>,
    wakeup: Condvar,
}

impl HealthCheckerStop {
    fn stop(&self) {
        *self.stopped.lock().unwrap() = true;
        self.wakeup.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let stopped = self.stopped.lock().unwrap();
        let (stopped, _result) = self
            .wakeup
            .wait_timeout_while(stopped, timeout, |s| !*s)
            .unwrap();
        *stopped
    }

    fn is_stopped(&self) -> bool {
        *self.stopped.lock().unwrap()
    }
}

impl Proxy {
    fn try_use_http(&self, url: &str) -> Option<String> {
        if self.replace_scheme.load(Ordering::Relaxed) == SCHEME_REVERSION_CACHE_REPLACE {
            Some(url.replacen("https", "http", 1))
        } else if self.replace_scheme.load(Ordering::Relaxed) == SCHEME_REVERSION_CACHE_UNSET {
            if url.starts_with("https:") {
                self.replace_scheme
                    .store(SCHEME_REVERSION_CACHE_REPLACE, Ordering::Relaxed);
                info!("Will replace backend's URL's scheme with http");
                Some(url.replacen("https", "http", 1))
            } else if url.starts_with("http:") {
                self.replace_scheme
                    .store(SCHEME_REVERSION_CACHE_RETAIN, Ordering::Relaxed);
                None
            } else {
                warn!("Can't replace http scheme, url {}", url);
                None
            }
        } else {
            None
        }
    }
}

/// A buffered HTTP response.
///
/// cyper's `Response` body is async, but the backend read path is synchronous.
/// The body is read fully into memory once (via `block_on_http`) and then
/// exposed through `std::io::Read` plus `status()`/`headers()`, matching the
/// surface the cache and `request.rs` previously consumed from the old
/// blocking HTTP response.
// `pub` (not `pub(crate)`) so it is at least as visible as the public
// `request::Response::Http` variant that wraps it. The fields stay private, so
// the type remains opaque to external callers.
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    // `bytes::Bytes` is Arc-backed, so wrapping it in a `Cursor` exposes the
    // buffered body through `Read` without an extra copy.
    body: std::io::Cursor<bytes::Bytes>,
}

impl Response {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consume the response and return its body as a (lossy) UTF-8 string.
    pub(crate) fn text(self) -> String {
        String::from_utf8_lossy(&self.body.into_inner()).into_owned()
    }

    /// Copy the not-yet-consumed body directly into `dst`, returning the number
    /// of bytes written. Unlike `std::io::copy` over the `Read` impl, this is a
    /// single `Bytes`->`dst` `memcpy` with no intermediate buffer - important on
    /// the blob read hot path, where the destination is a chunk-sized slice.
    pub(crate) fn copy_to_slice(&mut self, dst: &mut [u8]) -> usize {
        let pos = self.body.position() as usize;
        let src = &self.body.get_ref()[pos..];
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src[..n]);
        self.body.set_position((pos + n) as u64);
        n
    }
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.body.read(buf)
    }
}

#[cfg(test)]
impl<B: Into<bytes::Bytes>> From<http::Response<B>> for Response {
    fn from(resp: http::Response<B>) -> Self {
        let (parts, body) = resp.into_parts();
        Response {
            status: parts.status,
            headers: parts.headers,
            body: std::io::Cursor::new(body.into()),
        }
    }
}

/// Check whether the HTTP status code is a success result.
pub(crate) fn is_success_status(status: StatusCode) -> bool {
    status >= StatusCode::OK && status < StatusCode::BAD_REQUEST
}

/// Convert a HTTP `Response` into an `Result<Response>`.
pub(crate) fn respond(resp: Response, catch_status: bool) -> ConnectionResult<Response> {
    if !catch_status || is_success_status(resp.status()) {
        Ok(resp)
    } else {
        Err(ConnectionError::ErrorWithMsg(resp.text()))
    }
}

/// A network connection to communicate with remote server.
#[derive(Debug)]
pub(crate) struct Connection {
    /// Identifies this connection's per-thread cyper clients in `HTTP_CLIENTS`.
    id: u64,
    /// Backend config used to lazily build per-thread cyper clients.
    config: ConnectionConfig,
    proxy: Option<Arc<Proxy>>,
    pub shutdown: AtomicBool,
    /// Per-request timeout. cyper has no builtin timeout, so it is applied via
    /// `compio::time::timeout`. `None` means no timeout.
    timeout: Option<Duration>,
    /// Timestamp of connection's last active request, represents as duration since UNIX_EPOCH in seconds.
    last_active: Arc<AtomicU64>,
    health_checker_stop: Arc<HealthCheckerStop>,
}

impl Connection {
    /// Create a new connection according to the configuration.
    pub fn new(config: &ConnectionConfig) -> Result<Arc<Connection>> {
        info!("backend config: {:?}", config);
        // Per-thread cyper clients are built lazily inside the compio runtime
        // (cyper's hickory resolver needs `Runtime::current()` at build time).

        let proxy = if !config.proxy.url.is_empty() {
            let ping_url = if !config.proxy.ping_url.is_empty() {
                Some(Url::from_str(&config.proxy.ping_url).map_err(|e| einval!(e))?)
            } else {
                None
            };
            Some(Arc::new(Proxy {
                health: ProxyHealth::new(
                    config.proxy.check_interval,
                    config.proxy.check_pause_elapsed,
                    ping_url,
                ),
                fallback: config.proxy.fallback,
                use_http: config.proxy.use_http,
                replace_scheme: AtomicI16::new(SCHEME_REVERSION_CACHE_UNSET),
            }))
        } else {
            None
        };

        let connection = Arc::new(Connection {
            id: CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            config: config.clone(),
            proxy,
            shutdown: AtomicBool::new(false),
            timeout: if config.timeout != 0 {
                Some(Duration::from_secs(config.timeout as u64))
            } else {
                None
            },
            last_active: Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )),
            health_checker_stop: Arc::new(HealthCheckerStop::default()),
        });

        // Start proxy's health checking thread.
        connection.start_proxy_health_thread(config.connect_timeout as u64);

        Ok(connection)
    }

    fn start_proxy_health_thread(&self, connect_timeout: u64) {
        if let Some(proxy) = self.proxy.as_ref()
            && proxy.health.ping_url.is_some()
        {
            let proxy = proxy.clone();
            let last_active = Arc::clone(&self.last_active);
            let stop = Arc::clone(&self.health_checker_stop);

            // Spawn thread to update the health status of proxy server.
            thread::spawn(move || {
                let ping_url = proxy.health.ping_url.as_ref().unwrap();
                let mut last_success = true;

                loop {
                    if stop.is_stopped() {
                        break;
                    }
                    let elapsed = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - last_active.load(Ordering::Relaxed);
                    // If the connection is not active for a set time, skip proxy health check.
                    if elapsed <= proxy.health.check_pause_elapsed {
                        let ping: ConnectionResult<StatusCode> = block_on_http(async {
                            let client = Client::new().map_err(ConnectionError::Common)?;
                            let rb = client
                                .get(ping_url.clone())
                                .map_err(ConnectionError::Common)?;
                            match compio::runtime::time::timeout(
                                Duration::from_secs(connect_timeout),
                                rb.send(),
                            )
                            .await
                            {
                                Ok(r) => Ok(r.map_err(ConnectionError::Common)?.status()),
                                Err(_) => Err(ConnectionError::ErrorWithMsg(
                                    "proxy ping timed out".to_string(),
                                )),
                            }
                        });
                        match ping {
                            Ok(status) => {
                                let success = is_success_status(status);
                                if last_success && !success {
                                    warn!(
                                        "Detected proxy unhealthy when pinging proxy, response status {}",
                                        status
                                    );
                                } else if !last_success && success {
                                    info!("Backend proxy recovered")
                                }
                                last_success = success;
                                proxy.health.set(success);
                            }
                            Err(e) => {
                                if last_success {
                                    warn!("Detected proxy unhealthy when ping proxy, {}", e);
                                }
                                last_success = false;
                                proxy.health.set(false);
                            }
                        }
                    }

                    // Interruptible wait: shutdown/Drop wakes the worker
                    // instead of leaving it to sleep out the full interval.
                    if stop.wait(proxy.health.check_interval) {
                        break;
                    }
                }
            });
        }
    }

    /// Shutdown the connection.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.health_checker_stop.stop();
    }

    pub fn call<R: Read + Clone + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &mut HeaderMap,
        catch_status: bool,
    ) -> ConnectionResult<Response> {
        self.call_with_proxy_control(method, url, query, data, headers, catch_status, false)
    }

    /// Like `call()`, but when `skip_proxy` is true, bypass the HTTP proxy
    /// entirely and go direct to the origin. Used for auth token requests
    /// that must not have their URL scheme rewritten by `use_http`.
    #[allow(clippy::too_many_arguments)]
    pub fn call_with_proxy_control<R: Read + Clone + Send + 'static>(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &mut HeaderMap,
        catch_status: bool,
        skip_proxy: bool,
    ) -> ConnectionResult<Response> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ConnectionError::Disconnected);
        }
        self.last_active.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );

        if !skip_proxy && let Some(proxy) = &self.proxy {
            if proxy.health.ok() {
                let data_cloned = data.as_ref().cloned();

                let http_url: Option<String>;
                let mut replaced_url = url;

                if proxy.use_http {
                    http_url = proxy.try_use_http(url);
                    if let Some(ref r) = http_url {
                        replaced_url = r.as_str();
                    }
                }

                debug!(
                    "connection: routing via PROXY (fallback={}), url={} -> {}",
                    proxy.fallback, url, replaced_url,
                );

                let result = self.call_inner(
                    true,
                    method.clone(),
                    replaced_url,
                    &query,
                    data_cloned,
                    headers,
                    catch_status,
                    true,
                );

                match result {
                    Ok(resp) => {
                        debug!(
                            "connection: proxy returned status={}, fallback={}",
                            resp.status(),
                            proxy.fallback,
                        );
                        if !proxy.fallback || resp.status() < StatusCode::INTERNAL_SERVER_ERROR {
                            return Ok(resp);
                        }
                    }
                    Err(err) => {
                        warn!("Request proxy server failed: {:?}", err);
                        if !proxy.fallback {
                            return Err(err);
                        }
                    }
                }
                // If proxy server responds invalid status code or http connection failed, we need to
                // fallback to origin server, the policy only applicable to non-upload operation
                warn!("Request proxy server failed, fallback to original server");
            } else {
                if !proxy.fallback {
                    return Err(ConnectionError::ErrorWithMsg(
                        "proxy is not healthy and fallback is disabled".to_string(),
                    ));
                }
                LAST_FALLBACK_AT.with(|f| {
                    let current = SystemTime::now();
                    if current.duration_since(*f.borrow()).unwrap().as_secs()
                        >= RATE_LIMITED_LOG_TIME as u64
                    {
                        warn!("Proxy server is not healthy, fallback to original server");
                        f.replace(current);
                    }
                })
            }
        } // end if !skip_proxy

        debug!(
            "connection: routing DIRECT (no proxy or fallback), url={}",
            url
        );
        self.call_inner(
            false,
            method,
            url,
            &query,
            data,
            headers,
            catch_status,
            false,
        )
    }

    fn build_connection(proxy: &str, config: &ConnectionConfig) -> Result<Client> {
        // Note: cyper has no client-level request/connect timeout; the request
        // timeout is applied per-call via `compio::time::timeout` in `call_inner`.
        let mut cb = Client::builder()
            // Disable automatic redirect following so that registry.rs can
            // cache 307 redirect URLs (cached_redirect) and skip the registry
            // round-trip on subsequent chunk reads from the same blob.
            .redirect(cyper::redirect::Policy::none())
            // Resolve DNS through cyper's bundled hickory resolver.
            .hickory_dns(true);

        // TLS trust: `skip_verify` wins (verification is off entirely, extra
        // roots would be meaningless), then `ca_cert_files` extends the
        // platform store, then the cyper default (platform store only).
        cb = if config.skip_verify {
            cb.use_rustls_default().danger_accept_invalid_certs(true)
        } else if !config.ca_cert_files.is_empty() {
            cb.use_rustls(client_config_with_extra_roots(&config.ca_cert_files)?)
        } else {
            cb.use_rustls_default()
        };

        if !proxy.is_empty() {
            cb = cb.proxy(cyper::proxy::Proxy::all(proxy).map_err(|e| einval!(e))?)
        } else {
            // Explicitly disable system proxy (HTTP_PROXY/HTTPS_PROXY env vars)
            // so that the direct client truly bypasses any proxy, especially when
            // retry_op() sets disable_proxy=true for fallback to origin.
            cb = cb.no_proxy()
        }

        cb.build().map_err(|e| einval!(e))
    }

    #[allow(clippy::too_many_arguments)]
    fn call_inner<R: Read + Clone + Send + 'static>(
        &self,
        is_proxy: bool,
        method: Method,
        url: &str,
        query: &Option<&[(&str, &str)]>,
        data: Option<ReqBody<R>>,
        headers: &HeaderMap,
        catch_status: bool,
        proxy: bool,
    ) -> ConnectionResult<Response> {
        // Only clone header when debugging to reduce potential overhead.
        let display_headers = if max_level() >= Level::Debug {
            let mut display_headers = headers.clone();
            display_headers.remove(HEADER_AUTHORIZATION);
            Some(display_headers)
        } else {
            None
        };
        let has_data = data.is_some();
        let start = Instant::now();

        // cyper is async and its hickory resolver needs `Runtime::current()` at
        // client-build time, so build the per-thread client, construct the
        // request, and run it on the thread-local compio runtime. The cache
        // borrow and the built `RequestBuilder` (which owns an `Rc` clone of the
        // client) are released before the first `.await`.
        let timeout = self.timeout;
        let url_owned = url.to_string();
        let req_method = method.clone();
        let result: ConnectionResult<Response> = block_on_http(async move {
            let rb = HTTP_CLIENTS.with(|clients| -> ConnectionResult<RequestBuilder> {
                let mut clients = clients.borrow_mut();
                let key = (self.id, is_proxy);
                if let std::collections::hash_map::Entry::Vacant(e) = clients.entry(key) {
                    let proxy_url = if is_proxy {
                        self.config.proxy.url.as_str()
                    } else {
                        ""
                    };
                    let client = Self::build_connection(proxy_url, &self.config).map_err(|e| {
                        ConnectionError::ErrorWithMsg(format!("failed to build HTTP client: {e}"))
                    })?;
                    e.insert(client);
                }
                let client = clients.get(&key).unwrap();

                let mut rb = client
                    .request(req_method, url)
                    .map_err(ConnectionError::Common)?
                    .headers(headers.clone());
                if let Some(q) = query.as_ref() {
                    rb = rb.query(q).map_err(ConnectionError::Common)?;
                }
                if let Some(data) = data {
                    rb = match data {
                        ReqBody::Read(mut body, _total) => {
                            // cyper has no streaming-from-`Read` body; buffer the
                            // upload payload (registry push path, not blob reads).
                            let mut buf = Vec::new();
                            body.read_to_end(&mut buf).map_err(|e| {
                                ConnectionError::ErrorWithMsg(format!("read request body: {e}"))
                            })?;
                            rb.body(buf)
                        }
                        ReqBody::Buf(buf) => rb.body(buf),
                        ReqBody::Form(form) => rb.form(&form).map_err(ConnectionError::Common)?,
                    };
                } else {
                    rb = rb.body(Vec::<u8>::new());
                }
                Ok(rb)
            })?;

            let send = rb.send();
            let cyper_resp = match timeout {
                Some(t) => match compio::runtime::time::timeout(t, send).await {
                    Ok(r) => r.map_err(ConnectionError::Common)?,
                    Err(_) => {
                        return Err(ConnectionError::ErrorWithMsg(format!(
                            "request to {url_owned} timed out"
                        )));
                    }
                },
                None => send.await.map_err(ConnectionError::Common)?,
            };
            let status = cyper_resp.status();
            let resp_headers = cyper_resp.headers().clone();
            let body = cyper_resp.bytes().await.map_err(ConnectionError::Common)?;
            Ok(Response {
                status,
                headers: resp_headers,
                body: std::io::Cursor::new(body),
            })
        });

        debug!(
            "{} Request: {} {} headers: {:?}, proxy: {}, data: {}, duration: {}ms",
            std::thread::current().name().unwrap_or_default(),
            method,
            url,
            display_headers,
            proxy,
            has_data,
            Instant::now().duration_since(start).as_millis(),
        );

        result.and_then(|resp| respond(resp, catch_status))
    }

    /// Streaming variant of `call_inner` for the blob read path: stream the
    /// response body directly into `dst` (no full-body allocation) and return
    /// `(status, bytes_written, error_body)`. Used only for GET range reads, so
    /// there is no request body.
    fn call_inner_stream(
        &self,
        is_proxy: bool,
        method: Method,
        url: &str,
        query: &Option<&[(&str, &str)]>,
        headers: &HeaderMap,
        dst: &mut [u8],
    ) -> ConnectionResult<(StatusCode, usize, Option<String>)> {
        let timeout = self.timeout;
        let url_owned = url.to_string();
        let req_method = method.clone();
        block_on_http(async move {
            let rb = HTTP_CLIENTS.with(|clients| -> ConnectionResult<RequestBuilder> {
                let mut clients = clients.borrow_mut();
                let key = (self.id, is_proxy);
                if let std::collections::hash_map::Entry::Vacant(e) = clients.entry(key) {
                    let proxy_url = if is_proxy {
                        self.config.proxy.url.as_str()
                    } else {
                        ""
                    };
                    let client = Self::build_connection(proxy_url, &self.config).map_err(|e| {
                        ConnectionError::ErrorWithMsg(format!("failed to build HTTP client: {e}"))
                    })?;
                    e.insert(client);
                }
                let client = clients.get(&key).unwrap();
                let mut rb = client
                    .request(req_method, url)
                    .map_err(ConnectionError::Common)?
                    .headers(headers.clone());
                if let Some(q) = query.as_ref() {
                    rb = rb.query(q).map_err(ConnectionError::Common)?;
                }
                Ok(rb.body(Vec::<u8>::new()))
            })?;

            let send = rb.send();
            let resp = match timeout {
                Some(t) => match compio::runtime::time::timeout(t, send).await {
                    Ok(r) => r.map_err(ConnectionError::Common)?,
                    Err(_) => {
                        return Err(ConnectionError::ErrorWithMsg(format!(
                            "request to {url_owned} timed out"
                        )));
                    }
                },
                None => send.await.map_err(ConnectionError::Common)?,
            };

            let status = resp.status();
            if is_success_status(status) {
                // Stream the body straight into `dst` - no full-body allocation.
                let mut written = 0usize;
                let mut stream = resp.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(ConnectionError::Common)?;
                    if written >= dst.len() {
                        break;
                    }
                    let n = chunk.len().min(dst.len() - written);
                    dst[written..written + n].copy_from_slice(&chunk[..n]);
                    written += n;
                }
                Ok((status, written, None))
            } else {
                // Buffer the (small) error body for the caller's message.
                let body = resp.bytes().await.map_err(ConnectionError::Common)?;
                Ok((status, 0, Some(String::from_utf8_lossy(&body).into_owned())))
            }
        })
    }

    /// Streaming counterpart of `call` for the blob read path: routes through the
    /// proxy with origin fallback like the buffered path, but streams the
    /// response body into `dst` and returns the number of bytes written.
    /// Proxy-aware streaming core: streams the response body into `dst` and
    /// returns `(status, bytes_written, error_body)` *without* applying
    /// `catch_status`. Callers decide how to treat the status (e.g. registry
    /// inspects 307/401/403 itself). Shared by `call_stream` and
    /// `call_stream_status`.
    fn call_stream_status_err(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        headers: &HeaderMap,
        skip_proxy: bool,
        dst: &mut [u8],
    ) -> ConnectionResult<(StatusCode, usize, Option<String>)> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ConnectionError::Disconnected);
        }
        self.last_active.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );

        if !skip_proxy && let Some(proxy) = &self.proxy {
            if proxy.health.ok() {
                let http_url: Option<String>;
                let mut replaced_url = url;
                if proxy.use_http {
                    http_url = proxy.try_use_http(url);
                    if let Some(ref r) = http_url {
                        replaced_url = r.as_str();
                    }
                }
                let (status, written, err) = self.call_inner_stream(
                    true,
                    method.clone(),
                    replaced_url,
                    &query,
                    headers,
                    &mut *dst,
                )?;
                if !proxy.fallback || status < StatusCode::INTERNAL_SERVER_ERROR {
                    return Ok((status, written, err));
                }
                warn!("Request proxy server failed, fallback to original server");
            } else if !proxy.fallback {
                return Err(ConnectionError::ErrorWithMsg(
                    "proxy is not healthy and fallback is disabled".to_string(),
                ));
            }
        }

        self.call_inner_stream(false, method, url, &query, headers, dst)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_stream(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        headers: &HeaderMap,
        catch_status: bool,
        skip_proxy: bool,
        dst: &mut [u8],
    ) -> ConnectionResult<usize> {
        let (status, written, err) =
            self.call_stream_status_err(method, url, query, headers, skip_proxy, dst)?;
        if catch_status && !is_success_status(status) {
            return Err(ConnectionError::ErrorWithMsg(err.unwrap_or_default()));
        }
        Ok(written)
    }

    /// Like `call_stream`, but returns the HTTP status alongside the byte count
    /// instead of folding non-success into an error. Used by the registry blob
    /// read path, which must distinguish 200 (stream the blob) from 401/403 (a
    /// stale cached redirect to retry).
    pub fn call_stream_status(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        headers: &HeaderMap,
        skip_proxy: bool,
        dst: &mut [u8],
    ) -> ConnectionResult<(StatusCode, usize)> {
        let (status, written, _err) =
            self.call_stream_status_err(method, url, query, headers, skip_proxy, dst)?;
        Ok((status, written))
    }
}

/// rustls `ClientConfig` trusting the platform verifier's roots plus the PEM
/// roots in `ca_cert_files` (for registries signed by a private CA). Mirrors
/// what cyper builds for `use_rustls_default()` — platform verifier, ring
/// provider, ALPN `h2` + `http/1.1` — so behaviour differs only by the extra
/// roots. ALPN must be set here: cyper passes a custom config through
/// untouched, and omitting it silently downgrades HTTP/2 negotiation.
/// (Same helper as `registry_client::tls`; duplicated because storage sits
/// below the OCI client in the crate graph.)
fn client_config_with_extra_roots(
    ca_cert_files: &[String],
) -> Result<std::sync::Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let mut extra_roots: Vec<CertificateDer<'static>> = Vec::new();
    for path in ca_cert_files {
        let before = extra_roots.len();
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| einval!(format!("open CA cert file {path}: {e}")))?;
        for cert in certs {
            extra_roots.push(cert.map_err(|e| einval!(format!("parse CA cert file {path}: {e}")))?);
        }
        if extra_roots.len() == before {
            return Err(einval!(format!("no CA certificates found in {path}")));
        }
    }

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider.clone())
            .map_err(|e| einval!(format!("build certificate verifier with extra roots: {e}")))?;

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| einval!(format!("select rustls protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(std::sync::Arc::new(config))
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.health_checker_stop.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_progress() {
        let buf = vec![0x1u8, 2, 3, 4, 5];
        let mut progress = Progress::new(Cursor::new(buf), 5, |(curr, total)| {
            assert!(curr == 2 || curr == 4);
            assert_eq!(total, 5);
        });

        let mut buf1 = [0x0u8; 2];
        assert_eq!(progress.read(&mut buf1).unwrap(), 2);
        assert_eq!(buf1[0], 1);
        assert_eq!(buf1[1], 2);

        assert_eq!(progress.read(&mut buf1).unwrap(), 2);
        assert_eq!(buf1[0], 3);
        assert_eq!(buf1[1], 4);
    }

    #[test]
    fn test_proxy_health() {
        let checker = ProxyHealth::new(5, 300, None);

        assert!(checker.ok());
        assert!(checker.ok());
        checker.set(false);
        assert!(!checker.ok());
        assert!(!checker.ok());
        checker.set(true);
        assert!(checker.ok());
        assert!(checker.ok());
    }

    #[test]
    fn test_is_success_status() {
        assert!(!is_success_status(StatusCode::CONTINUE));
        assert!(is_success_status(StatusCode::OK));
        assert!(is_success_status(StatusCode::PERMANENT_REDIRECT));
        assert!(!is_success_status(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn test_connection_config_default() {
        let config = ConnectionConfig::default();

        assert_eq!(config.timeout, 5);
        assert_eq!(config.connect_timeout, 5);
        assert_eq!(config.retry_limit, 0);
        assert_eq!(config.proxy.check_interval, 5);
        assert_eq!(config.proxy.check_pause_elapsed, 300);
        assert!(config.proxy.fallback);
        assert_eq!(config.proxy.ping_url, "");
        assert_eq!(config.proxy.url, "");
        assert!(config.ca_cert_files.is_empty());
    }

    /// Helper to create a Connection with a proxy for testing fallback behavior.
    fn make_connection_with_proxy(proxy_url: &str, fallback: bool) -> Arc<Connection> {
        let config = ConnectionConfig {
            proxy: ProxyConfig {
                url: proxy_url.to_string(),
                fallback,
                check_interval: 5,
                check_pause_elapsed: 300,
                ..Default::default()
            },
            ..Default::default()
        };
        Connection::new(&config).unwrap()
    }

    #[test]
    fn test_unhealthy_proxy_no_fallback_returns_error() {
        // When proxy is unhealthy and fallback is disabled, call() must return
        // an error immediately without attempting the origin server.
        let conn = make_connection_with_proxy("http://127.0.0.1:1", false);

        // Mark proxy as unhealthy
        conn.proxy.as_ref().unwrap().health.set(false);

        let mut headers = HeaderMap::new();
        let result = conn.call::<Cursor<Vec<u8>>>(
            Method::GET,
            "http://127.0.0.1:1/test",
            None,
            None,
            &mut headers,
            true,
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("proxy is not healthy and fallback is disabled"),
            "Expected 'proxy is not healthy and fallback is disabled' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_unhealthy_proxy_with_fallback_attempts_origin() {
        // When proxy is unhealthy but fallback IS enabled, call() should
        // fall through to the origin server (which will fail with a connection
        // error here since the URL is unreachable, but NOT with the
        // "fallback is disabled" error).
        let conn = make_connection_with_proxy("http://127.0.0.1:1", true);

        // Mark proxy as unhealthy
        conn.proxy.as_ref().unwrap().health.set(false);

        let mut headers = HeaderMap::new();
        let result = conn.call::<Cursor<Vec<u8>>>(
            Method::GET,
            "http://127.0.0.1:1/test",
            None,
            None,
            &mut headers,
            true,
        );

        // Should fail (unreachable server) but NOT with "fallback is disabled"
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            !err_msg.contains("fallback is disabled"),
            "Should not get 'fallback is disabled' error when fallback=true, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_healthy_proxy_no_fallback_returns_proxy_error() {
        // When proxy is healthy and fallback is disabled, a failed proxy request
        // should return the proxy error directly without falling back.
        let conn = make_connection_with_proxy("http://127.0.0.1:1", false);

        // Proxy stays healthy (default)
        assert!(conn.proxy.as_ref().unwrap().health.ok());

        let mut headers = HeaderMap::new();
        let result = conn.call::<Cursor<Vec<u8>>>(
            Method::GET,
            "http://127.0.0.1:1/test",
            None,
            None,
            &mut headers,
            true,
        );

        // Should fail with the proxy connection error, not fallback
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            !err_msg.contains("fallback is disabled"),
            "Should get proxy error, not fallback error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_disconnected_connection_returns_error() {
        // Verify that a shutdown connection returns Disconnected error
        // regardless of proxy state.
        let conn = make_connection_with_proxy("http://127.0.0.1:1", false);
        conn.shutdown();

        let mut headers = HeaderMap::new();
        let result = conn.call::<Cursor<Vec<u8>>>(
            Method::GET,
            "http://127.0.0.1:1/test",
            None,
            None,
            &mut headers,
            true,
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("disconnected"),
            "Expected disconnected error, got: {}",
            err_msg
        );
    }

    fn health_check_connection() -> Arc<Connection> {
        let config = ConnectionConfig {
            connect_timeout: 1,
            proxy: ProxyConfig {
                url: "http://127.0.0.1:1".to_string(),
                ping_url: "http://127.0.0.1:1/healthy".to_string(),
                check_interval: 3600,
                check_pause_elapsed: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        Connection::new(&config).unwrap()
    }

    fn wait_for_proxy_owners(proxy: &std::sync::Weak<Proxy>, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while proxy.strong_count() != expected && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(proxy.strong_count(), expected);
    }

    #[test]
    fn test_shutdown_stops_proxy_health_checker() {
        let conn = health_check_connection();
        let proxy = Arc::downgrade(conn.proxy.as_ref().unwrap());

        conn.shutdown();

        // The connection still owns one reference; the worker must release its copy.
        wait_for_proxy_owners(&proxy, 1);
    }

    #[test]
    fn test_drop_stops_proxy_health_checker() {
        let conn = health_check_connection();
        let proxy = Arc::downgrade(conn.proxy.as_ref().unwrap());

        drop(conn);

        wait_for_proxy_owners(&proxy, 0);
    }
}
