// Copyright 2023 Ant Group. All rights reserved.

// SPDX-License-Identifier: Apache-2.0

// ! Storage backend driver to access the blobs through a http proxy.

use compio::net::UnixStream;
use cyper_core::HyperStream;
use http::{HeaderMap, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use nydus_api::HttpProxyConfig;
use nydus_utils::metrics::BackendMetrics;

use super::connection::{Connection, ConnectionConfig, ConnectionError, block_on_http};
use super::{BackendContext, BackendError, BackendResult, BlobBackend, BlobReader};
use crate::backend::request;
use std::path::Path;
use std::{
    io::Error,
    num::ParseIntError,
    str::{self},
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    /// Failed to parse string to integer.
    #[error("failed to parse string to integer, {0}")]
    ParseStringToInteger(#[source] ParseIntError),
    /// The `Content-Length` header was not valid UTF-8.
    #[error("failed to parse content length from header, {0}")]
    ParseContentLengthFromHeader(#[source] http::header::ToStrError),
    /// Failed to connect to the local http proxy unix socket.
    #[error("failed to connect to local http proxy socket, {0}")]
    LocalConnect(#[source] Error),
    /// Failed to perform the HTTP/1 handshake with the local http server.
    #[error("failed to handshake with local http proxy, {0}")]
    LocalHandshake(#[source] hyper::Error),
    /// Failed to get response from the local http server.
    #[error("failed to get response, {0}")]
    LocalRequest(#[source] hyper::Error),
    /// Failed to get response from the remote http server.
    #[error("failed to get response, {0}")]
    RemoteRequest(#[source] ConnectionError),
    /// Failed to build local http request.
    #[error("failed to build http request, {0}")]
    BuildHttpRequest(#[source] http::Error),
    /// Failed to read the response body.
    #[error("failed to read response body, {0}")]
    ReadResponseBody(#[source] hyper::Error),
    /// Failed to transport the remote response body.
    #[error("failed to transport remote response body, {0}")]
    Transport(#[source] Error),
    /// Failed to copy the buffer.
    #[error("failed to copy buffer, {0}")]
    CopyBuffer(#[source] Error),
    /// Invalid path.
    #[error("invalid path")]
    InvalidPath,
    /// Failed to build request header.
    #[error("failed to construct request header, {0}")]
    ConstructHeader(String),
}

impl From<HttpProxyError> for BackendError {
    fn from(error: HttpProxyError) -> Self {
        BackendError::HttpProxy(error)
    }
}

/// A storage backend driver to access blobs through a http proxy server.
/// The http proxy server may be local (using unix socket) or be remote (using `http://` or `https://`).
///
/// `HttpProxy` uses two API endpoints to access the blobs:
/// - `HEAD /path/to/blob` to get the blob size
/// - `GET /path/to/blob` to read the blob
///
/// The http proxy server should respect [the `Range` header](https://www.rfc-editor.org/rfc/rfc9110.html#name-range) to support range reading.
pub struct HttpProxy {
    addr: String,
    path: String,
    client: Client,
    metrics: Option<Arc<BackendMetrics>>,
}

/// HttpProxyReader is a BlobReader to implement the HttpProxy backend driver.
pub struct HttpProxyReader {
    client: Client,
    uri: Uri,
    metrics: Arc<BackendMetrics>,
}

/// Client for the local (unix-socket) http proxy. Speaks HTTP/1 over a compio
/// `UnixStream` using hyper's low-level client, driven by the shared thread-local
/// compio HTTP runtime — no tokio.
#[derive(Clone)]
struct LocalClient {
    socket: Arc<String>,
}

#[derive(Clone)]
enum Client {
    Local(LocalClient),
    Remote(Arc<request::Request>),
}

enum Uri {
    Local,
    Remote(String),
}

fn range_str_for_header(offset: u64, len: Option<usize>) -> String {
    match len {
        Some(len) => format!("bytes={}-{}", offset, offset + len as u64 - 1),
        None => format!("bytes={}-", offset),
    }
}

impl LocalClient {
    /// Issue a single HEAD/GET over a fresh unix-socket connection and return the
    /// response headers and (for GET) the collected body.
    ///
    /// The request-target is `/`, matching the previous `hyperlocal` behavior
    /// (the local proxy is addressed purely by its socket path).
    async fn do_req(
        &self,
        only_head: bool,
        offset: u64,
        len: Option<usize>,
    ) -> BackendResult<(HeaderMap<HeaderValue>, Vec<u8>)> {
        let stream = UnixStream::connect(self.socket.as_str())
            .await
            .map_err(HttpProxyError::LocalConnect)?;
        let io = HyperStream::new_plain(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(HttpProxyError::LocalHandshake)?;
        // Drive the connection concurrently with the request on the same compio
        // runtime; await it after the request so the socket is torn down before
        // we return (no detached/leaked connection task).
        let conn_task = compio::runtime::spawn(async move {
            let _ = conn.await;
        });

        let method = if only_head { Method::HEAD } else { Method::GET };
        let req = Request::builder()
            .method(method)
            .uri("/")
            .header(http::header::HOST, "localhost")
            .header(http::header::RANGE, range_str_for_header(offset, len))
            .body(Full::new(Bytes::new()))
            .map_err(HttpProxyError::BuildHttpRequest)?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(HttpProxyError::LocalRequest)?;
        let headers = resp.headers().clone();
        let body = if only_head {
            Vec::new()
        } else {
            resp.into_body()
                .collect()
                .await
                .map_err(HttpProxyError::ReadResponseBody)?
                .to_bytes()
                .to_vec()
        };

        drop(sender);
        // The connection task is done once the request completed and the sender
        // dropped; its result (clean close vs. peer reset) is not actionable here.
        let _ = conn_task.await;
        Ok((headers, body))
    }

    fn get_headers(&self) -> BackendResult<HeaderMap<HeaderValue>> {
        block_on_http(self.do_req(true, 0, None)).map(|(headers, _)| headers)
    }

    fn try_read(&self, offset: u64, len: usize) -> BackendResult<Vec<u8>> {
        block_on_http(self.do_req(false, offset, Some(len))).map(|(_, body)| body)
    }
}

impl BlobReader for HttpProxyReader {
    fn blob_size(&self) -> super::BackendResult<u64> {
        let headers = match &self.client {
            Client::Local(client) => client.get_headers(),
            Client::Remote(request) => {
                let uri = match self.uri {
                    Uri::Local => unreachable!(),
                    Uri::Remote(ref uri) => uri.clone(),
                };
                let mut ctx = BackendContext::default();
                request
                    .call::<&[u8]>(
                        Method::HEAD,
                        uri.as_str(),
                        None,
                        None,
                        &mut HeaderMap::new(),
                        true,
                        &mut ctx,
                        false,
                    )
                    .map(|resp| resp.headers().clone())
                    .map_err(BackendError::Request)
            }
        };
        let content_length = headers?[http::header::CONTENT_LENGTH]
            .to_str()
            .map_err(HttpProxyError::ParseContentLengthFromHeader)?
            .parse::<u64>()
            .map_err(HttpProxyError::ParseStringToInteger)?;
        Ok(content_length)
    }

    fn try_read(&self, buf: &mut [u8], offset: u64) -> BackendResult<usize> {
        self.try_read_ctx(buf, offset, None)
    }

    fn try_read_ctx(
        &self,
        buf: &mut [u8],
        offset: u64,
        ctx: Option<&mut BackendContext>,
    ) -> BackendResult<usize> {
        match &self.client {
            Client::Local(client) => {
                let content = client.try_read(offset, buf.len())?;
                let copied_size = std::io::copy(&mut content.as_slice(), &mut &mut *buf)
                    .map_err(HttpProxyError::CopyBuffer)?;
                Ok(copied_size as usize)
            }
            Client::Remote(request) => {
                let mut default_ctx = BackendContext::default();
                let ctx = ctx.unwrap_or(&mut default_ctx);
                let uri = match self.uri {
                    Uri::Local => unreachable!(),
                    Uri::Remote(ref uri) => uri.clone(),
                };
                let mut headers = HeaderMap::new();
                let range = range_str_for_header(offset, Some(buf.len()));
                headers.insert(
                    http::header::RANGE,
                    range
                        .as_str()
                        .parse()
                        .map_err(|e| HttpProxyError::ConstructHeader(format!("{}", e)))?,
                );
                let resp = request
                    .call::<&[u8]>(
                        Method::GET,
                        uri.as_str(),
                        None,
                        None,
                        &mut headers,
                        true,
                        ctx,
                        false,
                    )
                    .map_err(BackendError::Request)?;
                Ok(resp
                    .copy_to(buf)
                    .map_err(|e| HttpProxyError::Transport(std::io::Error::other(e)))
                    .map(|size| size as usize)?)
            }
        }
    }

    fn metrics(&self) -> &nydus_utils::metrics::BackendMetrics {
        &self.metrics
    }
}

impl HttpProxy {
    pub fn new(config: &HttpProxyConfig, id: Option<&str>) -> BackendResult<HttpProxy> {
        let client = if config.addr.starts_with("http://") || config.addr.starts_with("https://") {
            let conn_cfg: ConnectionConfig = config.clone().into();
            let proxy_config = conn_cfg.proxy.clone();
            let conn = Connection::new(&conn_cfg).map_err(BackendError::Connection)?;
            let request = request::Request::new(conn, proxy_config, false, id.unwrap_or(""));
            Client::Remote(request)
        } else {
            Client::Local(LocalClient {
                socket: Arc::new(config.addr.to_string()),
            })
        };
        Ok(HttpProxy {
            addr: config.addr.to_string(),
            path: config.path.to_string(),
            client,
            metrics: id.map(|i| BackendMetrics::new(i, "http-proxy")),
        })
    }
}

impl BlobBackend for HttpProxy {
    fn shutdown(&self) {
        match &self.client {
            Client::Local(_) => {}
            Client::Remote(request) => {
                request.shutdown();
            }
        }
    }

    fn metrics(&self) -> &nydus_utils::metrics::BackendMetrics {
        // `metrics()` is only used for nydusd, which will always provide valid `blob_id`, thus
        // `self.metrics` has valid value.
        self.metrics.as_ref().unwrap()
    }

    fn get_reader(
        &self,
        blob_id: &str,
    ) -> super::BackendResult<std::sync::Arc<dyn super::BlobReader>> {
        let path = Path::new(&self.path).join(blob_id);
        let path = path.to_str().ok_or(HttpProxyError::InvalidPath)?;
        let uri = match &self.client {
            Client::Local(_) => Uri::Local,
            Client::Remote(_) => {
                let uri = format!("{}{}", self.addr, path);
                Uri::Remote(uri)
            }
        };
        let reader = Arc::new(HttpProxyReader {
            client: self.client.clone(),
            uri,
            metrics: self.metrics.as_ref().unwrap().clone(),
        });
        Ok(reader)
    }
}

impl Drop for HttpProxy {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.release().unwrap_or_else(|e| error!("{:?}", e));
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        backend::{BlobBackend, http_proxy::HttpProxy},
        utils::alloc_buf,
    };

    use http::{Request, status};
    use http_body_util::Full;
    use hyper::Response;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder;
    use nydus_api::HttpProxyConfig;
    use std::{
        cmp,
        fs::{self},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::Path,
        thread,
        time::Duration,
    };
    use tokio::net::{TcpListener, UnixListener};
    use tokio::runtime::Runtime;

    use super::Bytes;

    const CONTENT: &str = "some content for test";
    const SOCKET_PATH: &str = "/tmp/nydus-test-local-http-proxy.sock";

    /// Build a tokio runtime for the test mock servers (the backend under test
    /// is on compio; only the test harness uses tokio).
    fn build_tokio_runtime(name: &str, thread_num: usize) -> std::io::Result<Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name(name)
            .worker_threads(thread_num)
            .enable_all()
            .build()
    }

    fn parse_range_header(range_str: &str) -> (u64, Option<u64>) {
        let range_str = range_str.trim_start_matches("bytes=");
        let range: Vec<&str> = range_str.split('-').collect();
        let start = range[0].parse::<u64>().unwrap();
        let end = match range[1] {
            "" => None,
            _ => Some(cmp::min(
                range[1].parse::<u64>().unwrap(),
                (CONTENT.len() - 1) as u64,
            )),
        };
        (start, end)
    }

    async fn server_handler(
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        match *req.method() {
            hyper::Method::HEAD => Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_LENGTH, CONTENT.len())
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
            hyper::Method::GET => {
                let range = req.headers()[http::header::RANGE].to_str().unwrap();
                println!("range: {}", range);
                let (start, end) = parse_range_header(range);
                let length = match end {
                    Some(e) => e - start + 1,
                    None => CONTENT.len() as u64,
                };
                println!("start: {}, end: {:?}, length: {}", start, end, length);
                let end = match end {
                    Some(e) => e,
                    None => (CONTENT.len() - 1) as u64,
                };
                let content = CONTENT.as_bytes()[start as usize..(end + 1) as usize].to_vec();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_LENGTH, length)
                        .body(Full::new(Bytes::from(content)))
                        .unwrap(),
                )
            }
            _ => Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .status(status::StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        }
    }

    #[test]
    fn test_head_and_get() {
        thread::spawn(|| {
            let rt = build_tokio_runtime("test-local-http-proxy-server", 1).unwrap();
            rt.block_on(async {
                println!("\nstarting local http proxy server......");
                let path = Path::new(SOCKET_PATH);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
                let listener = UnixListener::bind(path).unwrap();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(io, service_fn(server_handler))
                            .await
                            .ok();
                    });
                }
            });
        });

        thread::spawn(|| {
            let rt = build_tokio_runtime("test-remote-http-proxy-server", 1).unwrap();
            rt.block_on(async {
                println!("\nstarting remote http proxy server......");
                let listener = TcpListener::bind(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    9977,
                ))
                .await
                .unwrap();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(io, service_fn(server_handler))
                            .await
                            .ok();
                    });
                }
            });
        });

        // wait for server to start
        thread::sleep(Duration::from_secs(5));

        // start the client and test
        let test_list: Vec<(String, String)> = vec![
            (
                format!(
                    "{{\"addr\":\"{}\",\"path\":\"/namespace/<repo>/blobs\"}}",
                    SOCKET_PATH,
                ),
                "test-local-http-proxy".to_string(),
            ),
            (
                "{\"addr\":\"http://127.0.0.1:9977\",\"path\":\"/namespace/<repo>/blobs\"}"
                    .to_string(),
                "test-remote-http-proxy".to_string(),
            ),
        ];
        for test_case in test_list.iter() {
            let config: HttpProxyConfig = serde_json::from_str(test_case.0.as_str()).unwrap();
            let backend = HttpProxy::new(&config, Some(test_case.1.as_str())).unwrap();
            let reader = backend.get_reader("blob_id").unwrap();

            println!();
            println!("testing blob_size()......");
            let blob_size = reader
                .blob_size()
                .map_err(|e| {
                    println!("blob_size() failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(blob_size, CONTENT.len() as u64);

            println!();
            println!("testing read() range......");
            let mut buf = alloc_buf(3);
            let size = reader
                .try_read(&mut buf, 0)
                .map_err(|e| {
                    println!("read() range failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(size, 3);
            assert_eq!(buf, CONTENT.as_bytes()[0..3]);

            println!();
            println!("testing read() full......");
            let mut buf = alloc_buf(80);
            let size = reader
                .try_read(&mut buf, 0)
                .map_err(|e| {
                    println!("read() range failed: {}", e);
                    e
                })
                .unwrap();
            assert_eq!(size, CONTENT.len());
            assert_eq!(&buf[0..CONTENT.len()], CONTENT.as_bytes());
        }
    }
}
