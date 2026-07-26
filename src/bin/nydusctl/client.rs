// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, Result};
use compio::net::UnixStream;
use cyper_core::HyperStream;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri as HyperUri, header};

use serde_json::{self, Value};

pub struct NydusdClient {
    sock_path: PathBuf,
}

impl NydusdClient {
    pub fn new(sock: &str) -> Self {
        Self {
            sock_path: sock.to_string().into(),
        }
    }

    /// Build the origin-form request target (`/api/...?k=v`) for an endpoint.
    ///
    /// The socket path is not part of the URI: it is where we connect, not what we ask
    /// for. (The previous `hyperlocal` client smuggled it through the authority as a
    /// hex-encoded hostname; talking to the socket directly makes that unnecessary.)
    fn build_uri(&self, path: &str, query: Option<Vec<(&str, &str)>>) -> Result<HyperUri> {
        let mut endpoint = format!("/api/{}", path);

        if let Some(q) = query {
            let params = q
                .into_iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<_>>()
                .join("&");

            if !params.is_empty() {
                endpoint.push_str(&format!("?{}", params));
            }
        }

        HyperUri::try_from(endpoint.as_str())
            .with_context(|| format!("build request target {:?}", endpoint))
    }

    /// Issue one request over a fresh connection to the daemon's socket, returning the
    /// status code and the collected body.
    ///
    /// Speaks HTTP/1 over a compio `UnixStream` with hyper's low-level client — the same
    /// tokio-free pattern as `nydus-storage`'s http-proxy backend (see CLAUDE.md on the
    /// workspace runtime split). `nydusctl` runs one request per invocation, so a
    /// connection pool would buy nothing.
    async fn request(
        &self,
        method: Method,
        uri: HyperUri,
        data: Option<String>,
    ) -> Result<(u16, Bytes)> {
        let stream = UnixStream::connect(&self.sock_path)
            .await
            .with_context(|| {
                format!("connect to nydusd api socket {}", self.sock_path.display())
            })?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(HyperStream::new_plain(stream))
                .await
                .context("http/1 handshake with nydusd")?;
        // Drive the connection alongside the request on the same compio runtime, then
        // join it below so the socket is torn down before we return.
        let conn_task = compio::runtime::spawn(async move {
            let _ = conn.await;
        });

        let body = data.map(Bytes::from).unwrap_or_default();
        let req = Request::builder()
            .method(method)
            .uri(uri)
            // HTTP/1.1 requires a Host header; the daemon does not route on it.
            .header(header::HOST, "localhost")
            .header(header::USER_AGENT, "nydusctl")
            .body(Full::new(body))?;

        let response = sender
            .send_request(req)
            .await
            .context("request to nydusd")?;
        let status = response.status().as_u16();
        let buf = response.into_body().collect().await?.to_bytes();

        // Dropping the sender lets the connection future finish.
        drop(sender);
        let _ = conn_task.await;

        Ok((status, buf))
    }

    /// Decode an error body into whatever JSON the daemon returned, for the message.
    fn fail(buf: &[u8]) -> anyhow::Error {
        match serde_json::from_slice::<Value>(buf) {
            Ok(b) => anyhow!("Request failed. {:?}", b),
            Err(e) => anyhow!("deserialize: {}", e),
        }
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let uri = self.build_uri(path, None)?;
        let (sc, buf) = self.request(Method::GET, uri, None).await?;
        let b: Value = serde_json::from_slice(&buf).map_err(|e| anyhow!("deserialize: {}", e))?;

        if sc >= 400 {
            bail!("Request failed. {:?}", b);
        }

        Ok(b)
    }

    /// Shared body for the endpoints that return no payload on success.
    async fn send(
        &self,
        method: Method,
        path: &str,
        data: Option<String>,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<()> {
        let uri = self.build_uri(path, query)?;
        let (sc, buf) = self.request(method, uri, data).await?;

        if sc >= 400 {
            return Err(Self::fail(&buf));
        }

        Ok(())
    }

    pub async fn put(&self, path: &str, data: Option<String>) -> Result<()> {
        self.send(Method::PUT, path, data, None).await
    }

    pub async fn post(
        &self,
        path: &str,
        data: Option<String>,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<()> {
        self.send(Method::POST, path, data, query).await
    }

    pub async fn delete(
        &self,
        path: &str,
        data: Option<String>,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<()> {
        self.send(Method::DELETE, path, data, query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = NydusdClient::new("/tmp/nydus.sock");
        assert_eq!(client.sock_path, PathBuf::from("/tmp/nydus.sock"));

        let client = NydusdClient::new("/var/run/nydusd.sock");
        assert_eq!(client.sock_path, PathBuf::from("/var/run/nydusd.sock"));
    }

    #[test]
    fn test_build_uri_without_query() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let uri = client.build_uri("v1/daemon", None).unwrap();
        assert_eq!(uri.path_and_query().unwrap().as_str(), "/api/v1/daemon");
    }

    #[test]
    fn test_build_uri_with_query() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let query = vec![("key1", "value1")];
        let uri = client.build_uri("v1/daemon", Some(query)).unwrap();
        assert_eq!(
            uri.path_and_query().unwrap().as_str(),
            "/api/v1/daemon?key1=value1"
        );
    }

    #[test]
    fn test_build_uri_with_multiple_query_params() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let query = vec![("key1", "value1"), ("key2", "value2")];
        let uri = client.build_uri("v2/blobs", Some(query)).unwrap();
        assert_eq!(
            uri.path_and_query().unwrap().as_str(),
            "/api/v2/blobs?key1=value1&key2=value2"
        );
    }

    #[test]
    fn test_build_uri_with_empty_query_list() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        let uri = client.build_uri("v1/daemon", Some(vec![])).unwrap();
        assert_eq!(uri.path_and_query().unwrap().as_str(), "/api/v1/daemon");
    }

    #[test]
    fn test_build_uri_various_paths() {
        let client = NydusdClient::new("/tmp/nydus.sock");

        // Test different API paths
        let paths = vec![
            "v1/daemon",
            "v1/metrics/files",
            "v2/blobs/sha256:abc123",
            "v1/mount",
        ];

        for path in paths {
            let uri = client.build_uri(path, None).unwrap();
            assert!(
                uri.path_and_query()
                    .unwrap()
                    .as_str()
                    .starts_with(&format!("/api/{}", path)),
                "URI should contain /api/{}, got {}",
                path,
                uri
            );
        }
    }

    #[test]
    fn test_build_uri_rejects_invalid_target() {
        // A query value with a space cannot go into a request target verbatim; that
        // must surface as an error rather than a panic or a mangled request.
        let client = NydusdClient::new("/tmp/nydus.sock");
        assert!(
            client
                .build_uri("v1/daemon", Some(vec![("k", "bad value")]))
                .is_err()
        );
    }

    #[test]
    fn test_socket_path_is_not_part_of_the_request_target() {
        // Regression guard for the hyperlocal removal: the socket is where we connect,
        // not what we ask for.
        let client = NydusdClient::new("/tmp/nydus.sock");
        let uri = client.build_uri("v1/daemon", None).unwrap();
        assert!(uri.authority().is_none(), "unexpected authority in {uri}");
        assert_eq!(uri.to_string(), "/api/v1/daemon");
    }
}
