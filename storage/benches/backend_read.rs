// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Backend HTTP read-throughput benchmark.
//!
//! Drives the public object-storage (OSS) backend against a local keep-alive
//! HTTP server and measures the throughput of chunk-sized `BlobReader::read`
//! calls. The hot path exercised here is exactly the part the reqwest -> cyper
//! migration changes (the `Connection` HTTP client), so the same benchmark
//! provides a like-for-like before/after comparison: run it on the reqwest
//! baseline, then re-run after each migration stage to gate against regressions.
//!
//! Run with:
//!   cargo bench -p nydus-storage --features backend-oss --bench backend_read

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nydus_api::S3Config;
use nydus_storage::backend::s3::S3;
use nydus_storage::backend::{BlobBackend, BlobReader};

/// Size of the synthetic blob served by the mock backend.
const BLOB_SIZE: usize = 256 * 1024 * 1024;

/// Read sizes to benchmark: small (RAFS chunk-sized) through large, to
/// battle-test large-body throughput.
const READ_SIZES: &[usize] = &[
    4 * 1024,
    64 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
];

/// Parse the start/end of a `Range: bytes=START-END` header, if present.
fn parse_range(request: &str) -> Option<(usize, usize)> {
    let line = request
        .lines()
        .find(|l| l.trim().to_ascii_lowercase().starts_with("range:"))?;
    let value = line.split_once(':')?.1.trim();
    let range = value.trim_start_matches("bytes=");
    let (start, end) = range.split_once('-')?;
    let start: usize = start.trim().parse().ok()?;
    let end: usize = end.trim().parse().ok()?;
    Some((start, end))
}

/// Handle a single keep-alive connection: serve HEAD (content length) and GET
/// (range body) requests from `blob` until the peer closes the connection.
fn serve_connection(mut stream: TcpStream, blob: Arc<Vec<u8>>) {
    let _ = stream.set_nodelay(true);
    let mut pending = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // Accumulate until a full request header (terminated by CRLFCRLF).
        let header_end = loop {
            if let Some(pos) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            match stream.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(_) => return,
            }
        };

        let request = String::from_utf8_lossy(&pending[..header_end]).into_owned();
        pending.drain(..header_end);

        let response = if request.starts_with("HEAD ") {
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", blob.len()).into_bytes()
        } else if let Some((start, end)) = parse_range(&request) {
            let end = end.min(blob.len().saturating_sub(1));
            let body = &blob[start..=end];
            let mut resp = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            resp.extend_from_slice(body);
            resp
        } else {
            // Whole-object GET.
            let mut resp =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", blob.len()).into_bytes();
            resp.extend_from_slice(&blob);
            resp
        };

        if stream.write_all(&response).is_err() {
            return;
        }
    }
}

/// Start the mock object-storage server on an ephemeral port. Returns the
/// `host:port` endpoint and a shutdown flag.
fn start_server(blob: Arc<Vec<u8>>) -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while !shutdown_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let blob = blob.clone();
                    thread::spawn(move || serve_connection(stream, blob));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
    });

    (endpoint, shutdown)
}

/// Build an S3 backend reader pointed at the local mock server. S3 uses
/// path-style URLs (`scheme://endpoint/bucket/key`), so it works with a bare
/// `host:port` endpoint (unlike OSS's virtual-hosted `bucket.endpoint`).
fn make_reader(endpoint: &str) -> Arc<dyn BlobReader> {
    let config = S3Config {
        scheme: "http".to_string(),
        endpoint: endpoint.to_string(),
        region: "us-east-1".to_string(),
        bucket_name: "bench".to_string(),
        object_prefix: String::new(),
        access_key_id: "bench-ak".to_string(),
        access_key_secret: "bench-sk".to_string(),
        ..Default::default()
    };
    let backend = S3::new(&config, Some("bench")).unwrap();
    backend.get_reader("bench-blob").unwrap()
}

fn bench_backend_read(c: &mut Criterion) {
    let blob = Arc::new((0..BLOB_SIZE).map(|i| i as u8).collect::<Vec<u8>>());
    let (endpoint, shutdown) = start_server(blob);
    let reader = make_reader(&endpoint);

    let mut group = c.benchmark_group("backend_read");
    for &size in READ_SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut buf = vec![0u8; size];
            let mut offset = 0u64;
            b.iter(|| {
                // Stride through the blob so the same range is not always hit.
                if offset as usize + size >= BLOB_SIZE {
                    offset = 0;
                }
                let n = reader.read(&mut buf, offset).unwrap();
                offset += n as u64;
                n
            });
        });
    }
    group.finish();

    shutdown.store(true, Ordering::Relaxed);
}

criterion_group!(benches, bench_backend_read);
criterion_main!(benches);
