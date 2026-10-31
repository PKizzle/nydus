// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Compile vendored containerd service protos (Content, Images, Transfer, Streaming) into
//! tonic 0.14 clients.
//!
//! containerd-client on crates.io still targets tonic 0.12, which doesn't
//! coexist with the tonic 0.14 / hyper 1.x stack the snapshotter's gRPC server
//! is built on (cyper-axum + the in-repo `containerd-snapshots` git revision).
//! We vendor just the services the snapshotter calls, plus the types they reference, and
//! generate the bindings here so the containerd clients have a typed RPC surface, no
//! shell-out, and no proto version skew.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let services = [
        "containerd/api/services/content/v1/content.proto",
        "containerd/api/services/images/v1/images.proto",
        "containerd/api/services/transfer/v1/transfer.proto",
        "containerd/api/services/streaming/v1/streaming.proto",
        // Transfer payloads travel as `google.protobuf.Any`, so nothing imports these.
        "containerd/api/types/transfer/registry.proto",
        "containerd/api/types/transfer/imagestore.proto",
    ];
    let paths: Vec<PathBuf> = services.iter().map(|p| proto_dir.join(p)).collect();

    tonic_prost_build::configure()
        .build_server(false) // client-only
        .compile_protos(&paths, std::slice::from_ref(&proto_dir))?;

    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
