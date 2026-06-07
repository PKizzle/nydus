// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Compile vendored containerd Content service protos into tonic 0.14 clients.
//!
//! containerd-client on crates.io still targets tonic 0.12, which doesn't
//! coexist with the tonic 0.14 / hyper 1.x stack the snapshotter's gRPC server
//! is built on (cyper-axum + the in-repo `containerd-snapshots` git revision).
//! We vendor just the Content service + descriptor types and generate the
//! bindings here so the auto-accel content_store client has a typed RPC
//! surface, no shell-out, and no proto version skew.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    let content_proto = proto_dir.join("containerd/api/services/content/v1/content.proto");
    let images_proto = proto_dir.join("containerd/api/services/images/v1/images.proto");

    tonic_prost_build::configure()
        .build_server(false) // client-only
        .compile_protos(
            &[
                content_proto.to_string_lossy().as_ref(),
                images_proto.to_string_lossy().as_ref(),
            ],
            &[proto_dir.to_string_lossy().as_ref()],
        )?;

    println!("cargo:rerun-if-changed=proto/containerd/api/services/content/v1/content.proto");
    println!("cargo:rerun-if-changed=proto/containerd/api/services/images/v1/images.proto");
    println!("cargo:rerun-if-changed=proto/containerd/api/types/descriptor.proto");
    println!("cargo:rerun-if-changed=proto/google/protobuf/empty.proto");
    println!("cargo:rerun-if-changed=proto/google/protobuf/timestamp.proto");
    println!("cargo:rerun-if-changed=proto/google/protobuf/field_mask.proto");
    Ok(())
}
