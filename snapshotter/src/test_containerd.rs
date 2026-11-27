// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! A fake containerd for tests: Images.List, Images.Get and Content.Read
//! served on a Unix socket by cyper-axum, as in production, so clients reach
//! it through [`crate::containerd_grpc::ContainerdChannel`]. `build.rs`
//! generates clients only, so the services are tonic's server traits
//! implemented by hand.

use std::collections::HashMap;
use std::future::{Ready, ready};
use std::path::Path;
use std::sync::Arc;

use tonic::{Code, Request, Response, Status};

use crate::containerd_api::services::content::v1::{ReadContentRequest, ReadContentResponse};
use crate::containerd_api::services::images::v1::{
    GetImageRequest, GetImageResponse, Image, ListImagesRequest, ListImagesResponse,
};
use crate::containerd_api::types::Descriptor;

/// What the fake containerd holds.
#[derive(Default)]
pub(crate) struct FakeContainerd {
    pub images: Vec<Image>,
    /// Content by digest: its bytes, or the status code Content.Read answers.
    /// A digest not listed answers NotFound.
    pub blobs: HashMap<String, Result<Vec<u8>, Code>>,
}

/// An image record named `name` whose target is `digest` of `media_type`.
pub(crate) fn image(name: &str, media_type: &str, digest: &str) -> Image {
    Image {
        name: name.to_string(),
        target: Some(Descriptor {
            media_type: media_type.to_string(),
            digest: digest.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[derive(Clone)]
struct List(Arc<FakeContainerd>);

impl tonic::server::UnaryService<ListImagesRequest> for List {
    type Response = ListImagesResponse;
    type Future = Ready<Result<Response<ListImagesResponse>, Status>>;

    fn call(&mut self, _: Request<ListImagesRequest>) -> Self::Future {
        ready(Ok(Response::new(ListImagesResponse {
            images: self.0.images.clone(),
        })))
    }
}

#[derive(Clone)]
struct Get(Arc<FakeContainerd>);

impl tonic::server::UnaryService<GetImageRequest> for Get {
    type Response = GetImageResponse;
    type Future = Ready<Result<Response<GetImageResponse>, Status>>;

    fn call(&mut self, request: Request<GetImageRequest>) -> Self::Future {
        let name = request.into_inner().name;
        ready(match self.0.images.iter().find(|i| i.name == name) {
            Some(image) => Ok(Response::new(GetImageResponse {
                image: Some(image.clone()),
            })),
            None => Err(Status::not_found(format!("image {name} not found"))),
        })
    }
}

#[derive(Clone)]
struct Read(Arc<FakeContainerd>);

type ReadStream = futures::stream::Iter<std::vec::IntoIter<Result<ReadContentResponse, Status>>>;

impl tonic::server::ServerStreamingService<ReadContentRequest> for Read {
    type Response = ReadContentResponse;
    type ResponseStream = ReadStream;
    type Future = Ready<Result<Response<ReadStream>, Status>>;

    fn call(&mut self, request: Request<ReadContentRequest>) -> Self::Future {
        let digest = request.into_inner().digest;
        let data = match self.0.blobs.get(&digest) {
            Some(Ok(data)) => data.clone(),
            Some(Err(code)) => return ready(Err(Status::new(*code, format!("read {digest}")))),
            None => return ready(Err(Status::not_found(format!("{digest} not found")))),
        };
        let chunk = ReadContentResponse { offset: 0, data };
        ready(Ok(Response::new(futures::stream::iter(vec![Ok(chunk)]))))
    }
}

/// Serve `fake` on `socket` from a detached thread; returns once it listens.
pub(crate) fn serve(socket: &Path, fake: FakeContainerd) {
    use axum::extract::Request as HttpRequest;
    use axum::routing::post;
    use tonic::server::Grpc;
    use tonic_prost::ProstCodec;

    let fake = Arc::new(fake);
    let socket = socket.to_path_buf();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        compio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let listener = compio::net::UnixListener::bind(&socket).await.unwrap();
                let (list, get, read) = (List(fake.clone()), Get(fake.clone()), Read(fake));
                let app = axum::Router::new()
                    .route(
                        "/containerd.services.images.v1.Images/List",
                        post(|req: HttpRequest| async move {
                            Grpc::new(ProstCodec::default()).unary(list, req).await
                        }),
                    )
                    .route(
                        "/containerd.services.images.v1.Images/Get",
                        post(|req: HttpRequest| async move {
                            Grpc::new(ProstCodec::default()).unary(get, req).await
                        }),
                    )
                    .route(
                        "/containerd.services.content.v1.Content/Read",
                        post(|req: HttpRequest| async move {
                            Grpc::new(ProstCodec::default())
                                .server_streaming(read, req)
                                .await
                        }),
                    );
                ready_tx.send(()).unwrap();
                cyper_axum::serve(listener, app.into_make_service())
                    .await
                    .unwrap();
            });
    });
    ready_rx.recv().unwrap();
}

/// A containerd config whose socket is `socket` and content root `root`.
pub(crate) fn config(socket: &Path, root: &Path) -> crate::config::ContainerdConfig {
    crate::config::ContainerdConfig {
        address: Some(socket.to_path_buf()),
        namespace: "k8s.io".to_string(),
        content_root: Some(root.to_path_buf()),
        hosts_dir: None,
    }
}
