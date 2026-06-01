// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Native containerd NRI ttrpc transport.
//!
//! This module implements the subset of the NRI v0.8 Plugin service needed by
//! the Nydus prefetch plugin. It avoids generated code in-tree by defining the
//! protobuf messages used by the plugin with `prost` and manually registering
//! ttrpc method handlers.

use crate::nri::{PrefetchHint, SysctlClient, prefetch_hint_from_annotations};
use anyhow::{Context, Result};
use prost::Message;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};
use ttrpc::{Code, MethodHandler, Request, Response, Server, TtrpcContext};

const NRI_PLUGIN_SERVICE: &str = "nri.pkg.api.v1alpha1.Plugin";
const NRI_RUNTIME_SERVICE: &str = "nri.pkg.api.v1alpha1.Runtime";

pub const EVENT_RUN_POD_SANDBOX: i32 = 1;
pub const EVENT_START_CONTAINER: i32 = 6;
pub const EVENT_STOP_CONTAINER: i32 = 10;

pub const PREFETCH_IMAGE_ANNOTATION: &str = "containerd.io/nydus-prefetch-image";
pub const CRI_IMAGE_NAME_LABEL: &str = "io.kubernetes.cri.image-name";

#[derive(Clone, Debug)]
pub struct NriTtrpcConfig {
    pub listen_socket: PathBuf,
    pub runtime_socket: Option<PathBuf>,
    pub sysctl_socket: PathBuf,
    pub plugin_name: String,
    pub plugin_idx: String,
}

impl NriTtrpcConfig {
    pub fn prefetch_events(&self) -> i32 {
        event_mask(&[EVENT_RUN_POD_SANDBOX, EVENT_START_CONTAINER])
    }
}

#[derive(Clone)]
struct PrefetchPluginService {
    sysctl: SysctlClient,
    event_mask: i32,
}

pub fn serve_prefetch_plugin(config: NriTtrpcConfig) -> Result<()> {
    if let Some(runtime_socket) = config.runtime_socket.as_ref() {
        register_plugin(runtime_socket, &config.plugin_name, &config.plugin_idx)
            .with_context(|| format!("failed to register NRI plugin {}", config.plugin_name))?;
    }

    let service = Arc::new(PrefetchPluginService {
        sysctl: SysctlClient::new(config.sysctl_socket.clone()),
        event_mask: config.prefetch_events(),
    });
    let mut server = Server::new()
        .bind(&ttrpc_unix_address(&config.listen_socket))?
        .register_service(plugin_methods(service));
    server.start()?;
    info!(socket = %config.listen_socket.display(), "NRI prefetch ttrpc plugin listening");

    loop {
        std::thread::park();
    }
}

pub fn register_plugin(runtime_socket: &Path, plugin_name: &str, plugin_idx: &str) -> Result<()> {
    let request = RegisterPluginRequest {
        plugin_name: plugin_name.to_string(),
        plugin_idx: plugin_idx.to_string(),
    };
    let _empty: Empty = call_ttrpc(
        runtime_socket,
        NRI_RUNTIME_SERVICE,
        "RegisterPlugin",
        &request,
    )?;
    Ok(())
}

fn plugin_methods(
    service: Arc<PrefetchPluginService>,
) -> HashMap<String, Box<dyn MethodHandler + Send + Sync>> {
    let mut methods: HashMap<String, Box<dyn MethodHandler + Send + Sync>> = HashMap::new();
    methods.insert(
        method_path("Configure"),
        Box::new(NriMethodHandler::new(service.clone(), NriMethod::Configure)),
    );
    methods.insert(
        method_path("Synchronize"),
        Box::new(NriMethodHandler::new(
            service.clone(),
            NriMethod::Synchronize,
        )),
    );
    methods.insert(
        method_path("Shutdown"),
        Box::new(NriMethodHandler::new(service.clone(), NriMethod::Shutdown)),
    );
    methods.insert(
        method_path("CreateContainer"),
        Box::new(NriMethodHandler::new(
            service.clone(),
            NriMethod::CreateContainer,
        )),
    );
    methods.insert(
        method_path("UpdateContainer"),
        Box::new(NriMethodHandler::new(
            service.clone(),
            NriMethod::UpdateContainer,
        )),
    );
    methods.insert(
        method_path("StopContainer"),
        Box::new(NriMethodHandler::new(
            service.clone(),
            NriMethod::StopContainer,
        )),
    );
    methods.insert(
        method_path("StateChange"),
        Box::new(NriMethodHandler::new(service, NriMethod::StateChange)),
    );
    methods
}

fn method_path(method: &str) -> String {
    format!("/{NRI_PLUGIN_SERVICE}/{method}")
}

struct NriMethodHandler {
    service: Arc<PrefetchPluginService>,
    method: NriMethod,
}

#[derive(Clone, Copy)]
enum NriMethod {
    Configure,
    Synchronize,
    Shutdown,
    CreateContainer,
    UpdateContainer,
    StopContainer,
    StateChange,
}

impl NriMethodHandler {
    fn new(service: Arc<PrefetchPluginService>, method: NriMethod) -> Self {
        Self { service, method }
    }
}

impl MethodHandler for NriMethodHandler {
    fn handler(&self, ctx: TtrpcContext, req: Request) -> ttrpc::Result<()> {
        match self.method {
            NriMethod::Configure => {
                let _req = decode::<ConfigureRequest>(&req)?;
                respond(
                    ctx,
                    ConfigureResponse {
                        events: self.service.event_mask,
                    },
                )
            }
            NriMethod::Synchronize => {
                let req = decode::<SynchronizeRequest>(&req)?;
                self.service.handle_synchronize(req);
                respond(
                    ctx,
                    SynchronizeResponse {
                        update: Vec::new(),
                        more: false,
                    },
                )
            }
            NriMethod::Shutdown => respond(ctx, Empty {}),
            NriMethod::CreateContainer => respond(
                ctx,
                CreateContainerResponse {
                    adjust: None,
                    update: Vec::new(),
                    evict: Vec::new(),
                },
            ),
            NriMethod::UpdateContainer => respond(
                ctx,
                UpdateContainerResponse {
                    update: Vec::new(),
                    evict: Vec::new(),
                },
            ),
            NriMethod::StopContainer => respond(ctx, StopContainerResponse { update: Vec::new() }),
            NriMethod::StateChange => {
                let event = decode::<StateChangeEvent>(&req)?;
                self.service.handle_state_change(event);
                respond(ctx, Empty {})
            }
        }
    }
}

impl PrefetchPluginService {
    fn handle_synchronize(&self, req: SynchronizeRequest) {
        let hints = req
            .pods
            .iter()
            .filter_map(prefetch_hint_from_pod)
            .chain(
                req.containers
                    .iter()
                    .filter_map(prefetch_hint_from_container),
            )
            .collect::<Vec<_>>();
        self.put_hints(&hints);
    }

    fn handle_state_change(&self, event: StateChangeEvent) {
        let hint = match event.event {
            EVENT_RUN_POD_SANDBOX => event.pod.as_ref().and_then(prefetch_hint_from_pod),
            EVENT_START_CONTAINER => event
                .container
                .as_ref()
                .and_then(prefetch_hint_from_container),
            _ => None,
        };
        if let Some(hint) = hint {
            self.put_hints(&[hint]);
        }
    }

    fn put_hints(&self, hints: &[PrefetchHint]) {
        if hints.is_empty() {
            return;
        }
        if let Err(e) = self.sysctl.put_prefetch_hints(hints) {
            warn!(error = %e, hints = hints.len(), "failed to submit NRI prefetch hints");
        }
    }
}

fn prefetch_hint_from_pod(pod: &PodSandbox) -> Option<PrefetchHint> {
    let image = pod.annotations.get(PREFETCH_IMAGE_ANNOTATION)?.clone();
    prefetch_hint_from_annotations(image, &pod.annotations)
}

fn prefetch_hint_from_container(container: &Container) -> Option<PrefetchHint> {
    let image = container_image_ref(container)?;
    prefetch_hint_from_annotations(image, &container.annotations)
}

fn container_image_ref(container: &Container) -> Option<String> {
    [
        container.labels.get(CRI_IMAGE_NAME_LABEL),
        container.annotations.get(CRI_IMAGE_NAME_LABEL),
        container.labels.get("containerd.io/image.name"),
        container.annotations.get("containerd.io/image.name"),
        container.labels.get("image"),
        container.annotations.get("image"),
    ]
    .into_iter()
    .flatten()
    .find(|value| !value.trim().is_empty())
    .cloned()
}

fn event_mask(events: &[i32]) -> i32 {
    events.iter().fold(0, |mask, event| {
        if (0..31).contains(event) {
            mask | (1_i32 << event)
        } else {
            mask
        }
    })
}

fn decode<M: Message + Default>(req: &Request) -> ttrpc::Result<M> {
    M::decode(req.payload.as_slice()).map_err(|e| ttrpc::Error::Others(e.to_string()))
}

fn respond<M: Message>(ctx: TtrpcContext, msg: M) -> ttrpc::Result<()> {
    let mut response = Response::new();
    response.set_status(ttrpc::get_status(Code::OK, ""));
    response.payload = msg.encode_to_vec();
    ttrpc::response_to_channel(ctx.mh.stream_id, response, ctx.res_tx)
}

fn call_ttrpc<Req, Resp>(socket: &Path, service: &str, method: &str, request: &Req) -> Result<Resp>
where
    Req: Message,
    Resp: Message + Default,
{
    let client = ttrpc::Client::connect(&ttrpc_unix_address(socket))?;
    let mut req = Request::new();
    req.set_service(service.to_string());
    req.set_method(method.to_string());
    req.payload = request.encode_to_vec();
    let response = client.request(req)?;
    Resp::decode(response.payload.as_slice()).context("failed to decode ttrpc response")
}

fn ttrpc_unix_address(path: &Path) -> String {
    format!("unix://{}", path.display())
}

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, Message)]
pub struct RegisterPluginRequest {
    #[prost(string, tag = "1")]
    pub plugin_name: String,
    #[prost(string, tag = "2")]
    pub plugin_idx: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConfigureRequest {
    #[prost(string, tag = "1")]
    pub config: String,
    #[prost(string, tag = "2")]
    pub runtime_name: String,
    #[prost(string, tag = "3")]
    pub runtime_version: String,
    #[prost(int64, tag = "4")]
    pub registration_timeout: i64,
    #[prost(int64, tag = "5")]
    pub request_timeout: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConfigureResponse {
    #[prost(int32, tag = "2")]
    pub events: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SynchronizeRequest {
    #[prost(message, repeated, tag = "1")]
    pub pods: Vec<PodSandbox>,
    #[prost(message, repeated, tag = "2")]
    pub containers: Vec<Container>,
    #[prost(bool, tag = "3")]
    pub more: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct SynchronizeResponse {
    #[prost(message, repeated, tag = "1")]
    pub update: Vec<ContainerUpdate>,
    #[prost(bool, tag = "2")]
    pub more: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct StateChangeEvent {
    #[prost(enumeration = "Event", tag = "1")]
    pub event: i32,
    #[prost(message, optional, tag = "2")]
    pub pod: Option<PodSandbox>,
    #[prost(message, optional, tag = "3")]
    pub container: Option<Container>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CreateContainerResponse {
    #[prost(message, optional, tag = "1")]
    pub adjust: Option<ContainerAdjustment>,
    #[prost(message, repeated, tag = "2")]
    pub update: Vec<ContainerUpdate>,
    #[prost(message, repeated, tag = "3")]
    pub evict: Vec<ContainerEviction>,
}

#[derive(Clone, PartialEq, Message)]
pub struct UpdateContainerResponse {
    #[prost(message, repeated, tag = "1")]
    pub update: Vec<ContainerUpdate>,
    #[prost(message, repeated, tag = "2")]
    pub evict: Vec<ContainerEviction>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StopContainerResponse {
    #[prost(message, repeated, tag = "1")]
    pub update: Vec<ContainerUpdate>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PodSandbox {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub uid: String,
    #[prost(string, tag = "4")]
    pub namespace: String,
    #[prost(map = "string, string", tag = "5")]
    pub labels: HashMap<String, String>,
    #[prost(map = "string, string", tag = "6")]
    pub annotations: HashMap<String, String>,
    #[prost(string, tag = "7")]
    pub runtime_handler: String,
    #[prost(uint32, tag = "9")]
    pub pid: u32,
    #[prost(string, repeated, tag = "10")]
    pub ips: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Container {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub pod_sandbox_id: String,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(int32, tag = "4")]
    pub state: i32,
    #[prost(map = "string, string", tag = "5")]
    pub labels: HashMap<String, String>,
    #[prost(map = "string, string", tag = "6")]
    pub annotations: HashMap<String, String>,
    #[prost(string, repeated, tag = "7")]
    pub args: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    pub env: Vec<String>,
    #[prost(uint32, tag = "12")]
    pub pid: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ContainerAdjustment {}

#[derive(Clone, PartialEq, Message)]
pub struct ContainerUpdate {
    #[prost(string, tag = "1")]
    pub container_id: String,
    #[prost(bool, tag = "3")]
    pub ignore_failure: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct ContainerEviction {
    #[prost(string, tag = "1")]
    pub container_id: String,
    #[prost(string, tag = "2")]
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum Event {
    Unknown = 0,
    RunPodSandbox = EVENT_RUN_POD_SANDBOX,
    StartContainer = EVENT_START_CONTAINER,
    StopContainer = EVENT_STOP_CONTAINER,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nri::NYDUS_PREFETCH_ANNOTATION;

    #[test]
    fn event_mask_sets_nri_event_bits() {
        assert_eq!(
            event_mask(&[EVENT_RUN_POD_SANDBOX, EVENT_START_CONTAINER]),
            (1_i32 << EVENT_RUN_POD_SANDBOX) | (1_i32 << EVENT_START_CONTAINER)
        );
    }

    #[test]
    fn pod_prefetch_hint_requires_image_annotation() {
        let pod = PodSandbox {
            annotations: HashMap::from([
                (
                    PREFETCH_IMAGE_ANNOTATION.to_string(),
                    "registry.local/app:1".to_string(),
                ),
                (
                    NYDUS_PREFETCH_ANNOTATION.to_string(),
                    "/bin/app\n".to_string(),
                ),
            ]),
            ..PodSandbox::default()
        };
        let hint = prefetch_hint_from_pod(&pod).unwrap();
        assert_eq!(hint.image, "registry.local/app:1");
        assert_eq!(hint.files, vec!["/bin/app"]);
    }

    #[test]
    fn container_prefetch_hint_uses_cri_image_label() {
        let container = Container {
            labels: HashMap::from([(
                CRI_IMAGE_NAME_LABEL.to_string(),
                "registry.local/app:1".to_string(),
            )]),
            annotations: HashMap::from([(
                NYDUS_PREFETCH_ANNOTATION.to_string(),
                "/bin/app\n".to_string(),
            )]),
            ..Container::default()
        };
        let hint = prefetch_hint_from_container(&container).unwrap();
        assert_eq!(hint.image, "registry.local/app:1");
        assert_eq!(hint.files, vec!["/bin/app"]);
    }

    #[test]
    fn ttrpc_unix_address_uses_containerd_format() {
        assert_eq!(
            ttrpc_unix_address(Path::new("/run/nri/nydus.sock")),
            "unix:///run/nri/nydus.sock"
        );
    }
}
