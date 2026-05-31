# nydus-snapshotter

A Helm chart that deploys the Rust nydus v3 containerd remote snapshotter (`containerd-nydus`) as a
privileged DaemonSet. The snapshotter provides fanotify/EROFS on-demand image mounting, a FUSE
fallback, and node-local zran acceleration.

## Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture](#architecture)
4. [Installation](#installation)
   1. [Build the image](#1-build-the-image)
   2. [Integrate with containerd](#2-integrate-with-containerd)
   3. [Install the chart](#3-install-the-chart)
5. [Snapshotter selection modes](#snapshotter-selection-modes)
6. [Default RuntimeClass injection](#default-runtimeclass-injection)
7. [Verification](#verification)
8. [Configuration reference](#configuration-reference)
9. [Limitations](#limitations)

## Overview

The chart deploys:

- A privileged DaemonSet running `containerd-nydus` (with `nydus-image` bundled for node-local
  conversion), exposing the snapshotter's gRPC socket and persistent state on the host.
- A `nydus` RuntimeClass for opt-in workload routing (created in `runtime-handler` mode).
- Optionally, a mutating admission policy (Kyverno or OPA Gatekeeper) to apply the RuntimeClass
  cluster-wide, and an opt-in installer that integrates the snapshotter with the host containerd.

Two properties are structural rather than configurable:

- **The DaemonSet must be privileged.** The snapshotter creates EROFS/FUSE mounts that the host
  kubelet and containerd consume as container root filesystems. Propagating those mounts to the host
  requires `mountPropagation: Bidirectional`, which Kubernetes permits only for privileged
  containers. User namespaces (KEP-127, GA in Kubernetes v1.36) do not change this, and the proposal
  to allow unprivileged bidirectional propagation (kubernetes#117812) was closed without merging.

- **containerd integration requires one host-side config change per node.** containerd loads
  snapshotters (`proxy_plugins`) and runtime handlers from static configuration at startup; there is
  no runtime registration API. A small additive block must be written to the host containerd
  configuration and the runtime restarted once per node. The chart does not perform this change by
  default; it is documented below and also available as an opt-in installer.

## Prerequisites

- containerd 1.7+ (2.x recommended). k3s 1.31.6+/1.32.2+ and RKE2 ship containerd 2.x.
- Linux kernel 6.14 or newer for the fanotify path. On older kernels the capability probe falls back
  to FUSE (`/dev/fuse` required). The EROFS and FUSE kernel modules must be available.
- A cluster that permits privileged pods. Under Pod Security Admission, label the chart's namespace
  `pod-security.kubernetes.io/enforce: privileged`.
- For default RuntimeClass injection: Kyverno or OPA Gatekeeper, depending on the chosen engine.

## Architecture

containerd connects to the snapshotter over a Unix socket declared as a top-level `proxy_plugins`
entry. The snapshotter is then selected for workloads in one of two ways (see
[Snapshotter selection modes](#snapshotter-selection-modes)): per pod through a RuntimeClass, or
globally as the CRI default snapshotter.

The `proxy_plugins` table is identical across containerd config schema v2 (containerd 1.x) and v3
(containerd 2.x). Only the CRI plugin path differs by version:

| containerd | config schema | proxy_plugins | per-runtime snapshotter | global default snapshotter |
| --- | --- | --- | --- | --- |
| 1.x | v2 | `[proxy_plugins.nydus]` | `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nydus]` | `[plugins."io.containerd.grpc.v1.cri".containerd]` |
| 2.x+ | v3 | `[proxy_plugins.nydus]` (same) | `[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.nydus]` | `[plugins.'io.containerd.cri.v1.images']` |

The opt-in installer detects the containerd version on each node and selects the correct paths
automatically.

## Installation

### 1. Build the image

The image bundles `containerd-nydus` and `nydus-image`. Build it multi-arch (arm64 covers Raspberry
Pi and k3s-on-Pi):

```bash
docker buildx build -f deploy/docker/Dockerfile \
  -t <registry>/nydus-snapshotter:<tag> \
  --platform linux/amd64,linux/arm64 --push .
```

### 2. Integrate with containerd

This step is required once per node. It is decoupled from chart installation so it can be managed by
the operator's preferred configuration method. Three options follow.

#### Option A: native k3s / RKE2 integration (recommended for those distros)

k3s and RKE2 expose the configured snapshotter name to their containerd config template as
`.NodeConfig.AgentConfig.Snapshotter`. Setting the snapshotter to `nydus` makes the distribution use
nydus as the CRI default and lets the template register the proxy plugin conditionally.

1. Set the snapshotter in the distribution config (`/etc/rancher/k3s/config.yaml` or
   `/etc/rancher/rke2/config.yaml`):

   ```yaml
   snapshotter: nydus
   ```

2. Register the proxy plugin in `config-v3.toml.tmpl`, gated on the snapshotter value so the block is
   inert unless nydus is selected:

   ```gotemplate
   {{ template "base" . }}
   {{- if eq .NodeConfig.AgentConfig.Snapshotter "nydus" }}
   [proxy_plugins.nydus]
     type = 'snapshot'
     address = '/run/containerd-nydus/containerd-nydus-grpc.sock'
   {{- end }}
   ```

The leading `{{ template "base" . }}` is mandatory; without it the distribution replaces its
generated configuration instead of extending it. Apply by restarting the service (`systemctl restart
k3s` or `k3s-agent`; `rke2-server` or `rke2-agent`), which regenerates the configuration from the
template.

Setting the snapshotter globally couples this option to `global-default` mode. Review the
[bootstrap-ordering hazard](#bootstrap-ordering-with-global-default) before adopting it.

#### Option B: upstream Kubernetes (kubeadm / kops / kubespray) and vanilla containerd

This applies to standard, self-managed Kubernetes clusters whose nodes run an unmodified containerd
(installed by the distribution, a package, or the kubeadm/kops/kubespray bootstrap). Unlike k3s and
RKE2, these nodes have no config template: edit the containerd configuration file directly.

1. Add the block to `/etc/containerd/config.toml` (or to a file referenced by an `imports` entry in
   that file). Use the CRI path for the installed containerd version (see the
   [Architecture](#architecture) table). For `runtime-handler` mode on containerd 2.x:

   ```toml
   [proxy_plugins.nydus]
     type = "snapshot"
     address = "/run/containerd-nydus/containerd-nydus-grpc.sock"

   [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.nydus]
     runtime_type = "io.containerd.runc.v2"
     snapshotter = "nydus"
   [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.nydus.options]
     SystemdCgroup = true
   ```

   On containerd 1.x, replace `io.containerd.cri.v1.runtime` with `io.containerd.grpc.v1.cri`.

2. Restart containerd: `systemctl restart containerd`. Running containers keep running across the
   restart; the kubelet reconnects, and only new pod-sandbox operations pause briefly. (The
   `global-default` ordering hazard described below still applies.)

3. When installing the chart on upstream Kubernetes, set the host containerd socket to the standard
   path: `--set hostPaths.containerdSock=/run/containerd/containerd.sock`.

If the cluster is managed by `kubeadm` and uses a config drop-in, note that containerd honors
`imports` only when the directive is present in the main `config.toml`; there is no implicit
`config.toml.d` directory unless your distribution adds one.

On EKS AL2023, an in-place edit applies for the life of the node. For configuration that survives
node replacement, place the same block under `spec.containerd.config` of a `nodeadm` NodeConfig in
the launch-template user-data (the mechanism the SOCI snapshotter documents for EKS).

#### Option C: opt-in installer

Set `containerd.install.enable=true` to run a privileged init container that detects the
distribution and containerd version, writes the additive block idempotently, and (if
`containerd.install.autoRestart=true`) restarts the runtime. `containerd.install.runtime=auto` covers
k3s, RKE2, vanilla containerd, and EKS AL2023. Bottlerocket, GKE, and AKS managed nodes are detected
as not configurable from a DaemonSet; the installer prints the required configuration and exits
successfully without modifying the node.

Support matrix:

| Distribution | Mechanism | Installer |
| --- | --- | --- |
| k3s | containerd template (`config-v3.toml.tmpl`) | Automatic |
| RKE2 | containerd template (`config-v3.toml.tmpl`) | Automatic |
| kubeadm / vanilla containerd | edit `/etc/containerd/config.toml` | Automatic |
| EKS AL2023 | edit `/etc/containerd/config.toml`; nodeadm NodeConfig for durability | Automatic (prints nodeadm guidance) |
| EKS Bottlerocket | settings API (overlayfs/soci only) | Not supported; prints guidance |
| GKE / AKS managed | managed containerd | Not supported; prints guidance |

In `global-default` mode the installer writes the configuration but never restarts the runtime
automatically; see the [bootstrap-ordering hazard](#bootstrap-ordering-with-global-default).

### 3. Install the chart

```bash
helm install nydus deploy/helm/nydus-snapshotter \
  --namespace nydus-system --create-namespace \
  --set image.repository=<registry>/nydus-snapshotter \
  --set image.tag=<tag> \
  --set hostPaths.containerdSock=/run/k3s/containerd/containerd.sock
```

Set `hostPaths.containerdSock` to `/run/containerd/containerd.sock` for vanilla containerd.

## Snapshotter selection modes

`snapshotterMode` controls how workloads are routed to nydus.

### runtime-handler (default)

A `nydus` containerd runtime handler is configured with `snapshotter = "nydus"`, and a matching
RuntimeClass is created. Pods opt in explicitly:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  runtimeClassName: nydus
  containers:
    - name: app
      image: <accelerated-image>
```

The cluster default snapshotter (`overlayfs`) is unchanged. Workloads that do not request the
RuntimeClass are unaffected, and a temporary snapshotter outage affects only nydus-routed pods, which
retry once the snapshotter is available.

### global-default

nydus becomes the CRI default snapshotter for every image pull, with overlay fallback for
non-accelerated images. This is the model the SOCI snapshotter documents. No RuntimeClass is created.

#### Bootstrap-ordering with global-default

In `global-default` mode, containerd routes every pull through nydus after the configuration is
applied. If the runtime is restarted before the nydus snapshotter is running and its socket is
reachable, all image and pod-sandbox operations fail, including the snapshotter's own image pull,
which produces a node-level deadlock.

Mitigations:

- Prefer `runtime-handler` mode for DaemonSet deployments, where the default snapshotter is unchanged
  and no ordering constraint exists.
- For `global-default` mode, ensure the snapshotter starts before the runtime. A host-managed
  snapshotter (systemd) can express this with `Wants=`/`After=` ordering against the runtime unit. A
  DaemonSet has no equivalent guarantee, so the opt-in installer does not auto-restart the runtime in
  this mode; restart it manually only after confirming the snapshotter is Ready.

## Default RuntimeClass injection

Kubernetes has no native default RuntimeClass. To apply `runtimeClassName: nydus` without modifying
each workload, enable a mutating admission policy (relevant only in `runtime-handler` mode):

```bash
helm upgrade nydus ... \
  --set defaultRuntimeClass.enable=true \
  --set defaultRuntimeClass.engine=kyverno     # or: gatekeeper
kubectl label ns <namespace> nydus.dragonflyoss.io/accelerate=true
```

Both engines inject the RuntimeClass only into pods that do not already declare one, scoped to
namespaces carrying `defaultRuntimeClass.namespaceSelectorLabel`. Kyverno uses a `ClusterPolicy`;
Gatekeeper uses an `Assign` mutator (its mutation feature must be enabled).

## Verification

On k3s/RKE2, the containerd CLI is `k3s ctr` / `rke2 ctr`. On upstream Kubernetes use `ctr` (with
`--address /run/containerd/containerd.sock`) or `crictl`.

```bash
# Proxy plugin registered with the host runtime:
ctr plugin ls | grep nydus                          # k3s: k3s ctr plugin ls

# Snapshotter responding:
ctr -n k8s.io snapshot --snapshotter nydus ls

# CRI sees the snapshotter (upstream Kubernetes):
crictl info | grep -i snapshotter

# DaemonSet healthy:
kubectl -n nydus-system logs ds/nydus-nydus-snapshotter

# A pod using runtimeClassName: nydus starts and its rootfs is a nydus mount on the node:
mount | grep -E 'erofs|fuse.*nydus'
```

## Configuration reference

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` / `image.tag` | `…/nydus-snapshotter` / chart appVersion | Image bundling `containerd-nydus` + `nydus-image`. |
| `snapshotterMode` | `runtime-handler` | `runtime-handler` (per-pod RuntimeClass) or `global-default` (CRI default). |
| `daemonset.privileged` | `true` | Required; see [Overview](#overview). |
| `hostPaths.containerdSock` | `/run/k3s/containerd/containerd.sock` | Host containerd socket. |
| `config.fsDrivers` | fanotify, blockdev(loop), fusedev | Ordered driver fallback chain. |
| `runtimeClass.name` / `runtimeClass.handler` | `nydus` / `nydus` | RuntimeClass and the containerd handler it maps to. |
| `defaultRuntimeClass.enable` / `.engine` | `false` / `kyverno` | Cluster-wide RuntimeClass injection via Kyverno or Gatekeeper. |
| `containerd.install.enable` | `false` | Opt-in containerd integration installer. |
| `containerd.install.runtime` | `auto` | `auto`, `k3s`, `rke2`, or `containerd`. |
| `containerd.install.autoRestart` | `false` | Restart the runtime after writing config (never in `global-default`). |

## Limitations

- The privileged requirement cannot be removed on current stable Kubernetes or k3s.
- Node-local zran acceleration: the serving path is verified end-to-end (`misc/fanotify/*.sh`) and
  the binaries are bundled, but the snapshotter `Prepare`/commit lifecycle wiring is not yet merged.
  The `config.localAccel` block is therefore emitted commented out. The chart serves pre-built
  nydus/RAFS images in the interim.
- Bottlerocket cannot run an arbitrary proxy-plugin snapshotter; it supports only `overlayfs` and the
  built-in SOCI snapshotter. nydus would require a custom OS variant.
