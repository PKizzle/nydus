# Nydus Setup for Containerd Environment

This document will walk through how to setup a nydus image service to work with containerd. It assumes that you already have `containerd` installed. If not, please refer to [containerd documents](https://github.com/containerd/containerd/blob/master/docs/ops.md) on how to install and set it up.

## Install All Nydus Binaries

Get `nydus-image`, `nydusd`, `nydusify`, `nydusctl` and the snapshotter binaries
(`containerd-nydus`, `nydus-migrate`, `nydus-credential-bridge`) from the
[release](https://github.com/dragonflyoss/nydus/releases/latest) page — they all
ship in one tarball now.

```bash
sudo install -D -m 755 nydusd nydus-image nydusify nydusctl /usr/bin
sudo install -D -m 755 containerd-nydus nydus-migrate nydus-credential-bridge /usr/local/bin
```

## Start a Local Registry Container

To make it easier to convert and run nydus images next, we can run a local registry service with docker:

```bash
sudo docker run -d --restart=always -p 5000:5000 registry
```

## Convert/Build an Image to Nydus Format

Nydus image can be created by converting from an existing OCI or docker v2 image stored in container registry or directly built from Dockerfile(with [Buildkit](https://github.com/nydusaccelerator/buildkit/blob/master/docs/nydus.md))

Note: For private registry repo, please make sure you are authorized to pull and push the target registry. The basic method is to use `docker pull` and `docker push` to verify your access to the source or target registry.

```bash
sudo nydusify convert --source ubuntu --target localhost:5000/ubuntu-nydus
```

For more details about how to build nydus image, please refer to [Nydusify](https://github.com/dragonflyoss/nydus/blob/master/docs/nydusify-rust.md) conversion tool, [Acceld](https://github.com/goharbor/acceleration-service) conversion service or [Nerdctl](https://github.com/containerd/nerdctl/blob/master/docs/nydus.md#build-nydus-image-using-nerdctl-image-convert).

## Start Nydus Snapshotter

Nydus provides a containerd remote snapshotter, the single `containerd-nydus`
binary, to prepare container rootfs with nydus formatted images. It runs the
nydus daemon in-process (no separate `nydusd` child) and is configured by one
unified TOML file that replaces both the legacy Go-snapshotter TOML and the
`nydusd` JSON.

1. Install a configuration to `/etc/nydus/config.toml`. Start from the
   annotated example at
   [misc/configs/containerd-nydus-config.toml](../misc/configs/containerd-nydus-config.toml);
   the built-in defaults (kernel-capability probe picks fanotify → blockdev →
   fusedev automatically) are sensible, so a minimal file is enough:

```bash
sudo mkdir -p /etc/nydus
sudo tee /etc/nydus/config.toml > /dev/null << EOF
[snapshotter]
root = "/var/lib/containerd/io.containerd.snapshotter.v1.nydus"
address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
log_level = "info"
log_to_stdout = true
EOF
```

Registry credentials are resolved at runtime through the sysctl auth API and
the `nydus-credential-bridge` helper — see [credentials.md](./credentials.md).

2. [Optional] Make sure the snapshotter root directory is clear:

```
sudo rm -rf /var/lib/containerd/io.containerd.snapshotter.v1.nydus
```

3. Start the snapshotter:

```bash
sudo /usr/local/bin/containerd-nydus --config /etc/nydus/config.toml
```

For a full walkthrough (systemd unit, health checks, Kubernetes/Helm
deployment) see [quickstart-containerd.md](./quickstart-containerd.md).

## [Option 1] Configure as Containerd Global Snapshotter

Nydus depends on two features of Containerd:

- Support remote snapshotter plugin
- Support passing annotations to remote snapshotter

To enable them, add below configuration items to your `containerd` configuration file (default path is `/etc/containerd/config.toml`):

```toml
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
```

When working with Kubernetes CRI, please change the default snapshotter to `nydus` and enable snapshot annotations like below:

For version 1 containerd config format:

```toml
[plugins.cri]
  [plugins.cri.containerd]
    snapshotter = "nydus"
    disable_snapshot_annotations = false
    discard_unpacked_layers = false
```

For version 2 containerd config format:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
   snapshotter = "nydus"
   disable_snapshot_annotations = false
   discard_unpacked_layers = false
```

For version 3 containerd config format:

```toml
[plugins]
  [plugins.'io.containerd.cri.v1.images']
    snapshotter = 'nydus'
    disable_snapshot_annotations = false
    discard_unpacked_layers = false
```

Then restart containerd, e.g.:

```bash
sudo systemctl restart containerd
```

## [Option 2] Configure as Containerd Runtime-Level Snapshotter

Note: this way only works on CRI based scenario (for example crictl or kubernetes).

Containerd (>= v1.7.0) supports configuring the `runtime-level` snapshotter. By following the steps below, we can declare runtimes that use different snapshotters:

### Step 1: Apply Containerd Patches

[Patch](https://github.com/nydusaccelerator/containerd/commit/0959cdb0b190e35c058a0e5bc2e256e59b95b584): fixes the handle of sandbox run and container create for runtime-level snapshotter;

### Step 2: Configure Containerd

Only for version 2 containerd config format:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"
  disable_snapshot_annotations = false
  discard_unpacked_layers = false

  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc-nydus]
    snapshotter = "nydus"

[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
```

Then restart containerd, e.g.:

```bash
sudo systemctl restart containerd
```

### Step 3: Add an Extra Annotation in Sandbox Spec

The annotation `"io.containerd.cri.runtime-handler": "runc-nydus"` must be set in sandbox spec. The `nydus-sandbox.yaml` looks like below:

```yaml
metadata:
  attempt: 1
  name: nydus-sandbox
  namespace: default
  uid: nydus-sandbox-test
log_directory: /tmp
linux:
  security_context:
    namespace_options:
      network: 2
annotations:
  "io.containerd.cri.runtime-handler": "runc-nydus"
```

As shown above, the sandbox is declared with `"io.containerd.cri.runtime-handler": "runc-nydus"` annotation will use the `nydus` snapshotter, while others will use the default `overlayfs` snapshotter.

## Multiple Snapshotter Switch Troubleshooting

⚠️ You may encounter the following error when creating a Pod:

```
err="failed to \"StartContainer\" for \"xxx\" with CreateContainerError: \"failed to create containerd container: error unpacking image: failed to extract layer sha256:yyy: failed to get reader from content store: content digest sha256:zzz: not found\""
```

One possible reason is some images in the Pod (including the Pause image) have used containerd's default snapshotter (such as the `overlayfs` snapshotter), and the `discard_unpacked_layers` option was previously set to `true` in containerd config, containerd has already deleted the blobs from the content store. To resolve this issue, you should first ensure that `discard_unpacked_layers=false`, then use the following command to restore the image:

```
ctr -n k8s.io content fetch pause:3.8
```

Please note that `pause:3.8` is just an example image, you should also fetch all images used by the Pod to ensure that there are no issues.

## Try Nydus with `nerdctl`

Nydus snapshotter has been supported by [nerdctl](https://github.com/containerd/nerdctl)(requires >= v0.22), we can lazily start container with it.

```bash
$ sudo nerdctl --snapshotter nydus run --rm -it localhost:5000/ubuntu-nydus:latest bash
```

## Create Pod with Nydus Image in Kubernetes

For example, use the following `nydus-sandbox.yaml` and `nydus-container.yaml`

The `nydus-sandbox.yaml` looks like below:

```yaml
metadata:
  attempt: 1
  name: nydus-sandbox
  namespace: default
  uid: nydus-sandbox-test
log_directory: /tmp
linux:
  security_context:
    namespace_options:
      network: 2
```

The `nydus-container.yaml` looks like below:

```yaml
metadata:
  name: nydus-container
image:
  image: localhost:5000/ubuntu-nydus:latest
command:
  - /bin/sleep
args:
  - 600
log_path: container.1.log
```

To create a pod with the just converted nydus image:

```bash
$ sudo crictl pull localhost:5000/ubuntu-nydus:latest
$ pod=`sudo crictl runp nydus-sandbox.yaml`
$ container=`sudo crictl create $pod nydus-container.yaml nydus-sandbox.yaml`
$ sudo crictl start $container
$ sudo crictl ps
CONTAINER ID        IMAGE                                CREATED             STATE               NAME                      ATTEMPT             POD ID
f4a6c6dc47e34       localhost:5000/ubuntu-nydus:latest   9 seconds ago       Running             nydus-container           0                   21b91779d551e
```

## Integrate P2P with Dragonfly

Nydus is deeply integrated with [Dragonfly](https://d7y.io/) P2P system, which can greatly reduce the network latency and the single point of network pressure for registry server, testing in the production environment shows that using Dragonfly can reduce network latency by more than 80%, to understand the performance test data and how to configure Nydus to use Dragonfly, please refer to the [doc](https://d7y.io/docs/setup/integration/nydus).
