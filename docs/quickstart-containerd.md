# Quickstart: the Rust nydus snapshotter on stock containerd

A from-zero guide to running the Rust snapshotter (`containerd-nydus`) on a **stock containerd**
host (not k3s). For the k3s path use `profile = "k3s"` (or let `auto` detect it); everything else
below is the same.

> **Platform:** the runtime path is Linux-only. The fanotify/EROFS on-demand driver needs kernel
> ≥ 6.14; on older kernels the probe automatically falls back to fusedev (`/dev/fuse`) or a block
> device. See the platform note in [../CLAUDE.md](../CLAUDE.md).

## 1. Build / install the binary

```bash
cargo build --release -p nydus-snapshotter --bin containerd-nydus
sudo install -m0755 target/release/containerd-nydus /usr/local/bin/containerd-nydus
```

The snapshotter embeds nydus-service in-process — there is no separate `nydusd` to install or
supervise.

## 2. Minimal config.toml

Write `/etc/nydus/config.toml`. On a stock host the containerd socket
(`/run/containerd/containerd.sock`) and content-store root
(`/var/lib/containerd/io.containerd.content.v1.content`) come from the **profile** — you do not
repeat them here. A fully annotated example covering every common section ships as
[misc/configs/containerd-nydus-config.toml](../misc/configs/containerd-nydus-config.toml)
(also included in the release tarball's `configs/`).

```toml
[snapshotter]
# "containerd" pins the stock-containerd host paths. "auto" (the default) probes the well-known
# sockets and picks k3s vs stock automatically — either works on a stock host.
profile = "containerd"

# gRPC proxy-plugin socket containerd will connect to. This is the default; shown for reference
# because the containerd proxy_plugins block below must point at the same path.
address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
root = "/var/lib/containerd/io.containerd.snapshotter.v1.nydus"
```

That is enough to serve **public** images. Add a registry backend only if you need it:

```toml
# Optional. For a private / insecure registry. Auth is NOT put here — it is injected at runtime
# (see step 6). Omit this section entirely for public images over HTTPS.
[backends.registry]
# plain_http = true      # insecure/local registry with no TLS
# skip_verify = true     # self-signed TLS
```

Notes:
- The filesystem driver is auto-probed. The default preference order is
  `fanotify → blockdev(loop) → fusedev`; the first that passes the probe wins. Pin one with a
  `[[snapshotter.fs_drivers]]` block if you need determinism (e.g. `type = "fusedev"` on a
  pre-6.14 kernel).
- The sysctl admin API is **enabled by default** on
  `/run/containerd-nydus/containerd-nydus-api.sock` — used for verification (step 5) and credential
  injection (step 6).
- The default containerd namespace is `k8s.io`. For a plain `ctr`/`nerdctl` host that uses the
  `default` namespace, set `[snapshotter.containerd].namespace = "default"`. This only matters for
  the node-local acceleration path (`[snapshotter.auto_zran].enable = true`), which is **off by
  default**.

## 3. Register it as a containerd proxy plugin

Add to `/etc/containerd/config.toml` (containerd v2; only v2.x proxy-plugin API is supported). The
`proxy_plugins.nydus.address` **must** match `[snapshotter].address` from step 2.

```toml
version = 2

[proxy_plugins.nydus]
  type = "snapshot"
  address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
  [proxy_plugins.nydus.exports]
    # Required for the zran / lazy-pulling (remote snapshot) path.
    enable_remote_snapshot_annotations = "true"

# Make nydus the CRI snapshotter (skip if you only pull with `ctr --snapshotter nydus`).
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "nydus"
  disable_snapshot_annotations = false

# containerd v2 enables the Transfer service by default; a non-default snapshotter must declare its
# unpack platform or `pull --snapshotter nydus` fails with "no unpack platforms defined"
# (containerd issue #11606).
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux"
  snapshotter = "nydus"
```

A ready-to-copy version is in
[../misc/performance/containerd_config.toml](../misc/performance/containerd_config.toml).

Restart containerd after editing: `sudo systemctl restart containerd`.

## 4. Run the snapshotter

Start the snapshotter **before** containerd needs it. The reference systemd unit is
[../misc/performance/nydus-snapshotter.service](../misc/performance/nydus-snapshotter.service)
(`Type=notify` + a file-descriptor store so container mounts survive a snapshotter restart / hot
upgrade):

```bash
sudo cp misc/performance/nydus-snapshotter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nydus-snapshotter
```

Or run it directly:

```bash
sudo containerd-nydus --config /etc/nydus/config.toml
```

### Environment-variable overrides

Every core flag also reads an env var, so you can run without a mounted config file (precedence:
explicit flag > env var > TOML field > default):

| Env var                        | Overrides                          |
| ------------------------------ | ---------------------------------- |
| `NYDUS_SNAPSHOTTER_CONFIG`     | `--config` path                    |
| `NYDUS_SNAPSHOTTER_ADDRESS`    | `[snapshotter].address` (gRPC UDS) |
| `NYDUS_SNAPSHOTTER_ROOT`       | `[snapshotter].root`               |
| `NYDUS_SNAPSHOTTER_PROFILE`    | `[snapshotter].profile`            |
| `NYDUS_SNAPSHOTTER_LOG_LEVEL`  | log level (`info` default)         |

## 5. Verify it is running

**gRPC health** (containerd's dialer and `grpc_health_probe` use `grpc.health.v1.Health`):

```bash
grpc_health_probe -addr=unix:///run/containerd-nydus/containerd-nydus-grpc.sock
# status: SERVING
```

**containerd sees the plugin** and can list nydus snapshots:

```bash
ctr snapshot --snapshotter nydus ls
```

**sysctl admin API** over the UDS — Prometheus metrics and allocator/process-memory stats:

```bash
curl --unix-socket /run/containerd-nydus/containerd-nydus-api.sock http://localhost/metrics
curl --unix-socket /run/containerd-nydus/containerd-nydus-api.sock http://localhost/debug/allocator
```

(To expose Prometheus over TCP as well, set `[snapshotter.metrics].listen = "127.0.0.1:9110"`.)
See [operations.md](./operations.md) for the full ops runbook (memory stats, CPU profiling).

**Pull an image through nydus:**

```bash
ctr images pull --snapshotter nydus docker.io/library/nginx:latest
```

## 6. Private-registry credentials (optional)

The snapshotter pulls layer bytes itself, so it needs registry credentials for private images.
Auth is **not** stored in `config.toml`; it is injected at runtime into an in-memory auth store via
the sysctl API (`PUT /api/v1/auth`), typically by the `nydus-credential-bridge` binary. The full
flow — including wrapping a kubelet credential-provider plugin — is in
[credentials.md](./credentials.md).

Quick one-off injection:

```bash
echo '[{"registry":"registry.example.com","auth":"dXNlcjpwYXNz","expires_in_seconds":600}]' \
  | nydus-credential-bridge inject
```

(`auth` is base64 of `username:password`, the Docker config `auth` field format.)

## See also

- [ARCHITECTURE.md](../ARCHITECTURE.md) — design, runtime (compio), profiles, backends, storage
- [credentials.md](./credentials.md) — registry auth flow and the credential bridge
- [operations.md](./operations.md) — metrics, allocator stats, CPU profiling
