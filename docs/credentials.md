# Registry credentials in the Rust snapshotter

The Rust snapshotter (`snapshotter/`) pulls layer bytes itself (via the fanotify/EROFS
on-demand path and node-local zran conversion), so it needs registry credentials for private
images the same way `nydusd`'s registry backend does. This document describes how those
credentials reach the daemon **today**, and explicitly calls out what is *not* implemented.

## How it works today: a runtime auth store fed by an external bridge

Kubernetes does not hand a remote snapshotter registry credentials directly. The kubelet's
intended flow is:

```
imagePullSecrets / kubelet credential-provider plugins → CRI PullImage auth → container runtime
```

A remote snapshotter sits outside that handoff — containerd never forwards the credentials it
used for a pull to the snapshotter plugin. To close that gap without reading Docker config files
or Kubernetes `Secret` objects directly, the snapshotter exposes a small **in-memory runtime auth
store** (`snapshotter/src/daemon/auth.rs`) that something else populates at runtime:

- `resolve_auth(config, image_ref)` (`snapshotter/src/daemon/auth.rs:60`) is the single lookup
  point. It is called from `DaemonSupervisor` (`snapshotter/src/daemon/mod.rs:1337-1338`, used at
  both initial spawn and failover-recovery spawn) and from referrer detection
  (`snapshotter/src/source/referrer.rs:192`) before a daemon/backend is built for an image.
- Internally it consults `runtime_auth()`, which looks up a process-wide `OnceLock<Mutex<..>>`
  store keyed by registry, trying the most specific match first: `host/repo/subpath`, then
  `host/repo`, then bare `host` — checking both the API host and the mirror host, plus the
  Docker Hub `https://index.docker.io/v1/` alias (`auth_candidates` /
  `push_repo_scoped_candidates`, `snapshotter/src/daemon/auth.rs:107-147`).
- The stored value is the Docker-style base64 `user:password` string nydusd's registry backend
  expects for the `Authorization: Basic <auth>` header — the module never stores raw
  username/password pairs.
- Entries carry an optional TTL (`expires_in_seconds`) and are pruned lazily on every read/write
  (`RuntimeAuthStore::prune_expired`).

If no entry is found for any candidate key, `resolve_auth` returns `None` and the pull proceeds
unauthenticated (fine for public images, fails for private ones — same behavior as not
configuring auth at all).

### The sysctl HTTP API: `/api/v1/auth`

The runtime auth store is populated over the snapshotter's local sysctl HTTP API
(`snapshotter/src/sysctl.rs`), served on the same Unix socket as the daemon/cache/prefetch admin
endpoints (default `/run/containerd-nydus/containerd-nydus-api.sock`,
`default_sysctl_address()` in `snapshotter/src/config/mod.rs`):

- `PUT /api/v1/auth` — body is a JSON array of entries, injects/overwrites credentials in the
  store (`handle_auth_put`, `snapshotter/src/sysctl.rs:578`):

  ```json
  [
    { "registry": "registry.example.com/team/app", "auth": "dXNlcjpwYXNz", "expires_in_seconds": 300 }
  ]
  ```

  `auth` is the base64 of `username:password` (Docker config `auth` field format). Response:
  `{"registries": <count currently cached>}`.

- `GET /api/v1/auth` — returns the **non-secret** metadata for cached entries (registry key +
  expiry timestamp only, never the credential value) — useful for debugging what is currently
  cached, without leaking secrets over the admin socket.

Nothing calls this endpoint automatically; something outside the snapshotter process must PUT
credentials into it before a private-image pull needs them.

### `nydus-credential-bridge`: the intended caller of `/api/v1/auth`

`snapshotter/src/bin/nydus-credential-bridge.rs` is a small standalone binary built for that
purpose. It never reads Docker config or Kubernetes `Secret` files itself; it only relays
credentials from something that already produced them, straight into the sysctl socket. Two
subcommands:

- **`nydus-credential-bridge inject`** — reads credential JSON from stdin (native runtime-auth
  array/envelope, or a kubelet `CredentialProviderResponse`, auto-detected) and PUTs it to
  `/api/v1/auth`.
- **`nydus-credential-bridge wrap <provider> [args...]`** — wraps a
  [kubelet credential-provider plugin](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/)
  executable: forwards kubelet's request on stdin to `<provider>`, injects the provider's
  `CredentialProviderResponse` into `/api/v1/auth`, and tees the original response back to
  stdout unchanged (so it remains a drop-in credential-provider from kubelet's point of view).
  It maps each `auth` entry's `cacheDuration` (Go-duration string, e.g. `5m0s`) to
  `expires_in_seconds`, and skips wildcard registry scopes (`*.example.com`) since the runtime
  store only matches literal scopes.

Example wiring in a kubelet credential-provider config, so every kubelet-driven credential
refresh is mirrored into the snapshotter:

```yaml
# /etc/kubernetes/credential-providers.yaml (kubelet CredentialProviderConfig)
providers:
  - name: nydus-credential-bridge
    matchImages: ["registry.example.com"]
    defaultCacheDuration: "5m"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    args: ["wrap", "/usr/local/bin/real-credential-provider"]
```

or invoked manually / from a script for one-off injection:

```bash
echo '[{"registry":"registry.example.com","auth":"dXNlcjpwYXNz","expires_in_seconds":600}]' \
  | nydus-credential-bridge inject
```

`--sysctl-socket` (default `/run/containerd-nydus/containerd-nydus-api.sock`) and
`--default-ttl-seconds` (default `300`) are configurable flags.

## What is NOT implemented: CRI keychain / image-service credential proxying

The Go `nydus-snapshotter` (`containerd/nydus-snapshotter`, now LTS-only) supports
`EnableCRIKeychain` + `ImageServiceAddress`: it dials the CRI **image service** gRPC endpoint
(default `/run/containerd/containerd.sock`, see `DefaultImageServiceAddress` in
`nydus-snapshotter/pkg/auth/cri.go`) and proxies/relays credentials extracted from CRI
`PullImage` requests via `github.com/containerd/stargz-snapshotter/service/keychain/cri`,
so registry auth is transparently forwarded from the kubelet/CRI client with no separate
credential path to configure.

**The Rust snapshotter has no equivalent.** There is no `EnableCRIKeychain` config field, no CRI
image-service client, and no code that proxies or intercepts CRI `PullImage` credentials. This is
an **explicit non-goal for now**, not an oversight:

- CRI keychain proxying means dialing (and staying compatible with) the CRI `ImageService` gRPC
  API and reconstructing per-pull credential context outside the normal request path — a
  meaningfully larger surface than the runtime-auth-store approach above, for a use case (opaque
  CRI-only credential sources) that has not yet shown up as a real blocker.
- The runtime-auth-store + credential-bridge path already covers the common cases: static
  registry secrets, and kubelet credential-provider plugins (via `nydus-credential-bridge wrap`),
  which is how most clusters obtain per-pull credentials today (ECR/GCR/ACR provider binaries,
  `imagePullSecrets`-backed providers, etc).

**If your cluster relies on CRI-proxied pull credentials** (i.e. registry auth that only exists
inside containerd's CRI image-service call and is not obtainable via a kubelet credential-provider
plugin or a static secret), you have two options today:

1. Wrap the credential source as a kubelet credential-provider plugin and point
   `nydus-credential-bridge wrap` at it (preferred — this is the supported path and matches how
   kubelet itself would obtain the credential).
2. Push credentials directly via `nydus-credential-bridge inject` / `PUT /api/v1/auth` from
   whatever process already holds them (e.g. a sidecar or init step that resolves secrets from a
   vault).

The trigger to revisit CRI keychain support is real demand from a cluster whose only
credential source is CRI-proxied auth (not reachable via a kubelet credential-provider
plugin or a static secret).
