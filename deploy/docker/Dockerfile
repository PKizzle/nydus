# Multi-stage build for the nydus v3 snapshotter image used by the Helm chart.
# Bundles: containerd-nydus (snapshotter + in-process nydusd) and nydus-image (node-local zran
# conversion shells out to it). Build multi-arch with `docker buildx build --platform
# linux/amd64,linux/arm64` (arm64 covers Raspberry Pi / k3s on Pi).
#
#   docker buildx build -f deploy/docker/Dockerfile -t <repo>:<tag> --push .

ARG RUST_VERSION=1.85
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
# System deps for the storage backends (openssl) and EROFS/FUSE-adjacent crates.
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev cmake clang \
 && rm -rf /var/lib/apt/lists/*
COPY . .
# Build only what the node needs. The snapshotter links nydus-service in-process, so no separate
# nydusd binary is required at runtime.
RUN cargo build --release \
      --bin containerd-nydus \
      --bin nydus-image \
 && strip target/release/containerd-nydus target/release/nydus-image

FROM debian:bookworm-slim AS runtime
# Runtime tools the binaries invoke: ionice/nice (SchedClass low-priority conversion), mount/umount
# (EROFS/loop), fuse for the fusedev fallback, nsenter (opt-in containerd-config installer), and
# erofs-utils for diagnostics. util-linux provides ionice/nice/nsenter/mount.
RUN apt-get update && apt-get install -y --no-install-recommends \
      util-linux fuse3 ca-certificates erofs-utils \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/containerd-nydus /usr/local/bin/containerd-nydus
COPY --from=build /src/target/release/nydus-image      /usr/local/bin/nydus-image
# nydusify (Go, registry push-flow) is OPTIONAL and only used by auto_zran; the node-local accel
# path does not need it. Add it here if you enable auto_zran:
#   COPY --from=<nydusify-build> /nydusify /usr/local/bin/nydusify
ENTRYPOINT ["/usr/local/bin/containerd-nydus"]
CMD ["--config", "/etc/nydus/config.toml"]
