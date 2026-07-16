#!/bin/bash

: ${INSTALL_TARGET_TYPE:="release"}

SNAPSHOTTER_CONFIG="misc/performance/snapshotter_config.toml"
if [ "$1" == "takeover_test" ]; then
    sed -i 's/recover_policy = "restart"/recover_policy = "failover"/' "$SNAPSHOTTER_CONFIG"
fi

# Pin nerdctl to the 1.7.x line. nerdctl v2 pulls via containerd's Transfer service, which does not
# propagate the remote-snapshot image-ref annotation a proxy snapshotter needs (containerd issues
# #11606 / #11082), so `nerdctl run --snapshotter nydus` fails with "failed to find image ref of
# snapshot". nerdctl 1.7.x uses the legacy client-side pull that sets the label. This mirrors the
# nydus-snapshotter project's own integration test (NERDCTL_VER=1.7.6 with containerd v2).
readonly NERDCTL_VERSION=1.7.6
readonly CNI_PLUGINS_VERSION=`curl -s https://api.github.com/repos/containernetworking/plugins/releases/latest | grep tag_name | cut -f4 -d "\""`

# setup nerdctl and nydusd env
# nydusify is now the in-repo Rust crate (cargo build -p nydusify); the Go contrib/nydusify is gone.
sudo install -D -m 755 target/$INSTALL_TARGET_TYPE/nydusify /usr/local/bin
sudo install -D -m 755 target/$INSTALL_TARGET_TYPE/nydusd target/$INSTALL_TARGET_TYPE/nydus-image /usr/local/bin
# Install the in-repo Rust nydus snapshotter (containerd-nydus). It links nydus-service and runs the
# daemon in-process from a single unified TOML config, replacing the legacy Go containerd-nydus-grpc
# (which forked nydusd and needed a separate nydusd JSON config).
sudo install -D -m 755 target/$INSTALL_TARGET_TYPE/containerd-nydus /usr/local/bin
sudo wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
sudo tar -xzvf nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin
sudo mkdir -p /opt/cni/bin
sudo wget https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz
sudo tar -xzvf cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz -C /opt/cni/bin

# Upgrade containerd past the runner's stock v2.0.x, which lacks the Transfer-API unpacker fix
# (containerd#11236) and fails to pull with a snapshotter set: "unable to initialize unpacker: no
# unpack platforms defined" (containerd issues #11228 / #11606). Track the current stable line,
# which is what production clusters (k3s) actually run; the nerdctl 1.7.x pin above is the only
# version constraint that is load-bearing for the proxy-snapshotter annotation.
readonly CONTAINERD_VERSION=2.3.3
wget -q https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-amd64.tar.gz
sudo tar -C /usr -xzf containerd-static-${CONTAINERD_VERSION}-linux-amd64.tar.gz

sudo install -D misc/performance/containerd_config.toml /etc/containerd/config.toml
sudo systemctl restart containerd
# The Rust snapshotter builds the per-image nydusd backend/cache config in-process
# (snapshotter/src/daemon/config_builder.rs), so no separate nydusd JSON is installed.
sudo install -D $SNAPSHOTTER_CONFIG /etc/nydus/config.toml
sudo install -D misc/performance/nydus-snapshotter.service /etc/systemd/system/nydus-snapshotter.service
sudo systemctl start nydus-snapshotter

# setup protoc
bash misc/install-protoc.sh
