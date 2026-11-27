#!/bin/sh
# Installs, removes and watches the nydus snapshotter as a systemd service on the host
# (deploymentMode: hostSystemd). Runs in a privileged hostPID pod and reaches the host through
# PID 1's namespaces, so it uses the host's own systemctl and journalctl; files from the image are
# streamed into the host over stdin.
#
#   host-systemd.sh run          install, then follow the unit's journal (HOST_SYSTEMD_ACTION=install),
#                                or uninstall, then idle until deleted (HOST_SYSTEMD_ACTION=uninstall)
#   host-systemd.sh install      install or update; restart the unit only if a file changed
#   host-systemd.sh uninstall    stop, disable and remove a unit this chart installed; no-op otherwise
#   host-systemd.sh probe [ready]  liveness/readiness of the host unit (or of the uninstall)
# Host-side commands are single-quoted on purpose: they expand in the host shell.
# shellcheck disable=SC2016
set -eu

UNIT=${UNIT:-nydus-snapshotter.service}
# Sources inside the image / pod.
SRC_BIN_DIR=${SRC_BIN_DIR:-/usr/local/bin}
SRC_CONFIG=${SRC_CONFIG:-/etc/nydus/config.toml}
SRC_UNIT=${SRC_UNIT:-/host-systemd/$UNIT}
# Destinations on the host. The unit's ExecStart and the snapshotter's default nydus-image path
# (auto_zran) name these, so they are fixed.
BIN_DIR=/usr/local/bin
CONFIG=/etc/nydus/config.toml
UNIT_FILE=/etc/systemd/system/$UNIT
BINARIES="containerd-nydus nydus-image"
# Host tmpfs, so a reboot (which starts the unit fresh anyway) clears it.
RUN_DIR=${RUN_DIR:-/run/containerd-nydus}
RESTART_MARKER=$RUN_DIR/host-systemd.restart-required
API_SOCKET=${API_SOCKET:-$RUN_DIR/containerd-nydus-api.sock}
# A unit without this line is not ours: install refuses to replace it, uninstall leaves it alone.
OWNER_TAG='# Managed by the nydus-snapshotter Helm chart (deploymentMode: hostSystemd).'
UNINSTALLED=/tmp/host-systemd.uninstalled

log() { echo ">> host-systemd: $*"; }
host() { nsenter -t 1 -m -u -i -n -p -- "$@"; }

host_sum() { # prints the sha256 of a host file, or nothing when it does not exist
  host sh -c '[ -f "$1" ] && sha256sum < "$1" | cut -d" " -f1 || true' sh "$1"
}

# put <src> <host dst> <mode> [verify]: write src to dst if their contents differ. The new file is
# written beside dst and renamed over it, so a running process keeps its old inode and a reader
# never sees a partial file. With "verify" the new binary must run on the host before the rename.
put() {
  src=$1 dst=$2 mode=$3 verify=${4:-}
  [ -f "$src" ] || { log "missing source $src"; exit 1; }
  [ "$(sha256sum < "$src" | cut -d' ' -f1)" = "$(host_sum "$dst")" ] && return 0
  # Mark first: if this run dies between the rename and the restart, the next run still restarts.
  host sh -c 'mkdir -p "$(dirname "$1")" && : > "$1"' sh "$RESTART_MARKER"
  host sh -c '
    set -e
    mkdir -p "$(dirname "$1")"
    cat > "$1.new"
    chmod "$2" "$1.new"
    sync "$1.new"
    if [ -n "$3" ] && ! "$1.new" --version > /dev/null; then
      rm -f "$1.new"; echo "$1.new does not run on this host" >&2; exit 1
    fi
    mv -f "$1.new" "$1"' sh "$dst" "$mode" "$verify" < "$src"
  log "updated $dst"
}

managed_unit() { host grep -qxF "$OWNER_TAG" "$UNIT_FILE" 2> /dev/null; }

install() {
  if host test -e "$UNIT_FILE" && ! managed_unit; then
    log "$UNIT_FILE exists and was not installed by this chart; remove it or use deploymentMode=pod"
    exit 1
  fi
  # The unit goes first: once it carries the owner tag, uninstall removes everything below.
  put "$SRC_UNIT" "$UNIT_FILE" 0644
  put "$SRC_CONFIG" "$CONFIG" 0600
  for b in $BINARIES; do put "$SRC_BIN_DIR/$b" "$BIN_DIR/$b" 0755 verify; done
  host systemctl daemon-reload
  host systemctl enable --quiet "$UNIT"
  # A unit that hit its start limit stays failed until reset; a new installer run starts it again.
  host systemctl reset-failed "$UNIT" 2> /dev/null || true
  if host test -e "$RESTART_MARKER"; then
    # With FileDescriptorStorePreserve=restart this is the fd-store takeover path.
    log "files changed: restarting $UNIT"
    host systemctl restart "$UNIT"
    host rm -f "$RESTART_MARKER"
  else
    log "files unchanged: starting $UNIT if it is not running"
    host systemctl start "$UNIT"
  fi
  log "$UNIT is $(host systemctl is-active "$UNIT" || true)"
}

uninstall() {
  if ! host test -e "$UNIT_FILE"; then
    log "no $UNIT on this host"
    return 0
  fi
  if ! managed_unit; then
    log "$UNIT_FILE was not installed by this chart; leaving it alone"
    return 0
  fi
  log "stopping and disabling $UNIT"
  host systemctl disable --now --quiet "$UNIT"
  for f in "$CONFIG" $(for b in $BINARIES; do echo "$BIN_DIR/$b"; done) "$RESTART_MARKER"; do
    host rm -f "$f" "$f.new"
  done
  host rmdir "$(dirname "$CONFIG")" 2> /dev/null || true
  # The unit file goes last, so a retry after a failure here still recognises the files as ours.
  host rm -f "$UNIT_FILE" "$UNIT_FILE.new"
  host systemctl daemon-reload
  host systemctl reset-failed "$UNIT" 2> /dev/null || true
  log "removed $UNIT and its files"
}

case "${1:-run}" in
  install) install ;;
  uninstall) uninstall ;;
  probe)
    if [ "${HOST_SYSTEMD_ACTION:-install}" = uninstall ]; then
      test -f "$UNINSTALLED"
    elif [ "${2:-}" = ready ]; then
      exec "$SRC_BIN_DIR/containerd-nydus" healthcheck --ready --socket="$API_SOCKET"
    else
      exec "$SRC_BIN_DIR/containerd-nydus" healthcheck --socket="$API_SOCKET"
    fi
    ;;
  run)
    case "${HOST_SYSTEMD_ACTION:-install}" in
      install)
        install
        # kubectl logs shows the host unit's journal.
        exec nsenter -t 1 -m -u -i -n -p -- journalctl --unit="$UNIT" --follow --lines=100 --output=cat
        ;;
      uninstall)
        uninstall
        : > "$UNINSTALLED"
        exec sleep infinity
        ;;
      *) log "unknown HOST_SYSTEMD_ACTION=$HOST_SYSTEMD_ACTION"; exit 2 ;;
    esac
    ;;
  *) echo "usage: $0 [run|install|uninstall|probe [ready]]" >&2; exit 2 ;;
esac
