#!/usr/bin/env bash
#
# install.sh
#
# Installs one side of the tc traffic-mirror persistence setup:
#
#   honeypot  - installs the tc mirred SPAN port (mirrors SRC_IF -> DST_IF)
#   monitor   - installs the passive capture interface (promisc + no offloads)
#
# It copies the matching script to /usr/local/sbin, installs the systemd unit,
# seeds an example env file (without clobbering an existing one), then enables
# and starts the unit.
#
# Usage:
#   sudo ./install.sh honeypot
#   sudo ./install.sh monitor
#
set -euo pipefail

SBIN_DIR="/usr/local/sbin"
UNIT_DIR="/etc/systemd/system"
CONF_DIR="/etc/mirror-persistence"

# Directory this script lives in, so it works regardless of the caller's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 {honeypot|monitor}

  honeypot   Install the tc mirred SPAN port that mirrors SRC_IF -> DST_IF.
  monitor    Install the passive capture interface (promisc + offloads off).

Must be run as root (use sudo).
EOF
    exit 1
}

ROLE="${1:-}"

case "$ROLE" in
    honeypot)
        SCRIPT_NAME="honeypot-mirror.sh"
        UNIT_NAME="honeypot-mirror.service"
        ENV_NAME="honeypot.env"
        ;;
    monitor)
        SCRIPT_NAME="monitor-capture.sh"
        UNIT_NAME="monitor-capture.service"
        ENV_NAME="monitor.env"
        ;;
    *)
        usage
        ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (try: sudo $0 $ROLE)" >&2
    exit 1
fi

# 1. Install the worker script.
install -m 0755 "${SCRIPT_DIR}/${SCRIPT_NAME}" "${SBIN_DIR}/${SCRIPT_NAME}"
echo "installed ${SBIN_DIR}/${SCRIPT_NAME} (mode 755)"

# 2. Install the systemd unit.
install -m 0644 "${SCRIPT_DIR}/${UNIT_NAME}" "${UNIT_DIR}/${UNIT_NAME}"
echo "installed ${UNIT_DIR}/${UNIT_NAME}"

# 3. Seed an example env file, but never overwrite an existing one.
mkdir -p "$CONF_DIR"
ENV_PATH="${CONF_DIR}/${ENV_NAME}"
if [[ -e "$ENV_PATH" ]]; then
    echo "keeping existing ${ENV_PATH} (not overwritten)"
else
    if [[ "$ROLE" == "honeypot" ]]; then
        cat > "$ENV_PATH" <<'EOF'
# honeypot.env - overrides for honeypot-mirror.sh
#
# Uncomment and edit to override the interface names. If left commented, the
# script falls back to its built-in defaults (SRC_IF=ens18, DST_IF=ens19).
#
# SRC_IF: the live interface being mirrored
#SRC_IF=ens18
#
# DST_IF: the dedicated mirror-out interface
#DST_IF=ens19
EOF
    else
        cat > "$ENV_PATH" <<'EOF'
# monitor.env - overrides for monitor-capture.sh
#
# Uncomment and edit to override the capture interface. If left commented, the
# script falls back to its built-in default (CAP_IF=ens19).
#
# CAP_IF: the passive capture interface
#CAP_IF=ens19
EOF
    fi
    chmod 0644 "$ENV_PATH"
    echo "wrote example env file ${ENV_PATH}"
fi

# 4. Reload systemd, then enable + start the unit.
systemctl daemon-reload
systemctl enable --now "$UNIT_NAME"

# 5. Show status and a verification reminder.
echo
systemctl --no-pager --full status "$UNIT_NAME" || true

echo
echo "----------------------------------------------------------------------"
echo "Installed and started: ${UNIT_NAME}"
echo
if [[ "$ROLE" == "honeypot" ]]; then
    echo "Verify the mirror is active:"
    echo "  tc filter show dev <SRC_IF> ingress    # should be non-empty"
    echo "  tc filter show dev <SRC_IF> root       # should be non-empty"
    echo "On the monitor VM, confirm frames arrive on the mirror link:"
    echo "  tcpdump -ni <CAP_IF> -c 20"
else
    echo "Verify the capture interface is receiving mirrored traffic:"
    echo "  tcpdump -ni <CAP_IF> -c 20"
fi
echo "----------------------------------------------------------------------"
