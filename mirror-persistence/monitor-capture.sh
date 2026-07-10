#!/usr/bin/env bash
#
# monitor-capture.sh
#
# Prepares a passive capture interface on a monitor VM. The capture interface
# (CAP_IF) receives the mirrored traffic sent by the honeypot side and must be
# up, in promiscuous mode, and with offloads disabled so the capture reflects
# what is actually on the wire.
#
# promisc mode and offload settings are runtime-only and reset on reboot, so
# this script is meant to be driven by a systemd one-shot unit at boot.
#
# Idempotent: safe to re-run at any time.
#
# Configuration (environment variables, with fallbacks):
#   CAP_IF  (default ens19)  - the passive capture interface
#
set -euo pipefail

CAP_IF="${CAP_IF:-ens19}"

# 1. Bring the capture interface up (no IP required — it only receives copies).
ip link set "$CAP_IF" up

# 2. Enable promiscuous mode so frames not addressed to us are still accepted.
ip link set "$CAP_IF" promisc on

# 3. Disable offloads so the capture sees true on-wire framing. Tolerate vNICs
#    that reject certain offload toggles.
ethtool -K "$CAP_IF" gro off gso off tso off lro off || true

echo "monitor-capture: ${CAP_IF} up, promisc on, offloads disabled"
