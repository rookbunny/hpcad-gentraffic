#!/usr/bin/env bash
#
# honeypot-mirror.sh
#
# Sets up a tc mirred SPAN (port-mirror) so that all traffic seen on the live
# interface (SRC_IF) is copied out of a dedicated mirror-out interface (DST_IF).
#
# tc qdiscs/filters live only in the running kernel and are wiped on reboot,
# so this script is meant to be driven by a systemd one-shot unit at boot.
#
# Idempotent: existing qdiscs are torn down before new ones are added, so it is
# safe to re-run at any time.
#
# Configuration (environment variables, with fallbacks):
#   SRC_IF  (default ens18)  - the live interface being mirrored
#   DST_IF  (default ens19)  - the dedicated mirror-out interface
#
set -euo pipefail

SRC_IF="${SRC_IF:-ens18}"
DST_IF="${DST_IF:-ens19}"

# 1. Disable offloads on both interfaces. Offloading (GRO/GSO/TSO/LRO) coalesces
#    packets and can hide the true on-wire framing from a passive capture, so we
#    turn it off. Some vNICs reject certain offload toggles, so tolerate failure.
for IF in "$SRC_IF" "$DST_IF"; do
    ethtool -K "$IF" gro off gso off tso off lro off || true
done

# 2. Make sure the mirror-out interface is up so mirrored frames can egress.
ip link set "$DST_IF" up

# 3. Clear any existing qdiscs first so re-runs stay clean (|| true when absent).
tc qdisc del dev "$SRC_IF" ingress || true
tc qdisc del dev "$SRC_IF" root    || true

# 4. Ingress mirror: copy every inbound packet out of DST_IF.
tc qdisc add dev "$SRC_IF" handle ffff: ingress
tc filter add dev "$SRC_IF" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress mirror dev "$DST_IF"

# 5. Egress mirror: copy every outbound packet out of DST_IF.
tc qdisc add dev "$SRC_IF" handle 1: root prio
tc filter add dev "$SRC_IF" parent 1: protocol all u32 match u32 0 0 \
    action mirred egress mirror dev "$DST_IF"

echo "honeypot-mirror: mirroring ${SRC_IF} -> ${DST_IF} (ingress + egress)"
