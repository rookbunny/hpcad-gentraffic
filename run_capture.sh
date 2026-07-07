#!/usr/bin/env bash
# Orchestrate one capture: start tcpdump on the mirror, run the generator for the
# profile's window, then stop both. Everything for the run lands in one directory,
# logs/<run_id>_logs/, under the repository root: the pcap, the ground-truth logs,
# and the manifest. A pointer to the active run is written to .current_run in the
# repository root so log_user.py can pick it up automatically.
#
# Run on the capture host (the one that sees the mirror). For the promsvc scrape,
# run gen.py on the monitoring VM with the SAME seed and run id this prints.
#
#   sudo ./run_capture.sh baseline ens19            # fresh random seed
#   sudo ./run_capture.sh run2     ens19  1337       # pinned seed
#
# ens19 = the interface carrying the mirror copy off the honeypot.
set -euo pipefail

PROFILE="${1:?usage: run_capture.sh <profile> <capture_iface> [seed]}"
IFACE="${2:?need capture interface, e.g. ens19}"
SEED="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$HERE/.venv/bin/python3"; [ -x "$PYTHON" ] || PYTHON="python3"

STAMP="$(date +%Y%m%d-%H%M%S)"
[ -z "$SEED" ] && SEED="$RANDOM$RANDOM"
RUN_ID="${PROFILE}-${STAMP}-${SEED}"
RUN_DIR="$HERE/logs/${RUN_ID}_logs"
PCAP="${RUN_DIR}/${RUN_ID}.pcap"

mkdir -p "$RUN_DIR"
echo "$RUN_ID" > "$HERE/.current_run"

echo "[*] run_id=$RUN_ID"
echo "[*] dir   =$RUN_DIR"
echo "[*] pcap  =$PCAP  (iface $IFACE)"
echo "[*] seed  =$SEED  -> use this same seed AND run-id for gen.py on the promsvc VM"

# capture everything on the mirror; full snaplen for payload / JA3 analysis
tcpdump -i "$IFACE" -s 0 -w "$PCAP" -U &
TCPDUMP_PID=$!
trap 'kill $TCPDUMP_PID 2>/dev/null || true' EXIT
sleep 2   # let tcpdump attach before traffic starts

"$PYTHON" "$HERE/gen.py" --profile "$PROFILE" --role honeypot \
    --seed "$SEED" --run-id "$RUN_ID" --base "$HERE" --config "$HERE/config.yaml"

sleep 2   # flush tail packets
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
trap - EXIT

echo "[+] capture complete. In $RUN_DIR:"
echo "    ${RUN_ID}.pcap                     packet capture"
echo "    ${RUN_ID}_knownbenign.json         scripted benign events"
echo "    ${RUN_ID}_knownuser.json           manual/attacker events"
echo "    ${RUN_ID}_alltraffic.json          union of both"
echo "    ${RUN_ID}.honeypot.manifest.json"
echo
echo "[i] During run1/run2, log attacker actions and browsing with:"
echo "    $PYTHON $HERE/log_user.py \"<note>\" --source attacker|browsing"
