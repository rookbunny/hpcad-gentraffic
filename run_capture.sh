#!/usr/bin/env bash
# Orchestrate one capture: start tcpdump on the mirror, run the generator for the
# profile's window, then stop both. Everything for the run lands in one directory,
# logs/<tag>_logs/, under the repository root, where the tag is the run's
# R<run_id>-S<seed> stem: the pcap, the ground-truth logs, and the manifest. A
# pointer to the active run (the tag) is written to .current_run in the repository
# root so log_user.py can pick it up automatically.
#
# Run on the capture host (the one that sees the mirror). For the promsvc scrape,
# run gen.py on the monitoring VM with the SAME seed and run id this prints.
#
#   sudo ./run_capture.sh baseline ens19            # fresh random 5-digit seed
#   sudo ./run_capture.sh run2     ens19  13370      # pinned seed
#
# ens19 = the interface carrying the mirror copy off the honeypot.
set -euo pipefail

PROFILE="${1:?usage: run_capture.sh <profile> <capture_iface> [seed]}"
IFACE="${2:?need capture interface, e.g. ens19}"
SEED="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$HERE/.venv/bin/python3"; [ -x "$PYTHON" ] || PYTHON="python3"

# fresh random 5-digit seed if none pinned
[ -z "$SEED" ] && SEED=$(( (RANDOM % 90000) + 10000 ))

# next zero-padded sequential run id (0001, 0002, ...) from existing run dirs
NEXT=1
for d in "$HERE"/logs/R*-S*_logs; do
    [ -e "$d" ] || continue
    b="$(basename "$d")"; num="${b#R}"; num="${num%%-*}"; num=$((10#$num))
    [ "$num" -ge "$NEXT" ] && NEXT=$((num + 1))
done
RUN_ID="$(printf '%04d' "$NEXT")"

TAG="R${RUN_ID}-S${SEED}"
RUN_DIR="$HERE/logs/${TAG}_logs"
PCAP="${RUN_DIR}/${TAG}.pcap"

mkdir -p "$RUN_DIR"
echo "$TAG" > "$HERE/.current_run"

echo "[*] run_id=$RUN_ID  tag=$TAG"
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
echo "    ${TAG}.pcap                     packet capture"
echo "    ${TAG}_knownbenign.json         scripted benign events"
echo "    ${TAG}_knownuser.json           manual/attacker events"
echo "    ${TAG}_alltraffic.json          union of both"
echo "    ${TAG}.honeypot.manifest.json"
echo
echo "[i] During run1/run2, log attacker actions and browsing with:"
echo "    $PYTHON $HERE/log_user.py \"<note>\" --source attacker|browsing"
