#!/usr/bin/env bash
# Orchestrate one capture: start tcpdump on the mirror, start the Zabbix packet
# logger, run the generator, then stop all three and verify what landed on disk.
# Everything for the run lands in one directory, logs/<tag>_logs/, under the
# repository root, where the tag is the run's R<run_id>-S<seed> stem: the pcap,
# the ground-truth logs, and the manifest. A pointer to the active run (the tag)
# is written to .current_run in the repository root so log_user.py can pick it up
# automatically.
#
# ZABBIX: no Zabbix traffic is generated. The real zabbix-agent daemon on the
# honeypot is the only source, and zabbix_log.py records what it actually sends,
# packet by packet, into its own <tag>_zabbix.pcap and <tag>_knownzabbix.json
# (also folded into the benign and all-traffic unions). It reads the Zabbix and
# attacker addresses from config.yaml; if they are unset it says so loudly and
# the run proceeds without Zabbix ground truth.
#
# STOPPING A RUN: the untimed profiles (run1, run2, selftest -- anything whose
# run_seconds is null in config.yaml) run for as long as you want them to. Type
#
#     exit
#
# into this terminal and press Enter to stop. Ctrl-C works too. Either way the
# generator finalizes its manifest, tcpdump flushes, and a summary prints:
# whether every expected file was written, how many packets/records are in each,
# and how long the capture actually ran. The same summary prints if the script
# dies for any other reason (SIGTERM, a dropped ssh session, an error, a closed
# stdin), so a run never exits silently, and the exit status is non-zero when
# something is missing or truncated. A timed profile (baseline) still ends on its
# own at run_seconds, and prints the same summary then.
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
ZBX_PCAP="${RUN_DIR}/${TAG}_zabbix.pcap"

SECONDS=0        # bash counts the run for us; $SECONDS is the capture's length
MAIN_PID=$$
STOP_REASON=""
STOP_SECONDS=""
SUMMARY_DONE=0
GEN_PID=""
TCPDUMP_PID=""
ZBX_PID=""
READER_PID=""
FAILURES=0

# ------------------------------------------------------------------ reporting

# capture_report.py does the verification: what was written, how many packets and
# records are in each file, and whether anything is missing or truncated. Its
# exit status is 1 if it found a problem and 2 if it could not run at all, in
# which case fall back to a bare listing so the operator is never left guessing.
print_summary() {
    # STOP_SECONDS is when the stop was decided, so the reported length is the
    # capture itself and not the seconds spent shutting down and verifying
    local elapsed="${STOP_SECONDS:-$SECONDS}" rc=0
    "$PYTHON" "$HERE/capture_report.py" "$RUN_DIR" "$TAG" \
        --role honeypot --profile "$PROFILE" --iface "$IFACE" \
        --elapsed "$elapsed" --stopped-by "${STOP_REASON:-unknown}" || rc=$?
    if [ "$rc" -ge 2 ]; then
        echo "[!] could not run capture_report.py; raw listing of $RUN_DIR:"
        ls -l "$RUN_DIR" 2>&1 || echo "    (no run directory)"
        echo "[!] capture ran for ${elapsed}s, stopped by ${STOP_REASON:-unknown}"
    fi
    if [ "$rc" -ne 0 ]; then
        FAILURES=$((FAILURES + 1))
    fi
    if [ -n "${GEN_LOG_HINT:-}" ]; then
        echo "$GEN_LOG_HINT"
    fi
}

# ------------------------------------------------------------------ shutdown

# stop_child <pid> <label> <grace_seconds>
# SIGTERM, then block in wait (which is what reaps the child; polling kill -0
# would spin for the full grace period, because an exited-but-unreaped child is
# still a live pid). A watchdog SIGKILLs anything that ignores the SIGTERM, so
# the summary always gets printed. Returns 1 if it came to that.
stop_child() {
    local pid="$1" label="$2" grace="$3" rc=0 wd
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    # Watchdog: re-send SIGTERM every 5s, since a signal that lands while the
    # child is still starting up (before it installs its handler) is lost, then
    # SIGKILL at the deadline so the summary is always reached. It polls in 1s
    # slices so that cancelling it below costs at most a second.
    (
        waited=0
        while [ "$waited" -lt "$grace" ]; do
            sleep 1; waited=$((waited + 1))
            kill -0 "$pid" 2>/dev/null || exit 0
            if [ $((waited % 5)) -eq 0 ]; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        kill -KILL "$pid" 2>/dev/null || true
    ) &
    wd=$!
    wait "$pid" 2>/dev/null || rc=$?
    kill "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true      # reap it; an unreaped child can wedge the shell
    if [ "$rc" -eq 137 ]; then
        echo "[!] $label ignored SIGTERM for ${grace}s and was killed;" \
             "its output may be incomplete"
        return 1
    fi
    return 0
}

stop_children() {
    # the input watcher first, so no further input is acted on mid-shutdown
    if [ -n "$READER_PID" ]; then
        stop_child "$READER_PID" "input watcher" 5 || true
    fi

    # gen.py finalizes its manifest on SIGTERM, normally within a second
    if [ -n "$GEN_PID" ]; then
        echo "[*] stopping generator (pid $GEN_PID) and waiting for it to finalize..."
        stop_child "$GEN_PID" "generator" 30 || FAILURES=$((FAILURES + 1))
    fi

    sleep 2   # let tcpdump pick up the tail packets

    if [ -n "$TCPDUMP_PID" ]; then
        echo "[*] stopping tcpdump (pid $TCPDUMP_PID) and flushing the pcap..."
        stop_child "$TCPDUMP_PID" "tcpdump" 15 || FAILURES=$((FAILURES + 1))
    fi

    # Last, so the Zabbix stream is recorded for the whole capture window. It
    # signals its own tcpdump, drains the tail, and finalizes its meta file.
    if [ -n "$ZBX_PID" ]; then
        echo "[*] stopping the zabbix packet logger (pid $ZBX_PID)..."
        stop_child "$ZBX_PID" "zabbix logger" 20 || FAILURES=$((FAILURES + 1))
    fi
    sleep 0.5   # give the kernel a moment to land the final write
}

# Single exit path: stop both children, then always report what made it to disk.
cleanup() {
    local rc=$?
    STOP_SECONDS="$SECONDS"
    trap '' INT TERM HUP USR1 USR2   # nothing may abort the summary now
    trap - EXIT ERR
    if [ "$SUMMARY_DONE" -eq 1 ]; then
        exit "$rc"
    fi
    SUMMARY_DONE=1
    if [ -z "$STOP_REASON" ]; then
        if [ "$rc" -eq 0 ]; then
            STOP_REASON="clean exit"
        else
            STOP_REASON="script failure (exit $rc)"
        fi
    fi
    stop_children
    print_summary
    if [ "$FAILURES" -gt 0 ]; then
        exit 1
    fi
    exit "$rc"
}

trap 'STOP_REASON="script error at line $LINENO"' ERR
trap 'STOP_REASON="Ctrl-C / SIGINT"; exit 130' INT
trap 'STOP_REASON="SIGTERM"; exit 143' TERM
trap 'STOP_REASON="terminal closed (SIGHUP)"; exit 129' HUP   # dropped ssh session
trap 'STOP_REASON="operator typed exit"; exit 0' USR1   # sent by the input watcher
trap 'STOP_REASON="stdin closed (EOF)"; exit 0' USR2    # ditto
trap cleanup EXIT

# ------------------------------------------------------------------ run

mkdir -p "$RUN_DIR"
echo "$TAG" > "$HERE/.current_run"

echo "[*] run_id=$RUN_ID  tag=$TAG"
echo "[*] dir   =$RUN_DIR"
echo "[*] pcap  =$PCAP  (iface $IFACE)"
echo "[*] zabbix=$ZBX_PCAP  (real agent traffic, captured separately)"
echo "[*] seed  =$SEED  -> use this same seed AND run-id for gen.py on the promsvc VM"

# capture everything on the mirror; full snaplen for payload / JA3 analysis
tcpdump -i "$IFACE" -s 0 -w "$PCAP" -U < /dev/null &
TCPDUMP_PID=$!
sleep 2   # let tcpdump attach before traffic starts

# A run with no pcap is a wasted run, so refuse to start the generator if tcpdump
# died on the spot (bad interface, not root, tcpdump not installed). tcpdump
# creates the savefile as soon as it has the interface open, so the file is the
# thing to test: kill -0 would be no help, because a child that exited but has
# not been waited on is a zombie and still answers signals.
if [ ! -f "$PCAP" ]; then
    STOP_REASON="tcpdump did not start (check the interface name and run as root)"
    echo "[!] $STOP_REASON"
    exit 1
fi

# The real Zabbix agent's traffic, captured and labeled on its own. It owns the
# tcpdump it needs (one process, so the dedicated pcap and the ground-truth
# records are decoded from the same packets), and it self-disables with a loud
# warning if config.yaml carries no Zabbix addresses -- a missing Zabbix stream
# is worth a warning, but not worth throwing away an otherwise good capture.
"$PYTHON" -u "$HERE/zabbix_log.py" --config "$HERE/config.yaml" --iface "$IFACE" \
    --run-dir "$RUN_DIR" --tag "$TAG" --role honeypot < /dev/null &
ZBX_PID=$!

# -u so the generator's progress lines survive a redirect to a log file; stdin is
# /dev/null because the exit watcher below owns the terminal
"$PYTHON" -u "$HERE/gen.py" --profile "$PROFILE" --role honeypot \
    --seed "$SEED" --run-id "$RUN_ID" --base "$HERE" --config "$HERE/config.yaml" \
    < /dev/null &
GEN_PID=$!

GEN_LOG_HINT="[i] During run1/run2, log attacker actions and browsing with:
    $PYTHON $HERE/log_user.py \"<note>\" --source attacker|browsing"
echo
echo "$GEN_LOG_HINT"
echo

# The operator's "exit" is delivered as a signal by a small stdin watcher, which
# leaves this shell free to block in wait. Polling the generator with kill -0
# instead would never notice it finishing: an exited child that has not been
# waited on is a zombie, and signalling a zombie still succeeds.
if [ -t 0 ]; then
    echo "[*] capture running. Type 'exit' and press Enter to stop it (Ctrl-C also works)."
    # The watcher reads the terminal through fd 3: with job control off, bash
    # hands background jobs /dev/null for stdin, which would look like an
    # instant EOF. Normalizing the line with builtins keeps the watcher
    # fork-free.
    exec 3<&0
    (
        while IFS= read -r -u 3 line; do
            line="${line//[[:space:]]/}"
            case "${line,,}" in
                exit|quit|stop) kill -USR1 "$MAIN_PID" 2>/dev/null || true; exit 0 ;;
                "") : ;;
                *) echo "[?] type 'exit' to stop the capture." ;;
            esac
        done
        kill -USR2 "$MAIN_PID" 2>/dev/null || true   # stdin closed on us
    ) &
    READER_PID=$!
else
    echo "[*] stdin is not a terminal, so there is nowhere to type 'exit'. Waiting for"
    echo "    the generator to finish, or for SIGINT/SIGTERM (systemctl stop, kill)."
    echo "    For an interactive run that survives a disconnect, use tmux."
fi

# Returns when the generator ends by itself (a timed profile), or is cut short by
# one of the traps above; either way cleanup stops everything and reports.
wait "$GEN_PID" 2>/dev/null || true
STOP_REASON="generator finished on its own (profile timer or early exit)"
