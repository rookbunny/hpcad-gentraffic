#!/usr/bin/env python3
"""
Record a manual/human traffic event into the ground-truth logs.

Covers everything a person does at the keyboard during a run: attacker actions
(brute force, privilege escalation, C2 interaction) and ordinary web browsing.
Each event is appended to <run_id>_knownuser.json and mirrored into
<run_id>_alltraffic.json inside the run's logs/<run_id>_logs/ directory.

The run id defaults to the value written by run_capture.sh into <base>/.current_run,
so it can be omitted during an active capture.

    python3 log_user.py "hydra ssh brute force start" --source attacker --phase T1110
    python3 log_user.py "youtube session start"       --source browsing
    python3 log_user.py "sliver interactive shell open" --source attacker
"""
import argparse, os, time
from datetime import datetime, timezone

import logio

DEFAULT_BASE = os.path.dirname(os.path.abspath(__file__))

def read_current_run(base):
    p = os.path.join(base, ".current_run")
    if os.path.exists(p):
        return open(p).read().strip()
    return "unknown"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("note", help="what happened, e.g. 'hydra ssh brute force start'")
    ap.add_argument("--source", default="attacker",
                    choices=["attacker", "browsing", "other"])
    ap.add_argument("--phase", default=None,
                    help="optional tag, e.g. an ATT&CK id like T1110")
    ap.add_argument("--run-id", default=None,
                    help="defaults to <base>/.current_run")
    ap.add_argument("--base", default=DEFAULT_BASE,
                    help="base directory holding .current_run and the run dirs")
    args = ap.parse_args()

    run_id = args.run_id or read_current_run(args.base)
    run_dir = logio.run_dir_for(args.base, run_id)
    rec = {"run_id": run_id, "source": args.source, "phase": args.phase,
           "ts": datetime.now(timezone.utc).isoformat(),
           "ts_epoch": round(time.time(), 3), "note": args.note}
    logio.write_user(run_dir, run_id, rec)
    print(f"[+] logged ({args.source}) run={run_id}: {args.note}")

if __name__ == "__main__":
    main()
