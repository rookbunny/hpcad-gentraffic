#!/usr/bin/env python3
"""
Benign traffic generator for a honeypot golden dataset.

Drives the benign substrate for the engagement. Each capture (baseline / run1 /
run2) runs the SAME processes with the SAME interval distributions but a
DIFFERENT random draw, so the benign scaffold is not a fixed fingerprint across
the three captures. Every action is timestamp-logged so the benign ground truth
can be laid under the attack timeline.

The same file is deployed on every host that runs part of the generator; --role
selects which processes fire locally (honeypot vs. promsvc). One --seed
reproduces the whole run across all hosts, because each process is seeded from
(master_seed, process_name).

    python3 gen.py --profile baseline --role honeypot --seed 13370
    python3 gen.py --profile baseline --role promsvc  --seed 13370 --run-id 0001

A profile whose run_seconds is null has no timer: it runs until SIGINT, SIGTERM or
SIGHUP (Ctrl-C, systemctl stop, a dropped ssh session, or the operator typing exit
into run_capture.sh) and then finalizes the manifest with the actual elapsed time.
--run-seconds overrides either way; --run-seconds 0 forces the untimed behavior.

Not generated here: the C2 beacon (hand-run) and manual web browsing, which are
the anomalous / human streams, recorded via log_user.py; and Zabbix, which is
never simulated -- the real zabbix-agent daemon on the honeypot is the only
source of that stream and zabbix_log.py captures it at the packet level.
"""

import argparse, hashlib, json, os, random, signal, smtplib, ssl, sys, threading, time
import urllib.request
from datetime import datetime, timezone

import logio

# ------------------------------------------------------------------ utilities

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def derive_seed(master: int, name: str) -> int:
    """Per-process seed: pure function of (master_seed, process_name)."""
    h = hashlib.sha256(f"{master}:{name}".encode()).digest()
    return int.from_bytes(h[:8], "big")

class Ctx:
    """Shared context handed to every process thread."""
    def __init__(self, run_id, seed, role, endpoints, run_dir, stop_event):
        self.run_id = run_id
        self.seed = seed
        self.tag = logio.tag_for(run_id, seed)
        self.role = role
        self.ep = endpoints
        self.run_dir = run_dir
        self.stop = stop_event
        self._lock = threading.Lock()
        self._counts = {}

    def log(self, proc, event, ok=True, **detail):
        rec = {"run_id": self.run_id, "seed": self.seed, "role": self.role,
               "proc": proc, "ts": now_iso(), "ts_epoch": round(time.time(), 3),
               "event": event, "ok": ok, "detail": detail}
        logio.write_benign(self.run_dir, self.tag, rec)
        with self._lock:
            self._counts[proc] = self._counts.get(proc, 0) + 1

    def counts(self):
        with self._lock:
            return dict(self._counts)

def interruptible_sleep(stop_event, seconds):
    """Sleep in small slices so shutdown is prompt when the run window ends."""
    end = time.time() + seconds
    while time.time() < end:
        if stop_event.wait(min(0.25, end - time.time())):
            return False   # stopped
    return True

def jittered(rng, period, jitter, floor):
    return max(floor, rng.uniform(period - jitter, period + jitter))

# ------------------------------------------------------------------ processes
# Each proc owns its loop and runs until ctx.stop is set. Endpoint failures are
# logged and swallowed: a failed attempt still puts packets on the wire (which
# is what the mirror captures), and one dead service must not kill the thread.

def proc_healthcheck(ctx, p):
    rng = random.Random(derive_seed(ctx.seed, "healthcheck"))
    url = ctx.ep["healthcheck_url"]
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                r.read(2048)
            ctx.log("healthcheck", "get", ok=True, url=url)
        except Exception as e:
            ctx.log("healthcheck", "get", ok=False, url=url, err=str(e))

def proc_prom_scrape(ctx, p):
    rng = random.Random(derive_seed(ctx.seed, "prom_scrape"))
    url = ctx.ep["node_exporter_url"]
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                n = len(r.read())
            ctx.log("prom_scrape", "scrape", ok=True, url=url, bytes=n)
        except Exception as e:
            ctx.log("prom_scrape", "scrape", ok=False, url=url, err=str(e))

def proc_email(ctx, p):
    import imaplib
    rng = random.Random(derive_seed(ctx.seed, "email"))
    ep = ctx.ep
    passwd = os.environ.get("IMAP_PASS") or ep["imap_pass"]
    n = 0
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        n += 1
        try:
            M = imaplib.IMAP4(ep["imap_host"], ep.get("imap_port", 143))
            try:
                M.starttls(ssl.create_default_context())
            except Exception:
                pass  # server may not offer STARTTLS on this port; poll anyway
            M.login(ep["imap_user"], passwd)
            M.select("INBOX")
            M.search(None, "UNSEEN")
            M.logout()
            ctx.log("email", "imap_poll", ok=True, host=ep["imap_host"])
        except Exception as e:
            ctx.log("email", "imap_poll", ok=False, host=ep["imap_host"], err=str(e))
        if p.get("smtp_every") and n % int(p["smtp_every"]) == 0:
            try:
                s = smtplib.SMTP(ep["smtp_host"], ep.get("smtp_port", 587), timeout=8)
                s.ehlo()
                try:
                    s.starttls(context=ssl.create_default_context()); s.ehlo()
                except Exception:
                    pass
                frm = f"{ep['imap_user']}@localdomain"
                s.sendmail(frm, [frm],
                           f"Subject: run notes {int(time.time())}\r\n\r\nautomated.")
                s.quit()
                ctx.log("email", "smtp_send", ok=True, host=ep["smtp_host"])
            except Exception as e:
                ctx.log("email", "smtp_send", ok=False, host=ep["smtp_host"], err=str(e))

def proc_noaa(ctx, p):
    rng = random.Random(derive_seed(ctx.seed, "noaa"))
    urls = list(ctx.ep["noaa_urls"])
    dur = p.get("duration", 180)
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        start = time.time(); total = 0; files = 0
        rng.shuffle(urls)
        i = 0
        while time.time() - start < dur and not ctx.stop.is_set():
            u = urls[i % len(urls)]; i += 1
            try:
                with urllib.request.urlopen(u, timeout=20) as r:
                    b = r.read()
                total += len(b); files += 1
            except Exception as e:
                ctx.log("noaa", "fetch", ok=False, url=u, err=str(e))
            interruptible_sleep(ctx.stop, 1.0)
        ctx.log("noaa", "pull", ok=True, files=files, bytes=total,
                secs=round(time.time() - start, 1))

def proc_chat_ws(ctx, p):
    """Persistent WebSocket with periodic keepalive pings. Reconnects on drop."""
    from websockets.sync.client import connect
    rng = random.Random(derive_seed(ctx.seed, "chat_ws"))
    url = ctx.ep["chat_ws_url"]
    while not ctx.stop.is_set():
        try:
            with connect(url, open_timeout=5) as ws:
                ctx.log("chat_ws", "connect", ok=True, url=url)
                while not ctx.stop.is_set():
                    if not interruptible_sleep(ctx.stop,
                            jittered(rng, p["period"], p["jitter"], p["floor"])):
                        break
                    try:
                        ws.send(json.dumps({"t": "ping", "ts": time.time()}))
                        try:
                            ws.recv(timeout=3)
                        except Exception:
                            pass
                        ctx.log("chat_ws", "ping", ok=True)
                    except Exception as e:
                        ctx.log("chat_ws", "ping", ok=False, err=str(e))
                        break  # drop out to reconnect
        except Exception as e:
            ctx.log("chat_ws", "connect", ok=False, url=url, err=str(e))
            interruptible_sleep(ctx.stop, 5)  # backoff before retry

def proc_noop(ctx, p):
    rng = random.Random(derive_seed(ctx.seed, "noop"))
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        ctx.log("noop", "tick", ok=True)

PROCS = {
    "healthcheck": proc_healthcheck, "prom_scrape": proc_prom_scrape,
    "email": proc_email, "noaa": proc_noaa, "chat_ws": proc_chat_ws,
    "noop": proc_noop,
}
# No Zabbix process: Zabbix traffic is never simulated here. The real
# zabbix-agent daemon on the honeypot is the only source, and zabbix_log.py
# captures and labels it at the packet level (see README, "Zabbix").

# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--role", default="honeypot",
                    help="which host this is: honeypot | promsvc | any")
    ap.add_argument("--seed", type=int, default=None,
                    help="master seed; omit for a fresh random 5-digit one (RESEED PER RUN)")
    ap.add_argument("--run-seconds", type=int, default=None,
                    help="override the profile's run length; 0 means run until "
                         "stopped (SIGINT/SIGTERM)")
    ap.add_argument("--base", default=".",
                    help="repo root; run dirs are created under <base>/logs/<tag>_logs/")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    import yaml
    try:
        with open(args.config) as f:
            cfg = yaml.safe_load(f)
    except OSError as e:
        sys.exit(f"cannot read {args.config}: {e}\n"
                 f"    run ./SETUP.sh to generate it from config.example.yaml")

    # Before the first SETUP.sh run, config.yaml is the comment-only placeholder
    # and yaml hands back None for it. Say which file and what to do about it: the
    # alternative is a TypeError on the profile lookup below, which names neither.
    if not cfg:
        sys.exit(f"{args.config} has no configuration in it yet\n"
                 f"    run ./SETUP.sh to generate it from config.example.yaml")
    for section in ("profiles", "processes", "endpoints"):
        if not cfg.get(section):
            sys.exit(f"{args.config} has no {section!r} section\n"
                     f"    re-run ./SETUP.sh to regenerate it from "
                     f"config.example.yaml")

    if args.profile not in cfg["profiles"]:
        sys.exit(f"unknown profile {args.profile!r}; have {list(cfg['profiles'])}")
    prof = cfg["profiles"][args.profile]
    # A null/absent/<=0 run_seconds means "no timer": run until a signal arrives
    # (run_capture.sh sends one when the operator types exit; systemctl stop and
    # Ctrl-C do the same). Timed profiles still exit on their own at the window end.
    run_seconds = args.run_seconds if args.run_seconds is not None else prof.get("run_seconds")
    if run_seconds is not None and run_seconds <= 0:
        run_seconds = None
    seed = args.seed if args.seed is not None else random.SystemRandom().randint(10000, 99999)
    run_id = args.run_id or logio.next_run_id(args.base)
    tag = logio.tag_for(run_id, seed)

    run_dir = logio.run_dir_for(args.base, tag)
    os.makedirs(run_dir, exist_ok=True)

    selected = []
    for name in prof["processes"]:
        pcfg = cfg["processes"][name]
        host = pcfg.get("host", "honeypot")
        if host in (args.role, "any") or args.role == "any":
            selected.append(name)

    stop = threading.Event()
    ctx = Ctx(run_id, seed, args.role, cfg["endpoints"], run_dir, stop)

    manifest = {
        "run_id": run_id, "profile": args.profile, "role": args.role,
        "seed": seed, "bucket_span_s": 15, "run_seconds": run_seconds,
        "expected_buckets": (run_seconds // 15) if run_seconds else None,
        "timed": run_seconds is not None,
        "started": now_iso(), "processes": {n: cfg["processes"][n] for n in selected},
        "note": ("C2 beacon + manual browsing are not generated here; they are "
                 "recorded via log_user.py. Zabbix is not generated either: the "
                 "real zabbix-agent daemon is the only source, and zabbix_log.py "
                 "captures it per packet into <tag>_zabbix.pcap and "
                 "<tag>_knownzabbix.json, folded into the benign and all-traffic "
                 "unions."),
    }
    man_path = os.path.join(run_dir, f"{tag}.{args.role}.manifest.json")
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)

    window = (f"{run_seconds}s ({run_seconds//15} buckets @15s)" if run_seconds
              else "until stopped (no timer)")
    print(f"[+] run_id={run_id} tag={tag}")
    print(f"[+] role={args.role} seed={seed} run={window}")
    print(f"[+] processes: {', '.join(selected) or '(none for this role)'}")
    print(f"[+] logs -> {os.path.abspath(run_dir)}")

    # Signals only set the stop event; they never raise, so a second Ctrl-C while
    # the run is winding down cannot interrupt the manifest write below.
    stopped_by = {"reason": "run_seconds"}
    def on_signal(signum, _frame):
        if not stop.is_set():
            stopped_by["reason"] = signal.Signals(signum).name
            print(f"\n[!] {stopped_by['reason']} received; stopping and finalizing")
        stop.set()
    stop_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):        # a dropped ssh session must not lose the run
        stop_signals.append(signal.SIGHUP)
    for sig in stop_signals:
        signal.signal(sig, on_signal)

    started = time.time()
    threads = []
    for name in selected:
        t = threading.Thread(target=PROCS[name], args=(ctx, cfg["processes"][name]),
                             name=name, daemon=True)
        t.start(); threads.append(t)

    try:
        if run_seconds is None:
            while not stop.wait(1.0):   # slices so the handler runs promptly
                pass
        else:
            interruptible_sleep(stop, run_seconds)
    except KeyboardInterrupt:
        stopped_by["reason"] = "SIGINT"
        print("\n[!] interrupted; stopping early")
    stop.set()
    for t in threads:
        t.join(timeout=10)

    elapsed = round(time.time() - started, 1)
    manifest["ended"] = now_iso()
    manifest["stopped_by"] = stopped_by["reason"]
    manifest["elapsed_seconds"] = elapsed
    manifest["actual_buckets"] = int(elapsed // 15)
    manifest["event_counts"] = ctx.counts()
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] done after {elapsed}s ({int(elapsed // 15)} buckets @15s), "
          f"stopped by {stopped_by['reason']}")
    print(f"[+] event counts: {ctx.counts()}")
    print(f"[+] manifest -> {man_path}")

if __name__ == "__main__":
    main()
