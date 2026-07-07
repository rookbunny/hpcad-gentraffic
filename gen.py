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

    python3 gen.py --profile baseline --role honeypot --seed 1337
    python3 gen.py --profile baseline --role promsvc  --seed 1337 --run-id <id>

Not generated here: the C2 beacon (hand-run) and manual web browsing. Those are
the anomalous / human streams, recorded via log_user.py.
"""

import argparse, hashlib, json, os, random, smtplib, ssl, subprocess, sys, threading, time
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
        logio.write_benign(self.run_dir, self.run_id, rec)
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

def proc_zabbix(ctx, p):
    """Off by default; the real Zabbix agent daemon normally provides this stream."""
    rng = random.Random(derive_seed(ctx.seed, "zabbix"))
    ep = ctx.ep
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        try:
            subprocess.run(
                ["zabbix_sender", "-z", ep["zabbix_server"], "-s", ep["zabbix_host"],
                 "-k", "desktop.heartbeat", "-o", str(int(time.time()))],
                capture_output=True, timeout=8, check=False)
            ctx.log("zabbix", "sender", ok=True, server=ep["zabbix_server"])
        except Exception as e:
            ctx.log("zabbix", "sender", ok=False, err=str(e))

def proc_noop(ctx, p):
    rng = random.Random(derive_seed(ctx.seed, "noop"))
    while not ctx.stop.is_set():
        if not interruptible_sleep(ctx.stop, jittered(rng, p["period"], p["jitter"], p["floor"])):
            break
        ctx.log("noop", "tick", ok=True)

PROCS = {
    "healthcheck": proc_healthcheck, "prom_scrape": proc_prom_scrape,
    "email": proc_email, "noaa": proc_noaa, "chat_ws": proc_chat_ws,
    "zabbix": proc_zabbix, "noop": proc_noop,
}

# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--role", default="honeypot",
                    help="which host this is: honeypot | promsvc | any")
    ap.add_argument("--seed", type=int, default=None,
                    help="master seed; omit for a fresh random one (RESEED PER RUN)")
    ap.add_argument("--run-seconds", type=int, default=None,
                    help="override the profile's run length")
    ap.add_argument("--base", default=".",
                    help="repo root; run dirs are created under <base>/logs/<run_id>_logs/")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    import yaml
    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    if args.profile not in cfg["profiles"]:
        sys.exit(f"unknown profile {args.profile!r}; have {list(cfg['profiles'])}")
    prof = cfg["profiles"][args.profile]
    run_seconds = args.run_seconds or prof["run_seconds"]
    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 2**31)
    run_id = args.run_id or f"{args.profile}-{datetime.now():%Y%m%d-%H%M%S}-{seed}"

    run_dir = logio.run_dir_for(args.base, run_id)
    os.makedirs(run_dir, exist_ok=True)

    selected = []
    for name in prof["processes"]:
        pcfg = cfg["processes"][name]
        if name == "zabbix" and not pcfg.get("enabled_default", False):
            continue
        host = pcfg.get("host", "honeypot")
        if host in (args.role, "any") or args.role == "any":
            selected.append(name)

    stop = threading.Event()
    ctx = Ctx(run_id, seed, args.role, cfg["endpoints"], run_dir, stop)

    manifest = {
        "run_id": run_id, "profile": args.profile, "role": args.role,
        "seed": seed, "bucket_span_s": 15, "run_seconds": run_seconds,
        "expected_buckets": run_seconds // 15,
        "started": now_iso(), "processes": {n: cfg["processes"][n] for n in selected},
        "note": ("C2 beacon + manual browsing are not generated here; they are "
                 "recorded via log_user.py. If the real Zabbix agent daemon's "
                 "active checks are running, that Zabbix stream is present but "
                 "not logged here."),
    }
    man_path = os.path.join(run_dir, f"{run_id}.{args.role}.manifest.json")
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] run_id={run_id}")
    print(f"[+] role={args.role} seed={seed} run={run_seconds}s "
          f"({run_seconds//15} buckets @15s)")
    print(f"[+] processes: {', '.join(selected) or '(none for this role)'}")
    print(f"[+] logs -> {os.path.abspath(run_dir)}")

    threads = []
    for name in selected:
        t = threading.Thread(target=PROCS[name], args=(ctx, cfg["processes"][name]),
                             name=name, daemon=True)
        t.start(); threads.append(t)

    try:
        interruptible_sleep(stop, run_seconds)
    except KeyboardInterrupt:
        print("\n[!] interrupted; stopping early")
    stop.set()
    for t in threads:
        t.join(timeout=10)

    manifest["ended"] = now_iso()
    manifest["event_counts"] = ctx.counts()
    with open(man_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] done. event counts: {ctx.counts()}")
    print(f"[+] manifest -> {man_path}")

if __name__ == "__main__":
    main()
