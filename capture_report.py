#!/usr/bin/env python3
"""Verify and summarize what a capture actually wrote to disk.

run_capture.sh calls this on every exit path -- the operator typing exit, a
signal, a script failure -- so a run never ends without saying whether its files
landed, how much is in each one, and how long the capture ran. It is also useful
on its own, after the fact:

    ./.venv/bin/python3 capture_report.py logs/R0001-S12345_logs R0001-S12345

Nothing here reads the packet payloads: the pcap is counted by walking record
headers, so the cost is independent of capture size. A short final record is
reported as a truncated tail, which is the signature of a capture that was killed
mid-write rather than shut down.

Exit status: 0 = every expected file is present and intact; 1 = something is
missing, empty, truncated, or inconsistent; 2 = the report itself could not run.
"""

import argparse, json, os, struct, sys

# classic pcap global-header magics -> (struct byte order, note)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",   # microsecond, little endian
    b"\xa1\xb2\xc3\xd4": ">",   # microsecond, big endian
    b"\x4d\x3c\xb2\xa1": "<",   # nanosecond, little endian
    b"\xa1\xb2\x3c\x4d": ">",   # nanosecond, big endian
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_PACKET = 16 * 1024 * 1024   # sanity bound; tcpdump -s 0 snaps at 256KB


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def count_pcap(path, size):
    """Packet count for a classic pcap, walking 16-byte record headers.

    Returns (packets, problem_or_None).
    """
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return 0, "file header is incomplete"
        order = PCAP_MAGIC[head[:4]]
        packets, pos = 0, 24
        while pos < size:
            rec = f.read(16)
            if len(rec) < 16:
                return packets, f"truncated record header at byte {pos}"
            _, _, incl, _ = struct.unpack(order + "IIII", rec)
            if incl > MAX_PACKET:
                return packets, f"implausible record length {incl} at byte {pos}"
            pos += 16 + incl
            if pos > size:
                return packets, f"truncated final packet at byte {pos - incl}"
            f.seek(incl, os.SEEK_CUR)
            packets += 1
    return packets, None


def count_pcapng(path, size):
    """Packet count for a pcapng file: Enhanced (6) and Simple (3) Packet Blocks."""
    with open(path, "rb") as f:
        f.seek(8)
        bom = f.read(4)
        if len(bom) < 4:
            return 0, "section header is incomplete"
        order = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        f.seek(0)
        packets, pos = 0, 0
        while pos < size:
            head = f.read(8)
            if len(head) < 8:
                return packets, f"truncated block header at byte {pos}"
            btype, blen = struct.unpack(order + "II", head)
            if blen < 12 or blen > MAX_PACKET:
                return packets, f"implausible block length {blen} at byte {pos}"
            if btype in (3, 6):
                packets += 1
            pos += blen
            if pos > size:
                return packets, f"truncated final block at byte {pos - blen}"
            f.seek(pos)
    return packets, None


def check_pcap(path, size):
    """(status, detail) for the capture file."""
    if size <= 24:
        return "EMPTY", f"0 packets, {human(size)}"
    with open(path, "rb") as f:
        magic = f.read(4)
    try:
        if magic in PCAP_MAGIC:
            packets, problem = count_pcap(path, size)
        elif magic == PCAPNG_MAGIC:
            packets, problem = count_pcapng(path, size)
        else:
            return "UNKNOWN", f"unrecognized format (magic {magic.hex()}), {human(size)}"
    except OSError as e:
        return "UNREAD", f"{e}, {human(size)}"
    if problem:
        return "PARTIAL", f"{packets} packets then {problem}, {human(size)}"
    if packets == 0:
        return "EMPTY", f"0 packets, {human(size)}"
    return "OK", f"{packets} packets, {human(size)}"


def check_ndjson(path, size):
    """(status, detail, record_count) for one newline-delimited JSON log."""
    good = bad = 0
    try:
        with open(path, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                    good += 1
                except ValueError:
                    bad += 1
    except OSError as e:
        return "UNREAD", f"{e}, {human(size)}", 0
    if good == 0:
        return "EMPTY", f"0 records, {human(size)}", 0
    if bad:
        return "PARTIAL", f"{good} records + {bad} unparseable line(s), {human(size)}", good
    return "OK", f"{good} records, {human(size)}", good


def check_manifest(path, size):
    """(status, detail, manifest_or_None). A manifest without "ended" means the
    generator died before it could finalize."""
    try:
        with open(path) as f:
            man = json.load(f)
    except ValueError as e:
        return "CORRUPT", f"not valid JSON ({e}), {human(size)}", None
    except OSError as e:
        return "UNREAD", f"{e}, {human(size)}", None
    if not man.get("ended"):
        return "PARTIAL", f"never finalized (no \"ended\" field), {human(size)}", man
    return "OK", f"finalized, {human(size)}", man


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("tag")
    ap.add_argument("--role", default="honeypot")
    ap.add_argument("--profile", default="?")
    ap.add_argument("--iface", default="?")
    ap.add_argument("--elapsed", type=float, default=None,
                    help="seconds the capture ran, as measured by the caller")
    ap.add_argument("--stopped-by", default="unknown")
    args = ap.parse_args()

    tag, run_dir = args.tag, args.run_dir
    bar = "=" * 67
    rule = "-" * 67

    print()
    print(bar)
    print(f"[=] capture summary   tag={tag}  profile={args.profile}  iface={args.iface}")
    print(f"[=] stopped by:       {args.stopped_by}")
    if args.elapsed is not None:
        s = int(args.elapsed)
        print(f"[=] capture ran for:  {s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d} "
              f"({s}s)  ->  {s // 15} buckets @15s")
    print(f"[=] directory:        {os.path.abspath(run_dir)}")
    print(rule)

    if not os.path.isdir(run_dir):
        print(f"    run directory does not exist: {run_dir}")
        print(rule)
        print("[!] nothing was written. This run captured nothing.")
        print(bar)
        return 1

    # name, required, kind
    expected = [
        (f"{tag}.pcap",                      True,  "pcap"),
        (f"{tag}_knownbenign.json",          True,  "ndjson"),
        (f"{tag}_knownuser.json",            False, "ndjson"),
        (f"{tag}_alltraffic.json",           True,  "ndjson"),
        (f"{tag}.{args.role}.manifest.json", True,  "manifest"),
    ]

    problems, counts, manifest = [], {}, None
    for name, required, kind in expected:
        path = os.path.join(run_dir, name)
        if not os.path.exists(path):
            if required:
                print(f"    {name:<38} {'MISSING':<8} expected but never created")
                problems.append(f"{name} is missing")
            else:
                print(f"    {name:<38} {'-':<8} not created (nothing logged)")
            counts[kind] = 0
            continue
        size = os.path.getsize(path)
        if kind == "pcap":
            status, detail = check_pcap(path, size)
        elif kind == "ndjson":
            status, detail, counts[name] = check_ndjson(path, size)
        else:
            status, detail, manifest = check_manifest(path, size)
        print(f"    {name:<38} {status:<8} {detail}")
        if status != "OK":
            problems.append(f"{name}: {status.lower()}")

    # alltraffic is the union of the other two logs, so the counts must add up
    benign = counts.get(f"{tag}_knownbenign.json", 0)
    user = counts.get(f"{tag}_knownuser.json", 0)
    every = counts.get(f"{tag}_alltraffic.json", 0)
    if benign + user != every:
        print(rule)
        print(f"[!] record mismatch: knownbenign({benign}) + knownuser({user})"
              f" != alltraffic({every})")
        problems.append("log record counts do not add up")

    if manifest:
        gen_elapsed = manifest.get("elapsed_seconds")
        events = manifest.get("event_counts") or {}
        print(rule)
        print(f"[=] generator:        stopped by {manifest.get('stopped_by', '?')}"
              + (f", ran {gen_elapsed}s" if gen_elapsed is not None else ""))
        if events:
            print("[=] events by proc:   "
                  + ", ".join(f"{k}={v}" for k, v in sorted(events.items())))

    print(rule)
    if problems:
        print(f"[!] {len(problems)} problem(s): " + "; ".join(problems))
        print(f"[!] inspect {os.path.abspath(run_dir)} before trusting this run.")
        print(bar)
        return 1
    print("[+] all expected files were written successfully.")
    print(bar)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                       # never leave the caller blind
        print(f"[!] capture_report failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
