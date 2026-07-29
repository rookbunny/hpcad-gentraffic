#!/usr/bin/env python3
"""
Packet-level capture and labeling of the REAL Zabbix agent's traffic.

Nothing in this repository generates Zabbix traffic. The stream comes from the
zabbix-agent daemon on the Rocky 9 honeypot and the Zabbix server that polls it,
so what lands in the dataset is genuine telemetry rather than a simulation. This
process records it, next to the run's own files but never mixed into them:

  <tag>_zabbix.pcap        every Zabbix packet, in its own capture file
  <tag>_knownzabbix.json   one ground-truth record per Zabbix packet
  <tag>_knownbenign.json   the same records, folded into the benign union
  <tag>_alltraffic.json    the same records, folded into the all-traffic union
  <tag>.zabbix.meta.json   the BPF filter, the addresses, counts, stop reason

A single tcpdump feeds all of that. Its pcap stream arrives on a pipe; every
packet is written through to <tag>_zabbix.pcap byte for byte AND decoded into one
record, so the dedicated pcap and the log can never disagree about what was seen.
The run's main tcpdump keeps its own copy of these packets, because that capture
is the whole wire: the Zabbix stream is present there exactly once, the same way
a Zabbix record appears exactly once in <tag>_alltraffic.json.

WHAT COUNTS AS ZABBIX TRAFFIC. The agent runs ON the honeypot, so "every packet
involving the agent address" would match the entire capture. The filter is
therefore the Zabbix addresses scoped to the Zabbix ports (10050 agent /
10051 server by default, configurable), which is what makes "involving Zabbix"
mean the telemetry rather than everything the honeypot does. Traffic from the
attacker address is excluded: run2's covert operator impersonates the Zabbix
service account, and those packets are the adversary's, not benign telemetry.
They stay in the main pcap and are recorded by hand with log_user.py.

run_capture.sh starts this alongside the run's main tcpdump and stops it with
SIGTERM. It also runs by hand against an existing run directory:

    sudo ./.venv/bin/python3 zabbix_log.py --iface ens19 \
        --run-dir logs/R0001-S12345_logs --tag R0001-S12345
"""

import argparse, ipaddress, json, os, signal, struct, subprocess, sys, time
from datetime import datetime, timezone

import logio

# Agent passive checks arrive on 10050; the agent's active checks and
# zabbix_sender reach the server on 10051. Override in config.yaml when a proxy
# or a non-default port is in play.
DEFAULT_PORTS = [10050, 10051]

# classic pcap global-header magics -> (struct byte order, timestamp divisor)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

MAX_CAPLEN = 16 * 1024 * 1024   # sanity bound; tcpdump -s 0 snaps at 256KB
LINKTYPE_EN10MB, LINKTYPE_RAW = 1, 101
LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 113, 276
VLAN_TYPES = (0x8100, 0x88a8)          # 802.1Q, 802.1ad
IPV4, IPV6 = 0x0800, 0x86dd
TCP_FLAG_BITS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                 (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def iso_from_epoch(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


# ------------------------------------------------------------------- filter

def _bpf_host(value, label):
    """Validate an operator-supplied address before it becomes a BPF term.

    tcpdump would reject a malformed expression anyway, but it would do so
    several steps later and with a worse message than naming the config key.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise SystemExit(f"[!] {label}={value!r} in the config is not an IP "
                             f"address or network; fix it (re-run SETUP.sh)")
    return f"host {value}"


def build_filter(cfg):
    """(bpf_filter, addresses, ports, disabled_reason).

    disabled_reason is None when there is something to capture; otherwise the
    filter is None and the reason says why, so the run reports the gap instead
    of silently producing no Zabbix ground truth.
    """
    addr = cfg.get("addresses") or {}
    zc = cfg.get("zabbix_capture") or {}
    server = str(addr.get("zabbix_server_ip") or "").strip()
    agent = str(addr.get("zabbix_agent_ip") or "").strip()
    attacker = str(addr.get("attacker_ip") or "").strip()
    ports = [int(p) for p in (zc.get("ports") or DEFAULT_PORTS)]
    addresses = {"zabbix_server_ip": server or None,
                 "zabbix_agent_ip": agent or None,
                 "attacker_ip": attacker or None}

    terms = []
    if server:
        terms.append(_bpf_host(server, "addresses.zabbix_server_ip"))
    if agent:
        terms.append(_bpf_host(agent, "addresses.zabbix_agent_ip"))
    if not terms:
        return None, addresses, ports, ("neither addresses.zabbix_server_ip nor "
                                        "addresses.zabbix_agent_ip is set in the config")
    if not ports:
        return None, addresses, ports, "zabbix_capture.ports is empty in the config"

    hosts = " or ".join(terms)
    port_expr = " or ".join(f"port {p}" for p in ports)
    bpf = f"tcp and ({hosts}) and ({port_expr})"
    if attacker and zc.get("exclude_attacker", True):
        bpf += " and not " + _bpf_host(attacker, "addresses.attacker_ip")
    return bpf, addresses, ports, None


# ------------------------------------------------------------------- decoding
# Enough of the headers to attribute a packet: who, to whom, on what port, how
# big, and which way it went. Every step is length-checked, so a short or odd
# frame yields a thinner record rather than an exception that would drop it.

def _ipv6(raw):
    return str(ipaddress.IPv6Address(bytes(raw)))


def _l3_start(linktype, data):
    """(offset of the L3 header, ethertype or None to infer) for one frame."""
    if linktype == LINKTYPE_EN10MB:
        if len(data) < 14:
            return None, None
        etype = int.from_bytes(data[12:14], "big")
        off = 14
        while etype in VLAN_TYPES:
            if len(data) < off + 4:
                return None, None
            etype = int.from_bytes(data[off + 2:off + 4], "big")
            off += 4
        return off, etype
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, None
        return 16, int.from_bytes(data[14:16], "big")
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None, None
        return 20, int.from_bytes(data[0:2], "big")
    if linktype == LINKTYPE_RAW:
        return 0, None                  # the IP version nibble decides
    return None, None


def decode(linktype, data):
    """Fields for one captured frame; {} when it is not IP-over-something known."""
    off, etype = _l3_start(linktype, data)
    if off is None:
        return {}
    if etype is None:
        if len(data) <= off:
            return {}
        version = data[off] >> 4
        etype = IPV4 if version == 4 else IPV6 if version == 6 else None

    if etype == IPV4:
        if len(data) < off + 20:
            return {}
        ihl = (data[off] & 0x0f) * 4
        ip_len = int.from_bytes(data[off + 2:off + 4], "big")
        proto = data[off + 9]
        src = ".".join(str(b) for b in data[off + 12:off + 16])
        dst = ".".join(str(b) for b in data[off + 16:off + 20])
        l4, l4_len = off + ihl, max(0, ip_len - ihl)
    elif etype == IPV6:
        if len(data) < off + 40:
            return {}
        proto = data[off + 6]
        src, dst = _ipv6(data[off + 8:off + 24]), _ipv6(data[off + 24:off + 40])
        l4 = off + 40
        l4_len = int.from_bytes(data[off + 4:off + 6], "big")
    else:
        return {}

    out = {"src": src, "dst": dst, "proto": PROTO_NAMES.get(proto, str(proto))}
    if proto == 6 and len(data) >= l4 + 20:
        out["sport"] = int.from_bytes(data[l4:l4 + 2], "big")
        out["dport"] = int.from_bytes(data[l4 + 2:l4 + 4], "big")
        doff = (data[l4 + 12] >> 4) * 4
        out["flags"] = "".join(ch for bit, ch in TCP_FLAG_BITS if data[l4 + 13] & bit) or "-"
        out["seq"] = int.from_bytes(data[l4 + 4:l4 + 8], "big")
        out["payload_len"] = max(0, l4_len - doff)
    elif proto == 17 and len(data) >= l4 + 8:
        out["sport"] = int.from_bytes(data[l4:l4 + 2], "big")
        out["dport"] = int.from_bytes(data[l4 + 2:l4 + 4], "big")
        out["payload_len"] = max(0, int.from_bytes(data[l4 + 4:l4 + 6], "big") - 8)
    return out


# ------------------------------------------------------------------- capture

def read_exact(stream, n):
    """Exactly n bytes from a pipe.

    None when the stream ended right on a boundary, which is the normal way a
    terminated tcpdump ends; the short bytes when it ended mid-record, so the
    caller can report a truncated tail instead of writing a broken pcap.
    """
    chunks, got = [], 0
    while got < n:
        b = stream.read(n - got)
        if not b:
            return None if got == 0 else b"".join(chunks)
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


class ZabbixCapture:
    """One tcpdump, teed into the dedicated pcap and the ground-truth logs."""

    def __init__(self, args, bpf, addresses):
        self.args = args
        self.bpf = bpf
        self.addr = addresses
        self.run_id, self.seed = logio.parse_tag(args.tag)
        self.pcap_path = os.path.join(args.run_dir, f"{args.tag}_zabbix.pcap")
        self.meta_path = os.path.join(args.run_dir, f"{args.tag}.zabbix.meta.json")
        self.packets = 0
        self.records = 0
        self.undecoded = 0
        self.truncated = None
        self.linktype = None
        self.first_ts = None
        self.last_ts = None
        self.stopped_by = "tcpdump exited"
        self.proc = None
        self.stopping = False
        self.started = now_iso()

    # ---------------------------------------------------------- meta sidecar
    def write_meta(self, **extra):
        meta = {
            "tag": self.args.tag, "run_id": self.run_id, "seed": self.seed,
            "role": self.args.role, "source": "zabbix_agent (real daemon)",
            "enabled": True, "iface": self.args.iface, "bpf_filter": self.bpf,
            "addresses": self.addr, "pcap": os.path.basename(self.pcap_path),
            "log": f"{self.args.tag}_knownzabbix.json",
            "unions": [f"{self.args.tag}_knownbenign.json",
                       f"{self.args.tag}_alltraffic.json"],
            "started": self.started,
        }
        meta.update(extra)
        with open(self.meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    # ---------------------------------------------------------- run
    def start_tcpdump(self):
        cmd = ["tcpdump", "-i", self.args.iface, "-s", "0", "-U", "-w", "-",
               "-n", self.bpf]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            raise SystemExit("[!] tcpdump is not installed; no Zabbix capture")

    def on_signal(self, signum, _frame):
        # Only ask tcpdump to stop. It flushes and closes the pipe, the read loop
        # below sees EOF on a record boundary, and the meta is finalized there --
        # so a signal can never cut the log off mid-record.
        if not self.stopping:
            self.stopping = True
            self.stopped_by = signal.Signals(signum).name
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()

    def direction(self, fields):
        agent, server = self.addr.get("zabbix_agent_ip"), self.addr.get("zabbix_server_ip")
        src, dst = fields.get("src"), fields.get("dst")
        if agent and src == agent:
            return "agent_to_server" if (not server or dst == server) else "agent_to_other"
        if agent and dst == agent:
            return "server_to_agent" if (not server or src == server) else "other_to_agent"
        if server and src == server:
            return "server_to_agent"
        if server and dst == server:
            return "agent_to_server"
        return "unknown"

    def log_packet(self, ts, caplen, framelen, frame):
        fields = decode(self.linktype, frame)
        if not fields:
            self.undecoded += 1
        detail = dict(fields)
        detail.update(frame_len=framelen, cap_len=caplen,
                      direction=self.direction(fields), iface=self.args.iface)
        # Same record shape gen.py writes, so the Zabbix stream merges with the
        # scripted benign events on run_id/seed/role/proc without special casing.
        logio.write_zabbix(self.args.run_dir, self.args.tag, {
            "run_id": self.run_id, "seed": self.seed, "role": self.args.role,
            "proc": "zabbix", "ts": iso_from_epoch(ts), "ts_epoch": round(ts, 6),
            "event": "packet", "ok": True, "detail": detail,
        })
        self.records += 1

    def run(self):
        os.makedirs(self.args.run_dir, exist_ok=True)
        self.write_meta()

        print(f"[+] zabbix capture on {self.args.iface}: {self.bpf}")
        print(f"[+] zabbix pcap -> {self.pcap_path}")
        print(f"[+] zabbix log  -> {self.args.tag}_knownzabbix.json "
              f"(also folded into _knownbenign.json and _alltraffic.json)")

        self.proc = self.start_tcpdump()
        stop_signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):      # a dropped ssh session must not lose it
            stop_signals.append(signal.SIGHUP)
        for sig in stop_signals:
            signal.signal(sig, self.on_signal)

        stream = self.proc.stdout
        header = read_exact(stream, 24)
        if header is None or len(header) < 24:
            self.finish(problem="tcpdump wrote no pcap header (check the interface, "
                                "the filter, and that this runs as root)")
            return 1
        order, divisor = PCAP_MAGIC.get(header[:4], (None, None))
        if order is None:
            self.finish(problem=f"unrecognized pcap magic {header[:4].hex()}")
            return 1
        self.linktype = struct.unpack(order + "I", header[20:24])[0]

        # Byte-for-byte passthrough: the dedicated pcap is exactly the capture
        # tcpdump would have written itself.
        with open(self.pcap_path, "wb") as pcap:
            pcap.write(header)
            pcap.flush()
            while True:
                rec = read_exact(stream, 16)
                if rec is None:
                    break
                if len(rec) < 16:
                    self.truncated = f"partial record header ({len(rec)} bytes)"
                    break
                ts_sec, ts_frac, caplen, framelen = struct.unpack(order + "IIII", rec)
                # An implausible length means the pipe is out of step with the
                # record boundaries; stop rather than try to read that much.
                if caplen > MAX_CAPLEN:
                    self.truncated = (f"implausible record length {caplen} after "
                                      f"{self.packets} packets")
                    break
                frame = read_exact(stream, caplen) if caplen else b""
                if frame is None or len(frame) < caplen:
                    got = 0 if frame is None else len(frame)
                    self.truncated = f"partial packet ({got} of {caplen} bytes)"
                    break
                # pcap first, then the record: a hard kill can then only ever
                # leave the log one record behind the pcap, never ahead of it.
                pcap.write(rec + frame)
                pcap.flush()
                self.packets += 1
                ts = ts_sec + ts_frac / divisor
                self.first_ts = self.first_ts or ts
                self.last_ts = ts
                self.log_packet(ts, caplen, framelen, frame)
                if self.packets == 1:
                    print(f"[+] first Zabbix packet at {iso_from_epoch(ts)}")
                elif self.packets % 1000 == 0:
                    print(f"[+] {self.packets} Zabbix packets logged")

        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()               # it closed its pipe but will not exit
        self.finish()
        return 0

    def finish(self, problem=None):
        span = (round(self.last_ts - self.first_ts, 3)
                if self.first_ts and self.last_ts else None)
        self.write_meta(ended=now_iso(), stopped_by=self.stopped_by,
                        packets=self.packets, records=self.records,
                        undecoded=self.undecoded, truncated_tail=self.truncated,
                        linktype=self.linktype, span_seconds=span, problem=problem)
        if problem:
            print(f"[!] zabbix capture problem: {problem}")
        if self.truncated:
            print(f"[!] zabbix pcap stream ended mid-record: {self.truncated}")
        print(f"[+] zabbix capture done: {self.packets} packets, "
              f"{self.records} records, stopped by {self.stopped_by}")


def write_disabled_meta(args, addresses, ports, reason):
    os.makedirs(args.run_dir, exist_ok=True)
    path = os.path.join(args.run_dir, f"{args.tag}.zabbix.meta.json")
    with open(path, "w") as f:
        json.dump({"tag": args.tag, "role": args.role, "enabled": False,
                   "reason": reason, "iface": args.iface, "addresses": addresses,
                   "ports": ports, "started": now_iso()}, f, indent=2)
    print(f"[!] Zabbix capture DISABLED: {reason}")
    print(f"[!] this run will have NO Zabbix ground truth. Re-run SETUP.sh to set "
          f"the Zabbix addresses.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--iface", required=True,
                    help="interface carrying the mirror copy, e.g. ens19")
    ap.add_argument("--run-dir", required=True,
                    help="the run's logs/<tag>_logs/ directory")
    ap.add_argument("--tag", required=True, help="run stem R<run_id>-S<seed>")
    ap.add_argument("--role", default="honeypot")
    ap.add_argument("--print-filter", action="store_true",
                    help="print the BPF filter that would be used and exit")
    args = ap.parse_args()

    import yaml
    try:
        with open(args.config) as f:
            cfg = yaml.safe_load(f) or {}
    except OSError as e:
        raise SystemExit(f"[!] cannot read {args.config}: {e}")

    bpf, addresses, ports, disabled = build_filter(cfg)
    if args.print_filter:
        print(bpf if bpf else f"# disabled: {disabled}")
        return 0
    if disabled:
        write_disabled_meta(args, addresses, ports, disabled)
        return 0
    return ZabbixCapture(args, bpf, addresses).run()


if __name__ == "__main__":
    sys.exit(main())
