"""Shared machinery for the per-stream packet taps.

Its two subclasses are its siblings here in groundtruth/.

zabbix_log.py and attacker_log.py do the same thing to a different slice of the
wire: run one tcpdump with a BPF filter, write every matching packet through to a
dedicated pcap byte for byte, and decode those same packets into ground-truth
records. One tcpdump per stream is what makes the dedicated pcap and the log
unable to disagree about what was seen, and keeping the loop here means that
property -- and any fix to it -- holds for every stream at once.

A subclass supplies the filter, the file names, and where the records go:

    class MyTap(pcaptap.TeeCapture):
        label = "mystream"        # how the stream is named in messages
        proc_name = "mystream"    # the record's "proc" field
        def announce(self): ...                   # what it prints on startup
        def base_meta(self): ...                  # extra keys for the sidecar
        def annotate(self, fields, detail): ...   # per-packet attribution
        def emit(self, record): ...               # which logio writer to use

Nothing here touches the run's main pcap, and no packet payload is read beyond
the headers needed to attribute the packet.
"""

import ipaddress, json, os, signal, struct, subprocess
from datetime import datetime, timezone

import logio

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

def address_problem(value):
    """None if value is an IP address or network, else why it is not one.

    Returned rather than raised so a caller can decide whether a misconfigured
    address disables one stream with a warning or aborts.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return f"{value!r} is not an IP address or network"
    return None


def bpf_host(value, label):
    """Validate an operator-supplied address before it becomes a BPF term.

    tcpdump would reject a malformed expression anyway, but it would do so
    several steps later and with a worse message than naming the config key.
    """
    problem = address_problem(value)
    if problem:
        raise SystemExit(f"[!] {label}={value!r} in the config is not an IP "
                         f"address or network; fix it (re-run config/SETUP.sh)")
    return f"host {value}"


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


class TeeCapture:
    """One tcpdump, teed into a dedicated pcap and the ground-truth logs."""

    label = "capture"       # how the stream is named in operator-facing messages
    proc_name = "capture"   # the "proc" field on every record it writes

    def __init__(self, iface, run_dir, tag, role, bpf, pcap_name, meta_name):
        self.iface = iface
        self.run_dir = run_dir
        self.tag = tag
        self.role = role
        self.bpf = bpf
        self.run_id, self.seed = logio.parse_tag(tag)
        self.pcap_path = os.path.join(run_dir, pcap_name)
        self.meta_path = os.path.join(run_dir, meta_name)
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

    # ---------------------------------------------------------- subclass hooks
    def announce(self):
        print(f"[+] {self.label} capture on {self.iface}: {self.bpf}")
        print(f"[+] {self.label} pcap -> {self.pcap_path}")

    def base_meta(self):
        """The sidecar's common keys; subclasses add the stream-specific ones."""
        return {
            "tag": self.tag, "run_id": self.run_id, "seed": self.seed,
            "role": self.role, "enabled": True, "iface": self.iface,
            "bpf_filter": self.bpf, "pcap": os.path.basename(self.pcap_path),
            "started": self.started,
        }

    def annotate(self, fields, detail):
        """Add stream-specific attribution to one packet's detail dict."""

    def emit(self, record):
        raise NotImplementedError

    # ---------------------------------------------------------- meta sidecar
    def write_meta(self, **extra):
        meta = self.base_meta()
        meta.update(extra)
        with open(self.meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    # ---------------------------------------------------------- run
    def start_tcpdump(self):
        cmd = ["tcpdump", "-i", self.iface, "-s", "0", "-U", "-w", "-",
               "-n", self.bpf]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            raise SystemExit(f"[!] tcpdump is not installed; no {self.label} capture")

    def on_signal(self, signum, _frame):
        # Only ask tcpdump to stop. It flushes and closes the pipe, the read loop
        # below sees EOF on a record boundary, and the meta is finalized there --
        # so a signal can never cut the log off mid-record.
        if not self.stopping:
            self.stopping = True
            self.stopped_by = signal.Signals(signum).name
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()

    def log_packet(self, ts, caplen, framelen, frame):
        fields = decode(self.linktype, frame)
        if not fields:
            self.undecoded += 1
        detail = dict(fields)
        detail.update(frame_len=framelen, cap_len=caplen, iface=self.iface)
        self.annotate(fields, detail)
        # Same record shape generator/gen.py writes, so a packet stream merges with the
        # scripted events on run_id/seed/role/proc without special casing.
        self.emit({
            "run_id": self.run_id, "seed": self.seed, "role": self.role,
            "proc": self.proc_name, "ts": iso_from_epoch(ts),
            "ts_epoch": round(ts, 6), "event": "packet", "ok": True,
            "detail": detail,
        })
        self.records += 1

    def run(self):
        os.makedirs(self.run_dir, exist_ok=True)
        self.write_meta()
        self.announce()

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
                    print(f"[+] first {self.label} packet at {iso_from_epoch(ts)}")
                elif self.packets % 1000 == 0:
                    print(f"[+] {self.packets} {self.label} packets logged")

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
            print(f"[!] {self.label} capture problem: {problem}")
        if self.truncated:
            print(f"[!] {self.label} pcap stream ended mid-record: {self.truncated}")
        print(f"[+] {self.label} capture done: {self.packets} packets, "
              f"{self.records} records, stopped by {self.stopped_by}")
