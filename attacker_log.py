#!/usr/bin/env python3
"""
Packet-level capture and labeling of ALL traffic to or from the attacker address.

In every run, any packet whose source or destination is addresses.attacker_ip is
known attacker/anomalous traffic by definition -- whatever protocol it speaks and
whatever port it lands on. This process records that stream on its own:

  <tag>_attacker_traffic.pcap   every attacker packet, in its own capture file
  <tag>_attacker_traffic.json   one ground-truth record per attacker packet
  <tag>_alltraffic.json         the same records, folded into the all-traffic union
  <tag>.attacker.meta.json      the BPF filter, the address, counts, stop reason

A single tcpdump feeds all of that. Its pcap stream arrives on a pipe; every
packet is written through to <tag>_attacker_traffic.pcap byte for byte AND decoded
into one record, so the dedicated pcap and the log can never disagree about what
was seen. The run's main tcpdump keeps its own copy of these packets, because that
capture is the whole wire: the attacker stream is present there exactly once, the
same way an attacker record appears exactly once in <tag>_alltraffic.json.

WHICH UNIONS IT JOINS. Attacker traffic is its own class. It is folded into
<tag>_alltraffic.json, the holistic union of the ENTIRE capture, and deliberately
NOT into <tag>_knownbenign.json or <tag>_knownuser.json: those are the
known-benign and known-user unions, and adversary traffic belongs to neither. So

    knownbenign + knownuser + attacker_traffic == alltraffic

which is what capture_report.py checks. Compare zabbix_log.py, whose stream IS
benign and therefore does land in knownbenign.

WHAT IT PICKS UP THAT NOTHING ELSE DOES. The Zabbix filter excludes the attacker
address on purpose, because run2's covert operator impersonates the Zabbix service
account. Those impersonated packets used to live only in the run's main pcap with
no record of their own; they now land here, labeled as the adversary's.

An empty attacker stream is meaningful, not a failure: it is what a clean baseline
should look like, and it is evidence the baseline really is clean.

run_capture.sh starts this alongside the run's main tcpdump and stops it with
SIGTERM. It also runs by hand against an existing run directory:

    sudo ./.venv/bin/python3 attacker_log.py --iface ens19 \
        --run-dir logs/R0001-S12345_logs --tag R0001-S12345
"""

import argparse, ipaddress, json, os, sys

import logio, pcaptap


# ------------------------------------------------------------------- filter

def build_filter(cfg):
    """(bpf_filter, addresses, disabled_reason).

    disabled_reason is None when there is something to capture; otherwise the
    filter is None and the reason says why, so the run reports the gap loudly
    instead of silently producing no attacker ground truth.
    """
    addr = cfg.get("addresses") or {}
    attacker = str(addr.get("attacker_ip") or "").strip()
    addresses = {"attacker_ip": attacker or None}

    if not attacker:
        return None, addresses, "addresses.attacker_ip is not set in the config"
    problem = pcaptap.address_problem(attacker)
    if problem:
        return None, addresses, f"addresses.attacker_ip {problem}"

    # No port or protocol scoping, unlike the Zabbix filter: the attacker address
    # is not the honeypot, so "every packet involving it" is exactly the stream
    # wanted, down to the stray ICMP and the scan that got no answer.
    return f"host {attacker}", addresses, None


# ------------------------------------------------------------------- capture

class AttackerCapture(pcaptap.TeeCapture):
    """The attacker slice of the wire: its own pcap, its own log, alltraffic."""

    label = "attacker"
    proc_name = "attacker"

    def __init__(self, args, bpf, addresses):
        super().__init__(iface=args.iface, run_dir=args.run_dir, tag=args.tag,
                         role=args.role, bpf=bpf,
                         pcap_name=f"{args.tag}_attacker_traffic.pcap",
                         meta_name=f"{args.tag}.attacker.meta.json")
        self.addr = addresses
        attacker = addresses["attacker_ip"]
        self.attacker_str = attacker
        # A single address is matched by string compare, which costs nothing per
        # packet. Only a CIDR needs real membership testing.
        self.attacker_net = (ipaddress.ip_network(attacker, strict=False)
                             if "/" in attacker else None)

    def base_meta(self):
        meta = super().base_meta()
        meta.update(source="attacker_ip (operator / C2 address)",
                    addresses=self.addr,
                    log=f"{self.tag}_attacker_traffic.json",
                    unions=[f"{self.tag}_alltraffic.json"],
                    not_in_unions=[f"{self.tag}_knownbenign.json",
                                   f"{self.tag}_knownuser.json"])
        return meta

    def announce(self):
        print(f"[+] attacker capture on {self.iface}: {self.bpf}")
        print(f"[+] attacker pcap -> {self.pcap_path}")
        print(f"[+] attacker log  -> {self.tag}_attacker_traffic.json "
              f"(also folded into _alltraffic.json; NOT into _knownbenign.json "
              f"or _knownuser.json)")

    def is_attacker(self, ip):
        if ip is None:
            return False
        if ip == self.attacker_str:
            return True
        if self.attacker_net is None:
            return False
        try:
            return ipaddress.ip_address(ip) in self.attacker_net
        except ValueError:
            return False

    def annotate(self, fields, detail):
        """Which way the packet went, and who the attacker was talking to."""
        src, dst = fields.get("src"), fields.get("dst")
        if self.is_attacker(src):
            detail["direction"] = "attacker_to_target"
            detail["peer"] = dst
        elif self.is_attacker(dst):
            detail["direction"] = "target_to_attacker"
            detail["peer"] = src
        else:
            # The filter matched but the decode did not resolve an address --
            # a non-IP frame such as the ARP that "host X" also matches, or a
            # frame too short to read. The packet is still in the pcap.
            detail["direction"] = "unknown"
            detail["peer"] = None

    def emit(self, record):
        logio.write_attacker(self.run_dir, self.tag, record)


def write_disabled_meta(args, addresses, reason):
    os.makedirs(args.run_dir, exist_ok=True)
    path = os.path.join(args.run_dir, f"{args.tag}.attacker.meta.json")
    with open(path, "w") as f:
        json.dump({"tag": args.tag, "role": args.role, "enabled": False,
                   "reason": reason, "iface": args.iface, "addresses": addresses,
                   "started": pcaptap.now_iso()}, f, indent=2)
    print(f"[!] ATTACKER capture DISABLED: {reason}")
    print(f"[!] this run will have NO attacker ground truth, in any run type. "
          f"Re-run SETUP.sh to set the attacker address.")


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

    bpf, addresses, disabled = build_filter(cfg)
    if args.print_filter:
        print(bpf if bpf else f"# disabled: {disabled}")
        return 0
    if disabled:
        write_disabled_meta(args, addresses, disabled)
        return 0
    return AttackerCapture(args, bpf, addresses).run()


if __name__ == "__main__":
    sys.exit(main())
