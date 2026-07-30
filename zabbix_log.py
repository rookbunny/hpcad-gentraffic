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
That loop, and the header decoding, live in pcaptap.py, shared with
attacker_log.py. The run's main tcpdump keeps its own copy of these packets,
because that capture is the whole wire: the Zabbix stream is present there exactly
once, the same way a Zabbix record appears exactly once in <tag>_alltraffic.json.

WHAT COUNTS AS ZABBIX TRAFFIC. The agent runs ON the honeypot, so "every packet
involving the agent address" would match the entire capture. The filter is
therefore the Zabbix addresses scoped to the Zabbix ports (10050 agent /
10051 server by default, configurable), which is what makes "involving Zabbix"
mean the telemetry rather than everything the honeypot does. Traffic from the
attacker address is excluded: run2's covert operator impersonates the Zabbix
service account, and those packets are the adversary's, not benign telemetry.
They are captured and labeled by attacker_log.py instead.

run_capture.sh starts this alongside the run's main tcpdump and stops it with
SIGTERM. It also runs by hand against an existing run directory:

    sudo ./.venv/bin/python3 zabbix_log.py --iface ens19 \
        --run-dir logs/R0001-S12345_logs --tag R0001-S12345
"""

import argparse, json, os, sys

import logio, pcaptap

# Agent passive checks arrive on 10050; the agent's active checks and
# zabbix_sender reach the server on 10051. Override in config.yaml when a proxy
# or a non-default port is in play.
DEFAULT_PORTS = [10050, 10051]


# ------------------------------------------------------------------- filter

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
        terms.append(pcaptap.bpf_host(server, "addresses.zabbix_server_ip"))
    if agent:
        terms.append(pcaptap.bpf_host(agent, "addresses.zabbix_agent_ip"))
    if not terms:
        return None, addresses, ports, ("neither addresses.zabbix_server_ip nor "
                                        "addresses.zabbix_agent_ip is set in the config")
    if not ports:
        return None, addresses, ports, "zabbix_capture.ports is empty in the config"

    hosts = " or ".join(terms)
    port_expr = " or ".join(f"port {p}" for p in ports)
    bpf = f"tcp and ({hosts}) and ({port_expr})"
    if attacker and zc.get("exclude_attacker", True):
        bpf += " and not " + pcaptap.bpf_host(attacker, "addresses.attacker_ip")
    return bpf, addresses, ports, None


# ------------------------------------------------------------------- capture

class ZabbixCapture(pcaptap.TeeCapture):
    """The Zabbix slice of the wire: its own pcap, its own log, both unions."""

    label = "zabbix"
    proc_name = "zabbix"

    def __init__(self, args, bpf, addresses):
        super().__init__(iface=args.iface, run_dir=args.run_dir, tag=args.tag,
                         role=args.role, bpf=bpf,
                         pcap_name=f"{args.tag}_zabbix.pcap",
                         meta_name=f"{args.tag}.zabbix.meta.json")
        self.addr = addresses

    def base_meta(self):
        meta = super().base_meta()
        meta.update(source="zabbix_agent (real daemon)", addresses=self.addr,
                    log=f"{self.tag}_knownzabbix.json",
                    unions=[f"{self.tag}_knownbenign.json",
                            f"{self.tag}_alltraffic.json"])
        return meta

    def announce(self):
        print(f"[+] zabbix capture on {self.iface}: {self.bpf}")
        print(f"[+] zabbix pcap -> {self.pcap_path}")
        print(f"[+] zabbix log  -> {self.tag}_knownzabbix.json "
              f"(also folded into _knownbenign.json and _alltraffic.json)")

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

    def annotate(self, fields, detail):
        detail["direction"] = self.direction(fields)

    def emit(self, record):
        logio.write_zabbix(self.run_dir, self.tag, record)


def write_disabled_meta(args, addresses, ports, reason):
    os.makedirs(args.run_dir, exist_ok=True)
    path = os.path.join(args.run_dir, f"{args.tag}.zabbix.meta.json")
    with open(path, "w") as f:
        json.dump({"tag": args.tag, "role": args.role, "enabled": False,
                   "reason": reason, "iface": args.iface, "addresses": addresses,
                   "ports": ports, "started": pcaptap.now_iso()}, f, indent=2)
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
