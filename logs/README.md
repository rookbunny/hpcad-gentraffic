# `logs/` — where every capture lands

Nothing in this directory is written by hand. `capture/run_capture.sh`,
`generator/gen.py`, `groundtruth/zabbix_log.py`, `groundtruth/attacker_log.py` and
`groundtruth/log_user.py` create it all at run time. The directory and the naming
template below are tracked so the expected layout is visible before the first
capture; real run directories are gitignored and never committed, because they
hold the dataset.

This directory stays at the repository root, rather than under one of the
categorized directories, because programs in three of them write into it.

A run is identified by a sequential run id (`0001`, `0002`, ...) and a 5-digit
seed, folded on disk into one stem — the run tag `R<run_id>-S<seed>`. Each
capture gets its own directory `logs/<tag>_logs/`, and every file inside is
prefixed with the tag:

```
logs/
├── R0001-S12345_logs/                          one capture
│   ├── R0001-S12345.pcap                       the whole mirrored wire
│   ├── R0001-S12345_zabbix.pcap                the real Zabbix agent's packets
│   ├── R0001-S12345_attacker_traffic.pcap      every packet to/from attacker_ip
│   ├── R0001-S12345_knownbenign.json           scripted benign events + Zabbix
│   ├── R0001-S12345_knownuser.json             manual events (log_user.py)
│   ├── R0001-S12345_knownzabbix.json           Zabbix, one record per packet
│   ├── R0001-S12345_attacker_traffic.json      attacker, one record per packet
│   ├── R0001-S12345_alltraffic.json            union of all three classes
│   ├── R0001-S12345.honeypot.manifest.json     gen.py, one per role
│   ├── R0001-S12345.zabbix.meta.json           filter, counts, stop reason
│   └── R0001-S12345.attacker.meta.json         filter, counts, stop reason
└── R0002-S54321_logs/                          the next capture
```

The `.promsvc.manifest.json` variant appears in the matching run directory on the
monitoring VM, which runs `generator/gen.py --role promsvc` with the same seed and run id
and so writes its own `logs/<tag>_logs/` there.

Which files exist is a property of the run, not a fixed list.
`<tag>_knownuser.json` only appears once something is logged with `groundtruth/log_user.py`,
and either per-stream tap writes a `meta.json` recording `enabled: false` instead
of a pcap when its addresses are missing from `config/config.yaml`. `capture/capture_report.py`
knows the difference and says so at the end of every capture.

`_TEMPLATE_R0000-S00000_logs/` holds one empty file per name above. It is a map,
not a run: the tooling ignores it, because a run directory has to match
`R<digits>-S<digits>_logs` to be picked up as one.
