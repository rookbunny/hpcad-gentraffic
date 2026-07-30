# Honeypot Benign Traffic Generator and Holistic Logger

## Overview

This repo is the code storage for a summer-internship project at a government high-performance
computing center. It engineers and red-teams a purpose-built honeypot virtual
machine in order to test network anomaly-detection machine-learning models.
Traffic from the honeypot is mirrored to standalone detection stacks, and two
adversary profiles (run1: an opportunistic intruder, and run2: a covert long-dwell operator)
are emulated under a tightly scoped engagement so the models can be scored
against activity known to be malicious.

Anomaly-detection models on production networks train on overwhelmingly benign
traffic, so a valid test requires a representative benign baseline. Without one,
the "normal" class is too thin and the models separate attack from baseline on
trivial artifacts rather than on meaningful structure.

This repository is the benign traffic generator that produces that baseline. It
emulates the everyday activity of the honeypot's fictional user (Michael Gunderson:
a research-computing staff member using the VM as a work desktop) as a set of
automatically scheduled processes. It produces three reproducible, timestamp-labeled
captures: a long benign baseline (unsupervised training data for the detection models)
and the same benign substrate running underneath each of the two attack runs. 
Because every benign action is logged, each packet in a capture can be attributed
to a known benign process, a known user or attacker action, or the emulated adversary.
This methodology ensures that the resulting dataset usable as a golden evaluation set.

## Repository contents

| Path | Runs on | Purpose |
|---|---|---|
| `gen.py` | honeypot + promsvc | the driver |
| `config.example.yaml` | — | template; `SETUP.sh` generates `config.yaml` from it |
| `SETUP.sh` | each host | prompts for range values, writes `config.yaml` |
| `run_capture.sh` | capture host | tcpdump + generator, tied under one run id |
| `zabbix_log.py` | capture host | captures and labels the REAL Zabbix agent's traffic |
| `attacker_log.py` | capture host | captures and labels ALL traffic to/from the attacker IP |
| `pcaptap.py` | — | shared packet-tap machinery behind those two |
| `log_user.py` | capture host | records manual/attacker events into the ground truth |
| `logio.py` | — | shared append-only logging |
| `systemd/Honeypot_gentraffic@.service` | honeypot | optional bounded service for long runs |
| `companions/ws_echo_server.py` | chat VM | target for the chat keepalive |
| `companions/health_server.py` | service VM | target for the healthcheck |
| [`mirror-persistence/`](mirror-persistence/README.md) | honeypot + monitor | reboot-persistent tc mirror + passive capture setup |

Not generated here: the C2 beacon (hand-run in the C2 framework) and manual web
browsing. Those are the anomalous and human streams, and they are recorded with
`log_user.py`. Zabbix is not generated either — that stream comes from the real
`zabbix-agent` daemon on the Rocky 9 honeypot and is captured at the packet level
by `zabbix_log.py` (see "Zabbix" below). Nor is the attack: every packet to or
from the attacker address is captured at the packet level by `attacker_log.py`,
in every run, as its own class (see "Attacker traffic" below).

## Traffic model

| Process | Period | Jitter | Originates on | Endpoint |
|---|---|---|---|---|
| chat keepalive | 20s | ±15s | honeypot | internal WebSocket |
| healthcheck | 60s | ±15s | honeypot | internal HTTP |
| email (IMAP + occasional SMTP) | 120s | ±30s | honeypot | internal mail server |
| space-weather archive pull | 30m | ±3m | honeypot | external (real) |
| Prometheus scrape | 50s | ±10s | promsvc VM | honeypot :9100 |
| Zabbix agent | the daemon's own interval | — | honeypot ↔ Zabbix server | **real, not generated**; captured per packet |
| web browsing | manual | — | honeypot | external (operator) |
| C2 beacon | 60s | ±15s | attacker → honeypot | hand-run, not here; **captured per packet** |

Any flow must cross the wire to reach the mirror, so every internal endpoint
must be a different host than the honeypot.

## Requirements

- Python 3.9+ on the honeypot and on the monitoring (promsvc) VM.
- `tcpdump` on the capture host, and an interface carrying the mirror copy.
  See [`mirror-persistence/`](mirror-persistence/README.md) for a reboot-persistent
  way to set up and keep that mirror alive.
- `node_exporter` running on the honeypot (exposes `:9100`).
- Reachable internal targets for mail, chat, and the healthcheck. The two
  companion servers cover chat and healthcheck without additional software.
- The real `zabbix-agent` daemon running on the Rocky 9 honeypot and registered
  with the Zabbix server, so there is a genuine Zabbix stream to capture. The
  mirror must carry it: it is the same interface, but confirm the agent's
  conversation with the server actually crosses the mirrored link.

## Setup

Run these steps on the honeypot (role `honeypot`). Repeat steps 1–3 on the
monitoring VM (role `promsvc`); that host only needs the config and the
dependencies, and never uses the mail password.

1. Place the repository at the deploy location.

   ```bash
   sudo cp -r gunderson /opt/gunderson
   cd /opt/gunderson
   ```

2. Create a virtual environment and install dependencies into it (this avoids
   modifying system-managed Python packages).

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install pyyaml websockets
   ```

3. Generate the configuration. Run this first; it prompts for the
   range-specific addresses and the mail password and writes `config.yaml`
   (gitignored, mode 600) from the template.

   ```bash
   ./SETUP.sh
   ```

   Three of its prompts are addresses used to attribute packets rather than to
   generate traffic: the **Zabbix server IP**, the **Zabbix agent IP** (the
   honeypot itself, which defaults to the honeypot address already entered), and
   the **attacker IP**. `zabbix_log.py` and `attacker_log.py` build their capture
   filters from them.

   The attacker IP must be the address the operator **actually works from** during
   `run1`/`run2`. Every packet to or from it is labeled as attacker traffic, so if
   it is wrong the attack still lands in `<tag>.pcap` but with no label on it, and
   the run is not usable as ground truth. A CIDR is accepted when the operator
   works from more than one host. Re-run `SETUP.sh` if the address changes between
   captures.

4. Start the companion targets so the chat keepalive and healthcheck have
   endpoints. Run each on its respective VM.

   ```bash
   # chat VM
   python3 companions/ws_echo_server.py 0.0.0.0 8765
   # service VM
   python3 companions/health_server.py 0.0.0.0 8080
   ```

5. Confirm `node_exporter` is running on the honeypot and reachable on `:9100`
   from the monitoring VM.

6. (Optional) Install the systemd unit for long unattended runs — see
   "Long runs (systemd)" below.

A run is identified by a sequential run id (`0001`, `0002`, ...) and a 5-digit
seed. On disk both are folded into a single stem, the run tag `R<run_id>-S<seed>`
(for example `R0001-S12345`). Each capture creates its own directory
`logs/<tag>_logs/` under the repository root, containing `<tag>_knownbenign.json`,
`<tag>_knownuser.json`, `<tag>_knownzabbix.json`, `<tag>_attacker_traffic.json`,
`<tag>_alltraffic.json`, the `<tag>.pcap`, the Zabbix-only `<tag>_zabbix.pcap`, the
attacker-only `<tag>_attacker_traffic.pcap`, `<tag>.zabbix.meta.json`,
`<tag>.attacker.meta.json`, and `<tag>.<role>.manifest.json`. A `.current_run`
pointer at the repository root records the active run tag for `log_user.py`.

## Running a capture

A capture involves two hosts. The same seed is used on both: one seed reproduces
the whole run because each process is seeded from `(seed, process_name)`.

1. On the capture host, start tcpdump, the Zabbix and attacker packet loggers, and
   the honeypot processes. The script prints a run id and seed.

   ```bash
   sudo ./run_capture.sh baseline ens19          # fresh 5-digit seed
   sudo ./run_capture.sh run2     ens19  13370    # pinned seed
   ```

2. On the monitoring VM, run the scrape process with the same seed and run id.

   ```bash
   ./.venv/bin/python3 gen.py --profile baseline --role promsvc \
       --seed <seed> --run-id <run_id>
   ```

   This creates a matching `logs/<tag>_logs/` on the monitoring VM holding
   that host's benign log and manifest.

3. During `run1` and `run2`, record each attacker action and browsing session as
   it happens. The run id is read from the `.current_run` pointer automatically.

   ```bash
   ./.venv/bin/python3 log_user.py "hydra ssh brute force start" --source attacker --phase T1110
   ./.venv/bin/python3 log_user.py "youtube session start"       --source browsing
   ```

Profiles (all captured at a 15s bucket span):

| Profile | Window | Notes |
|---|---|---|
| `baseline` | 4h (timed, 960 buckets) | unsupervised training data; long on purpose for tail estimation |
| `run1` | until you stop it | opportunistic; benign scaffold under the loud attack |
| `run2` | until you stop it | covert dwell; run live browsing as cover during this window |
| `selftest` | until you stop it | wiring test; `noop` process only, touches no real endpoint |

## Stopping a run

`baseline` is timed and ends on its own. Every other profile has `run_seconds:
null` in the config and runs for as long as the engagement needs, so run lengths
can vary from capture to capture. To stop one, type `exit` (Ctrl-C also works) in
the terminal running `run_capture.sh`:

```bash
exit
```

Either way the generator finalizes its manifest with the real elapsed time, both
tcpdumps flush, the Zabbix logger drains its tail and finalizes its meta file,
and a summary reports whether every expected file was written,
how many packets and records are in each, and how long the capture ran. That
same summary prints on any other exit too -- a SIGTERM, a script error, a closed
stdin -- so a run never ends silently. The exit status is non-zero if anything is
missing, empty, or truncated.

The check is `capture_report.py`, which can also be run later against any
finished run:

```bash
./.venv/bin/python3 capture_report.py logs/R0001-S12345_logs R0001-S12345
```

An existing `config.yaml` predates the untimed profiles, so re-run `SETUP.sh`, or
set `run_seconds: null` for `run1`, `run2`, and `selftest` by hand. A profile
that still carries a number keeps stopping at that number; `--run-seconds` on
`gen.py` overrides either way.

## Long runs (systemd)

The unit is a template: the instance name after `@` is passed straight through
to the generator as the profile via `%i`. Starting `Honeypot_gentraffic@baseline`
therefore runs the `baseline` profile.

```bash
sudo cp systemd/Honeypot_gentraffic@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start Honeypot_gentraffic@baseline    # %i -> baseline
journalctl -u Honeypot_gentraffic@baseline -f
```

To pin a seed for a reproducible run, write it into the optional env file before
starting; with no file present the generator selects a random seed and records
it in the manifest.

```bash
echo 'SEED_ARG=--seed 13370' | sudo tee /opt/gunderson/run.env
```

The systemd unit runs the generator only. For a baseline pcap that survives a
disconnect, run `run_capture.sh baseline ens19` inside a tmux session instead.

## Reseeding per capture

Each of `baseline`, `run1`, and `run2` is run with a different seed: the same
process set and the same interval distributions, but a different draw. This keeps
the benign scaffold from being a fixed timing fingerprint across the three
captures, while the only systematic difference between baseline and a run remains
the attack itself. Ground truth is unaffected, since the labels come from the
logs rather than from the timing.

## Logging and labeling

All ground truth for a capture lives in that capture's `logs/<tag>_logs/`
directory as newline-delimited JSON:

There are three **classes** — `benign`, `user`, and `attacker` — and
`alltraffic` is their holistic union:

- `<tag>_knownbenign.json` — the holistic benign union: every scripted benign
  action, plus one record per real Zabbix packet.
- `<tag>_knownuser.json` — every manual action recorded via `log_user.py`
  (attacker actions and web browsing).
- `<tag>_knownzabbix.json` — the real Zabbix agent's traffic on its own, one
  record per packet. A subset view of `knownbenign`, not a separate class.
- `<tag>_attacker_traffic.json` — every packet to or from the attacker address,
  one record per packet. A **class of its own**: it is folded into `alltraffic`
  and deliberately *not* into `knownbenign` or `knownuser`.
- `<tag>_alltraffic.json` — the union of everything, distinguished by the
  `class` field. `knownbenign + knownuser + attacker_traffic == alltraffic` holds
  exactly, with the Zabbix stream counted once inside `knownbenign`;
  `capture_report.py` checks that arithmetic at the end of every run.

The two per-stream logs sit inside that arithmetic differently, and the
difference is the point. `knownzabbix` is a *subset view* of `knownbenign`,
because Zabbix telemetry genuinely is benign. `attacker_traffic` is a *separate
class*, because adversary traffic is neither known-benign nor known-user, and
folding it into either union would poison the very label it exists to define.

Note that the `attacker` class covers **packets**, not annotations. The operator's
own notes about what they were doing — `log_user.py --source attacker` — stay in
`knownuser.json` with `class=user`, deliberately: they are human keyboard events
recorded by hand, not traffic observed on the wire, and they are what you read the
packet labels *against*. The packets say what crossed the wire; the notes say what
the operator was doing at the time.

Every record also carries `run_id`, `seed`, and `role`, so events remain
attributable per host even after files from multiple hosts are merged. Zabbix and
attacker records use the same shape as the generator's, with `proc: zabbix` /
`proc: attacker` and a `source` field, so they merge without special casing.

Three capture files sit in the same directory: `<tag>.pcap` is the whole wire,
and `<tag>_zabbix.pcap` and `<tag>_attacker_traffic.pcap` are two subsets of it,
each written by its own tcpdump so those streams can be handled on their own
without ever being mixed into the generated-traffic capture. The relationship is
the same one the logs have — each packet is present in the all-traffic capture
exactly once, and mirrored into its stream's own file. Within a run window only
the scripted benign set, the real Zabbix stream, the recorded manual actions, and
the adversary are present, so any packet not attributable to a benign, Zabbix,
user, or attacker record is the residue worth looking at.

Capture the baseline and every run at the same 15s span. Count and volume
features scale with the span, so the training baseline and the run scored against
it must share it or the distributions are not comparable.

## Zabbix

Zabbix traffic is **real, never simulated**. Nothing in this repository generates
it: the `zabbix-agent` daemon on the Rocky 9 honeypot and the Zabbix server that
polls it are the only source, so the Zabbix stream in the dataset is genuine
telemetry from a genuine agent. Zabbix matters twice over — it is cover traffic,
and it is the service account the covert run impersonates — so a simulated
stand-in would be the wrong thing to train or score a model against.

`zabbix_log.py` records it. `run_capture.sh` starts it alongside the run's main
tcpdump and stops it at the end of the run, and it can also be run by hand:

```bash
sudo ./.venv/bin/python3 zabbix_log.py --iface ens19 \
    --run-dir logs/R0001-S12345_logs --tag R0001-S12345
```

It owns one tcpdump, filtered to the Zabbix conversation, and tees it: every
packet is written through to `<tag>_zabbix.pcap` byte for byte **and** decoded
into one ground-truth record. The dedicated pcap and the log therefore come from
the same packets and cannot disagree, which `capture_report.py` verifies by
comparing their counts.

What lands where, for one Zabbix packet:

| File | Contents |
|---|---|
| `<tag>_zabbix.pcap` | the packet, in the Zabbix-only capture |
| `<tag>.pcap` | the same packet, in the whole-wire capture (it is the union) |
| `<tag>_knownzabbix.json` | one record: src/dst, ports, TCP flags, lengths, direction |
| `<tag>_knownbenign.json` | the same record, in the holistic benign union |
| `<tag>_alltraffic.json` | the same record, in the all-traffic union — once, never twice |
| `<tag>.zabbix.meta.json` | the run's BPF filter, addresses, counts, and stop reason |

**What counts as Zabbix traffic.** The agent runs *on* the honeypot, so a filter
of "every packet involving the agent address" would match the entire capture.
The filter is therefore the Zabbix addresses scoped to the Zabbix ports —
`tcp and (host <server> or host <agent>) and (port 10050 or port 10051)` — which
is what makes "involving Zabbix" mean the telemetry rather than everything the
honeypot does. 10050 is the agent's passive checks and 10051 is the server side
(active checks, `zabbix_sender`); add ports under `zabbix_capture.ports` in
`config.yaml` if a Zabbix proxy or a non-default port is in play.

**The attacker address is excluded.** `run2`'s covert operator impersonates the
Zabbix service account, so packets from `addresses.attacker_ip` are the
adversary's and must not be labeled as benign telemetry. `attacker_log.py`
captures and labels them instead, as attacker traffic. Set
`zabbix_capture.exclude_attacker: false` to fold them into the Zabbix stream
anyway.

If `config.yaml` has no Zabbix addresses, the logger disables itself, says so
loudly, and writes `<tag>.zabbix.meta.json` with `enabled: false` and the reason,
so the closing summary reports the gap instead of a run quietly lacking Zabbix
ground truth. Re-run `SETUP.sh` to fix it.

## Attacker traffic

Any packet whose source or destination is `addresses.attacker_ip` is known
attacker/anomalous traffic **by definition** — whatever protocol it speaks and
whatever port it lands on. That is a property of the address, not of the run
type, so `attacker_log.py` runs on **every** capture including the baseline.

`run_capture.sh` starts it alongside the run's main tcpdump and stops it last, so
the attacker stream is recorded for the whole capture window. It can also be run
by hand:

```bash
sudo ./.venv/bin/python3 attacker_log.py --iface ens19 \
    --run-dir logs/R0001-S12345_logs --tag R0001-S12345
```

Like the Zabbix logger it owns one tcpdump and tees it: every packet is written
through to `<tag>_attacker_traffic.pcap` byte for byte **and** decoded into one
ground-truth record, so the dedicated pcap and the log come from the same packets
and cannot disagree. `capture_report.py` verifies that by comparing their counts.
Both taps share the capture loop and header decoding in `pcaptap.py`.

What lands where, for one attacker packet:

| File | Contents |
|---|---|
| `<tag>_attacker_traffic.pcap` | the packet, in the attacker-only capture |
| `<tag>.pcap` | the same packet, in the whole-wire capture (it is the union) |
| `<tag>_attacker_traffic.json` | one record: src/dst, ports, TCP flags, lengths, direction, peer |
| `<tag>_alltraffic.json` | the same record, in the all-traffic union — once, never twice |
| `<tag>_knownbenign.json` | **never** — attacker traffic is not benign |
| `<tag>_knownuser.json` | **never** — attacker traffic is not the known user |
| `<tag>.attacker.meta.json` | the run's BPF filter, address, counts, and stop reason |

**The filter is the whole address, not a port list.** Unlike the Zabbix filter,
which must be port-scoped because the agent runs *on* the honeypot, the attacker
address is not the honeypot — so `host <attacker_ip>` is exactly the wanted
stream, down to the stray ICMP and the scan that never got an answer. A CIDR
works when the operator uses several hosts. Each record carries `direction`
(`attacker_to_target` / `target_to_attacker`) and `peer`, the address at the
other end.

**It catches what nothing else did.** Because the Zabbix filter deliberately
excludes the attacker address, `run2`'s Zabbix-service-account impersonation used
to appear only in the whole-wire pcap with no record of its own. Those packets now
land here, labeled as the adversary's.

**An empty attacker stream is a result, not a failure.** Zero attacker packets is
what a clean baseline should look like, and it is positive evidence the baseline
*is* clean. In `run1`/`run2` it means the attack was missed — a wrong
`attacker_ip`, or a mirror that is not carrying it — so the closing summary warns
about that case specifically.

If `addresses.attacker_ip` is unset or malformed, the logger disables itself,
says so loudly, and writes `<tag>.attacker.meta.json` with `enabled: false`.
`capture_report.py` reports that as a **problem** rather than a warning, and the
run exits non-zero: attacker ground truth is expected in every run, so its absence
means the config is wrong and the capture cannot be labeled. Re-run `SETUP.sh`.

## One more decision worth knowing

**Per-destination periodicity.** The beacon (60s), the real Zabbix stream (the
agent's own interval, commonly 60s), and the healthcheck (60s) share a cadence by
design. At a 15s span the 60s period
spans four buckets, so timing features can resolve the rhythm — but only if
periodicity is computed per destination rather than aggregated across all traffic
in a bucket. Aggregated per bucket, the three 60s streams sum into a single
"normal at 60s" signal and the beacon becomes indistinguishable from benign
telemetry. Computed per destination, each periodic endpoint is modeled
separately and the beacon surfaces as its own periodic destination. The detection
features must therefore key on the destination:

- Group flows by the responder tuple (destination IP, or IP plus port) before
  computing inter-arrival and periodicity features, so the unit of analysis is
  `(destination, window)` rather than `window`.
- In an Elasticsearch ML job, set a partition or by field on the destination
  (for example `partition_field_name: destination.ip`) so a separate baseline is
  built per destination.
- In a Zeek-derived pipeline, aggregate `conn.log` by `id.resp_h` before deriving
  timing statistics.
- In a custom PyOD pipeline, construct one feature vector per
  `(destination, window)` with per-destination inter-arrival mean, variance, and
  autocorrelation, rather than pooling all destinations into a single per-window
  vector.
