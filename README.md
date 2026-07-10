<img width="995" height="407" alt="white-rabbit-logo" src="https://github.com/user-attachments/assets/f28fc8cb-c0eb-4947-9b85-39a6bab2f95f" />

# White-Rabbit: Honeypot Benign Traffic Generator

## Overview

WHITE-RABBIT is a summer-internship project at a government high-performance
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
| `log_user.py` | capture host | records manual/attacker events into the ground truth |
| `logio.py` | — | shared append-only logging |
| `systemd/Honeypot_gentraffic@.service` | honeypot | optional bounded service for long runs |
| `companions/ws_echo_server.py` | chat VM | target for the chat keepalive |
| `companions/health_server.py` | service VM | target for the healthcheck |
| [`mirror-persistence/`](mirror-persistence/README.md) | honeypot + monitor | reboot-persistent tc mirror + passive capture setup |

Not generated here: the C2 beacon (hand-run in the C2 framework) and manual web
browsing. Those are the anomalous and human streams, and they are recorded with
`log_user.py`.

## Traffic model

| Process | Period | Jitter | Originates on | Endpoint |
|---|---|---|---|---|
| chat keepalive | 20s | ±15s | honeypot | internal WebSocket |
| healthcheck | 60s | ±15s | honeypot | internal HTTP |
| email (IMAP + occasional SMTP) | 120s | ±30s | honeypot | internal mail server |
| space-weather archive pull | 30m | ±3m | honeypot | external (real) |
| Prometheus scrape | 50s | ±10s | promsvc VM | honeypot :9100 |
| Zabbix | 60s | ±10s | honeypot | internal (off by default) |
| web browsing | manual | — | honeypot | external (operator) |
| C2 beacon | 60s | ±15s | attacker → honeypot | hand-run, not here |

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
`<tag>_knownuser.json`, `<tag>_alltraffic.json`, the `<tag>.pcap`, and
`<tag>.<role>.manifest.json`. A `.current_run` pointer at the repository root
records the active run tag for `log_user.py`.

## Running a capture

A capture involves two hosts. The same seed is used on both: one seed reproduces
the whole run because each process is seeded from `(seed, process_name)`.

1. On the capture host, start tcpdump and the honeypot processes. The script
   prints a run id and seed.

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

| Profile | Window | Buckets | Notes |
|---|---|---|---|
| `baseline` | 4h | 960 | unsupervised training data; long on purpose for tail estimation |
| `run1` | 20m | 80 | opportunistic; benign scaffold under the loud attack |
| `run2` | 40m | 160 | covert dwell; run live browsing as cover during this window |

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

- `<tag>_knownbenign.json` — every scripted benign action, timestamped.
- `<tag>_knownuser.json` — every manual action recorded via `log_user.py`
  (attacker actions and web browsing).
- `<tag>_alltraffic.json` — the union of the two, distinguished by the
  `class` field.

Every record also carries `run_id`, `seed`, and `role`, so events remain
attributable per host even after files from multiple hosts are merged. The
`<tag>.pcap` sits in the same directory. Within a run window, only the scripted benign set,
the recorded manual actions, and the emulated adversary are present, so any
packet not attributable to a benign or user record belongs to the adversary.

Capture the baseline and every run at the same 15s span. Count and volume
features scale with the span, so the training baseline and the run scored against
it must share it or the distributions are not comparable.

## Two decisions worth knowing

**Zabbix.** Off by default in the config, because the real Zabbix agent daemon
should already be running on the honeypot. Zabbix provides cover traffic as well
as the service account the covert run impersonates. Leaving the daemon on
and noting its interval is the recommended path, as the manifest records that this
stream exists (even though its individual sends are not logged by the generator).
The scripted Zabbix process should be enabled only if the daemon's active checks
are disabled, otherwise two Zabbix streams appear.

**Per-destination periodicity.** The beacon (60s), the Zabbix stream (60s), and
the healthcheck (60s) share a cadence by design. At a 15s span the 60s period
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
