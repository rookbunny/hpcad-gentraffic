# How To Run: Baseline

## Purpose

- Produce the long benign capture that trains the anomaly-detection models.
- Window is 4 hours (14400 seconds), which is 960 buckets at a 15 second span. The length is deliberate so the tails of the interval distributions are estimated well.
- No attacker actions and no cover browsing are part of a baseline. Only the scripted benign substrate runs.

## Processes in this profile

- `chat_ws` (persistent WebSocket keepalive)
- `healthcheck` (internal HTTP)
- `email` (IMAP polls with occasional SMTP)
- `noaa` (external space-weather archive pulls)
- `prom_scrape` (runs on the monitoring VM, not the honeypot)

## Preconditions

- `config/SETUP.sh` has been run on both the honeypot capture host and the monitoring VM, including the Zabbix and attacker addresses.
- Companion targets and `node_exporter` are reachable, and the real `zabbix-agent` daemon is running on the honeypot (see the testing document).
- A test pass has already confirmed the pipeline wiring.
- The capture is long, so it should run inside `tmux` so it survives an SSH disconnect. For an unattended baseline that also auto-stops at the window end, see the baseline systemd document.

## Steps

1. On the capture host, start the capture. Omitting the seed draws a fresh 5 digit seed. The script prints the run id, the tag, and the seed.

   ```bash
   tmux new -s baseline
   sudo ./capture/run_capture.sh baseline ens19
   ```

   `ens19` is the interface carrying the mirror copy off the honeypot. Record the printed run id and seed, because the monitoring VM needs both.

2. On the monitoring VM, start the scrape process with the same seed and run id the capture host printed.

   ```bash
   ./.venv/bin/python3 generator/gen.py --profile baseline --role promsvc \
       --seed <seed> --run-id <run_id>
   ```

   This creates a matching `logs/<tag>_logs/` on the monitoring VM holding that host's benign log and manifest.

3. Let both hosts run to the end of the 4 hour window. `baseline` is the one profile that is still timed, so the driver exits on its own at `run_seconds`, stops tcpdump, and finalizes the manifest with event counts. To cut a baseline short, type `exit` into the terminal running `capture/run_capture.sh` (Ctrl-C also works); it finalizes the same way and the manifest records the shorter `elapsed_seconds`.

4. Read the closing summary either way. It lists every expected file with its packet or record count, how long the capture ran, and whether anything is missing or truncated; the script exits non-zero if so.

## Reseeding

- Baseline uses a different seed from `run1` and `run2`. Each process interval sequence is a pure function of `(seed, process_name)`, so reseeding keeps the benign scaffold from becoming a fixed timing fingerprint across the three captures.
- To reproduce an earlier baseline exactly, pin its seed as the third argument.

  ```bash
  sudo ./capture/run_capture.sh baseline ens19 13370
  ```

## Outputs

Under `logs/<tag>_logs/` on each host, where the tag is `R<run_id>-S<seed>`:

- `<tag>.pcap` (capture host only; the whole wire)
- `<tag>_zabbix.pcap` (capture host only; the real Zabbix agent's packets on their own)
- `<tag>_attacker_traffic.pcap` (capture host only; should be **empty** in a baseline)
- `<tag>_knownbenign.json` (scripted benign events plus one record per Zabbix packet)
- `<tag>_knownzabbix.json` (the Zabbix stream on its own, a subset of the benign union)
- `<tag>_alltraffic.json` (union view, distinguished by the `class` field)
- `<tag>.zabbix.meta.json` (the Zabbix filter, addresses, counts, and stop reason)
- `<tag>.attacker.meta.json` (the attacker filter, address, counts, and stop reason)
- `<tag>.<role>.manifest.json` (one per host, with started, ended, and event counts)

A baseline has no `<tag>_knownuser.json` unless a manual action was logged, which should not happen during a clean baseline.

A four hour baseline is the run where the Zabbix stream matters most, since it is the one the models train on. Confirm the closing summary reports a Zabbix packet count in the thousands rather than zero.

**The attacker tap runs on a baseline too, and it should capture nothing.** That is the point: a zero-packet `<tag>_attacker_traffic.pcap` is positive evidence the training data is clean, rather than an assumption that it is. The summary reports the empty stream as a warning, which is expected here. Any non-zero count in a baseline means the operator address was active during the window and the capture is **not** a clean baseline — investigate before training on it.

## Verification checklist

- The manifest reports `expected_buckets` of 960 and a populated `event_counts`.
- Each benign process shows a plausible count for a 4 hour window.
- The Zabbix line in the summary shows a non-zero packet count, and the pcap and log counts match.
- The attacker line in the summary shows **zero** packets. A non-zero count means the baseline is contaminated. `attacker: DISABLED` is a problem and exits non-zero: fix `addresses.attacker_ip` and re-run, since a baseline with no attacker tap cannot be shown to be clean.
- The capture host and the monitoring VM share the same tag, so their records merge cleanly by `run_id` and `seed`.
- Capture the baseline and every run at the same 15 second span, or the count and volume features will not be comparable.

---

A clean baseline keeps the whole warren secure. Ears up, anomalies down. 🐰
