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

- `SETUP.sh` has been run on both the honeypot capture host and the monitoring VM.
- Companion targets and `node_exporter` are reachable (see the testing document).
- A test pass has already confirmed the pipeline wiring.
- The capture is long, so it should run inside `tmux` so it survives an SSH disconnect. For an unattended baseline that also auto-stops at the window end, see the baseline systemd document.

## Steps

1. On the capture host, start the capture. Omitting the seed draws a fresh 5 digit seed. The script prints the run id, the tag, and the seed.

   ```bash
   tmux new -s baseline
   sudo ./run_capture.sh baseline ens19
   ```

   `ens19` is the interface carrying the mirror copy off the honeypot. Record the printed run id and seed, because the monitoring VM needs both.

2. On the monitoring VM, start the scrape process with the same seed and run id the capture host printed.

   ```bash
   ./.venv/bin/python3 gen.py --profile baseline --role promsvc \
       --seed <seed> --run-id <run_id>
   ```

   This creates a matching `logs/<tag>_logs/` on the monitoring VM holding that host's benign log and manifest.

3. Let both hosts run to the end of the 4 hour window. The driver exits on its own at `run_seconds`, stops tcpdump, and finalizes the manifest with event counts.

## Reseeding

- Baseline uses a different seed from `run1` and `run2`. Each process interval sequence is a pure function of `(seed, process_name)`, so reseeding keeps the benign scaffold from becoming a fixed timing fingerprint across the three captures.
- To reproduce an earlier baseline exactly, pin its seed as the third argument.

  ```bash
  sudo ./run_capture.sh baseline ens19 13370
  ```

## Outputs

Under `logs/<tag>_logs/` on each host, where the tag is `R<run_id>-S<seed>`:

- `<tag>.pcap` (capture host only)
- `<tag>_knownbenign.json` (scripted benign events)
- `<tag>_alltraffic.json` (union view, distinguished by the `class` field)
- `<tag>.<role>.manifest.json` (one per host, with started, ended, and event counts)

A baseline has no `<tag>_knownuser.json` unless a manual action was logged, which should not happen during a clean baseline.

## Verification checklist

- The manifest reports `expected_buckets` of 960 and a populated `event_counts`.
- Each benign process shows a plausible count for a 4 hour window.
- The capture host and the monitoring VM share the same tag, so their records merge cleanly by `run_id` and `seed`.
- Capture the baseline and every run at the same 15 second span, or the count and volume features will not be comparable.

---

A clean baseline keeps the whole warren secure. Ears up, anomalies down. 🐰
