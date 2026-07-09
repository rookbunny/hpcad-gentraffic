# How To Run: Baseline With System Service

## Purpose

- Run the baseline generator unattended so it survives an SSH disconnect and auto-stops at the window end.
- Suited to the 4 hour baseline, which is too long to babysit at the terminal.

## What the service does and does not do

- The unit is a template. The instance name after `@` is passed straight through to the generator as the profile via `%i`. Starting `Honeypot_gentraffic@baseline` runs the `baseline` profile.
- The unit runs the generator only. It does not start tcpdump, so it does not produce a pcap on its own.
- `RuntimeMaxSec` is set to 5 hours as a hard backstop. The driver already exits at `run_seconds`, so the backstop only matters if the driver hangs.
- `Restart=no`, so the run does not relaunch after the window ends.

## Preconditions

- The repository is deployed at `/opt/gunderson`. If it lives elsewhere, adjust the two paths inside the unit file before installing.
- `config.yaml`, the `.venv`, and reachable endpoints are all in place on the honeypot.

## Install the unit

1. Copy the template into the systemd unit directory and reload.

   ```bash
   sudo cp Honeypot_gentraffic@.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

## Optional. Pin a seed

- Without an env file, the generator selects a random 5 digit seed and records it in the manifest.
- To pin a reproducible seed, write it into the optional env file before starting. The unit reads it through `EnvironmentFile=-/opt/gunderson/run.env`.

  ```bash
  echo 'SEED_ARG=--seed 13370' | sudo tee /opt/gunderson/run.env
  ```

- Remove `run.env` to return to random seeding on the next start. Reseed per capture so the benign scaffold is not a fixed fingerprint across the three captures.

## Start and follow

1. Start the baseline instance and follow its journal.

   ```bash
   sudo systemctl start Honeypot_gentraffic@baseline    # %i -> baseline
   journalctl -u Honeypot_gentraffic@baseline -f
   ```

2. The generator writes its `logs/<tag>_logs/` directory, prints the run id and tag, and exits on its own at the 4 hour mark.

## Capturing a pcap alongside the service

The service does not capture packets. To obtain a baseline pcap that survives a disconnect, start the capture separately inside `tmux` instead of relying on the service.

```bash
tmux new -s baseline
sudo ./run_capture.sh baseline ens19
```

Running both the service and `run_capture.sh` at once would start the generator twice. Choose one path. Use the service when only the generator and its logs are needed, and use `run_capture.sh` when a pcap is required.

## Monitoring VM

The service covers the honeypot only. The monitoring VM still runs its scrape process manually with the same seed and run id.

```bash
./.venv/bin/python3 gen.py --profile baseline --role promsvc \
    --seed <seed> --run-id <run_id>
```

## Verification checklist

- `journalctl` shows the generator started, printed a tag, and exited cleanly near the 4 hour mark.
- The manifest under `logs/<tag>_logs/` reports `expected_buckets` of 960 and populated `event_counts`.
- If a pcap is needed, it was produced by `run_capture.sh`, not by the service.

---

Set it, forget it, and let the service stand guard over the warren all night. Hoppy hunting. 🐰
