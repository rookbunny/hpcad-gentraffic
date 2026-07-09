# How To Run: Testing (YouTube, SSH Tunnel)

## Purpose

- Verify the full pipeline (generator, logging, tag/manifest creation, mirror capture, manual logging) before committing to a timed baseline or attack run.
- Confirm that manual web browsing egresses from the honeypot and lands on the mirror, so it can be used as cover during `run2`.
- Catch endpoint, interface, and permission problems while they are cheap to fix.

## Preconditions

- `SETUP.sh` has been run on the honeypot capture host and `config.yaml` exists (mode 600).
- The virtual environment is present at `.venv` and dependencies are installed.
- Companion targets are running on their own VMs.
  - Chat: `python3 ws_echo_server.py 0.0.0.0 8765`
  - Healthcheck: `python3 health_server.py 0.0.0.0 8080`
- `node_exporter` is reachable on the honeypot at `:9100`.
- The mirror interface (for example `ens19`) carries the copied honeypot traffic.

## Part A. Generator and logging wiring test

The `selftest` profile runs the `noop` process for 6 seconds. It exercises run id assignment, tag folding, directory creation, the manifest, and the append-only logs without touching real endpoints.

1. Run the short profile end to end, including tcpdump, on the capture host.

   ```bash
   sudo ./run_capture.sh selftest ens19
   ```

2. Confirm the run directory and its contents.

   ```bash
   ls logs/R*-S*_logs/
   ```

   A healthy result contains `<tag>.pcap`, `<tag>_knownbenign.json`, `<tag>_alltraffic.json`, and `<tag>.honeypot.manifest.json`, and `.current_run` at the repository root holds the active tag.

3. Confirm scripted events were written and attributed.

   ```bash
   tail logs/R*-S*_logs/*_knownbenign.json
   ```

   Each record carries `run_id`, `seed`, `role`, and `proc`. If the file is empty or the directory is missing, stop and fix wiring before any real capture.

## Part B. Manual browsing egress test (SSH tunnel to YouTube)

Manual web browsing originates on the honeypot and exits to an external target. Routing an operator browser through an SSH dynamic proxy into the honeypot makes the browsing traffic egress from the honeypot uplink, which the mirror then captures. YouTube provides a sustained, high-volume streaming flow that is easy to spot in the pcap.

1. Open a dynamic SOCKS proxy through the honeypot from the operator workstation.

   ```bash
   ssh -D 1080 -N operator@<honeypot_ip>
   ```

2. Point a browser at the proxy so all requests egress from the honeypot.
   - SOCKS host `127.0.0.1`, port `1080`, SOCKS v5, with remote DNS enabled.

3. Start an ad-hoc capture on the mirror interface for the test window.

   ```bash
   sudo tcpdump -i ens19 -s 0 -w /tmp/browsing_test.pcap -U
   ```

4. Mark the browsing session boundaries in the ground truth. When no capture from `run_capture.sh` is active, pass an explicit test tag so the records land in a known directory rather than `unknown`.

   ```bash
   ./.venv/bin/python3 log_user.py "youtube session start" --source browsing --tag R0000-S00000
   # load and play a video for one to two minutes through the proxied browser
   ./.venv/bin/python3 log_user.py "youtube session stop"  --source browsing --tag R0000-S00000
   ```

5. Stop tcpdump and confirm the streaming flow was mirrored.

   ```bash
   sudo tcpdump -r /tmp/browsing_test.pcap -nn | head
   ```

   The presence of a sustained external TLS flow originating from the honeypot address confirms that operator browsing reaches the mirror and can serve as cover traffic.

## Verification checklist

- Run directory, pcap, logs, and manifest are all created.
- `.current_run` holds the active tag during a `run_capture.sh` capture.
- Companion endpoints respond and produce `ok=true` benign records under a real profile.
- Proxied browsing appears on the mirror as flows sourced from the honeypot.
- Manual browsing records appear in `<tag>_knownuser.json` and `<tag>_alltraffic.json` with `class=user`.

## Cleanup

- Test artifacts under `logs/` are gitignored and safe to delete once the checklist passes.
- Remove throwaway captures such as `/tmp/browsing_test.pcap` before starting real runs.

---

Every good hunt starts with a test burrow. Patch the holes before the fox finds them. 🐰
