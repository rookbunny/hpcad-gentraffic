# How To Run: Testing (YouTube, SSH Tunnel)

## Purpose

- Verify the full pipeline (generator, logging, tag/manifest creation, mirror capture, manual logging) before committing to a timed baseline or attack run.
- Confirm that manual web browsing egresses from the honeypot and lands on the mirror, so it can be used as cover during `run2`.
- Catch endpoint, interface, and permission problems while they are cheap to fix.

## Preconditions

- `config/SETUP.sh` has been run on the honeypot capture host and `config/config.yaml` exists (mode 600).
- The virtual environment is present at `.venv` and dependencies are installed.
- Companion targets are running on their own VMs.
  - Chat: `python3 companions/ws_echo_server.py 0.0.0.0 8765`
  - Healthcheck: `python3 companions/health_server.py 0.0.0.0 8080`
- `node_exporter` is reachable on the honeypot at `:9100`.
- The mirror interface (for example `ens19`) carries the copied honeypot traffic.
- The real `zabbix-agent` daemon is running on the honeypot. No Zabbix traffic is generated, so this daemon is the only source of that stream.

## Part A. Generator and logging wiring test

The `selftest` profile runs the `noop` process, which touches no real endpoint. It exercises run id assignment, tag folding, directory creation, the manifest, the append-only logs, and the stop-and-verify path. It has no timer, so it also proves out the way the real runs are stopped.

1. Run the profile end to end, including tcpdump, on the capture host.

   ```bash
   sudo ./capture/run_capture.sh selftest ens19
   ```

2. Let it run for half a minute or so, then stop it by typing `exit` and pressing Enter (Ctrl-C also works).

   ```bash
   exit
   ```

   The closing summary is the thing being tested here. It should list `<tag>.pcap`, `<tag>_knownbenign.json`, `<tag>_alltraffic.json`, and `<tag>.honeypot.manifest.json`, each `OK` with a non-zero count, report roughly the elapsed time you let it run, and end with `all expected files were written successfully`. If it names a `MISSING`, `EMPTY`, or `PARTIAL` file instead, fix that before any real capture: the same check runs at the end of every run.

   The summary also reports the Zabbix capture: the BPF filter it used, and how many packets landed in `<tag>_zabbix.pcap` and in the logs. A half-minute selftest may legitimately catch no Zabbix packets, which is reported as a warning rather than a failure. What must not appear is `zabbix: DISABLED` — that means `config/config.yaml` has no Zabbix addresses, so re-run `config/SETUP.sh` before a real capture.

   It reports the attacker capture the same way, and here `attacker: DISABLED` is a **problem** rather than a warning, so the summary ends non-zero. Attacker ground truth is expected in every run, so a missing or malformed `addresses.attacker_ip` has to be fixed with `config/SETUP.sh` before any real capture. Zero attacker packets during a selftest is fine and expected.

## Part A2. Zabbix capture wiring test

Zabbix traffic is real, not generated, so it is worth confirming separately that the agent is talking and that its conversation reaches the mirror.

1. Confirm the agent daemon is up on the honeypot.

   ```bash
   systemctl status zabbix-agent
   ```

2. Print the filter the logger will use, straight from `config/config.yaml`. It should name the Zabbix server and agent addresses and exclude the attacker address.

   ```bash
   ./.venv/bin/python3 groundtruth/zabbix_log.py --print-filter --iface ens19 \
       --run-dir /tmp --tag R0000-S00000
   ```

3. Watch that filter on the mirror for a couple of the agent's intervals. Traffic in both directions on `:10050` (or `:10051` for active checks) means the stream is there to be captured.

   ```bash
   sudo tcpdump -i ens19 -nn "$(./.venv/bin/python3 groundtruth/zabbix_log.py --print-filter \
       --iface ens19 --run-dir /tmp --tag R0000-S00000)"
   ```

   Nothing at all here means either the agent is idle, the server is not polling it, or the mirror is not carrying the Zabbix conversation. Fix that before a real capture: the run would otherwise produce an empty Zabbix stream.

## Part A3. Attacker capture wiring test

Every packet to or from the attacker address is labeled as attacker traffic, so this filter has to be right before `run1` or `run2`. Getting it wrong does not fail loudly during the run — it silently produces an unlabeled attack.

1. Print the filter the logger will use. It must name the address you will actually attack from.

   ```bash
   ./.venv/bin/python3 groundtruth/attacker_log.py --print-filter --iface ens19 \
       --run-dir /tmp --tag R0000-S00000
   ```

   A `# disabled:` line instead of a filter means `addresses.attacker_ip` is unset or malformed. Re-run `config/SETUP.sh`.

2. Generate one packet from the attacker host and confirm the mirror carries it. Anything works — a single SSH connection attempt, or one ping.

   ```bash
   sudo tcpdump -i ens19 -nn "$(./.venv/bin/python3 groundtruth/attacker_log.py --print-filter \
       --iface ens19 --run-dir /tmp --tag R0000-S00000)"
   ```

   Silence while the attacker host is actively sending means the mirror is not carrying that conversation, or the configured address is not the one in use. Either way the run would produce an empty attacker stream and an unlabeled attack.

3. Confirm the run directory and the run pointer.

   ```bash
   ls logs/R*-S*_logs/
   cat .current_run
   ```

   `.current_run` at the repository root holds the active tag, which is what `groundtruth/log_user.py` picks up.

4. Confirm scripted events were written and attributed.

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

4. Mark the browsing session boundaries in the ground truth. When no capture from `capture/run_capture.sh` is active, pass an explicit test tag so the records land in a known directory rather than `unknown`.

   ```bash
   ./.venv/bin/python3 groundtruth/log_user.py "youtube session start" --source browsing --tag R0000-S00000
   # load and play a video for one to two minutes through the proxied browser
   ./.venv/bin/python3 groundtruth/log_user.py "youtube session stop"  --source browsing --tag R0000-S00000
   ```

5. Stop tcpdump and confirm the streaming flow was mirrored.

   ```bash
   sudo tcpdump -r /tmp/browsing_test.pcap -nn | head
   ```

   The presence of a sustained external TLS flow originating from the honeypot address confirms that operator browsing reaches the mirror and can serve as cover traffic.

## Verification checklist

- Run directory, pcap, logs, and manifest are all created.
- Typing `exit` stops the capture, and the closing summary ends with `all expected files were written successfully`.
- `.current_run` holds the active tag during a `capture/run_capture.sh` capture.
- Companion endpoints respond and produce `ok=true` benign records under a real profile.
- Proxied browsing appears on the mirror as flows sourced from the honeypot.
- Manual browsing records appear in `<tag>_knownuser.json` and `<tag>_alltraffic.json` with `class=user`.
- The summary reports the Zabbix capture as enabled, with a filter naming the configured addresses. Real Zabbix packets are visible on the mirror under that filter.
- The summary reports the attacker capture as enabled, with a filter naming the address the operator will actually work from, and a packet from that host is visible on the mirror under that filter.

## Cleanup

- Test artifacts under `logs/` are gitignored and safe to delete once the checklist passes.
- Remove throwaway captures such as `/tmp/browsing_test.pcap` before starting real runs.

---

Every good hunt starts with a test burrow. Patch the holes before the fox finds them. 🐰
