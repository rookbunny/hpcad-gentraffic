# mirror-persistence

Reboot-persistent setup for a `tc`-based traffic mirror (SPAN port) that copies
all traffic from a live interface to a dedicated capture link, plus the matching
passive-capture configuration on the monitor side.

## What this solves

The pieces that make a `tc` mirror work are **runtime-only kernel state** and are
wiped on every reboot:

- `tc` qdiscs and `mirred` filters (the mirror itself)
- promiscuous mode on the capture interface
- disabled NIC offloads (GRO / GSO / TSO / LRO)

Configure them by hand once and the mirror silently disappears the next time a
VM reboots. This directory wraps each side in a small idempotent script and a
`systemd` one-shot unit (`Type=oneshot`, `RemainAfterExit=yes`) so the state is
re-applied automatically at boot and survives reboots.

## Honeypot vs. monitor split

There are two roles, installed independently:

- **honeypot** — the machine whose traffic you want to observe. It runs a `tc`
  `mirred` SPAN port that copies both ingress and egress packets from the live
  interface (`SRC_IF`) out of a dedicated mirror-out interface (`DST_IF`).
  Nothing is captured here; it only forwards copies out the mirror link.
- **monitor** — a separate VM connected to the mirror link. It brings its
  capture interface (`CAP_IF`) up, puts it in promiscuous mode, and disables
  offloads so tooling (tcpdump, an IDS, etc.) sees true on-wire framing.

The honeypot's `DST_IF` and the monitor's `CAP_IF` are the two ends of the same
dedicated mirror link.

## Files

| File | Role |
|------|------|
| `honeypot-mirror.sh` | Sets up the `tc` mirred SPAN port (`SRC_IF` -> `DST_IF`). |
| `monitor-capture.sh` | Brings up the capture interface (`CAP_IF`): up, promisc, offloads off. |
| `honeypot-mirror.service` | One-shot unit that runs `honeypot-mirror.sh` at boot. |
| `monitor-capture.service` | One-shot unit that runs `monitor-capture.sh` at boot. |
| `install.sh` | Installs one side (`honeypot` or `monitor`) and enables the unit. |

## Install

Run the installer as root on each machine, choosing the appropriate role.

On the honeypot:

```bash
sudo ./install.sh honeypot
```

On the monitor VM:

```bash
sudo ./install.sh monitor
```

`install.sh` will:

1. Copy the matching script to `/usr/local/sbin/` (mode `755`).
2. Install the matching unit to `/etc/systemd/system/`.
3. Create `/etc/mirror-persistence/` and seed a commented example env file
   (it will **not** overwrite an existing one).
4. Run `systemctl daemon-reload`, then `enable --now` the unit.
5. Print `systemctl status` and a verification reminder.

## Overriding interfaces

The scripts default to placeholder interface names (`ens18`, `ens19`). Override
them per host via the optional env files — the units load them with
`EnvironmentFile=-...`, so they are optional and the scripts fall back to their
built-in defaults when a value is absent.

Honeypot — `/etc/mirror-persistence/honeypot.env`:

```ini
# The live interface being mirrored
SRC_IF=ens18
# The dedicated mirror-out interface
DST_IF=ens19
```

Monitor — `/etc/mirror-persistence/monitor.env`:

```ini
# The passive capture interface
CAP_IF=ens19
```

After editing an env file, re-apply it:

```bash
sudo systemctl restart honeypot-mirror.service   # or monitor-capture.service
```

Both scripts are idempotent: `honeypot-mirror.sh` deletes any existing qdiscs
before adding new ones, so a restart cleanly reprograms the mirror.

## Verify

On the honeypot, confirm the mirror filters are installed (output should be
**non-empty**):

```bash
tc filter show dev <SRC_IF> ingress
tc filter show dev <SRC_IF> root
```

On the monitor VM, confirm mirrored frames are actually arriving on the capture
interface:

```bash
tcpdump -ni <CAP_IF> -c 20
```

Replace `<SRC_IF>` / `<CAP_IF>` with the interface names configured for your
hosts. A steady stream of packets on the monitor's `tcpdump` while the honeypot
sees live traffic confirms the mirror is working end to end.
