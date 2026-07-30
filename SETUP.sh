#!/usr/bin/env bash
# Generate config.yaml from config.example.yaml by prompting for the values that
# are specific to a given range. The generated config.yaml holds a password and
# internal addresses; it is gitignored and written mode 600. Run this once per
# host before the first capture.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$HERE/config.example.yaml"
OUT="$HERE/config.yaml"

[ -f "$EXAMPLE" ] || { echo "missing config.example.yaml"; exit 1; }
if [ -f "$OUT" ]; then
    read -rp "config.yaml already exists. Overwrite? [y/N] " a
    [[ "$a" =~ ^[Yy]$ ]] || { echo "aborted"; exit 0; }
fi

echo "Enter range-specific values. Press Enter to accept [defaults]."
read -rp "Honeypot IP (node_exporter scrape target): " HP_IP
read -rp "Mail server IP (IMAP + SMTP): " MAIL_IP
read -rp "IMAP port [143]: " IMAP_PORT;   IMAP_PORT=${IMAP_PORT:-143}
read -rp "IMAP username [mgunderson]: " IMAP_USER; IMAP_USER=${IMAP_USER:-mgunderson}
read -rsp "IMAP password: " IMAP_PASS; echo
read -rp "SMTP port [587]: " SMTP_PORT;   SMTP_PORT=${SMTP_PORT:-587}
read -rp "Chat WS server IP: " CHAT_IP
read -rp "Chat WS port [8765]: " CHAT_PORT; CHAT_PORT=${CHAT_PORT:-8765}
read -rp "Healthcheck server IP: " HC_IP
read -rp "Healthcheck port [8080]: " HC_PORT; HC_PORT=${HC_PORT:-8080}
read -rp "node_exporter port [9100]: " NE_PORT; NE_PORT=${NE_PORT:-9100}

# Addresses used to attribute packets, not to generate traffic. No Zabbix
# traffic is simulated: the real zabbix-agent daemon is the only source, and
# these two addresses are what zabbix_log.py filters its packet capture on. The
# attacker address is excluded from that filter, so an operator impersonating
# the Zabbix service account is never labeled as benign telemetry; attacker_log.py
# captures every packet to or from it as its own class instead. That makes the
# attacker address the single most important value here: get it wrong and the
# attack lands in the capture with no label on it.
echo
echo "Zabbix / attacker addresses (packet attribution; no Zabbix is simulated)."
read -rp "Zabbix server IP: " ZBX_SERVER_IP
read -rp "Zabbix agent IP (the honeypot itself) [${HP_IP}]: " ZBX_AGENT_IP
ZBX_AGENT_IP=${ZBX_AGENT_IP:-$HP_IP}
echo "Attacker IP: the address the operator ACTUALLY works from during run1/run2."
echo "  All traffic to/from it is captured and labeled as attacker traffic; it is"
echo "  also excluded from the Zabbix filter. A CIDR is accepted for several hosts."
read -rp "Attacker IP: " ATTACKER_IP
while [ -z "$ATTACKER_IP" ]; do
    echo "  [!] required: without it no run can produce attacker ground truth."
    read -rp "Attacker IP: " ATTACKER_IP
done

# substitution done in Python so passwords with shell/sed metacharacters are safe
IMAP_HOST="$MAIL_IP" SMTP_HOST="$MAIL_IP" IMAP_PORT="$IMAP_PORT" IMAP_USER="$IMAP_USER" \
IMAP_PASS="$IMAP_PASS" SMTP_PORT="$SMTP_PORT" \
CHAT_WS_URL="ws://${CHAT_IP}:${CHAT_PORT}" \
HEALTHCHECK_URL="http://${HC_IP}:${HC_PORT}/health" \
NODE_EXPORTER_URL="http://${HP_IP}:${NE_PORT}/metrics" \
ZABBIX_SERVER_IP="$ZBX_SERVER_IP" ZABBIX_AGENT_IP="$ZBX_AGENT_IP" \
ATTACKER_IP="$ATTACKER_IP" \
python3 - "$EXAMPLE" "$OUT" <<'PY'
import os, sys
example, out = sys.argv[1], sys.argv[2]
tokens = ["IMAP_HOST", "IMAP_PORT", "IMAP_USER", "IMAP_PASS", "SMTP_HOST",
          "SMTP_PORT", "CHAT_WS_URL", "HEALTHCHECK_URL", "NODE_EXPORTER_URL",
          "ZABBIX_SERVER_IP", "ZABBIX_AGENT_IP", "ATTACKER_IP"]
s = open(example).read()
for t in tokens:
    s = s.replace("__%s__" % t, os.environ.get(t, ""))
open(out, "w").write(s)
PY

chmod 600 "$OUT"
echo "[+] wrote $OUT (mode 600). It is gitignored; do not commit it."
