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
read -rp "Zabbix server IP (blank if using the real agent daemon) []: " ZBX_IP; ZBX_IP=${ZBX_IP:-}
read -rp "Zabbix host name [honeypot-hpc-01]: " ZBX_HOST; ZBX_HOST=${ZBX_HOST:-honeypot-hpc-01}

# substitution done in Python so passwords with shell/sed metacharacters are safe
IMAP_HOST="$MAIL_IP" SMTP_HOST="$MAIL_IP" IMAP_PORT="$IMAP_PORT" IMAP_USER="$IMAP_USER" \
IMAP_PASS="$IMAP_PASS" SMTP_PORT="$SMTP_PORT" \
CHAT_WS_URL="ws://${CHAT_IP}:${CHAT_PORT}" \
HEALTHCHECK_URL="http://${HC_IP}:${HC_PORT}/health" \
NODE_EXPORTER_URL="http://${HP_IP}:${NE_PORT}/metrics" \
ZABBIX_SERVER="$ZBX_IP" ZABBIX_HOST="$ZBX_HOST" \
python3 - "$EXAMPLE" "$OUT" <<'PY'
import os, sys
example, out = sys.argv[1], sys.argv[2]
tokens = ["IMAP_HOST", "IMAP_PORT", "IMAP_USER", "IMAP_PASS", "SMTP_HOST",
          "SMTP_PORT", "CHAT_WS_URL", "HEALTHCHECK_URL", "NODE_EXPORTER_URL",
          "ZABBIX_SERVER", "ZABBIX_HOST"]
s = open(example).read()
for t in tokens:
    s = s.replace("__%s__" % t, os.environ.get(t, ""))
open(out, "w").write(s)
PY

chmod 600 "$OUT"
echo "[+] wrote $OUT (mode 600). It is gitignored; do not commit it."
