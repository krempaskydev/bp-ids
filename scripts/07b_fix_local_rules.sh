#!/usr/bin/env bash
set -x
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sudo cp "$PROJECT_DIR/rules/local.rules" /var/lib/suricata/rules/local.rules
sudo chown root:suricata /var/lib/suricata/rules/local.rules
sudo chmod 640 /var/lib/suricata/rules/local.rules

sudo suricata -T -c /etc/suricata/suricata.yaml -v

sudo systemctl restart suricata
sleep 3
sudo systemctl status suricata --no-pager -l | head -15
