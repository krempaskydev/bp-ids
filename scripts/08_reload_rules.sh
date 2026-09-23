#!/usr/bin/env bash
set -x
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sudo cp "$PROJECT_DIR/rules/local.rules" /var/lib/suricata/rules/local.rules
sudo chown root:suricata /var/lib/suricata/rules/local.rules
sudo chmod 640 /var/lib/suricata/rules/local.rules

sudo suricata -T -c /etc/suricata/suricata.yaml -v

# cisty log pred dalsim (uz naozaj finalnym) behom
sudo systemctl stop suricata
sudo truncate -s 0 /var/log/suricata/eve.json
sudo systemctl start suricata
sleep 3
sudo systemctl status suricata --no-pager -l | head -10
