#!/usr/bin/env bash
set -x

CONF=/etc/suricata/suricata.yaml
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== 1. Nainstalovat vlastne pravidla (local.rules) ==="
sudo cp "$PROJECT_DIR/rules/local.rules" /var/lib/suricata/rules/local.rules
sudo chown root:suricata /var/lib/suricata/rules/local.rules
sudo chmod 640 /var/lib/suricata/rules/local.rules

# pridat local.rules do rule-files (ak tam este nie je)
if ! sudo grep -q "local.rules" "$CONF"; then
    sudo sed -i '/^rule-files:/a\  - local.rules' "$CONF"
fi

echo "=== Over rule-files ==="
sudo grep -n "rule-files:" -A3 "$CONF"

echo "=== 2. Log rotation pre eve.json (rotate-interval: day) ==="
if ! sudo grep -q "rotate-interval" "$CONF"; then
    sudo awk '
      /- eve-log:/ {print; getline; print; print "      rotate-interval: day"; next}
      {print}
    ' "$CONF" | sudo tee "${CONF}.new" > /dev/null
    sudo mv "${CONF}.new" "$CONF"
fi

echo "=== Over eve-log blok ==="
sudo sed -n '/- eve-log:/,+5p' "$CONF"

echo "=== 3. Otestovat konfiguraciu ==="
sudo suricata -T -c "$CONF" -v

echo "=== 4. Zastavit Suricatu, vycistit stare logy (4.3GB z neprerusenej prevadzky), restart s cistym logom ==="
sudo systemctl stop suricata
sudo truncate -s 0 /var/log/suricata/eve.json
sudo truncate -s 0 /var/log/suricata/fast.log
sudo truncate -s 0 /var/log/suricata/stats.log
sudo systemctl start suricata
sleep 3
sudo systemctl status suricata --no-pager -l | head -15

echo "=== 5. Restart evebox (nech cita od zaciatku cisteho logu) ==="
cd "$PROJECT_DIR/compose" && docker compose restart evebox

echo "=== HOTOVO ==="
echo "eve.json velkost teraz:"
sudo du -h /var/log/suricata/eve.json
