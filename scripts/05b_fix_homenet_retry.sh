#!/usr/bin/env bash
set -x

CONF=/etc/suricata/suricata.yaml

echo "=== Povodny HOME_NET ==="
sudo grep -n "HOME_NET:" "$CONF" | head -3

# spravna indentacia (4 medzery) - minule sed nic nenasiel
sudo sed -i 's|^    HOME_NET:.*|    HOME_NET: "[172.28.0.10,172.28.0.11]"|' "$CONF"

echo "=== Novy HOME_NET ==="
sudo grep -n "HOME_NET:" "$CONF" | head -3

sudo suricata -T -c "$CONF" -v
sudo systemctl restart suricata
sleep 3
sudo systemctl status suricata --no-pager -l | head -15
