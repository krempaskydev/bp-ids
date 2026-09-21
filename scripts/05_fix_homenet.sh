#!/usr/bin/env bash
set -x

CONF=/etc/suricata/suricata.yaml

echo "=== Povodny HOME_NET ==="
sudo grep -n "^  HOME_NET:" "$CONF"

# HOME_NET = len chranene servery (victim + dvwa), utocnik tak spada
# pod EXTERNAL_NET - realisticky model "utocnik zvonka -> server vo vnutri"
sudo sed -i 's|^  HOME_NET:.*|  HOME_NET: "[172.28.0.10,172.28.0.11]"|' "$CONF"

echo "=== Novy HOME_NET ==="
sudo grep -n "^  HOME_NET:" "$CONF"

sudo suricata -T -c "$CONF" -v
sudo systemctl restart suricata
sleep 3
sudo systemctl status suricata --no-pager -l | head -15

# Rozsirenie ACL aj na konfiguracne subory a pravidla, nech ich viem
# nabuduce citat bez opakovanych sudo skriptov
sudo setfacl -R -m u:fonzy:rX /etc/suricata
sudo setfacl -R -m u:fonzy:rX /var/lib/suricata

echo "=== HOTOVO ==="
