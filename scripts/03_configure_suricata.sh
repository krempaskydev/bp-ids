#!/usr/bin/env bash
set -x

CONF=/etc/suricata/suricata.yaml
IFACE=br-idsnet

# 0. Zaloha originalu (len raz)
if [ ! -f "${CONF}.orig" ]; then
    sudo cp "$CONF" "${CONF}.orig"
fi

echo "=== HOME_NET (over ze 172.28.0.0/24 spada pod default rozsah) ==="
sudo grep -n "HOME_NET:" "$CONF" | head -3

echo "=== Povodny af-packet blok (prvych 15 riadkov) ==="
sudo sed -n '/^af-packet:/,+15p' "$CONF"

# 1. Nastavit interface na br-idsnet v prvom (primarnom) af-packet zazname
sudo awk -v iface="$IFACE" '
  /^af-packet:/ {inblock=1}
  inblock && /interface:/ && !done {
    sub(/interface: .*/, "interface: " iface)
    done=1
  }
  {print}
' "$CONF" | sudo tee "${CONF}.new" > /dev/null
sudo mv "${CONF}.new" "$CONF"
sudo chown root:root "$CONF"
sudo chmod 640 "$CONF"
sudo chgrp suricata "$CONF" 2>/dev/null || true

echo "=== Novy af-packet blok ==="
sudo sed -n '/^af-packet:/,+15p' "$CONF"

# 2. /etc/default/suricata - niektore Ubuntu balicky odtial citaju IFACE pre systemd sluzbu
if [ -f /etc/default/suricata ]; then
    echo "=== /etc/default/suricata (pred zmenou) ==="
    sudo cat /etc/default/suricata
    sudo sed -i "s/^IFACE=.*/IFACE=${IFACE}/" /etc/default/suricata || true
    sudo sed -i "s/^LISTENMODE=.*/LISTENMODE=af-packet/" /etc/default/suricata || true
    echo "=== /etc/default/suricata (po zmene) ==="
    sudo cat /etc/default/suricata
fi

# 3. Stiahnut a aktivovat ET-open ruleset
sudo suricata-update

# 4. Otestovat konfiguraciu
sudo suricata -T -c "$CONF" -v

# 5. Povolit a nahodit systemd sluzbu
sudo systemctl enable suricata
sudo systemctl restart suricata
sleep 3
sudo systemctl status suricata --no-pager -l

echo "=== Posledne riadky eve.json ==="
sudo tail -n 5 /var/log/suricata/eve.json 2>&1
