#!/usr/bin/env bash
set -x

sudo apt-get install -y acl

# Umoznit pouzivatelovi fonzy citat logy Suricaty bez sudo (aj po rotacii/restartoch)
sudo setfacl -R -m u:fonzy:rX /var/log/suricata
sudo setfacl -R -d -m u:fonzy:rX /var/log/suricata

echo "=== over ==="
sudo -u fonzy tail -n 5 /var/log/suricata/eve.json 2>&1 || echo "FAIL - skus znova precitat po dalsom pokuse"
