#!/usr/bin/env bash
# Oprava rotacie logov (nahradza nefunkcne riesenie zo 07_apply_fixes.sh).
#
# "rotate-interval: day" v suricata.yaml rotuje IBA ak filename obsahuje
# casovy vzor (napr. eve-%Y-%m-%d.json); pri statickom "eve.json" Suricata
# len znovu otvori ten isty subor => subor rastie donekonecna (namerane:
# 1,47 GB od 23.9. do 4.11.2026). Spravne riesenie: logrotate + SIGHUP,
# na ktory Suricata znovu otvori logy.
set -euo pipefail

CONF=/etc/suricata/suricata.yaml

# 1. odstranit nefunkcny riadok
sudo sed -i '/^\s*rotate-interval:\s*day\s*$/d' "$CONF"

# 2. logrotate konfiguracia
sudo tee /etc/logrotate.d/suricata > /dev/null <<'CFG'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        systemctl kill -s HUP suricata.service > /dev/null 2>&1 || true
    endscript
}
CFG

# 3. overenie (suchy beh) a restart
sudo logrotate -d /etc/logrotate.d/suricata 2>&1 | tail -n 5
sudo suricata -T -c "$CONF"
sudo systemctl restart suricata
echo "Hotovo. eve.json teraz: $(du -h /var/log/suricata/eve.json | cut -f1)"
echo "Pozn.: evaluate.py cita eve.json aj nekomprimovany eve.json.1 (delaycompress),"
echo "takze rotacia pocas experimentu nesposobi stratu alertov."
