#!/usr/bin/env bash
# Prepne Suricatu medzi profilmi pravidiel pre porovnanie "pred/po ladeni"
# (kap. 5.3):
#   before = rules/local.rules (povodne 2 vlastne pravidla), bez suppress
#   after  = rules/tuned/local.rules (3 pravidla) + rules/tuned/threshold.config
#
# Pouzitie: ./09_set_profile.sh before|after
# ET-open sada (suricata.rules) sa NEMENI - medzi behmi nespustaj
# suricata-update, inak by profily neboli porovnatelne.
set -euo pipefail

PROFILE="${1:-}"
[[ "$PROFILE" == "before" || "$PROFILE" == "after" ]] || { echo "Pouzitie: $0 before|after"; exit 1; }

CONF=/etc/suricata/suricata.yaml
RULES_DIR=/var/lib/suricata/rules
THRESH=/etc/suricata/threshold.config
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$PROFILE" = "before" ]; then
    SRC_RULES="$PROJECT_DIR/rules/local.rules"
    echo "# profil before - ziadne potlacenie" | sudo tee "$THRESH" > /dev/null
else
    SRC_RULES="$PROJECT_DIR/rules/tuned/local.rules"
    sudo cp "$PROJECT_DIR/rules/tuned/threshold.config" "$THRESH"
fi

sudo cp "$SRC_RULES" "$RULES_DIR/local.rules"
sudo chown root:suricata "$RULES_DIR/local.rules" "$THRESH"
sudo chmod 644 "$RULES_DIR/local.rules" "$THRESH"

# zapnut threshold-file v suricata.yaml (standardne je zakomentovany)
if sudo grep -qE '^#\s*threshold-file:' "$CONF"; then
    sudo sed -i -E "s|^#\s*threshold-file:.*|threshold-file: $THRESH|" "$CONF"
fi
sudo grep -n '^threshold-file:' "$CONF"

# znacka aktivneho profilu - kontroluje ju run_experiment.sh
echo "$PROFILE" | sudo tee "$RULES_DIR/bp_profile.txt" > /dev/null
sudo chmod 644 "$RULES_DIR/bp_profile.txt"

sudo suricata -T -c "$CONF"
sudo systemctl restart suricata
sleep 5
systemctl is-active suricata
echo "Aktivny profil: $PROFILE"
