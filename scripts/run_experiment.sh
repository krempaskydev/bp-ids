#!/usr/bin/env bash
# Spusti opakovany experiment (kap. 3.6 "opakovatelnost") na HOSTITELOVI:
#   N-krat za rovnakych podmienok: benigna prevadzka na pozadi (client)
#   + vsetky utocne scenare (attacker) -> vyhodnotenie kazdeho behu
#   -> agregacia (priemer, smerodajna odchylka, miera detekcie k/N).
#
# Pouzitie:
#   ./scripts/09_set_profile.sh before   # (sudo) aktivuje profil pravidiel
#   ./scripts/run_experiment.sh before 3
#   ./scripts/09_set_profile.sh after
#   ./scripts/run_experiment.sh after 3
#   -> results/aggregate_before.md, results/aggregate_after.md, results/comparison.md
set -euo pipefail

LABEL="${1:-}"
N="${2:-3}"
[[ "$LABEL" == "before" || "$LABEL" == "after" ]] || { echo "Pouzitie: $0 before|after [pocet_behov]"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACTIVE=$(cat /var/lib/suricata/rules/bp_profile.txt 2>/dev/null || echo "?")
if [ "$ACTIVE" != "$LABEL" ]; then
    echo "CHYBA: aktivny profil Suricaty je '$ACTIVE', nie '$LABEL'. Spusti: ./scripts/09_set_profile.sh $LABEL"
    exit 1
fi
systemctl is-active --quiet suricata || { echo "CHYBA: Suricata nebezi"; exit 1; }

cd "$PROJECT_DIR/compose"
docker compose up -d --build
sleep 10

now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
md5() { md5sum "$1" 2>/dev/null | cut -d' ' -f1 || echo "?"; }

for i in $(seq 1 "$N"); do
    ID="${LABEL}_r${i}_$(date -u +%Y%m%dT%H%M%SZ)"
    RUN="$PROJECT_DIR/results/runs/$ID"
    echo "=================== Beh $i/$N: $ID ==================="

    docker exec client pkill -f benign_traffic.sh 2>/dev/null || true
    BENIGN_START=$(now)
    docker exec -d client bash /scripts/benign/benign_traffic.sh
    sleep 15                                   # benigna prevadzka sa rozbehne

    docker exec -e RUN_DIR="/results/runs/$ID" attacker bash /scripts/attacks/run_all.sh

    sleep 15
    docker exec client pkill -f benign_traffic.sh || true
    BENIGN_END=$(now)
    sleep 10                                   # Suricata dopise eve.json

    cat > "$RUN/meta.json" <<JSON
{
  "profile": "$LABEL",
  "repetition": $i,
  "benign_start": "$BENIGN_START",
  "benign_end": "$BENIGN_END",
  "suricata_version": "$(suricata -V 2>/dev/null | head -1)",
  "local_rules_md5": "$(md5 /var/lib/suricata/rules/local.rules)",
  "et_rules_md5": "$(md5 /var/lib/suricata/rules/suricata.rules)",
  "threshold_config_md5": "$(md5 /etc/suricata/threshold.config)"
}
JSON
    python3 "$PROJECT_DIR/scripts/evaluate.py" --run "$RUN"
    [ "$i" -lt "$N" ] && sleep 30
done

python3 "$PROJECT_DIR/scripts/aggregate.py"
