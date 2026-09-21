#!/usr/bin/env bash
# Nezavadna (benigna) prevadzka - pouziva sa na meranie False Positives.
# Vsetko tu su legitimne pozadavky, ktore by IDS NEMAL oznacit ako utok.
set -e
source /scripts/attacks/lib.sh

SCENARIO="baseline_benign"
log_event "$SCENARIO" "start" "\"attack_category\":\"none\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"benign-traffic\""

for i in $(seq 1 10); do
    curl -s -o /dev/null http://172.28.0.10/
    ping -c 1 172.28.0.10 > /dev/null
    sleep 1
done

# legitimne SSH prihlasenie so spravnym heslom
sshpass -p 'testpass123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@172.28.0.10 "echo ok" 2>/dev/null || true

log_event "$SCENARIO" "end"
