#!/usr/bin/env bash
# Nezavadna (benigna) prevadzka - pouziva sa na meranie False Positives.
# Vsetko tu su legitimne pozadavky, ktore by IDS NEMAL oznacit ako utok.
#
# Zamerne dlhsi a rozmanitejsi beh (cca 2-3 min) nez povodna 10-sekundova
# verzia - kratky baseline davat len hrstku vzoriek a robi FP-rate
# statisticky nevierohodnym (pripomienka z code review pred odovzdanim BP).
set -e
source /scripts/attacks/lib.sh

SCENARIO="baseline_benign"
log_event "$SCENARIO" "start" "\"attack_category\":\"none\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"benign-traffic\""

DVWA_PAGES=(
    "http://172.28.0.11/"
    "http://172.28.0.11/login.php"
    "http://172.28.0.11/setup.php"
)

# 1. Opakovana bezna navsteva webu (victim aj dvwa), bez akychkolvek
#    utocnych payloadov
for i in $(seq 1 30); do
    curl -s -o /dev/null http://172.28.0.10/
    curl -s -o /dev/null "${DVWA_PAGES[$((i % 3))]}"
    ping -c 1 172.28.0.10 > /dev/null
    sleep 3
done

# 2. Niekolko legitimnych SSH prihlaseni so spravnym heslom a bezmym
#    prikazom (simuluje spravcu/pouzivatela)
for i in $(seq 1 5); do
    sshpass -p 'testpass123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        testuser@172.28.0.10 "uname -a; uptime" 2>/dev/null || true
    sleep 2
done

# 3. Anonymny FTP listing - v nasej topologii je anonymny FTP zamerne
#    povoleny, takze obycajny listing je legitimna prevadzka (na rozdiel
#    od aktivneho zneuzitia/uploadu)
for i in $(seq 1 5); do
    curl -s "ftp://172.28.0.10/" > /dev/null || true
    sleep 2
done

log_event "$SCENARIO" "end"
