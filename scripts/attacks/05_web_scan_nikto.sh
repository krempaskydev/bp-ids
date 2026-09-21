#!/usr/bin/env bash
# Scenar 5: Vseobecny sken webovych zranitelnosti (nikto) na DVWA
set -e
source /scripts/attacks/lib.sh

SCENARIO="web_scan_nikto"
log_event "$SCENARIO" "start" "\"attack_category\":\"web\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.11\",\"tool\":\"nikto\""

nikto -h http://172.28.0.11/ || true

log_event "$SCENARIO" "end"
