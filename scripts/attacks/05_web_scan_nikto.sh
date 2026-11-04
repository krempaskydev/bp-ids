#!/usr/bin/env bash
# Scenar 5: Vseobecny sken webovych zranitelnosti (nikto) na DVWA
set -e
source /scripts/attacks/lib.sh

SCENARIO="web_scan_nikto"
log_event "$SCENARIO" "start" "recon" "172.28.0.11" "nikto" "TA0043/T1595.002"

nikto -h http://172.28.0.11/ || true

log_event "$SCENARIO" "end"
