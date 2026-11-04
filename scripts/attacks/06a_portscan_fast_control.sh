#!/usr/bin/env bash
# Scenar 6a: KONTROLNY rychly scan k scenaru 6 (low-and-slow).
#
# Presne tie iste porty a prepinace ako scenar 6, len BEZ --scan-delay.
# Ak je tento scan detekovany a scenar 6 nie, je preukazane, ze evaziu
# sposobilo casove rozlozenie utoku (a nie napr. maly pocet skenovanych
# portov alebo chybajuce -sV/-A).
set -e
source /scripts/attacks/lib.sh

SCENARIO="portscan_fast_control"
log_event "$SCENARIO" "start" "recon_control" "172.28.0.10" "nmap" "TA0043/T1595, TA0007/T1046"

nmap -sS -Pn --max-retries 0 -p 1-25 172.28.0.10

log_event "$SCENARIO" "end"
