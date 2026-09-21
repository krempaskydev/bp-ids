#!/usr/bin/env bash
# Scenar 1: Prieskum siete (reconnaissance) - SYN stealth scan + detekcia sluzieb/OS
set -e
source /scripts/attacks/lib.sh

SCENARIO="portscan"
log_event "$SCENARIO" "start" "\"attack_category\":\"recon\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"nmap\""

nmap -sS -T4 -p- 172.28.0.10
nmap -sV -A -p 21,22,80 172.28.0.10

log_event "$SCENARIO" "end"
