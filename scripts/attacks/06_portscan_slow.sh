#!/usr/bin/env bash
# Scenar 6: "Low-and-slow" port scan - zamerne navrhnuty tak, aby unikol
# DVOM detekcnym vrstvam naraz (nie len jednej - podla metrics.csv je bezny
# rychly portscan detekovany predovsetkym cez ET SCAN Nmap Scripting Engine
# User-Agent Detected, teda cez NSE/-sV/-A stopy, nie primarne cez nase
# prahove pravidlo):
#   1. Ziadne -sV/-A => ziadne NSE/User-Agent stopy => ET signatura
#      zalozena na User-Agente sa nema na com spustit.
#   2. --scan-delay 3s => nase vlastne prahove pravidlo LOCAL POLICY
#      Possible fast TCP port scan (5 SYN / 5s, viz rules/local.rules)
#      tento prah nikdy nedosiahne.
# Az kombinacia oboch technik naraz vedie k realnemu unikanu detekcii.
#
# OCAKAVANY VYSLEDOK: 0 alertov (False Negative) - toto je zamerne a je to
# hlavny bod diskusie v kap. 5 (limity signature-based pristupu).
set -e
source /scripts/attacks/lib.sh

SCENARIO="portscan_low_and_slow"
log_event "$SCENARIO" "start" "\"attack_category\":\"recon_evasion\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.10\",\"tool\":\"nmap\""

# --scan-delay 3s: medzi paketmi je 3s pauza => v ziadnom 5-sekundovom okne
# nevznikne 5 SYN paketov potrebnych na spustenie prahoveho pravidla.
# Ziadne -sV/-A: ziadne NSE/User-Agent stopy, ktore by zachytili ET pravidla.
nmap -sS -Pn --scan-delay 3s -T2 -p 21,22,80 172.28.0.10

log_event "$SCENARIO" "end"
