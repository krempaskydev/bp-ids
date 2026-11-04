#!/usr/bin/env bash
# Spusti vsetky testovacie scenare za sebou (v attacker kontajneri) a zaznamena
# presne casy do $RUN_DIR/attack_log.jsonl (ground truth pre evaluate.py).
#
# Benigna prevadzka NIE je sucastou tohto skriptu - bezi paralelne na pozadi
# v kontajneri "client" (spusta ju scripts/run_experiment.sh na hostitelovi).
# Medzi scenarmi je pauza PAUSE sekund, aby sa casove okna jednoznacne
# odlisili (musi byt > GRACE_SECONDS v evaluate.py).
#
# Pouzitie (normalne cez scripts/run_experiment.sh):
#   docker exec -e RUN_DIR=/results/runs/<id> attacker bash /scripts/attacks/run_all.sh
set -e

export RUN_DIR="${RUN_DIR:-/results/runs/manual_$(date -u +%Y%m%dT%H%M%SZ)}"
PAUSE="${PAUSE:-10}"
mkdir -p "$RUN_DIR"
chmod 777 "$RUN_DIR"           # aby evaluate.py na hostitelovi (bez root) mohol zapisovat
: > "$RUN_DIR/attack_log.jsonl"

step() {
    echo "############################################"
    echo "# $1"
    echo "############################################"
    "$2"
    sleep "$PAUSE"
}

step "0.  Baseline (cista benigna prevadzka - FP/TN)"        /scripts/attacks/00_baseline.sh
step "1.  Port scan so zistovanim sluzieb a OS (recon)"     /scripts/attacks/01_portscan.sh
step "6a. Kontrolny rychly scan (k scenaru 6)"              /scripts/attacks/06a_portscan_fast_control.sh
step "6.  Low-and-slow port scan (evazia - cas)"            /scripts/attacks/06_portscan_slow.sh
step "7.  Fragmentovany port scan (evazia - protokol)"      /scripts/attacks/07_portscan_fragmented.sh
step "2.  DoS - SYN flood"                                  /scripts/attacks/02_dos_synflood.sh
step "3.  SSH brute-force"                                  /scripts/attacks/03_ssh_bruteforce.sh
step "4.  Web SQL injection (DVWA)"                         /scripts/attacks/04_web_sqli.sh
step "5.  Web vulnerability scan (nikto)"                   /scripts/attacks/05_web_scan_nikto.sh

echo ""
echo "Vsetky scenare dokoncene. Ground truth: $RUN_DIR/attack_log.jsonl"
