#!/usr/bin/env bash
# Spusti vsetky testovacie scenare za sebou (v attacker kontajneri) a zaznamena
# presne casy do /results/attack_log.jsonl. Medzi scenarmi je pauza, aby sa
# dali casove okna v eve.json jednoznacne odlisit.
set -e

mkdir -p /results
: > /results/attack_log.jsonl

echo "############################################"
echo "# 0. Baseline (benigna prevadzka - meria FP)"
echo "############################################"
/scripts/attacks/00_baseline.sh
sleep 5

echo "############################################"
echo "# 1. Port scan (recon)"
echo "############################################"
/scripts/attacks/01_portscan.sh
sleep 5

echo "############################################"
echo "# 1b. Low-and-slow port scan (ocakavane NEDETEKOVANE - FN scenar)"
echo "############################################"
/scripts/attacks/06_portscan_slow.sh
sleep 5

echo "############################################"
echo "# 2. DoS - SYN flood"
echo "############################################"
/scripts/attacks/02_dos_synflood.sh
sleep 5

echo "############################################"
echo "# 3. SSH brute-force"
echo "############################################"
/scripts/attacks/03_ssh_bruteforce.sh
sleep 5

echo "############################################"
echo "# 4. Web SQL injection (DVWA)"
echo "############################################"
/scripts/attacks/04_web_sqli.sh
sleep 5

echo "############################################"
echo "# 5. Web vulnerability scan (nikto)"
echo "############################################"
/scripts/attacks/05_web_scan_nikto.sh

echo ""
echo "Vsetky scenare dokoncene."
echo "Ground-truth log: /results/attack_log.jsonl"
echo "Teraz na HOSTITELI spusti: python3 ~/Documents/bp-ids/scripts/evaluate.py"
