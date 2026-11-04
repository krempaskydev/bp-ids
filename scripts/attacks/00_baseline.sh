#!/usr/bin/env bash
# Faza 0: ciste benigne okno (meranie FP a TN).
#
# Utocnik v tejto faze NEROBI NIC - v sieti bezi iba benigna prevadzka
# kontajnera "client" (scripts/benign/benign_traffic.sh), ktora bezi na
# pozadi pocas celeho experimentu. Kazdy alert v tomto okne je teda false
# positive. evaluate.py okno rozdeli na 10 s sloty: slot s alertom = FP,
# slot bez alertu = TN.
set -e
source /scripts/attacks/lib.sh

BASELINE_SECONDS="${BASELINE_SECONDS:-180}"

log_event "baseline_benign" "start" "none" "172.28.0.10,172.28.0.11" "benign-traffic (client 172.28.0.30)" ""
sleep "$BASELINE_SECONDS"
log_event "baseline_benign" "end"
