#!/usr/bin/env bash
# Spolocna kniznica pre attack skripty - loguje presne casy zaciatku/konca
# kazdeho utoku (ground truth pre evaluate.py).
#
# Kazdy beh experimentu ma vlastny adresar RUN_DIR (nastavuje run_all.sh,
# resp. scripts/run_experiment.sh), aby sa opakovane behy navzajom neprepisovali.

RUN_DIR="${RUN_DIR:-/results/runs/manual}"
LOGFILE="$RUN_DIR/attack_log.jsonl"
ATTACKER_IP="172.28.0.20"

# log_event <scenar> <start|end> [kategoria] [ciel_ip] [nastroj] [mitre]
log_event() {
    local scenario="$1" phase="$2"
    local category="${3:-}" dst="${4:-}" tool="${5:-}" mitre="${6:-}"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    mkdir -p "$RUN_DIR"
    if [ "$phase" = "start" ]; then
        echo "{\"scenario\":\"$scenario\",\"phase\":\"start\",\"timestamp\":\"$ts\",\"attack_category\":\"$category\",\"src_ip\":\"$ATTACKER_IP\",\"dst_ip\":\"$dst\",\"tool\":\"$tool\",\"mitre\":\"$mitre\"}" >> "$LOGFILE"
    else
        echo "{\"scenario\":\"$scenario\",\"phase\":\"end\",\"timestamp\":\"$ts\"}" >> "$LOGFILE"
    fi
    echo ">>> [$scenario] $phase @ $ts"
}
