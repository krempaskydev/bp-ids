#!/usr/bin/env bash
# Spolocna kniznica pre attack skripty - loguje presne casy zaciatku/konca
# kazdeho utoku do /results/attack_log.jsonl (ground truth pre evaluate.py)

LOGFILE=/results/attack_log.jsonl

log_event() {
    local scenario="$1"
    local phase="$2"   # start|end
    local extra="${3:-}"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    if [ -n "$extra" ]; then
        echo "{\"scenario\":\"$scenario\",\"phase\":\"$phase\",\"timestamp\":\"$ts\",$extra}" >> "$LOGFILE"
    else
        echo "{\"scenario\":\"$scenario\",\"phase\":\"$phase\",\"timestamp\":\"$ts\"}" >> "$LOGFILE"
    fi
    echo ">>> [$scenario] $phase @ $ts"
}
