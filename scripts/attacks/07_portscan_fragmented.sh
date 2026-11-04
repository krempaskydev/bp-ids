#!/usr/bin/env bash
# Scenar 7: Port scan s fragmentaciou paketov - evazia na urovni protokolu
# (kap. 1.4; Ptacek & Newsham 1998, MITRE TA0043/T1595 + TA0007/T1046).
#
# nmap -f rozdeli TCP hlavicku SYN paketu do 8-bajtovych IP fragmentov.
# IDS, ktory fragmenty neskladá, nevidi v ziadnom z nich kompletnu TCP
# hlavicku (flagy, cielovy port) a pravidla na SYN sa nemaju na com spustit.
# Suricata ma defragmentaciu (sekcia "defrag" v suricata.yaml) zapnutu
# standardne - ocakavany vysledok je preto DETEKCIA, co ukazuje, ze
# samotna fragmentacia proti modernemu IDS nestaci. Aj tento vysledok je
# platny vystup evazneho testu (pozri kap. 5.4).
#
# Bez -sV/-A a s rovnakym rozsahom portov ako scenare 6/6a, aby boli
# vysledky porovnatelne.
set -e
source /scripts/attacks/lib.sh

SCENARIO="portscan_fragmented"
log_event "$SCENARIO" "start" "recon_evasion" "172.28.0.10" "nmap -f" "TA0043/T1595, TA0007/T1046"

nmap -sS -Pn -f --max-retries 0 -p 1-25 172.28.0.10

log_event "$SCENARIO" "end"
