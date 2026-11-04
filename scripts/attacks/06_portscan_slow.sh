#!/usr/bin/env bash
# Scenar 6: "Low-and-slow" port scan - evazia casovym rozlozenim utoku
# (kap. 1.4, MITRE TA0043/T1595 + TA0007/T1046).
#
# Skenuje 25 portov (1-25), takze pocet SYN paketov JE nad prahom
# rychleho pravidla sid 9000002 (5 SYN / 5 s) - ak by sa skenovalo bez
# spomalenia, pravidlo by sa spustilo (overuje kontrolny scenar 06a, ktory
# skenuje tie iste porty bez --scan-delay). Evaziu tu teda sposobuje
# VYHRADNE casove rozlozenie, nie maly pocet paketov.
#
# Zaroven sa nepouziva -sV/-A => ziadne NSE/User-Agent stopy pre ET pravidla.
#
#   --scan-delay 3s => max. 2 SYN v lubovolnom 5-sekundovom okne
#   => profil "pred ladenim": ocakavany FALSE NEGATIVE
#   => profil "po ladeni": zachyti ho pravidlo sid 9000003 (pokusy o spojenie
#      na nepouzivane porty, okno 120 s) - pozri rules/tuned/local.rules
set -e
source /scripts/attacks/lib.sh

SCENARIO="portscan_low_and_slow"
log_event "$SCENARIO" "start" "recon_evasion" "172.28.0.10" "nmap --scan-delay 3s" "TA0043/T1595, TA0007/T1046"

nmap -sS -Pn --scan-delay 3s --max-retries 0 -p 1-25 172.28.0.10

log_event "$SCENARIO" "end"
