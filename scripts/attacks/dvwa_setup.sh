#!/usr/bin/env bash
# Pomocny skript (nie samostatny testovaci scenar): prihlasi sa do DVWA,
# nastavi security level na "low" a inicializuje databazu.
# Musi bezat pred kazdym web utokom (SQLi a pod.), kedze session cookie
# ma obmedzenu platnost.
set -e
BASE="http://172.28.0.11"
COOKIEJAR="/results/dvwa_cookies.txt"
rm -f "$COOKIEJAR"

TOKEN=$(curl -s -c "$COOKIEJAR" "$BASE/login.php" | grep -oP "user_token' value='\K[a-f0-9]+")
curl -s -b "$COOKIEJAR" -c "$COOKIEJAR" \
    -d "username=admin&password=password&Login=Login&user_token=$TOKEN" \
    "$BASE/login.php" -o /dev/null

curl -s -b "$COOKIEJAR" -c "$COOKIEJAR" \
    -d "security=low&seclev_submit=Submit" \
    "$BASE/security.php" -o /dev/null

TOKEN2=$(curl -s -b "$COOKIEJAR" -c "$COOKIEJAR" "$BASE/setup.php" | grep -oP "user_token' value='\K[a-f0-9]+" || echo "$TOKEN")
curl -s -b "$COOKIEJAR" -c "$COOKIEJAR" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$TOKEN2" \
    "$BASE/setup.php" -o /dev/null

echo "DVWA pripravene: admin/password, security=low, DB inicializovana. Cookies v $COOKIEJAR"
