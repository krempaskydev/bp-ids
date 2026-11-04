#!/usr/bin/env bash
# Benigna (legitimna) prevadzka na pozadi - bezi v kontajneri "client"
# (172.28.0.30) pocas CELEHO experimentu, teda aj pocas utokov.
#
# Simuluje bezneho pouzivatela siete (kap. 3.6):
#   - web:   navstevy stranok na victim aj DVWA (bez utocnych payloadov)
#   - DNS:   preklad mien v lokalnej zone .lab (dnsmasq na victim)
#   - SSH:   obcasne legitimne prihlasenie so spravnym heslom
#   - FTP:   anonymny listing a stiahnutie suboru (prenos suborov)
#   - ICMP:  ping
# Intervaly su nahodne (1-4 s), aby prevadzka nebola strojovo pravidelna.
# Vsetky alerty s IP 172.28.0.30 su v evaluate.py povazovane za false positive.
#
# Ukoncenie: docker exec client pkill -f benign_traffic.sh
VICTIM=172.28.0.10
DVWA=172.28.0.11
PAGES=("http://$VICTIM/" "http://$DVWA/" "http://$DVWA/login.php" "http://www.lab/")
NAMES=(victim.lab dvwa.lab www.lab ftp.lab)
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

i=0
while true; do
    i=$((i + 1))
    name=${NAMES[$((RANDOM % ${#NAMES[@]}))]}
    dig +short @"$VICTIM" "$name" > /dev/null 2>&1 || true

    page=${PAGES[$((RANDOM % ${#PAGES[@]}))]}
    curl -s -o /dev/null -A "$UA" --resolve "www.lab:80:$VICTIM" "$page" || true

    case $((i % 10)) in
        0) sshpass -p 'testpass123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=5 testuser@"$VICTIM" "uptime" > /dev/null 2>&1 || true ;;
        3) curl -s "ftp://$VICTIM/pub/" > /dev/null 2>&1 || true ;;
        6) curl -s -o /dev/null "ftp://$VICTIM/pub/report.bin" || true ;;
        8) ping -c 1 -W 1 "$VICTIM" > /dev/null 2>&1 || true ;;
    esac

    sleep $((1 + RANDOM % 4))
done
