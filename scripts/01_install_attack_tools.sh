#!/usr/bin/env bash
set -x
sudo apt-get update
sudo apt-get install -y nmap hping3 hydra nikto
echo "=== overenie ==="
for t in nmap hping3 hydra nikto; do
    which "$t" >/dev/null 2>&1 && echo "$t: OK" || echo "$t: CHYBA"
done
