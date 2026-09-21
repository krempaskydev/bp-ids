#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Update systemu ==="
sudo apt-get update

echo "=== 2. Zakladne zavislosti ==="
sudo apt-get install -y ca-certificates curl gnupg lsb-release python3-pip python3-venv git jq

echo "=== 3. Docker install (oficialny repo) ==="
sudo install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "=== 4. Pridanie usera do docker group (aby nebolo treba sudo pre docker) ==="
sudo usermod -aG docker "$USER"

echo "=== 5. Suricata install ==="
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata suricata-update

echo "=== 6. Utocnicke/testovacie nastroje na hostitela (pre pripadne pomocne testy) ==="
sudo apt-get install -y nmap hping3 hydra nikto

echo "=== HOTOVO ==="
echo "DOLEZITE: odhlas sa a znova prihlas (alebo restartni PC), aby sa prejavilo pridanie do 'docker' group."
docker --version || true
suricata --version || true
