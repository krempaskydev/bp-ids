#!/usr/bin/env bash
set -x

# 1. Rucne vytvorit chybajuci runtime adresar
sudo mkdir -p /var/run/suricata

# 2. Dokoncit prerusenu konfiguraciu balika
sudo dpkg --configure -a

# 3. Doriesit prip. zavislosti
sudo apt-get -f install -y

# 4. Trvale riesenie: pridat systemd-tmpfiles pravidlo, aby sa adresar
#    znovu vytvoril po kazdom restarte (kedze /var/run je tmpfs)
echo "d /var/run/suricata 0750 suricata suricata -" | sudo tee /etc/tmpfiles.d/suricata.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/suricata.conf

# 5. Overenie
dpkg -l suricata | grep suricata
suricata -V
