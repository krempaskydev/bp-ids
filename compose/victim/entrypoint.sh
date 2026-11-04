#!/bin/bash
set -e

service ssh start
service vsftpd start
service apache2 start
dnsmasq --conf-file=/etc/dnsmasq.conf

echo "victim kontajner bezi: SSH(22), HTTP(80), FTP(21, pasv 30000-30010), DNS(53)"
tail -f /var/log/apache2/access.log
