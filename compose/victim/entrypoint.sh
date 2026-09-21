#!/bin/bash
set -e

service ssh start
service vsftpd start
service apache2 start

echo "victim kontajner bezi: SSH(22), HTTP(80), FTP(21)"
tail -f /var/log/apache2/access.log
