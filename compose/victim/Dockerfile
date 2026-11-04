FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    vsftpd \
    dnsmasq \
    net-tools \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# SSH setup - povolene heslove prihlasenie (zamerne slabe pre testovanie brute-force detekcie)
RUN mkdir -p /var/run/sshd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && useradd -m -s /bin/bash testuser \
    && echo "testuser:testpass123" | chpasswd

# Jednoduchy web obsah
RUN echo "<h1>Victim web server - BP IDS testbed</h1>" > /var/www/html/index.html

# vsftpd - povoleny ANONYMNY FTP pristup (zamerne slaba konfiguracia pre testovanie)
# Pasivny rezim ma pevny rozsah datovych portov 30000-30010: vdaka tomu ma
# victim presne definovanu mnozinu sluzieb (21, 22, 53, 80, 30000-30010),
# na ktoru sa odvolava vlastne pravidlo sid 9000003 (pokusy o spojenie na
# nepouzivane porty).
RUN sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf \
    && echo "write_enable=YES" >> /etc/vsftpd.conf \
    && echo "pasv_enable=YES" >> /etc/vsftpd.conf \
    && echo "pasv_min_port=30000" >> /etc/vsftpd.conf \
    && echo "pasv_max_port=30010" >> /etc/vsftpd.conf \
    && mkdir -p /srv/ftp/pub \
    && head -c 512000 /dev/urandom > /srv/ftp/pub/report.bin \
    && echo "Testovaci subor pre benignu FTP prevadzku" > /srv/ftp/pub/readme.txt

# DNS server (dnsmasq) - lokalna zona .lab pre benignu DNS prevadzku
COPY dnsmasq.conf /etc/dnsmasq.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 22 53/udp 53/tcp 80 30000-30010

CMD ["/entrypoint.sh"]
