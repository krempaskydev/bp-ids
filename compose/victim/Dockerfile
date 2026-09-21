FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    vsftpd \
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

# vsftpd - povolit lokalny FTP login (zamerne slaba konfiguracia pre testovanie)
RUN sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf \
    && echo "write_enable=YES" >> /etc/vsftpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 21

CMD ["/entrypoint.sh"]
