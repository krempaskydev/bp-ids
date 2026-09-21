FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    hydra \
    nikto \
    sqlmap \
    curl \
    netcat-traditional \
    iputils-ping \
    dnsutils \
    python3 \
    python3-pip \
    python3-requests \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

CMD ["/bin/bash"]
