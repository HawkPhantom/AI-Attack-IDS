# Faz 1 smoke ortami: gercek SSH kabugu + DTU loglarindan cikarilan aldatma profilleri.
# Tek imaj; PROFILE env'ine gore MOTD banner'i ve /root yem dizinleri kurulur.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo net-tools iproute2 procps vim-tiny less \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && printf '\n# hush default motd\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
