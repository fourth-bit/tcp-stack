FROM base/cpp:1.0

USER root

RUN apt-get update -y

RUN apt-get install -y \
    net-tools \
    iproute2 \
    iputils-arping \
    iputils-ping \
    nmap \
    valgrind \
    tcpdump \
    ethtool

RUN yes password | passwd

#RUN ( \
#    echo 'LogLevel DEBUG2'; \
#    echo 'PermitRootLogin yes'; \
#    echo 'PasswordAuthentication yes'; \
#    echo 'Subsystem sftp /usr/lib/openssh/sftp-server'; \
#    ) > /etc/ssh/sshd_config_clion \
#    && mkdir /run/sshd

# CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_clion"]