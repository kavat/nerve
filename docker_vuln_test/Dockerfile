FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

COPY start.sh /opt/start.sh

RUN apt-get update && apt-get install -y iptables iproute2 openssh-server apache2
RUN mkdir /run/sshd
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN ssh-keygen -A
RUN echo "root:TestMe_2022" | chpasswd

RUN chmod +x /opt/start.sh
CMD ["/opt/start.sh"]
