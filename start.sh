#!/bin/bash

echo "Create TUN for internal inspections"
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
ip tuntap add tun0 mode tun
ip addr add 10.0.2.1/30 dev tun0
ip link set dev tun0 up

echo "Fix per bug su avvio metasploit.."
export TERM="xterm-256color"
touch /opt/nerve/logs/msfconsole.log

echo "Start redis.."
redis-server --bind 127.0.0.1 2>&1> /var/log/redis.log &

atq | grep "^[ ]\+[0-9]\+" -o | xargs atrm > /dev/null 2>&1
echo "/opt/nerve/update_metasploit.sh" | at now + 15 minutes

echo "Start NERVE.."
export LANG="en_US.UTF-8"
echo "FLUSHALL" | redis-cli && /usr/bin/python3 main.py
tail -f /dev/null

echo "Exited.."
