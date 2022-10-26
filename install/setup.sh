#!/bin/bash
systemd_service="/lib/systemd/system/nerve.service"
cwd="$(pwd)"
password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-12} | head -n 1)

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root."
  exit 1
fi

mkdir /opt/nerve

if [ "$cwd" != "/opt/nerve" ]; then
  echo "please run this script from within /opt/nerve folder."
  exit 1
fi

if [ ! -f "requirements.txt" ]; then
  echo "requirements.txt is missing, did you unpack the files into /opt/nerve?"
  exit 1
fi

supported=no
if [ -f "/etc/redhat-release" ]; then
  os="redhat"
  supported=no
elif [ -f "/etc/lsb-release" ]; then
  os="ubuntu"
  supported=yes
fi

if [ "$supported" == "no" ]; then 
  echo "Can only run on Ubuntu 22.04 LTS"
  exit 1
fi

if ! ping -c 1 -W 3 google.com &> /dev/null; then
  echo "You must have a working internet connection to download the dependencies."
  exit 1
fi

function install_ubuntu {

  export DEBIAN_FRONTEND=noninteractive
  export TARGET_FOLDER=/opt/nerve

  apt update && \
  apt install -y gcc && \
  apt install -y redis && \
  apt install -y python3 && \
  apt install -y python3-pip && \
  apt install -y python3-dev && \
  apt install -y wget && \
  apt install -y bzip2 && \
  apt install -y make && \
  apt install -y vim && \
  apt install -y g++ && \
  apt install -y at && \
  apt install -y sudo && \
  apt install -y postgresql-contrib && \
  apt install -y libffi-dev && \
  apt install -y libssl-dev && \
  apt install -y build-essential && \ 
  apt install -y libjpeg-turbo8-dev && \
  apt install -y curl && \
  apt install -y unzip && \
  apt install -y jq && \
  apt install -y openssh-server && \
  apt install -y net-tools && \
  apt install -y iproute2 && \
  apt install -y git && \
  apt install -y libpq-dev && \
  apt install -y libkrb5-dev && \
  apt install -y gss-ntlmssp

  wget https://nmap.org/dist/nmap-7.92.tar.bz2 && \
    bzip2 -cd nmap-7.92.tar.bz2 | tar xvf - && \
    cd nmap-7.92 && ./configure && make && make install

  useradd -m metasploit && \
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | bash

  echo "no" | sudo -u metasploit "msfdb init"

  cd $TARGET_FOLDER/

}

function configure_firewalld {
  if firewall-cmd -V &> /dev/null; then
    echo "Checking Firewall settings..."
    if ps aux | grep -v grep | grep -q firewalld; then
      if [ -f "config.py" ]; then
      port=$(grep WEB_PORT config.py | awk -F' = ' '{print $2}')
      echo "Adding Firewalld rule to the public zone: 8080/tcp"
      firewall-cmd --zone=public --permanent --add-port=${port}/tcp &> /dev/null
      firewall-cmd --reload
      fi
    fi
  fi
}

function configure_iptables {
  if iptables -V &> /dev/null; then
    if ! iptables -vnL | grep -q "NERVE Console"; then
      iptables -I INPUT -p tcp --dport 8080 -j ACCEPT -m comment --comment "NERVE Console"
      iptables-save
    fi
  fi
}

function configure_selinux {
  if [ -f "/sbin/setenforce" ]; then
    echo "Setting SELinux in Permissive Mode..."
    setenforce 0
    if [ -f /etc/sysconfig/selinux ]; then
      if grep -q enforcing /etc/sysconfig/selinux; then
        sed -i s'/enforcing/permissive/'g /etc/sysconfig/selinux &> /dev/null
      fi
    fi
  fi
}

function check_fw {
  configure_firewalld
  configure_iptables
}

if [ ! -f "$systemd_service" ]; then
  echo "Setting up systemd service"
  echo "
[Unit]
Description=NERVE

[Service]
Type=simple
ExecStart=/bin/bash -c 'cd /opt/nerve/ && /usr/bin/python3 /opt/nerve/main.py'

[Install]
WantedBy=multi-user.target
" >> "$systemd_service"
  chmod 644 "$systemd_service"
fi

if [ "$os" == "redhat" ]; then
  echo "Installing Centos packages..."
  install_redhat
elif [ "$os" == "ubuntu" ]; then
  echo "Installing Centos packages..."
  install_ubuntu
fi

echo "Starting Redis..."
systemctl enable redis
systemctl start redis

echo "Installing Python requirements"
pip3 install -r requirements.txt

echo "Generating password"
if [ -f "config.py" ]; then
  sed -ine s/^WEB_PASSW\ =\ .*/WEB_PASSW\ =\ \'$password\'/ "config.py"
fi

echo "Starting NERVE..."
systemctl enable nerve
systemctl start nerve

echo "Checking Firewall..."
check_fw

echo "Checking SELinux..."
configure_selinux

systemctl is-active --quiet nerve
if [ $? != 1 ]; then
  echo 
  echo
  echo "Setup Complete!"
  echo "You may access via the following URL: http://your_ip_here:8080 with the credentials as defined in config.py"
  echo "Username: admin"
  echo "Password: $password"
  echo
  exit 0
else
  echo "Something went wrong, and the service could not be started."
  exit 1
fi
