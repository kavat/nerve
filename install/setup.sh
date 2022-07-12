#!/bin/bash
systemd_service="/lib/systemd/system/nerve.service"
cwd="$(pwd)"
password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-12} | head -n 1)

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root."
  exit 1
fi

mkdir /opt/nerve
mkdir /opt/profiles-inspec

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
  supported=yes
fi

if [ "$supported" == "no" ]; then 
  echo "Can only run on CentOS 7.x"
  exit 1
fi

if ! ping -c 1 -W 3 google.com &> /dev/null; then
  echo "You must have a working internet connection to download the dependencies."
  exit 1
fi


function install_redhat {
  yum install epel-release -y && \
  yum update -y && \
  yum install -y gcc && \
  yum install -y redis && \
  yum install -y python3 && \
  yum install -y python3-pip && \
  yum install -y python3-devel && \
  yum install -y wget && \
  yum install -y bzip2 && \
  yum install -y make && \
  yum install -y gcc-c++ && \
  yum install -y postgresql-devel && \
  yum install -y libffi-devel && \
  yum install -y openssl-devel && \
  yum install -y libjpeg-turbo-devel && \
  yum install -y curl && \
  yum install -y unzip && \
  yum install -y jq && \
  yum install -y openssh-clients && \
  yum install -y net-tools && \
  yum install -y iproute && \
  yum install -y git && \
  yum clean all && \
  wget https://nmap.org/dist/nmap-7.92.tar.bz2 && \
  bzip2 -cd nmap-7.92.tar.bz2 | tar xvf - && \
  cd nmap-7.92 && ./configure && make && make install && \
  curl https://omnitruck.chef.io/install.sh | bash -s -- -P inspec
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
  echo "Installing packages..."
  install_redhat
  echo "Starting Redis..."
  systemctl enable redis
  systemctl start redis
fi

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
