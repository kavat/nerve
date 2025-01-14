import requests
import nmap
import config
import pexpect
import time
import os

from core.utils   import (
Utils,
escape_ansi
)
from core.triage  import Triage
from core.logging import logger
from db import db_ports
from paramiko import SSHClient
from paramiko import AutoAddPolicy


class CommandSender():
  def __init__(self, host, username, password, how, package_type):
    self.host = host
    self.username = username
    self.password = password
    self.how = how
    self.package_type = package_type

  def get_local_cpe_list(self):

    cpes = []
    logger.info("Launching get packages list with version to generate CPE..")
    # Connect
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())

    logger.info("HOST: " + str(self.host))
    logger.info("USERNAME: " + str(self.username))
    logger.info("PASSWORD: " + str(self.password))

    client.connect(self.host, 22, self.username, self.password)

    if self.package_type == 'rpm':
      ssh_cpe_sub_commands = [ config.CPE_GENERATION_RPM ]
    else:
      if self.package_type == 'deb':
        ssh_cpe_sub_commands = [ config.CPE_GENERATION_DPKG ]
      else:
        return []

    for x in range(len(ssh_cpe_sub_commands)):
      logger.info("Command to execute: " + ssh_cpe_sub_commands[x]);
      stdin, stdout, stderr = client.exec_command(ssh_cpe_sub_commands[x])
      output = str(stdout.read().decode("utf8"))
      logger.info("STDOUT: " + output);
      logger.info("STDERR: " + str(stderr.read().decode("utf8")));
      logger.info("RETURN CODE: " + str(stdout.channel.recv_exit_status()));

      for cpe in output.split(" "):
        logger.info("Append of " + cpe)
        cpes.append(cpe)

    stdin.close()
    stdout.close()
    stderr.close()
    client.close()

    return list(dict.fromkeys(cpes))

  def create_tunnel(self):
    if self.how == 'automatic':
      logger.info("Automatic phase before, launching prelimary commands before tunnel creation..")
      # Connect
      client = SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(AutoAddPolicy())

      logger.info("HOST: " + str(self.host))
      logger.info("USERNAME: " + str(self.username))
      logger.info("PASSWORD: " + str(self.password))

      client.connect(self.host, 22, self.username, self.password)

      # Run a set of commands
      list = ['sed "s/^[#]\{0,1\}PermitTunnel\(.*\)/PermitTunnel point-to-point/g" /etc/ssh/sshd_config -i', 'systemctl restart sshd', 'ip tuntap add tun0 mode tun', 'ip addr add ' + config.DEFAULT_SCAN['ip_peer_static'] + '/30 dev tun0', 'ip link set dev tun0 up', 'sysctl net.ipv4.ip_forward=1', 'sysctl net.ipv4.conf.all.route_localnet=1', 'iptables -t nat -I PREROUTING -i tun0 -j DNAT --to 127.0.0.1']

      for x in range(len(list)):
        logger.info("Command to execute: " + list[x]);
        stdin, stdout, stderr = client.exec_command(list[x])
        logger.info("STDOUT: " + str(stdout.read().decode("utf8")));
        logger.info("STDERR: " + str(stderr.read().decode("utf8")));
        logger.info("RETURN CODE: " + str(stdout.channel.recv_exit_status()));

      stdin.close()
      stdout.close()
      stderr.close()
      client.close()

    else:
      logger.info("Manual phase before, creating tunnel directly..")

    options = '-f -w0:0 -q -oConnectTimeout=1 -oConnectionAttempts=1 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no'
    ssh_cmd = 'ssh %s %s@%s true' % (options, self.username, self.host)
    logger.info("SSH tunnel command: " + ssh_cmd)
    child = pexpect.spawn(ssh_cmd, timeout=3600)
    logger.info("Waiting for password prompt..")
    child.expect('assword: ')
    logger.info("Insert password..")
    child.sendline(self.password)
    time.sleep(3)
    logger.info("return_ssh_tunnel_command: {}".format(escape_ansi(child.before.decode('utf-8'))))

    check_ssh_tunnel = os.popen("ps xa | grep ssh | grep -v grep | grep " + self.host).read()
    logger.info("Tunnel: " + str(check_ssh_tunnel))

    if check_ssh_tunnel == '':
      raise Exception("Tunnel down")
