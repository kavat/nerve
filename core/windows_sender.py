import base64
import sys

from winrmcp import Client
from core.logging import logger

class WindowsSender():
  def __init__(self, host, username, password):
    self.host = host
    self.username = username
    self.password = password

  def connect(self):
    try:
      #logger.info("Establishing connection to {}".format(self.host))
      self.client = Client(self.host, auth=(self.username, self.password), operation_timeout_sec=3600, read_timeout_sec=3601)
      return True
    except Exception as e:
      logger.error("Exception creating connection to {}: {}".format(self.host, str(e)))
      return False
   
  def exec(self, ps_script):
    with self.client.shell() as shell:
      #logger.info("Executing {}".format(ps_script))
      return shell.check_ps(ps_script)

  def put_requirements(self):
    ps_script = """
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://raw.githubusercontent.com/kavat/nerve/master/scripts/nmap_portable.zip -OutFile c:\\nmap_portable.zip
Expand-Archive -Force C:\\nmap_portable.zip -DestinationPath C:\\nmap_portable"""

    with self.client.shell() as shell:
      r_std_out, r_std_err = shell.check_ps(ps_script)
      #logger.info("Result of upload nmap_portable.zip on {}: {}".format(self.host, r_std_out))
      if r_std_err != None:
        logger.error("Failed to upload nmap_portable.zip on {}: {}".format(self.host, r_std_err))
        return False
      return True
