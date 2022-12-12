import base64

from winrmcp import Client
from core.logging import logger

class WindowsSender():
  def __init__(self, host, username, password):
    self.host = host
    self.username = username
    self.password = password

  def connect(self):
    try:
      logger.info("Establishing connection to {}".format(self.host))
      self.client = Client(self.host, auth=(self.username, self.password), operation_timeout_sec=3600, read_timeout_sec=3601)
      return True
    except Exception as e:
      logger.error("Exception creating connection to {}: {}".format(self.host, str(e)))
      return False
    
  def put_requirements(self):
    ps_script = """
Invoke-WebRequest -Uri https://raw.githubusercontent.com/kavat/nerve/master/scripts/nmap_portable.zip -OutFile c:\\nmap_portable.zip"""

    with self.client.shell() as shell:
      r = shell.check_ps(ps_script)
      if r.status_code == 1:
        logger.error(r.std_err)
        return None

      logger.info(r.std_out)
      return r.std_out
  
  def scan(self):
    try:
      with self.client.shell() as shell:
        out, _ = shell.check_cmd(['powershell', 'Expand-Archive', '-PassThru', '-Force', '-LiteralPath', 'C:\\nmap_portable.zip', '-DestinationPath' 'C:\\'])
        logger.info("Output unzip nmap: {}".format(out))
        return True
    except Exception as e:
      logger.error("Exception unzipping nmap portable to {}: {}".format(self.host, str(e)))
      return False
