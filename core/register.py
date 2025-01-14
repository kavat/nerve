import threading

from core.parser   import ConfParser
from core.utils    import Utils
from core.logging  import logger
from core.redis    import rds

class Register:
  def __init__(self):
    self.rds = rds
    self.utils = Utils()

  def metasploit(self, command_line):
    logger.info('Storing the new Metasploit configuration')
    try:
      self.rds.store('sess_metasploit_command', command_line)
      return True
    except:
      return False

  def scan(self, scan):
    if rds.get_session_state() in ('running', 'created'):
      return (False, 429, 'There is already a scan in progress!')

    cfg = ConfParser(scan)
    
    self.rds.clear_session()
    self.rds.create_session()
    
    logger.info('Storing the new Scan configuration')
    self.rds.store_json('sess_config', scan)
    
    networks = cfg.get_cfg_networks()
    domains = cfg.get_cfg_domains()
    
    if networks:
      logger.info('Scheduling network(s): {}'.format(', '.join(networks)))
    
    if domains:
      logger.info('Scheduling domains(s): {}'.format(', '.join(domains)))
    
    return (True, 200, 'Registered a new scan successfully!')
