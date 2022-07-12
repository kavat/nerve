import time

from core.inspec  import get_inspec_analysis
from core.redis   import rds
from core.logging import logger
from core.parser  import ConfParser
from core.utils   import log_exception

def inspec_scanner():

  try:

    logger.info('INSPEC - Process started')

    while True:
      if not rds.is_session_active():
        time.sleep(10)
        continue

      conf = rds.get_scan_config()

      if not conf:
        time.sleep(10)
        continue

      c = ConfParser(conf)
      logger.info("INSPEC - Scan configuration: " + str(conf))

      if c.get_type_config() != 'inspec':
        logger.info("INSPEC - Not a scan with INSPEC request..")
        time.sleep(10)
        continue

      ip = rds.get_ips_to_scan(limit = c.get_cfg_scan_threads())
      username_ssh = c.get_username_ssh_config()
      password_ssh = c.get_password_ssh_config()
      profile_inspec = c.get_profile_inspec_config()
      os_inspec = c.get_os_inspec_config()

      logger.info("INSPECT - Hosts to scan: " + str(ip))

      if ip != "" and username_ssh != "" and password_ssh != "" and profile_inspec != "" and os_inspec != "":
        logger.info("INSPEC - Send request..")
        try:
          get_inspec_analysis("INSPEC", username_ssh, password_ssh, list(ip.keys())[0], profile_inspec, os_inspec)
        except Exception as e_get:
          log_exception("INSPEC - Exception: {}".format(str(e_get)))
          rds.save_error("INSPEC', 'inspec_scanner', 'Exception: {}".format(str(e_get)))
      else:
        logger.error("INSPEC - Parameters missed")
        rds.save_error("INSPEC', 'inspec_scanner', 'Parameters missed")

      rds.set_force_end_session()

  except Exception as e_global:
    log_exception("INSPEC - Exception global: {}".format(str(e_global)))
    rds.save_error("INSPEC', 'inspec_scanner', 'Exception global: {}".format(str(e_global)))
    rds.set_force_end_session()
