import time
import traceback

from core.redis          import rds
from core.logging        import logger
from core.port_scanner   import Scanner
from core.parser         import ConfParser
from core.command_sender import CommandSender
from core.attacker       import attacker
from core.utils          import log_exception

def scanner():

  try:

    scanner = Scanner()

    logger.info('Scanner process started')

    while True:
      if not rds.is_session_active():
        time.sleep(10)
        continue

      conf = rds.get_scan_config()

      if not conf:
        time.sleep(10)
        continue

      c = ConfParser(conf)
      logger.info("Scan configuration: " + str(conf))

      if c.get_type_config() != 'network':
        logger.info("Not a scan with NETWORK request..")
        time.sleep(10)
        continue

      hosts = rds.get_ips_to_scan(limit = c.get_cfg_scan_threads())
      logger.info("Hosts to scan: " + str(hosts))

      if hosts:
        conf = rds.get_scan_config()
        scan_data = scanner.scan(hosts,
                            max_ports = c.get_cfg_max_ports(),
                            custom_ports = c.get_cfg_custom_ports(),
                            interface = c.get_cfg_netinterface())

        if scan_data:
          for host, values in scan_data.items():
            logger.info('Discovered Asset: {}'.format(host))
            try:
              real_ip = c.get_real_ip_config()
            except:
              real_ip = ''
            if real_ip != '':
              host = real_ip
            logger.info('Asset remapping: {}'.format(host))
            if 'ports' in values and values['ports']:
              logger.debug('Host: {}, Open Ports: {}'.format(host, values['ports']))
              logger.info('Host: {}, values: {}'.format(host, values))
              rds.store_topology(host)
              rds.store_sca(host, values)
              rds.store_inv(host, values)
            else:
              logger.info("Ports field not present")
              if values['status_reason'] == 'echo-reply':
                logger.info('Discovered Asset: {}'.format(host))
                rds.store_topology(host)
        else:
          logger.error('NETWORK_SCANNER - no scan_data')
          rds.save_error('NETWORK_SCANNER', 'scanner', 'no scan_data', '')

      else:
        logger.error('NETWORK_SCANNER - no host')
        rds.save_error('NETWORK_SCANNER', 'scanner', 'no host', '')

      attacker(conf)

      rds.set_force_end_session()

  except Exception as e_global:
    log_exception("NETWORK_SCANNER - Exception global: {}".format(str(e_global)))
    rds.save_error("NETWORK_SCANNER", "scanner", "Exception global: {}".format(str(e_global)), str(traceback.format_exc()))

  rds.set_force_end_session()
