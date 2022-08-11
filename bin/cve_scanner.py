import time

from core.cve_scan       import get_cves_from_packages
from core.redis          import rds
from core.logging        import logger
from core.parser         import ConfParser
from core.command_sender import CommandSender
from core.utils          import log_exception
from config              import UPLOAD_FOLDER

def cve_scanner():

  try:

    logger.info('CVE_SCANNER - Process started')

    while True:
      if not rds.is_session_active():
        time.sleep(10)
        continue

      conf = rds.get_scan_config()

      if not conf:
        time.sleep(10)
        continue

      c = ConfParser(conf)
      logger.info("CVE_SCANNER - can configuration: " + str(conf))

      if c.get_type_config() != 'cve':
        logger.info("CVE_SCANNER - Not a scan with CVE request..")
        time.sleep(10)
        continue

      cpe_list = []
      ip = rds.get_ips_to_scan(limit = c.get_cfg_scan_threads())
      file_uploaded = c.get_file_uploaded_config()

      if file_uploaded == "none":
        username_ssh = c.get_username_ssh_config()
        password_ssh = c.get_password_ssh_config()
        package_type = c.get_package_type_config()
        logger.info("CVE_SCANNER - Hosts to scan: " + str(ip))

        if ip != "" and username_ssh != "" and password_ssh != "" and package_type != "":
          try:
            command_sender = CommandSender(list(ip.keys())[0], username_ssh, password_ssh, "", package_type)
            cpe_list = command_sender.get_local_cpe_list()
            logger.info("CVE_SCANNER - cpe_list: " + str(cpe_list))
          except Exception as e:
            rds.save_error("CVE_SCANNER", "cve_scanner", "Failed to execute command to get CPE list {}, exception: {}".format(str(cpe_list), str(e)))
            log_exception("CVE_SCANNER - Failed to execute command to get CPE list {}, exception: {}".format(str(cpe_list), str(e)))
        else:
          logger.error("CVE_SCANNER - Parameters missed")

      else: 
        try:
          logger.info("CVE_SCANNER - Trying open {} to compose cpe_list".format(file_uploaded))
          f = open("{}/{}".format(UPLOAD_FOLDER, file_uploaded), "r")
          cpe_list = f.read().split("\n")
        except Exception as e_set:
          rds.save_error("CVE_SCANNER", "cve_scanner", "Exception: {}".format(str(e_set)))
          log_exception("CVE_SCANNER - Exception: {}".format(str(e_set)))
        
      if len(cpe_list) > 0:
        logger.info("CVE_SCANNER - Send request..")
        try:
          get_cves_from_packages(cpe_list, list(ip.keys())[0])
        except Exception as e_get:
          rds.save_error("CVE_SCANNER", "cve_scanner", "Exception: {}".format(str(e_get)))
          log_exception("CVE_SCANNER - Exception: {}".format(str(e_get)))
      else:
        logger.info("CVE_SCANNER - CPE list equal to zero")

      rds.set_force_end_session()

  except Exception as e_global:
    log_exception("CVE_SCANNER - Exception global: {}".format(str(e_global)))
    rds.save_error("CVE_SCANNER", "cve_scanner", "Exception global: {}".format(str(e_global)))
    rds.set_force_end_session()
