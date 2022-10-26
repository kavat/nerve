import time
import traceback

from core.inspec  import (
  get_inspec_analysis,
  get_inspec_analysis_k8s
)

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

      if c.get_type_config() != 'inspec':
        logger.info("INSPEC - Not a scan with INSPEC request..")
        time.sleep(10)
        continue

      logger.debug("INSPEC - Scan configuration: " + str(conf))

      os_inspec = c.get_os_inspec_config()
      ip = rds.get_ips_to_scan(limit = c.get_cfg_scan_threads())
      
      if os_inspec == "kubernetes":
        namespace = c.get_namespace_config()
        pod = c.get_pod_config()
        container = c.get_container_config()
        kubeconfig_file = c.get_kubeconfig_file_config()
        kubeconfig_name = c.get_kubeconfig_name_config()
      else:
        username_ssh = c.get_username_ssh_config()
        password_ssh = c.get_password_ssh_config()

      profile_inspec = c.get_profile_inspec_config()
      optionals = c.get_optionals_inspec_config()

      logger.info("INSPECT - Hosts to scan: " + str(ip))

      if os_inspec != "kubernetes" and ip != "" and username_ssh != "" and password_ssh != "" and profile_inspec != "" and os_inspec != "":
        logger.info("INSPEC HOST - Send request..")
        try:
          get_inspec_analysis("INSPEC", username_ssh, password_ssh, list(ip.keys())[0], profile_inspec, os_inspec, optionals)
        except Exception as e_get:
          log_exception("INSPEC - Exception: {}".format(str(e_get)))
          rds.save_error("INSPEC", 'inspec_scanner', "Exception: {}".format(str(e_get)), str(traceback.format_exc()))
      else:
        if os_inspec == "kubernetes" and namespace and pod and container and kubeconfig_file and kubeconfig_name and profile_inspec != "" and os_inspec != "":
          logger.info("INSPEC K8S - Send request..")
          try:
            get_inspec_analysis_k8s("INSPEC", namespace, pod, container, kubeconfig_file, kubeconfig_name, profile_inspec, os_inspec, optionals)
          except Exception as e_get:
            log_exception("INSPEC K8S - Exception: {}".format(str(e_get)))
            rds.save_error("INSPEC", 'inspec_scanner', "Exception: {}".format(str(e_get)), str(traceback.format_exc()))
        else:
          logger.error("INSPEC - Parameters missed")
          rds.save_error("INSPEC', 'inspec_scanner', 'Parameters missed", '')

      rds.set_force_end_session()

  except Exception as e_global:
    log_exception("INSPEC - Exception global: {}".format(str(e_global)))
    rds.save_error("INSPEC", 'inspec_scanner', "Exception global: {}".format(str(e_global)), str(traceback.format_exc()))
    rds.set_force_end_session()
