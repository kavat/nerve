import time
import requests
import config

from core.logging import logger
from threading    import Thread
from core.redis   import rds
from core.utils   import log_exception

def get_cve_from_packages(cpe_list):
    logger.info("Split source array..")
    try:
      cpe_list_splitted = list(split_array(cpe_list, 25))
    except Exception as e_split:
      log_exception(str(e_spli))
      rds.save_error("CVE_SCAN SELENIUM", "get_inspec_analysis", str(e_spli))
    else:
      logger.info("Array splitted..")

    get_cve_from_list(cpe_list_splitted)

def get_cve_from_list(cpe_list_splitted):

  logger.info('CVEs detection process started')

  logger.info("Threads creation..")
  threads = []
  try:
    for i in range(len(cpe_list_splitted)):
      logger.info("Launching thread n " + str(i))
      t = Thread(target=get_cves_by_cpes, args=(cpe_list_splitted[i],))
      threads.append(t)
      t.start()
  except Exception as e:
    log_exception(str(e)) 
    rds.save_error("CVE_SCAN SELENIUM", "get_cve_from_list", str(e)) 

  for t in threads:
    logger.info("Wait for thread end..")
    t.join()

def split_array(a, n):
  k, m = divmod(len(a), n)
  return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def get_cves_by_cpes(cpes):
  try:
    url = "http://{}:{}/cve_scan_by_cpe?cpes={}".format(config.CVE_SCAN_SERVICE_HOST, str(config.CVE_SCAN_SERVICE_PORT), ','.join(cpes))
    logger.info("Launching GET request to {}".format(url))
    r = requests.get(url)
  except Exception as e:
    log_exception("Exception for {}: {}".format(str(cpes),str(e)))
    rds.save_error("CVE_SCAN SELENIUM", "get_cves_by_cpes", "Exception for {}: {}".format(str(cpes),str(e)))
  logger.info(str(r))
