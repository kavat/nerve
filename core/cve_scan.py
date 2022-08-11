import time
import requests
import config

from core.logging import logger
from threading    import Thread
from core.redis   import rds
from core.utils   import log_exception

def get_cves_from_packages(cpe_list, host):
  logger.info("Split source array..")
  try:
    if rds.get_custom_config('config_cve_scan_use_threads') == True:
      cpe_list_splitted = list(split_array(cpe_list, rds.get_custom_config('config_cve_scan_max_threads')))
    else:
      cpe_list_splitted = list(split_array(cpe_list, 1))
  except Exception as e_split:
    log_exception(str(e_split))
    rds.save_error("CVE_SCAN THREAD", "get_cves_from_packages", str(e_split))
  else:
    logger.info("Array splitted..")

  get_cve_from_list(cpe_list_splitted, host)

def get_cve_from_list(cpe_list_splitted, host):

  logger.info('CVEs detection process started')

  if rds.get_custom_config('config_cve_scan_use_threads') == True:
    logger.info("Threads creation..")
    threads = []
    try:
      for i in range(len(cpe_list_splitted)):
        logger.info("Launching thread n " + str(i))
        t = Thread(target=get_cves_by_cpes, args=(i, cpe_list_splitted[i], host,))
        threads.append(t)
        t.start()
    except Exception as e:
      log_exception(str(e))
      rds.save_error("CVE_SCAN THREAD", "get_cve_from_list", str(e))

    for t in threads:
      logger.info("Wait for thread end..")
      t.join()

    logger.info("Threads terminated")
  else:
    logger.info("Single thread execution")
    i = 0
    get_cves_by_cpes(i, cpe_list_splitted[i], host)
    logger.info("End")

def pulisci(stringa, chiave = ""):
  attiva = 0
  if attiva == 0:
    return stringa
  try:
    return str(bytes(stringa, 'utf-8').decode('utf-8', 'ignore'))
  except Exception as e:
    logger.error("Key {} Value {}".format(stringa, chiave))
    rds.save_error("CVE_SCAN THREAD", "pulisci", "Key {} Value {}".format(stringa, chiave))
    return stringa

def split_array(a, n):
  k, m = divmod(len(a), n)
  return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def get_cves_by_cpes(thread_id, cpes, host):
  logger.info("Thread {} - Start".format(str(thread_id)))
  try:
    for cpe_full in cpes:
      try:
        type_vuln = cpe_full.split(";")[0]
        cpe = cpe_full.split(";")[1]
        url = "http://{}:{}/api/get_cves/{}".format(rds.get_custom_config('config_cve_scan_service_host'), str(rds.get_custom_config('config_cve_scan_service_port')), cpe)
        logger.info("Thread {} - Launching GET request to {}".format(str(thread_id), url))
        r = requests.get(url)
        logger.info("Thread {} - Call ended with status {}".format(str(thread_id), str(r.status_code)))
        if r.status_code == 200:
          ritorno = r.json()
          try:
            for result in ritorno['results']:
              cve_id = result['id']
              cvss = 'ND'
              cvss3 = ''
              cvss2 = ''
              if 'cvss3' in result:
                cvss3 = result['cvss3']
              if 'cvss' in result:
                cvss2 = result['cvss']
              cvss = get_severity(cvss3, cvss2)
              summary = result['summary'].replace(u"\u2018", "'").replace(u"\u2019", "'")
              mitigations = "Please consider the linked references below in order to investigate the vulnerability:<br><br>{}".format("<br>".join(result['references']))
              details = "Vulnerability related to {} found (CVSS3: {}, CVSS2: {})".format(cve_id, str(cvss3), str(cvss2))
              product_name = cpe.split(":")[0]
              product_version = cpe.split(":")[1]

              try:
                attack_auth_req = result["access"]["authentication"]
              except:
                attack_auth_req = ""

              try:
                attack_complexity = result["access"]["complexity"]
              except:
                attack_complexity = ""

              try:
                attack_vector = result["access"]["vector"]
              except:
                attack_vector = ""

              logger.info("Thread {} - host: {}".format(str(thread_id), host))
              logger.info("Thread {} - cve_id: {}".format(str(thread_id), cve_id))
              logger.info("Thread {} - sev: {}".format(str(thread_id), str(cvss)))
              logger.info("Thread {} - summary: {}".format(str(thread_id), summary))
              logger.info("Thread {} - details: {}".format(str(thread_id), details))
              logger.info("Thread {} - mitigations: {}".format(str(thread_id), mitigations))
              logger.info("Thread {} - product_name: {}".format(str(thread_id), product_name))
              logger.info("Thread {} - product_version: {}".format(str(thread_id), product_version))
              logger.info("Thread {} - attack_auth_req: {}".format(str(thread_id), attack_auth_req))
              logger.info("Thread {} - attack_complexity: {}".format(str(thread_id), attack_complexity))
              logger.info("Thread {} - attack_vector: {}".format(str(thread_id), attack_vector))
              logger.info("Thread {} - type_vuln: {}".format(str(thread_id), type_vuln))

              details = "Please consider the linked references below in order to investigate the vulnerability:<br><br>{}".format("<br>".join(result['references']))
              rds.store_cve({
                'ip':pulisci(host, "host"),
                'cve_id':pulisci(cve_id, "cve_id"),
                'rule_id':'CVEs',
                'rule_sev':cvss,
                'rule_desc':pulisci(summary, "summary"),
                'rule_confirm':'Vulnerabilities Found',
                'rule_details':pulisci(details, "details"),
                'rule_mitigation':pulisci(mitigations, "mitigations"),
                'cvss3':pulisci(cvss3, "cvss3"),
                'cvss2':pulisci(cvss2, "cvss2"),
                'cpe':pulisci(cpe, "cpe"),
                'product_name':pulisci(product_name, "product_name"),
                'product_version':pulisci(product_version, "product_version"),
                'attack_auth_req':pulisci(attack_auth_req, "attack_auth_req"),
                'attack_complexity':pulisci(attack_complexity, "attack_complexity"),
                'attack_vector':pulisci(attack_vector, "attack_vector"),
                'type_vuln':pulisci(type_vuln, "type_vuln")
              })
          except Exception as e_store:
            log_exception("Thread {} - Exception on storing vulns: {}".format(str(thread_id), str(e_store)))
            rds.save_error("CVE_SCAN THREAD", "get_cves_by_cpes", "Thread {} - Exception on storing vulns: {}".format(str(thread_id), str(e_store)))
        else:
          logger.error("Thread {} - Status not 200, error {} to manage in response".format(str(thread_id), str(r.status_code)))
          insert_rds_cve_error(pulisci(host, "host"), "CVEs unavailable: {}".format(str(r.status_code)), pulisci(cpe, "cpe"), pulisci(product_name, "product_name"), pulisci(product_version, "product_version"))
      except Exception as e:
        log_exception("Thread {} - Exception: {}".format(str(thread_id),str(e)))
        rds.save_error("CVE_SCAN THREAD", "get_cves_by_cpes", "Thread {} - Exception: {}".format(str(thread_id),str(e)))
        insert_rds_cve_error(pulisci(host, "host"), "CVEs unavailable: {}".format(str(e)), pulisci(cpe, "cpe"), pulisci(product_name, "product_name"), pulisci(product_version, "product_version"))
  except Exception as e_thread_main:
    log_exception("Thread {} - Exception: {}".format(str(thread_id), str(e_thread_main)))
    rds.save_error("CVE_SCAN THREAD", "get_cves_by_cpes", "Thread {} - Exception main: {}".format(str(thread_id), str(e_thread_main)))
  logger.info("Thread {} - End".format(str(thread_id)))

def insert_rds_cve_error(host, error, cpe, product_name, product_version):
  rds.store_cve({
    'ip':host,
    'cve_id':'N/A',
    'rule_id':'CVEs',
    'rule_sev':4,
    'rule_desc':'N/A',
    'rule_confirm':error,
    'rule_details':'N/A',
    'rule_mitigation':'N/A',
    'cvss3':'N/A',
    'cvss2':'N/A',
    'cpe':cpe,
    'product_name':product_name,
    'product_version':product_version,
    'attack_auth_req':'N/A',
    'attack_complexity':'N/A',
    'attack_vector':'N/A',
    'type_vuln':'N/A'
  })

def get_severity(cvss3, cvss2):
  if cvss3 == '':
    cvss3 = 0
  if cvss2 == '':
    cvss2 = 0
  if cvss3 == 0 and cvss2 == 0:
    return 0
  if cvss3 != None and float(cvss3) > 0:
    if float(cvss3) >= 9.0 and float(cvss3) <= 10.0:
      return 4
    if float(cvss3) >= 7.0 and float(cvss3) <= 8.9:
      return 3
    if float(cvss3) >= 4.0 and float(cvss3) <= 6.9:
      return 2
    if float(cvss3) >= 0.1 and float(cvss3) <= 3.9:
      return 1
  if cvss2 != None and float(cvss2) > 0:
    if float(cvss2) >= 7.0 and float(cvss2) <= 10.0:
      return 3
    if float(cvss2) >= 4.0 and float(cvss2) <= 6.9:
      return 2
    if float(cvss2) >= 0.1 and float(cvss2) <= 3.9:
      return 1
  return 0

