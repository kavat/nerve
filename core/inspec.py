import time
import requests
import config
import os
import shutil
import json
import traceback
import base64

from git          import Repo
from pathlib      import Path
from core.logging import logger
from core.redis   import rds
from core.utils   import log_exception

def get_inspec_analysis(thread_id, username, password, host, profile, os):
  try:
    if username == "" or password == "" or host == "" or profile == "" or os == "":
      logger.error("Thread {} - Parameters missed".format(thread_id))

    url = "http://{}:{}/run_profile".format(rds.get_custom_config('config_profile_service_host'), str(rds.get_custom_config('config_profile_service_port')))
    body = {'username': username, 'password': password, 'host': host, 'profile': profile, 'os': os}
    logger.info("Thread {} - Launching POST request to {}".format(str(thread_id), url))
    r = requests.post(url, json=body)
    logger.info("Thread {} - Call ended with status {}".format(str(thread_id), str(r.status_code)))
    if r.status_code == 200:
      ritorno = r.text
      logger.info(ritorno)
      output_json = json.loads(ritorno)
      logger.info(output_json)
      rds.del_inspec_data()
      for row in output_json["rows"]:
        try:
          row["host"] = host
          row["profile"] = profile 
          rds.store_inspec(row)
        except Exception as e_redis:
          log_exception("Thread {} - Redis error: {}".format(thread_id, str(e_redis)))
          rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Redis error: {}".format(thread_id, str(e_redis)), str(traceback.format_exc()))
    else:
      logger.error("Thread {} - Status not 200")
      rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Status not 200", '')
  except Exception as e:
    log_exception("Thread {} - Exception main: {}".format(thread_id, str(e)))
    rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Exception main: {}".format(thread_id, str(e)), str(traceback.format_exc()))

def get_inspec_analysis_k8s(thread_id, namespace, pod, container, kubeconfig_file, profile, os):
  try:
    if namespace == "" or pod == "" or container == "" or kubeconfig_file == "" or profile == "" or os == "":
      logger.error("Thread {} - Parameters missed".format(thread_id))

    url = "http://{}:{}/run_profile".format(rds.get_custom_config('config_profile_service_host'), str(rds.get_custom_config('config_profile_service_port')))
    with open(kubeconfig_file, "rb") as kcf_file:
      kubeconfig_file_b64 = base64.b64encode(kcf_file.read())
    body = {'namespace': namespace, 'pod': pod, 'container': container, 'profile': profile, 'os': os, 'kubeconfig_file': kubeconfig_file_b64}
    logger.info("Thread {} - Launching POST request to {}".format(str(thread_id), url))
    r = requests.post(url, json=body)
    logger.info("Thread {} - Call ended with status {}".format(str(thread_id), str(r.status_code)))
    if r.status_code == 200:
      ritorno = r.text
      logger.info(ritorno)
      output_json = json.loads(ritorno)
      logger.info(output_json)
      rds.del_inspec_data()
      for row in output_json["rows"]:
        try:
          row["host"] = "{}/{}".format(pod, container)
          row["profile"] = profile
          rds.store_inspec(row)
        except Exception as e_redis:
          log_exception("Thread {} - Redis error: {}".format(thread_id, str(e_redis)))
          rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Redis error: {}".format(thread_id, str(e_redis)), str(traceback.format_exc()))
    else:
      logger.error("Thread {} - Status not 200")
      rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Status not 200", '')
  except Exception as e:
    log_exception("Thread {} - Exception main: {}".format(thread_id, str(e)))
    rds.save_error("INSPEC THREAD", "get_inspec_analysis", "Thread {} - Exception main: {}".format(thread_id, str(e)), str(traceback.format_exc()))
