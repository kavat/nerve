import config
import sys
import redis
import threading
import pickle
import json
import base64

from core.logging import logger
from core.utils   import Utils

class RedisManager:
  def __init__(self):
    self.utils = Utils()
    self.r = None
    try:
      self.conn_pool = redis.ConnectionPool(host=config.RDS_HOST, port=config.RDS_PORT, password=config.RDS_PASSW, db=0)
      self.r = redis.Redis(connection_pool=self.conn_pool)
    except TimeoutError:
      logger.error('Redis Connection Timed Out!')
      sys.exit(1)
  
  def store(self, key, value):
    res = self.r.set(key, value)
    if res:
      return True
    return False

  def store_json(self, key, value):
    if key and value:
      pickle_v = pickle.dumps(value)
      result = self.r.set(key, pickle_v)
      if result:
        return True
    return False
  
  def store_topology(self, host):
    self.r.sadd("sess_topology", host)

  def save_error(self, macro_name, func_name, message, traceback_str):
    try:
      traceback_str_base64 = base64.b64encode(traceback_str.encode('ascii')).decode('ascii')
      date_time = self.utils.get_datetime()
      key = "error_{}_{}_{}".format(macro_name, func_name, date_time)
      json_object = {
        "datetime": date_time,
        "macro_name": macro_name,
        "func_name": func_name,
        "message": message,
        "traceback_str": traceback_str_base64
      }
      self.store_json(key, json_object)
    except Exception as e:
      logger.error("Exception creating error on Redis: {}".format(str(e)))

  def get_custom_config(self, key):
    default = ''
    if key == 'config_cve_scan_service_host':
      default = config.CVE_SCAN_SERVICE_HOST
    if key == 'config_cve_scan_service_port':
      default = config.CVE_SCAN_SERVICE_PORT
    if key == 'config_cve_scan_use_threads':
      default = config.CVE_SCAN_USE_THREADS
    if key == 'config_cve_scan_max_threads':
      default = config.CVE_SCAN_MAX_THREADS
    if key == 'config_session_max_checks':
      default = config.SESSION_MAX_CHECKS
    if key == 'config_session_time_sleep_check':
      default = config.SESSION_TIME_SLEEP_CHECK 
    if key == 'config_profile_service_host':
      default = config.PROFILE_SERVICE_HOST
    if key == 'config_profile_service_port':
      default = config.PROFILE_SERVICE_PORT
    try:
      ritorno = self.r.get(key)
      if ritorno:
        if key == 'config_session_time_sleep_check' or key == 'config_session_max_checks' or key == 'config_cve_scan_service_port' or key == 'config_cve_scan_use_threads' or key == 'config_profile_service_port':
          return int(ritorno.decode('utf-8'))
        else:
          return ritorno.decode('utf-8')
      else:
        logger.error("Unable to return {}, return default {}".format(str(key), str(default)))
        return default
    except Exception as e:
      logger.error("Unable to return {}, return default {}, exception: {}".format(str(key), str(default), str(e)))
      return default
 
  def get_slack_settings(self):
    return self.r.get('p_settings_slack')
  
  def get_email_settings(self):
    settings = self.r.get('p_settings_email')
    if settings:
      settings = pickle.loads(settings)
    
    return settings
   
  def store_scan_info(self, type, value):
    key = 'last_scan_{}'.format(str(type))
   
    if self.r.exists(key):
      self.r.delete(key)
   
    self.r.set(key, value) 
 
  def store_vuln(self, value):
    key = '{}{}{}{}'.format(value['ip'], value['port'], 
                            value['rule_id'], value['rule_details'])
    key_hash = 'vuln_' + self.utils.hash_sha1(key)
    
    if self.r.exists(key_hash):
      self.r.delete(key_hash)
      #return False
    
    logger.info('Vulnerability detected')
    
    self.store_json(key_hash, value)
  
  def store_cve(self, value):
    key = '{}{}{}{}'.format(value['ip'], value['cve_id'],
                            value['cpe'], value['rule_details'])
    key_hash = 'cve_' + self.utils.hash_sha1(key)
   
    if self.r.exists(key_hash):
      self.r.delete(key_hash)
      #return False
   
    logger.info('CVE detected')
   
    self.store_json(key_hash, value)
 
  def store_inspec(self, value):
    key = '{}{}{}'.format(value['host'], value['profile'], value['control_id'])
    key_hash = 'inspec_' + self.utils.hash_sha1(key)

    if self.r.exists(key_hash):
      self.r.delete(key_hash)
      #return False
   
    logger.info('Inspec control detected')
   
    self.store_json(key_hash, value)

  def store_sca(self, key, value):
    key = 'sca_' + key
    self.store_json(key, value)
  
  def store_inv(self, key, value):
    key = 'inv_' + key
    self.store_json(key, value)
    
  def store_sch(self, value):
    key = 'sch_' + value
    self.store(key, value)
    
  def get_ips_to_scan(self, limit):
    data = {}
    count = 0
    
    for key in self.r.scan_iter(match="sch_*"):
      count += 1
      value = self.r.get(key)
      
      if not value:
        self.r.delete(key)
        return
    
      ip = key.decode('utf-8').split('_')[1]
      data[ip] = {}

      self.r.delete(key)
      
      if count == limit:
        break

    return data

  def get_last_scan_info(self, prefix):
    key = "last_scan_{}".format(prefix)
    if self.r.exists(key):
      return json.loads(base64.b64decode(self.r.get(key)).decode('ascii'))

  def get_scan_data(self):
    kv = {}
    ip_key = None
    
    for k in self.r.scan_iter(match="sca_*"):
      ip_key = k.decode('utf-8')
      break # only get one key

    if ip_key:
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          if result:
            ip = ip_key.split('_')[1]
            kv[ip] = result
            self.r.delete(ip_key)
        except pickle.UnpicklingError as e:
          logger.error('Error unpickling %s' % e)
          logger.debug('IP Key: %s' % ip_key)

    return kv

  def del_inspec_data(self):
    for ip_key in self.r.scan_iter(match="inspec_*"):
      self.r.delete(ip_key)

  def get_inspec_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="inspec_*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv

  def get_cve_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="cve_*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv

  def get_alarm_data(self):
    kv = {}
    for key in self.r.scan_iter(match="error_*"):
      data = self.r.get(key)
      if data:
        try:
          result = pickle.loads(data)
          kv[key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv

  def get_vuln_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="vuln_*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv
  
  def get_vuln_by_id(self, alert_id):
    vuln = self.r.get(alert_id)
    if vuln:
      return pickle.loads(vuln)
    return None

  def get_inventory_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="inv*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv
  
  def get_topology(self):
    return self.r.smembers("sess_topology")

  def get_scan_config(self):
    cfg = self.r.get('sess_config')
    if cfg: 
      return pickle.loads(cfg)
    return {}
  
  def get_scan_progress(self):
    count = 0
    for k in self.r.scan_iter(match="sch_*"):
      count += 1
    return count
  
  def get_exclusions(self):
    exc = self.r.get('p_rule-exclusions')
    if exc: 
      return pickle.loads(exc)
    return {}
    
  def get_last_scan(self):
    return self.r.get('p_last-scan')
  
  def get_scan_count(self):
    return self.r.get('p_scan-count')
  
  def is_attack_active(self):
    for i in threading.enumerate():
      if i.name.startswith('rule_'):
        return True
    return False

  def is_scan_active(self):
    return self.get_scan_progress()
  
  def is_session_active(self): 
    if self.is_scan_active() or self.is_attack_active():
      return True
    return False
 
  def get_force_end_session(self):
    try:
      state = self.r.get('sess_force_end')
      if state != None:
        if state.decode("utf-8") == 'to_end':
          logger.info("sess_force_end found, delete and return true")
          self.r.delete('sess_force_end')
          return True
    except Exception as e:
      logger.error(str(e))
      logger.exception(e)
      return False
    return False

  def set_force_end_session(self):
    self.store('sess_force_end', 'to_end')
 
  def get_session_state(self):
    state = self.r.get('sess_state')
    if state:
      return state.decode('utf-8')
    return None
  
  def create_session(self):
    self.store('sess_state', 'created')
    self.r.incr('p_scan-count')
    self.r.set('p_last-scan', self.utils.get_datetime())
    
  def start_session(self):
    logger.info('Starting a new session...')
    self.store('sess_state', 'running')
    
  def end_session(self):
    logger.info('The session has ended.')
    self.store('sess_state', 'completed')

  def backup_data(self):
    try:
      stringa_backup = ""
      for prefix in ('vuln', 'cve', 'inspec'):
        for key in self.r.scan_iter(match="{}_*".format(prefix)):
          contenuto = base64.b64encode(self.r.get(key)).decode('utf-8')
          stringa_backup = "{}{}__||__{}\n".format(stringa_backup, key.decode('utf-8'), contenuto)
      f = open("/tmp/backup_redis.txt", "w")
      f.write(stringa_backup)
      f.close()
      return True
    except Exception as e:
      logger.error("Exception generating Redis backup file: {}".format(str(e)))
      return False 

  def clear_session_orig(self):
    for prefix in ('vuln', 'sca', 'sch', 'inv', 'cve', 'inspec'):
      for key in self.r.scan_iter(match="{}_*".format(prefix)):
        self.r.delete(key)
      
    for i in ('topology', 'config', 'state'):
      self.r.delete('sess_{}'.format(i))
    
    self.utils.clear_log()

  def clear_session(self):
    for i in ('config', 'state'):
      self.r.delete('sess_{}'.format(i))

  def clear_data_prefix(self, prefix):
    if prefix == 'network':
      self.r.delete('last_scan_network')
      for i in ('vuln', 'sca', 'sch', 'inv'):
        self.clear_data_prefix(i)
    if prefix == 'cve' or prefix == 'inspec':
      self.r.delete("last_scan_{}".format(prefix))
    for key in self.r.scan_iter(match="{}_*".format(prefix)):
      self.r.delete(key)

  def is_ip_blocked(self, ip):
    key = 'logon_attempt-{}'.format(ip)
    attempts = self.r.get(key)
    if attempts:
      if int(attempts) >= config.MAX_LOGIN_ATTEMPTS:
        return True
    else:
      self.r.set(key, 1, ex=300)  
    return False
  
  def log_attempt(self, ip):
    key = 'logon_attempt-{}'.format(ip)
    self.r.incr(key)
    
  def queue_empty(self):
    if self.r.dbsize() == 0:
      return True
    return False

  def db_size(self):
    return self.r.dbsize()
 
  def set_custom_config(self):
    self.r.set('config_cve_scan_service_host', config.CVE_SCAN_SERVICE_HOST)
    self.r.set('config_cve_scan_service_port', config.CVE_SCAN_SERVICE_PORT)
    self.r.set('config_cve_scan_use_threads', config.CVE_SCAN_USE_THREADS)
    self.r.set('config_cve_scan_max_threads', config.CVE_SCAN_MAX_THREADS)
    self.r.set('config_session_max_checks', config.SESSION_MAX_CHECKS)
    self.r.set('config_session_time_sleep_check', config.SESSION_TIME_SLEEP_CHECK)
    self.r.set('config_profile_service_host', config.PROFILE_SERVICE_HOST)
    self.r.set('config_profile_service_port', config.PROFILE_SERVICE_PORT)
 
  def initialize(self):
    self.clear_session()
    self.r.set('p_scan-count', 0)
    self.r.set('p_last-scan', 'N/A')
    
  def flushdb(self):
    self.r.flushdb()

  def delete(self, key):
    self.r.delete(key)
    
rds = RedisManager()
