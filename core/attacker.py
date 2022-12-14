import time
import threading
import traceback

from core.manager   import rule_manager
from core.parser    import ConfParser
from core.logging   import logger
from core.redis     import rds
from core.utils     import log_exception

def run_rules(conf):

  threads = []

  data = rds.get_scan_data()
  exclusions = rds.get_exclusions()

  if not data:
    return threads

  for ip, values in data.items():
    rules = rule_manager(role='attacker')
    if 'ports' in values and len(values['ports']) > 0:  
      for port in values['ports']:
        logger.info('ATTACKER THREAD - Attacking Asset: {} on port: {}'.format(ip, port))
        for rule in rules.values():
          """
            Check if the target is in exclusions list, if it is, skip.
          """
          if rule.rule in exclusions and ip in exclusions[rule.rule]:
            logger.debug('ATTACKER THREAD - Skipping rule {} for target {}'.format(rule.rule, ip))
            continue

          """
            Only run rules that are in the allowed_aggressive config level.
          """
          if conf['config']['allow_aggressive'] >= rule.intensity:
            threads.append(threading.Thread(target=rule.check_rule, args=(ip, port, values, conf)))

  return threads

def attacker(conf):
  logger.info('ATTACKER THREAD - Attacker process started')

  logger.info("ATTACKER THREAD - Attacker threads creation..") 
  threads = run_rules(conf)

  for i in range(len(threads)):
    try:  
      logger.info("ATTACKER THREAD - Launching thread n " + str(i))
      threads[i].start()
    except Exception as e:
      log_exception("ATTACKER THREAD - Exception on thread start: {}".format(str(e)))
      rds.save_error("ATTACKER THREAD", "attacker", "Exception on thread start: {}".format(str(e)), str(traceback.format_exc()))

  for t in threads:
    try:
      logger.info("ATTACKER THREAD - Wait for thread end..")
      t.join()
    except Exception as e:
      log_exception("ATTACKER THREAD - Exception on thread join: {}".format(str(e)))
      rds.save_error("ATTACKER THREAD", "attacker", "Exception on thread join: {}".format(str(e)), str(traceback.format_exc()))

  logger.info("ATTACKER THREAD - Attacker threads terminated")
