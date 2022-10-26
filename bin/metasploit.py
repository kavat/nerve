import time
import traceback

from core.redis          import rds
from core.logging        import logger
from core.metasploit     import Metasploit
from core.parser         import ConfParser
from core.utils          import log_exception

def metasploit():

  try:

    logger.info('METASPLOIT - Process started')
    meta = Metasploit()

    while True:

      command = rds.get_metasploit_command()

      if not command or command == "":
        time.sleep(3)
        continue

      if meta.closed == True:
        meta.start()

      logger.debug("METASPLOIT - Scan configuration: " + command)

      if command == "quit" or command == "exit":
        meta.close()
      else:
        meta.send_command(command)

      time.sleep(1)

  except Exception as e_global:
    log_exception("METASPLOIT - Exception global: {}".format(str(e_global)))
    rds.save_error("METASPLOIT", "scanner", "Exception global: {}".format(str(e_global)), str(traceback.format_exc()))

