import copy
import config
import os

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger
from core.utils import (
  check_service_http,
  check_thread
)

from flask import (
  Blueprint,
  send_from_directory,
  render_template,
  flash,
  request,
  redirect
)

system_mgmnt = Blueprint('system_mgmnt', __name__,
                template_folder='templates')

@system_mgmnt.route('/system_mgmnt', methods=['GET'])
@session_required
def view_system_mgmnt():
  operation_found = False
  services = {}
  error = ""
  operation_status = False
  operation = request.values.get('operation')
  if operation == 'force_end_scan':
    operation_found = True
    try:
      rds.end_session()
      operation_status = True
    except Exception as e:
      error = "Exception: ".format(str(e))
  if operation == 'check_services':
    operation_found = True
    services['cve_service'] = check_service_http(rds.get_custom_config('config_cve_scan_service_host'), str(rds.get_custom_config('config_cve_scan_service_port')), 'api/get_cves/test:0', 'results', [])
    operation_status = True
  if operation == 'backup':
    operation_found = True
    #esito_backup = rds.backup_data()
    #esito_backup == True:
    #  return send_from_directory(directory="/tmp", filename="backup_redis.txt")
    try:
      os.popen("redis-cli --rdb /tmp/redis_backup.rdb")
      operation_status = True
    except Exception as e:
      error = "Exception: ".format(str(e))
  if operation_found == False:
    error = "Operation {} not found".format(str(operation))
  return { "operation": operation, "status": operation_status, "error": error, "details": services }
