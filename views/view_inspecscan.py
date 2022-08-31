import copy
import config

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger

from flask import (
  Blueprint,
  render_template,
  flash,
  request,
  redirect
)

inspecscan = Blueprint('inspecscan', __name__,
                template_folder='templates')

@inspecscan.route('/inspecscan', methods=['GET','POST'])
@session_required
def view_inspecscan():
  if request.method == 'POST':
    register = Register()
    ip = request.values.get('ip')
    username_ssh = request.values.get('username_ssh')
    password_ssh = request.values.get('password_ssh')
    profile_inspec = request.values.get('profile_inspec')
    os_inspec = "linux"
    if "Windows" in profile_inspec:
      os_inspec = "windows"

    if ip and username_ssh and password_ssh and profile_inspec and os_inspec:
      logger.info("Start INSPEC request..")
      scan = copy.deepcopy(config.DEFAULT_SCAN)
      scan['type'] = 'inspec'
      scan['username_ssh'] = username_ssh
      scan['password_ssh'] = password_ssh
      scan['profile_inspec'] = profile_inspec 
      scan['os_inspec'] = os_inspec 
      scan['targets']['networks'].append(ip)

      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()

      if vfd:
        res, code, msg = register.scan(scan)
        if res:
          logger.info('A INSPEC scan was initiated')
          flash('INSPEC scan started.', 'success')
        else:
          flash(msg, 'error')

      else:
        flash(msg, 'error')

  return render_template('inspecscan.html')
