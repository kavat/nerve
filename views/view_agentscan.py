import copy
import config

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger
from core.command_sender import CommandSender

from flask import (
  Blueprint,
  render_template,
  flash,
  request,
  redirect
)

agentscan = Blueprint('agentscan', __name__,
                template_folder='templates')

@agentscan.route('/agentscan', methods=['GET','POST'])
@session_required
def view_agentscan():
  if request.method == 'POST':
    register = Register()
    ip = request.values.get('ip')
    os = request.values.get('os')
    username_ssh = request.values.get('username_ssh')
    password_ssh = request.values.get('password_ssh')
    how = request.values.get('how')
    scan = copy.deepcopy(config.DEFAULT_SCAN)

    if ip and username_ssh and password_ssh and os:
      real_ip = ''
      try:
        if os == "linux":
          logger.info("Sending preliminar SSH commands..")
          command_sender = CommandSender(ip, username_ssh, password_ssh, how, "")
          command_sender.create_tunnel()
          real_ip = ip
          ip = scan['ip_peer_static']
        else:
          real_ip = ip
      except Exception as e:
        errore = 'Failed to execute preliminar commands: '+ str(e)
        logger.error(errore)
        logger.exception(e)
        flash(errore, 'error')
      else:
        scan['type'] = 'network'
        scan['type_ie'] = 'internal'
        scan['how'] = how
        scan['host_os'] = os
        scan['real_ip'] = real_ip
        scan['username_ssh'] = username_ssh
        scan['password_ssh'] = password_ssh
        scan['targets']['networks'].append(ip)
        scan['config']['scan_opts']['max_ports'] = -1
        schema = SchemaParser(scan, request)
        vfd, msg, scan = schema.verify()

        if vfd:
          res, code, msg = register.scan(scan)
          if res:
            logger.info('A scan was initiated')
            flash('Assessment started.', 'success')
            return redirect('/agentscan')
          else:
            flash(msg, 'error')

        else:
          flash(msg, 'error')

  return render_template('agentscan.html')
