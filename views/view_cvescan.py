import copy
import config

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger
from core.command_sender import CommandSender
from werkzeug.utils import secure_filename

from flask import (
  Blueprint,
  render_template,
  flash,
  request,
  redirect
)

cvescan = Blueprint('cvescan', __name__,
                template_folder='templates')

@cvescan.route('/cvescanfromfile', methods=['POST'])
@session_required
def view_cvescanfromfile():
  if request.method == 'POST':
    register = Register()
    ip = request.values.get('ip')
    f = request.files['file']
    try:
      f.save("{}/{}".format(config.UPLOAD_FOLDER,f.filename))
      scan = copy.deepcopy(config.DEFAULT_SCAN)
      scan['type'] = 'cve'
      scan['targets']['networks'].append(ip)
      scan['file_uploaded'] = f.filename
      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()

      if vfd:
        res, code, msg = register.scan(scan)
        if res:
          logger.info('A CVE scan was initiated')
          flash('CVE scan started.', 'success')
        else:
          flash(msg, 'error')
      else:
        flash(msg, 'error')
    except Exception as e:
      flash("Error saving file with packages list: {}".format(str(e)), 'error')

  return render_template('cpescan.html')

@cvescan.route('/cvescan', methods=['GET','POST'])
@session_required
def view_cvescan():
  if request.method == 'POST':
    register = Register()
    ip = request.values.get('ip')
    username_ssh = request.values.get('username_ssh')
    password_ssh = request.values.get('password_ssh')
    package_type = request.values.get('package_type')

    if ip and username_ssh and password_ssh and package_type:
      logger.info("Start CVE request..")
      scan = copy.deepcopy(config.DEFAULT_SCAN)
      scan['type'] = 'cve'
      scan['file_uploaded'] = "none" 
      scan['username_ssh'] = username_ssh
      scan['password_ssh'] = password_ssh
      scan['package_type'] = package_type
      scan['targets']['networks'].append(ip)

      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()

      if vfd:
        res, code, msg = register.scan(scan)
        if res:
          logger.info('A CVE scan was initiated')
          flash('CVE scan started.', 'success')
        else:
          flash(msg, 'error')

      else:
        flash(msg, 'error')

  return render_template('cpescan.html')
