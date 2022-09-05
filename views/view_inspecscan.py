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
    optionals = request.values.get('optionals')
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
      scan['optionals'] = optionals
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

@inspecscan.route('/inspecscank8s', methods=['GET','POST'])
@session_required
def view_inspecscan_k8s():
  if request.method == 'POST':
    register = Register()
    namespace = request.values.get('namespace')
    pod = request.values.get('pod')
    container = request.values.get('container')
    profile_inspec = request.values.get('profile_inspec')
    optionals = request.values.get('optionals')
    os_inspec = "kubernetes"
    
    kubeconfig_file = ""
    try:
      f = request.files['kubeconfig_file']
      kubeconfig_file = "{}/{}".format(config.UPLOAD_FOLDER,f.filename)
      f.save(kubeconfig_file)
    except Exception as e:
      flash("Error saving Kube config file: {}".format(str(e)), 'error')
      return render_template('inspecscan.html')
    
    if namespace and pod and container and kubeconfig_file and profile_inspec and os_inspec:
      logger.info("Start INSPEC request..")
      scan = copy.deepcopy(config.DEFAULT_SCAN)
      scan['type'] = 'inspec'
      scan['namespace'] = namespace
      scan['pod'] = pod
      scan['container'] = container
      scan['kubeconfig_file'] = kubeconfig_file
      scan['kubeconfig_name'] = f.filename
      scan['profile_inspec'] = profile_inspec
      scan['os_inspec'] = os_inspec
      scan['optionals'] = optionals 
      scan['targets']['networks'].append('1.1.1.1')

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

