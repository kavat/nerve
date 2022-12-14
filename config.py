import os
import base64

def get_base64_file(nome_file):
  with open(nome_file, "rb") as file_bin:
    return base64.b64encode(file_bin.read()).decode('utf-8')

CVE_SCAN_SERVICE_HOST = "172.17.0.2"
CVE_SCAN_SERVICE_PORT = 5000
CVE_SCAN_USE_THREADS = 0
CVE_SCAN_MAX_THREADS = 5
PROFILE_SERVICE_HOST = "172.17.0.3"
PROFILE_SERVICE_PORT = 5000
SESSION_MAX_CHECKS = 120
SESSION_TIME_SLEEP_CHECK = 30

# Logger Configuration
LOG_LEVEL = 'INFO'

# Webserver Configuration
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WEB_DEBUG = False
WEB_USER = os.environ.get('username', 'admin')
WEB_PASSW = os.environ.get('password', 'admin')
WEB_LOG = 'nerve.log'

# Web Security
# Setting this to True will return all responses with security headers.
WEB_SECURITY = True
WEB_SEC_HEADERS = {
  'CSP':'default-src \'self\' \'unsafe-inline\'; object-src \'none\'; img-src \'self\' data:',
  'CTO':'nosniff',
  'XSS':'1; mode=block',
  'XFO':'DENY',
  'RP':'no-referrer',
  'Server':'NERVE'
}

# Maximum allowed attempts before banning the remote origin
MAX_LOGIN_ATTEMPTS = 3

# Redis Configuration
# This should not be set to anything else except localhost unless you want to do a multi-node deployment.
RDS_HOST = '127.0.0.1'
RDS_PORT = 6379
RDS_PASSW = None

# Scan Configuration
USER_AGENT = 'NERVE'

PATH_NERVE_SCRIPTS = '/opt/nerve/scripts'

# COMMAND FOR OS RPM BASED TO LIST ALL SHARED LIBRARIES RELATED TO A SOFTWARES AND SOFTWARES WITH A TCP OR UDP STREAM EXPOSED
CPE_GENERATION_RPM = "echo {} | base64 -d | bash | xargs echo -n".format(get_base64_file(PATH_NERVE_SCRIPTS + "/check_packages_rpm.sh"))

# COMMAND FOR OS DEB BASED TO LIST ALL SHARED LIBRARIES RELATED TO A SOFTWARES AND SOFTWARES WITH A TCP OR UDP STREAM EXPOSED
CPE_GENERATION_DPKG = "echo {} | base64 -d | bash | xargs echo -n".format(get_base64_file(PATH_NERVE_SCRIPTS + "/check_packages_deb.sh"))

# Default scan configuration
# This will be used in the "Quick Start" scan.
DEFAULT_SCAN = {
  'type':'network',
  'ip_peer_static':'10.0.2.2',
  'type_ie':'external',
  'targets':{
    'networks':[],
    'excluded_networks':[],
    'domains':[]
  },
  'config':{
    'name':'Default',
    'description':'My Default Scan',
    'engineer':'Andrea',
    'allow_aggressive':3,
    'allow_dos':False,
    'allow_bf':False,
    'allow_internet':True,
    'dictionary':{
      'usernames':[],
      'passwords':[]
    },
    'scan_opts':{
      'interface':None,
      'max_ports':100,
      'custom_ports':[],
      'parallel_scan':50,
      'parallel_attack':30,
    },
    'post_event':{
      'webhook':None
    },
    'frequency':'once'
  }
}

UPLOAD_FOLDER = '/tmp'
MAX_CONTENT_PATH = 1000000000
