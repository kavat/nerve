import config
import os

from core.redis   import rds
from core.workers import start_workers
from core.utils import check_service_http
from version import VERSION
from flask   import Flask
from flask_restful  import Api

# Import Blueprints
from views.view_index         import index
from views.view_docs          import documentation
from views.view_dashboard     import dashboard
from views.view_reports       import reports
from views.view_assessment    import assessment
from views.view_topology      import topology
from views.view_assets        import assets
from views.view_welcome       import welcome
from views.view_qs            import qs
from views.view_agentscan     import agentscan
from views.view_cvescan       import cvescan
from views.view_inspecscan    import inspecscan
from views.view_system_mgmnt  import system_mgmnt
from views.view_system_errors import system_errors
from views.view_login         import login
from views.view_console       import console
from views.view_logout        import logout
from views.view_download      import download
from views.view_stream        import stream
from views.view_settings      import settings
from views.view_scan          import scan
from views.view_vulns         import vulns
from views.view_alert         import alert
from views.view_startover     import startover


# Import REST API Endpoints
from views_api.api_health import Health
from views_api.api_scan import Scan
from views_api.api_update import Update
from views_api.api_exclusions import Exclusion

app = Flask(__name__)

# Initialize Blueprints
app.register_blueprint(index)
app.register_blueprint(login)
app.register_blueprint(logout)
app.register_blueprint(welcome)
app.register_blueprint(download)
app.register_blueprint(assets)
app.register_blueprint(stream)
app.register_blueprint(console)
app.register_blueprint(documentation)
app.register_blueprint(dashboard)
app.register_blueprint(qs)
app.register_blueprint(agentscan)
app.register_blueprint(cvescan)
app.register_blueprint(inspecscan)
app.register_blueprint(system_mgmnt)
app.register_blueprint(system_errors)
app.register_blueprint(reports)
app.register_blueprint(assessment)
app.register_blueprint(topology)
app.register_blueprint(vulns)
app.register_blueprint(settings)
app.register_blueprint(scan)
app.register_blueprint(alert)
app.register_blueprint(startover)


app.config.update(
  SESSION_COOKIE_SAMESITE='Strict',
)
app.secret_key = os.urandom(24)

api = Api(app)
api.add_resource(Health, '/health')
api.add_resource(Update, '/api/update', '/api/update/<string:component>')
api.add_resource(Scan,   '/api/scan', '/api/scan/<string:action>')
api.add_resource(Exclusion,   '/api/exclusion', '/api/exclusion')


# Set Security Headers
@app.after_request
def add_security_headers(resp):
  if config.WEB_SECURITY:
    resp.headers['Content-Security-Policy'] = config.WEB_SEC_HEADERS['CSP']
    resp.headers['X-Content-Type-Options'] = config.WEB_SEC_HEADERS['CTO']
    resp.headers['X-XSS-Protection'] = config.WEB_SEC_HEADERS['XSS']
    resp.headers['X-Frame-Options'] = config.WEB_SEC_HEADERS['XFO']
    resp.headers['Referrer-Policy'] = config.WEB_SEC_HEADERS['RP']
    resp.headers['Server'] = config.WEB_SEC_HEADERS['Server']
  return resp

# Context Processors
@app.context_processor
def status():
  progress = rds.get_scan_progress()
  session_state = rds.get_session_state()
  status = 'Ready'
  if session_state == 'created':
    status = 'Initializing...'
  elif session_state == 'running':
    if progress:
      status = 'Scanning... [QUEUE:{}]'.format(progress)
    else:
      status = 'Busy...'

  return dict(status=status)

@app.context_processor
def show_version():
  return dict(version=VERSION)

@app.context_processor
def show_frequency():
  config = rds.get_scan_config()
  scan_frequency = None
  if config:
    scan_frequency = config['config']['frequency']
  return dict(frequency=scan_frequency)

@app.context_processor
def show_vuln_count():
  contatore = len(rds.get_vuln_data()) + len(rds.get_cve_data())
  return dict(vuln_count=contatore)

@app.context_processor
def show_alarm_count():
  contatore = len(rds.get_alarm_data())
  return dict(alarm_count=contatore)

@app.context_processor
def show_cve_service_status():
  return dict(cve_service_status=check_service_http(rds.get_custom_config('config_cve_scan_service_host'), str(rds.get_custom_config('config_cve_scan_service_port')), 'api/get_cves/openssh:8.2', {"yellow": "ritorno['results'] == []", "green": "len(ritorno['results']) > 0"}))

@app.context_processor
def show_profile_service_status():
  return dict(profile_service_status=check_service_http(rds.get_custom_config('config_profile_service_host'), str(rds.get_custom_config('config_profile_service_port')), '', {"green": "ritorno['status'] == True"}))


if __name__ == '__main__':
  rds.initialize()
  rds.set_custom_config()
  start_workers()
  app.run(debug = config.WEB_DEBUG,
          host  = config.WEB_HOST,
          port  = config.WEB_PORT,
          threaded=True,
          use_evalex=False)
