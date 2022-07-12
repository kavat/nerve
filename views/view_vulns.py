from core.security import session_required
from flask import Blueprint, render_template
from flask import request
from core.redis import rds

vulns = Blueprint('vulnerabilities', __name__,
                   template_folder='templates')

@vulns.route('/vulnerabilities')
@session_required
def view_vulns():
  try:
    scan_type = request.args.get('scan_type') 
  except:
    scan_type = 'network'
  data = []
  if scan_type == 'network':
    data = rds.get_vuln_data()
  if scan_type == 'cve':
    data = rds.get_cve_data()
  if scan_type == 'inspec':
    data = rds.get_inspec_data()
  if data:
    data = {k: v for k, v in sorted(data.items(), 
            key=lambda item: item[1]['rule_sev'], 
            reverse=True)}
  return render_template('vulnerabilities.html', data=data, scan_type=scan_type)

@vulns.route('/vulnerabilities/clear')
@session_required
def clear_vulns():
  try:
    scan_type = request.args.get('scan_type')
  except:
    scan_type = 'network'
  if scan_type == 'network':
    rds.clear_data_prefix('network')
  if scan_type == 'cve':
    rds.clear_data_prefix('cve')
  if scan_type == 'inspec':
    rds.clear_data_prefix('inspec')
  return render_template('vulnerabilities.html', data=[], scan_type=scan_type)
