import config

from core.redis import rds
from core.security import session_required
from core.logging import logger

from core.reports import (
  generate_html, 
  generate_html_cve, 
  generate_html_inspec, 
  generate_csv, 
  generate_txt,
  generate_xml
)

from flask import (
  Blueprint,
  flash,
  redirect,
  send_from_directory
)

download = Blueprint('download', __name__,
                      template_folder='templates')

@download.route('/download/<file>')
@session_required
def view_download(file):
  if not file:
    return {'status':'file is missing'}, 400
  
  if file == 'server_log':
    response = send_from_directory(directory='logs', 
                                    filename=config.WEB_LOG,
                                    as_attachment=True,
                                    cache_timeout=0)
    return response
  
  else:
    data = rds.get_vuln_data()
    data_network = rds.get_vuln_data()
    data_cve = rds.get_cve_data()
    data_inspec = rds.get_inspec_data()
    conf = rds.get_scan_config()
    head_network = rds.get_last_scan_info('network')    
    head_cve = rds.get_last_scan_info('cve')    
    head_inspec = rds.get_last_scan_info('inspec')    

    logger.info(head_cve)

    if not data_network and not data_inspec and not data_cve and not conf:
      flash('There is no data in the system for report generation', 'error')
      return redirect('/reports')
    
    if file == 'report_html':  
      report_file = generate_html(data_network, head_network, conf)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    elif file == 'report_html_cve':
      report_file = generate_html_cve(data_cve, head_cve, conf)
      response = send_from_directory(directory='reports',
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response    
    elif file == 'report_html_inspec':
      report_file = generate_html_inspec(data_inspec, head_inspec, conf)
      response = send_from_directory(directory='reports',
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response   
    elif file == 'report_txt':
      report_file = generate_txt(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    elif file == 'report_csv':
      report_file = generate_csv(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response

    elif file == 'report_xml':
      report_file = generate_xml(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
