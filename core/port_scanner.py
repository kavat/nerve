import requests
import nmap
import config
import traceback
import base64
import csv
import io
import os
import re
import shlex
import subprocess
import sys

from multiprocessing import Process
from xml.etree       import ElementTree as ET
from core.utils      import Utils
from core.triage     import Triage
from core.logging    import logger
from db              import db_ports
from core.redis      import rds

class Fingerprint():
  def __init__(self):
    self.t = Triage()

class Scanner():
  
  def scan_win(self, hosts="127.0.0.1", ports=None, arguments="-sV", sudo=False, timeout=0, username="", password=""):

    h_args = shlex.split(hosts)
    f_args = shlex.split(arguments)

    # Launch scan
    args = (
      ['C:\\nmap_portable\\nmap-7.92\\nmap.exe', "-oX", "-"]
      + ["127.0.0.1"]
      + ["-p", ports] * (ports is not None)
      + f_args
    )
    if sudo:
      args = ["sudo"] + args

    credentials = "{}__|||__{}__|||__{}".format(h_args[0], username, password)

    nmap_command = ["python3", "/opt/nerve/exec_winrm.py", base64.b64encode(' '.join(args).encode("ascii")).decode("ascii"), base64.b64encode(credentials.encode("ascii")).decode("ascii")]
    logger.info("Executing {}".format(' '.join(nmap_command)))

    p = subprocess.Popen(
      nmap_command,
      bufsize=100000,
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )

    if timeout == 0:
      (self.nmap._nmap_last_output, nmap_err) = p.communicate()
    else:
      try:
        (self.nmap._nmap_last_output, nmap_err) = p.communicate(timeout=timeout)
      except subprocess.TimeoutExpired:
        p.kill()
        raise PortScannerTimeout("Timeout from nmap process")

    nmap_err = bytes.decode(nmap_err)
    logger.info("OUTPUT: {}".format(self.nmap._nmap_last_output.decode("ascii")))
    logger.info("ERR: {}".format(nmap_err))
    self.nmap._nmap_last_output = self.nmap._nmap_last_output.decode("ascii").split("__|||__")[1].encode()

    nmap_err_keep_trace = []
    nmap_warn_keep_trace = []
    if len(nmap_err) > 0:
      regex_warning = re.compile("^Warning: .*", re.IGNORECASE)
      for line in nmap_err.split(os.linesep):
        if len(line) > 0:
          rgw = regex_warning.search(line)
          if rgw is not None:
            nmap_warn_keep_trace.append(line + os.linesep)
          else:
            nmap_err_keep_trace.append(nmap_err)

    logger.info("Analyse XML returned by NMAP: {}".format(self.nmap._nmap_last_output.decode()))

    return self.nmap.analyse_nmap_xml_scan(
      nmap_xml_output=self.nmap._nmap_last_output,
      nmap_err=nmap_err,
      nmap_err_keep_trace=nmap_err_keep_trace,
      nmap_warn_keep_trace=nmap_warn_keep_trace,
    )  

  def __init__(self):
    self.nmap = nmap.PortScanner()
    self.nmap_args = {
      'unpriv_scan':'-Pn -sV -sT -n --max-retries 10 --host-timeout 60m',
      'priv_scan':'-Pn -sV -O -sT -n --max-retries 10 --host-timeout 60m',
      'win_scan_internal':'-Pn -sV -sT -n --max-retries 10 --host-timeout 60m'
    }
    self.utils = Utils()
    
  def scan(self, hosts, max_ports, custom_ports, os="linux", interface=None, scan_type="external", username="", password=""):
    data = {}
    hosts = ' '.join(hosts.keys())
    extra_args = ''
    scan_cmdline = 'unpriv_scan'
    ports = ''
    
    if custom_ports:
      ports = '-p {}'.format(','.join([str(p) for p in set(custom_ports)]))
    
    elif max_ports:
      ports = '--top-ports {}'.format(max_ports)
    
    else:
      ports = '--top-ports 100'

    if max_ports == -1:
      ports = '-p-'

    if interface:
      extra_args += '-e {}'.format(interface)
    
    if self.utils.is_user_root():
      scan_cmdline = 'priv_scan'

    if os == "windows" and scan_type == "internal":
      scan_cmdline = 'win_scan_internal'

    result = {}
    
    try:
      logger.info("os: {}, scan_type: {}".format(os, scan_type))
      logger.info('Executing scan with {} {} {}'.format(self.nmap_args[scan_cmdline], ports, extra_args))
      if os == "windows" and scan_type == "internal":
        result = self.scan_win(hosts, arguments='{} {} {}'.format(self.nmap_args[scan_cmdline], ports, extra_args), username=username, password=password)
      else:
        result = self.nmap.scan(hosts, arguments='{} {} {}'.format(self.nmap_args[scan_cmdline], ports, extra_args))
      logger.info("Post scan execution..")
    except nmap.nmap.PortScannerError as e:
      logger.error('Error with scan. {}'.format(e))
      rds.save_error('PORT SCANNER', 'scan', 'Nmap error with scan. {}'.format(e), str(traceback.format_exc()))
    except Exception as egen:
      logger.error('Generic error with scan. {}'.format(egen))
      logger.error("STACKTRACE: {}".format(str(traceback.format_exc())))
      rds.save_error('PORT SCANNER', 'scan', 'Generic error with scan. {}'.format(egen), str(traceback.format_exc()))
   
    if 'scan' in result:  
      for host, res in result['scan'].items():
        
        data[host] = {}
        data[host]['status'] = res['status']['state']
        data[host]['status_reason'] = res['status']['reason']
        data[host]['domain'] = None
        data[host]['os'] = None
        
        for i in res['hostnames']:
          if i['type'] == 'user':
            data[host]['domain'] = i['name']
            break
        
        if 'osmatch' in res and res['osmatch']:
          for match in res['osmatch']:
            if int(match['accuracy']) >= 90:
              data[host]['os'] = match['name']
              break
                 
        if 'tcp' in res:
          data[host]['port_data'] = {}
          data[host]['ports'] = set()
          
          for port, values in res['tcp'].items():
            if port and values['state'] == 'open':
              data[host]['ports'].add(port)    
              data[host]['port_data'][port] = {}
              data[host]['port_data'][port]['cpe'] = values['cpe']
              data[host]['port_data'][port]['module'] = values['name']
              data[host]['port_data'][port]['state']  = values['state']
              data[host]['port_data'][port]['version'] = values['version']
              data[host]['port_data'][port]['product'] = values['product']
    
    return data
