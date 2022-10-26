import threading

from bin.scanner     import scanner
from bin.attacker    import attacker
from bin.scheduler   import scheduler
from bin.cve_scanner import cve_scanner
from bin.inspec      import inspec_scanner
from bin.metasploit  import metasploit


def start_workers():
  thread = threading.Thread(target=scanner)
  thread.name = "scanner"
  thread.daemon = True
  thread.start()

  #thread = threading.Thread(target=attacker)
  #thread.name = "attacker"
  #thread.daemon = True
  #thread.start()

  thread = threading.Thread(target=cve_scanner)
  thread.name = "cve_scanner"
  thread.daemon = True
  thread.start()

  thread = threading.Thread(target=inspec_scanner)
  thread.name = "inspec_scanner"
  thread.daemon = True
  thread.start()

  thread = threading.Thread(target=scheduler)
  thread.name = "scheduler"
  thread.daemon = True
  thread.start()

  thread = threading.Thread(target=metasploit)
  thread.name = "metasploit"
  thread.daemon = True
  thread.start()
