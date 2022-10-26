import pexpect
import time

from core.utils import escape_ansi

class Metasploit:

  def __init__(self):
    self.reset_output()
    self.closed = True

  def start(self):
    self.console = pexpect.spawn('msfconsole -q')
    self.wait()
    self.output()
    self.closed = False

  def wait(self):
    self.console.expect('>')

  def send_command(self, command):
    self.console.sendline("{}".format(command))
    self.wait()
    self.output()

  def close(self):
    self.console.close()
    self.reset_output()
    self.closed = True

  def reset_output(self):
    f = open("./logs/msfconsole.log", "w")
    f.truncate(0)
    f.close()

  def output(self):
    f = open("./logs/msfconsole.log", "a")
    f.write(escape_ansi(self.console.before.decode('utf-8')))
    f.close()
    #print(self.console.before.decode())
    #self.console.interact()

