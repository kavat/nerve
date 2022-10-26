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
  redirect,
  Response
)

from random import randint

msfconsole = Blueprint('msfconsole', __name__,
                    template_folder='templates')

@msfconsole.route('/msfconsole')
@session_required
def view_msfconsole():
  value_random = randint(1000,9999)
  return render_template('msfconsole.html', value_random=value_random)

@msfconsole.route('/msfconsole_command', methods=['POST'])
@session_required
def view_msfconsole_command():
  if request.values.get('command_line') == "":
    return Response("{'status':'ko', 'desc':'Command sent empty'}", status=500, mimetype='application/json')
  if request.method == 'POST':
    register = Register()
    try:
      res = register.metasploit(request.values.get('command_line'))
      if res == False:
        flash(msg, 'Error registering command')
        return Response("{'status':'ko', 'desc':'Error registering command request'}", status=500, mimetype='application/json')
        
    except Exception as e:
      flash("Error sending command to Metasploit thread: {}".format(str(e)), 'error')
      return Response("{'status':'ko', 'desc':'Error sending command to Metasploit thread: " + str(e) + "'}", status=500, mimetype='application/json')

    return Response("{'status':'ok'}", status=200, mimetype='application/json')
