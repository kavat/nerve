import copy
import config
import os

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger
from core.utils import check_service_http

from flask import (
  Blueprint,
  send_from_directory,
  render_template,
  flash,
  request,
  redirect
)

system_errors = Blueprint('system_errors', __name__,
                template_folder='templates')

@system_errors.route('/errors', methods=['GET'])
@session_required
def view_system_errors():
  data = rds.get_alarm_data()
  if data:
    data = {k: v for k, v in sorted(data.items(),
            key=lambda item: item[1]['datetime'],
            reverse=True)}
  else:
    data = []
  return render_template('system_errors.html', data=data)
