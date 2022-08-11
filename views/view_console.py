from random import randint
from core.security import session_required
from flask import Blueprint, render_template

console = Blueprint('console', __name__,
                    template_folder='templates')

@console.route('/console')
@session_required
def view_console():
  value_random = randint(1000,9999)
  return render_template('console.html', value_random=value_random)
