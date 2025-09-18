"""AIA Module Routes"""

from flask import Blueprint, render_template
from flask_login import login_required
from auth.decorators import module_access_required

aia_bp = Blueprint('aia', __name__)

@aia_bp.route('/dashboard')
@login_required
@module_access_required('aia')
def dashboard():
    return render_template('aia/dashboard.html')

@aia_bp.route('/infrastructure')
@login_required
@module_access_required('aia')
def infrastructure():
    return render_template('aia/infrastructure.html')

@aia_bp.route('/analytics')
@login_required
@module_access_required('aia')
def analytics():
    return render_template('aia/analytics.html')

@aia_bp.route('/capacity')
@login_required
@module_access_required('aia')
def capacity():
    return render_template('aia/capacity.html')
