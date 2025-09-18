"""BSSE Module Routes"""

from flask import Blueprint, render_template
from flask_login import login_required
from auth.decorators import module_access_required

bsse_bp = Blueprint('bsse', __name__)

@bsse_bp.route('/dashboard')
@login_required
@module_access_required('bsse')
def dashboard():
    return render_template('bsse/dashboard.html')

@bsse_bp.route('/architecture')
@login_required
@module_access_required('bsse')
def architecture():
    return render_template('bsse/architecture.html')

@bsse_bp.route('/integrations')
@login_required
@module_access_required('bsse')
def integrations():
    return render_template('bsse/integrations.html')

@bsse_bp.route('/compliance')
@login_required
@module_access_required('bsse')
def compliance():
    return render_template('bsse/compliance.html')
