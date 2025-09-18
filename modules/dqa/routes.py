"""DQA Module Routes"""

from flask import Blueprint, render_template
from flask_login import login_required
from auth.decorators import module_access_required

dqa_bp = Blueprint('dqa', __name__)

@dqa_bp.route('/dashboard')
@login_required
@module_access_required('dqa')
def dashboard():
    return render_template('dqa/dashboard.html')

@dqa_bp.route('/quality')
@login_required
@module_access_required('dqa')
def quality():
    return render_template('dqa/quality.html')

@dqa_bp.route('/lineage')
@login_required
@module_access_required('dqa')
def lineage():
    return render_template('dqa/lineage.html')

@dqa_bp.route('/reports')
@login_required
@module_access_required('dqa')
def reports():
    return render_template('dqa/reports.html')
