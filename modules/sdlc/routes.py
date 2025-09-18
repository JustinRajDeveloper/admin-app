"""SDLC Module Routes"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from auth.decorators import module_access_required, audit_log

sdlc_bp = Blueprint('sdlc', __name__)

@sdlc_bp.route('/dashboard')
@login_required
@module_access_required('sdlc')
def dashboard():
    """SDLC module dashboard."""
    return render_template('sdlc/dashboard.html')

@sdlc_bp.route('/release-reports')
@login_required
@module_access_required('sdlc')
def release_reports():
    """Release reports main page."""
    # Mock data for now
    reports = [
        {
            'id': 1,
            'title': 'Release v2.1.0 Report',
            'base_branch': 'main',
            'target_branch': 'release/v2.1.0',
            'target_version': 'v2.1.0',
            'stories_count': 15,
            'high_risk_count': 3,
            'status': 'completed',
            'created_by_name': 'System Admin'
        }
    ]
    return render_template('sdlc/release_reports.html', reports=reports)

@sdlc_bp.route('/release-reports/generate', methods=['GET', 'POST'])
@login_required
@module_access_required('sdlc')
def generate_release_report():
    """Generate new release report."""
    if request.method == 'GET':
        return render_template('sdlc/release_report_form.html')
    
    # For now, just redirect back with success message
    flash('Release report generation feature coming soon!', 'info')
    return redirect(url_for('sdlc.release_reports'))

@sdlc_bp.route('/pipelines')
@login_required
@module_access_required('sdlc')
def pipelines():
    """CI/CD pipelines overview."""
    return render_template('sdlc/pipelines.html')

@sdlc_bp.route('/quality')
@login_required
@module_access_required('sdlc')
def quality():
    """Code quality metrics."""
    return render_template('sdlc/quality.html')
