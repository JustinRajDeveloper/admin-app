"""SDLC Module Routes"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, make_response, send_file
from flask_login import login_required, current_user
from auth.decorators import module_access_required, audit_log
from datetime import datetime
import os
import tempfile
import json

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
            'created_by_name': 'System Admin',
            'created_at': datetime.now()
        }
    ]
    return render_template('sdlc/release_reports.html', reports=reports)

@sdlc_bp.route('/release-reports/generate', methods=['GET', 'POST'])
@login_required
@module_access_required('sdlc')
@audit_log('generate_release_report')
def generate_release_report():
    """Generate new release report."""
    if request.method == 'GET':
        return render_template('sdlc/release_report_form.html')
    
    try:
        # Get form data
        git_repo_path = request.form.get('git_repo_path', '').strip()
        base_branch = request.form.get('base_branch', '').strip()
        target_branch = request.form.get('target_branch', '').strip()
        target_version = request.form.get('target_version', '').strip()
        report_title = request.form.get('report_title', '').strip()
        
        # Validation
        if not all([git_repo_path, base_branch, target_branch]):
            flash('Please fill in all required fields.', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Check if git repository exists
        if not os.path.exists(git_repo_path):
            flash('Git repository path does not exist.', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Try to import and use the release report generator
        try:
            from modules.sdlc.release_report import ReleaseReportGenerator
            
            # Initialize the generator
            config = {
                'git_repo_path': git_repo_path,
                'openai_api_key': current_app.config.get('OPENAI_API_KEY'),
                'sonarqube_url': current_app.config.get('SONARQUBE_URL'),
                'sonarqube_token': current_app.config.get('SONARQUBE_TOKEN'),
                'veracode_api_id': current_app.config.get('VERACODE_API_ID'),
                'veracode_api_key': current_app.config.get('VERACODE_API_KEY'),
            }
            
            generator = ReleaseReportGenerator(config)
            
            # Generate report data
            report_data = generator.generate_report_data(
                base_branch=base_branch,
                target_branch=target_branch,
                target_version=target_version or target_branch
            )
            
            # Generate HTML report
            html_content = generate_html_report(
                report_data=report_data,
                title=report_title or f"Release Report: {target_branch}",
                base_branch=base_branch,
                target_branch=target_branch,
                generated_by=current_user.full_name
            )
            
        except ImportError:
            # Fallback: Generate mock report
            flash('Using mock data - original release report generator not available.', 'warning')
            html_content = generate_mock_html_report(
                title=report_title or f"Release Report: {target_branch}",
                base_branch=base_branch,
                target_branch=target_branch,
                target_version=target_version,
                generated_by=current_user.full_name
            )
        
        # Create response with HTML file download
        response = make_response(html_content)
        filename = f"release_report_{target_branch.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = 'text/html'
        
        flash(f'Release report generated successfully: {filename}', 'success')
        return response
        
    except Exception as e:
        flash(f'Error generating release report: {str(e)}', 'error')
        return render_template('sdlc/release_report_form.html')

def generate_html_report(report_data, title, base_branch, target_branch, generated_by):
    """Generate HTML report from report data."""
    
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .report-header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        .story-card {{ border-left: 4px solid #007bff; }}
        .high-risk {{ border-left-color: #dc3545 !important; }}
        .medium-risk {{ border-left-color: #ffc107 !important; }}
        .low-risk {{ border-left-color: #28a745 !important; }}
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <div class="report-header p-4 mb-4">
            <div class="container">
                <h1 class="display-4 mb-2">{title}</h1>
                <p class="lead mb-3">Branch Comparison: <code>{base_branch}</code> → <code>{target_branch}</code></p>
                <div class="row">
                    <div class="col-md-6">
                        <small><i class="fas fa-user"></i> Generated by: {generated_by}</small>
                    </div>
                    <div class="col-md-6 text-md-end">
                        <small><i class="fas fa-calendar"></i> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="container">
            <!-- Summary -->
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-primary">{len(report_data.get('stories', []))}</h3>
                            <p class="card-text">Total Stories</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info">{report_data.get('coverage_info', {}).get('current_coverage', 'N/A')}</h3>
                            <p class="card-text">Code Coverage</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning">{len(report_data.get('vulnerabilities', []))}</h3>
                            <p class="card-text">Vulnerabilities</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-success">Ready</h3>
                            <p class="card-text">Status</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- AI Summary -->
            {generate_ai_summary_section(report_data.get('ai_summary', 'No AI summary available.'))}
            
            <!-- Stories -->
            {generate_stories_section(report_data.get('stories', []))}
            
            <!-- Vulnerabilities -->
            {generate_vulnerabilities_section(report_data.get('vulnerabilities', []))}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    
    return html_template

def generate_mock_html_report(title, base_branch, target_branch, target_version, generated_by):
    """Generate a mock HTML report for testing."""
    
    mock_stories = [
        {
            'key': 'PROJ-123',
            'summary': 'Implement user authentication system',
            'risk_level': 'High',
            'story_points': 8,
            'assignee': 'John Doe'
        },
        {
            'key': 'PROJ-124', 
            'summary': 'Add data validation to forms',
            'risk_level': 'Medium',
            'story_points': 5,
            'assignee': 'Jane Smith'
        },
        {
            'key': 'PROJ-125',
            'summary': 'Update UI components',
            'risk_level': 'Low', 
            'story_points': 3,
            'assignee': 'Bob Johnson'
        }
    ]
    
    return generate_html_report(
        report_data={
            'stories': mock_stories,
            'ai_summary': 'This release includes 3 key stories focusing on security improvements and UI enhancements. The authentication system implementation represents the highest risk item requiring careful testing.',
            'coverage_info': {'current_coverage': '85.2%'},
            'vulnerabilities': [
                {'severity': 'Medium', 'title': 'SQL Injection vulnerability in login form'},
                {'severity': 'Low', 'title': 'Missing input validation'}
            ]
        },
        title=title,
        base_branch=base_branch,
        target_branch=target_branch,
        generated_by=generated_by
    )

def generate_ai_summary_section(ai_summary):
    return f"""
    <div class="card mb-4">
        <div class="card-header">
            <h5><i class="fas fa-robot me-2"></i>AI Analysis Summary</h5>
        </div>
        <div class="card-body">
            <p>{ai_summary}</p>
        </div>
    </div>
    """

def generate_stories_section(stories):
    stories_html = """
    <div class="card mb-4">
        <div class="card-header">
            <h5><i class="fas fa-tasks me-2"></i>Stories in This Release</h5>
        </div>
        <div class="card-body">
    """
    
    if not stories:
        stories_html += "<p class='text-muted'>No stories found.</p>"
    else:
        for story in stories:
            risk_class = {
                'High': 'high-risk',
                'Medium': 'medium-risk', 
                'Low': 'low-risk'
            }.get(story.get('risk_level', 'Low'), 'low-risk')
            
            stories_html += f"""
            <div class="card story-card {risk_class} mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-8">
                            <h6 class="card-title">{story.get('key', 'N/A')}: {story.get('summary', 'No summary')}</h6>
                            <p class="card-text text-muted">Assignee: {story.get('assignee', 'Unassigned')}</p>
                        </div>
                        <div class="col-md-4 text-end">
                            <span class="badge bg-primary">{story.get('story_points', 0)} pts</span>
                            <span class="badge bg-{'danger' if story.get('risk_level') == 'High' else 'warning' if story.get('risk_level') == 'Medium' else 'success'}">{story.get('risk_level', 'Low')} Risk</span>
                        </div>
                    </div>
                </div>
            </div>
            """
    
    stories_html += "</div></div>"
    return stories_html

def generate_vulnerabilities_section(vulnerabilities):
    vuln_html = """
    <div class="card mb-4">
        <div class="card-header">
            <h5><i class="fas fa-shield-alt me-2"></i>Security Vulnerabilities</h5>
        </div>
        <div class="card-body">
    """
    
    if not vulnerabilities:
        vuln_html += "<p class='text-success'>No vulnerabilities found.</p>"
    else:
        for vuln in vulnerabilities:
            severity_class = {
                'High': 'danger',
                'Medium': 'warning',
                'Low': 'info'
            }.get(vuln.get('severity', 'Low'), 'info')
            
            vuln_html += f"""
            <div class="alert alert-{severity_class}">
                <strong>{vuln.get('severity', 'Unknown')} Severity:</strong> {vuln.get('title', 'Unknown vulnerability')}
            </div>
            """
    
    vuln_html += "</div></div>"
    return vuln_html

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