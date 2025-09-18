"""SDLC Module Routes with Auto-Clone Functionality"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, make_response, send_file, current_app
from flask_login import login_required, current_user
from auth.decorators import module_access_required, audit_log
from datetime import datetime
import os
import tempfile
import json
import subprocess
import shutil
import git
from git import Repo

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

def clone_repository(repo_url, temp_dir, depth=50):
    """Clone repository to temporary directory."""
    try:
        print(f"🔄 Cloning repository: {repo_url}")
        print(f"📁 Destination: {temp_dir}")
        
        # Use GitPython for more control
        repo = Repo.clone_from(
            repo_url, 
            temp_dir,
            depth=depth,  # Shallow clone for speed
            single_branch=False  # Get all branches
        )
        
        # Fetch all remote branches
        print("🌿 Fetching all branches...")
        for remote in repo.remotes:
            remote.fetch()
        
        print("✅ Repository cloned successfully")
        return repo, temp_dir
        
    except Exception as e:
        print(f"❌ Clone failed: {str(e)}")
        raise Exception(f"Failed to clone repository: {str(e)}")

def validate_branches_exist(repo, base_branch, target_branch):
    """Validate that specified branches exist in the repository."""
    try:
        # Get all branch names (local and remote)
        all_branches = []
        
        # Local branches
        for branch in repo.branches:
            all_branches.append(branch.name)
        
        # Remote branches (without 'origin/' prefix)
        for remote in repo.remotes:
            for ref in remote.refs:
                branch_name = ref.name.split('/')[-1]  # Get branch name without remote prefix
                if branch_name not in all_branches and branch_name != 'HEAD':
                    all_branches.append(branch_name)
        
        print(f"📋 Available branches: {all_branches}")
        
        # Check if branches exist
        missing_branches = []
        if base_branch not in all_branches:
            missing_branches.append(base_branch)
        if target_branch not in all_branches:
            missing_branches.append(target_branch)
        
        if missing_branches:
            raise Exception(f"Branches not found: {missing_branches}. Available: {all_branches}")
        
        # Checkout branches locally if they're remote
        for branch_name in [base_branch, target_branch]:
            try:
                # Try to checkout the branch
                repo.git.checkout(branch_name)
            except:
                # If checkout fails, create local branch from remote
                try:
                    repo.git.checkout('-b', branch_name, f'origin/{branch_name}')
                    print(f"✅ Created local branch: {branch_name}")
                except:
                    print(f"⚠️  Could not checkout {branch_name}, but continuing...")
        
        return True
        
    except Exception as e:
        raise Exception(f"Branch validation failed: {str(e)}")

@sdlc_bp.route('/release-reports/generate', methods=['GET', 'POST'])
@login_required
@module_access_required('sdlc')
@audit_log('generate_release_report')
def generate_release_report():
    """Generate new release report with auto-clone functionality."""
    if request.method == 'GET':
        return render_template('sdlc/release_report_form.html')
    
    temp_dir = None
    try:
        # Get form data
        repo_url = request.form.get('repo_url', '').strip()
        base_branch = request.form.get('base_branch', '').strip()
        target_branch = request.form.get('target_branch', '').strip()
        target_version = request.form.get('target_version', '').strip()
        report_title = request.form.get('report_title', '').strip()
        clone_depth = int(request.form.get('clone_depth', 50))
        
        # Validation
        if not all([repo_url, base_branch, target_branch]):
            flash('Please fill in all required fields.', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Validate repository URL format
        if not (repo_url.startswith('https://') or repo_url.startswith('git@')):
            flash('Please provide a valid Git repository URL (https:// or git@)', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix='release_report_')
        print(f"📁 Created temp directory: {temp_dir}")
        
        # Clone repository
        try:
            repo, cloned_path = clone_repository(repo_url, temp_dir, depth=clone_depth)
        except Exception as e:
            flash(f'Failed to clone repository: {str(e)}', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Validate branches exist
        try:
            validate_branches_exist(repo, base_branch, target_branch)
        except Exception as e:
            flash(f'Branch validation failed: {str(e)}', 'error')
            return render_template('sdlc/release_report_form.html')
        
        # Try to import and use the release report generator
        try:
            from modules.sdlc.release_report import ReleaseReportGenerator
            
            # Initialize the generator with the cloned repo path
            config = {
                'git_repo_path': cloned_path,
                'openai_api_key': current_app.config.get('OPENAI_API_KEY'),
                'sonarqube_url': current_app.config.get('SONARQUBE_URL'),
                'sonarqube_token': current_app.config.get('SONARQUBE_TOKEN'),
                'veracode_api_id': current_app.config.get('VERACODE_API_ID'),
                'veracode_api_key': current_app.config.get('VERACODE_API_KEY'),
            }
            
            generator = ReleaseReportGenerator(config)
            
            # Generate report data using the cloned repository
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
                repo_url=repo_url,
                generated_by=current_user.full_name
            )
            
        except ImportError:
            # Fallback: Generate mock report using cloned repo for basic Git analysis
            flash('Using simplified analysis - full release report generator not available.', 'warning')
            html_content = generate_git_analysis_report(
                repo_path=cloned_path,
                title=report_title or f"Release Report: {target_branch}",
                base_branch=base_branch,
                target_branch=target_branch,
                target_version=target_version,
                repo_url=repo_url,
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
        
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                print(f"🗑️  Cleaned up temp directory: {temp_dir}")
            except Exception as e:
                print(f"⚠️  Failed to clean up temp directory: {e}")

def generate_git_analysis_report(repo_path, title, base_branch, target_branch, target_version, repo_url, generated_by):
    """Generate a simplified report using basic Git analysis of cloned repo."""
    try:
        repo = Repo(repo_path)
        
        # Get commits between branches
        commits = list(repo.iter_commits(f'{base_branch}..{target_branch}'))
        
        # Extract basic story information from commits
        stories = []
        for i, commit in enumerate(commits[:20]):  # Limit to first 20 commits
            # Simple JIRA ticket extraction from commit message
            message = commit.message.strip()
            ticket_id = extract_ticket_id(message)
            
            stories.append({
                'key': ticket_id or f'COMMIT-{i+1}',
                'summary': message.split('\n')[0][:100],  # First line, truncated
                'risk_level': assess_simple_risk(commit),
                'story_points': estimate_story_points(commit),
                'assignee': commit.author.name,
                'commit_hash': commit.hexsha[:8],
                'files_changed': len(commit.stats.files)
            })
        
        # Generate report data
        report_data = {
            'stories': stories,
            'ai_summary': f'Analysis of {len(commits)} commits between {base_branch} and {target_branch}. This automated analysis identified {len(stories)} changes requiring review.',
            'coverage_info': {'current_coverage': 'Not Available', 'note': 'SonarQube integration required'},
            'vulnerabilities': [],
            'git_stats': {
                'total_commits': len(commits),
                'total_files_changed': sum(len(c.stats.files) for c in commits),
                'contributors': len(set(c.author.name for c in commits))
            }
        }
        
        return generate_html_report(report_data, title, base_branch, target_branch, repo_url, generated_by)
        
    except Exception as e:
        # Even more basic fallback
        return generate_mock_html_report(title, base_branch, target_branch, target_version, repo_url, generated_by)

def extract_ticket_id(commit_message):
    """Extract JIRA ticket ID from commit message."""
    import re
    patterns = [
        r'([A-Z]+-\d+)',  # PROJ-123
        r'#(\d+)',        # #123
        r'([A-Z]{2,}-\d+)' # PROJECT-123
    ]
    
    for pattern in patterns:
        match = re.search(pattern, commit_message.upper())
        if match:
            return match.group(1)
    return None

def assess_simple_risk(commit):
    """Simple risk assessment based on commit data."""
    files_changed = len(commit.stats.files)
    total_changes = commit.stats.total['lines']
    
    if files_changed > 10 or total_changes > 500:
        return 'High'
    elif files_changed > 5 or total_changes > 100:
        return 'Medium'
    else:
        return 'Low'

def estimate_story_points(commit):
    """Estimate story points based on commit size."""
    total_changes = commit.stats.total['lines']
    
    if total_changes > 500:
        return 8
    elif total_changes > 200:
        return 5
    elif total_changes > 50:
        return 3
    else:
        return 1

def generate_html_report(report_data, title, base_branch, target_branch, repo_url, generated_by):
    """Generate HTML report from report data."""
    
    git_stats = report_data.get('git_stats', {})
    
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
        .git-info {{ background-color: #f8f9fa; border-radius: 8px; padding: 1rem; }}
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <div class="report-header p-4 mb-4">
            <div class="container">
                <h1 class="display-4 mb-2">{title}</h1>
                <p class="lead mb-3">Branch Comparison: <code>{base_branch}</code> → <code>{target_branch}</code></p>
                <div class="git-info mb-3">
                    <small><i class="fab fa-git-alt"></i> Repository: {repo_url}</small>
                </div>
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
                            <p class="card-text">Total Changes</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info">{git_stats.get('total_commits', 'N/A')}</h3>
                            <p class="card-text">Commits</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning">{git_stats.get('contributors', 'N/A')}</h3>
                            <p class="card-text">Contributors</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-success">Auto-Generated</h3>
                            <p class="card-text">Status</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- AI Summary -->
            {generate_ai_summary_section(report_data.get('ai_summary', 'No analysis summary available.'))}
            
            <!-- Stories -->
            {generate_stories_section(report_data.get('stories', []))}
            
            <!-- Git Statistics -->
            {generate_git_stats_section(git_stats)}
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    
    return html_template

def generate_mock_html_report(title, base_branch, target_branch, target_version, repo_url, generated_by):
    """Generate a mock HTML report for testing."""
    
    mock_stories = [
        {
            'key': 'AUTO-001',
            'summary': 'Repository cloned and analyzed automatically',
            'risk_level': 'Low',
            'story_points': 1,
            'assignee': 'Auto-Generated'
        }
    ]
    
    return generate_html_report(
        report_data={
            'stories': mock_stories,
            'ai_summary': 'Auto-clone successful. This is a demonstration report showing the system can clone and analyze repositories automatically.',
            'coverage_info': {'current_coverage': 'Demo Mode'},
            'vulnerabilities': [],
            'git_stats': {
                'total_commits': 'Demo',
                'total_files_changed': 'Demo',
                'contributors': 'Demo'
            }
        },
        title=title,
        base_branch=base_branch,
        target_branch=target_branch,
        repo_url=repo_url,
        generated_by=generated_by
    )

def generate_ai_summary_section(ai_summary):
    return f"""
    <div class="card mb-4">
        <div class="card-header">
            <h5><i class="fas fa-robot me-2"></i>Analysis Summary</h5>
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
            <h5><i class="fas fa-tasks me-2"></i>Changes in This Release</h5>
        </div>
        <div class="card-body">
    """
    
    if not stories:
        stories_html += "<p class='text-muted'>No changes found.</p>"
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
                            <p class="card-text text-muted">Author: {story.get('assignee', 'Unknown')}</p>
                            {f"<small class='text-muted'>Files changed: {story.get('files_changed', 'N/A')}</small>" if story.get('files_changed') else ""}
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

def generate_git_stats_section(git_stats):
    if not git_stats:
        return ""
    
    return f"""
    <div class="card mb-4">
        <div class="card-header">
            <h5><i class="fab fa-git-alt me-2"></i>Git Statistics</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-4">
                    <strong>Total Commits:</strong> {git_stats.get('total_commits', 'N/A')}
                </div>
                <div class="col-md-4">
                    <strong>Files Changed:</strong> {git_stats.get('total_files_changed', 'N/A')}
                </div>
                <div class="col-md-4">
                    <strong>Contributors:</strong> {git_stats.get('contributors', 'N/A')}
                </div>
            </div>
        </div>
    </div>
    """

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