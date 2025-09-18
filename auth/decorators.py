"""Authentication and authorization decorators"""

from functools import wraps
from flask import abort, redirect, url_for, flash, request
from flask_login import current_user

def permission_required(permission_name):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.url))
            
            if not current_user.has_permission(permission_name):
                flash('You do not have permission to access this resource.', 'error')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def module_access_required(module_name):
    """Decorator to require access to a specific module."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.url))
            
            if not current_user.can_access_module(module_name):
                flash(f'You do not have access to the {module_name} module.', 'error')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def audit_log(action_name, resource_name=None):
    """Decorator to automatically log user actions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            if current_user.is_authenticated:
                from models.user import UserActivity
                UserActivity.log_activity(
                    user_id=current_user.id,
                    action=action_name,
                    resource=resource_name or request.endpoint,
                    ip_address=request.remote_addr
                )
            return result
        return decorated_function
    return decorator

def register_template_functions(app):
    """Register utility functions for use in templates."""
    
    def check_permission(permission_name):
        if not current_user.is_authenticated:
            return False
        return current_user.has_permission(permission_name)
    
    def check_module_access(module_name):
        if not current_user.is_authenticated:
            return False
        return current_user.can_access_module(module_name)
    
    def check_module_admin(module_name):
        if not current_user.is_authenticated:
            return False
        return current_user.is_module_admin(module_name)
    
    app.jinja_env.globals.update({
        'check_permission': check_permission,
        'check_module_access': check_module_access,
        'check_module_admin': check_module_admin,
    })
