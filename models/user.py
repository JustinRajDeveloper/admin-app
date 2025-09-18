"""User and authentication models"""

from datetime import datetime, timedelta
import secrets
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    """User model with role-based access control."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    
    # Profile information
    department = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    avatar_url = db.Column(db.String(255))
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # SSO integration
    sso_provider = db.Column(db.String(50))
    sso_user_id = db.Column(db.String(255))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    
    # Password reset
    reset_token = db.Column(db.String(255))
    reset_token_expires = db.Column(db.DateTime)
    
    # Two-factor authentication
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(255))
    
    # Relationships - using string references to avoid circular imports
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    role = db.relationship('Role', back_populates='users')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    @property
    def initials(self):
        return f"{self.first_name[0]}{self.last_name[0]}".upper()
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission_name):
        if not self.role:
            return False
        return self.role.has_permission(permission_name)
    
    def has_any_permission(self, permission_names):
        for permission_name in permission_names:
            if self.has_permission(permission_name):
                return True
        return False
    
    def has_all_permissions(self, permission_names):
        for permission_name in permission_names:
            if not self.has_permission(permission_name):
                return False
        return True
    
    def can_access_module(self, module_name):
        module_permission = f"{module_name.lower()}_access"
        return self.has_permission(module_permission)
    
    def is_module_admin(self, module_name):
        admin_permission = f"{module_name.lower()}_admin"
        return self.has_permission(admin_permission)
    
    def update_last_activity(self):
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def is_session_valid(self, session_timeout_minutes=480):
        if not self.last_activity:
            return False
        timeout = timedelta(minutes=session_timeout_minutes)
        return datetime.utcnow() - self.last_activity < timeout

class UserSession(db.Model):
    """Track user sessions for security monitoring."""
    
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(255), nullable=False, unique=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationship
    user = db.relationship('User', backref='sessions')

class UserActivity(db.Model):
    """Log user activities for audit purposes."""
    
    __tablename__ = 'user_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(255))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    CATEGORY_AUTH = 'auth'
    CATEGORY_MODULE = 'module'
    CATEGORY_ADMIN = 'admin'
    CATEGORY_DATA = 'data'
    
    category = db.Column(db.String(50), default=CATEGORY_MODULE)
    
    # Relationship
    user = db.relationship('User', backref='activities')
    
    @staticmethod
    def log_activity(user_id, action, resource=None, details=None, 
                    category=None, ip_address=None, user_agent=None):
        activity = UserActivity(
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            category=category or UserActivity.CATEGORY_MODULE,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(activity)
        db.session.commit()
