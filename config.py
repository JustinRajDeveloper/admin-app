"""
Configuration settings for the Flask application
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class."""
    
    # Basic Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///enterprise_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    
    # Application settings
    APP_NAME = 'Enterprise DevOps Platform'
    COMPANY_NAME = 'Your Company Name'
    COMPANY_LOGO = '/static/images/logo.png'
    
    # Email settings (for notifications)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'localhost'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # OIDC Settings (for future SSO integration)
    OIDC_ENABLED = os.environ.get('OIDC_ENABLED', 'false').lower() in ['true', 'on', '1']
    OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
    OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET')
    OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL')
    OIDC_REDIRECT_URI = os.environ.get('OIDC_REDIRECT_URI', '/auth/oidc/callback')
    
    # API Integration Settings
    JIRA_URL = os.environ.get('JIRA_URL')
    JIRA_PAT_TOKEN = os.environ.get('JIRA_PAT_TOKEN')
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    SONARQUBE_URL = os.environ.get('SONARQUBE_URL')
    SONARQUBE_TOKEN = os.environ.get('SONARQUBE_TOKEN')
    VERACODE_API_ID = os.environ.get('VERACODE_API_ID')
    VERACODE_API_KEY = os.environ.get('VERACODE_API_KEY')
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')
    
    # Security settings
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SYMBOL = False
    
    # Session timeout (in minutes)
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 480))  # 8 hours
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')


class DevelopmentConfig(Config):
    """Development environment configuration."""
    
    DEBUG = True
    TESTING = False
    
    # Less strict session settings for development
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False  # Disable CSRF for easier API testing
    
    # Development database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///dev_enterprise_app.db'
    
    # Development logging
    LOG_LEVEL = 'DEBUG'


class TestingConfig(Config):
    """Testing environment configuration."""
    
    TESTING = True
    DEBUG = True
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Disable rate limiting for testing
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production environment configuration."""
    
    DEBUG = False
    TESTING = False
    
    # Production database (PostgreSQL recommended)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost/enterprise_app'
    
    # Strict security settings
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Enhanced security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'"
    }


class StagingConfig(Config):
    """Staging environment configuration."""
    
    DEBUG = False
    TESTING = False
    
    # Staging database
    SQLALCHEMY_DATABASE_URI = os.environ.get('STAGING_DATABASE_URL') or \
        'postgresql://user:password@localhost/staging_enterprise_app'
    
    # Moderate security settings
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    
    # Staging logging
    LOG_LEVEL = 'INFO'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Module-specific configurations
MODULES_CONFIG = {
    'SDLC': {
        'name': 'Software Development Lifecycle',
        'icon': 'fas fa-code-branch',
        'description': 'Manage development processes, release reports, and CI/CD pipelines',
        'color': '#3498db',
        'tools': [
            {'name': 'Release Reports', 'url': '/sdlc/release-reports', 'icon': 'fas fa-chart-line'},
            {'name': 'Pipeline Status', 'url': '/sdlc/pipelines', 'icon': 'fas fa-stream'},
            {'name': 'Code Quality', 'url': '/sdlc/quality', 'icon': 'fas fa-check-circle'},
            {'name': 'Deployment Tracking', 'url': '/sdlc/deployments', 'icon': 'fas fa-rocket'}
        ]
    },
    'BSSE': {
        'name': 'Business System Software Engineering',
        'icon': 'fas fa-building',
        'description': 'Enterprise software architecture and business system management',
        'color': '#e74c3c',
        'tools': [
            {'name': 'System Architecture', 'url': '/bsse/architecture', 'icon': 'fas fa-sitemap'},
            {'name': 'Integration Mapping', 'url': '/bsse/integrations', 'icon': 'fas fa-project-diagram'},
            {'name': 'Service Catalog', 'url': '/bsse/services', 'icon': 'fas fa-list-alt'},
            {'name': 'Compliance Tracking', 'url': '/bsse/compliance', 'icon': 'fas fa-shield-alt'}
        ]
    },
    'AIA': {
        'name': 'Application Infrastructure & Analytics',
        'icon': 'fas fa-server',
        'description': 'Infrastructure monitoring, analytics, and performance management',
        'color': '#f39c12',
        'tools': [
            {'name': 'Infrastructure Health', 'url': '/aia/infrastructure', 'icon': 'fas fa-heartbeat'},
            {'name': 'Performance Analytics', 'url': '/aia/analytics', 'icon': 'fas fa-chart-bar'},
            {'name': 'Capacity Planning', 'url': '/aia/capacity', 'icon': 'fas fa-expand-arrows-alt'},
            {'name': 'Cost Optimization', 'url': '/aia/costs', 'icon': 'fas fa-dollar-sign'}
        ]
    },
    'DQA': {
        'name': 'Data Quality & Analytics',
        'icon': 'fas fa-database',
        'description': 'Data quality monitoring, validation, and analytics reporting',
        'color': '#9b59b6',
        'tools': [
            {'name': 'Data Quality Dashboard', 'url': '/dqa/quality', 'icon': 'fas fa-tachometer-alt'},
            {'name': 'Data Lineage', 'url': '/dqa/lineage', 'icon': 'fas fa-share-alt'},
            {'name': 'Validation Rules', 'url': '/dqa/validation', 'icon': 'fas fa-check-double'},
            {'name': 'Analytics Reports', 'url': '/dqa/reports', 'icon': 'fas fa-file-chart'}
        ]
    }
}
