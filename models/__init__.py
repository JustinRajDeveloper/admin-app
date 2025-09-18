"""Database models for Enterprise DevOps Platform"""

from flask_sqlalchemy import SQLAlchemy

# Initialize db instance
db = SQLAlchemy()

# Import all models
from .role import Role, Permission, RoleHistory
from .user import User, UserSession, UserActivity

# Configure relationships after all models are loaded
def configure_relationships():
    """Configure model relationships after all models are imported"""
    pass

__all__ = ['db', 'User', 'UserSession', 'UserActivity', 'Role', 'Permission', 'RoleHistory']
