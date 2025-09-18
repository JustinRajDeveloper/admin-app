"""Role and Permission models for RBAC"""

from datetime import datetime
from . import db

# Association table for many-to-many relationship between roles and permissions
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

class Role(db.Model):
    """Role model for role-based access control."""
    
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_system_role = db.Column(db.Boolean, default=False, nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('Permission', secondary=role_permissions, 
                                 back_populates='roles')
    users = db.relationship('User', back_populates='role')
    
    def __repr__(self):
        return f'<Role {self.name}>'
    
    def has_permission(self, permission_name):
        permission = Permission.query.filter_by(name=permission_name).first()
        if not permission:
            return False
        return permission in self.permissions
    
    def add_permission(self, permission):
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission):
        if permission in self.permissions:
            self.permissions.remove(permission)

class Permission(db.Model):
    """Permission model for fine-grained access control."""
    
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text)
    module = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    CATEGORY_READ = 'read'
    CATEGORY_WRITE = 'write'
    CATEGORY_DELETE = 'delete'
    CATEGORY_ADMIN = 'admin'
    CATEGORY_SYSTEM = 'system'
    
    category = db.Column(db.String(20), default=CATEGORY_READ)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary=role_permissions, 
                           back_populates='permissions')

class RoleHistory(db.Model):
    """Track changes to roles for audit purposes."""
    
    __tablename__ = 'role_history'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    changed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    changes = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    role = db.relationship('Role', backref='history')
    user = db.relationship('User', backref='role_changes')
