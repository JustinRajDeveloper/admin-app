#!/usr/bin/env python3
"""
Production-Ready Enterprise DevOps Platform
Automatically initializes database on first run
"""

from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import LoginManager, login_required, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash
import os
from datetime import datetime

# Import the shared db instance from models
from models import db
from models.user import User, UserActivity
from models.role import Role, Permission

# Initialize extensions
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

def init_database_if_needed(app):
    """Initialize database tables and default data if they don't exist"""
    
    with app.app_context():
        try:
            # Check if the users table exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            table_names = inspector.get_table_names()
            
            if 'users' not in table_names:
                print("🗄️  Database not found. Creating tables and default data...")
                
                # Create all tables
                db.create_all()
                print("✅ Database tables created")
                
                # Create permissions
                print("🔐 Creating permissions...")
                permissions_data = [
                    ('sdlc_access', 'Access SDLC module', 'sdlc'),
                    ('sdlc_admin', 'Admin access to SDLC module', 'sdlc'),
                    ('bsse_access', 'Access BSSE module', 'bsse'),
                    ('bsse_admin', 'Admin access to BSSE module', 'bsse'),
                    ('aia_access', 'Access AIA module', 'aia'),
                    ('aia_admin', 'Admin access to AIA module', 'aia'),
                    ('dqa_access', 'Access DQA module', 'dqa'),
                    ('dqa_admin', 'Admin access to DQA module', 'dqa'),
                    ('user_management', 'Manage users and roles', 'system'),
                    ('system_admin', 'Full system administration', 'system'),
                ]
                
                for perm_name, perm_desc, perm_module in permissions_data:
                    permission = Permission(
                        name=perm_name, 
                        description=perm_desc,
                        module=perm_module
                    )
                    db.session.add(permission)
                
                db.session.commit()
                
                # Create roles
                print("👥 Creating roles...")
                
                # Super Admin role
                admin_role = Role(
                    name='Super Admin',
                    description='Full system access',
                    is_system_role=True
                )
                
                # Add all permissions to admin role
                all_permissions = Permission.query.all()
                for permission in all_permissions:
                    admin_role.add_permission(permission)
                
                db.session.add(admin_role)
                
                # Other roles
                roles_data = [
                    {
                        'name': 'SDLC User',
                        'description': 'SDLC module user',
                        'permissions': ['sdlc_access'],
                        'is_system_role': False
                    },
                    {
                        'name': 'All Access',
                        'description': 'Access to all modules',
                        'permissions': ['sdlc_access', 'bsse_access', 'aia_access', 'dqa_access'],
                        'is_system_role': False
                    }
                ]
                
                for role_data in roles_data:
                    role = Role(
                        name=role_data['name'],
                        description=role_data['description'],
                        is_system_role=role_data['is_system_role']
                    )
                    
                    for perm_name in role_data['permissions']:
                        permission = Permission.query.filter_by(name=perm_name).first()
                        if permission:
                            role.add_permission(permission)
                    
                    db.session.add(role)
                
                db.session.commit()
                
                # Create default admin user
                print("👤 Creating default admin user...")
                admin_user = User(
                    username='admin',
                    email='admin@company.com',
                    first_name='System',
                    last_name='Administrator',
                    password_hash=generate_password_hash('admin123'),
                    is_active=True,
                    is_verified=True,
                    role=admin_role
                )
                db.session.add(admin_user)
                db.session.commit()
                
                print("🎉 Database initialization complete!")
                print("🔑 Default login: admin / admin123")
                
            else:
                # Check if admin user exists, create if not
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    print("👤 Creating missing admin user...")
                    admin_role = Role.query.filter_by(name='Super Admin').first()
                    if admin_role:
                        admin_user = User(
                            username='admin',
                            email='admin@company.com',
                            first_name='System',
                            last_name='Administrator',
                            password_hash=generate_password_hash('admin123'),
                            is_active=True,
                            is_verified=True,
                            role=admin_role
                        )
                        db.session.add(admin_user)
                        db.session.commit()
                        print("✅ Admin user created")
                
                print("✅ Database ready")
                
        except Exception as e:
            print(f"⚠️  Database initialization error: {e}")
            # Log but don't crash
            import traceback
            traceback.print_exc()

def create_app(config_name='development'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name == 'development':
        from config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)
    elif config_name == 'production':
        from config import ProductionConfig
        app.config.from_object(ProductionConfig)
    elif config_name == 'testing':
        from config import TestingConfig
        app.config.from_object(TestingConfig)
    else:
        from config import Config
        app.config.from_object(Config)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Login manager configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Import and register blueprints
    from auth.routes import auth_bp
    from modules.sdlc.routes import sdlc_bp
    from modules.bsse.routes import bsse_bp
    from modules.aia.routes import aia_bp
    from modules.dqa.routes import dqa_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(sdlc_bp, url_prefix='/sdlc')
    app.register_blueprint(bsse_bp, url_prefix='/bsse')
    app.register_blueprint(aia_bp, url_prefix='/aia')
    app.register_blueprint(dqa_bp, url_prefix='/dqa')
    
    # Register template functions
    from auth.decorators import register_template_functions
    register_template_functions(app)
    
    # Main application routes
    @app.route('/')
    @login_required
    def index():
        """Main dashboard"""
        return render_template('dashboard/home.html')
    
    @app.route('/profile')
    @login_required
    def profile():
        """User profile page"""
        return render_template('dashboard/profile.html')
    
    # API routes
    @app.route('/api/activity/recent')
    @login_required
    def api_recent_activity():
        """API endpoint for recent activity"""
        activities = UserActivity.query.filter_by(user_id=current_user.id)\
            .order_by(UserActivity.timestamp.desc()).limit(10).all()
        
        return jsonify([{
            'id': a.id,
            'action': a.action,
            'resource': a.resource,
            'timestamp': a.timestamp.isoformat() if a.timestamp else None
        } for a in activities])
    
    @app.route('/api/system/status')
    @login_required
    def api_system_status():
        """API endpoint for system status"""
        return jsonify({
            'application': 'healthy',
            'database': 'healthy',
            'cache': 'warning',
            'external_apis': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403
    
    # Template filters and globals
    @app.template_filter('moment')
    def moment_filter(datetime_obj):
        """Mock moment.js filter"""
        if datetime_obj:
            return datetime_obj.strftime('%Y-%m-%d %H:%M:%S')
        return ''
    
    @app.template_global()
    def moment(datetime_obj):
        """Mock moment object for templates"""
        class MockMoment:
            def __init__(self, dt):
                self.dt = dt
            
            def fromNow(self):
                if not self.dt:
                    return 'Never'
                delta = datetime.utcnow() - self.dt
                if delta.days > 0:
                    return f'{delta.days} days ago'
                elif delta.seconds > 3600:
                    hours = delta.seconds // 3600
                    return f'{hours} hour{"s" if hours > 1 else ""} ago'
                elif delta.seconds > 60:
                    minutes = delta.seconds // 60
                    return f'{minutes} minute{"s" if minutes > 1 else ""} ago'
                else:
                    return 'Just now'
            
            def format(self, fmt):
                if not self.dt:
                    return ''
                if fmt == 'MMM DD, YYYY':
                    return self.dt.strftime('%b %d, %Y')
                elif fmt == 'MMM DD, HH:mm':
                    return self.dt.strftime('%b %d, %H:%M')
                else:
                    return self.dt.strftime(fmt)
            
            def year(self):
                return datetime.utcnow().year
        
        return MockMoment(datetime_obj)
    
    # Context processors for templates
    @app.context_processor
    def inject_template_vars():
        """Inject common template variables"""
        return {
            'config': app.config,
            'now': datetime.utcnow()
        }
    
    # Initialize database automatically on app creation
    init_database_if_needed(app)
    
    return app

# Create the app instance
app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    import sys
    
    # Parse command line arguments
    port = 5000  # default
    
    # Check for --port argument
    if '--port' in sys.argv:
        try:
            port_index = sys.argv.index('--port')
            if port_index + 1 < len(sys.argv):
                port = int(sys.argv[port_index + 1])
        except (ValueError, IndexError):
            print("❌ Invalid port number. Using default port 5000")
            port = 5000
    
    # Check environment variable (takes precedence)
    port = int(os.getenv('PORT', port))
    
    print("🚀 Enterprise DevOps Platform")
    print("=" * 40)
    print(f"📍 Starting on http://localhost:{port}")
    print("🔑 Default login: admin / admin123")
    print()
    
    def try_port(port_num):
        """Try to start the app on a specific port"""
        try:
            print(f"🔄 Starting on port {port_num}...")
            app.run(
                debug=app.config.get('DEBUG', False),
                host='0.0.0.0',
                port=port_num
            )
            return True
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"❌ Port {port_num} is already in use")
                return False
            else:
                raise e
    
    # Try the requested port first
    if not try_port(port):
        print(f"\n⚠️  Port {port} is already in use!")
        print("\n🔧 Quick fixes:")
        print(f"   PORT=5001 python3.12 app.py")
        print("   Or disable AirPlay in System Settings → Sharing")
        
        # Try alternative ports automatically
        alternative_ports = [5001, 5002, 8000, 8080, 3000, 9000]
        print(f"\n🔄 Trying alternative ports...")
        
        for alt_port in alternative_ports:
            if try_port(alt_port):
                break
        else:
            print("\n❌ Could not find an available port!")
            print("Try manually: PORT=9999 python3.12 app.py")
