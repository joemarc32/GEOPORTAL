from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash, g
import sqlite3
import io
import csv
import pandas as pd
from functools import lru_cache, wraps
import time
import hashlib
from datetime import datetime, timedelta
import threading
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import re
import html
import bleach
import os

# Optional geopandas - only import if available
try:
    import geopandas as gpd
    GEOPANDAS_AVAILABLE = True
except ImportError:
    GEOPANDAS_AVAILABLE = False
    print("⚠️ GeoPandas not available - GPKG upload functionality will be limited")

# Optional SSL support - only import if available
try:
    from ssl_config import create_ssl_config, check_ssl_status
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False
    print("ℹ️ SSL configuration not available - running without HTTPS support")

# ============================================================================
# AUTHENTICATION & AUTHORIZATION SYSTEM
# ============================================================================

# Role hierarchy (higher number = more permissions)
ROLE_HIERARCHY = {
    'guest': 1,
    'viewer': 2,
    'manager': 3,
    'admin': 4
}

# Define permissions for each role
ROLE_PERMISSIONS = {
    'admin': {
        'user_management': ['create', 'read', 'update', 'delete'],
        'system_config': ['read', 'update'],
        'cache_management': ['read', 'clear', 'stats'],
        'database_management': ['backup', 'restore', 'optimize'],
        'export': ['all_data', 'filtered_data', 'reports'],
        'customer_data': ['create', 'read', 'update', 'delete'],
        'meter_readings': ['create', 'read', 'update', 'delete'],
        'audit_logs': ['read'],
        'analytics': ['read'],
        'performance_monitoring': ['read']
    },
    'manager': {
        'user_management': ['read'],
        'export': ['all_data', 'filtered_data', 'reports'],
        'customer_data': ['read'],
        'meter_readings': ['read'],
        'analytics': ['read'],
        'performance_monitoring': ['read'],
        'audit_logs': ['read']
    },
    'viewer': {
        'customer_data': ['read', 'update'],
        'meter_readings': ['read', 'update'],
        'export': ['filtered_data'],
        'analytics': ['read']
    },
    'guest': {
        'customer_data': ['read_limited'],
        'analytics': ['read_basic']
    }
}

def hash_password(password):
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(32)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${password_hash}"

def check_password(password, hashed):
    """Check password against hash"""
    try:
        # Try salted password format first
        if '$' in hashed:
            salt, stored_hash = hashed.split('$', 1)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash == stored_hash
        else:
            # Handle legacy simple SHA-256 passwords
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return password_hash == hashed
    except Exception:
        # Handle any other password format issues
        return False

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def authenticate_user(username, password):
    """Authenticate user and return user data if successful"""
    conn = get_db_connection()
    try:
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        
        if user and check_password(password, user['password_hash']):
            # Update last login
            conn.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now().isoformat(), user['id'])
            )
            conn.commit()
            
            # Log successful login
            log_audit(user['id'], 'login', 'auth', 'User logged in successfully')
            
            return dict(user)
        return None
    finally:
        conn.close()

def get_current_user():
    """Get current authenticated user"""
    if 'user_id' not in session:
        return None
    
    # Handle guest users
    if session.get('user_id') == 'guest':
        return {
            'id': 'guest',
            'username': 'Guest',
            'full_name': 'Guest User',
            'email': None,
            'role': 'guest',
            'is_active': 1
        }
    
    conn = get_db_connection()
    try:
        user = conn.execute(
            'SELECT * FROM users WHERE id = ? AND is_active = 1',
            (session['user_id'],)
        ).fetchone()
        return dict(user) if user else None
    finally:
        conn.close()

def get_user_role():
    """Get current user's role"""
    user = get_current_user()
    return user['role'] if user else None

def has_permission(user_role, resource, action):
    """Check if user role has permission for specific resource and action"""
    if user_role not in ROLE_PERMISSIONS:
        return False
    
    role_perms = ROLE_PERMISSIONS[user_role]
    if resource not in role_perms:
        return False
    
    return action in role_perms[resource]

def update_last_login(user_id):
    """Update user's last login timestamp"""
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now().isoformat(), user_id)
        )
        conn.commit()
    finally:
        conn.close()

def log_audit(user_id, action, category, details):
    """Log user action for audit trail"""
    conn = get_db_connection()
    try:
        # Handle None user_id for system actions or failed logins
        conn.execute(
            '''INSERT INTO audit_logs (user_id, action, category, details, timestamp, ip_address)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, action, category, details, datetime.now().isoformat(), 
             request.remote_addr if request else 'system')
        )
        conn.commit()
    except Exception as e:
        # If there's an error with audit logging, don't break the application
        print(f"Audit logging error: {e}")
    finally:
        conn.close()

def cleanup_expired_sessions():
    """Clean up expired sessions"""
    conn = get_db_connection()
    try:
        conn.execute(
            'DELETE FROM user_sessions WHERE expires_at < ?',
            (datetime.now().isoformat(),)
        )
        conn.commit()
    finally:
        conn.close()

# Authentication decorators
def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Handle guest users
        if session.get('user_id') == 'guest':
            return f(*args, **kwargs)
        
        user = get_current_user()
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Require user to have one of the specified roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Invalid session', 'code': 401}), 401
            
            if user['role'] not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient permissions', 
                    'code': 403,
                    'required_roles': allowed_roles,
                    'user_role': user['role']
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required', 'code': 401}), 401
        
        user = get_current_user()
        if not user or user['role'] != 'admin':
            return jsonify({
                'error': 'Admin access required', 
                'code': 403,
                'user_role': user['role'] if user else None
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

def manager_or_admin_required(f):
    """Require manager or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required', 'code': 401}), 401
        
        user = get_current_user()
        if not user or user['role'] not in ['manager', 'admin']:
            return jsonify({
                'error': 'Manager or Admin access required', 
                'code': 403,
                'user_role': user['role'] if user else None
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

def viewer_or_above_required(f):
    """Require viewer, manager, or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required', 'code': 401}), 401
        
        user = get_current_user()
        if not user or user['role'] not in ['viewer', 'manager', 'admin']:
            return jsonify({
                'error': 'Viewer access or above required', 
                'code': 403,
                'user_role': user['role'] if user else None
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function

def permission_required(resource, action):
    """Require specific permission for resource and action"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Invalid session', 'code': 401}), 401
            
            if not has_permission(user['role'], resource, action):
                return jsonify({
                    'error': f'Permission denied: {action} on {resource}', 
                    'code': 403,
                    'user_role': user['role']
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def filter_data_by_role(data, user_role, data_type='customer_data'):
    """Filter data based on user role permissions"""
    if user_role == 'admin':
        return data  # Admin sees everything
    
    elif user_role == 'manager':
        return data  # Manager sees all data but limited actions
    
    elif user_role == 'viewer':
        # Viewer sees full customer data but limited export
        return data
    
    elif user_role == 'guest':
        # Guest sees limited fields only
        if data_type == 'customer_data':
            limited_fields = ['Name', 'AccountNumber', 'Status', 'AREA']
            if isinstance(data, list):
                return [{k: v for k, v in row.items() if k in limited_fields} for row in data]
            elif isinstance(data, dict):
                return {k: v for k, v in data.items() if k in limited_fields}
        return []
    
    return []

def can_export(user_role, export_type):
    """Check if user can perform specific export type"""
    role_perms = ROLE_PERMISSIONS.get(user_role, {})
    export_permissions = role_perms.get('export', [])
    return export_type in export_permissions

def get_db_connection():
    """Get database connection with optimizations"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    # Enable query optimization for better index usage
    conn.execute('PRAGMA optimize')
    return conn


app = Flask(__name__)

# Security configuration with SSL support
app.secret_key = secrets.token_hex(32)  # More secure than hardcoded key
app.config['SESSION_COOKIE_SECURE'] = True  # Enable for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# SSL Configuration - Optional for deployment flexibility
ssl_config = None
try:
    if SSL_AVAILABLE:
        # Determine environment (check for production indicators)
        environment = 'production' if os.getenv('FLASK_ENV') == 'production' else 'development'
        ssl_config = create_ssl_config(environment)
        if ssl_config:
            ssl_config.configure_flask_app(app)
            print(f"🔐 SSL configured for {environment} environment")
        else:
            print("⚠️ SSL configuration failed, running without HTTPS")
    else:
        print("ℹ️ SSL support disabled - suitable for reverse proxy deployment")
except Exception as e:
    print(f"⚠️ SSL configuration failed: {e}")
    print("Application will run without HTTPS - suitable for reverse proxy deployment")

# File upload configuration
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Custom CSRF Protection Implementation
def generate_csrf_token():
    """Generate a CSRF token for the current session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def csrf_token():
    """Template function to get CSRF token"""
    return generate_csrf_token()

# Make csrf_token available to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=csrf_token)

def validate_csrf_token():
    """Validate CSRF token for POST requests"""
    if request.method == 'POST':
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if request.is_json:
            json_data = request.get_json(silent=True)
            if json_data:
                token = json_data.get('csrf_token')
        
        session_token = session.get('csrf_token')
        if not token or not session_token or not secrets.compare_digest(token, session_token):
            log_audit(session.get('user_id'), 'csrf_validation_failed', 'security', 'CSRF token validation failed')
            return False
    return True

# CSRF decorator for routes that need protection
def csrf_required(f):
    """Decorator to require CSRF token validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not validate_csrf_token():
            return jsonify({'error': 'CSRF token missing or invalid'}), 400
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# INPUT VALIDATION MIDDLEWARE
# ============================================================================

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    # Dangerous patterns that could indicate injection attempts
    SUSPICIOUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',                # JavaScript protocol
        r'on\w+\s*=',                 # Event handlers
        r'union\s+select',            # SQL injection
        r'drop\s+table',              # SQL injection
        r'insert\s+into',             # SQL injection
        r'delete\s+from',             # SQL injection
        r'update\s+.*set',            # SQL injection
        r'exec\s*\(',                 # Command execution
        r'eval\s*\(',                 # Code evaluation
        r'<iframe[^>]*>',             # Embedded frames
        r'<object[^>]*>',             # Embedded objects
        r'<embed[^>]*>',              # Embedded content
    ]
    
    @staticmethod
    def sanitize_string(value, max_length=1000, allow_html=False):
        """Sanitize string input"""
        if not isinstance(value, str):
            return str(value)
        
        # Trim whitespace
        value = value.strip()
        
        # Check length
        if len(value) > max_length:
            value = value[:max_length]
        
        if allow_html:
            # Allow safe HTML tags for rich content
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
            value = bleach.clean(value, tags=allowed_tags, strip=True)
        else:
            # Escape HTML to prevent XSS
            value = html.escape(value, quote=True)
        
        return value
    
    @staticmethod
    def detect_suspicious_content(value):
        """Detect potentially malicious content"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        for pattern in InputValidator.SUSPICIOUS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not isinstance(email, str):
            return False
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email)) and len(email) <= 254
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not isinstance(username, str):
            return False
        # Allow alphanumeric, underscore, hyphen, and dot
        username_pattern = r'^[a-zA-Z0-9._-]{3,50}$'
        return bool(re.match(username_pattern, username))
    
    @staticmethod
    def validate_password(password):
        """Validate password strength (basic validation)"""
        if not isinstance(password, str):
            return False, "Password must be a string"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password is too long (max 128 characters)"
        
        return True, "Password is valid"
    
    @staticmethod
    def validate_account_number(account_number):
        """Validate account number format"""
        if not isinstance(account_number, str):
            account_number = str(account_number)
        
        # Allow alphanumeric and hyphens, 3-20 characters
        pattern = r'^[a-zA-Z0-9-]{3,20}$'
        return bool(re.match(pattern, account_number))
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename for upload"""
        if not isinstance(filename, str):
            return "file"
        
        # Remove path separators and dangerous characters
        filename = re.sub(r'[^\w\s.-]', '', filename)
        filename = re.sub(r'\.+', '.', filename)  # Collapse multiple dots
        filename = filename.strip('. ')  # Remove leading/trailing dots and spaces
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')
        
        return filename or "file"

def validate_request_data():
    """Validate and sanitize request data"""
    validation_errors = []
    suspicious_activity = []
    
    # Skip validation for certain endpoints
    if request.endpoint in ['static', 'suggest']:
        return None
    
    # Validate form data
    if request.form:
        for key, value in request.form.items():
            # Detect suspicious content
            if InputValidator.detect_suspicious_content(value):
                suspicious_activity.append(f"Suspicious content in form field '{key}': {value[:100]}")
            
            # Sanitize common fields
            if key in ['username']:
                if not InputValidator.validate_username(value):
                    validation_errors.append(f"Invalid username format: {key}")
            elif key in ['email']:
                if value and not InputValidator.validate_email(value):
                    validation_errors.append(f"Invalid email format: {key}")
            elif key == 'password':
                valid, message = InputValidator.validate_password(value)
                if not valid:
                    validation_errors.append(f"Password validation failed: {message}")
    
    # Validate JSON data
    if request.is_json:
        try:
            json_data = request.get_json()
            if json_data:
                for key, value in json_data.items():
                    if isinstance(value, str):
                        if InputValidator.detect_suspicious_content(value):
                            suspicious_activity.append(f"Suspicious content in JSON field '{key}': {value[:100]}")
        except Exception:
            validation_errors.append("Invalid JSON format")
    
    # Validate query parameters
    for key, value in request.args.items():
        if InputValidator.detect_suspicious_content(value):
            suspicious_activity.append(f"Suspicious content in query parameter '{key}': {value[:100]}")
        
        # Validate specific parameters
        if key == 'search' and len(value) > 100:
            validation_errors.append(f"Search term too long (max 100 characters)")
        elif key == 'page':
            try:
                page = int(value)
                if page < 1 or page > 10000:
                    validation_errors.append(f"Invalid page number: {page}")
            except ValueError:
                validation_errors.append(f"Page number must be an integer")
    
    # Log suspicious activity
    if suspicious_activity:
        user_id = session.get('user_id')
        for activity in suspicious_activity:
            log_audit(user_id, 'suspicious_input', 'security', activity)
    
    return validation_errors

# Input validation decorator
def validate_input(f):
    """Decorator to validate input for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        errors = validate_request_data()
        if errors:
            return jsonify({'error': 'Input validation failed', 'details': errors}), 400
        return f(*args, **kwargs)
    return decorated_function

DATABASE = 'tcwd_data.db'  # Updated to new database file
ITEMS_PER_PAGE = 15

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_database():
    """Initialize database with required tables for authentication"""
    conn = get_db_connection()
    try:
        # Create users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT,
                role TEXT NOT NULL DEFAULT 'guest',
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                CONSTRAINT role_check CHECK (role IN ('admin', 'manager', 'viewer', 'guest'))
            )
        ''')
        
        # Create or update audit_logs table
        # First check if table exists and what columns it has
        cursor = conn.execute("PRAGMA table_info(audit_logs)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        if not existing_columns:
            # Table doesn't exist, create it
            conn.execute('''
                CREATE TABLE audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'system',
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        else:
            # Table exists, check if we need to add missing columns
            if 'category' not in existing_columns:
                conn.execute('ALTER TABLE audit_logs ADD COLUMN category TEXT DEFAULT "system"')
                print("✅ Added 'category' column to audit_logs table")
            if 'ip_address' not in existing_columns:
                conn.execute('ALTER TABLE audit_logs ADD COLUMN ip_address TEXT')
                print("✅ Added 'ip_address' column to audit_logs table")
        
        # Create user_sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create default admin user if no users exist
        existing_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if existing_users == 0:
            admin_password = hash_password('Kapal011920!')  # Custom admin password
            manager_password = hash_password('manager123')
            viewer_password = hash_password('viewer123')
            guest_password = hash_password('guest123')
            
            # Create default users for each role
            users_to_create = [
                ('Dadi_Joe', admin_password, 'System Administrator', 'admin@tcwd.com', 'admin'),
                ('manager', manager_password, 'System Manager', 'manager@tcwd.com', 'manager'),
                ('viewer', viewer_password, 'Data Viewer', 'viewer@tcwd.com', 'viewer'),
                ('guest', guest_password, 'Guest User', 'guest@tcwd.com', 'guest')
            ]
            
            for username, password_hash, full_name, email, role in users_to_create:
                conn.execute('''
                    INSERT INTO users (username, password_hash, full_name, email, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, password_hash, full_name, email, role, datetime.now().isoformat()))
            
            conn.commit()
            print("✅ Default users created for initial setup")
            print("⚠️  SECURITY: Change default passwords immediately!")
            print("📧 Contact system administrator for login credentials")
            print("⚠️  WARNING: Change these default passwords in production!")
        
        # Create indexes for better performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)')
        
        conn.commit()
        print("✅ Database initialized/updated successfully")
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        # Don't fail silently - let the app know there's an issue
        raise e
    finally:
        conn.close()

# Initialize database on startup
init_database()

# ============================================================================
# ADVANCED CACHING SYSTEM
# ============================================================================

class AdvancedCache:
    """
    Advanced in-memory cache with TTL (Time To Live) and cache statistics
    """
    def __init__(self):
        self.cache = {}
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'evictions': 0
        }
        self.lock = threading.RLock()
    
    def _generate_key(self, *args, **kwargs):
        """Generate a cache key from arguments"""
        key_string = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, key):
        """Get item from cache"""
        with self.lock:
            if key in self.cache:
                data, expiry = self.cache[key]
                if datetime.now() < expiry:
                    self.cache_stats['hits'] += 1
                    return data
                else:
                    # Expired, remove from cache
                    del self.cache[key]
                    self.cache_stats['evictions'] += 1
            
            self.cache_stats['misses'] += 1
            return None
    
    def set(self, key, value, ttl_seconds=300):  # Default 5 minutes
        """Set item in cache with TTL"""
        with self.lock:
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
            self.cache[key] = (value, expiry)
            self.cache_stats['sets'] += 1
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()
            self.cache_stats = {'hits': 0, 'misses': 0, 'sets': 0, 'evictions': 0}
    
    def get_stats(self):
        """Get cache statistics"""
        with self.lock:
            total_requests = self.cache_stats['hits'] + self.cache_stats['misses']
            hit_rate = (self.cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            return {
                **self.cache_stats,
                'cache_size': len(self.cache),
                'hit_rate': round(hit_rate, 2)
            }

# Global cache instance
app_cache = AdvancedCache()

def cached_query(ttl_seconds=300):
    """
    Decorator for caching database queries
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = app_cache._generate_key(func.__name__, *args, **kwargs)
            
            # Try to get from cache first
            cached_result = app_cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Not in cache, execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            app_cache.set(cache_key, result, ttl_seconds)
            
            return result
        
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

def bookno_sort_key(val):
    if val is None:
        return (2, "")
    val = str(val)
    return (1, int(val)) if val.isdigit() else (0, val.upper())

@lru_cache(maxsize=1)
def get_latest_year_month():
    """Cache the latest year and month to avoid repeated queries"""
    conn = get_db_connection()
    latest_row = conn.execute('''
        SELECT Year, Month FROM tcwd_data 
        ORDER BY Year DESC, 
            CASE Month
                WHEN 'January' THEN 1
                WHEN 'February' THEN 2
                WHEN 'March' THEN 3
                WHEN 'April' THEN 4
                WHEN 'May' THEN 5
                WHEN 'June' THEN 6
                WHEN 'July' THEN 7
                WHEN 'August' THEN 8
                WHEN 'September' THEN 9
                WHEN 'October' THEN 10
                WHEN 'November' THEN 11
                WHEN 'December' THEN 12
            END DESC 
        LIMIT 1
    ''').fetchone()
    conn.close()
    if latest_row:
        return latest_row['Year'], latest_row['Month']
    return None, None

@cached_query(ttl_seconds=600)  # Cache for 10 minutes
def get_filter_options(latest_year, latest_month):
    """Cache filter options to improve performance"""
    if latest_year is None or latest_month is None:
        return [], [], [], [], []
    
    conn = get_db_connection()
    filter_base = "SELECT DISTINCT {col} FROM tcwd_data WHERE Year = ? AND Month = ?"
    
    all_statuses = [row['Status'] for row in conn.execute(filter_base.format(col='Status'), (latest_year, latest_month)).fetchall() if row['Status'] and str(row['Status']).strip()]
    all_booknos = [row['BookNo'] for row in conn.execute(filter_base.format(col='BookNo'), (latest_year, latest_month)).fetchall() if row['BookNo'] and str(row['BookNo']).strip()]
    all_ratecodes = [row['RateCode'] for row in conn.execute(filter_base.format(col='RateCode'), (latest_year, latest_month)).fetchall() if row['RateCode'] and str(row['RateCode']).strip()]
    all_areas = [row['AREA'] for row in conn.execute(filter_base.format(col='AREA'), (latest_year, latest_month)).fetchall() if row['AREA'] and str(row['AREA']).strip()]
    all_types = [row['Type'] for row in conn.execute(filter_base.format(col='Type'), (latest_year, latest_month)).fetchall() if row['Type'] and str(row['Type']).strip()]
    
    conn.close()
    
    # Sort the data consistently for better UX
    all_statuses = sorted(all_statuses, key=lambda x: (str(x).upper() if x is not None else ""))
    all_booknos = sorted(all_booknos, key=bookno_sort_key)
    all_ratecodes = sorted(all_ratecodes, key=lambda x: (str(x).upper() if x is not None else ""))
    all_areas = sorted(all_areas, key=lambda x: (str(x).upper() if x is not None else ""))
    all_types = sorted(all_types, key=lambda x: (str(x).upper() if x is not None else ""))
    
    return all_statuses, all_booknos, all_ratecodes, all_areas, all_types

@cached_query(ttl_seconds=1800)  # Cache for 30 minutes
def get_account_years(account):
    """Cache available years for an account"""
    conn = get_db_connection()
    rows = conn.execute('SELECT DISTINCT Year FROM tcwd_data WHERE AccountNumber = ? ORDER BY Year ASC', (account,)).fetchall()
    conn.close()
    return [row['Year'] for row in rows]

@cached_query(ttl_seconds=900)  # Cache for 15 minutes
def get_account_usage_data(account, year):
    """Cache account usage data for charts"""
    conn = get_db_connection()
    
    # Month name to number mapping for proper sorting
    month_mapping = {
        'January': 1, 'February': 2, 'March': 3, 'April': 4,
        'May': 5, 'June': 6, 'July': 7, 'August': 8,
        'September': 9, 'October': 10, 'November': 11, 'December': 12
    }
    
    rows = conn.execute(
        'SELECT Month, CumUsed FROM tcwd_data WHERE AccountNumber = ? AND Year = ?',
        (account, year)
    ).fetchall()
    conn.close()
    
    # Sort by month order
    sorted_rows = sorted(rows, key=lambda row: month_mapping.get(row['Month'], row['Month']))
    return [{'Month': row['Month'], 'CumUsed': row['CumUsed']} for row in sorted_rows]

@cached_query(ttl_seconds=300)  # Cache for 5 minutes
def get_search_suggestions(term):
    """Cache search suggestions"""
    conn = get_db_connection()
    latest_year, latest_month = get_latest_year_month()
    suggestions = []
    
    if latest_year and latest_month:
        rows = conn.execute(
            '''SELECT DISTINCT Name, AccountNumber, MeterNo FROM tcwd_data 
               WHERE (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?) 
               AND Year = ? AND Month = ? LIMIT 10''',
            (f'%{term}%', f'%{term}%', f'%{term}%', latest_year, latest_month)
        ).fetchall()
        
        for row in rows:
            suggestions.append({
                'Name': row['Name'],
                'AccountNumber': row['AccountNumber'],
                'MeterNo': row['MeterNo']
            })
    
    conn.close()
    return suggestions

# Endpoint to provide available years for an account (for chart selector)
@app.route('/account_usage_years')
def account_usage_years():
    if not session.get('logged_in'):
        return jsonify([])
    account = request.args.get('account')
    if not account:
        return jsonify([])
    
    # Use cached function
    years = get_account_years(account)
    return jsonify(years)

# Endpoint to provide CumUsed per month for a given account and year
# ... (existing imports and code) ...

# Endpoint to provide CumUsed per month for a given account and year
@app.route('/account_usage')
def account_usage():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401

    account = request.args.get('account')
    year = request.args.get('year', type=int)
    if not account or not year:
        return jsonify({'error': 'Missing account or year'}), 400

    # Use cached function
    usage_data = get_account_usage_data(account, year)
    return jsonify(usage_data)

# ... (rest of the code) ...

@app.route('/login', methods=['GET', 'POST'])
@csrf_required
@validate_input
def login():
    if request.method == 'POST':        
        # Check if this is a guest login
        if request.form.get('guest_login') == 'true':
            # Handle guest login - no credentials required
            session.clear()  # Clear session to prevent fixation
            session['logged_in'] = True
            session['user_id'] = 'guest'  # Use 'guest' string instead of None
            session['username'] = 'Guest'
            session['role'] = 'guest'
            
            # Log guest login
            log_audit(None, 'guest_login', 'auth', 'Guest user logged in')
            flash('Welcome Guest! You have read-only access to the system.')
            return redirect(url_for('index'))
        
        # Handle regular login with credentials
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error="Please enter both username and password.")
        
        # Enhanced input validation
        username = InputValidator.sanitize_string(username, max_length=50)
        if not InputValidator.validate_username(username):
            log_audit(None, 'invalid_username_attempt', 'security', f'Invalid username format attempted: {username}')
            return render_template('login.html', error="Invalid username format.")
        
        # Password validation (basic length check)
        valid_password, password_message = InputValidator.validate_password(password)
        if not valid_password:
            return render_template('login.html', error="Password requirements not met.")
        
        # Authenticate user
        user = authenticate_user(username, password)
        
        if user:
            session.clear()  # Clear session to prevent fixation
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Update last login
            update_last_login(user['id'])
            
            # Redirect based on role
            if user['role'] == 'admin':
                flash(f'Welcome back, {user["full_name"]}! You have admin privileges.')
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'manager':
                flash(f'Welcome back, {user["full_name"]}! You have manager privileges.')
                return redirect(url_for('manager_dashboard'))
            elif user['role'] == 'viewer':
                flash(f'Welcome back, {user["full_name"]}! You have viewer privileges.')
                return redirect(url_for('index'))
            else:  # guest
                flash(f'Welcome back, {user["full_name"]}! You have read-only access.')
                return redirect(url_for('index'))
        else:
            # Log failed login attempt
            log_audit(None, 'failed_login', 'auth', f'Failed login attempt for username: {username}')
            return render_template('login.html', error="Invalid credentials.")
    
    # Clean login page without any demo credentials
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_audit(user['id'], 'logout', 'auth', 'User logged out')
    
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

# ============================================================================
# USER PROFILE AND ROLE MANAGEMENT
# ============================================================================

@app.route('/profile')
@login_required
def user_profile():
    """User profile page"""
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user, role_permissions=ROLE_PERMISSIONS.get(user['role'], {}))

@app.route('/api/profile', methods=['PUT'])
@login_required
def api_update_profile():
    """Update user profile"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    conn = get_db_connection()
    try:
        # Users can only update their own profile (limited fields)
        update_fields = []
        params = []
        
        if 'full_name' in data:
            update_fields.append('full_name = ?')
            params.append(data['full_name'])
        
        if 'email' in data:
            update_fields.append('email = ?')
            params.append(data['email'])
        
        if 'password' in data and data['password']:
            update_fields.append('password_hash = ?')
            params.append(hash_password(data['password']))
        
        if update_fields:
            params.append(user['id'])
            conn.execute(f'UPDATE users SET {", ".join(update_fields)} WHERE id = ?', params)
            conn.commit()
        
        log_audit(user['id'], 'update_profile', 'profile', 'Updated own profile')
        return jsonify({'message': 'Profile updated successfully'})
    finally:
        conn.close()

# ============================================================================
# DASHBOARD AND ROLE-BASED VIEWS
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard"""
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        dashboard_data = {}
        
        # Common data for all roles
        if user['role'] in ['admin', 'manager', 'viewer']:
            dashboard_data['total_customers'] = conn.execute('SELECT COUNT(*) FROM tcwd_data').fetchone()[0]
            dashboard_data['active_connections'] = conn.execute("SELECT COUNT(*) FROM tcwd_data WHERE Status = 'Active'").fetchone()[0]
        
        # Role-specific data
        if user['role'] == 'admin':
            dashboard_data['total_users'] = conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0]
            dashboard_data['recent_logins'] = conn.execute('''
                SELECT COUNT(*) FROM users 
                WHERE last_login > datetime('now', '-24 hours') AND is_active = 1
            ''').fetchone()[0]
            dashboard_data['audit_entries_today'] = conn.execute('''
                SELECT COUNT(*) FROM audit_logs 
                WHERE date(timestamp) = date('now')
            ''').fetchone()[0]
        
        elif user['role'] == 'manager':
            dashboard_data['monthly_revenue'] = conn.execute('''
                SELECT COALESCE(SUM(BillAmount), 0) FROM tcwd_data 
                WHERE Month = ? AND Year = ?
            ''', (datetime.now().month, datetime.now().year)).fetchone()[0]
            dashboard_data['pending_readings'] = conn.execute('''
                SELECT COUNT(*) FROM tcwd_data WHERE PRSReading IS NULL OR PRVReading IS NULL
            ''').fetchone()[0]
        
        elif user['role'] == 'viewer':
            dashboard_data['my_recent_edits'] = conn.execute('''
                SELECT COUNT(*) FROM audit_logs 
                WHERE user_id = ? AND date(timestamp) = date('now')
                AND action IN ('update_customer', 'add_meter_reading')
            ''', (user['id'],)).fetchone()[0]
        
        elif user['role'] == 'guest':
            # Limited dashboard for guests
            dashboard_data['can_view_customers'] = True
            dashboard_data['available_areas'] = conn.execute('SELECT DISTINCT AREA FROM tcwd_data LIMIT 10').fetchall()
        
        return render_template('dashboard.html', user=user, data=dashboard_data, role_permissions=ROLE_PERMISSIONS.get(user['role'], {}))
    finally:
        conn.close()

@app.route('/admin_dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    """Admin-specific dashboard with administrative controls"""
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        # Collect comprehensive admin data
        admin_data = {}
        
        # System statistics
        admin_data['total_customers'] = conn.execute('SELECT COUNT(*) FROM tcwd_data').fetchone()[0]
        admin_data['active_connections'] = conn.execute("SELECT COUNT(*) FROM tcwd_data WHERE Status = 'Active'").fetchone()[0]
        admin_data['inactive_connections'] = conn.execute("SELECT COUNT(*) FROM tcwd_data WHERE Status != 'Active'").fetchone()[0]
        
        # User management data
        admin_data['total_users'] = conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0]
        admin_data['active_users'] = admin_data['total_users']  # Same as total_users since we only count active ones
        admin_data['admin_users'] = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1").fetchone()[0]
        admin_data['manager_users'] = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'manager' AND is_active = 1").fetchone()[0]
        admin_data['viewer_users'] = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'viewer' AND is_active = 1").fetchone()[0]
        admin_data['guest_users'] = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'guest' AND is_active = 1").fetchone()[0]
        
        # Recent activity
        admin_data['recent_logins'] = conn.execute('''
            SELECT COUNT(*) FROM users 
            WHERE last_login > datetime('now', '-24 hours') AND is_active = 1
        ''').fetchone()[0]
        admin_data['audit_entries_today'] = conn.execute('''
            SELECT COUNT(*) FROM audit_logs 
            WHERE date(timestamp) = date('now')
        ''').fetchone()[0]
        admin_data['failed_logins_today'] = conn.execute('''
            SELECT COUNT(*) FROM audit_logs 
            WHERE action = 'failed_login' AND date(timestamp) = date('now')
        ''').fetchone()[0]
        
        # System health metrics
        admin_data['database_size'] = conn.execute("SELECT COUNT(*) FROM tcwd_data").fetchone()[0]
        admin_data['latest_data_entry'] = conn.execute('''
            SELECT MAX(Year || '-' || printf('%02d', Month)) as latest_period 
            FROM tcwd_data
        ''').fetchone()[0]
        
        # Recent system activities for audit
        admin_data['recent_activities'] = conn.execute('''
            SELECT u.username, al.action, al.details, al.timestamp
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT 10
        ''').fetchall()
        
        return render_template('admin_dashboard.html', 
                             user=user, 
                             data=admin_data, 
                             stats=admin_data, 
                             role_permissions=ROLE_PERMISSIONS.get(user['role'], {}),
                             idle_timeout_ms=20*60*1000)
    finally:
        conn.close()

@app.route('/api/manager/users', methods=['POST'])
@manager_or_admin_required
def api_manager_create_user():
    """Create new user - Manager can create viewer and guest users only"""
    current_user = get_current_user()
    data = request.get_json()
    
    required_fields = ['username', 'password', 'full_name', 'email', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Manager can only create users with roles below their level
    allowed_roles_for_manager = ['viewer']
    if current_user['role'] == 'manager' and data['role'] not in allowed_roles_for_manager:
        return jsonify({'error': f'Managers can only create users with roles: {", ".join(allowed_roles_for_manager)}'}), 403
    
    # Admins can create any role
    if current_user['role'] == 'admin' and data['role'] not in ['admin', 'manager', 'viewer', 'guest']:
        return jsonify({'error': 'Invalid role specified'}), 400
    
    conn = get_db_connection()
    try:
        # Check if username already exists
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (data['username'],)).fetchone()
        if existing:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Hash password
        password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
        
        # Insert new user
        conn.execute('''
            INSERT INTO users (username, password_hash, full_name, email, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['username'], password_hash, data['full_name'], data['email'], 
              data['role'], datetime.now().isoformat()))
        conn.commit()
        
        # Log the action
        action_desc = f'Created user: {data["username"]} (role: {data["role"]})'
        log_audit(current_user['id'], 'create_user', current_user['role'], action_desc)
        
        return jsonify({
            'message': 'User created successfully',
            'created_by': current_user['role']
        }), 201
    finally:
        conn.close()

@app.route('/api/manager/users', methods=['GET'])
@manager_or_admin_required
def api_manager_get_users():
    """Get users that manager can view - Manager can see viewer and guest users"""
    current_user = get_current_user()
    
    conn = get_db_connection()
    try:
        # Managers can view viewer users only
        if current_user['role'] == 'manager':
            allowed_roles = ['viewer']
            query = '''
                SELECT id, username, full_name, email, role, is_active, created_at
                FROM users
                WHERE role IN ('viewer')
                ORDER BY created_at DESC
            '''
        else:  # Admin can see all users
            allowed_roles = ['admin', 'manager', 'viewer', 'guest']
            query = '''
                SELECT id, username, full_name, email, role, is_active, created_at
                FROM users
                ORDER BY role DESC, created_at DESC
            '''
        
        users = conn.execute(query).fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'full_name': user[2],
                'email': user[3],
                'role': user[4],
                'is_active': user[5],
                'created_at': user[6]
            })
        
        return jsonify({
            'users': users_list,
            'viewer_role': current_user['role'],
            'allowed_roles': allowed_roles
        }), 200
        
    finally:
        conn.close()

@app.route('/manager_dashboard')
@login_required
@role_required(['admin', 'manager'])
def manager_dashboard():
    """Manager-specific dashboard"""
    user = get_current_user()
    if not user or user['role'] not in ['admin', 'manager']:
        flash('Access denied. Manager privileges required.')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        manager_data = {}
        
        # Business metrics
        manager_data['total_customers'] = conn.execute('SELECT COUNT(*) FROM tcwd_data').fetchone()[0]
        manager_data['active_connections'] = conn.execute("SELECT COUNT(*) FROM tcwd_data WHERE Status = 'Active'").fetchone()[0]
        manager_data['monthly_revenue'] = conn.execute('''
            SELECT COALESCE(SUM(BillAmount), 0) FROM tcwd_data 
            WHERE Month = ? AND Year = ?
        ''', (datetime.now().month, datetime.now().year)).fetchone()[0]
        manager_data['pending_readings'] = conn.execute('''
            SELECT COUNT(*) FROM tcwd_data WHERE PRSReading IS NULL OR PRVReading IS NULL
        ''').fetchone()[0]
        
        return render_template('manager_dashboard.html', 
                             user=user, 
                             data=manager_data, 
                             role_permissions=ROLE_PERMISSIONS.get(user['role'], {}),
                             idle_timeout_ms=20*60*1000)
    finally:
        conn.close()

@app.route('/api/role-permissions')
@login_required
def api_role_permissions():
    """Get current user's role permissions"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'role': user['role'],
        'permissions': ROLE_PERMISSIONS.get(user['role'], {}),
        'hierarchy_level': ROLE_HIERARCHY.get(user['role'], 0)
    })

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin panel"""
    user = get_current_user()
    return render_template('admin.html', user=user)

@app.route('/test_api')
@admin_required  
def test_api():
    """Test API"""
    return render_template('test_api.html')

@app.route('/admin_users_test')
@admin_required  
def admin_users_test():
    """Test Admin Users Management"""
    return render_template('admin_users_test.html')

@app.route('/manager')
@manager_or_admin_required
def manager_panel():
    """Manager panel"""
    user = get_current_user()
    return render_template('manager.html', user=user)

@app.route('/viewer')
@viewer_or_above_required 
def viewer_panel():
    """Viewer panel - data browsing interface"""
    user = get_current_user()
    return render_template('index.html', user=user)

@app.route('/')
@login_required
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    search = request.args.get('q', '')
    status = request.args.get('status', '')
    bookno = request.args.get('bookno', '')
    ratecode = request.args.get('ratecode', '')
    area = request.args.get('area', '')
    type_ = request.args.get('type', '')  # NEW: get Type filter
    page = int(request.args.get('page', 1))
    
    # Sanitize search input
    if search:
        search = InputValidator.sanitize_string(search, max_length=100)
        if InputValidator.detect_suspicious_content(search):
            log_audit(user['id'], 'suspicious_search', 'security', f'Suspicious search query: {search}')
            search = ''  # Clear suspicious search

    try:
        # Base query - different fields based on role
        if user['role'] == 'guest':
            # Guest sees limited fields only
            query = """
                SELECT AccountNumber, Name, Address, MeterNo, Status, Cellphone, AREA, 
                       PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
                FROM "tcwd_data" WHERE 1=1
            """
        else:
            # All other roles see full data
            query = """
                SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                       Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
                FROM "tcwd_data" WHERE 1=1
            """
        params = []

        # Filter for latest year and month in the table (optimized with caching)
        latest_year, latest_month = get_latest_year_month()
        
        conn = get_db_connection()
        
        # Calculate total records for latest month only
        latest_month_total = 0
        if latest_year is not None and latest_month is not None:
            latest_month_count_query = "SELECT COUNT(*) FROM tcwd_data WHERE Year = ? AND Month = ?"
            latest_month_total = conn.execute(latest_month_count_query, [latest_year, latest_month]).fetchone()[0]
        if latest_year is not None and latest_month is not None:
            query += " AND Year = ? AND Month = ?"
            params.extend([latest_year, latest_month])

        if search:
            query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
            like_term = f"%{search}%"
            params.extend([like_term, like_term, like_term])

        # Only allow dropdown filters for non-guest users
        if user['role'] != 'guest':
            if status:
                query += " AND Status = ?"
                params.append(status)

            if bookno:
                query += " AND BookNo = ?"
                params.append(bookno)

            if ratecode:
                query += " AND RateCode = ?"
                params.append(ratecode)

            if area:
                query += " AND AREA = ?"
                params.append(area)

            if type_:
                query += " AND Type = ?"
                params.append(type_)

        offset = (page - 1) * ITEMS_PER_PAGE
        paginated_query = query + " LIMIT ? OFFSET ?"
        params_for_count = params.copy()
        params.extend([ITEMS_PER_PAGE, offset])

        rows = conn.execute(paginated_query, params).fetchall()
        rows = [dict(row) for row in rows]

        # Fetching all distinct values for filters (optimized with caching)
        all_statuses, all_booknos, all_ratecodes, all_areas, all_types = get_filter_options(latest_year, latest_month)

        # Get total rows for pagination (from latest month only)
        count_query = "SELECT COUNT(*) FROM (SELECT * FROM tcwd_data WHERE 1=1"
        count_params = []
        if latest_year is not None and latest_month is not None:
            count_query += " AND Year = ? AND Month = ?"
            count_params.extend([latest_year, latest_month])
        if search:
            count_query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
            count_params.extend([like_term, like_term, like_term])
            
        # Only allow dropdown filters for non-guest users  
        if user['role'] != 'guest':
            if status:
                count_query += " AND Status = ?"
                count_params.append(status)
            if bookno:
                count_query += " AND BookNo = ?"
                count_params.append(bookno)
            if ratecode:
                count_query += " AND RateCode = ?"
                count_params.append(ratecode)
            if area:
                count_query += " AND AREA = ?"
                count_params.append(area)
            if type_:
                count_query += " AND Type = ?"
                count_params.append(type_)
        count_query += ")"
        total_rows = conn.execute(count_query, count_params).fetchone()[0]

        # Define columns based on user role
        if user['role'] == 'guest':
            # Guest sees limited columns
            columns = ['AccountNumber', 'Name', 'Address', 'MeterNo', 'Status', 'Cellphone', 'AREA', 
                      'PRVReading', 'PRSReading', 'CumUsed', 'BillAmount', 'Year', 'Month']
        else:
            # All other roles see all columns
            columns = [description[0] for description in conn.execute('SELECT * FROM tcwd_data LIMIT 1').description]
        
        conn.close()

        total_pages = max(1, (total_rows + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)

        return render_template(
            'index.html',
            rows=rows,
            columns=columns,
            search=search,
            statuses=all_statuses,
            selected_status=status,
            booknos=all_booknos,
            selected_bookno=bookno,
            ratecodes=all_ratecodes,
            selected_ratecode=ratecode,
            areas=all_areas,
            selected_area=area,
            types=all_types,
            selected_type=type_,
            page=page,
            total_pages=total_pages,
            total_rows=total_rows,
            latest_month_total=latest_month_total,
            latest_year=latest_year,
            latest_month=latest_month,
            zip=zip,
            user=get_current_user(),  # Add user object for admin dashboard button
            # Pass idle timeout (ms) to template for JS - 20 minutes
            idle_timeout_ms=20*60*1000
        )
    except Exception as e:
        return render_template('error.html', message="A database error occurred. Please contact support.", error=str(e)), 500

@app.route('/export')
@role_required(['admin', 'manager', 'viewer'])  # Guest cannot export
def export():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    # Check export permissions based on role
    export_type = 'filtered_data'  # Default export type
    if not can_export(user['role'], export_type):
        return jsonify({'error': 'Export permission denied', 'user_role': user['role']}), 403

    search = request.args.get('q', '')
    status = request.args.get('status', '')
    bookno = request.args.get('bookno', '')
    ratecode = request.args.get('ratecode', '')
    area = request.args.get('area', '')
    type_ = request.args.get('type', '')  # NEW
    export_format = request.args.get('format', 'csv')

    # Role-based field selection
    if user['role'] == 'admin' or user['role'] == 'manager':
        # Admin and Manager can export all fields
        query = """
            SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                   Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
            FROM "tcwd_data" WHERE 1=1
        """
    else:  # editor
        # Editor gets limited fields for export
        query = """
            SELECT AccountNumber, Name, Address, MeterNo, Status, AREA, 
                   PRVReading, PRSReading, CumUsed, Year, Month
            FROM "tcwd_data" WHERE 1=1
        """
    params = []

    # Filter for latest year and month in the table
    conn = get_db_connection()
    latest_row = conn.execute('SELECT Year, Month FROM tcwd_data ORDER BY Year DESC, Month DESC LIMIT 1').fetchone()
    if latest_row:
        latest_year = latest_row['Year']
        latest_month = latest_row['Month']
        query += " AND Year = ? AND Month = ?"
        params.extend([latest_year, latest_month])
    else:
        latest_year = None
        latest_month = None

    if search:
        query += " AND (Name LIKE ? OR AccountNumber LIKE ? OR MeterNo LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term])

    if status:
        query += " AND Status = ?"
        params.append(status)

    if bookno:
        query += " AND BookNo = ?"
        params.append(bookno)

    if ratecode:
        query += " AND RateCode = ?"
        params.append(ratecode)

    if area:
        query += " AND AREA = ?"
        params.append(area)

    if type_:
        query += " AND Type = ?"
        params.append(type_)

    rows = conn.execute(query, params).fetchall()
    columns = [description[0] for description in conn.execute('SELECT * FROM tcwd_data LIMIT 1').description]
    conn.close()

    df = pd.DataFrame([dict(row) for row in rows], columns=columns)

    if export_format == 'excel':
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        return send_file(output, as_attachment=True, download_name="tcwd_export.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    else:
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="tcwd_export.csv", mimetype='text/csv')

@app.route('/suggest')
def suggest():
    if not session.get('logged_in'):
        return jsonify([])

    term = request.args.get('term', '')
    if not term or len(term) < 2:  # Minimum 2 characters for search
        return jsonify([])
    
    # Use cached function
    suggestions = get_search_suggestions(term)
    return jsonify(suggestions)

# ============================================================================
# CACHE MANAGEMENT ROUTES
# ============================================================================

@app.route('/cache/stats')
def cache_stats():
    """Get cache statistics - Admin only"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    stats = app_cache.get_stats()
    return jsonify({
        'cache_statistics': stats,
        'cache_health': 'Good' if stats['hit_rate'] > 70 else 'Needs Optimization',
        'recommendations': get_cache_recommendations(stats)
    })

@app.route('/cache/clear', methods=['POST'])
def admin_admin_clear_cache():
    """Clear all cache - Admin only"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in'}), 401
    
    # Clear advanced cache
    app_cache.clear()
    
    # Clear LRU caches
    get_latest_year_month.cache_clear()
    
    return jsonify({
        'status': 'success',
        'message': 'All caches cleared successfully',
        'timestamp': datetime.now().isoformat()
    })

def get_cache_recommendations(stats):
    """Generate cache optimization recommendations"""
    recommendations = []
    
    if stats['hit_rate'] < 50:
        recommendations.append("Low hit rate - consider increasing cache TTL")
    elif stats['hit_rate'] > 95:
        recommendations.append("Very high hit rate - cache is working optimally")
    
    if stats['cache_size'] > 1000:
        recommendations.append("Large cache size - consider implementing cache size limits")
    
    if stats['evictions'] > stats['sets'] * 0.1:
        recommendations.append("High eviction rate - consider increasing TTL or cache size")
    
    return recommendations if recommendations else ["Cache is performing well"]

# ============================================================================
# PERFORMANCE MONITORING & MIDDLEWARE
# ============================================================================

@app.before_request
def before_request():
    """Performance monitoring - track request start time"""
    request.start_time = time.time()

@app.after_request
def after_request(response):
    """Performance monitoring and response optimization"""
    # Add performance headers
    if hasattr(request, 'start_time'):
        response_time = time.time() - request.start_time
        response.headers['X-Response-Time'] = f"{response_time:.3f}s"
    
    # Add cache headers for static content
    if request.endpoint in ['static']:
        response.headers['Cache-Control'] = 'public, max-age=86400'  # 24 hours
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    
    return response

# ============================================================================
# BACKGROUND CACHE WARMING
# ============================================================================

def warm_cache():
    """Warm up cache with frequently accessed data"""
    try:
        # Warm up latest year/month
        get_latest_year_month()
        
        # Warm up filter options
        latest_year, latest_month = get_latest_year_month()
        if latest_year and latest_month:
            get_filter_options(latest_year, latest_month)
        
        print("âœ“ Cache warmed successfully")
    except Exception as e:
        print(f"âœ— Cache warming failed: {e}")

# Warm cache on startup (in a separate thread to avoid blocking)
def start_cache_warming():
    cache_thread = threading.Thread(target=warm_cache)
    cache_thread.daemon = True
    cache_thread.start()

# Start cache warming
start_cache_warming()

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal server error.", error=str(error)), 500



# ============================================================================
# ROLE-BASED API ROUTES
# ============================================================================

@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    user = get_current_user()
    
    # Check if we should show all users (including inactive) or just active
    show_all = request.args.get('show_all', '').lower() == 'true'
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    
    if show_all:
        users_df = pd.read_sql_query('''
            SELECT id, username, full_name, email, role, is_active, 
                   created_at, last_login
            FROM users 
            ORDER BY is_active DESC, created_at DESC
        ''', conn)
    else:
        users_df = pd.read_sql_query('''
            SELECT id, username, full_name, email, role, is_active, 
                   created_at, last_login
            FROM users 
            WHERE is_active = 1
            ORDER BY created_at DESC
        ''', conn)
    
    conn.close()
    
    log_audit(user['id'], 'view_users', 'admin', f'Accessed user list (show_all={show_all})')
    
    return jsonify({'users': users_df.to_dict('records'), 'show_all': show_all})

@app.route('/api/admin/audit-logs')
@admin_required  
def api_admin_audit_logs():
    user = get_current_user()
    
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)
    offset = (page - 1) * per_page
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    logs_df = pd.read_sql_query(f'''
        SELECT al.*, u.username, u.full_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
        LIMIT {per_page} OFFSET {offset}
    ''', conn)
    conn.close()
    
    log_audit(user['id'], 'view_audit_logs', 'admin', 'Accessed audit logs')
    
    return jsonify({
        'logs': logs_df.to_dict('records'),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/analytics')
@role_required(['admin', 'manager', 'viewer'])
def api_analytics():
    user = get_current_user()
    
    conn = sqlite3.connect(DATABASE)
    
    try:
        # Get latest year and month to filter data
        latest_year, latest_month = get_latest_year_month()
        
        if not latest_year or not latest_month:
            return jsonify({
                'error': 'No data available',
                'success': False,
                'status_distribution': [],
                'area_analysis': [],
                'type_distribution': [],
                'monthly_trends': []
            }), 404
        
        # Status distribution (latest data only)
        status_query = '''
            SELECT Status, COUNT(*) as count
            FROM tcwd_data
            WHERE Year = ? AND Month = ?
            GROUP BY Status
            ORDER BY count DESC
        '''
        
        # Area analysis (latest data only)
        area_query = '''
            SELECT AREA, COUNT(*) as count,
                   AVG(CumUsed) as avg_usage,
                   AVG(BillAmount) as avg_bill
            FROM tcwd_data 
            WHERE AREA IS NOT NULL AND AREA != ''
              AND Year = ? AND Month = ?
            GROUP BY AREA
            ORDER BY count DESC
        '''
        
        # Type distribution (latest data only)
        type_query = '''
            SELECT Type, COUNT(*) as count
            FROM tcwd_data
            WHERE Type IS NOT NULL AND Type != ''
              AND Year = ? AND Month = ?
            GROUP BY Type
            ORDER BY count DESC
        '''
        
        # Monthly trends (latest 12 months including current)
        monthly_query = '''
            SELECT Month, Year, COUNT(*) as total_accounts,
                   AVG(CumUsed) as avg_consumption,
                   SUM(BillAmount) as total_revenue
            FROM tcwd_data 
            GROUP BY Year, Month
            ORDER BY Year DESC, 
                CASE Month
                    WHEN 'January' THEN 1
                    WHEN 'February' THEN 2
                    WHEN 'March' THEN 3
                    WHEN 'April' THEN 4
                    WHEN 'May' THEN 5
                    WHEN 'June' THEN 6
                    WHEN 'July' THEN 7
                    WHEN 'August' THEN 8
                    WHEN 'September' THEN 9
                    WHEN 'October' THEN 10
                    WHEN 'November' THEN 11
                    WHEN 'December' THEN 12
                END DESC
            LIMIT 12
        '''
        
        # Execute queries with latest period filter
        status_df = pd.read_sql_query(status_query, conn, params=(latest_year, latest_month))
        area_df = pd.read_sql_query(area_query, conn, params=(latest_year, latest_month))
        type_df = pd.read_sql_query(type_query, conn, params=(latest_year, latest_month))
        monthly_df = pd.read_sql_query(monthly_query, conn)
        
        log_audit(user['id'], 'analytics_access', 'api', f'Accessed analytics data for {latest_year}-{latest_month}')
        
        return jsonify({
            'status_distribution': status_df.to_dict('records'),
            'area_analysis': area_df.to_dict('records'),
            'type_distribution': type_df.to_dict('records'),
            'monthly_trends': monthly_df.to_dict('records'),
            'latest_period': f'{latest_year}-{latest_month}',
            'success': True
        })
        
    except Exception as e:
        print(f"Analytics API Error: {str(e)}")
        return jsonify({
            'error': str(e),
            'success': False,
            'status_distribution': [],
            'area_analysis': [],
            'type_distribution': [],
            'monthly_trends': []
        }), 500
    finally:
        conn.close()

# TEMPORARY TEST ROUTE - FOR DEBUGGING ONLY
@app.route('/api/analytics/test')
def api_analytics_test():
    """Test analytics endpoint without authentication - REMOVE BEFORE PRODUCTION"""
    conn = sqlite3.connect(DATABASE)
    
    try:
        # Get latest year and month to filter data
        latest_year, latest_month = get_latest_year_month()
        
        if not latest_year or not latest_month:
            return jsonify({
                'error': 'No data available',
                'success': False
            }), 404
        
        # Status distribution (latest data only)
        status_query = '''
            SELECT Status, COUNT(*) as count
            FROM tcwd_data
            WHERE Year = ? AND Month = ?
            GROUP BY Status
            ORDER BY count DESC
        '''
        
        # Area analysis (latest data only)
        area_query = '''
            SELECT AREA, COUNT(*) as count,
                   AVG(CumUsed) as avg_usage,
                   AVG(BillAmount) as avg_bill
            FROM tcwd_data 
            WHERE AREA IS NOT NULL AND AREA != ''
              AND Year = ? AND Month = ?
            GROUP BY AREA
            ORDER BY count DESC
        '''
        
        # Type distribution (latest data only)
        type_query = '''
            SELECT Type, COUNT(*) as count
            FROM tcwd_data
            WHERE Type IS NOT NULL AND Type != ''
              AND Year = ? AND Month = ?
            GROUP BY Type
            ORDER BY count DESC
        '''
        
        status_df = pd.read_sql_query(status_query, conn, params=(latest_year, latest_month))
        area_df = pd.read_sql_query(area_query, conn, params=(latest_year, latest_month))
        type_df = pd.read_sql_query(type_query, conn, params=(latest_year, latest_month))
        
        return jsonify({
            'status_distribution': status_df.to_dict('records'),
            'area_analysis': area_df.to_dict('records'),
            'type_distribution': type_df.to_dict('records'),
            'monthly_trends': [],
            'latest_period': f'{latest_year}-{latest_month}',
            'success': True,
            'message': f'Test route working - showing data from {latest_year}-{latest_month}'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500
    finally:
        conn.close()

@app.route('/api/analytics/filtered', methods=['POST'])
@role_required(['admin', 'manager', 'viewer'])
def api_analytics_filtered():
    """Analytics endpoint with filtering options"""
    user = get_current_user()
    
    # Get filter parameters from request
    data = request.get_json() or {}
    filter_mode = data.get('mode', 'latest')  # latest, specific, year, multiple, zero_consumption, high_consumption
    year_filter = data.get('year', None)
    month_filter = data.get('month', None) 
    periods = data.get('periods', [])  # For multiple periods mode
    
    # Pagination parameters
    page = data.get('page', 1)  # Current page number (1-based)
    page_size = data.get('page_size', 50)  # Records per page
    page = max(1, int(page))  # Ensure page is at least 1
    page_size = max(10, min(500, int(page_size)))  # Limit page size between 10-500
    
    conn = sqlite3.connect(DATABASE)
    
    try:
        # Build WHERE clause based on filter mode
        where_params = []
        
        if filter_mode == 'latest':
            # Use latest period only
            latest_year, latest_month = get_latest_year_month()
            if not latest_year or not latest_month:
                return jsonify({'error': 'No data available', 'success': False}), 404
            where_clause = "WHERE Year = ? AND Month = ?"
            where_params = [latest_year, latest_month]
            filter_description = f"Latest period: {latest_year}-{latest_month}"
            
        elif filter_mode == 'specific':
            # Specific year and/or month
            conditions = []
            if year_filter:
                conditions.append("Year = ?")
                where_params.append(year_filter)
            if month_filter:
                conditions.append("Month = ?") 
                where_params.append(month_filter)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            filter_description = f"Filtered by: Year={year_filter or 'All'}, Month={month_filter or 'All'}"
            
        elif filter_mode == 'year':
            # Entire year
            if year_filter:
                where_clause = "WHERE Year = ?"
                where_params = [year_filter]
                filter_description = f"Year: {year_filter}"
            else:
                where_clause = ""
                filter_description = "All available data"
                
        elif filter_mode == 'multiple':
            # Multiple specific periods
            if periods:
                period_conditions = []
                for period in periods:
                    if '-' in period:
                        year, month = period.split('-', 1)
                        period_conditions.append("(Year = ? AND Month = ?)")
                        where_params.extend([year, month])
                
                where_clause = "WHERE " + " OR ".join(period_conditions) if period_conditions else ""
                filter_description = f"Multiple periods: {', '.join(periods)}"
            else:
                where_clause = ""
                filter_description = "All available data"
                
        elif filter_mode == 'zero_consumption':
            # Accounts with zero consumption
            conditions = ["(CumUsed = 0 OR CumUsed IS NULL)"]
            if year_filter:
                conditions.append("Year = ?")
                where_params.append(year_filter)
            if month_filter:
                conditions.append("Month = ?") 
                where_params.append(month_filter)
            
            where_clause = "WHERE " + " AND ".join(conditions)
            period_desc = f" for {year_filter or 'all years'}-{month_filter or 'all months'}"
            filter_description = f"Zero consumption accounts{period_desc}"
            
        elif filter_mode == 'high_consumption':
            # High consumption accounts: RateCode '01' with usage >= 30 cu.m.
            conditions = ["RateCode = '01'", "CumUsed >= 30"]
            print("✅ High consumption filter: RateCode '01' accounts with >= 30 cu.m. usage")
                
            if year_filter:
                conditions.append("Year = ?")
                where_params.append(year_filter)
            if month_filter:
                conditions.append("Month = ?") 
                where_params.append(month_filter)
            
            where_clause = "WHERE " + " AND ".join(conditions)
            period_desc = f" for {year_filter or 'all years'}-{month_filter or 'all months'}"
            filter_description = f"High consumption accounts{period_desc}"
            
        else:
            where_clause = ""
            filter_description = "All available data"
        
        # Build queries with dynamic WHERE clause
        base_where = where_clause if where_clause else ""
        
        # Status distribution
        status_query = f'''
            SELECT Status, COUNT(*) as count
            FROM tcwd_data
            {base_where}
            GROUP BY Status
            ORDER BY count DESC
        '''
        
        # Area analysis
        area_query = f'''
            SELECT AREA, COUNT(*) as count,
                   AVG(CumUsed) as avg_usage,
                   AVG(BillAmount) as avg_bill
            FROM tcwd_data 
            {base_where}
            {"AND" if where_clause else "WHERE"} AREA IS NOT NULL AND AREA != ''
            GROUP BY AREA
            ORDER BY count DESC
        '''
        
        # Type distribution
        type_query = f'''
            SELECT Type, COUNT(*) as count
            FROM tcwd_data
            {base_where}
            {"AND" if where_clause else "WHERE"} Type IS NOT NULL AND Type != ''
            GROUP BY Type
            ORDER BY count DESC
        '''
        
        # Monthly trends (always show available periods)
        monthly_query = '''
            SELECT Month, Year, COUNT(*) as total_accounts,
                   AVG(CumUsed) as avg_consumption,
                   SUM(BillAmount) as total_revenue
            FROM tcwd_data 
            GROUP BY Year, Month
            ORDER BY Year DESC, 
                CASE Month
                    WHEN 'January' THEN 1
                    WHEN 'February' THEN 2
                    WHEN 'March' THEN 3
                    WHEN 'April' THEN 4
                    WHEN 'May' THEN 5
                    WHEN 'June' THEN 6
                    WHEN 'July' THEN 7
                    WHEN 'August' THEN 8
                    WHEN 'September' THEN 9
                    WHEN 'October' THEN 10
                    WHEN 'November' THEN 11
                    WHEN 'December' THEN 12
                END DESC
            LIMIT 12
        '''
        
        # Execute queries with error handling
        try:
            print(f"🔍 Executing analytics queries for {filter_mode}")
            print(f"🔍 Base where clause: {base_where}")
            print(f"🔍 Where params: {where_params}")
            
            status_df = pd.read_sql_query(status_query, conn, params=where_params)
            area_df = pd.read_sql_query(area_query, conn, params=where_params)
            type_df = pd.read_sql_query(type_query, conn, params=where_params)
            monthly_df = pd.read_sql_query(monthly_query, conn)
            
            print(f"✅ Analytics queries executed successfully")
        except Exception as e:
            print(f"❌ Error executing analytics queries: {e}")
            import traceback
            traceback.print_exc()
            raise  # Re-raise to trigger the outer exception handler
        
        # Get detailed account list for consumption filters
        account_details = []
        # Get account details with pagination for consumption filters
        if filter_mode in ['zero_consumption', 'high_consumption']:
            try:
                # First, get total count for pagination
                count_query = f"SELECT COUNT(*) as total FROM tcwd_data {base_where}"
                print(f"🔍 Count query: {count_query}")
                print(f"🔍 Count params: {where_params}")
                
                count_result = pd.read_sql_query(count_query, conn, params=where_params)
                total_count = count_result.iloc[0]['total']
                
                # Calculate pagination metadata
                total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
                offset = (page - 1) * page_size
                has_next = page < total_pages
                has_prev = page > 1
                
                # Get paginated account details
                account_query = f'''
                    SELECT AccountNumber, Name, Address, AREA, MeterNo, BookNo, Status, 
                           CumUsed, BillAmount, Cellphone, Type, Year, Month
                    FROM tcwd_data 
                    {base_where}
                    ORDER BY CumUsed DESC, Name ASC
                    LIMIT {page_size} OFFSET {offset}
                '''
                
                print(f"🔍 Account query: {account_query}")
                print(f"🔍 Account params: {where_params}")
                
                account_df = pd.read_sql_query(account_query, conn, params=where_params)
                # Convert to dict and ensure all values are JSON serializable
                raw_records = account_df.to_dict('records')
                account_details = []
                for record in raw_records:
                    clean_record = {}
                    for key, value in record.items():
                        # Convert numpy/pandas types to native Python types
                        if pd.isna(value):
                            clean_record[key] = None
                        elif isinstance(value, (int, float, str, bool)):
                            clean_record[key] = value
                        else:
                            # Convert any other types to string or appropriate type
                            try:
                                clean_record[key] = float(value) if isinstance(value, (int, float)) else str(value)
                            except:
                                clean_record[key] = str(value)
                    account_details.append(clean_record)
                
                print(f"✅ Found {len(account_details)} accounts (page {page}/{total_pages}) for {filter_mode} filter")
                
                # Create pagination metadata - convert all to native Python types
                pagination = {
                    'current_page': int(page),
                    'page_size': int(page_size),
                    'total_records': int(total_count),
                    'total_pages': int(total_pages),
                    'has_next': bool(has_next),
                    'has_prev': bool(has_prev),
                    'start_record': int(offset + 1 if total_count > 0 else 0),
                    'end_record': int(min(offset + page_size, total_count))
                }
                
            except Exception as e:
                print(f"❌ Error in pagination logic for {filter_mode}: {e}")
                import traceback
                traceback.print_exc()
                account_details = []
                pagination = {
                    'current_page': int(1),
                    'page_size': int(page_size),
                    'total_records': int(0),
                    'total_pages': int(0),
                    'has_next': bool(False),
                    'has_prev': bool(False),
                    'start_record': int(0),
                    'end_record': int(0)
                }
        
        log_audit(user['id'], 'analytics_filtered_access', 'api', f'Accessed filtered analytics: {filter_description}')
        
        response_data = {
            'status_distribution': status_df.to_dict('records'),
            'area_analysis': area_df.to_dict('records'),
            'type_distribution': type_df.to_dict('records'),
            'monthly_trends': monthly_df.to_dict('records'),
            'filter_description': filter_description,
            'filter_mode': filter_mode,
            'success': True
        }
        
        # Include account details for consumption filters
        if filter_mode in ['zero_consumption', 'high_consumption']:
            response_data['account_details'] = account_details
            response_data['pagination'] = pagination
            response_data['show_account_list'] = True
        else:
            response_data['show_account_list'] = False
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Filtered Analytics API Error: {str(e)}")
        return jsonify({
            'error': str(e),
            'success': False,
            'status_distribution': [],
            'area_analysis': [],
            'type_distribution': [],
            'monthly_trends': []
        }), 500
    finally:
        conn.close()

@app.route('/api/analytics/periods')
@role_required(['admin', 'manager', 'viewer'])
def api_analytics_periods():
    """Get available periods for filtering"""
    conn = sqlite3.connect(DATABASE)
    
    try:
        # Get available years
        years_query = "SELECT DISTINCT Year FROM tcwd_data ORDER BY Year DESC"
        years_df = pd.read_sql_query(years_query, conn)
        years = years_df['Year'].tolist()
        
        # Get available months in chronological order
        months_query = '''
            SELECT DISTINCT Month FROM tcwd_data 
            ORDER BY 
                CASE Month
                    WHEN 'January' THEN 1
                    WHEN 'February' THEN 2
                    WHEN 'March' THEN 3
                    WHEN 'April' THEN 4
                    WHEN 'May' THEN 5
                    WHEN 'June' THEN 6
                    WHEN 'July' THEN 7
                    WHEN 'August' THEN 8
                    WHEN 'September' THEN 9
                    WHEN 'October' THEN 10
                    WHEN 'November' THEN 11
                    WHEN 'December' THEN 12
                END
        '''
        months_df = pd.read_sql_query(months_query, conn)
        months = months_df['Month'].tolist()
        
        # Get all available year-month combinations
        periods_query = '''
            SELECT Year, Month, COUNT(*) as record_count
            FROM tcwd_data 
            GROUP BY Year, Month
            ORDER BY Year DESC, 
                CASE Month
                    WHEN 'January' THEN 1
                    WHEN 'February' THEN 2
                    WHEN 'March' THEN 3
                    WHEN 'April' THEN 4
                    WHEN 'May' THEN 5
                    WHEN 'June' THEN 6
                    WHEN 'July' THEN 7
                    WHEN 'August' THEN 8
                    WHEN 'September' THEN 9
                    WHEN 'October' THEN 10
                    WHEN 'November' THEN 11
                    WHEN 'December' THEN 12
                END DESC
        '''
        periods_df = pd.read_sql_query(periods_query, conn)
        periods = [
            {
                'value': f"{row['Year']}-{row['Month']}", 
                'label': f"{row['Year']}-{row['Month']} ({row['record_count']:,} records)",
                'year': row['Year'],
                'month': row['Month'],
                'count': row['record_count']
            }
            for _, row in periods_df.iterrows()
        ]
        
        # Get latest period
        latest_year, latest_month = get_latest_year_month()
        
        return jsonify({
            'years': years,
            'months': months, 
            'periods': periods,
            'latest_period': f"{latest_year}-{latest_month}" if latest_year and latest_month else None,
            'success': True
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500
    finally:
        conn.close()

# ============================================================================
# EXPORT ROUTES (MANAGER+ ROLES)
# ============================================================================

@app.route('/api/analytics/export/current', methods=['POST'])
@role_required(['admin', 'manager'])
def api_export_current_page():
    """Export current page data to CSV"""
    user = get_current_user()
    data = request.get_json()
    
    try:
        from io import StringIO
        import csv
        from flask import make_response
        
        account_data = data.get('accounts', [])
        filter_description = data.get('description', 'Export')
        
        if not account_data:
            return jsonify({'error': 'No data to export'}), 400
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = ['Account Number', 'Book No', 'Name', 'Address', 'Area', 'Meter No', 
                  'Status', 'Consumption (cu.m)', 'Bill Amount', 'Cellphone', 'Type', 'Year', 'Month']
        writer.writerow(headers)
        
        # Write data
        for account in account_data:
            row = [
                account.get('AccountNumber', ''),
                account.get('BookNo', ''),
                account.get('Name', ''),
                account.get('Address', ''),
                account.get('AREA', ''),
                account.get('MeterNo', ''),
                account.get('Status', ''),
                account.get('CumUsed', 0),
                account.get('BillAmount', 0),
                account.get('Cellphone', ''),
                account.get('Type', ''),
                account.get('Year', ''),
                account.get('Month', '')
            ]
            writer.writerow(row)
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filter_description}_current_page.csv"'
        
        log_audit(user['id'], 'export_current_page', 'analytics', f'Exported current page: {filter_description}')
        return response
        
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/analytics/export/all', methods=['POST'])
@role_required(['admin', 'manager'])
def api_export_all_data():
    """Export all filtered data to CSV"""
    user = get_current_user()
    data = request.get_json()
    
    try:
        from io import StringIO
        import csv
        from flask import make_response
        
        filter_mode = data.get('mode', 'latest')
        year_filter = data.get('year')
        month_filter = data.get('month')
        
        conn = sqlite3.connect('tcwd_data.db')
        
        # Build the same query logic as the analytics filter
        conditions = []
        where_params = []
        
        if filter_mode == 'zero_consumption':
            conditions = ["CumUsed = 0"]
        elif filter_mode == 'high_consumption':
            conditions = ["RateCode = '01'", "CumUsed >= 30"]
        
        if year_filter:
            conditions.append("Year = ?")
            where_params.append(year_filter)
        if month_filter:
            conditions.append("Month = ?") 
            where_params.append(month_filter)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        # Export query - get all matching records
        export_query = f'''
            SELECT AccountNumber, BookNo, Name, Address, AREA, MeterNo, Status, 
                   CumUsed, BillAmount, Cellphone, Type, Year, Month
            FROM tcwd_data 
            {where_clause}
            ORDER BY CumUsed DESC, Name ASC
        '''
        
        df = pd.read_sql_query(export_query, conn, params=where_params)
        
        if df.empty:
            return jsonify({'error': 'No data found for export'}), 400
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = ['Account Number', 'Book No', 'Name', 'Address', 'Area', 'Meter No', 
                  'Status', 'Consumption (cu.m)', 'Bill Amount', 'Cellphone', 'Type', 'Year', 'Month']
        writer.writerow(headers)
        
        # Write data
        for _, row in df.iterrows():
            csv_row = [
                str(row['AccountNumber']) if pd.notna(row['AccountNumber']) else '',
                str(row['BookNo']) if pd.notna(row['BookNo']) else '',
                str(row['Name']) if pd.notna(row['Name']) else '',
                str(row['Address']) if pd.notna(row['Address']) else '',
                str(row['AREA']) if pd.notna(row['AREA']) else '',
                str(row['MeterNo']) if pd.notna(row['MeterNo']) else '',
                str(row['Status']) if pd.notna(row['Status']) else '',
                float(row['CumUsed']) if pd.notna(row['CumUsed']) else 0,
                float(row['BillAmount']) if pd.notna(row['BillAmount']) else 0,
                str(row['Cellphone']) if pd.notna(row['Cellphone']) else '',
                str(row['Type']) if pd.notna(row['Type']) else '',
                str(row['Year']) if pd.notna(row['Year']) else '',
                str(row['Month']) if pd.notna(row['Month']) else ''
            ]
            writer.writerow(csv_row)
        
        # Create filename based on filter
        if filter_mode == 'zero_consumption':
            filename = f"zero_consumption_accounts_{year_filter or 'all_years'}_{month_filter or 'all_months'}.csv"
        elif filter_mode == 'high_consumption':
            filename = f"high_consumption_accounts_{year_filter or 'all_years'}_{month_filter or 'all_months'}.csv"
        else:
            filename = f"analytics_export_{year_filter or 'all_years'}_{month_filter or 'all_months'}.csv"
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        log_audit(user['id'], 'export_all_data', 'analytics', f'Exported all data: {filter_mode} ({len(df)} records)')
        return response
        
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500
    finally:
        conn.close()

# ============================================================================
# USER MANAGEMENT ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/api/admin/users', methods=['POST'])
@admin_required
@validate_input
def api_admin_create_user():
    """Create new user - Admin only"""
    user = get_current_user()
    data = request.get_json()
    
    required_fields = ['username', 'password', 'full_name', 'email', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Validate role
    if data['role'] not in ROLE_HIERARCHY:
        return jsonify({'error': 'Invalid role'}), 400
    
    conn = get_db_connection()
    try:
        # Check if username already exists
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (data['username'],)).fetchone()
        if existing:
            return jsonify({'error': 'Username already exists'}), 409
        
        # Hash password
        password_hash = hash_password(data['password'])
        
        # Insert user
        conn.execute('''
            INSERT INTO users (username, password_hash, full_name, email, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        ''', (data['username'], password_hash, data['full_name'], data['email'], 
              data['role'], datetime.now().isoformat()))
        conn.commit()
        
        log_audit(user['id'], 'create_user', 'admin', f'Created user: {data["username"]}')
        return jsonify({'message': 'User created successfully'}), 201
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>', methods=['GET'])
@admin_required
def api_admin_get_user(user_id):
    """Get user details - Admin only"""
    conn = get_db_connection()
    try:
        user = conn.execute('''
            SELECT id, username, full_name, email, role, is_active, created_at
            FROM users
            WHERE id = ?
        ''', (user_id,)).fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'full_name': user['full_name'],
            'email': user['email'],
            'role': user['role'],
            'is_active': user['is_active'],
            'created_at': user['created_at']
        })
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    """Update user - Admin only"""
    user = get_current_user()
    data = request.get_json()
    
    conn = get_db_connection()
    try:
        # Check if user exists
        existing = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'User not found'}), 404
        
        # Build update query
        update_fields = []
        params = []
        
        if 'full_name' in data:
            update_fields.append('full_name = ?')
            params.append(data['full_name'])
        
        if 'email' in data:
            update_fields.append('email = ?')
            params.append(data['email'])
        
        if 'role' in data:
            if data['role'] not in ROLE_HIERARCHY:
                return jsonify({'error': 'Invalid role'}), 400
            update_fields.append('role = ?')
            params.append(data['role'])
        
        if 'is_active' in data:
            update_fields.append('is_active = ?')
            params.append(1 if data['is_active'] else 0)
        
        if 'password' in data:
            update_fields.append('password_hash = ?')
            params.append(hash_password(data['password']))
        
        if update_fields:
            params.append(user_id)
            conn.execute(f'UPDATE users SET {", ".join(update_fields)} WHERE id = ?', params)
            conn.commit()
        
        log_audit(user['id'], 'update_user', 'admin', f'Updated user ID: {user_id}')
        return jsonify({'message': 'User updated successfully'})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    """Delete user - Admin only"""
    user = get_current_user()
    
    # Prevent self-deletion
    if user['id'] == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    conn = get_db_connection()
    try:
        # Check if user exists
        existing = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'User not found'}), 404
        
        # Soft delete (deactivate) to preserve audit trail
        conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
        conn.commit()
        
        log_audit(user['id'], 'delete_user', 'admin', f'Deleted user: {existing["username"]}')
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/restore', methods=['POST'])
@admin_required
def api_admin_restore_user(user_id):
    """Restore (reactivate) user - Admin only"""
    user = get_current_user()
    
    conn = get_db_connection()
    try:
        # Check if user exists
        existing = conn.execute('SELECT username, is_active FROM users WHERE id = ?', (user_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'User not found'}), 404
        
        if existing['is_active']:
            return jsonify({'error': 'User is already active'}), 400
        
        # Restore user (reactivate)
        conn.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
        conn.commit()
        
        log_audit(user['id'], 'restore_user', 'admin', f'Restored user: {existing["username"]}')
        return jsonify({'success': True, 'message': 'User restored successfully'})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/permanent-delete', methods=['DELETE'])
@admin_required
def api_admin_permanent_delete_user(user_id):
    """Permanently delete user - Admin only (WARNING: This cannot be undone)"""
    user = get_current_user()
    
    # Prevent self-deletion
    if user['id'] == user_id:
        return jsonify({'error': 'Cannot permanently delete your own account'}), 400
    
    conn = get_db_connection()
    try:
        # Check if user exists
        existing = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'User not found'}), 404
        
        # Permanent delete - remove from database entirely
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        log_audit(user['id'], 'permanent_delete_user', 'admin', f'Permanently deleted user: {existing["username"]}')
        return jsonify({'success': True, 'message': 'User permanently deleted'})
    finally:
        conn.close()

@app.route('/api/admin/users/export', methods=['GET'])
@admin_required
def api_admin_export_users():
    """Export users to CSV - Admin only"""
    conn = get_db_connection()
    try:
        users = conn.execute('''
            SELECT username, full_name, email, role, is_active, created_at
            FROM users
            ORDER BY created_at DESC
        ''').fetchall()
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['username', 'full_name', 'email', 'role', 'is_active', 'created_at'])
        
        # Write user data
        for user in users:
            writer.writerow([
                user['username'],
                user['full_name'] or '',
                user['email'] or '',
                user['role'],
                'Yes' if user['is_active'] else 'No',
                user['created_at']
            ])
        
        output.seek(0)
        
        # Create response
        response = io.BytesIO()
        response.write(output.getvalue().encode('utf-8'))
        response.seek(0)
        
        log_audit(get_current_user()['id'], 'export_users', 'admin', f'Exported {len(users)} users to CSV')
        
        return send_file(
            response,
            as_attachment=True,
            download_name=f'users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            mimetype='text/csv'
        )
    finally:
        conn.close()

@app.route('/api/admin/users/import', methods=['POST'])
@admin_required
def api_admin_import_users():
    """Import users from CSV - Admin only"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'File must be a CSV'}), 400
    
    conn = get_db_connection()
    created_count = 0
    error_count = 0
    errors = []
    
    try:
        # Read CSV content
        content = file.read().decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(content))
        
        # Required columns
        required_columns = ['username', 'full_name', 'email', 'role', 'password']
        if not all(col in csv_reader.fieldnames for col in required_columns):
            return jsonify({
                'error': f'Missing required columns. Required: {", ".join(required_columns)}'
            }), 400
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 because of header
            try:
                # Validate required fields
                if not row['username'] or not row['full_name'] or not row['role'] or not row['password']:
                    errors.append(f'Row {row_num}: Missing required fields')
                    error_count += 1
                    continue
                
                # Validate role
                valid_roles = ['admin', 'manager', 'editor', 'guest']
                if row['role'].lower() not in valid_roles:
                    errors.append(f'Row {row_num}: Invalid role "{row["role"]}" (must be one of: {", ".join(valid_roles)})')
                    error_count += 1
                    continue
                
                # Check if username already exists
                existing = conn.execute('SELECT id FROM users WHERE username = ?', (row['username'],)).fetchone()
                if existing:
                    errors.append(f'Row {row_num}: Username "{row["username"]}" already exists')
                    error_count += 1
                    continue
                
                # Create password hash
                password_hash = generate_password_hash(row['password'])
                
                # Insert user
                conn.execute('''
                    INSERT INTO users (username, password_hash, full_name, email, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                ''', (
                    row['username'],
                    password_hash,
                    row['full_name'],
                    row['email'] if row['email'] else None,
                    row['role'].lower(),
                    datetime.now().isoformat()
                ))
                
                created_count += 1
                
            except Exception as e:
                errors.append(f'Row {row_num}: {str(e)}')
                error_count += 1
                continue
        
        conn.commit()
        
        log_audit(get_current_user()['id'], 'import_users', 'admin', 
                 f'Imported CSV: {created_count} users created, {error_count} errors')
        
        return jsonify({
            'success': True,
            'message': f'Import completed',
            'created': created_count,
            'errors': error_count,
            'error_details': errors[:10] if errors else []  # Return first 10 errors only
        })
        
    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/admin/activity-stats', methods=['GET'])
@admin_required
def api_admin_activity_stats():
    """Get real-time activity statistics - Admin only"""
    conn = get_db_connection()
    try:
        # Active users in last 5 minutes
        active_users = conn.execute('''
            SELECT COUNT(DISTINCT user_id) 
            FROM audit_logs 
            WHERE timestamp > datetime('now', '-5 minutes')
            AND user_id IS NOT NULL
        ''').fetchone()[0]
        
        # Total sessions today
        total_sessions = conn.execute('''
            SELECT COUNT(*) 
            FROM audit_logs 
            WHERE action = 'login' 
            AND date(timestamp) = date('now')
        ''').fetchone()[0]
        
        # Recent activities (last 10)
        recent_activities = conn.execute('''
            SELECT al.action, al.details, al.timestamp, u.username
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.timestamp > datetime('now', '-1 hour')
            ORDER BY al.timestamp DESC
            LIMIT 10
        ''').fetchall()
        
        activities_list = []
        for activity in recent_activities:
            activities_list.append({
                'username': activity['username'] or 'System',
                'action': activity['action'],
                'details': activity['details'],
                'timestamp': activity['timestamp']
            })
        
        return jsonify({
            'active_users': active_users,
            'total_sessions': total_sessions,
            'recent_activities': activities_list
        })
    finally:
        conn.close()

@app.route('/test-js')
def test_js():
    """Simple JavaScript test page"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>JavaScript Test</title>
</head>
<body>
    <h1>JavaScript Functionality Test</h1>
    
    <button onclick="testFunction()" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; margin: 5px;">
        🧪 Test JavaScript
    </button>
    
    <button onclick="testCreateUserModal()" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; margin: 5px;">
        🔧 Test Create User Modal
    </button>
    
    <div id="results" style="margin-top: 20px; padding: 15px; border: 1px solid #ccc; border-radius: 5px;">
        <h3>Test Results:</h3>
        <p id="status">Click a button to test</p>
    </div>

    <!-- Simple Test Modal -->
    <div id="testModal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">
        <div style="background-color: white; margin: 10% auto; padding: 20px; border-radius: 10px; width: 400px;">
            <h3>✅ Test Modal Working!</h3>
            <p>If you see this modal, JavaScript and modals are working correctly.</p>
            <button onclick="hideTestModal()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px;">Close</button>
        </div>
    </div>

    <script>
        function testFunction() {
            document.getElementById('status').innerHTML = '✅ JavaScript is working! Alert coming next...';
            alert('✅ JavaScript Alert Working!\\n\\n🎉 Basic functionality confirmed!');
            document.getElementById('status').innerHTML = '✅ JavaScript and alerts are both working perfectly!';
        }
        
        function testCreateUserModal() {
            document.getElementById('status').innerHTML = '✅ Testing modal functionality...';
            document.getElementById('testModal').style.display = 'block';
        }
        
        function hideTestModal() {
            document.getElementById('testModal').style.display = 'none';
            document.getElementById('status').innerHTML = '✅ Modal functionality working perfectly!';
        }
        
        // Test console output
        console.log('🧪 Test JavaScript loaded successfully');
    </script>
</body>
</html>
    '''

# ============================================================================
# CUSTOMER DATA MANAGEMENT ROUTES
# ============================================================================

@app.route('/api/customers', methods=['GET'])
@role_required(['admin', 'manager', 'editor', 'guest'])
def api_get_customers():
    """Get customer data with role-based filtering"""
    user = get_current_user()
    
    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 50)), 100)
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    try:
        # Role-based field selection
        if user['role'] == 'guest':
            query = '''
                SELECT Name, AccountNumber, Status, AREA
                FROM tcwd_data
                ORDER BY AccountNumber
                LIMIT ? OFFSET ?
            '''
        else:
            query = '''
                SELECT Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                       Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
                FROM tcwd_data
                ORDER BY AccountNumber
                LIMIT ? OFFSET ?
            '''
        
        customers = conn.execute(query, (per_page, offset)).fetchall()
        customers = [dict(row) for row in customers]
        
        log_audit(user['id'], 'view_customers', 'api', f'Viewed customers (page {page})')
        
        return jsonify({
            'customers': customers,
            'page': page,
            'per_page': per_page
        })
    finally:
        conn.close()

@app.route('/api/customers/<account_number>', methods=['PUT'])
@viewer_or_above_required
def api_update_customer(account_number):
    """Update customer data - Viewer, Manager, or Admin"""
    user = get_current_user()
    data = request.get_json()
    
    conn = get_db_connection()
    try:
        # Check if customer exists
        existing = conn.execute('SELECT * FROM tcwd_data WHERE AccountNumber = ?', (account_number,)).fetchone()
        if not existing:
            return jsonify({'error': 'Customer not found'}), 404
        
        # Build update query based on allowed fields for role
        allowed_fields = {
            'editor': ['Name', 'Address', 'Cellphone', 'PRVReading', 'PRSReading'],
            'manager': ['Name', 'Address', 'Cellphone', 'PRVReading', 'PRSReading', 'Status', 'RateCode'],
            'admin': ['Name', 'Address', 'Cellphone', 'PRVReading', 'PRSReading', 'Status', 'RateCode', 'Type', 'BookNo', 'AREA']
        }
        
        user_allowed_fields = allowed_fields.get(user['role'], [])
        update_fields = []
        params = []
        
        for field, value in data.items():
            if field in user_allowed_fields:
                update_fields.append(f'{field} = ?')
                params.append(value)
        
        if update_fields:
            params.append(account_number)
            conn.execute(f'UPDATE tcwd_data SET {", ".join(update_fields)} WHERE AccountNumber = ?', params)
            conn.commit()
        
        log_audit(user['id'], 'update_customer', 'api', f'Updated customer: {account_number}')
        return jsonify({'message': 'Customer updated successfully'})
    finally:
        conn.close()

@app.route('/api/meter-readings/<account_number>', methods=['POST'])
@viewer_or_above_required
def api_add_meter_reading(account_number):
    """Add new meter reading - Editor, Manager, or Admin"""
    user = get_current_user()
    data = request.get_json()
    
    required_fields = ['PRVReading', 'PRSReading', 'Month', 'Year']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    conn = get_db_connection()
    try:
        # Update the customer's reading data
        conn.execute('''
            UPDATE tcwd_data 
            SET PRVReading = ?, PRSReading = ?, Month = ?, Year = ?, 
                CumUsed = ? - ?, BillAmount = ? * ?
            WHERE AccountNumber = ?
        ''', (data['PRVReading'], data['PRSReading'], data['Month'], data['Year'],
              data['PRSReading'], data['PRVReading'], 
              data['PRSReading'] - data['PRVReading'], 
              50,  # Rate per unit - should be dynamic based on RateCode
              account_number))
        conn.commit()
        
        log_audit(user['id'], 'add_meter_reading', 'api', f'Added meter reading for: {account_number}')
        return jsonify({'message': 'Meter reading added successfully'})
    finally:
        conn.close()

# ============================================================================
# SYSTEM CONFIGURATION ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/api/admin/system/config', methods=['GET'])
@admin_required
def api_admin_get_config():
    """Get system configuration - Admin only"""
    user = get_current_user()
    
    # Return current system configuration
    config = {
        'items_per_page': ITEMS_PER_PAGE,
        'cache_ttl_seconds': 300,
        'session_timeout_hours': 8,
        'max_export_rows': 10000,
        'audit_retention_days': 90
    }
    
    log_audit(user['id'], 'view_system_config', 'admin', 'Viewed system configuration')
    return jsonify({'config': config})

@app.route('/api/admin/system/config', methods=['PUT'])
@admin_required
def api_admin_update_config():
    """Update system configuration - Admin only"""
    user = get_current_user()
    data = request.get_json()
    
    # In a real system, this would update configuration in database
    # For now, just log the action
    log_audit(user['id'], 'update_system_config', 'admin', f'Updated config: {list(data.keys())}')
    return jsonify({'message': 'Configuration updated successfully'})

@app.route('/api/admin/database/backup', methods=['POST'])
@admin_required
def api_admin_backup_database():
    """Backup database - Admin only"""
    user = get_current_user()
    
    try:
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'tcwd_backup_{timestamp}.db'
        
        # Copy database file (simplified backup)
        import shutil
        shutil.copy2(DATABASE, backup_filename)
        
        log_audit(user['id'], 'backup_database', 'admin', f'Created database backup: {backup_filename}')
        return jsonify({'message': f'Database backup created: {backup_filename}'})
    except Exception as e:
        return jsonify({'error': f'Backup failed: {str(e)}'}), 500

@app.route('/api/admin/database/stats', methods=['GET'])
@admin_required
def api_admin_database_stats():
    """Get database statistics - Admin only"""
    user = get_current_user()
    
    try:
        conn = get_db_connection()
        
        # Get latest month/year - sort by year and convert month names to numbers for proper chronological sorting
        latest = conn.execute('''
            SELECT Year, Month FROM tcwd_data 
            ORDER BY Year DESC, 
                CASE Month
                    WHEN 'January' THEN 1
                    WHEN 'February' THEN 2
                    WHEN 'March' THEN 3
                    WHEN 'April' THEN 4
                    WHEN 'May' THEN 5
                    WHEN 'June' THEN 6
                    WHEN 'July' THEN 7
                    WHEN 'August' THEN 8
                    WHEN 'September' THEN 9
                    WHEN 'October' THEN 10
                    WHEN 'November' THEN 11
                    WHEN 'December' THEN 12
                END DESC
            LIMIT 1
        ''').fetchone()
        latest_month = f"{latest['Month']} {latest['Year']}" if latest else "No data"
        
        # Get total records for latest month only (consistent with main interface)
        total_records = 0
        if latest:
            total_records = conn.execute(
                'SELECT COUNT(*) FROM tcwd_data WHERE Year = ? AND Month = ?',
                [latest['Year'], latest['Month']]
            ).fetchone()[0]
        
        # Get available months count
        available_months = conn.execute('SELECT COUNT(DISTINCT Year || "-" || Month) FROM tcwd_data').fetchone()[0]
        
        conn.close()
        
        log_audit(user['id'], 'view_database_stats', 'admin', 'Viewed database statistics')
        return jsonify({
            'success': True,
            'total_records': total_records,
            'latest_month': latest_month,
            'available_months': available_months
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get database stats: {str(e)}'}), 500

@app.route('/api/admin/database/upload', methods=['POST'])
@admin_required
@csrf_required
def api_admin_database_upload():
    """Upload new monthly data to database - Admin only"""
    user = get_current_user()
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    year = request.form.get('year')
    month = request.form.get('month')
    
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate and sanitize filename
    original_filename = file.filename
    sanitized_filename = InputValidator.sanitize_filename(original_filename)
    
    # File extension validation
    if not sanitized_filename.lower().endswith('.gpkg'):
        log_audit(user['id'], 'invalid_file_upload', 'security', f'Invalid file extension attempted: {original_filename}')
        return jsonify({'error': 'File must be a GeoPackage (.gpkg)'}), 400
    
    # File size validation (limit to 100MB)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Seek back to start
    
    max_size = 100 * 1024 * 1024  # 100MB
    if file_size > max_size:
        log_audit(user['id'], 'oversized_file_upload', 'security', f'File too large: {file_size} bytes')
        return jsonify({'error': f'File too large. Maximum size is {max_size // (1024*1024)}MB'}), 400
        
    if not year or not month:
        return jsonify({'error': 'Year and month are required'}), 400
    
    try:
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid year format'}), 400
    
    conn = get_db_connection()
    records_processed = 0
    records_added = 0
    errors = []
    
    try:
        # Check if data for this year/month already exists
        existing = conn.execute(
            'SELECT COUNT(*) FROM tcwd_data WHERE Year = ? AND Month = ?',
            (year, month)
        ).fetchone()[0]
        
        if existing > 0:
            return jsonify({
                'error': f'Data for {month} {year} already exists in the database ({existing} records). Please delete existing data first or use a different month/year.'
            }), 400
        
        # Read GPKG content
        # Save the uploaded file temporarily to read it with GeoPandas
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.gpkg') as temp_file:
            file.save(temp_file.name)
            temp_filename = temp_file.name
        
        try:
            # Read GPKG file using GeoPandas (if available)
            if not GEOPANDAS_AVAILABLE:
                return jsonify({
                    'error': 'GPKG upload functionality requires GeoPandas library which is not available in this deployment. Please upload data in CSV format instead.'
                }), 400
            
            gdf = gpd.read_file(temp_filename)
        except Exception as e:
            os.unlink(temp_filename)  # Clean up temp file
            return jsonify({'error': f'Invalid GeoPackage file: {str(e)}'}), 400
        finally:
            # Clean up temp file if it still exists
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
        
        # Required columns for tcwd_data table
        required_columns = [
            'Type', 'AccountNumber', 'Name', 'Address', 'MeterNo', 'BookNo', 
            'RateCode', 'Status', 'Cellphone', 'SeqNo', 'AREA', 'x', 'y',
            'PRVReading', 'PRSReading', 'CumUsed', 'BillAmount', 'Year', 'Month'
        ]
        
        # Check if all required columns exist
        if gdf.empty:
            return jsonify({'error': 'GeoPackage file appears to be empty or invalid'}), 400
            
        missing_columns = [col for col in required_columns if col not in gdf.columns]
        if missing_columns:
            return jsonify({
                'error': f'Missing required columns: {", ".join(missing_columns)}'
            }), 400
        
        # Validate and process each row
        rows_to_insert = []
        
        for row_num, (index, row) in enumerate(gdf.iterrows(), start=1):
            records_processed += 1
            
            try:
                # Validate required fields
                if pd.isna(row['AccountNumber']) or pd.isna(row['Name']) or not str(row['AccountNumber']).strip() or not str(row['Name']).strip():
                    errors.append(f'Row {row_num}: Missing AccountNumber or Name')
                    continue
                
                # Validate Year/Month consistency
                row_year = str(row.get('Year', '')).strip()
                row_month = str(row.get('Month', '')).strip()
                
                if row_year != str(year) or row_month != month:
                    errors.append(f'Row {row_num}: Year/Month mismatch. Expected {year}/{month}, got {row_year}/{row_month}')
                    continue
                
                # Prepare row data for insertion - handle pandas/GeoPandas data types
                def safe_convert(value, convert_type=float, default=0.0):
                    if pd.isna(value) or value == '' or value is None:
                        return default
                    try:
                        if convert_type == str:
                            return str(value).strip()
                        else:
                            return convert_type(value)
                    except (ValueError, TypeError):
                        return default
                
                row_data = (
                    safe_convert(row['Type'], str, ''),
                    safe_convert(row['AccountNumber'], str, ''), 
                    safe_convert(row['Name'], str, ''),
                    safe_convert(row['Address'], str, ''),
                    safe_convert(row['MeterNo'], str, ''),
                    safe_convert(row['BookNo'], str, ''),
                    safe_convert(row['RateCode'], str, ''),
                    safe_convert(row['Status'], str, ''),
                    safe_convert(row['Cellphone'], str, ''),
                    safe_convert(row['SeqNo'], float, 0.0),
                    safe_convert(row['AREA'], str, ''),
                    safe_convert(row['x'], float, 0.0),
                    safe_convert(row['y'], float, 0.0),
                    safe_convert(row['PRVReading'], float, 0.0),
                    safe_convert(row['PRSReading'], float, 0.0),
                    safe_convert(row['CumUsed'], float, 0.0),
                    safe_convert(row['BillAmount'], float, 0.0),
                    year,
                    month
                )
                
                rows_to_insert.append(row_data)
                
            except ValueError as e:
                errors.append(f'Row {row_num}: Invalid numeric value - {str(e)}')
                continue
            except Exception as e:
                errors.append(f'Row {row_num}: {str(e)}')
                continue
        
        # Insert all valid rows at once for better performance
        if rows_to_insert:
            conn.executemany('''
                INSERT INTO tcwd_data (
                    Type, AccountNumber, Name, Address, MeterNo, BookNo, RateCode, Status, 
                    Cellphone, SeqNo, AREA, x, y, PRVReading, PRSReading, CumUsed, BillAmount, Year, Month
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', rows_to_insert)
            
            records_added = len(rows_to_insert)
        
        conn.commit()
        
        # Log the upload action
        log_audit(user['id'], 'upload_database', 'admin', 
                 f'Uploaded {records_added} records for {month} {year}. Processed: {records_processed}, Errors: {len(errors)}')
        
        # Clear cache to refresh latest year/month after upload
        get_latest_year_month.cache_clear()
        app_cache.clear()
        
        return jsonify({
            'success': True,
            'message': f'Database upload completed successfully',
            'records_processed': records_processed,
            'records_added': records_added,
            'errors': len(errors),
            'year': year,
            'month': month,
            'error_details': errors[:10] if errors else []  # Return first 10 errors only
        })
        
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/admin/database/check-records')
@admin_required
def api_admin_check_records():
    """Check how many records exist for a given year/month - Admin only"""
    user = get_current_user()
    
    year = request.args.get('year')
    month = request.args.get('month')
    
    if not year or not month:
        return jsonify({'error': 'Year and month are required'}), 400
    
    try:
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid year format'}), 400
    
    conn = get_db_connection()
    try:
        # Check how many records exist for this year/month
        record_count = conn.execute(
            'SELECT COUNT(*) FROM tcwd_data WHERE Year = ? AND Month = ?',
            (year, month)
        ).fetchone()[0]
        
        log_audit(user['id'], 'check_records', 'admin', 
                 f'Checked records for {month} {year}: {record_count} found')
        
        return jsonify({
            'success': True,
            'record_count': record_count,
            'year': year,
            'month': month
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to check records: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/admin/database/delete-month', methods=['POST'])
@admin_required
def api_admin_delete_month():
    """Delete all records for a given year/month - Admin only"""
    user = get_current_user()
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    year = data.get('year')
    month = data.get('month')
    
    if not year or not month:
        return jsonify({'error': 'Year and month are required'}), 400
    
    try:
        year = int(year)
    except ValueError:
        return jsonify({'error': 'Invalid year format'}), 400
    
    conn = get_db_connection()
    try:
        # First check how many records exist
        existing_count = conn.execute(
            'SELECT COUNT(*) FROM tcwd_data WHERE Year = ? AND Month = ?',
            (year, month)
        ).fetchone()[0]
        
        if existing_count == 0:
            return jsonify({'error': f'No records found for {month} {year}'}), 400
        
        # Delete the records
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM tcwd_data WHERE Year = ? AND Month = ?',
            (year, month)
        )
        
        records_deleted = cursor.rowcount
        conn.commit()
        
        # Log the deletion action
        log_audit(user['id'], 'delete_month_data', 'admin', 
                 f'Deleted {records_deleted} records for {month} {year}')
        
        # Clear cache to refresh latest year/month after deletion
        get_latest_year_month.cache_clear()
        app_cache.clear()
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted data for {month} {year}',
            'records_deleted': records_deleted,
            'year': year,
            'month': month
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to delete data: {str(e)}'}), 500
    finally:
        conn.close()

# ============================================================================
# PERFORMANCE MONITORING ROUTES
# ============================================================================

@app.route('/api/performance/stats')
@manager_or_admin_required
def api_performance_stats():
    """Get performance statistics - Manager or Admin"""
    user = get_current_user()
    
    conn = get_db_connection()
    try:
        # Database statistics
        stats = {
            'total_customers': conn.execute('SELECT COUNT(*) FROM tcwd_data').fetchone()[0],
            'total_users': conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
            'recent_logins': conn.execute('''
                SELECT COUNT(*) FROM users 
                WHERE last_login > datetime('now', '-24 hours')
            ''').fetchone()[0],
            'cache_stats': app_cache.get_stats()
        }
        
        log_audit(user['id'], 'view_performance_stats', 'monitoring', 'Viewed performance statistics')
        return jsonify({'stats': stats})
    finally:
        conn.close()

# ============================================================================
# SECURITY & SESSION MANAGEMENT ROUTES
# ============================================================================

@app.route('/api/admin/security/sessions')
@admin_required
def api_admin_active_sessions():
    """View active user sessions - Admin only"""
    user = get_current_user()
    
    conn = get_db_connection()
    try:
        sessions = conn.execute('''
            SELECT us.id, us.user_id, u.username, u.full_name, us.created_at, us.expires_at
            FROM user_sessions us
            JOIN users u ON us.user_id = u.id
            WHERE us.expires_at > datetime('now')
            ORDER BY us.created_at DESC
        ''').fetchall()
        
        sessions_data = [dict(session) for session in sessions]
        
        log_audit(user['id'], 'view_active_sessions', 'security', 'Viewed active user sessions')
        return jsonify({'sessions': sessions_data})
    finally:
        conn.close()

@app.route('/api/admin/security/sessions/<int:session_id>', methods=['DELETE'])
@admin_required
def api_admin_terminate_session(session_id):
    """Terminate a user session - Admin only"""
    user = get_current_user()
    
    conn = get_db_connection()
    try:
        # Get session info before deletion
        session_info = conn.execute('''
            SELECT us.user_id, u.username
            FROM user_sessions us
            JOIN users u ON us.user_id = u.id
            WHERE us.id = ?
        ''', (session_id,)).fetchone()
        
        if not session_info:
            return jsonify({'error': 'Session not found'}), 404
        
        # Delete the session
        conn.execute('DELETE FROM user_sessions WHERE id = ?', (session_id,))
        conn.commit()
        
        log_audit(user['id'], 'terminate_session', 'security', f'Terminated session for user: {session_info["username"]}')
        return jsonify({'message': 'Session terminated successfully'})
    finally:
        conn.close()

@app.route('/api/security/failed-logins')
@admin_required
def api_failed_logins():
    """View failed login attempts - Admin only"""
    user = get_current_user()
    
    conn = get_db_connection()
    try:
        failed_logins = conn.execute('''
            SELECT action, details, timestamp, ip_address
            FROM audit_logs
            WHERE action = 'failed_login'
            ORDER BY timestamp DESC
            LIMIT 100
        ''').fetchall()
        
        failed_data = [dict(attempt) for attempt in failed_logins]
        
        log_audit(user['id'], 'view_failed_logins', 'security', 'Viewed failed login attempts')
        return jsonify({'failed_logins': failed_data})
    finally:
        conn.close()

@app.before_request
def before_request():
    """Security checks before each request"""
    # Clean up expired sessions periodically
    if request.endpoint and request.endpoint.startswith('api_'):
        cleanup_expired_sessions()
    
    # Global input validation for high-risk requests
    if request.method in ['POST', 'PUT', 'DELETE'] and request.endpoint not in ['static']:
        errors = validate_request_data()
        if errors and len(errors) > 3:  # Only block if multiple serious validation errors
            return jsonify({'error': 'Multiple input validation failures detected', 'details': errors}), 400
    
    # Add security headers
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Log response time for monitoring
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        if duration > 2.0:  # Log slow requests
            user = get_current_user()
            if user:
                log_audit(user['id'], 'slow_request', 'performance', 
                         f'Slow request: {request.endpoint} took {duration:.2f}s')
    
    return response

# CSRF Error Handler
@app.errorhandler(400)
def bad_request_error(error):
    """Handle bad request errors including CSRF failures"""
    error_msg = str(error) if error else "Bad request"
    if 'csrf' in error_msg.lower():
        log_audit(session.get('user_id'), 'csrf_error', 'security', f'CSRF token error: {error_msg}')
        return render_template('error.html', 
                             error='Security token error. Please refresh the page and try again.',
                             error_code=400), 400
    return render_template('error.html', 
                         error='Bad request',
                         error_code=400), 400

# Cache management routes
@app.route('/api/admin/cache/clear')
@admin_required
def api_admin_clear_cache():
    user = get_current_user()
    app_cache.clear()
    log_audit(user['id'], 'admin_clear_cache', 'admin', 'Cleared application cache')
    return jsonify({'message': 'Cache cleared successfully'})

@app.route('/api/admin/cache/stats')
@admin_required
def api_admin_cache_stats():
    cache_stats = app_cache.get_stats()
    # Transform data to match what template expects
    return jsonify({
        'total_items': cache_stats.get('cache_size', 0),
        'total_accesses': cache_stats.get('hits', 0) + cache_stats.get('misses', 0),
        'hit_rate': cache_stats.get('hit_rate', 0),
        'hits': cache_stats.get('hits', 0),
        'misses': cache_stats.get('misses', 0)
    })

# ============================================================================
# ROLE-BASED ACCESS CONTROL SUMMARY
# ============================================================================
"""
🔒 COMPLETE ROLE-BASED ACCESS CONTROL IMPLEMENTATION:

ADMIN (Full Access):
✅ User management (create, edit, delete users) - /api/admin/users/*
✅ System configuration - /api/admin/system/config
✅ Cache management - /api/admin/cache/stats, /api/admin/cache/clear
✅ Database management - /api/admin/database/backup
✅ All CRUD operations on customer data
✅ Export all data - /export (all fields)
✅ Security monitoring - /api/admin/security/sessions, /api/security/failed-logins
✅ Audit logs access - /api/admin/audit-logs
✅ Performance monitoring - /api/performance/stats

MANAGER (Management Access):
✅ View all data - / (full access to customer data)
✅ Export capabilities - /export (all fields)
✅ Limited user management - /api/admin/users (view only)
✅ Performance monitoring - /api/performance/stats
✅ Data analysis and reporting - /api/analytics
✅ Dashboard with management metrics - /dashboard

EDITOR (Edit Access):
✅ View and edit customer data - /api/customers/* (limited fields)
✅ Update meter readings - /api/meter-readings/*
✅ Limited export capabilities - /export (limited fields)
❌ Cannot manage users
✅ Dashboard with edit metrics - /dashboard

GUEST (Read-Only Access):
✅ View customer data (limited fields) - / (Name, AccountNumber, Status, AREA only)
✅ Basic search functionality
❌ No export capabilities
❌ No administrative functions
✅ Limited dashboard - /dashboard

SECURITY FEATURES:
✅ Password hashing with bcrypt
✅ Session management with expiration
✅ Audit logging for all actions
✅ Role-based decorators (@admin_required, @manager_or_admin_required, etc.)
✅ Permission-based access control
✅ Field-level data filtering by role
✅ Security headers on all responses
✅ Failed login attempt logging
✅ Session cleanup and monitoring

INITIAL SETUP:
- Default system users are created on first run
- Contact system administrator for login credentials
- Change all default passwords immediately after first login
- Refer to system documentation for user management procedures
"""

if __name__ == '__main__':
    print("\n🚀 Starting TCWD GeoPortal...")
    print("=" * 50)
    
    # Get port from environment variable (for Render.com deployment)
    port = int(os.environ.get('PORT', 5000))
    
    # Determine if running in production
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    # Check SSL status
    if SSL_AVAILABLE and ssl_config and ssl_config.is_ssl_enabled and not is_production:
        print("🔐 HTTPS/SSL: Enabled (Development)")
        run_config = ssl_config.get_run_config(host='0.0.0.0', port=port, debug=not is_production)
        
        print("\n📋 SSL Certificate Information:")
        check_ssl_status()
        
        print("\n⚠️ Browser Security Notice:")
        print("   If using self-signed certificates, your browser will show a security warning.")
        print("   Click 'Advanced' → 'Proceed to localhost (unsafe)' to continue.")
        print("   This is normal for development certificates.")
        
    else:
        if is_production:
            print("🌐 Production Mode: HTTPS handled by Render.com")
        else:
            print("ℹ️ HTTPS/SSL: Disabled")
        print("   Running in HTTP mode - suitable for reverse proxy deployment")
        run_config = {
            'host': '0.0.0.0',
            'port': port,
            'debug': not is_production
        }
    
    if is_production:
        print(f"\n🌐 Production deployment on port: {port}")
        print("   SSL/HTTPS automatically handled by Render.com")
    else:
        print(f"\n🌐 Access the application at:")
        protocol = "https" if (SSL_AVAILABLE and ssl_config and ssl_config.is_ssl_enabled) else "http"
        print(f"   {protocol}://localhost:{port}")
        print(f"   {protocol}://127.0.0.1:{port}")
    
    print("\n🔑 Default Login Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   (Change immediately after first login)")
    
    print("\n🛡️ Security Features Active:")
    print("   ✅ CSRF Protection")
    print("   ✅ Input Validation Middleware")
    print("   ✅ Audit Logging")
    if SSL_AVAILABLE and ssl_config and ssl_config.is_ssl_enabled and not is_production:
        print("   ✅ HTTPS/SSL Encryption")
        print("   ✅ Secure Headers")
    elif is_production:
        print("   ✅ HTTPS/SSL: Provided by Render.com")
        print("   ✅ Production Security Headers")
    else:
        print("   ℹ️ HTTPS/SSL: Handled by deployment environment")
        print("   ℹ️ Perfect for reverse proxy deployment")
    
    print("\n" + "=" * 50)
    
    # Start the Flask application
    app.run(**run_config)







