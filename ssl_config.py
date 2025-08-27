"""
SSL Configuration for TCWD GeoPortal
Handles SSL/HTTPS configuration for development and production environments
"""

import os
import ssl
from flask import Flask


class SSLConfig:
    """SSL Configuration handler"""
    
    def __init__(self, app_root_dir=None):
        if app_root_dir is None:
            app_root_dir = os.path.dirname(__file__)
        
        self.app_root_dir = app_root_dir
        self.cert_dir = os.path.join(app_root_dir, 'certificates')
        
        # Development SSL files
        self.dev_cert_file = os.path.join(self.cert_dir, 'tcwd_portal.crt')
        self.dev_key_file = os.path.join(self.cert_dir, 'tcwd_portal.key')
        
        # Production SSL files
        self.prod_cert_file = os.path.join(self.cert_dir, 'tcwd_portal_production.crt')
        self.prod_key_file = os.path.join(self.cert_dir, 'tcwd_portal_production.key')
        
        # SSL Context settings
        self.ssl_context = None
        self.is_ssl_enabled = False
        
    def setup_development_ssl(self):
        """Setup SSL for development environment"""
        try:
            if not self._check_certificate_files(self.dev_cert_file, self.dev_key_file):
                print("⚠️ Development SSL certificates not found!")
                print("Run 'python generate_ssl_certificate.py' to generate them.")
                return False
            
            # Create SSL context for development
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Load certificate and key
            context.load_cert_chain(self.dev_cert_file, self.dev_key_file)
            
            # Development-friendly settings
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.ssl_context = context
            self.is_ssl_enabled = True
            
            print("🔐 Development SSL enabled")
            print(f"📜 Certificate: {os.path.basename(self.dev_cert_file)}")
            print(f"🔑 Private key: {os.path.basename(self.dev_key_file)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup development SSL: {e}")
            return False
    
    def setup_production_ssl(self):
        """Setup SSL for production environment"""
        try:
            if not self._check_certificate_files(self.prod_cert_file, self.prod_key_file):
                print("⚠️ Production SSL certificates not found!")
                print("Please obtain valid SSL certificates from a Certificate Authority.")
                return False
            
            # Create SSL context for production
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Production security settings
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            context.check_hostname = False  # Handled by reverse proxy in production
            context.verify_mode = ssl.CERT_NONE
            
            # Load certificate and key
            context.load_cert_chain(self.prod_cert_file, self.prod_key_file)
            
            # Enable session resumption for better performance
            context.options |= ssl.OP_NO_COMPRESSION
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            context.options |= ssl.OP_SINGLE_DH_USE
            context.options |= ssl.OP_SINGLE_ECDH_USE
            
            self.ssl_context = context
            self.is_ssl_enabled = True
            
            print("🔐 Production SSL enabled")
            print(f"📜 Certificate: {os.path.basename(self.prod_cert_file)}")
            print(f"🔑 Private key: {os.path.basename(self.prod_key_file)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup production SSL: {e}")
            return False
    
    def setup_auto_ssl(self, environment='development'):
        """Automatically setup SSL based on environment"""
        if environment == 'production':
            return self.setup_production_ssl()
        else:
            return self.setup_development_ssl()
    
    def _check_certificate_files(self, cert_file, key_file):
        """Check if certificate files exist and are readable"""
        return (os.path.isfile(cert_file) and 
                os.path.isfile(key_file) and 
                os.access(cert_file, os.R_OK) and 
                os.access(key_file, os.R_OK))
    
    def get_ssl_context(self):
        """Get the configured SSL context"""
        return self.ssl_context if self.is_ssl_enabled else None
    
    def configure_flask_app(self, app):
        """Configure Flask app with SSL security headers"""
        
        @app.before_request
        def ssl_security_headers():
            """Add SSL-related security headers"""
            pass  # Headers will be added in after_request
        
        @app.after_request
        def add_ssl_security_headers(response):
            """Add SSL security headers to all responses"""
            if self.is_ssl_enabled:
                # Strict Transport Security - force HTTPS
                response.headers['Strict-Transport-Security'] = (
                    'max-age=31536000; includeSubDomains; preload'
                )
                
                # Mixed content protection
                response.headers['Content-Security-Policy'] = (
                    "upgrade-insecure-requests; "
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "connect-src 'self'; "
                    "font-src 'self'; "
                    "object-src 'none'; "
                    "media-src 'self'; "
                    "frame-src 'none'"
                )
                
            # Always add these security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            return response
    
    def get_run_config(self, host='0.0.0.0', port=5000, debug=False):
        """Get Flask app.run() configuration with SSL"""
        config = {
            'host': host,
            'port': port,
            'debug': debug,
        }
        
        if self.is_ssl_enabled and self.ssl_context:
            config['ssl_context'] = self.ssl_context
            print(f"🌐 Server will run with HTTPS on https://{host}:{port}")
        else:
            print(f"🌐 Server will run with HTTP on http://{host}:{port}")
            print("⚠️ Running without SSL - not recommended for production!")
        
        return config


# Utility functions
def create_ssl_config(environment='development'):
    """Create and configure SSL for the specified environment"""
    ssl_config = SSLConfig()
    
    if ssl_config.setup_auto_ssl(environment):
        return ssl_config
    else:
        print("⚠️ SSL setup failed, running without HTTPS")
        return ssl_config


def check_ssl_status():
    """Check the status of SSL certificates"""
    ssl_config = SSLConfig()
    
    print("\n🔍 SSL Certificate Status Check")
    print("=" * 40)
    
    # Check development certificates
    if ssl_config._check_certificate_files(ssl_config.dev_cert_file, ssl_config.dev_key_file):
        print("✅ Development certificates: Available")
        try:
            # Check certificate validity
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            with open(ssl_config.dev_cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            print(f"   📅 Valid from: {cert.not_valid_before}")
            print(f"   📅 Valid until: {cert.not_valid_after}")
            print(f"   🏷️ Subject: {cert.subject.rfc4514_string()}")
            
            # Check if certificate is expired
            from datetime import datetime
            now = datetime.utcnow()
            if now > cert.not_valid_after:
                print("   ⚠️ Certificate is EXPIRED!")
            elif (cert.not_valid_after - now).days < 30:
                print(f"   ⚠️ Certificate expires in {(cert.not_valid_after - now).days} days")
            else:
                print("   ✅ Certificate is valid")
                
        except ImportError:
            print("   ℹ️ Install 'cryptography' package for detailed certificate info")
        except Exception as e:
            print(f"   ❌ Error reading certificate: {e}")
    else:
        print("❌ Development certificates: Not found")
        print("   Run 'python generate_ssl_certificate.py' to generate them")
    
    # Check production certificates
    if ssl_config._check_certificate_files(ssl_config.prod_cert_file, ssl_config.prod_key_file):
        print("✅ Production certificates: Available")
    else:
        print("❌ Production certificates: Not found")
        print("   Obtain certificates from a trusted Certificate Authority")
    
    return ssl_config


if __name__ == '__main__':
    check_ssl_status()
