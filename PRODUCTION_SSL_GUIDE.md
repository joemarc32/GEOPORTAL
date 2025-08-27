# 🚀 TCWD GeoPortal Production SSL Deployment Guide

## Overview
This guide covers deploying the TCWD GeoPortal with proper SSL certificates in a production environment.

## Prerequisites
- Valid domain name
- SSL certificate from a trusted Certificate Authority (CA)
- Production server with Python 3.7+

## 1. Obtain SSL Certificate

### Option A: Let's Encrypt (Free)
```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com
```

### Option B: Commercial SSL Certificate
1. Generate CSR using the application:
   ```bash
   python generate_ssl_certificate.py
   # Select option 2 for production CSR
   ```
2. Submit CSR to your Certificate Authority
3. Download the signed certificate files

## 2. Install Production Certificates

1. Copy your SSL files to the certificates directory:
   ```
   certificates/
   ├── tcwd_portal_production.crt  (Your signed certificate)
   ├── tcwd_portal_production.key  (Your private key)
   └── ca_bundle.crt               (CA bundle, if required)
   ```

2. Set secure file permissions:
   ```bash
   chmod 600 certificates/tcwd_portal_production.key
   chmod 644 certificates/tcwd_portal_production.crt
   ```

## 3. Production Configuration

### Environment Variables
```bash
export FLASK_ENV=production
export FLASK_DEBUG=False
export SSL_CERT_PATH="/path/to/certificates/tcwd_portal_production.crt"
export SSL_KEY_PATH="/path/to/certificates/tcwd_portal_production.key"
```

### Reverse Proxy Setup (Nginx) - Recommended
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/certificates/tcwd_portal_production.crt;
    ssl_certificate_key /path/to/certificates/tcwd_portal_production.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}
```

### Direct Flask SSL (Alternative)
If not using a reverse proxy, Flask can handle SSL directly:

```python
# Set environment variable
export FLASK_ENV=production

# Run the application
python app.py
```

### Systemd Service (Linux)
```ini
[Unit]
Description=TCWD GeoPortal
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/path/to/tcwd-geoportal
Environment=FLASK_ENV=production
Environment=FLASK_DEBUG=False
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## 4. Security Checklist

### SSL/TLS Security
- ✅ Use TLS 1.2 or higher
- ✅ Strong cipher suites only
- ✅ HTTP Strict Transport Security (HSTS)
- ✅ Certificate transparency monitoring
- ✅ Regular certificate renewal

### Application Security
- ✅ Change all default passwords
- ✅ Enable audit logging
- ✅ Configure proper file permissions
- ✅ Set up firewall rules
- ✅ Regular security updates

### Monitoring
- ✅ SSL certificate expiry monitoring
- ✅ Application performance monitoring
- ✅ Security event logging
- ✅ Backup and disaster recovery

## 5. Testing Production SSL

### SSL Test Commands
```bash
# Test SSL configuration
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate details
openssl x509 -in certificates/tcwd_portal_production.crt -text -noout

# Test SSL rating
curl -s "https://api.ssllabs.com/api/v3/analyze?host=your-domain.com"
```

### Browser Testing
1. Access https://your-domain.com
2. Check for green padlock icon
3. Verify certificate details
4. Test all application functionality

## 6. Deployment Options

### Option 1: Reverse Proxy (Recommended)
- **Benefits**: Better performance, easier certificate management, additional security
- **Setup**: nginx/Apache handles SSL, Flask runs on HTTP
- **SSL Files**: Not needed in Flask application

### Option 2: Direct Flask SSL
- **Benefits**: Simpler setup, no additional software
- **Setup**: Flask handles SSL directly
- **SSL Files**: Required in certificates/ directory

### Option 3: Cloud Deployment
- **Platforms**: Heroku, AWS, Azure, Google Cloud
- **Benefits**: Automatic SSL management
- **SSL Files**: Not needed, handled by platform

## 7. Maintenance

### Certificate Renewal
- Monitor certificate expiry (30 days before)
- Set up automatic renewal for Let's Encrypt
- Test renewal process regularly

### Security Updates
- Keep SSL certificates updated
- Monitor security advisories
- Update dependencies regularly
- Conduct regular security audits

## 8. Troubleshooting

### Common Issues
- **Certificate not trusted**: Check CA bundle installation
- **Mixed content warnings**: Ensure all resources use HTTPS
- **Performance issues**: Enable HTTP/2 and SSL session resumption
- **Connection timeouts**: Check firewall and reverse proxy configuration

### Log Locations
- Application logs: Check Flask application output
- SSL/TLS logs: `/var/log/nginx/` (if using Nginx)
- System logs: `/var/log/syslog`

## 9. Performance Optimization

### SSL Optimization
```nginx
# Enable HTTP/2
listen 443 ssl http2;

# SSL session resumption
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;

# Enable gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss;
```

## 10. Security Hardening

### Additional Security Headers
```nginx
# Security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
```

### Firewall Configuration
```bash
# Allow only necessary ports
ufw allow ssh
ufw allow http
ufw allow https
ufw enable
```

For support, contact the TCWD IT Department.
