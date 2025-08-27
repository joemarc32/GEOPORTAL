#!/usr/bin/env python3
"""
SSL Certificate Generation Script for TCWD GeoPortal
Generates self-signed certificates for development and testing
"""

import os
import subprocess
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_self_signed_certificate():
    """Generate self-signed SSL certificate for development"""
    
    print("🔐 Generating SSL Certificate for TCWD GeoPortal...")
    
    # Create certificates directory
    cert_dir = os.path.join(os.path.dirname(__file__), 'certificates')
    os.makedirs(cert_dir, exist_ok=True)
    
    # Generate private key
    print("📝 Generating private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Metro Manila"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taguig City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Taguig City Water District"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    # Generate certificate
    print("🏷️ Generating certificate...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valid for 1 year
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
            x509.DNSName("*.localhost"),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    key_path = os.path.join(cert_dir, 'tcwd_portal.key')
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"🔑 Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(cert_dir, 'tcwd_portal.crt')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"📜 Certificate saved to: {cert_path}")
    
    # Set appropriate permissions (Windows)
    try:
        import stat
        os.chmod(key_path, stat.S_IREAD | stat.S_IWRITE)
        os.chmod(cert_path, stat.S_IREAD | stat.S_IWRITE)
        print("🔒 Set secure file permissions")
    except:
        print("⚠️ Could not set file permissions (Windows limitation)")
    
    print("\n✅ SSL Certificate generation completed!")
    print(f"📁 Certificate directory: {cert_dir}")
    print(f"🔑 Private key: {os.path.basename(key_path)}")
    print(f"📜 Certificate: {os.path.basename(cert_path)}")
    print("\n⚠️ WARNING: This is a SELF-SIGNED certificate for DEVELOPMENT ONLY!")
    print("   For production, use certificates from a trusted Certificate Authority.")
    
    return cert_path, key_path


def generate_csr_for_production():
    """Generate Certificate Signing Request for production certificates"""
    
    print("\n🏢 Generating CSR for Production Certificate...")
    
    cert_dir = os.path.join(os.path.dirname(__file__), 'certificates')
    os.makedirs(cert_dir, exist_ok=True)
    
    # Generate private key for production
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # CSR details (customize as needed)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Metro Manila"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taguig City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Taguig City Water District"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
        x509.NameAttribute(NameOID.COMMON_NAME, "your-domain.com"),  # Change this!
    ])
    
    # Generate CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("your-domain.com"),  # Change this!
            x509.DNSName("www.your-domain.com"),  # Change this!
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Save production private key
    prod_key_path = os.path.join(cert_dir, 'tcwd_portal_production.key')
    with open(prod_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Save CSR
    csr_path = os.path.join(cert_dir, 'tcwd_portal_production.csr')
    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    print(f"🔑 Production private key: {prod_key_path}")
    print(f"📝 CSR file: {csr_path}")
    print("\n📋 Next steps for production SSL:")
    print("1. Submit the CSR file to your Certificate Authority")
    print("2. Complete domain validation process")
    print("3. Download the signed certificate")
    print("4. Update ssl_config.py with production certificate paths")


def install_certificate_requirements():
    """Install required packages for SSL certificate generation"""
    
    print("📦 Installing SSL certificate requirements...")
    required_packages = [
        'cryptography>=3.4.8'
    ]
    
    try:
        for package in required_packages:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print("✅ SSL requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False


if __name__ == '__main__':
    print("🔐 TCWD GeoPortal SSL Certificate Generator")
    print("=" * 50)
    
    # Check if cryptography is available
    try:
        import cryptography
        print(f"✅ Cryptography library version: {cryptography.__version__}")
    except ImportError:
        print("📦 Installing cryptography library...")
        if not install_certificate_requirements():
            print("❌ Failed to install requirements. Please install manually:")
            print("   pip install cryptography>=3.4.8")
            sys.exit(1)
        import cryptography
    
    print("\nSelect certificate type:")
    print("1. Self-signed certificate (Development)")
    print("2. CSR for production certificate")
    print("3. Both")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice in ['1', '3']:
        generate_self_signed_certificate()
    
    if choice in ['2', '3']:
        generate_csr_for_production()
    
    print("\n🎉 Certificate generation process completed!")
