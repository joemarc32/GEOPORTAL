#!/usr/bin/env bash
# Render.com build script for TCWD GeoPortal - Python 3.10 Compatible

echo "🏗️ Starting TCWD GeoPortal build process..."

# Check Python version
python --version

# Upgrade pip to latest version
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies with wheel preference
echo "📦 Installing Python packages (preferring wheels to avoid compilation)..."
pip install --only-binary=all -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads
mkdir -p certificates
mkdir -p logs

# Set proper permissions
chmod 755 uploads
chmod 755 certificates
chmod 755 logs

# Database setup and verification
echo "🗄️ Setting up database..."
python -c "
import sqlite3
import os

print('Checking database...')
if os.path.exists('tcwd_data.db'):
    print('✅ Database file exists')
    conn = sqlite3.connect('tcwd_data.db')
    cursor = conn.cursor()
    
    # Check if tables exist
    cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='users';\")
    if cursor.fetchone():
        print('✅ Users table exists')
    else:
        print('⚠️ Users table not found - will be created on first run')
    
    cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='tcwd_data';\")
    if cursor.fetchone():
        print('✅ TCWD data table exists')
        # Get record count
        cursor.execute('SELECT COUNT(*) FROM tcwd_data;')
        count = cursor.fetchone()[0]
        print(f'📊 Database contains {count} records')
    else:
        print('⚠️ TCWD data table not found')
    
    conn.close()
else:
    print('⚠️ Database file not found - will be created on first run')
"

# Display environment info
echo "🌍 Environment Information:"
python -c "
import sys
print(f'Python version: {sys.version}')
print(f'Platform: {sys.platform}')
"

echo "✅ Build process completed successfully!"
echo "🚀 Ready to start TCWD GeoPortal..."
