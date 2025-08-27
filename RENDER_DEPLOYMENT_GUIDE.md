# 🚀 TCWD GeoPortal - Complete Render.com Deployment Guide

## Overview
Step-by-step guide for deploying the TCWD GeoPortal to Render.com using Git push deployment with automatic HTTPS/SSL.

## Prerequisites
- ✅ Git installed on your system
- ✅ GitHub account (free)
- ✅ Render.com account (free tier available)
- ✅ Your TCWD GeoPortal project ready

---

## 🎯 **STEP-BY-STEP DEPLOYMENT PROCESS**

### **Step 1: Prepare Git Repository**

#### 1.1 Initialize Git Repository (if not already done)
```bash
cd "E:\WEBSITE\GEOPORTAL_Final with new database and graphs"
git init
```

#### 1.2 Create .gitignore file
Create a `.gitignore` file to exclude sensitive files:
```bash
# Copy this content to .gitignore file
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.env
.venv
.DS_Store
Thumbs.db
*.log
certificates/
uploads/temp/
.pytest_cache/
node_modules/
```

#### 1.3 Add all files to Git
```bash
git add .
git commit -m "Initial commit - TCWD GeoPortal ready for Render deployment"
```

### **Step 2: Create GitHub Repository**

#### 2.1 Create Repository on GitHub
1. Go to https://github.com
2. Click "New repository"
3. Repository name: `tcwd-geoportal`
4. Description: `TCWD GeoPortal - Water Consumption Management System`
5. Set to Public or Private
6. ✅ DO NOT initialize with README (you already have files)
7. Click "Create repository"

#### 2.2 Connect Local Repository to GitHub
```bash
# Replace 'yourusername' with your actual GitHub username
git remote add origin https://github.com/yourusername/tcwd-geoportal.git
git branch -M main
git push -u origin main
```

### **Step 3: Deploy to Render.com**

#### 3.1 Sign Up/Login to Render
1. Go to https://render.com
2. Sign up with GitHub (recommended) or email
3. Authorize Render to access your GitHub repositories

#### 3.2 Create New Web Service
1. Click "New +" in Render dashboard
2. Select "Web Service"
3. Connect your GitHub repository:
   - Click "Connect GitHub"
   - Select your `tcwd-geoportal` repository
   - Click "Connect"

#### 3.3 Configure Web Service Settings
```
Service Name: tcwd-geoportal
Environment: Python 3
Region: Choose closest to your users
Branch: main

Build Command: chmod +x build.sh && ./build.sh
Start Command: python app.py

Instance Type: Free (or upgrade as needed)
```

#### 3.4 Set Environment Variables
In the "Environment Variables" section, add:
```
FLASK_ENV = production
FLASK_DEBUG = False
PYTHON_VERSION = 3.9.19
```

#### 3.5 Deploy
1. Click "Create Web Service"
2. Render will automatically:
   - Clone your repository
   - Install dependencies from requirements.txt
   - Run the build script
   - Start your application
   - Provide HTTPS automatically

### **Step 4: Monitor Deployment**

#### 4.1 Watch Build Logs
- Monitor the "Logs" tab during deployment
- Look for successful build messages
- Check for any error messages

#### 4.2 Expected Build Output
```
🏗️ Starting TCWD GeoPortal build process...
📦 Installing Python packages...
📁 Creating directories...
🗄️ Setting up database...
✅ Database file exists
✅ Users table exists  
✅ TCWD data table exists
✅ Build process completed successfully!
```

### **Step 5: Access Your Deployed Application**

#### 5.1 Get Your App URL
- Render provides a URL like: `https://tcwd-geoportal.onrender.com`
- Found in your service dashboard
- Automatically includes HTTPS/SSL certificate

#### 5.2 First Access
1. Visit your app URL
2. You should see the TCWD GeoPortal login page
3. Default credentials:
   - Username: `admin`
   - Password: `admin123`
4. **IMPORTANT**: Change default password immediately!

---

## 🔧 **CONFIGURATION DETAILS**

### **Files Created for Render Deployment**
- ✅ `Procfile` - Tells Render how to run your app
- ✅ `runtime.txt` - Specifies Python version
- ✅ `build.sh` - Build script for setup
- ✅ Updated `app.py` - Render-compatible configuration
- ✅ Updated `requirements.txt` - All dependencies

### **Automatic Features by Render**
- ✅ **HTTPS/SSL**: Automatic SSL certificates
- ✅ **Custom Domain**: Can add your own domain
- ✅ **Auto-Deploy**: Updates when you push to GitHub
- ✅ **Health Checks**: Automatic monitoring
- ✅ **Logs**: Real-time application logs
- ✅ **Environment Variables**: Secure configuration

### **Database Handling**
- ✅ SQLite database included in deployment
- ✅ Data persists across deployments
- ✅ For production scale, consider PostgreSQL upgrade

---

## 🚨 **TROUBLESHOOTING**

### **Common Issues & Solutions**

#### Issue: Build Failed
```bash
# Check logs for specific errors
# Common fixes:
1. Check requirements.txt for typos
2. Ensure Python version compatibility
3. Check file permissions
```

#### Issue: App Won't Start
```bash
# Check that PORT environment variable is handled
# Verify start command: python app.py
# Check logs for import errors
```

#### Issue: Database Not Working
```bash
# Ensure tcwd_data.db is committed to Git
# Check database file permissions
# Verify table structure
```

### **Testing Locally Before Deploy**
```bash
# Test with production environment
set FLASK_ENV=production
set PORT=5000
python app.py
```

---

## 🔄 **UPDATING YOUR DEPLOYED APP**

### **Make Changes and Redeploy**
```bash
# Make your changes to code
git add .
git commit -m "Description of changes"
git push origin main

# Render automatically detects changes and redeploys
```

---

## 🎯 **COMPLETE COMMAND SEQUENCE**

Here's the complete sequence of commands to run in PowerShell:

```powershell
# Navigate to your project
cd "E:\WEBSITE\GEOPORTAL_Final with new database and graphs"

# Create .gitignore file (create manually with content above)

# Initialize Git (if not already done)
git init

# Add all files
git add .

# Commit files
git commit -m "Initial commit - TCWD GeoPortal ready for Render deployment"

# Add remote repository (replace with your GitHub URL)
git remote add origin https://github.com/yourusername/tcwd-geoportal.git

# Set main branch and push
git branch -M main
git push -u origin main

# Then go to Render.com and follow the web interface steps
```

---

## 🌟 **POST-DEPLOYMENT CHECKLIST**

### **Security Tasks**
- [ ] Change default admin password
- [ ] Create additional user accounts
- [ ] Review audit logs
- [ ] Test all functionality
- [ ] Verify HTTPS is working

### **Optional Enhancements**
- [ ] Set up custom domain
- [ ] Configure monitoring alerts
- [ ] Set up database backups
- [ ] Add performance monitoring
- [ ] Configure error tracking

---

## 📞 **SUPPORT & RESOURCES**

### **Render.com Documentation**
- [Render Python Guide](https://render.com/docs/deploy-flask)
- [Environment Variables](https://render.com/docs/environment-variables)
- [Custom Domains](https://render.com/docs/custom-domains)

### **Troubleshooting Resources**
- Check Render dashboard logs
- GitHub repository issues
- Flask deployment best practices

---

## 🎉 **SUCCESS INDICATORS**

Your deployment is successful when:
- ✅ Build completes without errors
- ✅ App starts and shows "Deploy succeeded" 
- ✅ You can access the login page via HTTPS
- ✅ You can log in with default credentials
- ✅ All features work as expected
- ✅ Database data is accessible

**Your TCWD GeoPortal is now live on the internet with automatic HTTPS!** 🚀
