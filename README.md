# 🔐 Iron Armour - Secure Password Vault

A modern, enterprise-grade Windows desktop application for managing passwords with military-grade encryption and MySQL server synchronization. Built with C# and WPF, featuring AES-256-GCM encryption, multi-user support, and comprehensive password management capabilities.

## ✨ Features

### 🔒 Security Features
- **AES-256-GCM Encryption**: Industry-standard encryption for all stored passwords
- **BCrypt Password Hashing**: Secure master password protection
- **Multi-User Support**: Individual user accounts with isolated data
- **Session-Based Security**: Master password required for each session
- **SQLite + MySQL Support**: Local storage with optional server synchronization
- **Zero-Knowledge Architecture**: Server never sees plain text passwords

### 🖥️ User Interface
- **Modern Dark Theme**: Professional gradient design with animations
- **Tabbed Interface**: Organized sections for different functions
- **Login System**: Secure user authentication with account creation
- **Responsive Design**: Fixed window size for consistent experience
- **Animated Elements**: Smooth transitions and visual effects
- **Status Notifications**: Real-time feedback for all operations

### 🛠️ Core Functionality
1. **User Management**: Create accounts and secure login system
2. **Add Password**: Securely store passwords for accounts
3. **View Passwords**: List and retrieve stored passwords
4. **Generate OTP**: Create strong passwords using HMAC-SHA256
5. **Wi-Fi Analysis**: Real Windows netsh integration for Wi-Fi password analysis
6. **Server Synchronization**: Optional MySQL server sync for multi-device access
7. **Password Reports**: PDF/CSV export for password strength analysis

### 🔄 Synchronization Features
- **MySQL Server Sync**: Enterprise-grade server synchronization
- **HTTP API Integration**: RESTful API for secure server communication
- **Bidirectional Sync**: Sync between multiple devices
- **Conflict Resolution**: Automatic conflict detection and resolution
- **Offline Support**: Full functionality without internet connection
- **Auto-Sync**: Configurable automatic synchronization

## 🚀 Getting Started

### Prerequisites
- **Windows 10/11**
- **.NET 9.0 SDK** (download from [Microsoft](https://dotnet.microsoft.com/download))
- **MySQL Server** (optional, for server synchronization)

### Installation
1. Clone or download the repository
2. Navigate to the `IronArmour` directory
3. Run the application:
   ```bash
   cd IronArmour
   dotnet run
   ```

### First Use
1. **Launch** the application
2. **Create Account**: Click "Create New Account" and set up your user account
3. **Login**: Use your credentials to log into the application
4. **Set Master Password**: Create a strong master password for your vault
5. **Access Vault**: Use the tabs to manage your passwords

### MySQL Server Setup (Optional)
For enterprise synchronization across multiple devices:

#### Option 1: HTTP API Server (Recommended)
1. Set up a MySQL database:
   ```sql
   CREATE DATABASE ironarmour;
   CREATE USER 'ironarmour'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON ironarmour.* TO 'ironarmour'@'localhost';
   ```

2. Create a REST API server (Node.js example):
   ```javascript
   // server.js
   const express = require('express');
   const mysql = require('mysql2/promise');
   const bcrypt = require('bcrypt');
   const jwt = require('jsonwebtoken');

   const app = express();
   app.use(express.json());

   const db = mysql.createPool({
     host: 'localhost',
     user: 'ironarmour',
     password: 'your_password',
     database: 'ironarmour'
   });

   // API endpoints for sync operations
   app.post('/api/sync', authenticateToken, async (req, res) => {
     // Handle password synchronization
   });

   app.listen(3000, () => console.log('Iron Armour API running on port 3000'));
   ```

3. Configure Iron Armour:
   - Go to Settings tab
   - Set Database Type: "MySQL"
   - Server URL: "http://localhost:3000"
   - Auth Token: Your JWT token
   - Test Connection and start syncing

## 📋 Usage Guide

### Account Management
1. **Create Account**: Click "Create New Account" on login screen
2. **Login**: Enter your username and password
3. **Master Password**: Set up your vault's master password (required for encryption)

### Adding Passwords
1. Click the **"Add Password"** tab
2. Enter the **Account Name** (e.g., Gmail, GitHub)
3. Enter the **Password** to store
4. Click **"Add Password"**
5. Password is encrypted and stored locally

### Viewing Passwords
1. Click the **"View Passwords"** tab
2. Click **"List Accounts"** to see all stored accounts
3. Click **"View"** next to any account to decrypt and see its password
4. Passwords are decrypted on-demand for security

### Generating OTP Passwords
1. Click the **"Generate OTP"** tab
2. Enter **Account Name**, **Username**, and **OTP Secret**
3. Set desired **Password Length** (8-32 characters)
4. Click **"Generate OTP Password"**
5. Strong, unique password generated using HMAC-SHA256

### Wi-Fi Analysis
1. Click the **"Wi-Fi Analysis"** tab
2. Click **"Analyze Wi-Fi Passwords"**
3. Application uses Windows `netsh` to retrieve saved Wi-Fi passwords
4. View network names, passwords, and security strength analysis

### Server Synchronization
1. Go to **Settings** tab
2. Enable **Sync** checkbox
3. Choose **Database Type**: "MySQL" for server sync
4. Enter **Server URL** (API endpoint)
5. Set **Auth Token** for authentication
6. Configure sync direction and intervals
7. Click **"Test Connection"** to verify setup
8. Click **"Sync Now"** to synchronize with server

### Password Reports
1. Use **"Export PDF Report"** or **"Export CSV Report"** buttons
2. Choose save location for the report
3. Reports include password strength analysis
4. PDF reports are automatically opened after creation

## 🔧 Technical Details

### Architecture
- **Frontend**: WPF (Windows Presentation Foundation) with modern UI
- **Backend**: C# .NET 9.0 with async/await patterns
- **Database**: SQLite (local) + MySQL (server sync) with Entity Framework Core
- **Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Hashing**: BCrypt for user passwords, PBKDF2 for encryption keys
- **Synchronization**: HTTP REST API with JWT authentication

### Security Implementation
- **User Authentication**: BCrypt-hashed passwords with salt
- **Master Password**: Per-user vault encryption key
- **Password Encryption**: AES-256-GCM with unique salt per entry
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Database Security**: All sensitive data encrypted before storage
- **Zero-Knowledge**: Server synchronization without exposing plain text
- **Session Security**: Master password required for decryption operations

### Database Schema
```sql
-- Users table (for multi-user support)
CREATE TABLE Users (
    Id INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(255) UNIQUE NOT NULL,
    HashedPassword VARCHAR(255) NOT NULL,
    Salt VARCHAR(255) NOT NULL,
    CreatedAt DATETIME NOT NULL
);

-- Master passwords table (per-user vault keys)
CREATE TABLE MasterPasswords (
    Id INT PRIMARY KEY AUTO_INCREMENT,
    UserId INT NOT NULL,
    HashedPassword VARCHAR(255) NOT NULL,
    Salt VARCHAR(255) NOT NULL,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Password entries table
CREATE TABLE PasswordEntries (
    Id INT PRIMARY KEY AUTO_INCREMENT,
    UserId INT NOT NULL,
    Account VARCHAR(255) NOT NULL,
    EncryptedPassword TEXT NOT NULL,
    Nonce VARCHAR(255) NOT NULL,
    Salt VARCHAR(255) NOT NULL,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Sync settings table
CREATE TABLE SyncSettings (
    Id INT PRIMARY KEY AUTO_INCREMENT,
    IsSyncEnabled BOOLEAN DEFAULT FALSE,
    ServerUrl VARCHAR(500),
    AuthToken VARCHAR(500),
    DatabaseType VARCHAR(50) DEFAULT 'HTTP',
    MySqlConnectionString TEXT,
    SyncDirection INT DEFAULT 0,
    AutoSyncEnabled BOOLEAN DEFAULT FALSE,
    SyncIntervalMinutes INT DEFAULT 30,
    ExcludedAccounts TEXT
);
```

### File Structure
```
IronArmour/
├── App.xaml                 # Application entry point
├── App.xaml.cs
├── MainWindow.xaml          # Main application window (vault interface)
├── MainWindow.xaml.cs
├── LoginWindow.xaml         # User authentication window
├── LoginWindow.xaml.cs
├── Models.cs                # Entity Framework models
├── VaultService.cs          # Core business logic and encryption
├── CryptoHelper.cs          # Cryptographic utilities
├── SyncManager.cs           # Server synchronization logic
├── MySqlSyncProvider.cs     # MySQL server communication
├── SyncModels.cs            # Sync-related data models
├── ReportGenerator.cs       # PDF/CSV report generation
├── IronArmour.csproj        # Project configuration
└── vault.db                 # SQLite database (created at runtime)
```

## 🔐 Security Best Practices

- **Strong Master Password**: Use a long, complex master password
- **Regular Backups**: Backup your `vault.db` file regularly
- **Session Management**: Passwords are only accessible during active sessions
- **Local Storage**: No data is sent to external servers
- **Encryption**: All passwords are encrypted with unique salts

## 🐛 Troubleshooting

### Common Issues
- **Application won't start**: Ensure .NET 9.0 SDK is installed
- **Login fails**: Check username/password or reset database
- **Database errors**: Delete `vault.db` and restart (will recreate database)
- **Sync connection fails**: Verify server URL and authentication token
- **Wi-Fi analysis fails**: Requires administrator privileges for netsh access
- **MySQL connection errors**: Check connection string and server permissions

### Reset Application
To completely reset the application:
1. Close the application
2. Delete the `vault.db` file
3. Restart the application
4. Create new account and set up master password

### MySQL Sync Troubleshooting
- **Connection refused**: Ensure MySQL server is running and accessible
- **Authentication failed**: Verify username/password in connection string
- **Permission denied**: Grant proper permissions to database user
- **SSL errors**: Configure SSL settings in connection string if required

### Performance Issues
- **Slow startup**: Database migration may be running (normal for first run)
- **Sync delays**: Check network connectivity and server response time
- **Memory usage**: Large password databases may require more RAM

## 📄 License

This project is open-source. Feel free to use, modify, and distribute.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## ⚠️ Disclaimer

This application is for educational and personal use. Always follow your organization's security policies when handling sensitive data.

## 🚀 API Reference (For MySQL Sync)

### Authentication Endpoints
```http
POST /api/auth
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "userpassword"
}

Response:
{
  "success": true,
  "token": "jwt_token_here",
  "userId": 123
}
```

### Sync Endpoints
```http
POST /api/sync
Authorization: Bearer jwt_token
Content-Type: application/json

{
  "passwords": [
    {
      "id": "unique_id",
      "account": "Gmail",
      "encryptedPassword": "encrypted_data",
      "nonce": "nonce_value",
      "salt": "salt_value",
      "lastModified": "2024-01-01T00:00:00Z",
      "isDeleted": false
    }
  ],
  "lastSync": "2024-01-01T00:00:00Z"
}

Response:
{
  "success": true,
  "serverPasswords": [...],
  "conflicts": [...],
  "message": "Sync completed successfully"
}
```

### Device Registration
```http
POST /api/devices/register
Authorization: Bearer jwt_token
Content-Type: application/json

{
  "deviceId": "unique_device_id",
  "deviceName": "My Laptop"
}

Response:
{
  "success": true,
  "message": "Device registered successfully"
}
```

## 📊 System Requirements

### Minimum Requirements
- **OS**: Windows 10 version 1903 or later
- **RAM**: 512 MB
- **Storage**: 50 MB free space
- **Display**: 1024x768 resolution

### Recommended Requirements
- **OS**: Windows 10/11
- **RAM**: 1 GB
- **Storage**: 100 MB free space
- **Display**: 1920x1080 resolution
- **Network**: Stable internet for sync features

## 🔄 Release Notes

### Version 2.0.0 (Current)
- ✅ Multi-user support with secure login system
- ✅ MySQL server synchronization
- ✅ Enhanced UI with animations and modern design
- ✅ Password strength analysis and reporting
- ✅ Real Windows Wi-Fi password analysis
- ✅ PDF/CSV export functionality
- ✅ Zero-knowledge server architecture

### Version 1.0.0
- Basic password vault functionality
- Local SQLite storage
- AES-256-GCM encryption
- Simple WPF interface

---

**Built with ❤️ using C# and WPF - Enterprise-Grade Password Management** 🛡️⚡🔐