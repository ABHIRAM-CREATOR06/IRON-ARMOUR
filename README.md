# 🔐 Iron Armour - Secure Password Vault

A modern, secure Windows desktop application for managing passwords with military-grade encryption. Built with C# and WPF, featuring AES-256-GCM encryption and a sleek dark theme interface.

## ✨ Features

### 🔒 Security Features
- **AES-256-GCM Encryption**: Industry-standard encryption for all stored passwords
- **BCrypt Password Hashing**: Secure master password protection
- **Session-Based Security**: Master password required for each session
- **SQLite Database**: Local encrypted storage with no cloud dependency

### 🖥️ User Interface
- **Modern Dark Theme**: Professional black/red color scheme
- **Tabbed Interface**: Organized sections for different functions
- **Responsive Design**: Fixed window size for consistent experience
- **Animated Elements**: Smooth transitions and visual effects

### 🛠️ Core Functionality
1. **Add Password**: Securely store passwords for accounts
2. **View Passwords**: List and retrieve stored passwords
3. **Generate OTP**: Create strong passwords using HMAC-SHA256
4. **Wi-Fi Analysis**: Real Windows netsh integration for Wi-Fi password analysis

## 🚀 Getting Started

### Prerequisites
- **Windows 10/11**
- **.NET 9.0 SDK** (download from [Microsoft](https://dotnet.microsoft.com/download))

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
2. **Set Master Password**: Create a strong master password (minimum 6 characters)
3. **Access Vault**: Use the four tabs to manage your passwords

## 📋 Usage Guide

### Adding Passwords
1. Click the **"Add Password"** tab
2. Enter the **Account Name** (e.g., Gmail, GitHub)
3. Enter the **Password** to store
4. Click **"Add Password"**

### Viewing Passwords
1. Click the **"View Passwords"** tab
2. Click **"List Accounts"** to see all stored accounts
3. Click **"View"** next to any account to see its password

### Generating OTP Passwords
1. Click the **"Generate OTP"** tab
2. Enter **Account Name**, **Username**, and **OTP Secret**
3. Set desired **Password Length** (8-32 characters)
4. Click **"Generate OTP Password"**

### Wi-Fi Analysis
1. Click the **"Wi-Fi Analysis"** tab
2. Click **"Analyze Wi-Fi Passwords"**
3. View saved Wi-Fi network passwords and their strength

## 🔧 Technical Details

### Architecture
- **Frontend**: WPF (Windows Presentation Foundation)
- **Backend**: C# .NET 9.0
- **Database**: SQLite with Entity Framework Core
- **Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Hashing**: BCrypt for master password

### Security Implementation
- **Master Password**: Hashed with BCrypt, never stored in plain text
- **Password Encryption**: AES-256-GCM with unique salt per entry
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Database Security**: All sensitive data encrypted before storage

### File Structure
```
IronArmour/
├── App.xaml                 # Application entry point
├── App.xaml.cs
├── MainWindow.xaml          # Main application window
├── MainWindow.xaml.cs
├── LoginWindow.xaml         # Login window (removed from final version)
├── LoginWindow.xaml.cs
├── Models.cs                # Database models
├── VaultService.cs          # Core business logic
├── CryptoHelper.cs          # Encryption utilities
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
- **Database errors**: Delete `vault.db` and restart (will recreate database)
- **Wi-Fi analysis fails**: Requires administrator privileges for netsh access

### Reset Application
To completely reset the application:
1. Close the application
2. Delete the `vault.db` file
3. Restart the application

## 📄 License

This project is open-source. Feel free to use, modify, and distribute.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## ⚠️ Disclaimer

This application is for educational and personal use. Always follow your organization's security policies when handling sensitive data.

---

**Built with ❤️ using C# and WPF along with Rust Tauri Framework**