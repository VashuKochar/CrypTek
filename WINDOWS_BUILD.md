# 🪟 Windows Manual Build Guide

If GitHub Actions fails or you want to build CrypTek manually on Windows, follow this guide.

## 📋 Prerequisites

### Required Software
1. **Python 3.8+** from [python.org](https://www.python.org/downloads/)
   - ✅ **Important**: Check "Add Python to PATH" during installation
2. **Git** from [git-scm.com](https://git-scm.com/download/win)
3. **PowerShell** or **Command Prompt** (built into Windows)

### Verify Installation
Open PowerShell/CMD and run:
```powershell
python --version     # Should show Python 3.8+
git --version        # Should show Git version
pip --version        # Should show pip version
```

## 🚀 Quick Build Process

### 1. Clone the Repository
```powershell
# Clone from GitHub
git clone https://github.com/VashuKochar/CrypTek.git
cd CrypTek
```

### 2. Install Dependencies
```powershell
# Install CrypTek and dependencies
pip install .

# Install PyInstaller for building
pip install pyinstaller
```

### 3. Build Executables
```powershell
# Build CLI executable
pyinstaller --onefile --name cryptek --clean cryptek_cli.py

# Build GUI executable  
pyinstaller --onefile --windowed --name cryptek-gui --clean cryptek_gui_app.py
```

### 4. Test the Executables
```powershell
# Test CLI
.\dist\cryptek.exe --version

# Test GUI (should open window)
.\dist\cryptek-gui.exe
```

## 📁 Output Location

After building, you'll find the executables in:
```
CrypTek\
├── dist\
│   ├── cryptek.exe      # CLI executable
│   └── cryptek-gui.exe  # GUI executable
```

## 🛠️ Alternative: Using Make (Optional)

If you have `make` installed (via Chocolatey or Git Bash):

```powershell
# Install dependencies
make install

# Build both executables
make build

# Or build individually
make build-cli    # CLI only
make build-gui    # GUI only
```

## 🔧 Troubleshooting

### Common Issues

#### "Python is not recognized"
```powershell
# Add Python to PATH manually
set PATH=%PATH%;C:\Python311;C:\Python311\Scripts
```

#### "No module named 'cryptography'"
```powershell
# Install missing dependencies
pip install cryptography pycryptodome
```

#### "tkinter not found" (for GUI)
```powershell
# Reinstall Python with tkinter
# Download Python from python.org and select "tcl/tk and IDLE"
```

#### PyInstaller fails
```powershell
# Clean and retry
rmdir /s dist build
del *.spec
pyinstaller --onefile --name cryptek --clean cryptek.py
```

#### "Access Denied" errors
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell -> "Run as Administrator"
```

## 🎯 Step-by-Step Detailed Guide

### Method 1: PowerShell
```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to desired directory
cd C:\Users\%USERNAME%\Desktop

# 3. Clone repository
git clone https://github.com/VashuKochar/CrypTek.git
cd CrypTek

# 4. Create virtual environment (optional but recommended)
python -m venv cryptek_env
.\cryptek_env\Scripts\activate

# 5. Install package
pip install .

# 6. Install PyInstaller
pip install pyinstaller

# 7. Build CLI
pyinstaller --onefile --name cryptek --distpath dist --workpath build --specpath . --clean cryptek_cli.py

# 8. Build GUI
pyinstaller --onefile --windowed --name cryptek-gui --distpath dist --workpath build --specpath . --clean cryptek_gui_app.py

# 9. Test executables
.\dist\cryptek.exe --help
.\dist\cryptek-gui.exe
```

### Method 2: Command Prompt
```cmd
:: Same steps but use 'cmd' syntax
cd C:\Users\%USERNAME%\Desktop
git clone https://github.com/VashuKochar/CrypTek.git
cd CrypTek
pip install .
pip install pyinstaller
pyinstaller --onefile --name cryptek --clean cryptek_cli.py
pyinstaller --onefile --windowed --name cryptek-gui --clean cryptek_gui_app.py
```

## 📦 Distribution

After successful build:

1. **Navigate to `dist\` folder**
2. **Copy both executables**:
   - `cryptek.exe` (Command line tool)
   - `cryptek-gui.exe` (Graphical interface)
3. **Distribute or use** as standalone applications

## 🔐 Security Notes

- **Run as Administrator** for drive operations
- **Windows Defender** might flag executables (add exception)
- **Virus scanners** may need to whitelist the files
- **Keep source code** for future updates

## ⚡ Quick Commands Summary

```powershell
# One-liner build process
git clone https://github.com/VashuKochar/CrypTek.git && cd CrypTek && pip install . && pip install pyinstaller && pyinstaller --onefile --name cryptek --clean cryptek_cli.py && pyinstaller --onefile --windowed --name cryptek-gui --clean cryptek_gui_app.py
```

## 🎯 Expected Build Time

- **Download**: 1-2 minutes
- **Dependencies**: 2-3 minutes  
- **Build process**: 3-5 minutes per executable
- **Total**: ~10-15 minutes

Your Windows executables will be ready to use! 🚀