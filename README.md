# CrypTek 🛡️

Standalone Utility for encrypting/decrypting Windows files, folders, or drives with custom extensions and full audit logs—no dependencies, no guesswork.

## Table of Contents

* [About](#about)
* [Reference Tool](#reference-tool)
* [Limitations](#limitations)
* [Features](#features)
* [CLI & GUI Support](#cli--gui-support)
* [Installation](#installation)
* [Usage](#usage)
* [Examples](#examples)
* [Flags & Options](#flags--options)
* [Error Handling](#error-handling)
* [Logging](#logging)
* [Contribution](#contribution)
* [License](#license)

---

## About

CrypTek consolidates strong encryption, extension control, and audit logging into a single CLI and GUI tool built with Python and PyInstaller to replace scattered, GUI-based workflows on Windows.

---

## Reference Tool

Microsoft’s “AES Encryption Tools” (Windows Store app) encrypts files with AES via GUI only. It lacks CLI control, extension handling, audit logging, and error reporting ([apps.microsoft.com](https://apps.microsoft.com/detail/9nblggh5glqk?hl=en-US&gl=IN)).

---

## Limitations of Reference Tool

* Supports only AES.
* No custom extensions.
* No logging or audit capabilities.
* No CLI interface.
* Silent on encryption failures.

---

## Features

* Encrypts and decrypts files, folders (recursive), and drives.
* AES‑128/256 with user-configurable modes (CBC/GCM), RSA hybrid with configurable key sizes, Blowfish with configurable key sizes.
* Accepts password, passphrase, or PEM/DER key files (examples provided in usage section).
* Appends custom extensions and restores original names during decryption.
* Recursive folder support and optional deletion.
* Text or JSON audit logs.
* Detects permission errors, bad keys, and corrupt data.
* Standalone `.exe` packaged with PyInstaller.
* Compatible with Windows 10/11 (32 & 64-bit).
* **Requires Administrator privileges** for drive-level operations.

---

## CLI & GUI Support

* **CLI** for scripting and automation with full flag support.
* **GUI** (Tkinter/PySimpleGUI) for user-friendly encryption without the need for command-line knowledge.
* Both built from shared Python core and packaged separately via PyInstaller:

  * `cryptek.exe` (CLI)
  * `cryptek-gui.exe` (GUI)

---

## Installation

1. Clone or download the repository.
2. Build both executables:

   ```bash
   pip install pyinstaller
   pyinstaller cryptek.py --onefile --name cryptek
   pyinstaller cryptek_gui.py --onefile --windowed --name cryptek-gui
   ```
3. Optionally add to `PATH` and verify:

   ```powershell
   cryptek.exe --version
   cryptek-gui.exe
   ```

---

## Usage

### CLI

```powershell
cryptek.exe --mode encrypt --path "C:\docs\file.txt" \
  --algo AES256 --aes-mode GCM --key "pass123" --ext ".vault" --log "C:\logs\ct.log"
```

### Key File Examples

Generate RSA key pair:
```powershell
# Generate private key (2048-bit)
openssl genpkey -algorithm RSA -out private.pem -pkcs8 -aes256
# Extract public key
openssl rsa -pubout -in private.pem -out public.pem
```

Use key file:
```powershell
cryptek.exe --mode encrypt --path "C:\docs\file.txt" \
  --algo RSA --rsa-keysize 2048 --key "public.pem" --ext ".vault" --log "C:\logs\ct.log"
```

### GUI

* Run `python cryptek_gui.py` or `cryptek-gui.exe` **as Administrator** for drive operations.
* Select mode, path, algorithm, key, extension, and logging options.
* Configure algorithm-specific options (AES mode, RSA key size, Blowfish key size).
* Click **Start Operation** to execute.

---

## Examples

```powershell
# Encrypt folder with AES256-GCM
cryptek.exe --mode encrypt --path "C:\media" --algo AES256 --aes-mode GCM \
  --key "arch1ve!" --ext ".encx" --recursive --delete-original \
  --log "C:\logs\ct.log"
```

```powershell
# Encrypt with Blowfish (custom key size)
cryptek.exe --mode encrypt --path "C:\docs" --algo Blowfish \
  --blowfish-keysize 448 --key "mypassword" --ext ".bf" --log "C:\logs\ct.log"
```

```powershell
# Decrypt files (automatically detects original extension)
cryptek.exe --mode decrypt --path "C:\media" --key "arch1ve!" \
  --recursive --log "C:\logs\ct.log"
```

```powershell
# Launch GUI as Administrator
cryptek-gui.exe
```

---

## Flags & Options

| Flag                | Description                                          |
| ------------------- | ---------------------------------------------------- |
| `--mode`            | `encrypt` or `decrypt` **(required)**                |
| `--path`            | Target file, folder, or drive path **(required)**    |
| `--algo`            | AES128, AES256, RSA, Blowfish              |
| `--aes-mode`        | AES mode: `CBC` or `GCM` (default: CBC)              |
| `--rsa-keysize`     | RSA key size: 1024, 2048, 3072, 4096 (default: 2048)|
| `--blowfish-keysize`| Blowfish key size in bits: 32-448 (default: 128)    |
| `--key`             | Password or key file path **(required)**             |
| `--ext`             | Custom extension for encrypted output **(required for encrypt)** |
| `--recursive`       | Process folders recursively                          |
| `--delete-original` | Delete source files post-encryption                  |
| `--log`             | Path to audit log file **(required)**                |
| `--log-format`      | `text` (default) or `json`                           |

---

## Error Handling

Validates all inputs and flags, checks file/directory access, detects incorrect keys or corrupted files, and provides detailed error messages. Administrator privileges are automatically requested for drive-level operations.

---

## Logging

Operations log timestamp, mode, algorithm, input/output paths, and status. Outputs support plaintext or structured JSON.

---

## Development

### Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/CrypTek.git
cd CrypTek

# Install dependencies
make install

# Run tests
make test

# Test CLI
make run

# Test GUI  
make run-gui
```

### Available Commands

```bash
make help          # Show all available commands
make install       # Install core dependencies
make install-dev   # Install development dependencies
make test          # Run test suite
make clean         # Clean build artifacts
make build         # Build executables
make run           # Test CLI
make run-gui       # Launch GUI
make lint          # Run code linting
make format        # Format code
```

### Building Executables

Local build:
```bash
make build         # Build both CLI and GUI executables
```

Automated Windows releases:
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0  # Triggers automated Windows build
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- 🚀 Setting up development environment
- 📋 Pull request process
- 🔐 Security guidelines
- 🏗️ Architecture guidelines
- 📝 Documentation standards

### Code Quality Standards

- ✅ **Type hints** throughout codebase
- ✅ **Comprehensive tests** with pytest
- ✅ **Security-focused** development practices
- ✅ **Professional documentation**
- ✅ **Cross-platform compatibility**

---

## License

MIT License. See `LICENSE` for details.
