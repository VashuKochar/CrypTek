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
* AES‑128/256 (CBC/GCM), RSA hybrid, ChaCha20, Blowfish.
* Accepts password, passphrase, or PEM/DER key files.
* Appends custom extensions and restores original names.
* Recursive folder support and optional deletion.
* Text or JSON audit logs.
* Detects permission errors, bad keys, and corrupt data.
* Standalone `.exe` packaged with PyInstaller.
* Compatible with Windows 10/11 (32 & 64-bit).

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
  --algo AES256 --key "pass123" --ext ".vault" --log "C:\logs\ct.log"
```

### GUI

* Run `cryptek-gui.exe`.
* Select mode, path, algorithm, key, extension, and logging options.
* Click **Start** to execute.

---

## Examples

```powershell
cryptek.exe --mode encrypt --path "C:\media" --algo ChaCha20 \
  --key "arch1ve!" --ext ".encx" --recursive --delete-original \
  --log "C:\logs\ct.log"
```

```powershell
cryptek-gui.exe  # Launch GUI
```

---

## Flags & Options

| Flag                | Description                                          |
| ------------------- | ---------------------------------------------------- |
| `--mode`            | `encrypt` or `decrypt` **(required)**                |
| `--path`            | Target file, folder, or drive path **(required)**    |
| `--algo`            | AES128, AES256, RSA, ChaCha20, Blowfish              |
| `--key`             | Password or key file path **(required)**             |
| `--ext`             | Custom extension for encrypted output **(required)** |
| `--recursive`       | Process folders recursively                          |
| `--delete-original` | Delete source files post-encryption                  |
| `--log`             | Path to audit log file **(required)**                |
| `--log-format`      | `text` (default) or `json`                           |

---

## Error Handling

Validates all inputs and flags, checks file/directory access, detects incorrect keys or corrupted files, and exits with non-zero codes on failure.

---

## Logging

Operations log timestamp, mode, algorithm, input/output paths, and status. Outputs support plaintext or structured JSON.

---

## Contribution

1. Fork the repository.
2. Create a feature branch.
3. Implement and test changes.
4. Submit a pull request.
5. Explore features with `cryptek.exe --help`.

---

## License

MIT License. See `LICENSE` for details.
