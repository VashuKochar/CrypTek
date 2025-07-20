# Changelog

All notable changes to CrypTek will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-20

### Added
- Complete project restructure with proper Python package layout
- Comprehensive type hints throughout the codebase
- Enhanced error handling with custom exception hierarchy
- Configuration management system
- Professional logging system with rotation
- Comprehensive input validation
- Permission checking system
- Modular architecture with separation of concerns
- PyInstaller build system for executables
- Proper Python packaging with pyproject.toml
- Test suite with pytest
- Code quality tools (black, isort, mypy, flake8)

### Changed
- Restructured project into src/cryptek package layout
- Refactored crypto operations into focused modules
- Improved CLI with better argument validation
- Enhanced file operations with proper error handling
- Upgraded logging to support both text and JSON formats

### Removed
- ChaCha20 algorithm (due to implementation issues)
- Monolithic file structure
- Unsafe error handling practices

### Security
- Improved key derivation with PBKDF2
- Enhanced secure file deletion
- Better input validation and sanitization
- Proper permission checking before operations

## [0.1.0] - 2024-01-19

### Added
- Initial implementation with basic encryption algorithms
- CLI and GUI interfaces
- File and folder processing
- Basic logging system