# 🤝 Contributing to CrypTek

Thank you for your interest in contributing to CrypTek! This guide will help you get started.

## 🚀 GitHub Setup & Deployment

### Setting Up the Repository

1. **Fork or create repository** on GitHub
2. **Clone locally**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/CrypTek.git
   cd CrypTek
   ```

3. **Set up development environment**:
   ```bash
   make install-dev  # or pip install -e ".[dev]"
   ```

### Creating Releases

To create a new release with automated executable builds:

```bash
# Make your changes and commit
git add .
git commit -m "Add new feature"
git push origin main

# Create and push a version tag
git tag -a v1.0.0 -m "CrypTek v1.0.0 - Initial Release"
git push origin v1.0.0
```

**What happens automatically:**
- ✅ Builds Windows executables (CLI and GUI)
- ✅ Creates GitHub release with download links
- ✅ Tests executables before release
- ✅ Generates release notes

## 🛠️ Development Workflow

### Local Development

```bash
# Install dependencies
make install

# Run tests
make test

# Test CLI
make run

# Test GUI
make run-gui

# Build executables locally
make build

# Clean build artifacts
make clean
```

### Code Style

We follow Python best practices:

- **Type hints** throughout the codebase
- **Docstrings** for all public functions
- **Black** for code formatting
- **isort** for import sorting
- **mypy** for type checking

```bash
# Format code
make format

# Run linting
make lint
```

### Testing

- Write tests for new features in `tests/`
- Ensure all tests pass: `make test`
- Test both CLI and GUI functionality
- Test on different operating systems if possible

## 📋 Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/new-algorithm
   ```

2. **Make your changes** with proper tests and documentation

3. **Test locally**:
   ```bash
   make test
   make run  # Test CLI
   make run-gui  # Test GUI
   ```

4. **Submit pull request** with:
   - Clear description of changes
   - Test results
   - Screenshots (if UI changes)

## 🔐 Security Guidelines

Since CrypTek is a security tool:

- **Never commit** passwords, keys, or sensitive data
- **Review crypto code** carefully for implementation errors
- **Test security features** thoroughly
- **Follow OWASP** security guidelines
- **Use secure coding practices**

## 📝 Documentation

- Update **README.md** for user-facing changes
- Update **CHANGELOG.md** for all releases
- Add **docstrings** for new functions
- Include **usage examples** for new features

## 🐛 Bug Reports

Use the GitHub issue template with:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, version, etc.)
- **No sensitive data** in reports

## 💡 Feature Requests

Include:
- Problem statement
- Proposed solution
- Use cases
- Security considerations

## 🏗️ Architecture Guidelines

### Code Organization
```
src/cryptek/
├── core/          # Core encryption functionality
├── cli/           # Command line interface
├── gui/           # Graphical user interface
└── utils/         # Utility functions
```

### Adding New Algorithms

1. Add algorithm to `core/constants.py`
2. Implement in `core/crypto_engine.py`
3. Add validation in `utils/validation.py`
4. Update CLI parser in `cli/parser.py`
5. Update GUI options in `gui/main.py`
6. Add tests in `tests/`

### Error Handling

- Use custom exceptions from `core/exceptions.py`
- Provide helpful error messages
- Log errors appropriately
- Never expose sensitive information in errors

## 🎯 Release Process

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md** with changes
3. **Test thoroughly** on multiple platforms
4. **Create release tag**: `git tag -a v1.x.x -m "Release v1.x.x"`
5. **Push tag**: `git push origin v1.x.x`
6. **GitHub Actions** builds and releases automatically

## 📞 Getting Help

- **GitHub Issues** - for bugs and feature requests
- **GitHub Discussions** - for questions and general discussion
- **Security Issues** - report privately via GitHub security tab

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to CrypTek! 🛡️