# 📦 Installation Guide

This guide will help you install SpindleX and get it running in your environment.

## 🚀 Quick Installation

### Standard Installation

```bash
pip install spindlex
```

### With Optional Features

```bash
# Async support
pip install spindlex[async]

# Development tools
pip install spindlex[dev]

# GSSAPI authentication (Unix only)
pip install spindlex[gssapi]

# Everything
pip install spindlex[async,dev,gssapi]
```

## 📋 System Requirements

### Python Version
- **Python 3.8+** (recommended: Python 3.9+)
- **PyPy 3.8+** (for performance-critical applications)

### Operating Systems
- ✅ **Linux** (all distributions)
- ✅ **macOS** (10.14+)
- ✅ **Windows** (10+)
- ✅ **FreeBSD, OpenBSD**
- ✅ **Docker containers**

### Dependencies

SpindleX has minimal dependencies:

```
cryptography >= 3.0    # Core cryptographic operations
```

Optional dependencies:
```
asyncio-dgram >= 2.0    # For async support
gssapi >= 1.6.0         # For GSSAPI authentication (Unix only)
```

## 🔧 Installation Methods

### 1. Using pip (Recommended)

```bash
# Latest stable version
pip install spindlex

# Specific version
pip install spindlex==0.1.0

# Pre-release versions
pip install --pre spindlex
```

### 2. Using conda

```bash
# Coming soon - conda-forge package in development
conda install -c conda-forge spindlex
```

### 3. From Source

```bash
# Clone the repository
git clone https://gitlab.com/daveops.world/development/python/spindlex.git
cd spindlex

# Install in development mode
pip install -e .

# Or build and install
python -m build
pip install dist/spindlex-*.whl
```

### 4. Using Poetry

```bash
# Add to your project
poetry add spindlex

# With optional features
poetry add spindlex[async,dev]
```

### 5. Using pipenv

```bash
# Add to Pipfile
pipenv install spindlex

# With optional features
pipenv install spindlex[async]
```

## 🐳 Docker Installation

### Using Official Python Images

```dockerfile
FROM python:3.11-slim

# Install SpindleX
RUN pip install spindlex[async]

# Your application code
COPY . /app
WORKDIR /app

CMD ["python", "your_app.py"]
```

### Alpine Linux

```dockerfile
FROM python:3.11-alpine

# Install build dependencies for cryptography
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

# Install SpindleX
RUN pip install spindlex

# Clean up build dependencies
RUN apk del gcc musl-dev libffi-dev

# Your application
COPY . /app
WORKDIR /app
CMD ["python", "your_app.py"]
```

## ✅ Verification

After installation, verify SpindleX is working:

```python
import spindlex

# Check version
print(f"SpindleX version: {spindlex.__version__}")

# Test basic import
from spindlex import SSHClient, SFTPClient
print("✅ SpindleX installed successfully!")

# Test cryptography
from spindlex.crypto.pkey import Ed25519Key
print("✅ Cryptography support available!")
```

## 🔍 Troubleshooting Installation

### Common Issues

#### 1. Cryptography Installation Fails

**Problem**: `Failed building wheel for cryptography`

**Solution**:
```bash
# Update pip and setuptools
pip install --upgrade pip setuptools wheel

# Install build dependencies (Linux)
sudo apt-get install build-essential libffi-dev python3-dev

# Install build dependencies (macOS)
xcode-select --install

# Try installing again
pip install spindlex
```

#### 2. GSSAPI Installation Fails (Unix)

**Problem**: `Failed to install gssapi`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install libkrb5-dev

# CentOS/RHEL
sudo yum install krb5-devel

# macOS
brew install krb5

# Then install SpindleX
pip install spindlex[gssapi]
```

#### 3. Permission Denied

**Problem**: `Permission denied` during installation

**Solution**:
```bash
# Use user installation
pip install --user spindlex

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install spindlex
```

#### 4. Old Python Version

**Problem**: `Requires Python 3.8+`

**Solution**:
```bash
# Check Python version
python --version

# Install newer Python (Ubuntu)
sudo apt-get install python3.9 python3.9-pip

# Use pyenv for version management
curl https://pyenv.run | bash
pyenv install 3.11.0
pyenv global 3.11.0
```

## 🚀 Virtual Environment Setup

### Using venv (Recommended)

```bash
# Create virtual environment
python -m venv spindlex-env

# Activate (Linux/macOS)
source spindlex-env/bin/activate

# Activate (Windows)
spindlex-env\Scripts\activate

# Install SpindleX
pip install spindlex[async,dev]

# Deactivate when done
deactivate
```

### Using conda

```bash
# Create environment
conda create -n spindlex python=3.11

# Activate
conda activate spindlex

# Install SpindleX
pip install spindlex

# Deactivate
conda deactivate
```

## 🔄 Upgrading SpindleX

```bash
# Upgrade to latest version
pip install --upgrade spindlex

# Upgrade with optional features
pip install --upgrade spindlex[async,dev]

# Check current version
python -c "import spindlex; print(spindlex.__version__)"
```

## 🧪 Development Installation

For contributing to SpindleX:

```bash
# Clone repository
git clone https://gitlab.com/daveops.world/development/python/spindlex.git
cd spindlex

# Create development environment
python -m venv dev-env
source dev-env/bin/activate

# Install in development mode with all features
pip install -e .[dev,async,gssapi]

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/
```

## 📊 Performance Considerations

### For High-Performance Applications

```bash
# Use PyPy for better performance
pypy3 -m pip install spindlex[async]

# Or use Python 3.11+ with optimizations
pip install spindlex[async]
```

### Memory-Constrained Environments

```bash
# Minimal installation
pip install spindlex --no-deps
pip install cryptography
```

## 🆘 Getting Help

If you encounter issues during installation:

1. 📖 Check this troubleshooting guide
2. 🔍 Search [existing issues](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)
3. 🐛 [Create a new issue](https://gitlab.com/daveops.world/development/python/spindlex/-/issues/new) with:
   - Your operating system and version
   - Python version (`python --version`)
   - Full error message
   - Installation command used

---

**Next Steps**: [Quick Start Tutorial](quick-start) →