# SpindleX Deployment Guide

This guide explains how to securely deploy SpindleX releases to PyPI using GitLab CI/CD.

## 🔐 Security Setup

### 1. Generate PyPI API Tokens

You need to create API tokens for both Test PyPI and Production PyPI:

#### Production PyPI Token
1. Go to [PyPI Account Settings](https://pypi.org/manage/account/)
2. Scroll to "API tokens" section
3. Click "Add API token"
4. Name: `SpindleX GitLab CI`
5. Scope: `Entire account` or `Project: spindlex`
6. Copy the token (starts with `pypi-`)

#### Test PyPI Token
1. Go to [Test PyPI Account Settings](https://test.pypi.org/manage/account/)
2. Follow the same steps as above
3. Copy the token (starts with `pypi-`)

### 2. Configure GitLab CI Variables

Add the API tokens as protected CI/CD variables in GitLab:

1. Go to your GitLab project: `Settings > CI/CD > Variables`
2. Add the following variables:

| Variable Name | Value | Protected | Masked |
|---------------|-------|-----------|--------|
| `PYPI_TOKEN` | `pypi-your-production-token` | ✅ | ✅ |
| `PYPI_TEST_TOKEN` | `pypi-your-test-token` | ✅ | ✅ |

**Important Security Notes:**
- ✅ **Protected**: Only available on protected branches/tags
- ✅ **Masked**: Hidden in job logs
- ❌ **Never commit tokens to code**
- ❌ **Never share tokens in chat/email**

## 🚀 Release Process

### Automated Release (Recommended)

Use the release automation script:

```bash
# Create a new minor release
python scripts/release.py --version 0.3.0 --type minor

# Create a patch release
python scripts/release.py --version 0.2.1 --type patch

# Dry run to see what would happen
python scripts/release.py --version 0.3.0 --dry-run
```

The script will:
1. ✅ Validate version format
2. ✅ Check git status is clean
3. ✅ Run tests
4. ✅ Update version files
5. ✅ Update changelog
6. ✅ Create git commit and tag
7. ✅ Push to GitLab

### Manual Release

If you prefer manual control:

1. **Update Version Files**
   ```bash
   # Update spindlex/_version.py
   __version__ = "0.3.0"
   __version_info__ = (0, 3, 0)
   
   # Update pyproject.toml
   version = "0.3.0"
   ```

2. **Update Changelog**
   ```bash
   # Replace [Unreleased] with [0.3.0] - 2024-01-15
   # Add new [Unreleased] section
   ```

3. **Create Git Tag**
   ```bash
   git add .
   git commit -m "Release version 0.3.0"
   git tag -a v0.3.0 -m "Release version 0.3.0"
   git push origin main
   git push origin v0.3.0
   ```

## 📦 PyPI Deployment

Once you push a tag, GitLab CI will automatically:

1. **Build Package**: Create wheel and source distributions
2. **Run Tests**: Ensure everything works
3. **Wait for Manual Trigger**: Deployment jobs are manual for safety

### Deployment Steps

1. **Go to GitLab Pipelines**
   - Visit: https://gitlab.com/daveops.world/development/python/spindle/-/pipelines
   - Find the pipeline for your tag (e.g., `v0.3.0`)

2. **Deploy to Test PyPI First**
   - Click the manual `deploy:pypi:test` job
   - This uploads to https://test.pypi.org/project/spindlex/
   - Test the installation: `pip install -i https://test.pypi.org/simple/ spindlex`

3. **Deploy to Production PyPI**
   - After testing, click the manual `deploy:pypi:production` job
   - This uploads to https://pypi.org/project/spindlex/
   - Verify: `pip install spindlex`

## 🔍 Verification

After deployment, verify the release:

```bash
# Install from PyPI
pip install spindlex==$VERSION

# Test basic functionality
python -c "import spindlex; print(spindlex.__version__)"

# Run a quick test
python -c "
from spindlex import SSHClient
print('SpindleX imported successfully!')
"
```

## 🛡️ Security Best Practices

### Token Management
- 🔄 **Rotate tokens** every 6-12 months
- 🔒 **Use project-scoped tokens** when possible
- 📝 **Document token purposes** in GitLab
- 🚫 **Revoke unused tokens** immediately

### Access Control
- 👥 **Limit who can create tags** (maintainers only)
- 🔐 **Protect main branch** from direct pushes
- 📋 **Require code reviews** for releases
- 🔍 **Monitor deployment logs** for anomalies

### Backup Plan
- 📦 **Keep local copies** of release artifacts
- 🔑 **Have backup tokens** ready
- 👨‍💻 **Multiple maintainers** with access
- 📚 **Document recovery procedures**

## 🚨 Troubleshooting

### Common Issues

#### "Invalid token" Error
```bash
# Check token format (should start with pypi-)
# Verify token is not expired
# Ensure token has correct permissions
```

#### "Package already exists" Error
```bash
# Version already published to PyPI
# Increment version number
# Cannot overwrite existing versions
```

#### "Authentication failed" Error
```bash
# Check GitLab CI variables are set correctly
# Verify tokens are masked and protected
# Ensure running on protected branch/tag
```

### Getting Help

- 📖 **Documentation**: https://spindlex.readthedocs.io/
- 🐛 **Issues**: https://gitlab.com/daveops.world/development/python/spindle/-/issues
- 💬 **Discussions**: https://gitlab.com/daveops.world/development/python/spindle/-/issues

## 📋 Checklist

Before each release:

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version numbers incremented
- [ ] Git working directory clean
- [ ] On main branch
- [ ] PyPI tokens valid
- [ ] GitLab CI variables configured

After each release:

- [ ] Test PyPI deployment successful
- [ ] Production PyPI deployment successful
- [ ] Package installable via pip
- [ ] Basic functionality verified
- [ ] Release notes published
- [ ] Community notified

---

**Remember**: Security is paramount. Never expose API tokens, and always test on Test PyPI first!