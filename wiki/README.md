# 📚 SpindleX Wiki

This directory contains the source files for the SpindleX GitLab wiki.

## 🚀 Wiki Structure

- `home.md` - Main wiki homepage
- `installation.md` - Installation guide
- `quick-start.md` - Quick start tutorial
- `ssh-client-guide.md` - Complete SSH client documentation
- `examples.md` - Code examples and recipes
- `faq.md` - Frequently asked questions
- `api-reference.md` - API documentation

## 📝 How to Update the Wiki

### Method 1: Direct GitLab Wiki Editing
1. Go to your GitLab project
2. Navigate to Wiki section
3. Edit pages directly in the web interface

### Method 2: Git Repository (Recommended)
1. Clone the wiki repository:
   ```bash
   git clone https://gitlab.com/daveops.world/development/python/spindlex.wiki.git
   ```

2. Edit the markdown files

3. Commit and push:
   ```bash
   git add .
   git commit -m "Update wiki content"
   git push origin master
   ```

### Method 3: Automated Deployment
The wiki can be automatically deployed using GitLab CI when changes are made to this directory.

## 📋 Wiki Pages to Create

After setting up the wiki repository, copy these files:

```bash
# Copy all wiki files to your wiki repository
cp wiki/*.md /path/to/spindlex.wiki/
```

## 🔗 Wiki Navigation

The wiki uses GitLab's automatic sidebar generation based on file names. Pages are automatically linked and searchable.

## 📖 Writing Guidelines

- Use clear, descriptive headings
- Include code examples for all features
- Add emoji icons for visual appeal
- Cross-reference related pages
- Keep examples practical and tested

## 🆘 Need Help?

- [GitLab Wiki Documentation](https://docs.gitlab.com/ee/user/project/wiki/)
- [Markdown Guide](https://www.markdownguide.org/)
- [SpindleX Issues](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)