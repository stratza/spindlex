# 📚 GitLab Wiki Setup Guide

This guide will help you set up the SpindleX GitLab wiki with all the prepared content.

## 🎯 Quick Setup (Automated)

### For Linux/macOS:
```bash
chmod +x setup-wiki.sh
./setup-wiki.sh
```

### For Windows:
```cmd
setup-wiki.bat
```

## 🔧 Manual Setup

### Step 1: Enable Wiki in GitLab
1. Go to your project: `https://gitlab.com/daveops.world/development/python/spindlex`
2. Navigate to **Settings** → **General** → **Visibility, project features, permissions**
3. Ensure **Wiki** is enabled
4. Click **Save changes**

### Step 2: Access Wiki Section
1. Go to your project's **Wiki** section (left sidebar)
2. You should see an option to create your first page

### Step 3: Clone Wiki Repository
```bash
# Clone the wiki repository (separate from main repo)
git clone https://gitlab.com/daveops.world/development/python/spindlex.wiki.git
cd spindlex.wiki
```

### Step 4: Copy Wiki Content
```bash
# Copy all prepared wiki files
cp ../wiki/home.md ./home.md
cp ../wiki/installation.md ./installation.md
cp ../wiki/quick-start.md ./quick-start.md
cp ../wiki/ssh-client-guide.md ./ssh-client-guide.md
cp ../wiki/examples.md ./examples.md
cp ../wiki/faq.md ./faq.md
cp ../wiki/api-reference.md ./api-reference.md
```

### Step 5: Create Navigation Sidebar
Create `_Sidebar.md`:
```markdown
## 📚 SpindleX Wiki

### 🚀 Getting Started
- [🏠 Home](home)
- [📦 Installation](installation)
- [🚀 Quick Start](quick-start)

### 📖 Guides
- [🔌 SSH Client Guide](ssh-client-guide)
- [💡 Examples](examples)
- [📖 API Reference](api-reference)
- [❓ FAQ](faq)

---
**[📖 Full Documentation](https://spindlex.readthedocs.io/)**
```

### Step 6: Commit and Push
```bash
git add .
git commit -m "📚 Initial SpindleX wiki setup"
git push origin master
```

## 🌐 Access Your Wiki

After setup, visit: `https://gitlab.com/daveops.world/development/python/spindlex/-/wikis/home`

## 📋 Wiki Pages Created

- **home.md** - Main wiki homepage with navigation
- **installation.md** - Complete installation guide
- **quick-start.md** - 5-minute tutorial
- **ssh-client-guide.md** - Comprehensive SSH documentation
- **examples.md** - Code examples and recipes
- **faq.md** - Frequently asked questions
- **api-reference.md** - API documentation
- **_Sidebar.md** - Navigation sidebar

## 🔧 Troubleshooting

### Wiki Not Visible?
- Ensure Wiki is enabled in project settings
- Check project permissions
- Try refreshing the page

### Clone Failed?
- Make sure you have access to the project
- Check if wiki has been initialized (create first page manually)
- Verify the repository URL

### Push Failed?
- Ensure you have push permissions
- Check if you're authenticated with GitLab
- Try: `git remote -v` to verify remote URL

## 🆘 Need Help?

- [GitLab Wiki Documentation](https://docs.gitlab.com/ee/user/project/wiki/)
- [SpindleX Issues](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)

---

**Once set up, your wiki will be available at:**
`https://gitlab.com/daveops.world/development/python/spindlex/-/wikis/home`