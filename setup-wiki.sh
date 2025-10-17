#!/bin/bash

# SpindleX Wiki Setup Script
# This script copies wiki content to your GitLab wiki repository

echo "🚀 Setting up SpindleX GitLab Wiki..."

# Check if wiki repository exists
if [ ! -d "spindlex.wiki" ]; then
    echo "📥 Cloning wiki repository..."
    git clone https://gitlab.com/daveops.world/development/python/spindlex.wiki.git
fi

cd spindlex.wiki

echo "📝 Copying wiki content..."

# Copy all wiki files
cp ../wiki/home.md ./home.md
cp ../wiki/installation.md ./installation.md
cp ../wiki/quick-start.md ./quick-start.md
cp ../wiki/ssh-client-guide.md ./ssh-client-guide.md
cp ../wiki/examples.md ./examples.md
cp ../wiki/faq.md ./faq.md
cp ../wiki/api-reference.md ./api-reference.md

# Create sidebar for navigation
cat > _Sidebar.md << 'EOF'
## 📚 SpindleX Wiki

### 🚀 Getting Started
- [🏠 Home](home)
- [📦 Installation](installation)
- [🚀 Quick Start](quick-start)

### 📖 Guides
- [🔌 SSH Client Guide](ssh-client-guide)
- [📁 SFTP Operations](sftp-operations)
- [⚡ Async Programming](async-programming)
- [🌐 Port Forwarding](port-forwarding)

### 📋 Reference
- [💡 Examples](examples)
- [📖 API Reference](api-reference)
- [❓ FAQ](faq)
- [🔧 Troubleshooting](troubleshooting)

### 🛠️ Development
- [🤝 Contributing](contributing)
- [🏗️ Architecture](architecture)
- [🧪 Testing](testing)

---
**[📖 Full Documentation](https://spindlex.readthedocs.io/)**
EOF

echo "📋 Adding files to git..."
git add .

echo "💾 Committing changes..."
git commit -m "📚 Initial SpindleX wiki setup

✨ Added comprehensive documentation:
- Home page with navigation
- Installation guide with troubleshooting
- Quick start tutorial
- Complete SSH client guide
- Code examples and recipes
- FAQ and API reference
- Navigation sidebar

🎯 Features:
- Modern markdown formatting
- Comprehensive examples
- Cross-referenced navigation
- Best practices and security tips"

echo "🚀 Pushing to GitLab..."
git push origin master

echo "✅ Wiki setup complete!"
echo "🌐 Visit your wiki at: https://gitlab.com/daveops.world/development/python/spindlex/-/wikis/home"