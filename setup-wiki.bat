@echo off
REM SpindleX Wiki Setup Script for Windows
REM This script copies wiki content to your GitLab wiki repository

echo 🚀 Setting up SpindleX GitLab Wiki...

REM Check if wiki repository exists
if not exist "spindlex.wiki" (
    echo 📥 Cloning wiki repository...
    git clone https://gitlab.com/daveops.world/development/python/spindlex.wiki.git
)

cd spindlex.wiki

echo 📝 Copying wiki content...

REM Copy all wiki files
copy ..\wiki\home.md .\home.md
copy ..\wiki\installation.md .\installation.md
copy ..\wiki\quick-start.md .\quick-start.md
copy ..\wiki\ssh-client-guide.md .\ssh-client-guide.md
copy ..\wiki\examples.md .\examples.md
copy ..\wiki\faq.md .\faq.md
copy ..\wiki\api-reference.md .\api-reference.md

REM Create sidebar for navigation
echo ## 📚 SpindleX Wiki > _Sidebar.md
echo. >> _Sidebar.md
echo ### 🚀 Getting Started >> _Sidebar.md
echo - [🏠 Home](home) >> _Sidebar.md
echo - [📦 Installation](installation) >> _Sidebar.md
echo - [🚀 Quick Start](quick-start) >> _Sidebar.md
echo. >> _Sidebar.md
echo ### 📖 Guides >> _Sidebar.md
echo - [🔌 SSH Client Guide](ssh-client-guide) >> _Sidebar.md
echo - [💡 Examples](examples) >> _Sidebar.md
echo - [📖 API Reference](api-reference) >> _Sidebar.md
echo - [❓ FAQ](faq) >> _Sidebar.md

echo 📋 Adding files to git...
git add .

echo 💾 Committing changes...
git commit -m "📚 Initial SpindleX wiki setup - Added comprehensive documentation"

echo 🚀 Pushing to GitLab...
git push origin master

echo ✅ Wiki setup complete!
echo 🌐 Visit your wiki at: https://gitlab.com/daveops.world/development/python/spindlex/-/wikis/home

pause