@echo off
echo 🚀 Creating individual wiki pages through GitLab web interface...
echo.
echo Since the wiki repository doesn't exist yet, we'll create pages manually.
echo.
echo 📋 Follow these steps:
echo.
echo 1️⃣ Go to: https://gitlab.com/daveops.world/development/python/spindlex
echo 2️⃣ Click "Wiki" in the left sidebar
echo 3️⃣ Click "Create your first page" or "New page"
echo.
echo 📄 Create these pages one by one:
echo.

set /p dummy="Press Enter to open the first page content..."

echo ========================================
echo PAGE 1: home
echo ========================================
type wiki\home.md
echo.
echo ========================================
echo Copy the above content and create a page titled "home"
echo ========================================
echo.

set /p dummy="Press Enter for next page..."

echo ========================================
echo PAGE 2: installation  
echo ========================================
type wiki\installation.md | more
echo.
echo ========================================
echo Copy the above content and create a page titled "installation"
echo ========================================
echo.

set /p dummy="Press Enter for next page..."

echo ========================================
echo PAGE 3: quick-start
echo ========================================
type wiki\quick-start.md | more
echo.
echo ========================================
echo Copy the above content and create a page titled "quick-start"
echo ========================================
echo.

echo 📝 Continue creating pages for:
echo - ssh-client-guide
echo - examples  
echo - faq
echo - api-reference
echo.
echo 💡 Tip: You can copy content from the wiki\ folder files
echo.
echo ✅ Once all pages are created, your wiki will be live at:
echo https://gitlab.com/daveops.world/development/python/spindlex/-/wikis/home

pause