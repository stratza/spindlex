#!/usr/bin/env python3
"""
SpindleX Release Automation Script

This script automates the release process for SpindleX:
1. Updates version numbers
2. Updates changelog
3. Creates git tag
4. Pushes to GitHub (triggers CI/CD pipeline)

Usage:
    python scripts/release.py --version 0.4.0 --type minor
    python scripts/release.py --version 0.2.1 --type patch
"""

import argparse
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {cmd}")
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)  # noqa: S603
    if check and result.returncode != 0:
        print(f"Error running command: {cmd}")
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)
    return result


def update_version_file(version):
    """Update the version in spindlex/_version.py"""
    version_file = Path("spindlex/_version.py")
    if not version_file.exists():
        print(f"Version file not found: {version_file}")
        sys.exit(1)
    
    content = version_file.read_text()
    
    # Update version string
    content = re.sub(
        r'__version__ = ["\'][^"\']*["\']',
        f'__version__ = "{version}"',
        content
    )
    
    # Update version tuple
    version_parts = version.split('.')
    if len(version_parts) >= 3:
        version_tuple = f"({version_parts[0]}, {version_parts[1]}, {version_parts[2]})"
        content = re.sub(
            r'__version_info__ = \([^)]*\)',
            f'__version_info__ = {version_tuple}',
            content
        )
    
    version_file.write_text(content)
    print(f"Updated version in {version_file}")


def update_pyproject_toml(version):
    """Update version in pyproject.toml"""
    pyproject_file = Path("pyproject.toml")
    if not pyproject_file.exists():
        print(f"pyproject.toml not found: {pyproject_file}")
        sys.exit(1)
    
    content = pyproject_file.read_text()
    content = re.sub(
        r'version = "[^"]*"',
        f'version = "{version}"',
        content
    )
    
    pyproject_file.write_text(content)
    print(f"Updated version in {pyproject_file}")


def update_changelog(version, release_type):
    """Update CHANGELOG.md with new version"""
    changelog_file = Path("CHANGELOG.md")
    if not changelog_file.exists():
        print(f"CHANGELOG.md not found: {changelog_file}")
        sys.exit(1)
    
    content = changelog_file.read_text()
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Replace [Unreleased] with the new version
    new_header = f"## [{version}] - {today}"
    content = content.replace("## [Unreleased]", new_header)
    
    # Add new [Unreleased] section
    unreleased_section = f"""## [Unreleased]

### Added

### Changed

### Fixed

### Security

{new_header}"""
    
    content = content.replace(new_header, unreleased_section)
    
    changelog_file.write_text(content)
    print(f"Updated changelog for version {version}")


def validate_version(version):
    """Validate version format (semantic versioning)"""
    pattern = r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)?$'
    if not re.match(pattern, version):
        print(f"Invalid version format: {version}")
        print("Version should follow semantic versioning (e.g., 1.2.3 or 1.2.3-alpha.1)")
        sys.exit(1)


def check_git_status():
    """Check if git working directory is clean"""
    result = run_command("git status --porcelain", check=False)
    if result.stdout.strip():
        print("Git working directory is not clean. Please commit or stash changes first.")
        print("Uncommitted changes:")
        print(result.stdout)
        sys.exit(1)


def check_current_branch():
    """Check if we're on the main branch"""
    result = run_command("git branch --show-current", check=False)
    current_branch = result.stdout.strip()
    if current_branch != "main":
        print(f"Not on main branch (currently on: {current_branch})")
        print("Please switch to main branch before creating a release")
        sys.exit(1)


def create_git_tag(version):
    """Create and push git tag"""
    tag_name = f"v{version}"
    
    # Check if tag already exists
    result = run_command(f"git tag -l {tag_name}", check=False)
    if result.stdout.strip():
        print(f"Tag {tag_name} already exists")
        sys.exit(1)
    
    # Create tag
    run_command(f'git tag -a {tag_name} -m "Release version {version}"')
    print(f"Created git tag: {tag_name}")
    
    return tag_name


def main():
    parser = argparse.ArgumentParser(description="Automate SpindleX release process")
    parser.add_argument("--version", required=True, help="Version to release (e.g., 0.4.0)")
    parser.add_argument(
        "--type", 
        choices=["major", "minor", "patch", "prerelease"], 
        default="minor",
        help="Type of release"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--skip-git", action="store_true", help="Skip git operations")
    
    args = parser.parse_args()
    
    print(f"🚀 Starting SpindleX release process for version {args.version}")
    print(f"Release type: {args.type}")
    
    if args.dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
    
    # Validate inputs
    validate_version(args.version)
    
    if not args.skip_git:
        check_git_status()
        check_current_branch()
    
    # Run tests unless skipped
    if not args.skip_tests:
        print("🧪 Running tests...")
        if not args.dry_run:
            run_command("python -m pytest tests/unit/ --ignore=tests/unit/test_benchmarks.py --ignore=tests/unit/test_interoperability.py -v")
        print("✅ Tests passed")
    
    # Update version files
    if not args.dry_run:
        print("📝 Updating version files...")
        update_version_file(args.version)
        update_pyproject_toml(args.version)
        update_changelog(args.version, args.type)
        print("✅ Version files updated")
    else:
        print("📝 Would update version files")
    
    # Git operations
    if not args.skip_git and not args.dry_run:
        print("📦 Committing changes...")
        run_command("git add .")
        run_command(f'git commit -m "Release version {args.version}"')
        
        print("🏷️ Creating git tag...")
        tag_name = create_git_tag(args.version)
        
        print("🚀 Pushing to GitHub...")
        run_command("git push origin main")
        run_command(f"git push origin {tag_name}")
        
        print("✅ Git operations completed")
    elif not args.skip_git:
        print("📦 Would commit changes and create tag")
    
    print(f"""
🎉 Release process completed for SpindleX {args.version}!

Next steps:
1. Go to GitHub Actions: https://github.com/Di3Z1E/spindlex/actions
2. Find the pipeline for tag v{args.version}
3. Manually trigger the PyPI deployment jobs:
   - First: deploy:pypi:test (uploads to Test PyPI)
   - Then: deploy:pypi:production (uploads to Production PyPI)

📋 Don't forget to:
- Update the GitHub release notes
- Announce the release
- Update documentation if needed
""")


if __name__ == "__main__":
    main()
