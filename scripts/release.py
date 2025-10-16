#!/usr/bin/env python3
"""
Release automation script for ssh-library.

This script helps automate the release process including:
- Version bumping
- Changelog generation
- Building distributions
- Publishing to PyPI
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Tuple


def get_current_version() -> str:
    """Get the current version from _version.py."""
    version_file = Path("ssh_library/_version.py")
    content = version_file.read_text()
    match = re.search(r'__version__ = "([^"]+)"', content)
    if not match:
        raise ValueError("Could not find version in _version.py")
    return match.group(1)


def parse_version(version: str) -> Tuple[int, int, int]:
    """Parse a version string into components."""
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version}")
    return tuple(int(p) for p in parts)


def bump_version(current: str, bump_type: str) -> str:
    """Bump version based on type (major, minor, patch)."""
    major, minor, patch = parse_version(current)
    
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")


def update_version_file(new_version: str) -> None:
    """Update the version in _version.py."""
    version_file = Path("ssh_library/_version.py")
    content = version_file.read_text()
    
    # Update version string
    content = re.sub(
        r'__version__ = "[^"]+"',
        f'__version__ = "{new_version}"',
        content
    )
    
    # Update version info tuple
    major, minor, patch = parse_version(new_version)
    content = re.sub(
        r'__version_info__ = \([^)]+\)',
        f'__version_info__ = ({major}, {minor}, {patch})',
        content
    )
    
    version_file.write_text(content)
    print(f"Updated version to {new_version}")


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def build_distributions() -> None:
    """Build wheel and source distributions."""
    print("Building distributions...")
    
    # Clean previous builds
    run_command(["python", "-m", "pip", "install", "--upgrade", "build", "twine"])
    run_command(["rm", "-rf", "dist/", "build/", "*.egg-info/"], check=False)
    
    # Build distributions
    run_command(["python", "-m", "build"])
    
    # Check distributions
    run_command(["python", "-m", "twine", "check", "dist/*"])
    print("Distributions built successfully")


def run_tests() -> None:
    """Run the test suite."""
    print("Running tests...")
    result = run_command(["python", "-m", "pytest", "tests/", "-v"], check=False)
    if result.returncode != 0:
        print("Tests failed!")
        sys.exit(1)
    print("All tests passed")


def check_git_status() -> None:
    """Check if git working directory is clean."""
    result = run_command(["git", "status", "--porcelain"], check=False)
    if result.stdout.strip():
        print("Git working directory is not clean. Please commit changes first.")
        sys.exit(1)


def create_git_tag(version: str) -> None:
    """Create and push a git tag for the release."""
    tag = f"v{version}"
    run_command(["git", "add", "ssh_library/_version.py"])
    run_command(["git", "commit", "-m", f"Bump version to {version}"])
    run_command(["git", "tag", "-a", tag, "-m", f"Release {version}"])
    print(f"Created git tag {tag}")


def main():
    """Main release function."""
    parser = argparse.ArgumentParser(description="Release automation for ssh-library")
    parser.add_argument(
        "bump_type",
        choices=["major", "minor", "patch"],
        help="Type of version bump"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running tests"
    )
    parser.add_argument(
        "--skip-git",
        action="store_true",
        help="Skip git operations"
    )
    
    args = parser.parse_args()
    
    # Get current version
    current_version = get_current_version()
    new_version = bump_version(current_version, args.bump_type)
    
    print(f"Current version: {current_version}")
    print(f"New version: {new_version}")
    
    if args.dry_run:
        print("Dry run - no changes will be made")
        return
    
    # Check git status
    if not args.skip_git:
        check_git_status()
    
    # Run tests
    if not args.skip_tests:
        run_tests()
    
    # Update version
    update_version_file(new_version)
    
    # Build distributions
    build_distributions()
    
    # Git operations
    if not args.skip_git:
        create_git_tag(new_version)
    
    print(f"Release {new_version} prepared successfully!")
    print("To publish to PyPI, run:")
    print("  python -m twine upload dist/*")


if __name__ == "__main__":
    main()