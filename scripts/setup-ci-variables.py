#!/usr/bin/env python3
"""
GitLab CI Variables Setup Helper

This script helps you set up the required CI/CD variables for PyPI deployment.
It provides instructions and validates token formats.
"""

import re
import sys


def validate_pypi_token(token):
    """Validate PyPI token format"""
    if not token.startswith('pypi-'):
        return False, "Token should start with 'pypi-'"
    
    if len(token) < 20:
        return False, "Token seems too short"
    
    return True, "Token format looks valid"


def main():
    print("🔐 SpindleX GitLab CI Variables Setup Helper")
    print("=" * 50)
    
    print("\n📋 Required Variables:")
    print("1. PYPI_TOKEN - Production PyPI API token")
    print("2. PYPI_TEST_TOKEN - Test PyPI API token")
    
    print("\n🔗 Get your tokens from:")
    print("- Production: https://pypi.org/manage/account/")
    print("- Test: https://test.pypi.org/manage/account/")
    
    print("\n⚙️ GitLab CI Variables Setup:")
    print("1. Go to: Settings > CI/CD > Variables")
    print("2. Add each variable with these settings:")
    print("   - Protected: ✅ (only on protected branches/tags)")
    print("   - Masked: ✅ (hidden in logs)")
    
    # Optional token validation
    if len(sys.argv) > 1 and sys.argv[1] == "--validate":
        print("\n🔍 Token Validation:")
        
        prod_token = input("Enter Production PyPI token (or press Enter to skip): ").strip()
        if prod_token:
            valid, msg = validate_pypi_token(prod_token)
            print(f"Production token: {'✅' if valid else '❌'} {msg}")
        
        test_token = input("Enter Test PyPI token (or press Enter to skip): ").strip()
        if test_token:
            valid, msg = validate_pypi_token(test_token)
            print(f"Test token: {'✅' if valid else '❌'} {msg}")
    
    print("\n✅ Once variables are set, you can create releases with:")
    print("   python scripts/release.py --version X.Y.Z")


if __name__ == "__main__":
    main()