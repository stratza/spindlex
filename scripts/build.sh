#!/bin/bash
# Build script for Spindle

set -e

echo "Building Spindle distributions..."

# Clean previous builds
rm -rf dist/ build/ *.egg-info/

# Install build dependencies
python -m pip install --upgrade build==1.4.4 twine==6.2.0

# Build wheel and source distribution
python -m build

# Check the distributions
python -m twine check dist/*

echo "Build completed successfully!"
echo "Distributions available in dist/:"
ls -la dist/
