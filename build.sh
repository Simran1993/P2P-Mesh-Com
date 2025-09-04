#!/bin/bash
echo "Building Mesh Network Application..."
echo

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Install build requirements
echo "Installing build requirements..."
pip install -r requirements-build.txt

# Clean and build
echo "Cleaning previous builds..."
python3 build.py

echo
echo "Build complete! Check the dist/ folder for your executable."
