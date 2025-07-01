#!/bin/bash
set -euo pipefail

echo "🔒 DevScrub Security Scanner Installation"
echo "========================================"

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed" >&2
    exit 1
fi

echo "✅ Python 3 found"

# Install Python dependencies
echo "📦 Installing Python security tools..."
if ! pip3 install -r requirements.txt; then
    echo "❌ Failed to install Python dependencies" >&2
    exit 1
fi

# Install JavaScript tools if available
if command -v npm &> /dev/null; then
    echo "📦 Installing JavaScript security tools..."
    if npm install -g yarn; then
        echo "✅ JavaScript tools installed"
    else
        echo "⚠️  Failed to install JavaScript tools"
    fi
else
    echo "⚠️  npm not found - JavaScript scanning will be limited"
fi

# Make scanner executable
chmod +x security_scanner.py

echo ""
echo "🎉 Installation completed!"
echo ""
echo "Usage:"
echo "  python3 security_scanner.py"
echo "  python3 security_scanner.py /path/to/project"
echo "  python3 security_scanner.py --help"
echo ""
echo "For more information, see README.md" 