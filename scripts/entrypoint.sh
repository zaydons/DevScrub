#!/bin/bash
set -euo pipefail

# Docker entrypoint for DevScrub Security Scanner

# Set default values
SCAN_DIR="/scan"
REPORTS_DIR="/scan/security-reports"

# Parse scan directory from arguments
if [ $# -gt 0 ] && { [[ $1 == /* ]] || [[ $1 == .* ]] || [[ $1 != -* ]]; }; then
    SCAN_DIR="$1"
    REPORTS_DIR="$1/security-reports"
    shift
fi

# Validate scan directory
if [ ! -d "$SCAN_DIR" ] || [ ! -r "$SCAN_DIR" ]; then
    echo "❌ Error: Scan directory '$SCAN_DIR' does not exist or is not accessible" >&2
    echo "💡 Mount your project directory to /scan:" >&2
    echo "   docker run -v /path/to/project:/scan devscrub-scanner" >&2
    exit 1
fi

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

echo "🔒 DevScrub Security Scanner"
echo "📁 Scanning: $SCAN_DIR"
echo "📊 Reports: $REPORTS_DIR"

# Execute security scanner
exec python3 -m src.security_scanner "$SCAN_DIR" --output "$REPORTS_DIR" "$@" 