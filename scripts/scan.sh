#!/bin/bash
set -euo pipefail

# DevScrub Security Scanner - Docker Runner Script

# Default values
PROJECT_PATH="${1:-$(pwd)}"
REPORTS_PATH="${2:-$(pwd)/reports}"
FORMAT="${3:-all}"

show_help() {
    cat << EOF
🔒 DevScrub Security Scanner (Docker)

Usage: $0 [PROJECT_PATH] [REPORTS_PATH] [FORMAT]

Arguments:
  PROJECT_PATH   Path to project to scan (default: current directory)
  REPORTS_PATH   Path to save reports (default: ./reports)
  FORMAT         Report format: json, html, all (default: all)

Examples:
  $0                                   # Scan current directory
  $0 /path/to/project                  # Scan specific project
  $0 /path/to/project ./reports json   # Custom reports path and format

Environment variables:
  DOCKER_IMAGE   Docker image name (default: devscrub-scanner:latest)
EOF
    exit 0
}

# Validate inputs
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
fi

# Validate format
if [[ ! "$FORMAT" =~ ^(json|html|all)$ ]]; then
    echo "❌ Error: Invalid format '$FORMAT'. Must be: json, html, all" >&2
    exit 1
fi

# Set Docker image
DOCKER_IMAGE="${DOCKER_IMAGE:-devscrub-scanner:latest}"

# Validate project path exists and is accessible
if [ ! -d "$PROJECT_PATH" ] || [ ! -r "$PROJECT_PATH" ]; then
    echo "❌ Error: Project path '$PROJECT_PATH' does not exist or is not accessible" >&2
    exit 1
fi

# Create reports directory
mkdir -p "$REPORTS_PATH"

# Convert to absolute paths
PROJECT_PATH=$(realpath "$PROJECT_PATH")
REPORTS_PATH=$(realpath "$REPORTS_PATH")

echo "🔒 DevScrub Security Scanner"
echo "📁 Project: $PROJECT_PATH"
echo "📊 Reports: $REPORTS_PATH"
echo "📄 Format: $FORMAT"
echo "🐳 Image: $DOCKER_IMAGE"

# Validate Docker image exists
if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "❌ Docker image '$DOCKER_IMAGE' not found!" >&2
    echo "💡 Build it first with: ./scripts/build.sh" >&2
    exit 1
fi

# Run the scanner with proper error handling
if docker run --rm \
    -v "$PROJECT_PATH:/scan:ro" \
    -v "$REPORTS_PATH:/reports" \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    "$DOCKER_IMAGE" \
    /scan --format "$FORMAT"; then
    
    echo "✅ Security scan completed successfully!"
    echo "📊 Reports saved to: $REPORTS_PATH"
    
    # List generated reports
    if ls "$REPORTS_PATH"/security_report_*.* >/dev/null 2>&1; then
        echo "📄 Generated reports:"
        ls -la "$REPORTS_PATH"/security_report_*.*
    fi
else
    echo "❌ Security scan failed!" >&2
    exit 1
fi 