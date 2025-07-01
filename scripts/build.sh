#!/bin/bash
set -euo pipefail

# Build DevScrub Security Scanner Docker Image

# Validate Dockerfile exists
if [ ! -f "Dockerfile" ]; then
    echo "❌ Error: Dockerfile not found!" >&2
    exit 1
fi

# Build the Docker image
echo "🏗️  Building Docker image..."
if docker build -t devscrub-scanner:latest .; then
    echo "✅ Docker image built successfully!"
    echo ""
    echo "🚀 Usage:"
    echo "  ./scripts/scan.sh"
    echo "  ./scripts/scan.sh /path/to/project"
    echo "  docker-compose up security-scanner"
    echo "  docker run --rm -v /path/to/project:/scan:ro -v \$(pwd)/reports:/reports devscrub-scanner"
else
    echo "❌ Docker build failed!" >&2
    exit 1
fi 