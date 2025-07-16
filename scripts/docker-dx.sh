#!/bin/bash

# DevScrub Docker DX Helper Script
# Provides useful commands for building, testing, and managing Docker images

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="devscrub"
REGISTRY="ghcr.io"
VERSION=$(cat VERSION 2>/dev/null || echo "0.0.5")
PLATFORMS="linux/amd64,linux/arm64"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running or not accessible"
        exit 1
    fi
}

# Build image locally
build_local() {
    local platform=${1:-linux/amd64}
    local tag="local"
    
    log_info "Building image for platform: $platform"
    log_info "Image: $IMAGE_NAME:$tag"
    
    docker buildx build \
        --platform "$platform" \
        --tag "$IMAGE_NAME:$tag" \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo 'local')" \
        --build-arg GIT_REF="$(git branch --show-current 2>/dev/null || echo 'local')" \
        --load \
        .
    
    log_success "Build completed successfully"
}

# Build multi-platform image
build_multi() {
    log_info "Building multi-platform image"
    log_info "Platforms: $PLATFORMS"
    
    docker buildx build \
        --platform "$PLATFORMS" \
        --tag "$IMAGE_NAME:latest" \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo 'local')" \
        --build-arg GIT_REF="$(git branch --show-current 2>/dev/null || echo 'local')" \
        --push \
        .
    
    log_success "Multi-platform build completed successfully"
}

# Test image functionality
test_image() {
    local tag=${1:-local}
    
    log_info "Testing image: $IMAGE_NAME:$tag"
    
    # Test Python
    log_info "Testing Python..."
    docker run --rm "$IMAGE_NAME:$tag" python --version
    
    # Test Node.js
    log_info "Testing Node.js..."
    docker run --rm "$IMAGE_NAME:$tag" node --version
    
    # Test npm
    log_info "Testing npm..."
    docker run --rm "$IMAGE_NAME:$tag" npm --version
    
    # Test security tools
    log_info "Testing security tools..."
    docker run --rm "$IMAGE_NAME:$tag" trivy --version
    docker run --rm "$IMAGE_NAME:$tag" syft --version
    
    log_success "All tests passed"
}

# Run security scan on the image
security_scan() {
    local tag=${1:-local}
    
    log_info "Running security scan on image: $IMAGE_NAME:$tag"
    
    # Check if Trivy is available
    if ! command -v trivy &> /dev/null; then
        log_warning "Trivy not found. Install it to run security scans."
        return 0
    fi
    
    # Run Trivy scan
    trivy image --severity HIGH,CRITICAL "$IMAGE_NAME:$tag"
    
    log_success "Security scan completed"
}

# Clean up local images
cleanup() {
    log_info "Cleaning up local images..."
    
    # Remove local images
    docker images "$IMAGE_NAME" --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep -v "REPOSITORY" | while read -r line; do
        local image=$(echo "$line" | awk '{print $1}')
        log_info "Removing: $image"
        docker rmi "$image" 2>/dev/null || true
    done
    
    # Clean up dangling images
    docker image prune -f
    
    log_success "Cleanup completed"
}

# Show image information
info() {
    local tag=${1:-local}
    
    log_info "Image information for: $IMAGE_NAME:$tag"
    
    # Check if image exists
    if ! docker images "$IMAGE_NAME:$tag" | grep -q "$IMAGE_NAME"; then
        log_error "Image $IMAGE_NAME:$tag not found"
        return 1
    fi
    
    # Show image details
    echo
    docker images "$IMAGE_NAME:$tag"
    echo
    
    # Show image history
    log_info "Image layers:"
    docker history "$IMAGE_NAME:$tag"
    echo
    
    # Show image labels
    log_info "Image labels:"
    docker inspect "$IMAGE_NAME:$tag" --format '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}'
}

# Show usage
usage() {
    cat << EOF
DevScrub Docker DX Helper Script

Usage: $0 <command> [options]

Commands:
    build [platform]     Build image for specific platform (default: linux/amd64)
    multi               Build multi-platform image
    test [tag]          Test image functionality (default: local)
    scan [tag]          Run security scan on image (default: local)
    cleanup             Clean up local images
    info [tag]          Show image information (default: local)
    help                Show this help message

Examples:
    $0 build                    # Build for linux/amd64
    $0 build linux/arm64       # Build for linux/arm64
    $0 multi                   # Build multi-platform
    $0 test                    # Test local image
    $0 scan                    # Scan local image
    $0 cleanup                 # Clean up images
    $0 info                    # Show local image info

Environment variables:
    IMAGE_NAME          Image name (default: devscrub)
    REGISTRY           Registry (default: ghcr.io)
    VERSION            Version (default: from VERSION file)
    PLATFORMS          Multi-platform targets (default: linux/amd64,linux/arm64)
EOF
}

# Main script
main() {
    check_docker
    
    case "${1:-help}" in
        build)
            build_local "${2:-linux/amd64}"
            ;;
        multi)
            build_multi
            ;;
        test)
            test_image "${2:-local}"
            ;;
        scan)
            security_scan "${2:-local}"
            ;;
        cleanup)
            cleanup
            ;;
        info)
            info "${2:-local}"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 