# DevScrub Security Scanner Docker Image - Multi-stage Alpine Build

FROM alpine:3.22.0 AS base

LABEL maintainer="Sal Zaydon<devscrub@zaydon.email>"
LABEL description="Security Scanner with Code Analysis"
LABEL version="0.0.5"
LABEL org.opencontainers.image.source="https://github.com/zaydons/DevScrub"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="DevScrub"

# Set shell for better error handling
SHELL ["/bin/ash", "-o", "pipefail", "-c"]

# Install build dependencies for Python compilation and security tools
RUN apk add --no-cache \
    curl \
    git \
    bash \
    gcc \
    g++ \
    make \
    musl-dev \
    libffi-dev \
    openssl-dev \
    zlib-dev \
    bzip2-dev \
    readline-dev \
    sqlite-dev \
    ncurses-dev \
    xz-dev \
    libxml2-dev \
    python3-dev \
    py3-pip \
    docker-cli

# Python build stage
FROM base AS python-build

# Download and compile Python 3.12.1 from source
WORKDIR /tmp/python-build
RUN curl -fsSL https://www.python.org/ftp/python/3.12.1/Python-3.12.1.tgz | tar -xz && \
    cd Python-3.12.1 && \
    ./configure --prefix=/usr/local --enable-optimizations --with-ensurepip=install && \
    make -j$(nproc) && \
    make install && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/local/bin/pip3 /usr/local/bin/pip

# Node.js tools stage using node:24-alpine
FROM node:24-alpine AS node-tools

# Yarn is already included in node:24-alpine, just clean cache
RUN npm cache clean --force

# Install system dependencies for Node.js tools
RUN apk add --no-cache libstdc++ gcc

# Install JavaScript linters
RUN npm install -g eslint

# Final stage
FROM alpine:3.22.0 AS final

# Set shell for better error handling
SHELL ["/bin/ash", "-o", "pipefail", "-c"]

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    git \
    bash \
    docker-cli \
    libffi \
    openssl \
    zlib \
    bzip2 \
    readline \
    sqlite \
    ncurses \
    xz \
    libxml2

# Copy Python from build stage
COPY --from=python-build /usr/local /usr/local

# Copy Node.js tools from node stage
COPY --from=node-tools /usr/local/bin/node /usr/local/bin/
COPY --from=node-tools /usr/local/bin/npm /usr/local/bin/
COPY --from=node-tools /usr/local/bin/yarn /usr/local/bin/
COPY --from=node-tools /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=node-tools /usr/local/bin/eslint /usr/local/bin/

# Install security tools with architecture detection
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install hadolint with architecture detection
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint; \
    elif [ "$ARCH" = "aarch64" ]; then \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-arm64 -o /usr/local/bin/hadolint; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    chmod +x /usr/local/bin/hadolint

# Install shellcheck with architecture detection
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.x86_64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    elif [ "$ARCH" = "aarch64" ]; then \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.aarch64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi

# Install Python security tools
RUN pip install --no-cache-dir \
    bandit==1.7.5 \
    pip-audit==2.6.1 \
    semgrep==1.60.0 \
    pylint==3.0.3 \
    deepsecrets==1.2.0

# Install Python linters
RUN pip install --no-cache-dir ruff

# Set up working directory
WORKDIR /scan

# Copy application files
COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY requirements.txt /app/
COPY VERSION /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Make scripts executable
RUN chmod +x /app/scripts/*.sh

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"

# Create non-root user for security
RUN addgroup -g 1000 scanner && \
    adduser -D -s /bin/bash -u 1000 -G scanner scanner

# Change ownership of application files
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Set entrypoint
ENTRYPOINT ["/app/scripts/entrypoint.sh"] 