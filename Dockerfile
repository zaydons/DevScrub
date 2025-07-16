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

# Debug: Show build environment
RUN echo "=== Build Environment Debug ===" && \
    echo "Architecture: $(uname -m)" && \
    echo "OS: $(uname -s)" && \
    echo "Kernel: $(uname -r)" && \
    echo "Available memory: $(free -h | grep Mem | awk '{print $2}')" && \
    echo "Available disk space:" && df -h / && \
    echo "================================"

# Install build dependencies
RUN echo "Installing build dependencies..." && \
    apk add --no-cache \
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
    docker-cli && \
    echo "Build dependencies installed successfully"

# Python build stage
FROM base AS python-build
WORKDIR /tmp/python-build
RUN echo "=== Python Build Stage ===" && \
    echo "Downloading Python 3.12.11..." && \
    curl -fsSL https://www.python.org/ftp/python/3.12.11/Python-3.12.11.tgz | tar -xz && \
    echo "Python downloaded successfully" && \
    cd Python-3.12.11 && \
    echo "Configuring Python build..." && \
    ./configure --prefix=/usr/local --enable-optimizations --with-ensurepip=install && \
    echo "Building Python (this may take a while)..." && \
    make -j$(nproc) && \
    echo "Installing Python..." && \
    make install && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/local/bin/pip3 /usr/local/bin/pip && \
    echo "Python build completed successfully" && \
    echo "Python version: $(python --version)" && \
    echo "================================"

# Node.js tools stage
FROM node:24-alpine AS node-tools
RUN echo "=== Node.js Tools Stage ===" && \
    echo "Node.js version: $(node --version)" && \
    echo "npm version: $(npm --version)" && \
    npm cache clean --force && \
    apk add --no-cache libstdc++ gcc && \
    echo "Installing ESLint..." && \
    npm install -g eslint && \
    echo "ESLint installed successfully" && \
    echo "================================"

# Security tools stage
FROM alpine:3.22.0 AS security-tools
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
RUN echo "=== Security Tools Stage ===" && \
    echo "Installing base packages..." && \
    apk add --no-cache \
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
    libxml2 && \
    echo "Base packages installed successfully"

# Install all security tools in one layer
RUN echo "Installing security tools..." && \
    echo "Installing Trivy..." && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    echo "Installing TruffleHog..." && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin && \
    echo "Installing Syft..." && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    echo "Installing Grype..." && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    ARCH=$(uname -m) && \
    echo "Architecture detected: $ARCH" && \
    if [ "$ARCH" = "x86_64" ]; then \
        echo "Installing x86_64 specific tools..." && \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.x86_64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    elif [ "$ARCH" = "aarch64" ]; then \
        echo "Installing aarch64 specific tools..." && \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-arm64 -o /usr/local/bin/hadolint && \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.aarch64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    chmod +x /usr/local/bin/hadolint && \
    echo "Security tools installed successfully" && \
    echo "================================"

FROM security-tools AS python-tools
COPY --from=python-build /usr/local /usr/local
RUN echo "=== Python Tools Stage ===" && \
    echo "Python version: $(python --version)" && \
    echo "Installing Python security tools..." && \
    pip install --no-cache-dir \
    bandit==1.7.5 \
    pip-audit==2.6.1 \
    semgrep==1.60.0 \
    pylint==3.0.3 \
    deepsecrets==1.2.0 \
    ruff && \
    echo "Python tools installed successfully" && \
    echo "================================"

FROM security-tools AS final
COPY --from=python-build /usr/local /usr/local
COPY --from=node-tools /usr/local/bin/node /usr/local/bin/
COPY --from=node-tools /usr/local/bin/npm /usr/local/bin/
COPY --from=node-tools /usr/local/bin/yarn /usr/local/bin/
COPY --from=node-tools /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=node-tools /usr/local/bin/eslint /usr/local/bin/
COPY --from=python-tools /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
WORKDIR /scan
COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY requirements.txt /app/
COPY VERSION /app/
RUN echo "=== Final Stage ===" && \
    echo "Installing Python requirements..." && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    echo "Making scripts executable..." && \
    chmod +x /app/scripts/*.sh && \
    echo "Setting up environment..." && \
    echo "Python version: $(python --version)" && \
    echo "Node version: $(node --version)" && \
    echo "npm version: $(npm --version)" && \
    echo "Available tools:" && \
    which trivy && which trufflehog && which syft && which grype && which hadolint && which shellcheck && \
    echo "================================"
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"
RUN echo "Creating scanner user..." && \
    addgroup -g 1000 scanner && \
    adduser -D -s /bin/bash -u 1000 -G scanner scanner && \
    chown -R scanner:scanner /app && \
    echo "User setup completed" && \
    echo "================================"
USER scanner
ENTRYPOINT ["/app/scripts/entrypoint.sh"] 