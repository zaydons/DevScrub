# DevScrub Security Scanner - Optimized Ubuntu Build
# BuildKit: 1.0
# Syntax: docker/dockerfile:1.4

# Version extraction
FROM ubuntu:22.04 AS version
COPY VERSION /VERSION
RUN VERSION=$(cat /VERSION | tr -d ' \n') && echo "VERSION=$VERSION" > /version.env

# Base stage
FROM ubuntu:22.04 AS base

# Define build arguments
ARG VERSION
ARG BUILD_DATE
ARG GIT_SHA
ARG GIT_REF
ARG TARGETPLATFORM

# Security labels and metadata
LABEL maintainer="Sal Zaydon<devscrub@zaydon.email>"
LABEL description="Security Scanner with Code Analysis and Vulnerability Detection"
LABEL version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/zaydons/DevScrub"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="DevScrub"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.version="${VERSION}"

# Set non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Security: Set shell for better error handling
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Security: Create non-root user
RUN groupadd -g 1000 scanner && \
    useradd -m -s /bin/bash -u 1000 -g scanner scanner

# Install Python 3.12.11 from deadsnakes PPA
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y \
    python3.12 \
    python3.12-venv \
    python3.12-dev \
    python3.12-distutils \
    curl \
    git \
    docker.io \
    ca-certificates \
    libstdc++6 && \
    # Install pip for Python 3.12
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12 && \
    # Create symlinks
    ln -sf /usr/bin/python3.12 /usr/local/bin/python && \
    ln -sf /usr/bin/python3.12 /usr/local/bin/python3 && \
    ln -sf /usr/local/bin/pip /usr/local/bin/pip && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R scanner:scanner /home/scanner

# Node.js tools stage
FROM node:24 AS node-tools

# Install Node.js tools
RUN npm config set audit false && \
    npm config set fund false && \
    npm cache clean --force && \
    npm install -g eslint@8.57.0 && \
    npm cache clean --force

# Final production stage
FROM base AS final

# Copy Node.js from build stage
COPY --from=node-tools /usr/local/bin/node /usr/local/bin/
COPY --from=node-tools /usr/local/bin/npm /usr/local/bin/
COPY --from=node-tools /usr/local/bin/yarn /usr/local/bin/
COPY --from=node-tools /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=node-tools /usr/local/bin/eslint /usr/local/bin/

# Set working directory
WORKDIR /scan

# Copy requirements first for better layer caching
COPY --chown=scanner:scanner requirements.txt /app/
COPY --chown=scanner:scanner VERSION /app/

# Install Python requirements
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    rm -rf /root/.cache

# Copy application code
COPY --chown=scanner:scanner src/ /app/src/
COPY --chown=scanner:scanner scripts/ /app/scripts/

# Make scripts executable and set ownership
RUN chmod +x /app/scripts/*.sh && \
    chown -R scanner:scanner /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER scanner

# Verify Python installation
RUN python --version

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Entrypoint
ENTRYPOINT ["/app/scripts/entrypoint.sh"] 