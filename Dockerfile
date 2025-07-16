# DevScrub Security Scanner - Optimized Multi-stage Build
# BuildKit: 1.0
# Syntax: docker/dockerfile:1.4

# Version extraction
FROM alpine:3.22.0 AS version
COPY VERSION /VERSION
RUN VERSION=$(cat /VERSION | tr -d ' \n') && echo "VERSION=$VERSION" > /version.env

# Base stage
FROM alpine:3.22.0 AS base

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

# Security: Set shell for better error handling
SHELL ["/bin/ash", "-o", "pipefail", "-c"]

# Security: Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -s /bin/bash -u 1000 -G scanner scanner

# Install essential packages
RUN apk update && \
    apk upgrade --no-cache && \
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
    libxml2 \
    ca-certificates && \
    rm -rf /var/cache/apk/* && \
    chown -R scanner:scanner /home/scanner

# Python build stage
FROM base AS python-build
WORKDIR /tmp/python-build

# Install build dependencies for Python compilation
RUN apk add --no-cache --virtual .build-deps \
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
    python3-dev

# Download and build Python with optimizations
RUN curl -fsSL https://www.python.org/ftp/python/3.12.11/Python-3.12.11.tgz | tar -xz && \
    cd Python-3.12.11 && \
    ./configure \
        --prefix=/usr/local \
        --enable-optimizations \
        --with-ensurepip=install \
        --with-system-ffi \
        --enable-loadable-sqlite-extensions \
        --with-lto && \
    make -j$(nproc) LDFLAGS="-Wl,--strip-all" && \
    make install && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/local/bin/pip3 /usr/local/bin/pip && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    cd / && rm -rf /tmp/python-build && \
    apk del .build-deps && \
    rm -rf /var/cache/apk/*

# Node.js tools stage
FROM node:24-alpine AS node-tools

# Install Node.js tools
RUN npm config set audit false && \
    npm config set fund false && \
    npm cache clean --force && \
    apk add --no-cache libstdc++ gcc && \
    npm install -g eslint@8.57.0 && \
    npm cache clean --force && \
    apk del gcc && \
    rm -rf /var/cache/apk/*

# Final production stage
FROM base AS final

# Copy Python and Node.js from build stages
COPY --from=python-build /usr/local /usr/local
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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Entrypoint
ENTRYPOINT ["/app/scripts/entrypoint.sh"] 