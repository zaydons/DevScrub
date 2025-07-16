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

# Install build dependencies with cache mount
RUN --mount=type=cache,target=/var/cache/apk \
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
    docker-cli

# Python build stage with cache mount
FROM base AS python-build
WORKDIR /tmp/python-build
RUN --mount=type=cache,target=/tmp/python-cache \
    curl -fsSL https://www.python.org/ftp/python/3.12.11/Python-3.12.11.tgz | tar -xz && \
    cd Python-3.12.11 && \
    ./configure --prefix=/usr/local --enable-optimizations --with-ensurepip=install && \
    make -j$(nproc) && \
    make install && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/local/bin/pip3 /usr/local/bin/pip

# Node.js tools stage with cache mount
FROM node:24-alpine AS node-tools
RUN --mount=type=cache,target=/root/.npm \
    npm cache clean --force && \
    apk add --no-cache libstdc++ gcc && \
    npm install -g eslint

# Security tools stage
FROM alpine:3.22.0 AS security-tools
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
RUN --mount=type=cache,target=/var/cache/apk \
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
    libxml2

# Install all security tools in one layer with cache mounts
RUN --mount=type=cache,target=/tmp/tools \
    --mount=type=cache,target=/var/cache/apk \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.x86_64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    elif [ "$ARCH" = "aarch64" ]; then \
        curl -L https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-arm64 -o /usr/local/bin/hadolint && \
        curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.aarch64.tar.xz | tar -xJ && \
        mv shellcheck-v0.10.0/shellcheck /usr/local/bin/ && \
        rm -rf shellcheck-v0.10.0; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    chmod +x /usr/local/bin/hadolint

FROM security-tools AS python-tools
COPY --from=python-build /usr/local /usr/local
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir \
    bandit==1.7.5 \
    pip-audit==2.6.1 \
    semgrep==1.60.0 \
    pylint==3.0.3 \
    deepsecrets==1.2.0 \
    ruff

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
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r /app/requirements.txt
RUN chmod +x /app/scripts/*.sh
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"
RUN addgroup -g 1000 scanner && \
    adduser -D -s /bin/bash -u 1000 -G scanner scanner
RUN chown -R scanner:scanner /app
USER scanner
ENTRYPOINT ["/app/scripts/entrypoint.sh"] 