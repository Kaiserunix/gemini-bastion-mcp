# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22-bookworm-slim

# ==============================================================================
# Stage 1: base-lite (slim Node 22.23.4+ runtime + bwrap + git + ripgrep)
# ==============================================================================
FROM ${NODE_IMAGE} AS base-lite

# Enforce October 2026 Node 22 LTS security baseline (>= 22.23.4).
RUN node -e 'const [maj,min,pat]=process.versions.node.split(".").map(Number); if(maj<22||(maj===22&&(min<23||(min===23&&pat<4)))){console.error(`ERROR: Node.js ${process.versions.node} is below the 22.23.4 security baseline. Pull a newer base image or pass --build-arg NODE_IMAGE=node:22.23.4-bookworm-slim.`);process.exit(1);}'

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash \
      bubblewrap \
      ca-certificates \
      curl \
      git \
      jq \
      ripgrep \
      sudo \
      tini \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Stage 2: builder (compiles TypeScript & native modules; stripped from runtime)
# ==============================================================================
FROM base-lite AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      g++ \
      make \
      python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY tsconfig.json ./
COPY src ./src

# Keep production dependencies (including `typescript` for L0 validation)
RUN npm run build && npm prune --omit=dev

# ==============================================================================
# Stage 3: runtime-lite (compact ~300-400MB non-root runtime, UID 1001/1002)
# ==============================================================================
FROM base-lite AS runtime-lite

# Create isolated service users:
# - gateway (UID 1001): owns /data (0700, including /data/artifacts and /data/codex) and /app
# - worker  (UID 1002): owns /workspaces; runs sandboxed workspace_exec / shell_task / runner
# gateway is in the worker group to manage workspaces, while worker has ZERO access to /data.
RUN groupadd --gid 1001 gateway \
    && useradd --uid 1001 --gid 1001 --create-home --home-dir /home/gateway --shell /bin/bash gateway \
    && groupadd --gid 1002 worker \
    && useradd --uid 1002 --gid 1002 --create-home --home-dir /home/worker --shell /bin/bash worker \
    && usermod -aG worker gateway \
    && echo "gateway ALL=(worker:worker) NOPASSWD: ALL" > /etc/sudoers.d/gateway-worker \
    && chmod 0440 /etc/sudoers.d/gateway-worker \
    && mkdir -p /data/artifacts /data/codex /workspaces /opt/mise /app \
    && chown -R gateway:gateway /data /home/gateway /app \
    && chmod 0700 /data /data/artifacts /data/codex /home/gateway \
    && chown -R worker:worker /workspaces /home/worker /opt/mise \
    && chmod 2775 /workspaces /opt/mise

WORKDIR /app

COPY --from=builder --chown=gateway:gateway /app/package.json ./
COPY --from=builder --chown=gateway:gateway /app/node_modules ./node_modules
COPY --from=builder --chown=gateway:gateway /app/dist ./dist
COPY --chown=gateway:gateway docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod 0755 /usr/local/bin/entrypoint.sh

ENV NODE_ENV=production \
    PORT=8787 \
    DATA_DIR=/data \
    ARTIFACTS_DIR=/data/artifacts \
    WORKSPACES_DIR=/workspaces \
    CODEX_HOME=/data/codex

LABEL org.opencontainers.image.title="GeminiBastionMCP" \
      org.opencontainers.image.description="Self-hosted OAuth 2.1 Streamable HTTP MCP bastion for Web Gemini, Claude & ChatGPT" \
      org.opencontainers.image.source="https://github.com/Kaiserunix/gemini-bastion-mcp" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.kaiserunix/gemini-bastion-mcp"

USER gateway

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8787/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["node", "dist/index.js"]

# ==============================================================================
# Stage 4: runtime-full (default target; adds Python 3.12+uv, mise & linters)
# ==============================================================================
FROM runtime-lite AS runtime-full

ARG HADOLINT_VERSION=2.12.0
ARG ACTIONLINT_VERSION=1.7.7
ARG GITLEAKS_VERSION=8.24.2

USER root

# Keep /opt/mise/shims OUT of gateway's global PATH so worker-writable tools cannot shadow /usr/bin/sudo or node
ENV MISE_DATA_DIR=/opt/mise \
    MISE_CACHE_DIR=/opt/mise/cache \
    MISE_CONFIG_DIR=/opt/mise/config \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_TOOL_DIR=/opt/uv-tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_CACHE_DIR=/opt/mise/uv-cache \
    NPM_CONFIG_CACHE=/opt/mise/npm-cache \
    npm_config_cache=/opt/mise/npm-cache

RUN apt-get update && apt-get install -y --no-install-recommends \
      gnupg \
      openssh-client \
      shellcheck \
      unzip \
      xz-utils \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
         -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
         > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# uv + Python 3.12 + ruff
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv python install 3.12 \
    && py_bin="$(uv python find 3.12)" \
    && ln -sf "${py_bin}" /usr/local/bin/python3.12 \
    && ln -sf /usr/local/bin/python3.12 /usr/local/bin/python3 \
    && ln -sf /usr/local/bin/python3.12 /usr/local/bin/python \
    && uv tool install ruff

# mise (for on-demand Go/Rust/extra runtimes persisted in /opt/mise)
RUN curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh \
    && mkdir -p /opt/mise/cache /opt/mise/config /opt/mise/shims /opt/mise/uv-cache /opt/mise/npm-cache \
    && chown -R worker:worker /opt/mise \
    && chmod -R 2775 /opt/mise

# Security & CI linters (hadolint, actionlint, gitleaks)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) hl_arch="x86_64"; al_arch="amd64"; gl_arch="x64" ;; \
      arm64) hl_arch="arm64"; al_arch="arm64"; gl_arch="arm64" ;; \
      *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${hl_arch}" \
      -o /usr/local/bin/hadolint; \
    chmod 0755 /usr/local/bin/hadolint; \
    curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${al_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin actionlint; \
    chmod 0755 /usr/local/bin/actionlint; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks

# Global Node-based developer & quality tools
RUN npm install -g \
      repomix \
      @biomejs/biome \
      pyright \
      @ast-grep/cli \
      wrangler \
    && npm cache clean --force

USER gateway
