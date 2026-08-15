FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="AgentGate" \
      org.opencontainers.image.description="Firewall for AI coding agents" \
      org.opencontainers.image.url="https://github.com/FelixMa01/agentgate" \
      org.opencontainers.image.source="https://github.com/FelixMa01/agentgate" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN groupadd -r agentgate && useradd -r -g agentgate agentgate

WORKDIR /opt/agentgate

# Copy just the project metadata first for layer caching.
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install (uv is faster + resolves transitives cleanly).
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir "cryptography>=45" "mitmproxy>=12" \
 && pip install --no-cache-dir .

USER agentgate
ENV AGENTGATE_HOME=/home/agentgate/.agentgate
RUN mkdir -p /home/agentgate/.agentgate

EXPOSE 8080 8081
VOLUME ["/home/agentgate/.agentgate", "/policies"]

ENTRYPOINT ["agentgate"]
CMD ["--help"]

# Healthcheck uses `agentgate doctor` which exits 0 on success.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD agentgate doctor || exit 1