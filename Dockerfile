# AgentGate Docker image — minimal runtime for headless deployments.
# Build:  docker build -t agentgate-firewall:0.6.1 .
# Use:    docker run --rm -v $(pwd)/audit.db:/tmp/audit.db agentgate-firewall audit --db /tmp/audit.db

FROM python:3.12-slim AS base

LABEL maintainer="FelixMa01"
LABEL org.opencontainers.image.source="https://github.com/FelixMa01/agentgate"
LABEL org.opencontainers.image.description="Firewall for AI coding agents"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir agentgate-firewall

# Run as non-root for security.
RUN useradd --create-home --shell /bin/bash agent
USER agent
WORKDIR /home/agent

ENTRYPOINT ["agentgate"]
CMD ["--help"]