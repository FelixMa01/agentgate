# AgentGate — convenience targets for common tasks.
# Run `make help` for the full list.

.PHONY: help install test verify lint format build publish clean release doctor run-dashboard run-proxy

help:
	@echo "AgentGate targets:"
	@echo "  make install    - uv sync (deps + editable install)"
	@echo "  make test       - pytest tests/"
	@echo "  make verify     - bash scripts/verify.sh (10-step e2e)"
	@echo "  make lint       - pyflakes + import order"
	@echo "  make format     - black + isort"
	@echo "  make build      - uv build (wheel + sdist)"
	@echo "  make publish    - uv publish to PyPI (needs UV_PUBLISH_TOKEN)"
	@echo "  make release    - build + publish + tag + GitHub release"
	@echo "  make clean      - remove build artifacts"
	@echo "  make doctor     - print env diagnostics"
	@echo ""
	@echo "  make run-dashboard   - agentgate dashboard (port 8766)"
	@echo "  make run-proxy       - agentgate proxy (port 8080)"
	@echo "  make run-approval    - agentgate approval-server (port 8765)"

install:
	uv sync --all-extras

test:
	uv run pytest tests/ -v

verify:
	bash scripts/verify.sh

lint:
	uv run python -m pyflakes src/ tests/

format:
	uv run python -m black src/ tests/
	uv run python -m isort src/ tests/

build:
	uv build

publish:
	@test -n "$(UV_PUBLISH_TOKEN)" || { echo "set UV_PUBLISH_TOKEN=pypi-***"; exit 1; }
	uv publish dist/*

release: build publish
	@echo "✓ released. Tag + GitHub release still need to be created manually:"
	@echo "  gh release create v$$(grep version pyproject.toml | head -1 | cut -d'\"' -f2) --generate-notes"

clean:
	rm -rf dist/ build/ *.egg-info/
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

doctor:
	uv run python -c "import sys; print('python:', sys.version); \
		import agentgate; print('agentgate:', agentgate.__version__); \
		import mitmproxy; print('mitmproxy:', mitmproxy.__version__); \
		import click; print('click:', click.__version__); \
		import yaml; print('pyyaml:', yaml.__version__)"

run-dashboard:
	uv run agentgate dashboard --db ./demo/audit.db

run-proxy:
	uv run agentgate proxy --policy ./examples/policy.yaml --db ./demo/audit.db

run-approval:
	uv run agentgate approval-server --port 8765