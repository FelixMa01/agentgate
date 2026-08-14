#!/usr/bin/env python3
"""AgentGate hook entrypoint — invoked by Claude Code as a PreToolUse hook.

Reads AGENTGATE_POLICY and AGENTGATE_DB env vars, delegates to agentgate.hook.

This script lives at bin/agentgate-hook.py. install-hook writes its absolute
path into settings.json. We expect either:
  (a) The script is run with `python3 bin/agentgate-hook.py` — sys.path[0] is
      the script's dir, but the package lives in src/. We add src/ explicitly.
  (b) The script is run with `uv run --project .` (the recommended pattern),
      which puts src/ on sys.path via the installed package.
Either way, the explicit src/ insertion below is a safety net.
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentgate.hook import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())