"""Shared CLI utilities."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import click
import yaml

DEFAULT_POLICY = """\
version: 1
metadata:
  author: agentgate
  version: 1
  last_reviewed: 2026-08-14

default: allow

rules:
  - id: deny-rm-rf
    name: Block destructive rm
    match:
      tool: Bash
      command_glob: "rm -rf /*"
    action: deny
    reason: "Mass deletion outside repo"

  - id: deny-secrets-read
    name: Block reading secrets
    match:
      tool: Read
      file_glob: ["*.pem", ".env*", "*id_rsa*"]
    action: deny
    reason: "Secret files are off-limits"

  - id: ask-network-exfil
    name: Require approval for new domains
    match:
      tool: Bash
      command_glob: ["curl *", "wget *", "http*"]
    action: ask
    reason: "Outbound network from agent"

  - id: log-grep
    name: Log read-only search
    match:
      tool: Grep
    action: log
    reason: ""

network:
  allowed_domains:
    - github.com
    - "*.githubusercontent.com"
    - pypi.org
    - "*.pypi.org"
    - openai.com
    - "*.openai.com"
    - anthropic.com
    - "*.anthropic.com"
  denied_domains:
    - pastebin.com
    - transfer.sh
    - "*gist.github.com/leak*"
  require_https: true
"""


def friendly_yaml_error(path: Path, e: yaml.YAMLError) -> str:
    """Format a YAML error with the offending line (if available)."""
    msg = f"could not parse YAML in {path}: {e}"
    mark = getattr(e, "problem_mark", None)
    if mark:
        line = mark.line + 1
        col = mark.column + 1
        msg += f"\n  near line {line}, column {col}"
    return msg


def resolve_policy(path: str) -> Path:
    p = Path(path).resolve()
    if not p.exists():
        raise click.ClickException(f"policy file not found: {p}")
    return p


def resolve_db(path: str) -> Path:
    p = Path(path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def port_in_use(port: int) -> bool:
    """Light-weight check: is anyone listening on this port?"""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def suggest_port(preferred: int) -> int:
    """Pick the next free port starting from preferred."""
    p = preferred
    for _ in range(20):
        if not port_in_use(p):
            return p
        p += 1
    return preferred  # give up and let the server crash with a real error
