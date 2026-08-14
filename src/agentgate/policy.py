"""Policy DSL — load YAML rules, evaluate tool calls and network requests."""
from __future__ import annotations
import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # require human approval (Slack/Telegram)
    LOG = "log"  # allow but record


@dataclass
class Rule:
    id: str
    name: str
    match: dict[str, Any]  # {"tool": "Bash", "command_glob": "rm -rf *"}
    action: Action
    reason: str = ""

    def matches(self, event: dict) -> bool:
        for key, pattern in self.match.items():
            actual = self._dig(event, key)
            if actual is None:
                # Allow glob suffix: e.g. match key 'file_glob' digs event 'file'.
                base = key.removesuffix("_glob")
                if base != key:
                    actual = self._dig(event, base)
            if actual is None:
                return False
            if not self._match_pattern(actual, pattern):
                return False
        return True

    @staticmethod
    def _dig(obj: dict, dotted: str) -> Any:
        cur = obj
        for part in dotted.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
            if cur is None:
                return None
        return cur

    @staticmethod
    def _match_pattern(actual: Any, pattern: Any) -> bool:
        if isinstance(pattern, list):
            return any(Rule._match_pattern(actual, p) for p in pattern)
        if not isinstance(pattern, str):
            return actual == pattern
        if pattern == "*":
            return True
        if pattern.startswith("~"):
            try:
                return bool(re.search(pattern[1:], str(actual)))
            except re.error:
                return False
        # Translate fnmatch-style glob to regex so '*' matches '/' too,
        # then anchor full-string match.
        regex = fnmatch.translate(pattern)
        return re.fullmatch(regex, str(actual)) is not None


@dataclass
class Policy:
    version: int = 1
    default_action: Action = Action.ALLOW
    rules: list[Rule] = field(default_factory=list)
    network: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, event: dict) -> tuple[Action, Rule | None]:
        for rule in self.rules:
            if rule.matches(event):
                return rule.action, rule
        return self.default_action, None


def load_policy(path: str | Path) -> Policy:
    """Load a YAML policy file.

    Schema:
      version: 1
      default: allow | deny | ask
      rules:
        - id: unique-id
          name: Human label
          match: {tool: Bash, command_glob: "rm -rf /*"}
          action: deny
          reason: "Why this rule exists"
      network:
        allowed_domains: [github.com, *.pypi.org]
        denied_domains:  [pastebin.com, *.onion]
        require_https: true
    """
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"Policy root must be a mapping, got {type(raw).__name__}")

    rules = []
    for r in raw.get("rules", []):
        r2 = dict(r)
        if "action" in r2 and isinstance(r2["action"], str):
            r2["action"] = Action(r2["action"])
        rules.append(Rule(**r2))
    return Policy(
        version=int(raw.get("version", 1)),
        default_action=Action(raw.get("default", "allow")),
        rules=rules,
        network=raw.get("network", {}),
    )