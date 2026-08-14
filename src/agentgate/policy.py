"""Policy DSL — load YAML rules, evaluate tool calls and network requests."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from . import __version__


class Action(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # require human approval (Slack/Telegram)
    LOG = "log"  # allow but record


class Mode(StrEnum):
    """Enforcement mode — how AgentGate treats verdicts.

    - enforce (default): ASK blocks until human approval, DENY blocks hard.
    - observe:           Record the decision but never block. Useful for tuning.
    - ci:                ASK becomes DENY (no interactive prompts in CI).
    """

    ENFORCE = "enforce"
    OBSERVE = "observe"
    CI = "ci"

    @classmethod
    def from_env(cls) -> "Mode":
        raw = os.environ.get("AGENTGATE_MODE", "enforce").lower().strip()
        for m in cls:
            if m.value == raw:
                return m
        raise ValueError(
            f"Unknown AGENTGATE_MODE={raw!r}; expected one of: enforce, observe, ci"
        )


def event_provenance(event: dict, rule_id: str | None = None) -> dict:
    """Compute a provenance record for an event being approved.

    Binds the event payload hash + rule_id + version. Used to detect
    replay attacks where someone tries to reuse an approval token against
    a different event payload.

    Returned dict is JSON-serializable for inclusion in audit_log event_json.
    """
    payload = json.dumps(event, sort_keys=True, default=str)
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "event_sha256": h,
        "rule_id": rule_id,
        "agentgate_version": __version__,
    }


@dataclass
class Rule:
    id: str
    match: dict[str, Any]
    action: Action
    name: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.id

    def matches(self, event: dict) -> bool:
        for key, pattern in self.match.items():
            actual = self._dig(event, key)
            if actual is None:
                # Allow glob/regex suffix: e.g. match key 'file_glob' digs event 'file'.
                base = key.removesuffix("_glob").removesuffix("_regex")
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
            # Explicit regex form: ~pattern (or ~pattern list) — re.search semantics.
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
    metadata: dict[str, Any] = field(default_factory=dict)
    mode: Mode = Mode.ENFORCE

    # Action when an event's tool is not referenced by ANY rule's match.
    # None (default) = fall through to default_action (back-compat).
    # Set to ASK to surface unknown tools to the user (fail-closed-but-not-silent).
    # Set to DENY for strict lockdown (fail-closed).
    unknown_tool_action: Action | None = None

    # Optional: tool names explicitly allowed even when unknown_tool_action=DENY
    known_tools: set[str] = field(default_factory=set)

    def is_known_tool(self, tool_name: str) -> bool:
        """Check whether `tool_name` appears in any rule's match.

        Used to decide whether the unknown_tool_action should kick in.
        """
        if tool_name in self.known_tools:
            return True
        for rule in self.rules:
            if "tool" in rule.match and rule.match["tool"] == tool_name:
                return True
        return False

    def effective_action(self, action: Action) -> Action:
        """Apply current mode to a raw decision.

        observe → always ALLOW (record only)
        ci      → ASK becomes DENY (no prompts in CI)
        enforce → unchanged
        """
        if self.mode is Mode.OBSERVE:
            return Action.ALLOW
        if self.mode is Mode.CI and action is Action.ASK:
            return Action.DENY
        return action

    @property
    def allowed_domains(self) -> list[str]:
        return self.network.get("allowed_domains", []) or []

    @property
    def denied_domains(self) -> list[str]:
        return self.network.get("denied_domains", []) or []

    @property
    def require_https(self) -> bool:
        return bool(self.network.get("require_https", False))

    def evaluate(self, event: dict) -> tuple[Action, Rule | None]:
        """Evaluate event, returning the EFFECTIVE action (after applying mode).

        For audit logging where you need both raw and effective, use
        evaluate_with_meta instead.
        """
        raw, rule = self._evaluate_raw(event)
        return self.effective_action(raw), rule

    def _evaluate_raw(self, event: dict) -> tuple[Action, Rule | None]:
        # Per-rule evaluation
        for rule in self.rules:
            if rule.matches(event):
                return rule.action, rule
        # Fallback: check if the event's tool was even referenced by any rule.
        tool_name = event.get("tool")
        if tool_name and not self.is_known_tool(tool_name) and self.unknown_tool_action is not None:
            return self.unknown_tool_action, None
        return self.default_action, None

    def evaluate_with_meta(self, event: dict) -> dict:
        """Return both raw and effective decisions plus rule metadata.

        Used by audit logging so we can show "policy said ask, mode=observe made
        it allow" in the dashboard.
        """
        raw, rule = self._evaluate_raw(event)
        effective = self.effective_action(raw)
        return {
            "raw_action": raw.value,
            "effective_action": effective.value,
            "mode": self.mode.value,
            "rule_id": rule.id if rule else None,
            "rule_name": rule.name if rule else "",
            "rule_reason": rule.reason if rule else "",
        }

    def evaluate_explain(self, event: dict) -> dict:
        """Like evaluate(), but also returns why each rule matched/missed.

        Returns both raw_action (what the policy literally says) and
        effective_action (after applying mode). decision = effective_action.
        """
        candidates = []
        raw_action = self.default_action
        matched_rule_dict = None
        for idx, rule in enumerate(self.rules):
            matched = rule.matches(event)
            candidates.append({
                "index": idx,
                "id": rule.id,
                "name": rule.name,
                "action": rule.action.value,
                "matched": matched,
            })
            if matched:
                raw_action = rule.action
                matched_rule_dict = {
                    "index": idx,
                    "id": rule.id,
                    "name": rule.name,
                    "action": rule.action.value,
                    "reason": rule.reason,
                }
                break
        effective = self.effective_action(raw_action)
        return {
            "raw_action": raw_action.value,
            "effective_action": effective.value,
            "decision": effective.value,
            "mode": self.mode.value,
            "matched_rule": matched_rule_dict,
            "candidates": candidates,
            "total_rules": len(self.rules),
            "default": self.default_action.value,
        }


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
    for i, r in enumerate(raw.get("rules", [])):
        r2 = dict(r)
        if "action" in r2 and isinstance(r2["action"], str):
            r2["action"] = Action(r2["action"])
        # Auto-assign id from name (or positional index if name missing)
        # so policies don't have to repeat themselves.
        if "id" not in r2:
            r2["id"] = r2.get("name") or f"rule-{i}"
        rules.append(Rule(**r2))
    return Policy(
        version=int(raw.get("version", 1)),
        default_action=Action(raw.get("default", "allow")),
        rules=rules,
        network=raw.get("network", {}) or {},
        metadata=raw.get("metadata", {}) or {},
        mode=Mode(raw.get("mode", os.environ.get("AGENTGATE_MODE", "enforce"))),
        unknown_tool_action=(
            Action(raw["unknown_tool_action"]) if raw.get("unknown_tool_action") else None
        ),
        known_tools=set(raw.get("known_tools", []) or []),
    )
