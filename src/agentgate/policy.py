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
from .rate_limit import RateLimitConfig, RateLimiter


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
    - dry-run:           Never block, never ask, never approve. Record every
                        decision with what the outcome WOULD have been. Lets
                        you preview a policy change before flipping the switch.
    """

    ENFORCE = "enforce"
    OBSERVE = "observe"
    CI = "ci"
    DRY_RUN = "dry-run"

    @classmethod
    def from_env(cls) -> Mode:
        raw = os.environ.get("AGENTGATE_MODE", "enforce").lower().strip()
        for m in cls:
            if m.value == raw:
                return m
        raise ValueError(
            f"Unknown AGENTGATE_MODE={raw!r}; "
            f"expected one of: enforce, observe, ci, dry-run"
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


def evaluate_cel(expr: str, event: dict) -> bool:
    """Evaluate a CEL-lite `when` expression against an event dict.

    Supported grammar (small but covers most "deny rm unless cwd is X" cases):

        when: 'event.cwd == "/srv" and event.tool == "Bash"'
        when: 'event.session_id in allowlist or event.cwd != "/tmp"'
        when: 'not event.dry_run'
        when: 'event.risk_score > 7'

    Operators: ==, !=, in, not-in (written as 'not-in'), >, <, >=, <=
    Logical: and, or, not, parens
    Literals: strings ("..."), numbers (123, 1.5), bools (true/false), null,
              barewords (event.x — looked up on the event dict)
    """
    import ast
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"invalid CEL expression {expr!r}: {exc}") from exc

    def _eval(node: ast.AST):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [_eval(elt) for elt in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(_eval(elt) for elt in node.elts)
        if isinstance(node, ast.Name):
            if node.id == "event":
                return event
            return event.get(node.id)
        if isinstance(node, ast.Attribute):
            base = _eval(node.value)
            if isinstance(base, dict):
                return base.get(node.attr)
            return None
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(_eval(v) for v in node.values)
            if isinstance(node.op, ast.Or):
                return any(_eval(v) for v in node.values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not _eval(node.operand)
        if isinstance(node, ast.Compare):
            left = _eval(node.left)
            for op, comparator in zip(node.ops, node.comparators, strict=False):
                right = _eval(comparator)
                ok = (
                    (isinstance(op, ast.Eq) and left == right) or
                    (isinstance(op, ast.NotEq) and left != right) or
                    (isinstance(op, ast.Gt) and _cmp(left, right, lambda a, b: a > b)) or
                    (isinstance(op, ast.Lt) and _cmp(left, right, lambda a, b: a < b)) or
                    (isinstance(op, ast.GtE) and _cmp(left, right, lambda a, b: a >= b)) or
                    (isinstance(op, ast.LtE) and _cmp(left, right, lambda a, b: a <= b)) or
                    (isinstance(op, ast.In) and _membership(left, right)) or
                    (isinstance(op, ast.NotIn) and not _membership(left, right))
                )
                if not ok:
                    return False
                left = right if len(node.ops) > 1 else left
            return True
        return False

    return bool(_eval(tree))


def evaluate_when(when: str, event: dict) -> bool:
    """Rule.matches() helper: True if `when` is empty OR evaluates True.

    An empty/missing `when` means no extra constraint, so the rule can
    fire purely on the match dict. Any non-empty expression must
    evaluate truthy against the event.
    """
    return not when or evaluate_cel(when, event)


def _cmp(a, b, op) -> bool:
    """Numeric-aware compare; returns False on mixed/uncomparable types
    instead of raising (so `event.foo > 5` with foo='bar' fails closed)."""
    if a is None or b is None:
        return False
    try:
        return op(a, b)
    except TypeError:
        return False


def _membership(a, b) -> bool:
    """`in` check that returns False on non-iterables instead of raising."""
    if b is None:
        return False
    try:
        return a in b
    except TypeError:
        return False


@dataclass
class Rule:
    id: str
    match: dict[str, Any]
    action: Action
    name: str = ""
    reason: str = ""
    # Optional CEL-lite condition evaluated against the event dict.
    # Only supports: `event.<key> ==/!=/in/not-in <literal>`,
    # `and`/`or`/`not`, and `true`/`false` — anything else raises at load.
    when: str = ""
    # Optional token-bucket rate limit. When the bucket is empty, this
    # rule is skipped (falls through to the next matching rule).
    rate_limit: RateLimitConfig | None = None

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
            # Pick match mode by key suffix: '*_regex' -> re.search, '*_glob' -> fnmatch,
            # otherwise plain equality.
            if key.endswith("_regex"):
                try:
                    if not re.search(str(pattern), str(actual)):
                        return False
                except re.error:
                    return False
            elif key.endswith("_glob"):
                regex = fnmatch.translate(str(pattern))
                if re.fullmatch(regex, str(actual)) is None:
                    return False
            else:
                if not self._match_pattern(actual, pattern):
                    return False
        # Optional CEL-lite `when` condition on top of the match patterns.
        return evaluate_when(self.when, event)

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

    # Per-rule token-bucket rate limiter. Shared across all evaluations in
    # this Policy instance; reset on PolicyWatcher reload.
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)

    def is_known_tool(self, tool_name: str) -> bool:
        """Check whether `tool_name` appears in any rule's match.

        Used to decide whether the unknown_tool_action should kick in.
        """
        if tool_name in self.known_tools:
            return True
        return any(rule.match.get("tool") == tool_name for rule in self.rules if "tool" in rule.match)

    def effective_action(self, action: Action) -> Action:
        """Apply current mode to a raw decision.

        observe → always ALLOW (record only)
        ci      → ASK becomes DENY (no prompts in CI)
        dry-run → always ALLOW but record the raw verdict (preview mode)
        enforce → unchanged
        """
        if self.mode is Mode.OBSERVE:
            return Action.ALLOW
        if self.mode is Mode.DRY_RUN:
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

        Fails closed (ASK) when critical fields are missing. For audit
        logging where you need both raw and effective, use evaluate_with_meta.
        """
        raw, rule = self.validate_event(event)
        return self.effective_action(raw), rule

    def _evaluate_raw(self, event: dict) -> tuple[Action, Rule | None]:
        # DENY-first semantics: any matching deny rule wins immediately.
        # This prevents an earlier, broader allow/ask rule from silently
        # overriding a more specific deny. Without this, `ask-bash` would
        # shadow `deny-rm` for `rm -rf /`. Deny rules bypass rate limits —
        # they should always fire when matched.
        for rule in self.rules:
            if rule.action == Action.DENY and rule.matches(event):
                return Action.DENY, rule
        # Then first-match for allow/ask rules, with rate-limit gating.
        for rule in self.rules:
            if not rule.matches(event):
                continue
            if rule.rate_limit is not None and not self.rate_limiter.check(
                rule.id, rule.rate_limit
            ):
                # Rate-limit exhausted: skip this rule, fall through.
                continue
            return rule.action, rule
        # Fallback: check if the event's tool was even referenced by any rule.
        tool_name = event.get("tool")
        if tool_name and not self.is_known_tool(tool_name) and self.unknown_tool_action is not None:
            return self.unknown_tool_action, None
        return self.default_action, None

    def missing_fields(self, event: dict) -> list[str]:
        """Return names of critical fields that are missing or None for this event.

        Each tool has its own required fields. Used by hooks to fail-closed
        (ASK) when an agent submits an incomplete event payload.
        """
        tool = (event.get("tool") or "").lower()
        requirements: dict[str, list[str]] = {
            "bash": ["command"],
            "exec": ["command"],
            "shell": ["command"],
            "read": ["file"],
            "write": ["file", "content"],
            "edit": ["file", "content"],
            "glob": ["pattern"],
            "grep": ["pattern"],
            "webfetch": ["url"],
            "curl": ["url"],
        }
        required = requirements.get(tool, [])
        missing: list[str] = []
        for required_field in required:
            val = event.get(required_field)
            if val is None or (isinstance(val, str) and not val.strip()):
                missing.append(required_field)
        return missing

    def validate_event(self, event: dict) -> tuple[Action, Rule | None]:
        """Evaluate event with fail-closed validation.

        If a critical field for the event's tool is missing or None (e.g.
        Bash with no command), returns ASK with a synthetic rule explaining
        what's wrong — better to ask than to silently allow an ambiguous
        tool call.

        Otherwise falls through to _evaluate_raw.
        """
        missing = self.missing_fields(event)
        if missing:
            tool_name = event.get("tool") or "?"
            synth_rule = Rule(
                id=f"missing-{tool_name}",
                name=f"Missing required field: {', '.join(missing)}",
                match={"tool": tool_name},
                action=Action.ASK,
                reason=f"agent submitted incomplete event (missing {', '.join(missing)})",
            )
            return Action.ASK, synth_rule
        return self._evaluate_raw(event)

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
        # Parse rate_limit dict into RateLimitConfig; bad shape raises.
        if "rate_limit" in r2 and isinstance(r2["rate_limit"], dict):
            r2["rate_limit"] = RateLimitConfig.from_dict(r2["rate_limit"])
        rules.append(Rule(**r2))
    return Policy(
        version=int(raw.get("version", 1)),
        default_action=Action(raw.get("default_action", raw.get("default", "allow"))),
        rules=rules,
        network=raw.get("network", {}) or {},
        metadata=raw.get("metadata", {}) or {},
        mode=Mode(raw.get("mode", os.environ.get("AGENTGATE_MODE", "enforce"))),
        unknown_tool_action=(
            Action(raw["unknown_tool_action"]) if raw.get("unknown_tool_action") else None
        ),
        known_tools=set(raw.get("known_tools", []) or []),
    )


class PolicyWatcher:
    """Reload a policy from disk when the file changes.

    Designed for long-lived processes (proxy, dashboard) that hold a
    single Policy instance but need to pick up edits without a restart.
    Cheap O(1) stat-then-load; safe to call on every request.

    Usage:
        watcher = PolicyWatcher("/etc/agentgate/policy.yaml")
        policy = watcher.policy          # current snapshot
        if watcher.changed():            # polled
            policy = watcher.reload()
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._mtime: float | None = None
        self._policy: Policy = load_policy(self.path)
        self._stamp()

    def _stamp(self) -> None:
        try:
            self._mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            self._mtime = None

    @property
    def policy(self) -> Policy:
        return self._policy

    def changed(self) -> bool:
        """True if the file's mtime has advanced since last load."""
        try:
            current = self.path.stat().st_mtime
        except FileNotFoundError:
            return False
        return self._mtime is None or current != self._mtime

    def reload(self) -> Policy:
        """Force a reload from disk. Returns the new Policy."""
        self._policy = load_policy(self.path)
        self._stamp()
        return self._policy

    def maybe_reload(self) -> Policy:
        """Reload only if the file changed. Returns the (possibly same) Policy."""
        if self.changed():
            self.reload()
        return self._policy
