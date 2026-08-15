"""Static linter for AgentGate policy YAML files.

Catches the most common authoring mistakes that survive a YAML parse but
silently make a policy less effective:

- dead rules (action ``log`` with no event ever reaching them — usually
  means the matcher is wrong)
- shadowed rules (a later rule that is *strictly more specific* than an
  earlier rule with the same action supersedes it)
- unreachable default (a catch-all ``tool: '*'`` rule makes every other
  rule dead)
- missing required keys (every rule needs an action + a match dict)
- unknown action / unknown tool names (typo guard)
- network allowlist contradictions (allowlist + blocklist both empty
  while ``require_https: true``)
- rate_limit schema errors (must be ``{capacity, refill_per_sec}`` or
  ``{requests, per}``)
- ``when:`` CEL expressions that reference unknown event keys

Usage::

    from agentgate.lint import lint_policy, format_report
    findings = lint_policy(policy_dict)
    print(format_report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LintSeverity(StrEnum):
    ERROR = "error"     # definitely wrong, won't behave as expected
    WARNING = "warning" # suspicious, worth a look
    INFO = "info"       # stylistic suggestion


VALID_ACTIONS = {"allow", "deny", "ask", "log"}
VALID_TOOLS = {
    "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "TodoWrite", "network", "*",
}
KNOWN_NETWORK_KEYS = {"default", "allowed_domains", "blocked_domains",
                     "require_https", "max_response_size"}


@dataclass
class LintFinding:
    rule: str          # stable id, e.g. "shadowed-rule"
    severity: LintSeverity
    where: str         # path within the policy, e.g. "rules[3].match.tool"
    message: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "where": self.where,
            "message": self.message,
        }


def lint_policy(policy: dict) -> list[LintFinding]:
    """Return a list of findings. Empty list means the policy is clean."""
    findings: list[LintFinding] = []
    _check_top_level(policy, findings)
    rules = policy.get("rules") or []
    if not isinstance(rules, list):
        findings.append(LintFinding(
            "bad-rules", LintSeverity.ERROR, "rules",
            f"`rules` must be a list, got {type(rules).__name__}",
        ))
        return findings
    seen_ids: set[str] = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            findings.append(LintFinding(
                "bad-rule", LintSeverity.ERROR, f"rules[{i}]",
                f"rule must be a mapping, got {type(rule).__name__}",
            ))
            continue
        _check_rule(rule, i, findings)
        rid = rule.get("id")
        if rid:
            if rid in seen_ids:
                findings.append(LintFinding(
                    "duplicate-id", LintSeverity.ERROR, f"rules[{i}].id",
                    f"duplicate rule id: {rid!r}",
                ))
            seen_ids.add(rid)
    _check_overlap_and_shadow(rules, findings)
    _check_catchall_dead_rules(rules, findings)
    _check_network(policy.get("network") or {}, findings)
    return findings


def _check_top_level(policy: dict, findings: list[LintFinding]) -> None:
    if "version" not in policy:
        findings.append(LintFinding(
            "missing-version", LintSeverity.WARNING, "version",
            "`version:` not set — add `version: 1` to make upgrades explicit",
        ))
    if "default" in policy and policy["default"] not in VALID_ACTIONS:
        findings.append(LintFinding(
            "bad-default", LintSeverity.ERROR, "default",
            f"unknown default action: {policy['default']!r} (valid: {sorted(VALID_ACTIONS)})",
        ))


def _check_rule(rule: dict, index: int, findings: list[LintFinding]) -> None:
    where = f"rules[{index}]"
    if "id" not in rule:
        findings.append(LintFinding(
            "missing-id", LintSeverity.WARNING, f"{where}.id",
            "rule has no `id` — coverage reports and audit will be hard to read",
        ))
    if "action" not in rule:
        findings.append(LintFinding(
            "missing-action", LintSeverity.ERROR, f"{where}.action",
            "rule is missing `action`",
        ))
    elif rule["action"] not in VALID_ACTIONS:
        findings.append(LintFinding(
            "bad-action", LintSeverity.ERROR, f"{where}.action",
            f"unknown action {rule['action']!r} (valid: {sorted(VALID_ACTIONS)})",
        ))
    match = rule.get("match")
    if not isinstance(match, dict) or not match:
        findings.append(LintFinding(
            "empty-match", LintSeverity.ERROR, f"{where}.match",
            "rule needs a non-empty `match:` dict (otherwise it fires on everything)",
        ))
    else:
        tool = match.get("tool")
        if isinstance(tool, str) and tool not in VALID_TOOLS:
            findings.append(LintFinding(
                "unknown-tool", LintSeverity.INFO, f"{where}.match.tool",
                f"tool {tool!r} not in the AgentGate known set {sorted(VALID_TOOLS)} "
                "— verify it's spelled correctly",
            ))
    # CEL `when` expression: surface obvious typos by collecting event keys.
    when = rule.get("when")
    if isinstance(when, str) and when:
        # Cheap parse: look for `event.<word>` references.
        import re
        refs = re.findall(r"event\.([a-zA-Z_][a-zA-Z0-9_]*)", when)
        if refs:
            valid_keys = {"tool", "command", "file", "path", "cwd", "url",
                          "method", "host", "agent", "ts", "action"}
            for ref in refs:
                if ref not in valid_keys:
                    findings.append(LintFinding(
                        "cel-unknown-key", LintSeverity.WARNING,
                        f"{where}.when",
                        f"`when` references `event.{ref}` which is not a known "
                        f"event key (known: {sorted(valid_keys)})",
                    ))
    # rate_limit schema
    rl = rule.get("rate_limit")
    if rl is not None:
        if not isinstance(rl, dict):
            findings.append(LintFinding(
                "bad-rate-limit", LintSeverity.ERROR, f"{where}.rate_limit",
                "`rate_limit` must be a mapping",
            ))
        else:
            ok_a = {"capacity", "refill_per_sec"}.issubset(rl.keys())
            ok_b = {"requests", "per"}.issubset(rl.keys())
            if not (ok_a or ok_b):
                findings.append(LintFinding(
                    "bad-rate-limit-keys", LintSeverity.ERROR,
                    f"{where}.rate_limit",
                    "`rate_limit` needs `{capacity, refill_per_sec}` "
                    "or `{requests, per}`",
                ))


def _check_overlap_and_shadow(rules: list[dict], findings: list[LintFinding]) -> None:
    """A rule that strictly subsumes an earlier one with the same action
    shadows it — usually accidental."""
    for i, later in enumerate(rules):
        for j, earlier in enumerate(rules):
            if j >= i:
                continue
            if later.get("action") != earlier.get("action"):
                continue
            if _subsumes(_match_keys(later), _match_keys(earlier)):
                findings.append(LintFinding(
                    "shadowed-rule", LintSeverity.WARNING,
                    f"rules[{i}]",
                    f"rule #{i} shadows rule #{j} "
                    f"(same action, more specific matcher) — consider removing #{j}",
                ))


def _match_keys(rule: dict) -> dict:
    return rule.get("match") if isinstance(rule.get("match"), dict) else {}


def _subsumes(a: dict, b: dict) -> bool:
    """True if every key in b is also in a with the same value (a is more specific)."""
    return all(a.get(k) == v for k, v in b.items())


def _check_catchall_dead_rules(rules: list[dict], findings: list[LintFinding]) -> None:
    """If a rule matches every tool, all subsequent rules with stricter matchers
    still win because of deny-first ordering — but earlier allow rules are
    now unreachable. Flag it."""
    for i, rule in enumerate(rules):
        match = _match_keys(rule)
        if match.get("tool") == "*" and rule.get("action") == "allow":
            findings.append(LintFinding(
                "catchall-allow", LintSeverity.WARNING, f"rules[{i}]",
                f"rule #{i} allows every tool — earlier allow rules are "
                "unreachable",
            ))


def _check_network(net: dict, findings: list[LintFinding]) -> None:
    if not net:
        return
    unknown = set(net.keys()) - KNOWN_NETWORK_KEYS
    for k in sorted(unknown):
        findings.append(LintFinding(
            "unknown-network-key", LintSeverity.WARNING, f"network.{k}",
            f"unknown network key {k!r} (known: {sorted(KNOWN_NETWORK_KEYS)})",
        ))
    if net.get("require_https") and not net.get("allowed_domains"):
        findings.append(LintFinding(
            "https-no-allowlist", LintSeverity.INFO, "network",
            "`require_https: true` set but `allowed_domains` empty — "
            "every request will be denied",
        ))
    allowed = set(net.get("allowed_domains") or [])
    blocked = set(net.get("blocked_domains") or [])
    overlap = allowed & blocked
    for d in sorted(overlap):
        findings.append(LintFinding(
            "network-domain-contradiction", LintSeverity.ERROR,
            f"network.{d}",
            f"domain {d!r} is in both allowed_domains and blocked_domains",
        ))


def format_report(findings: list[LintFinding]) -> str:
    if not findings:
        return "✓ No issues found."
    by_sev = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        by_sev[f.severity.value] += 1
    out = [f"  {by_sev['error']} errors, {by_sev['warning']} warnings, "
           f"{by_sev['info']} info\n"]
    for f in findings:
        sev = f.severity.value.upper().ljust(7)
        out.append(f"  {sev}  {f.where:30}  {f.message}  ({f.rule})")
    return "\n".join(out)
