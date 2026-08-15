"""Static scanner for AI coding-agent configurations.

Scans the user's Claude Code / Cursor / Continue / Aider / Gemini /
Codex / MCP configurations for high-risk patterns and reports findings
with severity + remediation hints. Inspired by affaan-m/agentshield.

Usage:
    from agentgate.scanner import Scanner, Finding

    s = Scanner()
    findings = s.scan_path(Path.home() / ".claude")
    for f in findings:
        print(f.severity, f.path, f.message)

Or via CLI: ``agentgate scan [--report graded|json] [--min-severity critical|high|...]``
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    path: Path
    line: int | None
    message: str
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "path": str(self.path),
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "fix": self.fix,
        }


@dataclass
class Rule:
    id: str
    severity: Severity
    description: str
    # file_glob is matched against the relative path with fnmatch
    file_glob: str
    pattern: re.Pattern
    message: str
    fix: str = ""

    def test(self, content: str, path: Path) -> Iterable[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self.pattern.search(line):
                evidence = line.strip()[:120]
                yield Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    path=path,
                    line=lineno,
                    message=self.message,
                    evidence=evidence,
                    fix=self.fix,
                )


# -------------------------------------------------------------------- rules
# Pattern categories loosely follow agentshield's buckets: Secrets,
# Permissions, Hooks, MCP Servers, Network. Each rule carries a stable
# id so users can suppress or pin findings.

SECRET_PATTERNS: list[tuple[str, Severity, str, str]] = [
    ("sc-anthropic", Severity.CRITICAL, r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API key", "Use $ANTHROPIC_API_KEY"),
    ("sc-openai",    Severity.CRITICAL, r"sk-(?:proj-|svcacct-)?[a-zA-Z0-9\-_]{20,}", "OpenAI API key", "Use $OPENAI_API_KEY"),
    ("sc-openrouter",Severity.CRITICAL, r"sk-or-v1-[A-Fa-f0-9]{20,}", "OpenRouter API key", "Use $OPENROUTER_API_KEY"),
    ("sc-github-pat",Severity.CRITICAL, r"ghp_[A-Za-z0-9]{30,}", "GitHub PAT", "Use $GITHUB_TOKEN"),
    ("sc-github-fine",Severity.CRITICAL,r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT", "Use $GITHUB_TOKEN"),
    ("sc-aws-id",    Severity.CRITICAL, r"AKIA[0-9A-Z]{16}", "AWS access key ID", "Use IAM role or env var"),
    ("sc-google",    Severity.CRITICAL, r"AIza[0-9A-Za-z\-_]{35}", "Google API key", "Use $GOOGLE_API_KEY"),
    ("sc-stripe",    Severity.CRITICAL, r"sk_(?:test|live)_[A-Za-z0-9]{24,}", "Stripe key", "Use $STRIPE_KEY"),
    ("sc-slack",     Severity.HIGH,     r"xox[bprs]-[A-Za-z0-9\-]{10,}", "Slack token", "Use $SLACK_TOKEN"),
    ("sc-jwt",       Severity.HIGH,     r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT", "Use short-lived token + refresh"),
    ("sc-pg-conn",   Severity.CRITICAL, r"postgres(?:ql)?://[^:]+:[^@]+@\S+", "Postgres connection string with creds", "Use $DATABASE_URL"),
    ("sc-private-key",Severity.CRITICAL,r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) (?:PRIVATE )?KEY-----", "Private key in config", "Move to ~/.ssh with 600 perms"),
]


PERMISSION_PATTERNS: list[tuple[str, Severity, str, str, str]] = [
    ("perm-bash-star",  Severity.CRITICAL, "*", r'["\']?Bash\(\*\)["\']?',
     "Unrestricted Bash permission allows arbitrary commands",
     "Replace with Bash(git *), Bash(npm test), etc."),
    ("perm-write-star", Severity.HIGH,     "*", r'["\']?Write\(\*\)["\']?',
     "Unrestricted Write permission", "Scope to a directory glob"),
    ("perm-edit-star",  Severity.HIGH,     "*", r'["\']?Edit\(\*\)["\']?',
     "Unrestricted Edit permission", "Scope to a directory glob"),
    ("perm-skip",       Severity.CRITICAL, "*", r"--dangerously-skip-permissions",
     "Bypasses ALL permission checks", "Remove the flag"),
    ("perm-rm-rf",      Severity.HIGH,     "*", r"\brm\s+-[rf]+[rf]*\s+/",
     "Destructive rm on absolute path",
     "Scope rm to project dir; pair with allowlist"),
    ("perm-chmod-777",  Severity.HIGH,     "*", r"chmod\s+777\b",
     "World-writable permissions", "Use 755 / 644"),
    ("perm-git-force",  Severity.HIGH,     "*", r"git\s+push\s+--force",
     "Destructive git push", "Require review for force pushes"),
    ("perm-curl-wild",  Severity.MEDIUM,   "*", r'["\']?(?:curl|wget)\*["\']?',
     "Unrestricted network tool", "Scope curl to known hosts"),
]


HOOK_PATTERNS: list[tuple[str, Severity, str, str, str]] = [
    ("hk-shell-interp",Severity.CRITICAL, "*", r'(?:\$\(|`)[^`\n]*(?:\$file|\$input|\$\{file\}|\$\{input\})',
     "Command injection via unquoted variable in hook",
     "Quote variables and validate input"),
    ("hk-exfil",       Severity.CRITICAL, "*",
     r'(?:curl|wget)\s+[^\n]*-X\s+POST[^\n]*(?:\$\(|`)',
     "Hook exfiltrates data via HTTP POST",
     "Remove outbound HTTP from hooks"),
    ("hk-silent-err",  Severity.MEDIUM,   "*", r"2>/dev/null\s*\|\|\s*true",
     "Hook silently swallows errors", "Log failures to stderr"),
    ("hk-reverse-sh",  Severity.CRITICAL, "*", r"/dev/tcp/|\b(?:nc|ncat)\s+-e\b|mkfifo\b",
     "Reverse shell pattern in hook", "Remove immediately"),
    ("hk-pkg-install", Severity.HIGH,     "*",
     r"(?:npm install -g|pip install --break-system|gem install|cargo install)\b",
     "Hook installs system packages", "Pre-pin packages in project config"),
    ("hk-rm-logs",     Severity.HIGH,     "*",
     r"(?:rm|truncate)\s+(?:/var/log|~\/\.bash_history)",
     "Anti-forensics: log/history tampering", "Remove log-clearing hooks"),
    ("hk-clipboard",   Severity.MEDIUM,   "*", r"\b(?:pbcopy|xclip|xsel|wl-copy)\b",
     "Hook accesses clipboard", "Confirm intent with user"),
    ("hk-priv-mount",  Severity.CRITICAL, "*",
     r"--privileged|--pid=host|--network=host|:\/host",
     "Hook escalates container privileges", "Remove privileged flags"),
]


MCP_PATTERNS: list[tuple[str, Severity, str, str, str]] = [
    ("mcp-shell",     Severity.CRITICAL, "*", r'"command"\s*:\s*"(?:bash|sh|zsh|/bin/sh)"',
     "MCP server runs a raw shell", "Use a typed MCP server instead"),
    ("mcp-curl",      Severity.HIGH,     "*", r'"command"\s*:\s*"(?:curl|wget)"',
     "MCP server runs curl (exfil risk)", "Confirm the package source"),
    ("mcp-pip-remote",Severity.HIGH,     "*",
     r'"args"\s*:\s*\[[^\]]*"(?:pip|npm|pnpx|uvx)"[^\]]*"--(?:break-system|trusted)"',
     "MCP server installs from remote with weakened safety",
     "Pin the package; drop --break-system"),
]


# Aggregated rule registry ----------------------------------------------------
def _compile(pairs):
    """Compile rule tuples. Accepts either 5-tuple (id, sev, pattern, msg, fix)
    or 6-tuple (id, sev, glob, pattern, msg, fix)."""
    out = []
    for tup in pairs:
        if len(tup) == 6:
            rid, sev, glob, pat, msg, fix = tup
        elif len(tup) == 5:
            rid, sev, pat, msg, fix = tup
            glob = "*"
        else:
            raise ValueError(f"unexpected pattern tuple length: {len(tup)}")
        out.append(Rule(rid, sev, rid, glob, re.compile(pat), msg, fix))
    return out


_RULES = (
    _compile(SECRET_PATTERNS)
    + _compile(PERMISSION_PATTERNS)
    + _compile(HOOK_PATTERNS)
    + _compile(MCP_PATTERNS)
)


class Scanner:
    """Scan paths for security-relevant config patterns."""

    SKIP_DIRS: frozenset[str] = frozenset({"node_modules", "__pycache__", ".git", "dist", "build", ".venv", "venv"})

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else _RULES

    def scan_path(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not root.exists():
            return findings
        for path in self._iter_files(root):
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeError):
                continue
            for rule in self.rules:
                findings.extend(rule.test(content, path))
        return findings

    def _iter_files(self, root: Path) -> Iterable[Path]:
        if root.is_file():
            yield root
            return
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if any(part in self.SKIP_DIRS for part in rel.parts):
                continue
            # Only scan plausible config-ish files.
            if p.suffix not in {".json", ".yaml", ".yml", ".toml", ".md", ".sh", ""} and not p.name.startswith("."):
                continue
            yield p


# Reporting ------------------------------------------------------------------
def grade(findings: list[Finding]) -> tuple[str, int]:
    """Return (letter, 0-100) using a simple weighted sum."""
    weights = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}
    score = max(0, 100 - sum(weights.get(f.severity, 0) for f in findings))
    if score >= 90:
        return ("A", score)
    if score >= 75:
        return ("B", score)
    if score >= 60:
        return ("C", score)
    if score >= 40:
        return ("D", score)
    return ("F", score)


def report_text(findings: list[Finding]) -> str:
    grade_letter, score = grade(findings)
    lines = ["AgentGate Scan Report", f"Grade: {grade_letter} ({score}/100)", ""]
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    for s in Severity:
        lines.append(f"  {s.value:<8} {counts[s]}")
    lines.append("")
    by_sev = {s: [] for s in Severity}
    for f in findings:
        by_sev[f.severity].append(f)
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        for f in by_sev[sev]:
            tag = f"[{sev.value.upper():<8}] {f.rule_id}"
            lines.append(f"  {tag}  {f.path.name}:{f.line}")
            lines.append(f"      {f.message}")
            if f.evidence:
                lines.append(f"      Evidence: {f.evidence[:100]}")
            if f.fix:
                lines.append(f"      Fix:      {f.fix}")
    return "\n".join(lines) + "\n"


def report_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
