"""DLP-style body/header scanner for agent egress.

Inspects request bodies, URLs, and headers for known secret patterns
(provider API keys, connection strings, JWTs, etc.) plus prompt
injection markers. Inspired by luckyPipewrench/pipelock's DLP patterns.

Usage:
    from agentgate.dlp import DlpScanner, ScanResult

    scanner = DlpScanner()
    findings = scanner.scan_body(b"sk-ant-abc123...")
    if findings:
        for f in findings:
            print(f.severity, f.pattern_name)
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum


class DlpSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ScanResult:
    pattern_name: str
    severity: DlpSeverity
    evidence: str  # redacted excerpt, e.g. "sk-ant-***"
    location: str  # "url" | "body" | "header:Authorization"

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "location": self.location,
        }


# Each pattern: (name, severity, regex, exempt_hosts_or_None)
PATTERNS: list[tuple[str, DlpSeverity, str, tuple[str, ...] | None]] = [
    # --- API keys (provider) ---
    ("Anthropic API Key", DlpSeverity.CRITICAL, r"sk-ant-[a-zA-Z0-9\-_]{20,}", ("*.anthropic.com",)),
    ("OpenAI API Key", DlpSeverity.CRITICAL, r"sk-(?:proj-|svcacct-)?[a-zA-Z0-9\-_]{20,}", ("*.openai.com",)),
    ("OpenRouter API Key", DlpSeverity.CRITICAL, r"sk-or-v1-[A-Fa-f0-9]{20,}", ("*.openrouter.ai",)),
    ("Fireworks API Key", DlpSeverity.CRITICAL, r"fw_[A-Za-z0-9]{22}\b", ("*.fireworks.ai",)),
    ("xAI API Key", DlpSeverity.CRITICAL, r"xai-[A-Za-z0-9]{20,}", ("*.x.ai",)),
    ("Google API Key", DlpSeverity.CRITICAL, r"AIza[0-9A-Za-z\-_]{35}", ("*.googleapis.com",)),
    ("Mistral API Key", DlpSeverity.CRITICAL, r"[a-zA-Z0-9]{32}(?=\.[a-z0-9-]+\.mistral\.ai)", ("*.mistral.ai",)),
    ("DeepSeek API Key", DlpSeverity.CRITICAL, r"sk-[a-f0-9]{32}", ("*.deepseek.com",)),
    ("Cohere API Key", DlpSeverity.CRITICAL, r"[A-Za-z0-9]{40}(?=\.cohere\.com)", ("*.cohere.com",)),
    ("Together AI Key", DlpSeverity.CRITICAL, r"[a-f0-9]{64}(?=together)", ("*.together.ai",)),
    ("Groq API Key", DlpSeverity.CRITICAL, r"gsk_[A-Za-z0-9]{20,}", ("*.groq.com",)),
    ("Perplexity API Key", DlpSeverity.CRITICAL, r"pplx-[A-Za-z0-9]{20,}", ("*.perplexity.ai",)),
    ("Hugging Face Token", DlpSeverity.CRITICAL, r"hf_[A-Za-z0-9]{20,}", ("*.huggingface.co",)),

    # --- VCS / SaaS ---
    ("GitHub PAT", DlpSeverity.CRITICAL, r"ghp_[A-Za-z0-9]{30,}", ("*.github.com",)),
    ("GitHub Fine-Grained PAT", DlpSeverity.CRITICAL, r"github_pat_[A-Za-z0-9_]{20,}", ("*.github.com",)),
    ("GitLab PAT", DlpSeverity.CRITICAL, r"glpat-[A-Za-z0-9_\-]{20,}", ("*.gitlab.com",)),
    ("Linear API Key", DlpSeverity.CRITICAL, r"lin_api_[A-Za-z0-9]{40}", ("*.linear.app",)),
    ("Notion API Key", DlpSeverity.CRITICAL, r"secret_[A-Za-z0-9]{43}", ("*.notion.so",)),
    ("Slack Token", DlpSeverity.HIGH, r"xox[bprs]-[A-Za-z0-9\-]{10,}", ("*.slack.com",)),
    ("Discord Bot Token", DlpSeverity.HIGH, r"[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}", ("*.discord.com",)),
    ("Stripe Key", DlpSeverity.CRITICAL, r"sk_(?:test|live)_[A-Za-z0-9]{24,}", ("*.stripe.com",)),
    ("Supabase Service Key", DlpSeverity.CRITICAL, r"sb_secret_[A-Za-z0-9_\-]{30,}", ("*.supabase.co",)),

    # --- Cloud ---
    ("AWS Access Key ID", DlpSeverity.CRITICAL, r"AKIA[0-9A-Z]{16}", ("*.amazonaws.com",)),
    ("AWS Secret Key", DlpSeverity.CRITICAL, r"(?i)aws(.{0,20})?(secret|sk)[^a-z0-9][a-z0-9/+]{40}", ("*.amazonaws.com",)),
    ("Azure SAS Token", DlpSeverity.CRITICAL, r"sig=[A-Za-z0-9%]{43,}", ("*.blob.core.windows.net",)),
    ("GCP Service Account", DlpSeverity.CRITICAL, r'"type"\s*:\s*"service_account"', ("*.googleapis.com",)),

    # --- DB connection strings ---
    ("Postgres Connection String", DlpSeverity.CRITICAL,
     r"postgres(?:ql)?://[^\s:]+:[^@\s]+@[^\s/]+", None),
    ("MySQL Connection String", DlpSeverity.CRITICAL,
     r"mysql://[^\s:]+:[^@\s]+@[^\s/]+", None),
    ("MongoDB Connection String", DlpSeverity.CRITICAL,
     r"mongodb(?:\+srv)?://[^\s:]+:[^@\s]+@[^\s/]+", None),
    ("Redis Connection String", DlpSeverity.CRITICAL,
     r"redis://[^\s:]*:[^@\s]+@[^\s/]+", None),

    # --- Auth tokens ---
    ("JWT Token", DlpSeverity.HIGH,
     r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", None),
    ("Bearer Token", DlpSeverity.MEDIUM,
     r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}", None),

    # --- Crypto wallet ---
    ("Ethereum Address", DlpSeverity.MEDIUM, r"0x[a-fA-F0-9]{40}\b", None),
    ("Bitcoin WIF", DlpSeverity.HIGH, r"[5KL][1-9A-HJ-NP-Za-km-z]{51}", None),

    # --- Private key headers ---
    ("Private Key Header", DlpSeverity.CRITICAL,
     r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE|PGP) (?:PRIVATE )?KEY-----", None),

    # --- Prompt injection markers ---
    ("Prompt Injection", DlpSeverity.CRITICAL,
     r"(?i)ignore (?:all )?previous instructions", None),
    ("System Override", DlpSeverity.CRITICAL,
     r"(?i)system\s*:\s*you are now", None),
    ("Role Override", DlpSeverity.CRITICAL,
     r"(?i)act as (?:a )?(?:dan|jailbroken|unrestricted)", None),
    ("New Instructions", DlpSeverity.HIGH,
     r"(?i)new instructions:\s", None),
    ("Jailbreak Attempt", DlpSeverity.HIGH,
     r"(?i)developer mode|do anything now|DAN\b", None),
    ("Tool Invocation Injection", DlpSeverity.HIGH,
     r"(?i)<function_calls>|<invoke\s+", None),
    ("Authority Escalation", DlpSeverity.HIGH,
     r"(?i)you (?:must|have to) (?:comply|obey)", None),
    ("System Prompt Extraction", DlpSeverity.HIGH,
     r"(?i)(?:repeat|reveal|print) your (?:system )?prompt", None),
    ("Hidden Instruction", DlpSeverity.MEDIUM,
     r"<!--\s*(?:ignore|system|prompt)", None),
    ("Pliny Divider", DlpSeverity.LOW,
     r"-{10,}\s*(?:prompt|system)", None),

    # --- Destructive commands embedded in bodies (agent-gone-rogue) ---
    ("Destructive File Delete", DlpSeverity.CRITICAL,
     r"\brm\s+-[rf]+[rf]*\s+/", None),
    ("Destructive Git Operation", DlpSeverity.HIGH,
     r"git\s+push\s+--force", None),
    ("Reverse Shell", DlpSeverity.CRITICAL,
     r"/dev/tcp/|\b(?:nc|ncat)\s+-e\b|mkfifo\s+/tmp/", None),
    ("Disk Wipe Command", DlpSeverity.CRITICAL,
     r"\bdd\s+if=.+of=/dev/(?:sd|nvme|hd)", None),
]


COMPILED = [
    (name, sev, re.compile(pat), exempt)
    for (name, sev, pat, exempt) in PATTERNS
]


def _redact(match: re.Match) -> str:
    """Show first 4 chars + *** + last 2 chars so the key is recognizable but not copy-pastable."""
    s = match.group(0)
    if len(s) <= 8:
        return s[:2] + "***"
    return s[:4] + "***" + s[-2:]


def _exempt(url: str | None, hosts: tuple[str, ...] | None) -> bool:
    if not url or not hosts:
        return False
    from fnmatch import fnmatch
    return any(fnmatch(url, h) for h in hosts)


class DlpScanner:
    """Scans URLs, headers, and bodies for secrets and prompt-injection markers."""

    def __init__(self, patterns=None):
        self.patterns = patterns if patterns is not None else COMPILED

    def scan_url(self, url: str) -> list[ScanResult]:
        out: list[ScanResult] = []
        for name, sev, regex, exempt in self.patterns:
            if exempt and _exempt(url, exempt):
                continue
            for m in regex.finditer(url):
                out.append(ScanResult(name, sev, _redact(m), "url"))
        return out

    def scan_body(self, body: bytes | str, url: str | None = None) -> list[ScanResult]:
        text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray)) else body
        out: list[ScanResult] = []
        for name, sev, regex, exempt in self.patterns:
            if exempt and _exempt(url, exempt):
                continue
            for m in regex.finditer(text):
                out.append(ScanResult(name, sev, _redact(m), "body"))
        return out

    def scan_headers(self, headers: dict[str, str], url: str | None = None) -> list[ScanResult]:
        out: list[ScanResult] = []
        for k, v in headers.items():
            text = f"{k}: {v}"
            for name, sev, regex, exempt in self.patterns:
                if exempt and _exempt(url, exempt):
                    continue
                for m in regex.finditer(text):
                    out.append(ScanResult(name, sev, _redact(m), f"header:{k}"))
        return out

    def scan(self, *, url: str | None = None, body: bytes | str | None = None,
             headers: dict[str, str] | None = None) -> list[ScanResult]:
        findings: list[ScanResult] = []
        if url:
            findings.extend(self.scan_url(url))
        if body is not None:
            findings.extend(self.scan_body(body, url))
        if headers:
            findings.extend(self.scan_headers(headers, url))
        # Dedup identical findings.
        seen = Counter()
        unique = []
        for f in findings:
            key = (f.pattern_name, f.location, f.evidence)
            if seen[key]:
                continue
            seen[key] = 1
            unique.append(f)
        return unique


# Shannon entropy for the "leaked base64/hex blob" path ---------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def looks_like_high_entropy_blob(s: str, threshold: float = 4.5) -> bool:
    """True if string looks like a random base64/hex blob (entropy > threshold bits/char).

    English text sits ~3.5-4.0; random bytes are >5.5. A threshold of 4.5
    catches base64 secrets with some false positives.
    """
    return len(s) >= 32 and shannon_entropy(s) >= threshold
