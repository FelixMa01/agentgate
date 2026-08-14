"""Network egress filter — pure-Python URL matcher.

Evaluates an outbound URL against policy.network:
  - allowed_domains: list of glob patterns (e.g. "*.pypi.org") that are OK
  - denied_domains: list of glob patterns that are always blocked
  - require_https: if True, http:// (non-TLS) is denied

Returns one of ("allow", "deny", "ask") plus a reason.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class NetDecision:
    action: str  # "allow" | "deny" | "ask"
    reason: str
    matched_rule: str | None = (
        None  # "allowed:github.com" / "denied:pastebin.com" / "https_required"
    )


def _extract_host(url: str) -> str | None:
    """Pull the hostname out of a URL or naked host string."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.scheme and parsed.netloc:
        return parsed.hostname  # lowercased, no port
    if parsed.scheme in ("", None) and parsed.path:
        # Naked host possibly with path: take the first segment as host.
        first = parsed.path.split("/", 1)[0]
        if first and "." in first:
            return first.lower()
    return None


def _glob_match(host: str, pattern: str) -> bool:
    """Match a hostname against a glob pattern (e.g. '*.github.com').

    Globs are anchored: '*.example.com' matches 'a.example.com' but NOT 'example.com'.
    """
    pattern = pattern.lower()
    host = host.lower()
    regex = fnmatch.translate(pattern)
    return re.fullmatch(regex, host) is not None


def evaluate_network(url: str, network_cfg: dict, default: str = "allow") -> NetDecision:
    host = _extract_host(url)
    if not host:
        return NetDecision(
            "deny", f"could not parse host from URL: {url!r}", matched_rule="invalid_url"
        )

    scheme = urlparse(url).scheme.lower() if "://" in url else "https"
    has_explicit_scheme = "://" in url

    # 1. require_https check (only applies when URL has explicit scheme)
    if network_cfg.get("require_https") and has_explicit_scheme and scheme not in ("https", ""):
        return NetDecision("deny", f"non-HTTPS URL denied: {url!r}", matched_rule="https_required")

    # 2. explicit deny first (deny takes precedence)
    for pattern in network_cfg.get("denied_domains", []):
        if _glob_match(host, pattern):
            return NetDecision(
                "deny",
                f"host {host} matches denied pattern {pattern!r}",
                matched_rule=f"denied:{pattern}",
            )

    # 3. allowed list (if defined, only those are allowed)
    allowed = network_cfg.get("allowed_domains")
    if allowed:
        for pattern in allowed:
            if _glob_match(host, pattern):
                return NetDecision(
                    "allow",
                    f"host {host} allowed by {pattern!r}",
                    matched_rule=f"allowed:{pattern}",
                )
        return NetDecision(
            "deny", f"host {host} not in allowed_domains", matched_rule="not_allowed"
        )

    return NetDecision(
        default, f"host {host} (no deny match, no allow list)", matched_rule="default"
    )
