"""Tests for network egress filter."""
import pytest

from agentgate.network import evaluate_network


@pytest.fixture
def cfg():
    return {
        "allowed_domains": ["github.com", "*.pypi.org", "*.openai.com"],
        "denied_domains": ["pastebin.com", "*.transfer.sh"],
        "require_https": True,
    }


def test_allow_exact(cfg):
    d = evaluate_network("https://github.com/foo", cfg)
    assert d.action == "allow"
    assert d.matched_rule == "allowed:github.com"


def test_allow_wildcard(cfg):
    d = evaluate_network("https://api.pypi.org/abc", cfg)
    assert d.action == "allow"


def test_allow_nested_wildcard(cfg):
    d = evaluate_network("https://api.openai.com/v1", cfg)
    assert d.action == "allow"


def test_deny_exact(cfg):
    d = evaluate_network("https://pastebin.com/raw/x", cfg)
    assert d.action == "deny"
    assert "pastebin.com" in d.matched_rule


def test_deny_not_in_allowlist(cfg):
    d = evaluate_network("https://evil.com/x", cfg)
    assert d.action == "deny"
    assert d.matched_rule == "not_allowed"


def test_deny_http_when_https_required(cfg):
    d = evaluate_network("http://github.com/foo", cfg)
    assert d.action == "deny"
    assert d.matched_rule == "https_required"


def test_https_allowed_with_required(cfg):
    d = evaluate_network("https://github.com/foo", cfg)
    assert d.action == "allow"


def test_deny_takes_precedence_over_allow():
    """If a host appears in both lists, deny wins."""
    cfg = {
        "allowed_domains": ["*.example.com"],
        "denied_domains": ["evil.example.com"],
        "require_https": False,
    }
    d = evaluate_network("https://evil.example.com/x", cfg)
    assert d.action == "deny"
    assert "evil.example.com" in d.matched_rule


def test_no_allowed_list_uses_default_action():
    """When no allowed_domains is defined, default action applies."""
    cfg = {"require_https": False, "denied_domains": []}
    d = evaluate_network("https://anything.com/", cfg, default="ask")
    assert d.action == "ask"


def test_allowed_list_takes_precedence_over_default():
    """If allowed_domains is defined, hosts not in it are denied (default ignored)."""
    cfg = {"allowed_domains": ["github.com"]}
    d = evaluate_network("https://other.com/", cfg, default="ask")
    assert d.action == "deny"


def test_require_https_does_not_block_naked_host():
    """No scheme → assume https and defer to allowlist."""
    cfg = {"allowed_domains": ["github.com"], "require_https": True}
    d = evaluate_network("github.com/foo", cfg)
    assert d.action == "allow"


def test_invalid_url_denied(cfg):
    d = evaluate_network("", cfg)
    assert d.action == "deny"
    assert d.matched_rule == "invalid_url"


def test_custom_default_action():
    """Default action applies when no allowed_domains is defined."""
    cfg = {}  # no allowed_domains
    d = evaluate_network("https://other.com/", cfg, default="ask")
    assert d.action == "ask"