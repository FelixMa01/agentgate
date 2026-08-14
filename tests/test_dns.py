"""Tests for the DNS sinkhole — no actual network calls needed."""

import socket
import struct
import threading
import time

import pytest

from agentgate.dns_sinkhole import (
    DnsSinkhole,
    _build_a_response,
    _build_nxdomain,
    _build_sinkhole_response,
    _decode_query_name,
    _encode_query_name,
)


def _make_query(name: str = "example.com", txn_id: bytes = b"\xab\xcd") -> bytes:
    """Build a minimal DNS A query."""
    flags = struct.pack(">H", 0x0100)  # standard query, recursion desired
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = _encode_query_name(name) + struct.pack(">HH", 1, 1)
    return txn_id + flags + counts + question


def test_qname_roundtrip():
    encoded = _encode_query_name("api.github.com")
    decoded, _ = _decode_query_name(encoded, 0)
    assert decoded == "api.github.com"


def test_qname_roundtrip_with_trailing_dot():
    encoded = _encode_query_name("example.com.")
    decoded, _ = _decode_query_name(encoded, 0)
    assert decoded == "example.com"


def test_a_response_has_correct_ip():
    query = _make_query("evil.example.com")
    response = _build_sinkhole_response(query, "evil.example.com")
    # Last 4 bytes = rdata (0.0.0.0)
    assert response[-4:] == b"\x00\x00\x00\x00"
    # Transaction ID preserved
    assert response[:2] == b"\xab\xcd"


def test_nxdomain_response():
    query = _make_query()
    response = _build_nxdomain(query, "evil.com")
    # RCODE bits in flags: 0x8183 = response + NXDOMAIN
    assert response[2:4] == b"\x81\x83"


def test_sinkhole_blocks_denied_domain(tmp_path):
    """End-to-end: spin up the UDP server, send a query for a denied domain."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""
version: 1
default: allow
rules: []
network:
  denied_domains:
    - "*.evil.test"
""")
    from agentgate.policy import load_policy

    policy = load_policy(str(policy_path))

    # Find a free port.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = DnsSinkhole(
        policy, host="127.0.0.1", port=port, upstream=("127.0.0.1", 1)
    )  # upstream unused for denied
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        client.sendto(_make_query("api.evil.test"), ("127.0.0.1", port))
        response, _ = client.recvfrom(4096)
        # Sinkhole: returns A record with 0.0.0.0
        assert response[-4:] == b"\x00\x00\x00\x00"
    finally:
        # Daemon thread will die with the test
        pass


def test_sinkhole_allows_allowed_domain(tmp_path):
    """Allowed domain should not be sinkholed — but since upstream is bogus,
    the upstream lookup will fail and we should return NXDOMAIN (not 0.0.0.0)."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""
version: 1
default: allow
rules: []
network:
  allowed_domains:
    - github.com
""")
    from agentgate.policy import load_policy

    policy = load_policy(str(policy_path))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = DnsSinkhole(policy, host="127.0.0.1", port=port, upstream=("127.0.0.1", 1))
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        client.sendto(_make_query("github.com"), ("127.0.0.1", port))
        response, _ = client.recvfrom(4096)
        # NXDOMAIN (RCODE=3): flags = 0x8183
        assert response[2:4] == b"\x81\x83"
        # Crucially: NOT 0.0.0.0 (which would mean sinkhole)
        assert response[-4:] != b"\x00\x00\x00\x00"
    finally:
        pass
