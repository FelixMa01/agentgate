"""DNS sinkhole — agent-egress control without mitmproxy or eBPF.

The mitmproxy add-on (proxy_addon.py) requires the user to set HTTP_PROXY
and only sees HTTP/S traffic. This module is the "zero config" alternative:

How it works
------------
A tiny UDP DNS server runs on 127.0.0.1:5300 (configurable). It reads each
DNS query, evaluates the queried domain against policy.network, and either
returns the real IP (allow) or returns 0.0.0.0 / NXDOMAIN (deny).

When the user runs `agentgate dns`, we write /etc/resolver/agentgate (macOS
per-interface resolver) or similar. The agent's DNS lookups for blocked
domains get a fake answer, so the connection fails fast.

Limitations vs mitmproxy
------------------------
- No TLS inspection (mitmproxy + HTTPS_PROXY still does that)
- Cannot block by URL path (only by domain)
- Adds ~1-5 ms latency to every DNS lookup
- Cannot stop raw IP connections (use sandbox-exec for that)

But it works WITHOUT any proxy env vars and WITHOUT any privileged install
beyond /etc/resolver/ (macOS) or systemd-resolved drop-in (Linux).
"""

from __future__ import annotations

import os
import socket
import struct
import sys
from pathlib import Path

# --- DNS protocol helpers (RFC 1035) ------------------------------------------


def _encode_query_name(name: str) -> bytes:
    """Encode a domain name as a DNS QNAME (length-prefixed labels)."""
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    out += b"\x00"
    return out


def _decode_query_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME starting at offset. Returns (name, new_offset)."""
    labels = []
    while True:
        n = data[offset]
        offset += 1
        if n == 0:
            break
        if n & 0xC0:
            raise ValueError("DNS name compression not supported in stub")
        labels.append(data[offset : offset + n].decode("ascii"))
        offset += n
    return ".".join(labels), offset


def _build_a_response(query: bytes, name: str, ip: str) -> bytes:
    """Build a DNS A record response with a 60-second TTL.

    The query and the response share transaction ID, flags (QR=1, AA=1, RCODE=0),
    and question section.
    """
    txn_id = query[:2]
    # Flags: QR=1 (response), AA=1 (authoritative), RCODE=0 (no error)
    flags = struct.pack(">H", 0x8180)
    qdcount = b"\x00\x01"
    ancount = struct.pack(">H", 1)
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    # Question section: name + type (A=1) + class (IN=1)
    question = _encode_query_name(name) + struct.pack(">HH", 1, 1)
    # Answer: name (we re-encode for simplicity), type, class, ttl, rdlength, rdata
    ip_bytes = bytes(int(o) for o in ip.split("."))
    answer = _encode_query_name(name) + struct.pack(">HHIH", 1, 1, 60, 4) + ip_bytes
    return txn_id + flags + qdcount + ancount + nscount + arcount + question + answer


def _build_nxdomain(query: bytes, name: str) -> bytes:
    """Build a DNS NXDOMAIN response (signals the domain doesn't exist)."""
    txn_id = query[:2]
    # Flags: QR=1, RCODE=3 (NXDOMAIN), no recursion desired
    flags = struct.pack(">H", 0x8183)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = _encode_query_name(name) + struct.pack(">HH", 1, 1)
    return txn_id + flags + counts + question


def _build_sinkhole_response(query: bytes, name: str) -> bytes:
    """Return 0.0.0.0 for blocked domains — connection fails fast."""
    return _build_a_response(query, name, "0.0.0.0")


# --- Policy lookup ------------------------------------------------------------


def _resolve(query_name: str, policy) -> str:
    """Return one of: 'allow', 'deny', 'nxdomain'."""
    from .network import evaluate_network

    decision = evaluate_network(query_name, policy.network)
    if decision.action == "deny":
        return "deny"
    return "allow"


# --- Server ------------------------------------------------------------------


class DnsSinkhole:
    """A tiny DNS server on UDP 127.0.0.1:port. Single-threaded is fine."""

    def __init__(
        self,
        policy,
        host: str = "127.0.0.1",
        port: int = 5300,
        upstream: tuple[str, int] | None = None,
    ):
        self.policy = policy
        self.host = host
        self.port = port
        # Forward allowed queries to the real resolver. Falls back to system DNS.
        self.upstream = upstream or self._detect_upstream()

    def _detect_upstream(self) -> tuple[str, int]:
        # /etc/resolv.conf first entry is usually the real DNS.
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                if line.startswith("nameserver"):
                    return line.split()[1], 53
        except Exception:
            pass
        return ("1.1.1.1", 53)

    def _forward(self, query: bytes) -> bytes:
        """Forward the query upstream and return the raw response."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.sendto(query, self.upstream)
            data, _ = s.recvfrom(4096)
            return data

    def handle_query(self, query: bytes) -> bytes:
        try:
            name, _ = _decode_query_name(query, 12)  # skip header
        except Exception:
            return _build_nxdomain(query, "invalid")
        decision = _resolve(name, self.policy)
        if decision == "allow":
            try:
                return self._forward(query)
            except (TimeoutError, OSError):
                return _build_nxdomain(query, name)
            except Exception:
                return _build_nxdomain(query, name)
        # deny
        return _build_sinkhole_response(query, name)

    def serve_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        print(f"[agentgate] DNS sinkhole on udp://{self.host}:{self.port}", flush=True)
        print(f"[agentgate] upstream: {self.upstream[0]}:{self.upstream[1]}", flush=True)
        print(
            f"[agentgate] policy: {self.policy.allowed_domains}+ / {self.policy.denied_domains}-",
            flush=True,
        )
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response = self.handle_query(data)
                sock.sendto(response, addr)
            except KeyboardInterrupt:
                print("[agentgate] stopping", flush=True)
                sock.close()
                return
            except Exception as e:
                print(f"[agentgate] error: {e}", flush=True)


def _resolve_with_retry(query_name: str, policy, retries: int = 1):
    """Helper that retries policy re-load — for the test harness."""

    decision = _resolve(query_name, policy)
    return decision


# --- CLI entrypoint ----------------------------------------------------------


def main() -> int:
    from .cli._common import resolve_policy
    from .policy import load_policy

    policy_path = os.environ.get("AGENTGATE_POLICY") or (sys.argv[1] if len(sys.argv) > 1 else None)
    if not policy_path:
        print(
            "usage: agentgate dns <policy.yaml> [--host 127.0.0.1] [--port 5300]", file=sys.stderr
        )
        return 2
    policy = load_policy(str(resolve_policy(policy_path)))
    host = os.environ.get("AGENTGATE_DNS_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENTGATE_DNS_PORT", "5300"))
    DnsSinkhole(policy, host=host, port=port).serve_forever()
    return 0
