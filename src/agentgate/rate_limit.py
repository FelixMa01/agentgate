"""Per-rule rate limiting (token-bucket).

Each rule can declare a `rate_limit` field in policy.yaml:

    rules:
      - id: ask-deploy
        match: {tool: Bash, command_glob: "kubectl apply*"}
        action: ask
        reason: "deploys need human approval"
        rate_limit:
          capacity: 5        # bucket size (burst budget)
          refill_per_sec: 0.1  # refill rate (long-run budget)

When the bucket is empty, the rule falls through to the next matching
rule (or the default action), so rate limiting is "fail-open within
the budget" rather than hard-deny. This keeps a misconfigured budget
from bricking the agent.

Rate-limiter state is in-memory per process — sufficient for a single
agent's lifetime. Restart = reset budget.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitConfig:
    """Token-bucket config parsed from a rule's `rate_limit:` YAML field."""

    capacity: float = 1.0
    refill_per_sec: float = 1.0

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> RateLimitConfig | None:
        if not d:
            return None
        try:
            capacity = float(d.get("capacity", 1.0))
            refill = float(d.get("refill_per_sec", 1.0))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"invalid rate_limit config {d!r}: {exc}"
            ) from exc
        if capacity <= 0 or refill < 0:
            raise ValueError(
                f"invalid rate_limit config {d!r}: "
                f"capacity must be > 0 and refill_per_sec >= 0"
            )
        return cls(capacity=capacity, refill_per_sec=refill)


class TokenBucket:
    """Thread-safe token bucket. One per (rule_id)."""

    def __init__(self, cfg: RateLimitConfig) -> None:
        self.cfg = cfg
        self._tokens: float = cfg.capacity
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: float = 1.0) -> bool:
        """Try to take `n` tokens. Returns True if allowed, False if starved."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            if elapsed > 0 and self.cfg.refill_per_sec > 0:
                self._tokens = min(
                    self.cfg.capacity,
                    self._tokens + elapsed * self.cfg.refill_per_sec,
                )
                self._last_refill = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    @property
    def tokens(self) -> float:
        """Current token count (for /metrics or debug)."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            if elapsed > 0 and self.cfg.refill_per_sec > 0:
                return min(
                    self.cfg.capacity,
                    self._tokens + elapsed * self.cfg.refill_per_sec,
                )
            return self._tokens


class RateLimiter:
    """Registry of per-rule buckets. Keyed by rule id."""

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check(self, rule_id: str, cfg: RateLimitConfig | None) -> bool:
        """Return True if the call is allowed by the rule's bucket.

        No `cfg` (= no rate_limit on the rule) → always allow.
        Empty bucket → False (caller should fall through to next rule).
        """
        if cfg is None:
            return True
        with self._lock:
            bucket = self._buckets.get(rule_id)
            if bucket is None or bucket.cfg != cfg:
                bucket = TokenBucket(cfg)
                self._buckets[rule_id] = bucket
        return bucket.consume()

    def metrics(self) -> dict[str, float]:
        """Snapshot of current token counts (for /metrics or debug)."""
        with self._lock:
            return {rid: b.tokens for rid, b in self._buckets.items()}

    def reset(self) -> None:
        """Drop all buckets (used by hot-reload to avoid stale state)."""
        with self._lock:
            self._buckets.clear()
