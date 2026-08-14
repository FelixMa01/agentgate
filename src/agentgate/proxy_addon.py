"""mitmproxy add-on: intercepts HTTP(S) egress and evaluates against policy.network.

Run with:
  mitmdump -s src/agentgate/proxy_addon.py \
           --set agentgate_policy=./examples/policy.yaml \
           --set agentgate_db=./demo/audit.db

Then export HTTP_PROXY=http://127.0.0.1:8080 and HTTPS_PROXY=...
(or use --mode transparent:on with iptables — out of scope here).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running via `mitmdump -s` from outside the venv: ensure src/ on sys.path.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from agentgate.audit import Audit  # noqa: E402
from agentgate.network import evaluate_network  # noqa: E402
from agentgate.policy import Action, load_policy  # noqa: E402


class AgentGateAddon:
    def __init__(self) -> None:
        policy_path = os.environ.get("AGENTGATE_POLICY")
        db_path = os.environ.get("AGENTGATE_DB")
        if not policy_path or not db_path:
            raise RuntimeError("AGENTGATE_POLICY and AGENTGATE_DB env vars must be set")
        self.policy = load_policy(policy_path)
        self.audit = Audit(db_path)
        self._intercepted = 0

    # mitmproxy hook: every HTTP request before it's sent
    def request(self, flow):
        url = flow.request.pretty_url
        decision = evaluate_network(
            url, self.policy.network, default=self.policy.default_action.value
        )
        self.audit.record(
            source="network",
            agent="mitmproxy",
            action=Action(decision.action)
            if decision.action in ("allow", "deny", "ask", "log")
            else Action.DENY,
            event={
                "url": url,
                "method": flow.request.method,
                "host": flow.request.host,
                "matched": decision.matched_rule,
            },
            rule_id=decision.matched_rule,
            rule_name=f"Network {decision.action}",
            reason=decision.reason,
        )
        if decision.action in ("deny", "ask"):
            self._intercepted += 1
            from mitmproxy.http import Response

            msg = (f"AgentGate: {decision.action.upper()} — {decision.reason}\n").encode()
            flow.response = Response.make(
                403,
                msg,
                {"Content-Type": "text/plain; charset=utf-8"},
            )

    def done(self):
        ctx_log = getattr(self, "_intercepted", 0)
        print(f"[agentgate] session done; intercepted {ctx_log} requests", file=sys.stderr)


addons = [AgentGateAddon()]
