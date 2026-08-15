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
from agentgate.policy import Action, PolicyWatcher  # noqa: E402


class AgentGateAddon:
    def __init__(self) -> None:
        policy_path = os.environ.get("AGENTGATE_POLICY")
        db_path = os.environ.get("AGENTGATE_DB")
        if not policy_path or not db_path:
            raise RuntimeError("AGENTGATE_POLICY and AGENTGATE_DB env vars must be set")
        # PolicyWatcher hot-reloads the policy file on mtime change so edits
        # to policy.yaml take effect without restarting mitmdump.
        self.watcher = PolicyWatcher(policy_path)
        self.policy = self.watcher.policy
        self.audit = Audit(db_path)
        self._intercepted = 0
        self._reload_count = 0

    def _maybe_reload(self) -> None:
        if self.watcher.changed():
            self.policy = self.watcher.reload()
            self._reload_count += 1
            print(
                f"[agentgate] policy reloaded ({len(self.policy.rules)} rules)",
                file=sys.stderr,
            )

    # mitmproxy hook: every HTTP request before it's sent
    def request(self, flow):
        self._maybe_reload()
        url = flow.request.pretty_url
        decision = evaluate_network(
            url, self.policy.network, default=self.policy.default_action.value
        )

        # DLP + prompt-injection + entropy scan before forwarding.
        dlp_findings: list = []
        try:
            # mitmdump loads this script via importlib so relative imports
            # of the package break — use absolute + defensive try/except.
            try:
                from agentgate.dlp import DlpScanner, DlpSeverity
            except Exception:
                from .dlp import DlpScanner, DlpSeverity  # type: ignore
            scanner = DlpScanner()
            dlp_findings = scanner.scan(
                url=url,
                body=flow.request.raw_content or b"",
                headers=dict(flow.request.headers.items()),
            )
        except Exception:
            pass

        # If any CRITICAL DLP finding -> deny (catch exfil of secrets).
        criticals = [f for f in dlp_findings if f.severity == DlpSeverity.CRITICAL]
        if criticals:
            from mitmproxy.http import Response
            summary = ", ".join(f.pattern_name for f in criticals[:3])
            msg = f"AgentGate: DENY — DLP tripped: {summary}\n".encode()
            self.audit.record(
                source="network",
                agent="mitmproxy",
                action=Action.DENY,
                event={
                    "url": url,
                    "method": flow.request.method,
                    "host": flow.request.host,
                    "dlp_findings": [f.to_dict() for f in dlp_findings],
                },
                rule_id="dlp-" + criticals[0].pattern_name.lower().replace(" ", "-"),
                rule_name=f"DLP {criticals[0].pattern_name}",
                reason=f"DLP scan detected {len(criticals)} critical finding(s)",
            )
            flow.response = Response.make(
                403,
                msg,
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            return

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
                "dlp_findings": [f.to_dict() for f in dlp_findings] if dlp_findings else None,
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
        print(
            f"[agentgate] session done; intercepted {ctx_log} requests; "
            f"policy reloads: {self._reload_count}",
            file=sys.stderr,
        )


addons = [AgentGateAddon()]
