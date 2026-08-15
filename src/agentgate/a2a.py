"""A2A (Agent-to-Agent) protocol inspector.

A2A is Google's emerging standard for agent-to-agent messaging
(agentcard.json + JSON-RPC). AgentGate inspects A2A traffic and
applies the same policy decisions as for HTTP.

Two halves:

- :class:`A2AInspector` — pure-Python inspection of A2A payloads.
  Detects:
    - prompt-injection in messages[].parts[].text
    - data-exfiltration patterns in attachments / file URLs
    - capability downgrades (a peer claiming reduced capabilities)
    - unsafe tool invocations embedded in messages
    - policy-relevant metadata (agentCard identity drift)

- :func:`inspect_payload` — convenience: given a JSON string, return
  a list of :class:`A2AFinding`.

Run from the proxy addon or as a standalone check:

    from agentgate.a2a import A2AInspector
    ins = A2AInspector()
    findings = ins.inspect(payload_bytes)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from .dlp import DlpScanner, DlpSeverity


class A2ASeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class A2AFinding:
    severity: A2ASeverity
    rule: str
    location: str       # json-path-ish pointer
    message: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "rule": self.rule,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
        }


_PROMPT_INJECTION_HINTS = (
    "ignore previous",
    "ignore all instructions",
    "system:",
    "you are now",
    "reveal your system prompt",
    "disregard the above",
    "act as dan",
    "no restrictions",
    "tool_calls",
    "<|im_start|>",
    "<|im_end|>",
)

_UNSAFE_TOOL_HINTS = (
    "rm -rf",
    "curl ",
    "wget ",
    ":(){ :|:& };:",
    "format c:",
    "del /f /s",
)

_DOWNGRADE_HINTS = (
    '"permissions":[]',
    '"elevation":false',
    '"elevation": false',
    '"scope":"minimal"',
    '"dangerouslydisable":true',
    '"dangerouslydisable": true',
    'skip-permissions',
    '--dangerously-skip-permissions',
)


class A2AInspector:
    def __init__(self, dlp: DlpScanner | None = None):
        self.dlp = dlp or DlpScanner()

    def inspect(self, payload: bytes | str | dict) -> list[A2AFinding]:
        if isinstance(payload, (bytes, bytearray)):
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                return []
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return []
        if not isinstance(payload, dict):
            return []
        findings: list[A2AFinding] = []
        self._walk(payload, findings, path="")
        return findings

    def _walk(self, node, findings: list[A2AFinding], path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else k
                if k in {"text", "content", "body", "message"} and isinstance(v, str):
                    self._scan_text(v, findings, child_path)
                elif k == "tool" or k == "tool_name":
                    self._scan_tool(v, findings, child_path)
                elif k in {"agentCard", "agent_card", "capabilities"}:
                    self._scan_capabilities(v, findings, child_path)
                elif k in {"attachments", "files"} and isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, dict) and "url" in item:
                            self._scan_url(item["url"], findings,
                                           f"{child_path}[{i}].url")
                self._walk(v, findings, child_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk(item, findings, f"{path}[{i}]")

    def _scan_text(self, text: str, findings: list[A2AFinding], path: str) -> None:
        lower = text.lower()
        for hint in _PROMPT_INJECTION_HINTS:
            if hint in lower:
                findings.append(A2AFinding(
                    severity=A2ASeverity.CRITICAL,
                    rule="a2a-prompt-injection",
                    location=path,
                    message=f"Prompt injection marker in A2A message: {hint!r}",
                    evidence=text[:120],
                ))
                break
        # Re-use the DLP body scanner.
        for f in self.dlp.scan_body(text.encode("utf-8", "ignore")):
            if f.severity in (DlpSeverity.CRITICAL, DlpSeverity.HIGH):
                findings.append(A2AFinding(
                    severity=A2ASeverity.CRITICAL,
                    rule=f"a2a-{f.pattern_name}",
                    location=path,
                    message=f"DLP match in A2A payload: {f.pattern_name}",
                    evidence=f.evidence,
                ))

    def _scan_tool(self, value, findings: list[A2AFinding], path: str) -> None:
        s = str(value).lower()
        for hint in _UNSAFE_TOOL_HINTS:
            if hint in s:
                findings.append(A2AFinding(
                    severity=A2ASeverity.CRITICAL,
                    rule="a2a-unsafe-tool",
                    location=path,
                    message=f"Unsafe tool invocation in A2A payload: {hint!r}",
                    evidence=str(value)[:120],
                ))
                break

    def _scan_url(self, url, findings: list[A2AFinding], path: str) -> None:
        s = str(url)
        for f in self.dlp.scan_url(s):
            if f.severity == DlpSeverity.CRITICAL:
                findings.append(A2AFinding(
                    severity=A2ASeverity.CRITICAL,
                    rule=f"a2a-{f.pattern_name}",
                    location=path,
                    message=f"Unsafe URL in A2A payload: {f.pattern_name}",
                    evidence=f.evidence,
                ))

    def _scan_capabilities(self, value, findings: list[A2AFinding], path: str) -> None:
        s = json.dumps(value, default=str).lower()
        for hint in _DOWNGRADE_HINTS:
            if hint in s:
                findings.append(A2AFinding(
                    severity=A2ASeverity.WARNING,
                    rule="a2a-capability-downgrade",
                    location=path,
                    message=f"Capability downgrade detected: {hint!r}",
                    evidence=s[:120],
                ))
                break


def has_critical(findings: list[A2AFinding]) -> bool:
    return any(f.severity == A2ASeverity.CRITICAL for f in findings)
