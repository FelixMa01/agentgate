"""Tests for the webhook subsystem."""
import http.server
import json
import socket
import threading
import time

import pytest

from agentgate.webhooks import (
    DEFAULT_PATH,
    Webhook,
    _matches,
    deliver,
    load_webhooks,
    save_webhooks,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    received: list[dict] = []  # noqa: RUF012
    response_status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            self.received.append(json.loads(body))
        except Exception:
            self.received.append({"raw": body.decode("utf-8", errors="replace")})
        self.send_response(self.response_status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args, **kwargs):
        pass


def _start_server(handler_cls):
    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def test_load_webhooks_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "nope.yaml"))
    assert load_webhooks() == []


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    whs = [
        Webhook(name="slack", url="https://example.com/slack", on={"action": "deny"}, template="blocked {rule_id}"),
        Webhook(name="log", url="https://example.com/log", on={}),
    ]
    save_webhooks(whs)
    loaded = load_webhooks()
    assert len(loaded) == 2
    assert loaded[0].name == "slack"
    assert loaded[0].on == {"action": "deny"}
    assert loaded[0].template == "blocked {rule_id}"


def test_filter_matches_single_value():
    assert _matches({"action": "deny"}, {"action": "deny"})
    assert not _matches({"action": "ask"}, {"action": "deny"})


def test_filter_matches_list_value():
    assert _matches({"action": "deny"}, {"action": ["allow", "deny"]})
    assert not _matches({"action": "ask"}, {"action": ["allow", "deny"]})


def test_filter_matches_missing_field_means_pass():
    """If filter key not present in event, that key passes (no constraint)."""
    assert _matches({"action": "deny"}, {})


def test_deliver_to_matching_webhook(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    CaptureHandler.received = []
    srv, port = _start_server(CaptureHandler)
    try:
        whs = [Webhook(name="t", url=f"http://127.0.0.1:{port}/hook", on={"action": "deny"})]
        event = {"action": "deny", "rule_id": "r1", "rule_name": "rule one", "source": "x"}
        results = deliver(event, webhooks=whs)
        assert results == [("t", True, "ok")]
        assert len(CaptureHandler.received) == 1
        assert CaptureHandler.received[0]["event"]["rule_id"] == "r1"
    finally:
        srv.shutdown()


def test_deliver_skips_non_matching_webhook(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    CaptureHandler.received = []
    srv, port = _start_server(CaptureHandler)
    try:
        whs = [Webhook(name="t", url=f"http://127.0.0.1:{port}/hook", on={"action": "deny"})]
        event = {"action": "allow"}  # no match
        results = deliver(event, webhooks=whs)
        assert results == []
        assert CaptureHandler.received == []
    finally:
        srv.shutdown()


def test_deliver_records_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    # Closed port — should fail all retries.
    whs = [Webhook(name="t", url="http://127.0.0.1:1/hook", on={}, template="")]
    event = {"action": "deny", "rule_id": "r1"}
    results = deliver(event, webhooks=whs, timeout=0.5)
    assert len(results) == 1
    name, ok, msg = results[0]
    assert name == "t"
    assert ok is False
    assert msg  # some error message


def test_deliver_renders_template(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    CaptureHandler.received = []
    srv, port = _start_server(CaptureHandler)
    try:
        whs = [Webhook(name="t", url=f"http://127.0.0.1:{port}/hook",
                       on={}, template="denied {rule_name} ({rule_id})")]
        event = {"action": "deny", "rule_name": "rm -rf /", "rule_id": "deny-rm"}
        deliver(event, webhooks=whs)
        msg = CaptureHandler.received[0]["message"]
        assert msg == "denied rm -rf / (deny-rm)"
    finally:
        srv.shutdown()


def test_cli_webhook_add_list_remove(tmp_path, monkeypatch):
    """End-to-end CLI: add → list → remove."""
    from click.testing import CliRunner

    from agentgate.cli.cli_webhook import webhook

    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    runner = CliRunner()

    result = runner.invoke(webhook, ["add", "test", "http://x/y", "--action", "deny"])
    assert result.exit_code == 0, result.output
    assert "Added" in result.output

    result = runner.invoke(webhook, ["list"])
    assert "test" in result.output
    assert "http://x/y" in result.output
    assert "deny" in result.output

    result = runner.invoke(webhook, ["remove", "test"])
    assert result.exit_code == 0

    result = runner.invoke(webhook, ["list"])
    assert "No webhooks" in result.output


def test_cli_webhook_test_overrides_url(tmp_path, monkeypatch):
    """--url override should send a single test event without saving config."""
    from click.testing import CliRunner

    from agentgate.cli.cli_webhook import webhook
    monkeypatch.setenv("AGENTGATE_WEBHOOKS", str(tmp_path / "wh.yaml"))
    CaptureHandler.received = []
    srv, port = _start_server(CaptureHandler)
    try:
        runner = CliRunner()
        result = runner.invoke(webhook, ["test", "--url", f"http://127.0.0.1:{port}/x"])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output
        assert len(CaptureHandler.received) == 1
    finally:
        srv.shutdown()
