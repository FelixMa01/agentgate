"""Minimal HTTP server exposing /approve/<token>?d=allow|deny endpoints.

Intended to run as a long-lived process alongside the proxy / hooks. It is NOT
the webhook receiver (Slack incoming webhooks are POST). This server is the
"click the link" receiver for human approval actions.

To start it: `agentgate approval-server --port 8765`
Then in the Slack message template the host:port is rendered so the link works.
"""
from __future__ import annotations
import http.server
import socketserver
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .approval import STORE
from . import __version__


HTML = """\
<!doctype html>
<html><head><meta charset=utf-8><title>AgentGate</title>
<style>
body {{ font: 16px system-ui; max-width: 600px; margin: 60px auto; padding: 0 20px; }}
.box {{ border: 2px solid #ccc; border-radius: 8px; padding: 20px; margin: 20px 0; }}
.box.allow {{ border-color: #2d9c4f; background: #e8f6ed; }}
.box.deny  {{ border-color: #d32f2f; background: #fde8e8; }}
.kv {{ font-family: monospace; background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
h1 {{ margin-top: 0; }}
</style></head><body>
{body}
</body></html>
"""


def _render(event: dict, decision: str | None, token: str) -> str:
    body = f"""
    <h1>🛡️ AgentGate v{__version__}</h1>
    <div class="box">
      <p><b>Tool:</b> <span class="kv">{event.get('tool', '?')}</span></p>
      <p><b>Event:</b></p>
      <pre style="background:#f4f4f4;padding:10px;border-radius:4px;overflow:auto">{event}</pre>
      <p><b>Status:</b> {('resolved: ' + decision) if decision else '⏳ awaiting decision'}</p>
    </div>
    """
    if not decision:
        body += f"""
        <p>
          <a class="box allow" style="display:inline-block;text-decoration:none;color:#000"
             href="/approve/{token}?d=allow">✅ Allow</a>
          &nbsp;
          <a class="box deny" style="display:inline-block;text-decoration:none;color:#000"
             href="/approve/{token}?d=deny">✗ Deny</a>
        </p>
        """
    return HTML.format(body=body)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._respond(200, "ok\n")
            return
        if parsed.path.startswith("/approve/"):
            token = parsed.path.split("/", 2)[2]
            qs = parse_qs(parsed.query)
            ask = STORE.get(token)
            if not ask:
                self._respond(404, f"Token {token!r} not found (or already resolved & cleaned up)\n")
                return
            d = qs.get("d", [None])[0]
            if d in ("allow", "deny"):
                STORE.resolve(token, d)
                self._respond(200, _render(ask.event, d, token))
                return
            # Just display the form
            self._respond(200, _render(ask.event, ask.decision, token))
            return
        self._respond(404, "not found\n")

    def _respond(self, code: int, body: str) -> None:
        if body.startswith("<"):
            ctype = "text/html; charset=utf-8"
        else:
            ctype = "text/plain; charset=utf-8"
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), Handler) as httpd:
        print(f"[agentgate] approval server on http://{host}:{port}", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[agentgate] shutting down", file=sys.stderr)
            httpd.shutdown()