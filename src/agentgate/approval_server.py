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
from urllib.parse import parse_qs, urlparse

from . import __version__
from .approval import STORE

HTML = """\
<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AgentGate · {title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    max-width: 640px; margin: 48px auto; padding: 0 24px;
    background: #0e1117; color: #e6edf3;
  }}
  h1 {{ margin: 0 0 4px; font-size: 22px; }}
  .sub {{ color: #8b949e; font-size: 13px; margin-bottom: 24px; }}
  .card {{
    border: 1px solid #30363d; border-radius: 8px;
    padding: 16px 20px; margin: 16px 0; background: #161b22;
  }}
  .kv {{ font: 13px ui-monospace, SFMono-Regular, monospace;
        background: #0e1117; color: #79c0ff; padding: 2px 6px;
        border-radius: 3px; border: 1px solid #30363d; }}
  pre {{ font: 12px ui-monospace, monospace; background: #0e1117;
        padding: 12px; border-radius: 6px; overflow: auto;
        border: 1px solid #30363d; max-height: 280px; }}
  .toolbar {{ display: flex; gap: 12px; margin: 24px 0; }}
  .btn {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 20px; border-radius: 6px; text-decoration: none;
    font-weight: 600; font-size: 14px; transition: filter 0.1s;
    border: 1px solid transparent;
  }}
  .btn:hover {{ filter: brightness(1.15); }}
  .btn-allow {{ background: #238636; color: #fff; border-color: #2ea043; }}
  .btn-deny {{ background: #da3633; color: #fff; border-color: #f85149; }}
  .resolved {{ padding: 10px 16px; border-radius: 6px; font-weight: 600; }}
  .resolved.allow {{ background: rgba(35, 134, 54, 0.15); color: #3fb950; }}
  .resolved.deny {{ background: rgba(218, 54, 51, 0.15); color: #f85149; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px;
            font: 11px ui-monospace, monospace; font-weight: 600;
            background: #30363d; color: #e6edf3; }}
  .muted {{ color: #8b949e; }}
  code {{ font: 12px ui-monospace, monospace; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _render(event: dict, decision: str | None, token: str) -> str:
    import json
    tool = event.get("tool", "?")
    event_json = json.dumps(event, indent=2, default=str)
    title = f"Approve {tool}" if decision is None else f"Resolved · {decision}"
    body = f"""
    <h1>🛡 AgentGate <span class="badge">v{__version__}</span></h1>
    <div class="sub">A pending action needs your call.</div>

    <div class="card">
      <div><b>Tool</b> &nbsp; <span class="kv">{tool}</span></div>
      <div style="margin-top:8px"><b>Token</b> &nbsp; <span class="kv">{token[:12]}…</span></div>
      <div style="margin-top:14px"><b>Event</b></div>
      <pre>{event_json}</pre>
    </div>
    """
    if decision:
        body += f'<div class="resolved {decision}">Resolved: {decision}</div>'
        body += '<p class="muted">You can close this window.</p>'
    else:
        body += f"""
        <div class="toolbar">
          <a class="btn btn-allow" href="/approve/{token}?d=allow">✅ Allow once</a>
          <a class="btn btn-deny" href="/approve/{token}?d=deny">✗ Deny</a>
        </div>
        <p class="muted">
          Decision is final. If you deny, the AI agent will see a clear rejection
          and can retry with a different approach.
        </p>
        """
    return HTML.format(body=body, title=title)


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
                self._respond(
                    404, f"Token {token!r} not found (or already resolved & cleaned up)\n"
                )
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
        ctype = "text/html; charset=utf-8" if body.startswith("<") else "text/plain; charset=utf-8"
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
