"""AgentGate dashboard — single-page HTML viewer for the audit DB.

Run: agentgate dashboard --db /path/to/audit.db [--port 8766]
Visit: http://localhost:8766

Renders:
  - Top stats cards (total / allow / deny / ask)
  - Time-series of decisions (last 24h, bucketed hourly)
  - Top denied rules
  - Recent events table
  - Live poll every 5s via fetch()
"""
from __future__ import annotations
import http.server
import json
import socketserver
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from . import __version__


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset=utf-8>
<title>AgentGate v__VER__ Dashboard</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root {{
  --bg:#0e1117; --panel:#161b22; --border:#30363d;
  --text:#e6edf3; --muted:#7d8590;
  --green:#3fb950; --red:#f85149; --yellow:#d29922; --blue:#58a6ff;
}}
* {{ box-sizing:border-box; }}
body {{ font:14px -apple-system,system-ui,sans-serif; background:var(--bg); color:var(--text);
       margin:0; padding:24px; max-width:1200px; margin:auto; }}
h1 {{ font-size:20px; margin:0 0 4px; }}
.subtitle {{ color:var(--muted); margin-bottom:24px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
         gap:16px; margin-bottom:24px; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:8px;
         padding:16px; }}
.card .v {{ font-size:28px; font-weight:600; }}
.card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px;
            margin-top:4px; }}
.allow {{ color:var(--green); }}
.deny  {{ color:var(--red); }}
.ask   {{ color:var(--yellow); }}
.log   {{ color:var(--blue); }}
table {{ width:100%; border-collapse:collapse; background:var(--panel);
         border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
th {{ background:#0d1117; font-weight:600; font-size:12px; text-transform:uppercase;
      color:var(--muted); letter-spacing:.5px; }}
tr:last-child td {{ border-bottom:none; }}
code {{ font-family:ui-monospace,SF Mono,Menlo,monospace; background:#0d1117;
        padding:1px 6px; border-radius:3px; font-size:12px; }}
button.refresh {{ background:#21262d; color:var(--text); border:1px solid var(--border);
                  padding:6px 12px; border-radius:6px; cursor:pointer; font-size:12px; }}
button.refresh:hover {{ background:#30363d; }}
.bar-row {{ display:flex; align-items:center; gap:8px; margin:6px 0; font-size:12px; }}
.bar-row .name {{ width:160px; color:var(--muted); overflow:hidden; text-overflow:ellipsis;
                  white-space:nowrap; }}
.bar-row .bar {{ flex:1; background:#0d1117; border-radius:3px; height:18px; position:relative; }}
.bar-row .fill {{ position:absolute; left:0; top:0; bottom:0;
                  background:var(--red); border-radius:3px; }}
.bar-row .n {{ width:48px; text-align:right; color:var(--muted); }}
#chart {{ background:var(--panel); border:1px solid var(--border); border-radius:8px;
          padding:16px; margin-bottom:24px; }}
svg {{ display:block; width:100%; height:160px; }}
.legend {{ display:flex; gap:16px; margin-top:8px; font-size:12px; color:var(--muted); }}
.legend span {{ display:inline-flex; align-items:center; gap:4px; }}
.legend i {{ width:10px; height:10px; border-radius:2px; display:inline-block; }}
.empty {{ color:var(--muted); padding:24px; text-align:center; }}
</style></head>
<body>
<h1>🛡️ AgentGate <span style="font-weight:400;color:var(--muted);font-size:14px">v__VER__</span></h1>
<div class=subtitle>Audit dashboard · last updated <span id=ts>—</span> · auto-refresh every 5s
  <button class=refresh style=float:right onclick=fetchAll()>Refresh</button>
</div>

<div class=grid id=cards></div>

<div id=chart>
  <h2 style="margin:0 0 12px;font-size:14px;color:var(--muted);
              text-transform:uppercase;letter-spacing:.5px;">Decisions over the last 24 hours</h2>
  <svg id=svg viewBox="0 0 720 160" preserveAspectRatio=none></svg>
  <div class=legend>
    <span><i style=background:var(--green)></i>allow</span>
    <span><i style=background:var(--red)></i>deny</span>
    <span><i style=background:var(--yellow)></i>ask</span>
  </div>
</div>

<h2 style="margin:0 0 12px;font-size:14px;color:var(--muted);
           text-transform:uppercase;letter-spacing:.5px;">Top denied rules</h2>
<div id=rules></div>

<h2 style="margin:24px 0 12px;font-size:14px;color:var(--muted);
           text-transform:uppercase;letter-spacing:.5px;">Recent events</h2>
<table id=events><thead><tr>
  <th>Time</th><th>Source</th><th>Action</th><th>Rule</th><th>Reason</th><th>Detail</th>
</tr></thead><tbody></tbody></table>

<script>
async function fetchJSON(url){{
  const r = await fetch(url); if (!r.ok) throw new Error(r.statusText); return r.json();
}}
function el(tag, attrs, ...children){{
  const e = document.createElement(tag); if (attrs) Object.assign(e, attrs);
  for (const c of children) if (c) e.appendChild(typeof c==='string' ? document.createTextNode(c) : c);
  return e;
}}
async function fetchAll(){{
  try {{
    const s = await fetchJSON('/api/stats');
    renderCards(s);
    const r = await fetchJSON('/api/recent_rules');
    renderRules(r);
    const e = await fetchJSON('/api/recent_events');
    renderEvents(e);
    const t = await fetchJSON('/api/timeseries');
    renderChart(t);
    document.getElementById('ts').textContent = new Date().toLocaleTimeString();
  }} catch (err) {{ console.error(err); }}
}}
function renderCards(s){{
  const root = document.getElementById('cards'); root.innerHTML = '';
  const items = [
    ['Total', s.total, ''],
    ['Allow', s.allow, 'allow'],
    ['Deny',  s.deny,  'deny'],
    ['Ask',   s.ask,   'ask'],
  ];
  for (const [label, n, cls] of items){{
    const c = el('div', {{className:'card'}});
    c.innerHTML = `<div class="v ${{cls}}">${{n}}</div><div class=l>${{label}}</div>`;
    root.appendChild(c);
  }}
}}
function renderRules(rules){{
  const root = document.getElementById('rules'); root.innerHTML = '';
  if (!rules.length) {{ root.innerHTML = '<div class=card><div class=empty>No denies yet 🎉</div></div>'; return; }}
  const max = Math.max(...rules.map(r => r.n));
  for (const r of rules){{
    const row = el('div', {{className:'bar-row'}});
    row.innerHTML = `<div class=name><code>${{escapeHtml(r.rule_id || '—')}}</code></div>
      <div class=bar><div class=fill style="width:${{(r.n/max*100).toFixed(0)}}%"></div></div>
      <div class=n>${{r.n}}</div>`;
    root.appendChild(row);
  }}
}}
function renderEvents(events){{
  const tbody = document.querySelector('#events tbody'); tbody.innerHTML = '';
  if (!events.length) {{ tbody.innerHTML = '<tr><td colspan=6 class=empty>No events recorded yet.</td></tr>'; return; }}
  for (const e of events){{
    const tr = document.createElement('tr');
    const detail = JSON.stringify({{...e.event, _ask_token: undefined, _resolved: undefined}}).slice(0, 120);
    tr.innerHTML = `
      <td><code>${{e.ts}}</code></td>
      <td>${{escapeHtml(e.source)}}</td>
      <td><span class="${{e.action.toLowerCase()}}">${{e.action.toUpperCase()}}</span></td>
      <td><code>${{escapeHtml(e.rule_id || '—')}}</code></td>
      <td>${{escapeHtml(e.reason || '')}}</td>
      <td><code style="opacity:.6">${{escapeHtml(detail)}}</code></td>`;
    tbody.appendChild(tr);
  }}
}}
function renderChart(t){{
  const svg = document.getElementById('svg'); svg.innerHTML = '';
  const W = 720, H = 160, pad = 8;
  const buckets = t.buckets;
  if (!buckets.length) return;
  const maxY = Math.max(1, ...buckets.flatMap(b => [b.allow, b.deny, b.ask]));
  const bw = (W - pad*2) / buckets.length;
  function bar(x, h, color){{
    const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    r.setAttribute('x', x); r.setAttribute('y', H - h);
    r.setAttribute('width', Math.max(0, bw-2)); r.setAttribute('height', h);
    r.setAttribute('fill', color); r.setAttribute('rx', 1);
    svg.appendChild(r);
  }}
  // Grid line
  const grid = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  grid.setAttribute('x1', 0); grid.setAttribute('x2', W);
  grid.setAttribute('y1', H-1); grid.setAttribute('y2', H-1);
  grid.setAttribute('stroke', '#30363d'); svg.appendChild(grid);
  for (let i=0; i<buckets.length; i++){{
    const b = buckets[i];
    const x = pad + i*bw;
    const aH = (b.allow/maxY)*(H-pad*2);
    const dH = (b.deny/maxY)*(H-pad*2);
    const askH = (b.ask/maxY)*(H-pad*2);
    bar(x, dH, 'var(--red)');
    bar(x, askH, 'var(--yellow)');
    bar(x, aH, 'var(--green)');
  }}
}}
function escapeHtml(s){{
  return String(s||'').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
}}
fetchAll(); setInterval(fetchAll, 5000);

// Live SSE stream — push new events without polling
if (typeof EventSource !== 'undefined') {
  const es = new EventSource('/api/events/stream');
  es.addEventListener('audit', e => {
    try {
      const evt = JSON.parse(e.data);
      notify(evt.action, evt.rule_id, evt.reason);
      flash(evt.action);
      fetchAll();  // re-pull stats + tables
    } catch (err) { console.error(err); }
  });
  es.onerror = () => console.warn('SSE connection lost, will reconnect');
}
function flash(action) {
  // brief border flash on body for visual cue
  const color = action === 'DENY' ? 'var(--red)'
    : action === 'ASK' ? 'var(--yellow)'
    : action === 'ALLOW' ? 'var(--green)' : 'var(--blue)';
  document.body.style.boxShadow = 'inset 0 0 0 3px ' + color;
  setTimeout(() => document.body.style.boxShadow = '', 600);
}
function notify(action, rule_id, reason) {
  if (action === 'DENY' && 'Notification' in window) {
    if (Notification.permission === 'granted') {
      new Notification('AgentGate: DENY', {
        body: (rule_id || '') + ' — ' + (reason || ''),
      });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission();
    }
  }
}
</script>
</body></html>
""".replace("__VER__", __version__)


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    db_path: Path  # set on the class by serve()

    def log_message(self, fmt, *args):  # quiet
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            body = INDEX_HTML.encode()
            self._send(200, "text/html; charset=utf-8", body)
            return
        if parsed.path == "/api/stats":
            self._send(200, "application/json", json.dumps(self._stats()).encode())
            return
        if parsed.path == "/api/recent_rules":
            self._send(200, "application/json", json.dumps(self._top_denied()).encode())
            return
        if parsed.path == "/api/recent_events":
            self._send(200, "application/json", json.dumps(self._recent_events()).encode())
            return
        if parsed.path == "/api/timeseries":
            self._send(200, "application/json", json.dumps(self._timeseries()).encode())
            return
        if parsed.path == "/api/events/stream":
            self._sse_stream()
            return
        if parsed.path == "/api/events":
            self._api_events(parsed)
            return
        self._send(404, "text/plain", b"not found\n")

    def _api_events(self, parsed) -> None:
        """GET /api/events?action=deny&source=claude-code&since=ts&limit=50.

        Returns recent events filtered by action / source / timestamp.
        """
        from urllib.parse import parse_qs
        q = parse_qs(parsed.query)
        action = (q.get("action") or [None])[0]
        source = (q.get("source") or [None])[0]
        since = (q.get("since") or [None])[0]
        limit = int((q.get("limit") or ["50"])[0])

        sql = "SELECT id, ts, source, agent, action, rule_id, rule_name, reason, event_json FROM events WHERE 1=1"
        params: list = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if source:
            sql += " AND source = ?"
            params.append(source)
        if since:
            try:
                sql += " AND ts >= ?"
                params.append(float(since))
            except ValueError:
                pass
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            ev = json.loads(r["event_json"]) if r["event_json"] else {}
            out.append({
                "id": r["id"],
                "ts": r["ts"],
                "source": r["source"],
                "agent": r["agent"],
                "action": str(r["action"]),
                "rule_id": r["rule_id"],
                "rule_name": r["rule_name"],
                "reason": r["reason"],
                "event": ev,
            })
        self._send(200, "application/json", json.dumps(out).encode())

    def _sse_stream(self):
        """Server-Sent Events — push new audit rows in real time.

        Polls the DB every 1s for new events (id > last_seen_id). Yields an
        SSE `event: audit` payload per new row.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")  # nginx hint
        self.end_headers()
        last_id = 0
        try:
            with self._connect() as conn:
                cur = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events")
                last_id = int(cur.fetchone()[0])
        except Exception:
            pass
        # Send an initial heartbeat so the client knows we're connected.
        self.wfile.write(b": connected\n\n")
        self.wfile.flush()
        while True:
            try:
                with self._connect() as conn:
                    conn.row_factory = sqlite3.Row
                    # Make sure the table exists (no-op if it does).
                    try:
                        conn.execute("SELECT 1 FROM events LIMIT 1")
                    except Exception:
                        # Schema missing — wait for Audit to create it.
                        time.sleep(0.5)
                        continue
                    cur = conn.execute(
                        "SELECT id, ts, source, agent, action, rule_id, "
                        "rule_name, reason, event_json FROM events "
                        "WHERE id > ? ORDER BY id ASC LIMIT 50",
                        (last_id,),
                    )
                    rows = cur.fetchall()
                for row in rows:
                    payload = {
                        "id": row["id"],
                        "ts": row["ts"],
                        "source": row["source"],
                        "agent": row["agent"],
                        "action": str(row["action"]),
                        "rule_id": row["rule_id"],
                        "rule_name": row["rule_name"],
                        "reason": row["reason"],
                        "event": json.loads(row["event_json"]) if row["event_json"] else {},
                    }
                    self.wfile.write(b"event: audit\n")
                    self.wfile.write(b"data: " + json.dumps(payload).encode() + b"\n\n")
                    self.wfile.flush()
                    last_id = max(last_id, row["id"])
                # Heartbeat to keep connection alive through proxies.
                self.wfile.write(b": ping\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                # Stay quiet — better to drop the connection than spam logs.
                return
            time.sleep(1)

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute("SELECT action, COUNT(*) n FROM events GROUP BY action").fetchall()
            counts = {r["action"]: r["n"] for r in rows}
            total = sum(counts.values())
        return {
            "total": total,
            "allow": counts.get("allow", 0),
            "deny": counts.get("deny", 0),
            "ask": counts.get("ask", 0),
            "log": counts.get("log", 0),
        }

    def _top_denied(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT COALESCE(rule_id, '—') AS rule_id, COUNT(*) AS n
                   FROM events WHERE action='deny' GROUP BY rule_id
                   ORDER BY n DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [{"rule_id": r["rule_id"], "n": r["n"]} for r in rows]

    def _recent_events(self, limit: int = 30) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ts, source, action, rule_id, rule_name, reason, event_json
                   FROM events ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            ev = json.loads(r["event_json"]) if r["event_json"] else {}
            out.append({
                "ts": datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S"),
                "source": r["source"] or "?",
                "action": r["action"] or "?",
                "rule_id": r["rule_id"],
                "reason": r["reason"] or "",
                "event": ev,
            })
        return out

    def _timeseries(self, hours: int = 24) -> dict:
        """Bucket events into hourly buckets for the last `hours` hours."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, action FROM events WHERE ts > ?",
                (time.time() - hours * 3600,),
            ).fetchall()
        # Round down to hour boundary
        buckets: dict[int, dict] = {}
        for r in rows:
            ts = float(r["ts"])
            bucket = int(ts // 3600) * 3600
            b = buckets.setdefault(bucket, {"allow": 0, "deny": 0, "ask": 0})
            if r["action"] in b:
                b[r["action"]] += 1
        # Build a continuous time series
        now = int(time.time() // 3600) * 3600
        series = []
        for h in range(now - (hours - 1) * 3600, now + 1, 3600):
            b = buckets.get(h, {"allow": 0, "deny": 0, "ask": 0})
            series.append({"t": h, **b})
        return {"buckets": series}


def serve(db_path: str | Path, host: str = "127.0.0.1", port: int = 8766) -> None:
    db = Path(db_path)
    if not db.exists():
        # Touch a fresh DB so the schema is created on first run.
        sqlite3.connect(db).close()
    DashboardHandler.db_path = db
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), DashboardHandler) as httpd:
        print(f"[agentgate] dashboard at http://{host}:{port}", file=sys.stderr)
        print(f"  reading from: {db}", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[agentgate] dashboard shutting down", file=sys.stderr)
            httpd.shutdown()