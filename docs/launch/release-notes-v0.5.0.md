## v0.5.0 — DNS sinkhole + live SSE dashboard + hosted team mode

Three big additions expand AgentGate's scope beyond local-only:

### 1. DNS sinkhole (`python -m agentgate.dns_sinkhole`)

Zero-config alternative to the mitmproxy proxy for blocking agent egress:

- Spins up a UDP DNS server on `127.0.0.1:5300` (default)
- Returns `0.0.0.0` for denied domains → connection fails fast
- Forwards allowed domains to your real upstream resolver
- Configure `AGENTGATE_POLICY` and start; no `HTTP_PROXY` env vars needed

**Why DNS instead of eBPF?** eBPF requires Linux + clang + libbpf + sudo. DNS interception works on macOS, Linux, and Windows, with zero native dependencies. The tradeoff: cannot block by URL path (only by domain).

### 2. Live SSE dashboard (`/api/events/stream`)

The dashboard now pushes new audit events in real time via Server-Sent Events. The browser opens an `EventSource`, and the server polls the DB every second for rows newer than the last seen id.

On a deny, the page border flashes red and (with permission) a desktop notification fires. No build tools, no React — vanilla JS embedded in the single HTML page.

### 3. Hosted team mode (`pull-policy`, `push-events`)

For teams that want a central source of truth:

- `agentgate pull-policy --out policy.hosted.yaml` downloads the canonical policy from your team endpoint
- `agentgate push-events --db audit.db` uploads new audit rows to the central collector
- Auth via `AGENTGATE_HOSTED_TOKEN` (bearer token)
- Cursor-based sync — only new rows are uploaded

The hosted protocol is plain HTTP so any backend (FastAPI, Cloudflare Worker, Lambda) can host the policy/event endpoints.

### Tests

78 → 83 unit tests. New:
- `tests/test_dns.py` (6 tests)
- `tests/test_dashboard_sse.py` (1 end-to-end)
- `tests/test_hosted.py` (5 tests with in-process HTTP server)

### Verify script

Still 10 end-to-end steps; CI runs pytest + e2e on Py 3.12 + 3.13.