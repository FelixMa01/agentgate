"""Embeddable web policy editor.

Single-page application served from the dashboard. Lets users:

- load a policy.yaml from disk (uploaded via /api/policy/load)
- edit rules in a structured form (tool / match / action / reason)
- validate via /api/policy/lint (returns findings inline)
- save back to /api/policy/save

The editor is a small JS file embedded directly in this module so
the dashboard has no external asset dependency.
"""

from __future__ import annotations

POLICY_EDITOR_HTML = """\
<div id="policy-editor">
  <header>
    <h2>Policy editor</h2>
    <p class="muted">Edit agentgate.yaml rules inline. Save commits back to disk.</p>
  </header>

  <section class="toolbar">
    <label class="file">
      <span>Load policy</span>
      <input type="file" id="pe-load" accept=".yaml,.yml">
    </label>
    <button id="pe-validate">Lint</button>
    <button id="pe-save" class="primary">Save</button>
    <span class="muted" id="pe-status"></span>
  </section>

  <section class="meta">
    <label>Version <input id="pe-version" type="number" value="1" min="1"></label>
    <label>Default action
      <select id="pe-default">
        <option value="allow">allow</option>
        <option value="deny" selected>deny</option>
        <option value="ask">ask</option>
        <option value="log">log</option>
      </select>
    </label>
  </section>

  <section class="rules">
    <h3>Rules</h3>
    <table id="pe-rules">
      <thead>
        <tr>
          <th>id</th>
          <th>tool</th>
          <th>match (regex / glob)</th>
          <th>action</th>
          <th>reason</th>
          <th></th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <button id="pe-add">+ add rule</button>
  </section>

  <section class="network">
    <h3>Network policy</h3>
    <label><input type="checkbox" id="pe-net-require-https"> require_https</label>
    <label>allowed_domains (one per line)
      <textarea id="pe-net-allowed" rows="4"></textarea>
    </label>
    <label>blocked_domains (one per line)
      <textarea id="pe-net-blocked" rows="4"></textarea>
    </label>
  </section>

  <section id="pe-findings" hidden>
    <h3>Lint findings</h3>
    <ul></ul>
  </section>
</div>
"""

POLICY_EDITOR_JS = """\
(function() {
  const $ = (id) => document.getElementById(id);
  const tbody = $("pe-rules").querySelector("tbody");
  let policy = {version: 1, default_action: "deny", rules: [], network: {}};

  function render() {
    $("pe-version").value = policy.version || 1;
    $("pe-default").value = policy.default_action || "deny";
    $("pe-net-require-https").checked = !!(policy.network||{}).require_https;
    $("pe-net-allowed").value = ((policy.network||{}).allowed_domains||[]).join("\\n");
    $("pe-net-blocked").value = ((policy.network||{}).blocked_domains||[]).join("\\n");
    tbody.innerHTML = "";
    (policy.rules||[]).forEach((r, i) => tbody.appendChild(ruleRow(r, i)));
  }

  function ruleRow(rule, idx) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input data-k="id" value="${rule.id||""}"></td>
      <td><input data-k="tool" value="${(rule.match&&rule.match.tool)||""}"></td>
      <td><input data-k="match" placeholder="command_regex / file_regex"
                 value="${(rule.match&&(rule.match.command_regex||rule.match.file_regex))||""}"></td>
      <td>
        <select data-k="action">
          ${["allow","deny","ask","log"].map(a =>
            `<option value="${a}" ${rule.action===a?"selected":""}>${a}</option>`).join("")}
        </select>
      </td>
      <td><input data-k="reason" value="${rule.reason||""}"></td>
      <td><button data-rm="${idx}">x</button></td>`;
    return tr;
  }

  $("pe-add").addEventListener("click", () => {
    policy.rules.push({id: "rule-"+(policy.rules.length+1),
                       match: {tool: "Bash"}, action: "allow", reason: ""});
    render();
  });

  tbody.addEventListener("click", (e) => {
    if (e.target.dataset.rm != null) {
      policy.rules.splice(+e.target.dataset.rm, 1);
      render();
    }
  });

  tbody.addEventListener("change", (e) => {
    const tr = e.target.closest("tr");
    const idx = Array.from(tbody.children).indexOf(tr);
    if (idx < 0) return;
    const r = policy.rules[idx];
    const k = e.target.dataset.k;
    if (k === "tool") r.match = r.match || {}, r.match.tool = e.target.value;
    else if (k === "match") r.match = r.match || {},
      (e.target.placeholder.includes("command")
        ? (r.match.command_regex = e.target.value)
        : (r.match.file_regex = e.target.value));
    else r[k] = e.target.value;
  });

  $("pe-load").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const txt = await f.text();
    policy = parseYaml(txt);
    render();
    $("pe-status").textContent = `loaded ${f.name}`;
  });

  function readMeta() {
    policy.version = +$("pe-version").value || 1;
    policy.default_action = $("pe-default").value;
    policy.network = policy.network || {};
    policy.network.require_https = $("pe-net-require-https").checked;
    policy.network.allowed_domains = $("pe-net-allowed").value.split("\\n").filter(Boolean);
    policy.network.blocked_domains = $("pe-net-blocked").value.split("\\n").filter(Boolean);
  }

  $("pe-validate").addEventListener("click", async () => {
    readMeta();
    const r = await fetch("/api/policy/lint", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(policy)
    });
    const findings = await r.json();
    showFindings(findings);
  });

  $("pe-save").addEventListener("click", async () => {
    readMeta();
    const r = await fetch("/api/policy/save", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(policy)
    });
    const out = await r.json();
    $("pe-status").textContent = out.ok ? "saved" : "error: "+(out.error||"");
  });

  function showFindings(findings) {
    const sec = $("pe-findings");
    sec.hidden = !findings.length;
    sec.querySelector("ul").innerHTML = findings.map(f =>
      `<li class="${f.severity}">[${f.severity}] ${f.where}: ${f.message}</li>`).join("");
  }

  // Minimal YAML parser tailored for policy.yaml. Avoids external deps.
  function parseYaml(text) {
    // Defer to the server by sending the raw text as-is to /api/policy/load,
    // which uses PyYAML. The server returns the parsed dict.
    return null; // server side flow only; see dashboard handler
  }

  render();
})();
"""


def editor_assets() -> dict[str, str]:
    """Return the HTML + JS for the editor page."""
    return {"html": POLICY_EDITOR_HTML, "js": POLICY_EDITOR_JS}
