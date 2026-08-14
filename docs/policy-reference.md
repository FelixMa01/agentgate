# Policy reference

A complete reference for the YAML format AgentGate uses to describe allow / deny / ask rules and network policies.

## Top-level structure

```yaml
version: 1                    # required, must be 1
metadata:                     # optional — for humans and tooling
  author: agentgate
  name: my-team-policy
  version: 1
  last_reviewed: 2026-08-14   # ISO 8601 date
  description: |
    Multi-line description of what this policy does and who owns it.

default: allow                # allow | deny | ask | log

rules:                        # list of Rule objects
  - id: unique-id             # required, machine-readable
    name: Human label         # optional, defaults to id
    match: {tool: Bash}       # required, see "Matching" below
    action: deny              # allow | deny | ask | log
    reason: "Why this rule exists"   # optional, surfaced in audit + Slack

network:                      # optional, applies to mitmproxy add-on
  allowed_domains: [github.com, *.pypi.org]
  denied_domains:  [pastebin.com]
  require_https: true
```

## Actions

| Action | Meaning | Surfaces in audit as |
|---|---|---|
| `allow` | Tool runs immediately, recorded | `allow` row |
| `deny`  | Tool blocked, agent sees the `reason` | `deny` row |
| `ask`   | Tool blocked until human approves (Slack/file) | `ask` row + `_resolved` follow-up |
| `log`   | Tool runs, but recorded for compliance audit | `log` row |

## Matching

Each rule has a `match` map. Every key in the map must match the event for the rule to fire (AND semantics). Values can be a string (exact match) or a list (any-of).

### Match keys (AgentGate event schema)

| Key | Type | Example |
|---|---|---|
| `tool` | string / list | `Bash`, `Read`, `Write`, `Edit`, `Grep`, `Glob`, `WebFetch` |
| `command` | string | `"rm -rf /etc"` |
| `file_path` | string | `"/etc/passwd"` |
| `agent` | string | `"claude-code"`, `"cursor"` |
| `source` | string | `"claude-code"`, `"manual"`, `"proxy"` |
| `cwd` | string | `"/Users/me/project"` |

### Match patterns

A value can be a plain string (exact match) or one of three kinds of patterns:

1. **Exact**: `"rm -rf /etc"` — only the exact string.
2. **Glob** (suffix `_glob` on the match key, or just use a glob pattern directly): `"*.pem"`, `"rm -rf /*"`. Uses `fnmatch` with `/` crossing. The match key may end with `_glob` (`file_glob`, `command_glob`) to disambiguate, in which case AgentGate strips the suffix to find the event field.
3. **Regex** (suffix `_regex` on the match key): `"^[A-Z][a-z]+$"`. Python `re.search`.

```yaml
rules:
  - id: deny-rm-rf
    match:
      tool: Bash
      command_glob: "rm -rf /*"          # glob (key suffix optional)
    action: deny

  - id: deny-secrets
    match:
      tool: Read
      file_glob: ["*.pem", ".env*"]      # list = any-of
    action: deny

  - id: deny-eval
    match:
      tool: Bash
      command_regex: "(?i)\\beval\\b"    # case-insensitive regex
    action: deny

  - id: deny-known-bad-agents
    match:
      agent: ["untrusted-agent", "leaky-agent"]
    action: deny
```

## Network policy

```yaml
network:
  allowed_domains:        # strict allowlist (when present, deny anything else)
    - github.com
    - "*.pypi.org"
    - "*.anthropic.com"
  denied_domains:         # explicit denylist (always enforced)
    - pastebin.com
    - "*.onion"
    - "*gist.github.com/leak*"   # glob on subdomain
  require_https: true    # block http:// (naked hosts still allowed)
```

- If `allowed_domains` is defined, **anything not on the list is denied** (strict allowlist).
- If only `denied_domains` is defined, the default is "allow everything else".
- Domain globs use `fnmatch` with `/` crossing.
- `require_https: true` blocks requests with `http://` scheme but allows naked hosts (e.g. `curl example.com` resolves to https automatically).

## Metadata for compliance audits

```yaml
metadata:
  author: security-team          # who owns this policy
  name: production-rules         # a short name (used in dashboards)
  version: 3                     # increment on every change
  last_reviewed: 2026-08-14      # ISO 8601, used to flag stale policies
  description: |                 # free-form, rendered by `agentgate validate`
    Permissive in dev, restrictive in CI.
```

`agentgate validate` will warn when `metadata` is missing.

## Rule ordering

Rules are evaluated in **top-to-bottom order**. The first matching rule wins. Put your most specific rules first.

```yaml
rules:
  # specific deny first
  - id: deny-rm-rf-outside-tmp
    match: {tool: Bash, command_regex: "rm -rf /(?!(tmp|var/folders))"}
    action: deny

  # broader allow second
  - id: allow-bash
    match: {tool: Bash}
    action: allow
```

## Dry-run

```bash
agentgate eval -p policy.yaml --db /tmp/x.db \
  --event-json '{"tool":"Bash","command":"rm -rf /etc"}' --dry-run
```

Returns the decision without writing to the audit DB. Useful when iterating on a policy.

## Replay

Re-evaluate historical events against a new policy — useful for migrations:

```bash
agentgate replay --db audit.db --audit-id 42 -p new-policy.yaml
```

Shows whether the decision would have changed.

## Examples

See `examples/`:

- `examples/policy.yaml` — default (allow + a few denies)
- `examples/policy-secure.yaml` — strict, deny by default
- `examples/policy-permissive.yaml` — dev mode, only block the worst
- `examples/policy-team.yaml` — log everything + ask for risky ops