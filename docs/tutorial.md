# AgentGate Tutorial — custom policy for your stack

This tutorial walks through designing a policy for a typical backend
service repo. By the end you'll have a policy that:

- Denies writes to `.env`, `.git/`, `secrets/`
- Asks before running `terraform apply` / `kubectl apply`
- Allows read-only inspection freely
- Restricts network to GitHub + your own registry

## Step 1: Start from a preset

```bash
agentgate init --preset balanced --output ./policy.yaml
```

## Step 2: Add path denies

Open `policy.yaml` and append:

```yaml
rules:
  - id: deny-secret-writes
    name: No writes to secrets
    match:
      tool: [Write, Edit, NotebookEdit]
      file_glob: ".env*"
    action: deny
    reason: "Secrets must never be written by an agent."

  - id: deny-git-writes
    match:
      tool: [Write, Edit]
      file_glob: ".git/*"
    action: deny
    reason: "Agents must not touch git internals."
```

The `file_glob` suffix switches matching to fnmatch glob semantics —
so `.env*` matches `.env`, `.envrc`, `.env.production`.

## Step 3: Add ASK for deploy commands

```yaml
  - id: ask-deploy
    name: Confirm deploy commands
    match:
      tool: Bash
      command_glob: "(terraform apply|kubectl apply|helm upgrade).*"
    action: ask
    reason: "Production deployments need human sign-off."
```

`command_glob` matches the full command string via fnmatch. Use
`command_regex` when you need `re.search` semantics (more permissive
partial-match):

```yaml
  - id: deny-exfil
    match:
      tool: Bash
      command_regex: "curl.*--upload-file|curl.*-T "
    action: deny
    reason: "Exfiltration via curl upload."
```

## Step 4: Lock down network

```yaml
network:
  allowed_domains:
    - github.com
    - "*.githubusercontent.com"
    - pypi.org
    - "*.pypi.org"
    - registry.yourcompany.internal
  denied_domains:
    - pastebin.com
    - "*.onion"
  require_https: true
```

Then run mitmdump with the bundled proxy add-on:

```bash
agentgate proxy --policy ./policy.yaml --db ./audit.db --port 8080 &
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

Anything not in `allowed_domains` gets a `403` and a row in the audit log.

## Step 5: Dry-run the policy

Before flipping the switch, run the agent for a few minutes in dry-run:

```bash
AGENTGATE_MODE=dry-run agentgate install-hook -p ./policy.yaml --db ./audit.db
```

In dry-run mode AgentGate records what each decision *would* have been
but never blocks. Inspect the dashboard afterwards to see if your
allow/deny split matches your expectations.

## Step 6: Promote to enforce

```bash
agentgate install-hook -p ./policy.yaml --db ./audit.db
# (default mode = enforce)
```

That's it. AgentGate is now a wall between your agent and your laptop.
