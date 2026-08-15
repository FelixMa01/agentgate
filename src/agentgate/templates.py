"""Built-in policy templates for common deployment shapes.

Loaded via ``agentgate init --template <name>``. Each template is a
self-contained policy.yaml that the user can edit. The templates are
shipped as a flat module so they are importable even when no policy
file exists yet.

Templates:
- ``yolo`` — default allow, only block known-dangerous patterns
- ``enterprise`` — default deny, allowlist common dev tools
- ``airgapped`` — no network, no destructive Bash, read-only file tools
- ``ci-cd`` — GitHub Actions runner: allow GitHub API, no sudo, log everything
- ``pair-programming`` — ask for any non-read, auto-allow read/write inside repo
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Template:
    name: str
    description: str
    yaml: str


YOLO = Template(
    name="yolo",
    description="Permissive: only block known-dangerous commands.",
    yaml="""\
version: 1
default: allow

rules:
  - id: deny-rm-rf-root
    match: {tool: Bash, command_regex: "rm\\\\s+-[rf]+\\\\s+/(?:$|\\\\s)"}
    action: deny
    reason: "Deleting from root is never OK"

  - id: deny-fork-bomb
    match: {tool: Bash, command_regex: ":\\\\(\\\\)\\\\{[^}]*\\\\}:|curl[^|]*\\\\|\\\\s*(?:ba)?sh" }
    action: deny
    reason: "Possible fork bomb or piped shell"

  - id: deny-disable-perms
    match: {tool: Bash, command_regex: "--dangerously-skip-permissions|chmod\\\\s+-R\\\\s+777" }
    action: deny
    reason: "Disabling safety controls"

network:
  default: allow
  require_https: true
""",
)


ENTERPRISE = Template(
    name="enterprise",
    description="Default deny. Allowlist dev tools + known domains.",
    yaml="""\
version: 1
default: deny

rules:
  # ---- read-only tools, always safe ----
  - id: allow-read
    match: {tool: Read}
    action: allow
  - id: allow-glob
    match: {tool: Glob}
    action: allow
  - id: allow-grep
    match: {tool: Grep}
    action: allow

  # ---- writes go through human review ----
  - id: ask-write
    match: {tool: Write}
    action: ask
  - id: ask-edit
    match: {tool: Edit}
    action: ask

  # ---- bash: allow safe subset, ask on the rest ----
  - id: allow-bash-readonly
    match: {tool: Bash, command_regex: "^(?:ls|cat|head|tail|wc|grep|which|echo)\\\\b"}
    action: allow
  - id: allow-bash-git-read
    match: {tool: Bash, command_regex: "^git\\\\s+(?:status|log|diff|show|branch)\\\\b"}
    action: allow
  - id: ask-bash-anything-else
    match: {tool: Bash}
    action: ask

  # ---- destructive always denied ----
  - id: deny-rm-rf
    match: {tool: Bash, command_regex: "rm\\\\s+-[rf]+\\\\s+(?!/tmp|node_modules|\\\\.git)"}
    action: deny
  - id: deny-sudo
    match: {tool: Bash, command_regex: "\\\\bsudo\\\\b"}
    action: deny
  - id: deny-curl-pipe
    match: {tool: Bash, command_regex: "curl[^|]*\\\\|\\\\s*(?:ba)?sh|wget[^|]*\\\\|\\\\s*(?:ba)?sh"}
    action: deny

network:
  default: deny
  require_https: true
  allowed_domains:
    - "*.github.com"
    - "*.anthropic.com"
    - "*.openai.com"
    - "registry.npmjs.org"
    - "pypi.org"
    - "files.pythonhosted.org"
""",
)


AIRGAPPED = Template(
    name="airgapped",
    description="No network, no destructive Bash, read-only file tools.",
    yaml="""\
version: 1
default: deny

rules:
  - id: allow-read
    match: {tool: Read}
    action: allow
  - id: allow-glob
    match: {tool: Glob}
    action: allow
  - id: allow-grep
    match: {tool: Grep}
    action: allow

  - id: deny-write
    match: {tool: Write}
    action: deny
    reason: "Airgapped: no writes"
  - id: deny-edit
    match: {tool: Edit}
    action: deny
    reason: "Airgapped: no edits"

  - id: deny-bash-network
    match: {tool: Bash, command_regex: "\\\\b(?:curl|wget|nc|ncat|scp|rsync|ssh)\\\\b"}
    action: deny
    reason: "Airgapped: no network tools"
  - id: ask-bash-anything-else
    match: {tool: Bash}
    action: ask

network:
  default: deny
""",
)


CI_CD = Template(
    name="ci-cd",
    description="GitHub Actions runner. Allow GitHub API, no sudo, log everything.",
    yaml="""\
version: 1
default: allow

rules:
  - id: deny-sudo
    match: {tool: Bash, command_regex: "\\\\bsudo\\\\b"}
    action: deny
  - id: deny-secrets-write
    match: {tool: Bash, command_regex: "\\\\b(?:cp|mv|cat|tee)\\\\b[^\\\\n]*(?:\\\\$GITHUB_TOKEN|\\\\.npmrc|\\\\.pypirc|id_rsa)"}
    action: deny
    reason: "Don't leak CI secrets"
  - id: deny-fork-bomb
    match: {tool: Bash, command_regex: ":\\\\(\\\\)\\\\{[^}]*\\\\}:"}
    action: deny

  - id: log-everything
    match: {}
    action: log
    reason: "CI runs must produce a full audit trail"

network:
  default: allow
  require_https: true
  allowed_domains:
    - "*.github.com"
    - "*.githubusercontent.com"
    - "registry.npmjs.org"
    - "pypi.org"
    - "files.pythonhosted.org"
""",
)


PAIR_PROGRAMMING = Template(
    name="pair-programming",
    description="Ask on anything non-read, auto-allow reads/writes inside repo.",
    yaml="""\
version: 1
default: ask

rules:
  - id: allow-read-anywhere
    match: {tool: Read}
    action: allow
  - id: allow-glob-anywhere
    match: {tool: Glob}
    action: allow
  - id: allow-grep-anywhere
    match: {tool: Grep}
    action: allow

  # writes inside repo dir don't need approval
  - id: allow-write-in-repo
    match: {tool: Write, file_regex: "^\\\\./[^/]*"}
    action: allow
    when: 'event.cwd.startswith("/home/user/projects/")'
  - id: ask-write-elsewhere
    match: {tool: Write}
    action: ask

  - id: deny-rm-rf
    match: {tool: Bash, command_regex: "rm\\\\s+-[rf]+"}
    action: deny

  - id: allow-bash-safe
    match: {tool: Bash, command_regex: "^(?:ls|cat|head|tail|wc|grep|echo|which)\\\\b"}
    action: allow
  - id: ask-bash-rest
    match: {tool: Bash}
    action: ask

network:
  default: allow
  require_https: true
""",
)


_TEMPLATES: list[Template] = [YOLO, ENTERPRISE, AIRGAPPED, CI_CD, PAIR_PROGRAMMING]


def list_templates() -> list[Template]:
    return list(_TEMPLATES)


def get_template(name: str) -> Template | None:
    for t in _TEMPLATES:
        if t.name == name:
            return t
    return None


def render_template(name: str, path: str | None = None) -> str:
    """Return the YAML body for ``name``. If ``path`` is given, prepend a
    comment header pointing to it."""
    t = get_template(name)
    if t is None:
        names = ", ".join(t.name for t in _TEMPLATES)
        raise ValueError(f"unknown template {name!r} (known: {names})")
    header = f"# Generated by `agentgate init --template {name}`\n"
    header += f"# {t.description}\n"
    if path:
        header += f"# Written to: {path}\n"
    header += "\n"
    return header + t.yaml
