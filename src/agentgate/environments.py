"""Multi-policy environment manager.

Stores named policy references in `~/.agentgate/environments.yaml`:

    environments:
      dev:
        policy: ./policies/dev.yaml
        db: ./audit-dev.db
      staging:
        policy: ./policies/staging.yaml
        db: ./audit-staging.db
      prod:
        policy: ./policies/prod.yaml
        db: ./audit-prod.db
        require_approval: true

`agentgate policy use <env>` writes the chosen env's paths into
`AGENTGATE_POLICY` / `AGENTGATE_DB` for the current shell (via a
sourced env file at `~/.agentgate/active.env`), and prints the
`export` lines so you can `eval` them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path.home() / ".agentgate" / "environments.yaml"
ACTIVE_ENV_FILE = Path.home() / ".agentgate" / "active.env"


@dataclass
class Environment:
    name: str
    policy: str
    db: str
    require_approval: bool = False
    mode: str = "enforce"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "db": self.db,
            "require_approval": self.require_approval,
            "mode": self.mode,
            "notes": self.notes,
        }


@dataclass
class EnvironmentStore:
    environments: dict[str, Environment] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> EnvironmentStore:
        p = Path(path or CONFIG_PATH)
        if not p.exists():
            return cls()
        raw = yaml.safe_load(p.read_text()) or {}
        envs = {}
        for name, cfg in raw.get("environments", {}).items():
            envs[name] = Environment(
                name=name,
                policy=cfg.get("policy", ""),
                db=cfg.get("db", ""),
                require_approval=bool(cfg.get("require_approval", False)),
                mode=cfg.get("mode", "enforce"),
                notes=cfg.get("notes", ""),
            )
        return cls(environments=envs)

    def save(self, path: str | Path | None = None) -> None:
        p = Path(path or CONFIG_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        out = {
            "environments": {n: e.to_dict() for n, e in self.environments.items()}
        }
        p.write_text(yaml.safe_dump(out, sort_keys=False))

    def get(self, name: str) -> Environment:
        if name not in self.environments:
            raise KeyError(
                f"unknown environment {name!r}; "
                f"defined: {list(self.environments)}"
            )
        return self.environments[name]

    def set(self, env: Environment) -> None:
        self.environments[env.name] = env

    def unset(self, name: str) -> None:
        self.environments.pop(name, None)

    def use(self, name: str) -> Environment:
        """Mark `name` as the active environment. Returns it.

        Writes ~/.agentgate/active.env so other tools / wrappers can
        source it. The caller is expected to also `eval` the printed
        export lines for the current shell.
        """
        env = self.get(name)
        ACTIVE_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        ACTIVE_ENV_FILE.write_text(
            f'export AGENTGATE_POLICY="{env.policy}"\n'
            f'export AGENTGATE_DB="{env.db}"\n'
            f'export AGENTGATE_MODE="{env.mode}"\n'
            f'export AGENTGATE_ENV="{env.name}"\n'
        )
        return env

    def active_name(self) -> str | None:
        if not ACTIVE_ENV_FILE.exists():
            return None
        for line in ACTIVE_ENV_FILE.read_text().splitlines():
            if line.startswith("export AGENTGATE_ENV="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
        return None
