# AgentGate architecture

A single diagram is worth a thousand comments.

## High-level flow

```mermaid
flowchart LR
    A[AI Coding Agent<br/>Claude Code / Cursor / Aider] -->|tool call| H[Hook script<br/>reads stdin]
    H -->|event| E[PolicyEngine<br/>load_policy + match rules]
    E -->|allow| A
    E -->|deny| A
    E -->|ask| N[Notify<br/>Telegram / Slack / file]
    N -->|wait| S[ApprovalServer<br/>HTTP /approve/token]
    S -->|allow/deny| A
    E -->|every event| DB[(SQLite<br/>audit.db)]

    Net[mitmproxy / DNS sinkhole] -->|outbound HTTP| P[proxy_addon]
    P -->|allow| INET[internet]
    P -->|deny| DB

    D[Dashboard<br/>HTTP + SSE] -->|query| DB
    H -->|log| DB
    P -->|log| DB
```

## Component map

```mermaid
graph TB
    subgraph CLI
        CLI[cli/main + 13 subcommands]
    end
    subgraph Hooks
        CC[hook.py - Claude Code]
        CUR[cursor_hook.py - Cursor]
        CONT[continue_hook.py - Continue.dev]
        AID[aider_adapter.py - Aider]
        GH[actions_annotate.py - GitHub Actions]
    end
    subgraph Network
        MITM[proxy_addon.py<br/>mitmproxy]
        DNS[dns_sinkhole.py<br/>UDP server]
    end
    subgraph Approval
        ASTORE[approval.py<br/>SQLite-backed STORE]
        ASVR[approval_server.py<br/>HTTP /approve]
    end
    subgraph Audit
        A1[audit.py<br/>SQLite]
    end
    subgraph Policy
        P1[policy.py<br/>YAML + match]
    end
    subgraph Notify
        NT[notify.py<br/>Telegram / Slack / file]
    end
    subgraph Dashboard
        DASH[dashboard.py<br/>HTTP + SSE + HTML]
    end
    subgraph Hosted
        HOST[hosted.py<br/>pull-policy / push-events]
    end
    CLI --> P1
    CLI --> A1
    CC --> P1
    CC --> A1
    CC --> ASTORE
    CC --> NT
    CUR --> P1
    CONT --> CC
    AID --> P1
    GH --> P1
    MITM --> P1
    MITM --> A1
    DNS --> P1
    ASVR --> ASTORE
    ASTORE --> A1
    NT --> ASVR
    DASH --> A1
    HOST --> A1
    HOST --> P1
```

## Data flow: a tool call that gets denied

```mermaid
sequenceDiagram
    participant User
    participant Agent as Claude Code
    participant Hook as agentgate-hook.py
    participant Policy
    participant Audit as audit.db
    participant User2 as Human

    User->>Agent: "fix the typo"
    Agent->>Hook: PreToolUse event (Bash, "rm -rf /etc")
    Hook->>Policy: evaluate(event)
    Policy-->>Hook: (DENY, deny-rm-rf)
    Hook->>Audit: record(DENY, ...)
    Hook-->>Agent: {"permissionDecision": "deny", "reason": "..."}
    Agent-->>User: tool blocked, reason surfaced
```

## Data flow: ASK round-trip

```mermaid
sequenceDiagram
    participant Agent
    participant Hook
    participant STORE as ApprovalStore (SQLite)
    participant Notify as Telegram / Slack
    participant User
    participant Server as approval_server

    Agent->>Hook: PreToolUse (Bash, "git push origin main")
    Hook->>STORE: request(ask_token)
    STORE-->>Hook: token=abc123
    Hook->>Notify: send(token, rule, event)
    Notify->>User: "Allow/Deny?"
    User->>Server: curl /approve/abc123?d=allow
    Server->>STORE: resolve(token, "allow")
    Hook->>STORE: wait(token, timeout=60s)
    STORE-->>Hook: "allow"
    Hook->>Audit: record(ALLOW, _resolved)
    Hook-->>Agent: {"permissionDecision": "allow"}
```

## Where to add a new adapter

```mermaid
flowchart LR
    A[New agent<br/>e.g. Codex] --> B[Read agent docs]
    B --> C[Add my_agent_hook.py<br/>~50 lines]
    C --> D[Call evaluate_event<br/>from agentgate.hook]
    D --> E[Add CLI install-my-agent-hook<br/>~50 lines]
    E --> F[Add test_my_agent.py]
    F --> G[Update verify.sh step N+1]
```

The whole new adapter is ~100-150 lines of Python + a CLI flag.

## Performance characteristics

| Layer | Latency (typical) | Notes |
|---|---|---|
| Hook (Claude Code → SQLite → response) | <5 ms | One policy.evaluate + one audit.record, both <1 ms |
| Proxy (HTTP → mitmproxy → decision) | <10 ms | Adds one sqlite read per request |
| Dashboard SSE poll | 1 s | Server polls DB every 1s; not event-driven |
| Approval round-trip (ASK) | 1-60 s | Mostly Slack/HTTP latency; configurable timeout |
| Policy load (yaml parse) | <10 ms | YAML parsing once per hook invocation |

The hot path (single tool call decision) is dominated by `sqlite3.connect()`,
which we keep open via a per-call `with` block. For 1000 events/minute this
remains negligible.