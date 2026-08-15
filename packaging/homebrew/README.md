# AgentGate Homebrew Tap

This is a [Homebrew tap](https://docs.brew.sh/Taps) for
[AgentGate](https://github.com/FelixMa01/agentgate) — the firewall
for AI coding agents.

## Install

```sh
brew tap FelixMa01/agentgate
brew install agentgate
```

## Verify

```sh
agentgate --version
agentgate doctor
```

## Upgrade

```sh
brew update
brew upgrade agentgate
```

## Unlink / Uninstall

```sh
brew uninstall agentgate
brew untap FelixMa01/agentgate
```

## Repository layout

- `Formula/agentgate.rb` — the formula
- `Formula/agentgate@0.13.rb` — pinned older formula (optional)

The tap repo is hosted at <https://github.com/FelixMa01/homebrew-agentgate>.