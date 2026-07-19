# Oxidra 个人 CLI Agent 设计

状态：M1 已实现。Windows、Linux、macOS CI 通过。当前主线定位为个人使用的轻量 coding agent，不维护第三方插件生态。

历史 MCP 实验实现保存在 Git tag `archive/mcp-mvp`。它不属于当前产品范围；未来只有出现真实扩展需求时，才按届时正式协议重新评估。

## 1. 产品边界

当前必须稳定工作的闭环：

```text
用户输入
  -> OpenAI Responses API 流式响应
  -> read / edit / write / shell
  -> 工具结果回填模型
  -> 实际运行验证
  -> append-only session journal
```

包含：

- 交互式 REPL 与 `-p` 单次模式。
- Responses SSE 实时文本与工具调用过程展示。
- Ctrl+C 取消当前 LLM 请求或工具进程。
- Windows Job Object、Unix process group 的进程树清理。
- 本地 session journal 与 `--resume`。
- `doctor`、`session list/show`。
- Windows 安装脚本与 Release workflow。

暂不实现：

- 第三方工具协议、插件安装器和 registry。
- Goal mode、compaction、sub-agent。
- TUI、steering/follow-up 队列。
- delete/move 等更多文件工具。

## 2. 项目根与数据目录

项目根规则：

1. 用户提供 `--cwd <DIR>` 时严格使用该目录。
2. 否则从当前目录向上寻找最近的 `.git`。
3. 找不到 `.git` 时使用当前目录。

文件工具只能访问项目根内部。项目级 `AGENTS.md` 最大读取 32 KiB，只能提供编码与工作流约定，不能改变根目录、动作授权、模型或 CLI 限制。

用户数据不写入项目：

- Windows：`%LOCALAPPDATA%/oxidra`
- macOS：`~/Library/Application Support/oxidra`
- Linux：`$XDG_STATE_HOME/oxidra`，否则 `~/.local/state/oxidra`

## 3. 核心架构

```text
CLI
  -> Agent loop
      -> Responses provider
      -> Builtin ToolExecutor
      -> Approval policy
      -> Session journal
      -> Context projector
```

Rust traits 是内部实现契约，不承诺第三方 Rust ABI。外部扩展系统当前不存在。

## 4. Provider

默认配置：

```text
API_KEY       必需
API_BASE_URL  默认 https://api.openai.com/v1
MODEL         默认 gpt-5.6-sol
```

兼容回退组为 `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`OPENAI_MODEL`。两组配置不交叉拼接。

请求固定使用：

```text
POST {API_BASE_URL}/responses
stream: true
store: false
```

### 流与提交

- delta 只展示，不进入 canonical history。
- `response.completed` 后才提交完整原始 output items。
- 未完成响应记录 `response.aborted`，partial text 不参与重放。
- 首个 SSE 事件前的可重试传输错误最多重试 3 次。
- 首个事件后断流不自动重试，避免重复未知工具调用。

## 5. Agent loop

- 一个用户输入开启一个 turn。
- 同一 response 的多个工具调用按顺序执行。
- 工具错误作为结构化结果回填模型。
- Ctrl+C 后，未执行调用标记为跳过。
- `--max-responses`、`--max-tools` 是用户显式保险丝，默认关闭。
- 同一工具、规范化参数和稳定错误结果连续出现 3 次时记录 `agent.stalled` 并暂停。
- 错误 fingerprint 排除 `duration_ms` 等观测字段，避免相同失败因耗时变化绕过熔断。

工具调用不是事务。进程中断无法撤销已发生的文件或外部副作用，因此未知副作用绝不自动重试。

## 6. 内置工具

### read

```text
path, offset?, byte_offset?, limit?
-> text, full_file_sha256, range, truncated?
```

只允许项目根内 canonical path；拒绝 `..`、绝对路径和符号链接逃逸。单文件上限 16 MiB，默认返回最多 2000 行或 50 KiB。

### edit

```text
path, old_text, new_text, expected_sha256
-> replaced_count, new_sha256
```

- `old_text` 必须恰好匹配一次。
- hash 变化返回 `stale_file`。
- 同目录临时文件加原子替换，并保留权限。
- 执行前在 stderr 展示精确 replacement diff。

### write

```text
path, content
-> path, bytes, sha256
```

只创建新的 UTF-8 文件，拒绝覆盖。父目录必须存在，内容上限 16 MiB。同目录写临时文件并同步后，以 no-clobber 方式发布；文件系统不支持安全发布时明确失败。

### shell

```text
command, timeout?
-> exit_code, stdout, stderr, hashes, duration_ms, artifact?
```

- Windows 使用 `powershell.exe -NoProfile -NonInteractive`。
- Unix 使用 `/bin/sh -lc`。
- 默认每条命令确认；`--full-auto` 仅对本次进程关闭确认。
- 默认超时 120 秒。
- 返回模型的输出上限为 2000 行或 50 KiB，完整超限输出写入 artifact。
- Ctrl+C 终止整个进程树。

## 7. 动作授权与边界

| 动作 | 默认行为 |
|---|---|
| `read` | 项目根内自动执行 |
| `edit` | 项目根内自动执行 |
| `write` | 项目根内自动执行，禁止覆盖 |
| `shell` | 每条命令确认 |
| `--full-auto` | 本次进程内自动执行 shell |

`--full-auto` 只改变动作批准，不关闭路径边界、取消、超时、重复错误熔断、context 限制或未知副作用恢复规则。

## 8. Session journal

journal 是本地 append-only JSONL，是会话真相源。API 始终 `store: false`，恢复时手动重放完整历史。

关键事件：

```text
session.started
user.message
response.started / completed / aborted / failed
tool.started / completed / cancelled
tool.in_doubt / tool.in_doubt_resolved
agent.stalled / agent.limit_reached
context.limit_reached
```

- 关键事件 flush/sync。
- session lock 防止两个进程同时写。
- 不完整尾行作为崩溃尾巴恢复。
- 只有 `tool.started` 的调用恢复为 `in_doubt`，用户检查后才能继续。
- journal 永远保留完整历史，projection 可替换。

## 9. Context

MVP 不实现 compaction。

默认：

```text
context_window = 128000
reserve_tokens = 16384
```

可通过用户配置或 `OXIDRA_CONTEXT_WINDOW`、`OXIDRA_RESERVE_TOKENS` 覆盖。估算接近 `context_window - reserve_tokens` 时返回 `context_limit` 并记录事件，不静默截断。

## 10. CLI

```text
oxidra
oxidra -p "修复测试"
oxidra --resume <session-id>
oxidra doctor
oxidra session list
oxidra session show <session-id>
```

常用参数：

```text
--cwd <DIR>
--model <MODEL>
--full-auto
--max-responses <N>
--max-tools <N>
```

stdout 只承载 assistant 文本；工具状态、diff、确认、诊断和错误写 stderr。

## 11. 验收

最小验收：

1. `read` 读取故意写错的 `calc.py`。
2. `edit` 把 `a - b` 改为 `a + b`，并展示 diff。
3. `shell` 执行 `python calc.py`。
4. `python calc.py | grep -q '^8$'` 成功。

自动化还必须验证：

- SSE delta 在 `response.completed` 前可见。
- Ctrl+C 取消 LLM 和 shell 进程树。
- `--resume` 重放完整 output items，包括 encrypted reasoning 与 phase。
- 路径逃逸被拒绝。
- 相同失败 shell 的 `duration_ms` 不会绕过重复错误熔断。
- 默认 context 限制实际启用。
- Windows、Linux、macOS 执行 fmt、test、Clippy。
