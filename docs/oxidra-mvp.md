# Oxidra 个人 CLI Agent 设计

状态：M1-M3 已实现；M5 checkpoint 协议、低权限版本化 summary envelope、真实 Provider `compact_once`、checkpoint-aware Agent projection、受控历史回查、model-aware context 测量/审计、Provider context 超限后的显式 retry/abandon 恢复，以及默认关闭的 `--experimental-auto-compact` preflight 已经实现。当前改动已通过本地 Windows 验证；推送后仍需由 Linux、macOS 和 Windows 远程 CI 重新确认。当前主线定位为个人使用的轻量 coding agent，不包含扩展系统。递归摘要漂移 harness 已实现，但在明确授权的 live 3/5/10 artifact 完成并审阅前，自动 compaction 不会默认启用。

已删除的协议实验代码仅作为历史源码保存在 Git tag `archive/mcp-mvp`，主线不为其保留兼容层或扩展接口。

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
- 可审计全局 memory 与 `remember`。
- `doctor`、`session list/show/delete`。
- Windows 安装脚本与 Release workflow。

暂不实现：

- 扩展系统、插件安装器和 registry。
- Goal mode、默认启用的自动 compaction、sub-agent。M5 的 checkpoint/reducer、真实 Provider 摘要调用、受控历史回查和显式实验入口已进入主线，但默认开关仍关闭。
- TUI、steering/follow-up 队列。
- delete/move 等更多文件工具。

## 2. 项目根与数据目录

项目根规则：

1. 用户提供 `--cwd <DIR>` 时严格使用该目录。
2. 未提供 `--cwd` 时严格使用当前目录，不向上寻找 `.git`。

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
      -> BuiltinTools
      -> Approval policy
      -> Session journal
      -> Context projector
```

Agent 直接持有 `BuiltinTools`，不提供工具注册器、动态工具接口或第三方 ABI。

## 4. Provider

默认配置：

```text
API_KEY       环境变量或独立 credential store
API_BASE_URL  环境变量或 [provider].api_base_url；默认 https://api.openai.com/v1
MODEL         环境变量或 [provider].model；默认 gpt-5.6-sol
```

用户配置文件位于平台用户配置目录的 `oxidra/config.toml`；Windows 为 `%APPDATA%\oxidra\config.toml`。该文件只保存非秘密设置。`[auth].credential_store` 默认为 `keyring`，使用操作系统凭据存储；显式配置 `file` 时才使用同目录的明文 `auth.json`。提供 `auth login/status/logout` 管理凭据。

持久凭据只支持一个活动 Provider，并绑定到规范化后的 API base URL；URL 变化后拒绝使用旧 key。环境变量优先于持久配置。兼容回退组为 `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`OPENAI_MODEL`，三者作为整组使用，不与主环境变量组交叉拼接。

旧版 `[provider].api_key` 字段不再接受；迁移时先从 `config.toml` 删除该字段，再执行 `oxidra auth login`。

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

只允许解析后仍位于项目根内的 canonical path；相对路径中的 `..`、项目根内的绝对路径都按最终 canonical 结果判断，拒绝符号链接或绝对路径逃逸。单文件上限 16 MiB，默认返回最多 2000 行或 50 KiB。

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

journal 是本地 append-only JSONL，是会话真相源。API 始终 `store: false`。当前恢复重放原始 projection；M5 完成后从同一份完整 journal 重建并使用经校验的原始 projection 或最新 checkpoint + tail，不修改旧事件。

结构化消息角色也属于重放契约：Provider output message 只能以 `assistant` 提交，journal 中的 user item 只能以 `user` 重放；缺失或伪造 `developer/system` role 时停止，而不是把不可信结构原样发送给下一次请求。

关键事件：

```text
session.started
user.message
response.started / completed / aborted / failed
tool.started / completed / cancelled
tool.in_doubt / tool.in_doubt_resolved
agent.stalled / agent.limit_reached
context.limit_reached
turn.completed
compaction.started / compaction.checkpoint / compaction.failed / compaction.aborted
```

- 关键事件 flush/sync。
- session lock 防止两个进程同时写。
- 不完整尾行作为崩溃尾巴恢复。
- 只有 `tool.started` 的调用恢复为 `in_doubt`，用户检查后才能继续。
- journal 永远保留完整历史，projection 可替换。
- `session.started` 保存创建它的 Oxidra Cargo 版本；旧 header 缺字段时显示为 `pre-v0.1`。

### 派生 instructions 契约

Oxidra 采用完整输入契约：journal 必须记录模型实际看到的所有 instructions，而不只记录 item 流。

- 每次进程启动，包括新建 session 和每次 `--resume`，都追加一条 `context.instructions` 事件。
- 事件保存本次拼好的完整 instructions：基础 prompt、当前 `AGENTS.md`，以及启用记忆后注入的当前 memory。
- `AGENTS.md` 与 memory 都是活文档；resume 使用它们的当前版本，不复活旧版本。
- journal 中每个 epoch 的全文快照负责审计和重建“当时模型看到了什么”。不另设 hash、version 或只覆盖单一来源的漂移机制。
- `session show` 应能直接展示这些快照；projection 只使用当前 epoch 的 instructions，不能把历史快照重复注入模型。

## 9. Context

当前发布行为提供默认关闭的实验入口 `--experimental-auto-compact`。M5 已实现 turn 边界、checkpoint reducer、低权限 `role: "user"` summary envelope、六类不可变版本注册表、checkpoint + tail projection、真实 Provider `compact_once`、受控历史回查、model-aware 测量基础，以及 Provider context 超限后的恢复。实验入口在估算达到 trigger 时为当前 user turn 最多执行一次压缩；不开启时行为与之前相同。

默认：

```text
context_window = 128000
reserve_tokens = 16384
```

可通过 CLI、环境变量、精确 model 配置或全局用户配置覆盖，优先级依次为 CLI > 环境变量 > `[context.models."<exact-model>"]` > `[context]` > 内置默认。`OXIDRA_CONTEXT_WINDOW`、`OXIDRA_RESERVE_TOKENS` 是环境变量入口；CLI 对应 `--context-window`、`--reserve-tokens`。reserve 必须小于 window。

每次启动追加 `context.configured`，记录实际 model、Provider usage domain、window/reserve/usable/trigger/target、字段来源和测量协议版本。每个启动 epoch 与 tools schema 变化时追加 `context.tools`；每次 `response.started` 保存完整 prepared-request digest、序列化请求字节数、确定性估算、journal/checkpoint/instructions/tools 引用和 usage anchor 差分。存在可比较的上一普通 response 时，下一次输入估算使用真实 `input_tokens + E(current) - E(anchor)`；cached tokens 不扣除。无可比较 usage 时才从零估算完整请求。anchor 产生非正值或异常漂移时回退完整请求估算，不 clamp 为 `0`。

当前没有 model tokenizer 或 Provider 计数接口，因此估算只用于显示、审计和显式启用的 compaction planning，不能作为普通请求的 token hard limit。实验开关开启且估算达到 trigger 时，Agent 先同步 boundary intent，再从同一 journal/config 快照为安全 cutoff 构造完整 summary-budget + tail 请求；候选估算包含当前 instructions、实际 tools/history schema 和与 8192 输出上限对应的估算器占位预算，真实 summary 返回后还会按同一 prepared-request/usage-anchor 语义重建，只有达到 target 才提交 checkpoint。同一 user turn 最多自动压缩一次；无候选、Provider 失败或真实 summary 仍超 target 都停止当前请求，不发送原大请求。Provider attempt 已 durable 的失败可由 `--retry-pending` 重放；尚未产生 candidate/attempt 的 preflight-only failure 也由 `--retry-pending` 重新规划，或显式 abandon。planning v1 使用冻结 reader 和字面量 fixture，只把旧 context 当成 lineage 审计证据；resume 时必须按当前 model/context 配置、instructions、tools 和 history view 重新构造完整请求并测量。若当前请求已低于 trigger，boundary v5 要求 retry intent 中的 planning-v1 prefix、estimate 和 trigger 与随后同步的 `compaction.boundary.resolved_without_checkpoint` 逐字段一致，并证明未启动 compaction Provider attempt、slot 仍为 `Ready` 且 `estimate < trigger`；随后不调用 compaction Provider、不生成 checkpoint、不复制 user message，直接继续原 turn。resolution fsync 后崩溃时，`--retry-pending` 复用同一 durable resolution 继续 normal Provider request。不开启实验开关时，普通请求仍直接交给 Provider。Provider 返回受识别的结构化 context-limit 错误时，Oxidra 写入 `response.failed` + `context.limit_reached`，禁止继续追加新 prompt。`--retry-pending --resume <ID>` 从一份 journal snapshot 生成版本化恢复计划：若同 turn 同时存在 context pending 与 failed compaction boundary，先恢复 boundary；历史 durable candidate 按事件记录的协议版本重放；retry intent、compaction Provider 调用和 checkpoint commit 之前，先验证 prospective boundary/turn/slot、checkpoint chain、实际 history snapshot、quota、tools 与后续请求测量。纯 context-limit 同步版本化 `turn.retry_started`；处于 `Ready` Provider slot 的 checkpointed 或 resolved-without-checkpoint boundary 继续原 turn；有 durable candidate 的 failed boundary 同步 `compaction.boundary.retry_started` 后重放压缩。replacement retry intent 同步后、candidate planning 前崩溃时，session reopen 会把孤立 boundary 结算为 failed，下一次 retry 可沿同一 lineage 继续。对于 `55e5b0c` 已写出的 `checkpointed -> agent.limit_reached` 污染状态，只有在当前 `--max-responses` 已提高到大于 durable dispatch 数或被关闭时，才同步原子的 `compaction.boundary.budget_retry_started`：它严格引用旧 limit、旧 boundary 与同一 checkpoint，把 boundary v3 升到 v4。boundary v4、turn validator v5 和 Provider request-slot reducer v2 共同消费一个从 durable prefix 完整验证 lineage、无版本旧 terminal、dispatch 数与恢复状态的 canonical migration 结果；带未知 `provider_call_budget_version` 的 terminal 不会被当成 legacy。boundary v4 还把 turn metadata compatibility ceiling 固定为 v5，因此未来 turn 版本不会追溯改变旧 boundary 的读取语义。旧 turn v4、slot v1 与 boundary v3 的历史结果不变。checkpointed 后的其他 terminal outcome 尚无同 turn retry 协议，必须显式 abandon；Agent 在追加新 `response.started` 前拒绝非法重试。`--abandon-pending --resume <ID>` 同时处理两类 pending，允许用户随后提交替代 prompt；所有路径都复用原 user message，不写第二份。turn validator v3 严格校验 `user < limit < control`、response attempt 绑定、状态和唯一性，并与 source projection v3 一起 supersede latest retry 之前的完整 attempt 终态；v4 只修正 legacy completion evidence 的时序，v5 只消费经过严格引用的 budget migration。历史 turn validator v1-v4、source projection v1-v3、Provider request-slot reducer v1 与 compaction boundary v1-v4 按首次登记语义重建，不会被新版本原地改写。source projection v4 首次消费 canonical boundary chain，并从 summary source 中排除已验证 abandoned turn。boundary v2 首次用独立 request-slot reducer v1 逐事件验证 response/tool 因果顺序；boundary v3 在同一固定 slot policy 之上建立不可降级的 session epoch并要求退出连续性；boundary v4 固定承载 legacy budget migration；当前 writer 使用 boundary v5 与固定 turn validator v5、slot reducer v2 和 turn metadata ceiling v5。普通 retry 只能保持或升级协议版本，v3 的 legacy budget migration另有唯一的 `v3 checkpointed -> v4 checkpointed` 原子转换。history extractor v4、当前 Provider projection 与 source projection v4 都会排除已验证的 compaction-boundary abandoned turn；历史 source v1-v3 checkpoint 若跨过这类 turn仍 fail closed，新 v4 checkpoint 可以安全跨越。

每次新建或 resume 都以当前解析出的 provider/model/context、当前 `AGENTS.md`/memory 和当前内置 tools 为运行真相；journal 中历史配置与 instructions 快照只供审计，不反向恢复旧配置。API key 等秘密不写 journal。

## 10. CLI

```text
oxidra
oxidra -p "修复测试"
oxidra --resume <session-id>
oxidra doctor
oxidra auth login
oxidra auth status
oxidra auth logout
oxidra session list
oxidra session show <session-id>
oxidra session delete <session-id>
```

常用参数：

```text
--cwd <DIR>
--model <MODEL>
--full-auto
--max-responses <N>
--max-tools <N>
--experimental-auto-compact
```

`session delete` 永久删除对应 journal 与 artifact 目录；删除前获取 session 独占锁，因此不能删除正在使用的 session。目标不存在时返回成功并明确报告。

`--max-responses` 是从 journal 归约的每个 logical turn 的保守 Provider dispatch-intent 预算。普通 `response.started` 和绑定该 turn boundary 的 `compaction.started` 都占用额度，失败、取消和崩溃恢复后的 attempt 也不会退还；因此同一上限下显式 retry 不能重置保险丝。resume 仍以当前配置为真，用户提高上限后可继续剩余额度。若 compaction boundary 正在拥有恢复权，额度耗尽只由 durable dispatch intent 与当前配置推导，不追加会把 turn 永久终结的 `agent.limit_reached`，从而允许提高上限后继续该 boundary。对旧版本已经写出的 checkpointed + `agent.limit_reached`，`--retry-pending` 在提高或关闭当前额度后写入版本化 budget migration，继承原 checkpoint 和原 user message，无损继续；原上限未提高时 journal 保持不变。可见的 response 数量不包含内部 compaction 调用，但同一进程成功完成的 `TurnOutcome.usage` 会累计 checkpoint 返回的 compaction usage。

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
- Provider context-limit 错误会形成可恢复 pending turn；估算器不会被当作本地 hard limit。
- Windows、Linux、macOS 执行 fmt、test、Clippy。

## 12. 后续里程碑

### M2：回合末 UI（已实现）

- 新建 `render.rs`，集中纯显示逻辑。
- 累计一个 turn 内全部 Responses 的 usage。
- 回合结束显示 model、token 和下一次请求的 context 估算。
- edit diff 仅在交互式 stderr TTY 中着色；`-p`、管道和 CI 保持纯文本。
- 不实现常驻状态条，不引入终端 UI 依赖。

### M3：可审计记忆（已实现）

- memory 默认全局注入；provenance 只用于审计，不参与当前选择或排序，也不建立项目/session 作用域。
- remember 写入持久文件前必须获得用户确认；--full-auto 不绕过这一确认。
- remember 写入的文件只含 project_root 与 created 两个 frontmatter 字段；用户手写的无 frontmatter 文件按 provenance unknown 处理。
- frontmatter 使用每行 splitn(2, ':') 解析；Windows 盘符和 ISO 时间中的冒号必须完整保留。
- 注入前剥离 frontmatter，只把正文交给模型；memory list/show 显示 provenance。
- 64 KiB 文件上限在 frontmatter 与正文完整拼接后检查。
- 注入预算为 16 KiB；按文件 mtime 从新到旧遍历（mtime 相同按 ID 倒序），整条能放下才加入，放不下的整条跳过并在 stderr 报告未注入数量。
- 16 KiB 装箱预算只累计正文，不计算 frontmatter 或渲染包装。
- 不做 LLM 摘要、相关性排序或隐式重写；同一批文件在相同 mtime/id 下得到相同注入文本。
- 用户数据目录下使用有界、明文、可删除的 `memory/*.md`。
- 提供 `remember`，并提供 `memory list/show/forget` 管理命令。
- memory 与 `AGENTS.md` 同属活的派生 instructions；每次新建或 resume 都读取当前内容。
- 本次完整注入文本统一写入 `context.instructions`，不只保存引用、hash 或版本号。
- journal 保存的是每个启动 epoch 的输入快照；memory 文件仍是当前可编辑的真相源。

### M5 及以后

M4 与 M5 的完整实施契约见 [`m4-m5-roadmap.md`](m4-m5-roadmap.md)。

1. M5 checkpoint 核心、真实 Provider `compact_once`、受控历史回查、model-aware 配置、prepared-request usage-anchor 测量、Provider context-limit retry/abandon、compaction request-boundary v1-v5、不可变版本 policy、版本化 request-slot reducer、旧 budget terminal 兼容迁移、bound Provider 调用、session-open 恢复、Agent/CLI pending 管理、projection/history abandon 语义，以及默认关闭的自动 compaction preflight 实验入口已经实现。legacy budget migration 和 no-checkpoint resolution 都有 fsync 后强杀、由新 CLI 进程继续同一 prompt 的测试，恢复不会重复追加 intent、resolution、checkpoint 或原 user message。
2. 已加入 `examples/compaction_drift.rs` 与 frozen fixture，按 production prompt、低权限 envelope、无 tools 和 8192 输出上限运行 3/5/10 次真实递归摘要，逐轮保存 raw response、usage、summary hash 和事实保留指标。live run 需要显式 `--confirm-live-calls`；仓库不伪造离线结果。只有实际 artifact 数据支持时才默认启用自动 compaction。
3. M4：每会话 token/执行时间预算按实际使用数据推迟，后续作为独立里程碑。
4. 只有实际高频需要时才重新评估子 agent；它必须使用独立子会话，并受父级预算约束。
