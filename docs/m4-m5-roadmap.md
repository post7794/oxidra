# Oxidra M4/M5 实施规划

状态：设计基线，尚未实现。

本文只规划两个后续里程碑：

- M4：每 session 的 token 与执行时间预算。
- M5：自动 compaction 与可审计 checkpoint。

它们的共同目标不是增加 Agent 能力，而是让长任务拥有明确的资源上限和可恢复的上下文。实现必须继续遵守现有契约：本地 journal 是 append-only 真相源，Responses API 使用 `store: false`，已提交的原始事件永不因 projection 或 compaction 被修改、覆盖或删除。

## 1. 不可破坏的底层契约

1. **journal 与 projection 分离。** journal 保存发生过的完整事实；projection 只决定下一次请求向模型重放哪些内容。
2. **Provider usage 是 token 记账依据。** `total_tokens` 已包含 input 与 output；cached input 和 reasoning output 是子项，不能重复相加。
3. **已知完成后才提交。** 流式 delta 不写 canonical history；未完成的普通 response 或 compaction response 不参与之后的 projection。
4. **未知工具副作用不自动重试。** 预算超限或 compaction 都不能绕过现有 `in_doubt` 恢复规则。
5. **不静默丢历史。** compaction 失败、无可压缩前缀或压缩后仍超限时，明确停止并写 journal，绝不按字符或条数偷偷截断。
6. **`--full-auto` 只改变 shell 授权。** 它不能关闭预算、context 限制、compaction 校验或恢复检查。
7. **管理成本服从个人工具定位。** M4 新建 `budget.rs`，M5 新建 `compaction.rs`；不引入插件接口、后台守护进程、数据库或 TUI。

## 2. M4：Session 预算保险丝

### 2.1 目的与非目标

M4 防止一次 session 因循环、长时间命令或连续模型调用无限消耗资源。它是硬保险丝，不是任务规划器，也不判断目标是否完成。

M4 不实现：

- Goal mode 或无人值守任务队列。
- 按美元计费。模型价格和兼容 Provider 价格会变化，不能把估算金额当真相源。
- 精确的远端账单对账。`store: false` 下，进程若在远端完成后、本地落盘前崩溃，该次费用无法可靠恢复。
- 每 turn 独立预算或全局每日配额。MVP 只做每 session 累计预算。

### 2.2 默认值与配置

新 session 默认启用两条高位保险丝：

```toml
[budget]
max_tokens = 1000000
max_active_seconds = 7200
```

- `max_tokens`：该 session 所有已完成普通 response 和 compaction response 的累计 `total_tokens`。
- `max_active_seconds`：LLM 请求与工具实际执行的累计墙钟时间。REPL 等待输入、等待 shell/remember 确认、进程关闭期间不计时。
- 默认值的定位是阻止失控，不是建议消费目标。

CLI 覆盖：

```text
--max-session-tokens <N>
--max-session-seconds <N>
--no-session-budget
```

所有数值必须为正整数。`--no-session-budget` 必须显式提供，不能与两个上限参数同时使用；它会作为配置变更写入 journal，不能由 `--full-auto` 暗中触发。

配置优先级：

```text
本次 CLI 显式覆盖 > session 已保存预算 > 用户 config.toml > 内置默认值
```

新 session 在 `session.started` 后追加 `budget.configured`。resume 默认沿用该 session 最近一次保存的预算，不因用户配置文件后来变化而静默改变。resume 时显式传入新上限或 `--no-session-budget`，追加 `budget.reconfigured`。旧 session 没有预算事件时，在第一次 resume 应用当前默认值并追加配置事件。

建议事件数据：

```json
{
  "kind": "budget.configured",
  "data": {
    "max_tokens": 1000000,
    "max_active_ms": 7200000,
    "source": "builtin_default"
  }
}
```

### 2.3 Token 记账

预算状态从 journal 重建，不维护第二份可漂移的 sidecar：

- 普通调用累计 `response.completed.data.usage.total_tokens`。
- M5 调用累计 `compaction.checkpoint.data.usage.total_tokens`。
- cached input 不从 total 中扣除，也不再次加入。
- aborted/failed response 若没有 Provider usage，不能猜测成精确值；session 展示的累计值是“已提交、Provider 已报告”的下界。

成功 response 若 Provider 完全不返回 usage，预算开启时必须追加 `budget.accounting_failed` 并停止，不允许把缺失值当成 0 后继续执行工具。使用不提供 usage 的兼容 Provider 时，用户只能显式采用 `--no-session-budget`。

token 预算只能在请求边界精确检查。一次请求开始时尚不知道最终 output，因此允许最多超出一个 response：

1. 请求前若累计值已经达到上限，不发请求。
2. 若下一请求的估算 input 已不小于剩余 token，也不发请求；事件同时保存估算值，明确它不是 Provider usage。
3. response 完成后立即提交 usage。
4. 如果此时达到或超过上限，不执行该 response 中的 tool calls；为每个 call 写 `tool.skipped_due_to_budget`，再写 `budget.exhausted`。

这条“最多一个 response 的超额”必须在 CLI help 和文档中明确，不能把保险丝描述成精确账单封顶。

### 2.4 执行时间记账

“active time”定义为 Oxidra 正在等待以下操作完成的真实 elapsed time：

- Responses HTTP/SSE 请求，包括 compaction 请求。
- 已获授权后开始执行的内置工具。

以下时间不计入：

- CLI 启动、读取配置和构建 instructions。
- REPL 等待用户输入。
- shell/remember 等待用户确认。
- session 未打开或进程已经退出的时间。

实现使用单调时钟 `Instant` 测量每个 operation，不能用系统时间戳相减作为正常记账。每个 operation 的终结事件保存 `duration_ms`，包括 completed、failed、aborted、cancelled 和 in_doubt；resume 通过这些事件重建累计 active time。

剩余时间同时作为当前 LLM/tool operation 的 deadline。deadline 到达时触发同一条 CancellationToken 链，取消网络请求或终止工具进程树。预算取消必须与用户 Ctrl+C 使用不同的 journal reason，最终写 `budget.exhausted`。

崩溃可能丢失正在执行的最后一个 operation 的 elapsed time，这是无远端协调器、无高频 journal heartbeat 时不可消除的边界。MVP 明确记录这一限制，不为追求假精确而每秒 sync journal。

### 2.5 耗尽行为

预算耗尽是“干净暂停”，不是成功完成：

```text
budget.exhausted
```

事件至少保存：

```json
{
  "kind": "tokens | active_time",
  "limit": 1000000,
  "consumed": 1001234,
  "phase": "before_response | response_completed | tool_running | compaction",
  "estimated_next_input": null
}
```

行为：

- 不再启动新的 response 或工具。
- 正在运行的 operation 因时间预算耗尽而取消时，继续服从现有 cancelled/in_doubt 语义。
- 交互模式打印当前消费与恢复命令，然后退出当前进程。
- `-p` 返回专用非零退出码；不能返回 0，也不能只在 stderr 提示后假装完成。
- session 保持可 resume。用户必须显式提高预算或关闭预算；不能自动续费、自动重置或按天归零。

无人值守任务在预算耗尽时停止是硬预算成立的必要条件。友好性来自“阈值由用户控制、状态完整落盘、可提高预算后恢复”，而不是越过上限继续消费。

### 2.6 CLI 与显示

回合末指标在现有 model/token/context 后增加 session 累计值：

```text
session budget: tokens 143,200/1,000,000 (14%), active 8m12s/2h (7%)
```

`session list` 增加累计 token、active time 和 budget 状态，仍然只读，不获取写锁、不修复 journal。`session show` 已能展示所有原始预算事件，不再设计单独的预算数据库。

### 2.7 实现顺序

1. 新建 `budget.rs`：配置、journal reducer、剩余额度和耗尽原因。
2. 扩展 config/CLI，并实现新建、resume、显式重配置语义。
3. 给所有 LLM/tool 终结事件增加 operation `duration_ms`，接入 active deadline。
4. 在 response 完成与 tool dispatch 之间增加 token 后检查和 skip 事件。
5. 扩展 render、session list、错误类型和退出码。
6. 单元测试后补 CLI E2E，再跑三平台 CI。

### 2.8 M4 验收门槛

- 新 session 默认预算实际启用，不能只在测试中手工配置才生效。
- resume 沿用 session 预算；用户 config 变化不会改变旧 session。
- CLI 显式提高预算后，同一 session 可继续。
- 多个 response 的 `total_tokens` 正确累计，cached/reasoning 不重复计算。
- 完成 response 导致超限时，其 tool calls 全部被明确 skip。
- 缺失 Provider usage 时 fail closed，不按 0 继续。
- active deadline 能取消 SSE 和 shell 进程树。
- 等待 REPL 与等待人工确认不消耗 active time。
- `--full-auto` 不能绕过预算。
- 崩溃/resume 从 journal 重建相同的已提交消费值。
- Windows、Linux、macOS 的 fmt、test、Clippy 全绿。

## 3. M5：自动 Compaction 与 Checkpoint

### 3.1 目的与非目标

M5 解决的是“下一次请求装不下完整历史”，不是删除历史，也不是降低已经产生的 token 费用。完整原始事件仍保留在 journal；checkpoint 只是一个新的、有出处的派生输入。

M5 不实现：

- 修改、删除或重写旧 journal 行。
- 对 memory 或 `AGENTS.md` 做摘要。它们仍按当前版本注入并由 `context.instructions` 快照审计。
- 向量检索、embedding、相关性打分或跨 session 合并。
- 后台压缩任务、多个压缩模型、用户可编程摘要 hook。
- sub-agent。M5 只为以后评估 sub-agent 清除上下文阻塞，不承诺实现它。

### 3.2 自动触发与目标水位

M5 默认自动启用，不要求用户等到硬 `context_limit` 后手工补救。基于当前已配置的 `context_window` 与 `reserve_tokens`：

```text
usable = context_window - reserve_tokens
trigger = usable * 80%
target = usable * 50%
max_summary_output = 8192 tokens
min_recent_complete_turns = 2
```

每次普通 response 发出前：

1. 用当前 instructions、tools 和 projection 估算下一请求大小。
2. 小于 trigger，正常请求。
3. 达到 trigger，选择一个完整旧前缀并最多执行一次 compaction。
4. checkpoint 提交后重新构建 projection 并重新检查。
5. 仍达到硬上限时返回 `context_limit`，不继续压缩循环，不静默截断。

压缩选择必须至少保留最近两个完整 turn 和当前 turn。若当前 turn 本身过大，或不存在能在完整 turn 边界切开的旧前缀，则明确停止；不能切开 function call 与 function_call_output，也不能只丢大工具输出。

百分比和 summary 上限可进入用户配置，但第一版不增加一组临时 CLI 开关。缺少实际使用证据前，不做按模型、项目或 session 的策略框架。

### 3.3 Compaction 单位与边界

最小可压缩单位是一个完整 turn：

```text
user.message
  -> response.completed
  -> zero or more tool terminal events
  -> ...
  -> final response.completed without tool calls
```

M5 应新增显式 `turn.completed` 事件，供新 journal 确定边界。兼容旧 session 时，可把“下一个 `user.message` 已出现”视为前一个 turn 已关闭，但绝不能推断 journal 尾部的 turn 已完成。

以下 turn 永不进入压缩前缀：

- 含未解决 `tool.in_doubt`。
- 正在运行或只有 `response.started`。
- cancelled/aborted 且恢复投影尚未形成明确结果。
- 当前正在处理的 turn。

前缀选择算法必须是纯函数：相同事件、checkpoint、context 参数得到相同 `covers_through_seq`。先按 turn 边界从旧到新装入候选，直到用 summary 替换后预计回落至 target；不使用 LLM 相关性评分决定删谁。

### 3.4 Checkpoint 链

每个成功 checkpoint 至少保存：

```json
{
  "checkpoint_id": "uuid-v7",
  "parent_checkpoint_id": null,
  "covers_through_seq": 123,
  "source_digest": "sha256-of-canonical-source-projection",
  "summary": "模型实际生成并将在 projection 中使用的完整文本",
  "model": "gpt-5.6-sol",
  "usage": {},
  "duration_ms": 1234,
  "raw_response": {}
}
```

- 第一份 checkpoint 总结 journal 的旧前缀。
- 后续 checkpoint 的输入是“上一份 summary + 上一 cutoff 之后的新完整 turns”，而不是每次重新发送全部原始历史。
- `parent_checkpoint_id` 形成单链；projection 只使用最新有效 checkpoint。
- `source_digest` 用于证明 summary 对应哪份规范化 source。这里 hash 只是完整 source 和完整 summary 之外的完整性校验，不承担恢复内容的职责。
- journal 仍保存 checkpoint 覆盖范围内的全部原始事件，因此可审计、可重新实现 projection，也可在未来离线重做摘要。

下一次普通请求的 input 为：

```text
[latest checkpoint summary as a synthetic developer message]
+ [journal 中 seq > covers_through_seq 的正常 projection]
```

synthetic message 必须明确标记为“已压缩的旧会话事实，不是新的用户指令”；当前进程构建的 instructions 始终具有更高时效性。历史 `context.instructions` 继续只留在 journal 审计，不进入 compaction source 或普通 projection，避免复活已经变化的 `AGENTS.md`/memory。

### 3.5 调用与提交协议

compaction 使用同一个 Responses Provider、当前 model、`store: false`，但不暴露 tools。它有固定、内置、版本化的 summary instructions，要求保留：

- 用户目标、明确约束和已经拍板的决定。
- 修改过的文件、重要符号和当前工作区状态。
- 已执行命令、关键结果和验证状态。
- 未解决错误、风险、待办和下一步。
- 精确路径、标识符、数值与错误文本，不得编造完成状态。

调用事件：

```text
compaction.started
compaction.checkpoint
compaction.aborted | compaction.failed
```

`compaction.started` 在发请求前 sync，保存 compaction model 实际收到的完整 instructions 和 source input。只有收到完整 response、summary 非空且通过大小/边界校验后，才一次性追加 `compaction.checkpoint`，其中保存完整 raw response、usage 和最终注入文本。

partial delta 只显示状态，不进入 checkpoint。进程崩溃留下单独的 `compaction.started` 时，resume 追加 `compaction.aborted`；partial summary 不参与 projection。之后若仍超过 trigger，可把下一次压缩作为新 attempt，但同一 turn 内不能无界自动重试。

### 3.6 与 M4 的关系

- compaction 的 `usage.total_tokens` 与 `duration_ms` 计入同一 session 预算。
- 发 compaction 前先经过 M4 预算检查。
- 预算不足以容纳估算 input 时，预算耗尽优先，不能为了“省 context”越过费用上限。
- compaction response 本身导致 token 预算超限时，先提交有效 checkpoint 和实际 usage，然后停止，不再发送普通 response。
- `--no-session-budget` 只关闭 M4，不关闭 M5 的 context hard limit 或 checkpoint 校验。

### 3.7 失败策略

- Provider 失败、取消、空 summary、summary 超限或校验失败：写 failed/aborted，不启用半成品 checkpoint。
- 最新 checkpoint 的 parent、cutoff 或 digest 不合法：明确报 session 错误，不能静默换回全量投影继续请求。
- compaction 后仍超过 hard limit：写 `context.limit_reached` 并停止。
- 无可压缩完整前缀：写明原因并停止。
- 不在同一个 request boundary 连续尝试不同 prompt、不同 cutoff 或不同模型。

compaction 本质上是有损操作。可靠性来自保留原文、保守保留 recent tail、明确 source 范围和让失败可见，不来自假装摘要不会掉信息。

### 3.8 CLI 与可见性

自动触发时只在 stderr 显示简短状态，不污染 assistant stdout：

```text
[compaction] context 91,420/111,616; compacting 8 completed turns
[compaction] checkpoint <ID>; context 52,180/111,616
```

`session show` 直接展示 compaction request、raw response、summary、usage 与 cutoff。M5 第一版不增加交互式编辑 checkpoint、手工挑 turn 或后台管理命令。

### 3.9 实现顺序

1. 为新 turn 写 `turn.completed`，实现旧 journal 的保守边界识别。
2. 将现有 `project_events` 拆成“原始事件投影”“按 cutoff 投影”“checkpoint + tail 投影”三个纯函数。
3. 新建 `compaction.rs`：候选选择、source 规范化/digest、checkpoint reducer 与校验。
4. 扩展 `ResponseRequest` 支持 compaction 的无工具请求和 summary output 上限。
5. 在 Agent 的 context preflight 接入单次自动 compaction，再重新估算。
6. 接入 M4 usage/time、observer stderr 状态和 crash recovery。
7. 单元测试、合成大 journal 的 CLI E2E、三平台 CI。

### 3.10 M5 验收门槛

- 默认在 trigger 自动压缩，不必等到 hard limit。
- 相同 journal 和配置选择相同完整 turn 前缀。
- function call 与 output 永不被切到 checkpoint 两侧。
- 最新 projection 为一个 summary 加 cutoff 后的 tail；被覆盖原始 items 不再发送给模型。
- journal 原始事件逐字保留，`session show` 可看到模型用于摘要的完整 source 和生成结果。
- resume 选择同一最新有效 checkpoint，并继续形成单链。
- 单独 `compaction.started` 恢复为 aborted，partial summary 不使用。
- compaction usage 和时间进入 M4 累计值。
- 压缩失败、无候选或压缩后仍过大时明确停止，无静默截断。
- 当前 instructions 使用当前 `AGENTS.md`/memory；旧 instructions 快照不因 compaction 被重新注入。
- Windows、Linux、macOS 的 fmt、test、Clippy 全绿。

## 4. M4/M5 完成后的决策门

M4 与 M5 完成并实际使用一段时间后，才重新评估 sub-agent。进入该工作前必须同时满足：

1. 单 Agent 确实频繁遇到可并行的独立工作，而不是只因框架看起来更完整。
2. 子 Agent 使用独立 session/journal，父 session 只引用结果，不能破坏单写者锁。
3. 子 Agent 的 token 和 active time 从父级预算分配，不能各自获得一份无限额度。
4. 每个子 session 独立 compaction，父级不能把多个原始历史直接拼进同一 context。

Goal mode 同样不自动随 M4 出现。未来若实现，它可以消费 M4 的资源预算和 M5 的长上下文能力，但“何时认为目标完成、何时重试、无人值守时如何报告”必须另开设计，不能塞进预算模块。

## 5. 推荐提交边界

为降低回退成本，按以下边界提交，不把 M4/M5 混成一次大改：

1. `docs: lock M4 and M5 execution contracts`
2. `feat: persist and enforce session budgets`
3. `feat: expose session budget diagnostics`
4. `refactor: make turn boundaries and projection explicit`
5. `feat: add auditable compaction checkpoints`
6. `feat: trigger compaction before context exhaustion`
7. `test: cover budget and compaction recovery end to end`

每个功能提交都必须保持现有 read/edit/write/remember/shell、session resume 和 memory 测试通过。M5 未完整通过验收前，不删除原有 `context.limit_reached` 硬停止路径。
