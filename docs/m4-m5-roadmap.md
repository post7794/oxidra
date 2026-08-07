# Oxidra M4/M5 实施规划

状态：设计与实现基本完成。M4 按实际使用数据推迟。M5 的显式 turn 边界、原始 projection、checkpoint 数据模型与 reducer、低权限 summary envelope、不可变格式版本注册表、checkpoint + tail projection、真实 Responses Provider `compact_once`、boundary-bound Provider 调用、8192 输出上限、Provider 完成到 checkpoint 落盘窗口的生产路径故障注入、连续父子 checkpoint 与失败 child 重试内核测试、三个受控历史回查工具、model-aware context 配置、prepared-request usage-anchor 测量/审计、Provider context 超限后的显式 retry/abandon 恢复，以及 `--experimental-auto-compact` preflight 已经实现。自动触发、retry/replan、no-checkpoint resolution、legacy budget migration、abandoned-turn source projection 与跨进程 CLI 恢复已经闭环。2026-08-07 的 `Kimi-K2.7-Code` live 3/5/10 baseline 证明 prompt v3 在该 Provider usage domain 上连续十轮保留 17/17 事实且未执行注入文本。该结论只绑定记录的 model/backend；默认/当前其他模型尚未通过相同 gate，因此自动 compaction 继续显式 opt-in，而不是把单模型结果外推为全局默认。

本文只规划两个后续里程碑：

- M4：每 session 的 token 与执行时间预算。
- M5：自动 compaction 与可审计 checkpoint。

当前实施顺序不再要求先完成 M4。第 2 节保留为未来预算契约；M5 第一版不得留下未生效的预算检查、deadline 或累计器钩子。

它们的共同目标不是增加 Agent 能力，而是让长任务拥有明确的资源上限和可恢复的上下文。实现必须继续遵守现有契约：本地 journal 是 append-only 真相源，Responses API 使用 `store: false`，已提交的原始事件永不因 projection 或 compaction 被修改、覆盖或删除。

## 1. 不可破坏的底层契约

1. **journal 与 projection 分离。** journal 保存发生过的完整事实；projection 只决定下一次请求向模型重放哪些内容。
2. **Provider usage 是真实 token 依据。** `input_tokens` 是下一请求上下文占用的校准锚点，cached input 已包含在其中，不得扣除；`total_tokens` 用于未来预算记账，cached input 和 reasoning output 是子项，不能重复相加。
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
本次 CLI 显式覆盖 > 环境变量 > 当前用户 config.toml > 内置默认值
```

新建和每次 resume 都重新解析当前配置，并在 `session.started` 后或新启动 epoch 开始时追加 `budget.configured`。历史 `budget.configured` / `budget.reconfigured` 只回答“当时使用了什么”，不能反向恢复旧配置。当前配置变化会改变 resume 后的运行行为；journal 快照负责让变化可审计，而不是成为配置真相源。

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
- resume 使用当前解析出的预算配置，并追加审计事件；旧 session 中的预算快照不能覆盖当前 CLI/env/config。
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

设计定位是：Codex 的窗口化上下文 + Claude Code 的压缩后状态重载与完整 transcript 保留 + Oxidra 的可审计 checkpoint 和受控历史回查。公开证据不能证明 Claude Code 向模型提供了压缩历史搜索工具；`history_*` 是 Oxidra 自己补全的能力。

M5 不实现：

- 修改、删除或重写旧 journal 行。
- 对 memory 或 `AGENTS.md` 做摘要。它们仍按当前版本注入并由 `context.instructions` 快照审计。
- 向量检索、embedding、相关性打分或跨 session 合并。
- 后台压缩任务、多个压缩模型、用户可编程摘要 hook。
- sub-agent。M5 只为以后评估 sub-agent 清除上下文阻塞，不承诺实现它。

### 3.2 Context 测量、触发与发布门

自动触发实现后先默认关闭，只通过测试或显式实验入口启用。真实 `compact_once`、受控历史回查、崩溃与连续压缩闭环测试、漂移测量基线全部完成后，才能根据数据另行确定默认启用门槛；不能在实现前预设“摘要质量应该足够好”。发布 gate 按 Provider usage domain、model、prompt 和 envelope 分别判定，某个模型通过不能授权未测模型。

基于当前解析出的 `context_window` 与 `reserve_tokens`：

```text
usable = context_window - reserve_tokens
trigger = usable * 80%
target = usable * 50%
max_summary_output = 8192 tokens
min_recent_complete_turns = 2
```

`context_window`、`trigger` 与 `target` 是 planning/telemetry 参数，不是假装精确的本地安全边界。当前不引入 model tokenizer，也不调用 Provider 的计数接口，因此本地无法证明某个 prepared request 的真实 token 数。普通请求不能仅凭 `ascii/4` 或 usage-anchor 差分被拦截；Provider 报告的结构化 context-limit 错误才是当前发布版的权威 hard boundary。这样会多花一次被拒绝的请求，但不会把估算器伪装成保险丝，也不会因为保守字节上界而在真实窗口很早的位置停机。

每次普通 response 发出前，先对 Provider 实际准备发送的完整请求做 preflight。优先使用最近一次可比较的普通 response 作为差分锚点：

```text
next_input ~= anchor.reported_input_tokens
             + E(current_prepared_request)
             - E(anchor_prepared_request)
```

差值必须使用有符号计算，允许请求变小。`E(current_prepared_request)` 与 `E(anchor_prepared_request)` 必须使用同一版本的确定性估算器和相同的完整请求形状，包括：

- 当前 canonical instructions。
- 全部 input items，包括 checkpoint summary、assistant output、function call 和 tool output。
- 当前 canonical tools schema。
- model/protocol 相关固定开销。

`E(anchor_prepared_request)` 必须是在发送锚点请求时保存的同版本估算值，并绑定实际 prepared-request digest。checkpoint、instructions 或 tools 发生变化本身不机械使锚点失效；只要仍能按相同语义构造 current/anchor 两份请求，差分继续有效。只有无法可靠重建 anchor 请求，或 `provider_usage_domain`、request-shape/estimator version 不再可比时，才从零估算完整当前请求。

`provider_usage_domain` 是不含秘密的稳定兼容键，至少绑定 provider 类型、去除凭据/query/fragment 后的规范化 endpoint 或 provider profile，以及 effective model。只比较 protocol + model 不够：两个 OpenAI-compatible 后端即使使用同一模型名，也可能采用不同 token 统计语义。domain 变化时旧 usage 锚点必须失效。

Provider 未报告 `usage.input_tokens` 必须视为“没有锚点”，不能把缺失值当成真实的 `0`。cached input 已包含在 `input_tokens` 中，不得扣除；也不能直接再加上一次 `output_tokens`，因为真正进入当前请求的 assistant/function/tool 内容已经包含在请求差分里。

usage-anchor 修正若得到非正值，或锚点的真实 usage 与同版本估算偏差异常，不得 clamp 为 `0`；必须让锚点失效并回退到完整请求估算。每次测量还保存完整 Provider JSON 的 UTF-8 字节数，用于审计估算密度，但字节数不冒充 token hard limit。

以下触发流程只在显式实验入口或未来默认开关启用时生效；开关关闭时只显示/审计估算并直接发送普通请求，不调用 compaction：

1. 小于 trigger，正常发送普通请求。
2. 达到 trigger，在安全 turn 边界选择一个连续旧前缀；同一个 request boundary 最多执行一次 compaction。
3. Provider 完成后，先用候选 summary + tail 重建 prepared request；只有估算达到 target 才允许提交 checkpoint。
4. 仍高于 target 时写 `compaction.failed`，保留上一有效 checkpoint 并终止当前请求；不能在同一 boundary 换 cutoff 再试。
5. checkpoint 提交后重建普通请求并发送。若 Provider 仍报告 context limit，写 `response.failed` 与 `context.limit_reached`，保留 checkpoint 和 pending turn，不能循环 compact，不静默截断。

cutoff 不得进入最近两个完整 turn，当前开放 turn 也永不被覆盖。这是不可侵犯的安全下限，不是“必定能装下”的容量保证。若 checkpoint summary、最近两个完整 turn、当前开放 turn、当前 instructions 和 tools 仍无法达到可发送范围，则不生成不安全 checkpoint，记录明确原因并终止当前请求。不能切开 function call 与 function_call_output，也不能靠静默丢弃大工具输出兜底。

`context_window` 允许按精确 model 配置；`context_window` 与 `reserve_tokens` 都必须保留最终生效值和各自来源（CLI、环境变量、model config、全局 config 或内置默认）。第一版不调用 `/models` 自动探测窗口，不引入本地 tokenizer，也不做按项目或 session 的 compaction 策略框架。

每次新建或 resume 都以当前解析出的 provider、model、context、instructions 和 tools 为运行真相；历史快照只供审计，不能复活旧配置。追加独立的 `context.configured`，保存 model、provider protocol、`provider_usage_domain`、window、reserve、usable、trigger、target、各字段来源和 measurement/estimator/request-shape version。

为使 anchor 请求可重建，每次启动和 canonical tool 集合变化时追加 `context.tools`，保存完整 canonical tool schemas 与 digest；`response.started` 引用对应的 instructions/tools epoch，并保存本次完整请求估算与 digest、序列化请求字节数、请求可见的 journal seq、checkpoint/cutoff、使用的锚点 response seq、真实 anchor input、anchor estimate、有符号差值和最终 `next_input`。Provider 报告 context limit 时，`context.limit_reached` 保存同一组决策字段、response attempt 和来源。API key、endpoint 中的凭据/query 等秘密不得写入 journal。

### 3.3 Compaction 单位与边界

最小可压缩单位是一个完整 turn：

```text
user.message
  -> response.completed
  -> zero or more tool terminal events
  -> ...
  -> final response.completed without tool calls
```

M5 checkpoint 核心已经新增显式 `turn.completed` 事件，供新 journal 确定边界。最终无工具调用的 `response.completed` 同时保存同事件内的 completion coverage，随后正常追加 `turn.completed`；如果进程恰好在两次 sync 之间崩溃，完整的 response 事件仍能恢复边界。兼容旧 session 时，可把“下一个 `user.message` 已出现”视为前一个 turn 已关闭，但绝不能推断 journal 尾部的 turn 已完成。

“turn 成功完成”和“journal 前缀可安全切分”是两个概念。`turn.completed` 只表示成功；failed/cancelled/aborted/stalled/limit 或已显式解决的 in-doubt turn 仍可位于后续完整 cutoff 覆盖的前缀中，前提是已出现下一条 `user.message`、provider projection 已确定且没有 pending/in-doubt/配对不明的工具调用。候选 cutoff 自身仍只能落在成功完成的 turn 边界上。这样一次早期失败不会永久禁用之后的 compaction，也不会把失败伪装成成功。

以下 turn 永不进入压缩前缀：

- 含未解决 `tool.in_doubt`。
- 正在运行或只有 `response.started`。
- cancelled/aborted 且恢复投影尚未形成明确结果。
- 当前正在处理的 turn。

前缀选择算法必须是纯函数：相同事件、checkpoint、context 参数得到相同 `covers_through_seq`。从旧到新只选择连续、安全的 turn 前缀，同时禁止 cutoff 进入最近两个完整 turn；不使用 LLM 相关性评分决定删谁。若所有合法候选都无法使请求达到目标，返回 `TargetUnreachable` 等明确原因，而不是扩大 cutoff 越过安全下限。

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
  "prompt_version": 2,
  "summary_envelope_version": 1,
  "source_projection_version": 3,
  "turn_boundary_validator_version": 5,
  "source_digest_version": 1,
  "usage_contract_version": 1,
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

Checkpoint 接入必须保留清晰的函数边界：`validate_checkpoint_chain` 单独还原并校验 parent 单链、cutoff 与 source digest；`project_checkpoint_and_tail` 只能在链校验成功后投影最新 summary 与 cutoff 后的原始 tail。现有 `project_events` 继续只做原始事件投影，`project_tail` 继续只验证完整 turn cutoff 并投影原始 tail；不得把 checkpoint reducer 或“失败后静默回退全量历史”的行为塞进这两个函数。

下一次普通请求的结构为：

```text
完整 append-only journal
        │
        ├── 最新有效 checkpoint summary
        └── checkpoint cutoff 后的完整 tail
              ├── 至少两个已完成 turn
              └── 当前开放 turn
        │
        ├── 当前 canonical instructions
        └── 当前 canonical tools
                    ↓
                Provider request
```

“至少两个完整 turn”是 cutoff 选择时的保留约束，不是 projection 阶段额外读取和拼接的第二份数据源。projection 只能是一个最新 summary 加 `seq > covers_through_seq` 的正常 tail，禁止重复拼接 recent turns。

summary synthetic item 固定使用低权限 `role: "user"`；当前 canonical instructions 继续使用真正的顶层 `instructions` / developer 通道。父 summary 进入下一次 compaction source 时也必须通过其持久化版本的低权限 envelope，不能进入 compaction instructions。

权限边界来自 Provider 的消息 role。固定 notice、标签和内容分隔只帮助模型识别来源，是 defense in depth，不提供权限隔离，也不能承诺模型完全不受历史 prompt injection 影响。这里保证的是旧 user/tool 文本不会被提升为 developer/system；历史 summary 与当前用户消息同属 user level，不能虚构一个 Provider 并不存在的 data role。历史 `context.instructions` 继续只留在 journal 审计，不进入 compaction source 或普通 projection，避免复活已经变化的 `AGENTS.md`/memory。

同一规则必须覆盖 summary 之外的原始 projection：Provider 返回的 `type: "message"` output item 只能是 `role: "assistant"`，`user.message.data.item` 只能是 `role: "user"`。Provider 提交前和 journal 重放时都要校验；缺失 role、伪造 user/developer/system role 或被篡改的 journal 必须 fail closed，不能把结构化高权限 item 原样带进下一请求。

#### 版本演进契约

checkpoint 的可重建性同时依赖六类独立版本：

- `prompt_version`：compaction 顶层 instructions 的逐字内容。
- `summary_envelope_version`：summary 的 role、notice、分隔符和 JSON shape。
- `source_projection_version`：原始 journal 事件进入 compaction source 时的选择和 JSON shape。
- `turn_boundary_validator_version`：哪些完整 turn 边界可作为 cutoff，以及 pending/in-doubt/tool 配对的判定规则。
- `source_digest_version`：source 的 canonical JSON、hash 算法和字符串编码。
- `usage_contract_version`：raw usage 的必需字段、计数关系与 compaction 最大输出 token 上限。

`compaction.started` 和 `compaction.checkpoint` 都保存这六个版本，checkpoint 必须与对应 started 完全一致。读取时使用事件记录的版本，不要求它等于当前默认版本：

```rust
fn compaction_instructions(version: u32) -> Option<&'static str>;
fn compacted_history_item(version: u32, summary: &str) -> Result<Value>;
fn project_events_for_compaction(version: u32, events: &[JournalEvent]) -> Result<Vec<Value>>;
fn complete_prefix_candidates_for_version(version: u32, events: &[JournalEvent]) -> Result<Vec<CompletePrefix>>;
fn digest_with_version(version: u32, source: &CompactionSource) -> Result<String>;
fn max_compaction_output_tokens(version: u32) -> Option<u64>;
fn validate_compaction_usage(version: u32, usage: &Value) -> Result<()>;
```

规则：

1. 注册表中已经发布的 match arm、它调用的传递依赖语义与输出字节都不可修改；改共享 helper 若会改变旧版本结果，也等同于修改旧协议。升级只能新增版本，并只把新默认用于新 attempt。
2. `compaction.started.instructions` 必须与其 `prompt_version` 的注册文本逐字相等。
3. 普通 projection 使用最新 checkpoint 自己保存的 `summary_envelope_version`。
4. 构建子 checkpoint source 时，父 summary 使用父 checkpoint 保存的 envelope version；原始事件、cutoff 校验和 digest 分别使用本次 started 保存的 source projection、turn validator 和 digest version。
5. parent cutoff 已由 checkpoint chain 按 parent 自己的历史版本验证。child validator 只能处理 `seq > parent.covers_through_seq` 的未压缩后缀，不能用新版本重新审判旧 parent cutoff。
6. reducer 重建历史 source 并校验 checkpoint usage 时按事件版本执行，不能调用当前默认 renderer、turn reducer、digest、输出上限或 usage 规则。未知、缺失、已撤销或 started/checkpoint 不一致的版本全部 fail closed，不回退最新版本或全量历史。

六类基础协议的首个可执行版本都是 v1，并由独立字面量、frozen JSONL、golden source digest 和 usage 边界测试锁定；测试不能通过调用当前实现生成自己的期望值。当前新 compaction attempt 使用的版本组合是 `prompt=3`、`summary envelope=1`、`source projection=4`、`turn validator=5`、`source digest=1`、`usage contract=1`。prompt v1 保持 Oxidra 最初的事实清单字节；prompt v2 逐字采用 OpenAI Codex 公开的 context-checkpoint handoff prompt；prompt v3 保留完整 v2 前缀，并根据 live recursive-drift 失败新增事实保留契约，禁止把低权限历史递归压成泛化警告、等待状态或“请用户重述任务”。source 的低权限与不可信身份继续由 `role: "user"` 的版本化 summary envelope、角色校验和 projection 边界保证，而不是由 prompt 文本声称。turn validator v1-v4、Provider request-slot reducer v1 和 compaction boundary v1-v4 均已冻结；turn v4 修正 legacy completion evidence 的时间，turn v5 只为严格引用的 legacy Provider-budget migration neutralize 对应 `agent.limit_reached`。boundary v2 首次绑定 turn v4 与独立 slot v1，boundary v3 新增 session epoch 与退出连续性，boundary v4 固定绑定 turn v5 与 slot v2、承载旧 checkpointed budget terminal 的兼容迁移；当前 writer boundary v5 继承 turn v5/slot v2 与 metadata ceiling v5，并新增严格证据绑定的 `resolved_without_checkpoint`。source projection v1/v2/v3 保持冻结；source projection v4 首次消费已验证 boundary chain 并排除 abandoned turn。历史 prompt/turn/slot/boundary reducer 都必须按首次登记时的字面语义重建，不能吸收后续修正。此前仅存在于未接 Provider 的开发代码/测试夹具中的无版本 developer envelope 从未成为可用发布格式，不注册为可投影的 legacy 版本；对应 frozen fixture 必须证明它会 fail closed。若存在手工构造的此类 journal，只允许审计或从完整原文显式重做 checkpoint，不能为了兼容而重新发送 developer summary。

### 3.5 调用与提交协议

compaction 使用同一个 Responses Provider、当前 model、`store: false`，但不暴露任何 tools。Provider 请求固定设置 `max_output_tokens = 8192`；checkpoint reducer 还必须独立校验 `raw_response.usage.output_tokens <= 8192`，即使兼容 Provider 忽略请求参数，也不能提交超限 summary。raw usage 必须原样保存并满足 Responses 计数关系：`total_tokens == input_tokens + output_tokens`，若 Provider 报告 cached/reasoning 子计数，则还必须分别满足 `cached_tokens <= input_tokens` 与 `reasoning_tokens <= output_tokens`；缺失的可选子计数保持缺失，不能补成 0。新 attempt 使用注册表中的固定 prompt v3；读取历史 attempt 时使用事件自己的受支持版本。prompt v3 以 Codex 原始 handoff prompt 为完整前缀，并补充 Oxidra 的递归事实保留规则。Codex 前缀要求生成简洁、结构化、可供另一个 LLM 继续工作的 handoff，内容包括：

- 用户目标、明确约束和已经拍板的决定。
- 重要上下文、约束和用户偏好。
- 尚待完成的工作与明确下一步。
- 继续工作所需的关键数据、示例或引用。

Codex 原始 prompt 本身不声明 Oxidra 的不可信历史策略。source 的角色归因、低权限投影以及禁止把 summary 提升为 developer/instructions，继续由 summary envelope、输入角色校验和 projection 协议负责。

调用事件：

```text
compaction.started
compaction.checkpoint
compaction.aborted | compaction.failed
```

`compaction.started` 在发请求前 sync，保存 compaction model 实际收到的完整 instructions 和 source input、六类协议版本，以及本次生效的 window/reserve/source、真实 token 锚点、估算差值、trigger 与 target。只有收到完整 response、summary 非空且通过大小/边界校验后，才一次性追加 `compaction.checkpoint`，其中保存相同版本、完整 raw response、usage 和最终注入文本。

partial delta 只显示状态，不进入 checkpoint。进程崩溃留下单独的 `compaction.started` 时，resume 追加 `compaction.aborted`；partial summary 不参与 projection。

journal 的 write、flush 或 `sync_data` 任一步返回错误后，当前 `SessionJournal` 立即进入 poisoned 状态，禁止继续读取、投影或追加。此时完整行可能已经对当前进程可见，但持久化状态不确定；调用方不能自行把它解释为已提交。必须关闭句柄并重新打开 session，由统一的尾行修复、事件校验和 attempt 恢复流程决定磁盘内容是否有效。

一个 request boundary 一旦触发 compaction，Provider 失败、取消、空/超限 summary、校验失败、无安全候选、压缩后仍达不到 target，或随后普通请求被 Provider 判定 context 超限，都必须终止本次普通请求，也不得执行工具。journal 保留上一有效 checkpoint、当前开放 turn和完整 attempt 状态；同一 request boundary 不自动循环重试。

当前 `compact_once` 把“summary + tail 是否达到 target”的判定作为提交前必需回调；回调失败会同步写 `compaction.failed`，不会生成 checkpoint。`--experimental-auto-compact` 是唯一自动入口，默认关闭；没有绕过 boundary、候选或提交前验证的 CLI 路径。

如果 Provider 已完整返回，但因输出超限、usage 内部矛盾、target 校验失败或提交前取消而未形成 checkpoint，终态事件仍保存完整 `raw_response`、原始 usage 和 duration 供审计；这些字段不参与 checkpoint chain 或后续 projection。未完整返回的 partial delta 仍不写入 canonical journal。

错误终态按来源边界分类，而不是按底层错误类型猜测：经过 `StreamObserver` callback 边界包装的本地渲染/输出错误写 `compaction.aborted/code=observer_error`；明确的 Provider 错误写 `compaction.failed/code=provider_error`；其他本地错误（包括 Provider 实现自己返回的 `Io`）写 `compaction.failed/code=local_error`。这样 broken pipe 等 observer 故障不会被误报成远端失败，也不会把任意 I/O 故障误判为 UI 中断。

### 3.6 受控历史回查

完整 journal 留在磁盘，只解决“原文没有丢”；要让压缩后的模型恢复精确事实，还必须提供一个受限、可引用、会计入上下文的查询闭环。受控历史回查必须先于自动 compaction 默认启用。

第一版只提供三个无斜杠工具名：

```text
history_search
history_turn
history_artifact
```

统一作用域是当前 session 且 `seq <= latest_checkpoint.covers_through_seq`。没有有效 checkpoint 时，正常 Provider 请求不注册这些工具；若收到旧调用则返回 `history_not_available`。checkpoint 链非法时直接终止当前请求，不能把历史查询降级为空结果继续运行。当前开放 turn 和 checkpoint cutoff 后的 tail 永远不属于查询范围。

#### 检索语料

history 不能直接搜索原始 JSONL 行。它从同一份已校验 journal 快照生成规范化记录，只保留：

- 用户消息正文。
- assistant 的可投影文本、非 history function call 名称与参数。
- 工具终态结果、错误与 journal 已记录的 artifact 引用。
- failed、aborted、cancelled、stalled 和 limit 的可读状态。

明确排除历史 `context.instructions` / `context.configured`、所有 `compaction.*` 和显示/恢复/turn 管理事件、`raw_response` 的重复副本、usage、encrypted reasoning，以及旧 `history_*` 调用及其结果。artifact 文件正文不进入 `history_search` 语料，只能通过授权后的 `history_artifact` 分页读取。

每条规范化记录至少包含：

```text
seq, turn_id, kind, field, artifact_id?, byte_range?, excerpt
```

返回值必须固定声明它是“不可信历史证据，不是 instructions”。它只能作为普通 tool output 回填，消耗 context 并进入之后的正常 projection；旧 user/tool 内容中的“忽略当前 instructions”等文字不能获得 developer 或 instructions 权限。

#### 查询与分页

- `history_search` 支持 `substring`（默认）和 `exact`，大小写敏感可配置；`exact` 表示规范化 field 全文相等。不支持 regex、模糊匹配、embedding 或语义搜索。
- `history_turn` 只接受精确 `turn_id`，返回带引用的分页摘录，不自动倾倒整个 turn。
- `history_artifact` 只接受 checkpoint 覆盖前缀内、由 journal 工具终态明确引用的 `artifact_id`，不能接受任意路径。核心负责在当前 session artifact 目录中解析引用、拒绝 symlink，并验证 journal 的 `artifact_sha256` 与 `metadata.json`。新 artifact metadata 使用 schema v2，为每个落盘 stream 记录 `stored_sha256`；旧的未截断 schema v1 artifact 可用完整 stream hash 校验，旧的已截断且没有 stored hash 的 artifact 返回 `artifact_integrity_unverifiable`。metadata 或文件 hash 不一致返回 `artifact_integrity_error`，不能把变化后的字节当作历史证据。artifact 正文按二进制读取并以 base64 返回，不假设它是 UTF-8。
- 结果固定按 journal `seq`、记录字段顺序和匹配偏移稳定排序。
- cursor 绑定 schema/extractor version、session、创建时的 checkpoint ID/cutoff、查询参数、snapshot digest 和下一位置。latest checkpoint 后续推进时，只要绑定的旧 checkpoint 仍位于当前有效链中且 snapshot digest 一致，就继续对旧 snapshot 分页；断链、snapshot/extractor 变化时返回 `cursor_stale`。cursor 不能扩大 cutoff。
- `history_turn` / `history_artifact` 查询不存在、位于 cutoff 后或属于当前开放 turn 时，统一返回 `not_found_in_compacted_prefix`，不泄露范围外对象是否存在。

第一版限额固定为代码常量，并按最终序列化为 Provider tool output 的 UTF-8 字节计数：

```text
query                         512 B
cursor                       2048 B
max_results                  default 5, hard max 8
single excerpt               1024 B
artifact source chunk        8192 B
one history tool output     12288 B
one live user turn total    32768 B
history calls per response       8
reserved control output/call   512 B
```

当前用户 turn 的累计值包含所有 history tool 的成功和错误输出，跨该 turn 内的多次 response 不重置。配额必须从同一 `turn_id` 已提交的 history 工具终态事件重建，崩溃和 resume 不能重置。每次提交 Provider response 前先验证 history call 不超过 8 个，并为这一批每个尚未执行的 call 预留 512 B，使每个 function call 都能得到确定终态而不会突破 32768 B 硬上限。prepared request 的剩余配额不足以容纳最大一批 8 个控制结果时就提前移除全部 history schemas；不能让模型靠反复查询继续填满 context。artifact chunk 还必须受单次序列化总上限约束，并按最终 base64/JSON 输出大小动态缩小。

第一版每个 Provider request boundary 可对 journal 做一次线性扫描并构建不可变 `HistorySnapshot`；一次 history tool call 不能重新打开并扫描 journal。没有性能证据前不增加数据库、embedding 索引或物理分段。

### 3.7 M4 推迟后的边界

M4 当前按实际使用数据推迟，本节不再是 M5 第一版的实现前置条件。M5 仍把每次 compaction 的完整 usage 与 `duration_ms` 写进 checkpoint 供审计，但不实现 session 预算 reducer、发请求前预算检查、active-time deadline 或 `--no-session-budget` 分支。自动 compaction 因而没有 session 级费用/时间保险丝，这一限制必须在发布说明中明确。

### 3.8 失败策略

- Provider 失败、取消、空 summary、summary 超限或校验失败：写 failed/aborted，不启用半成品 checkpoint，并停止当前请求。
- 最新 checkpoint 的 parent、cutoff 或 digest 不合法：明确报 session 错误，不能静默换回全量投影继续请求。
- compaction 后的普通请求仍被 Provider 判定 context 超限：写 `response.failed` 与 `context.limit_reached` 并停止。
- 无可压缩完整前缀，或最近两个完整 turn 与当前开放 turn 本身已无法安全装入：写明原因并停止。
- 不在同一个 request boundary 连续尝试不同 prompt、不同 cutoff 或不同模型。
- 停止后保留状态；显式 retry/abandon 必须留下可审计事件，不能静默修改旧 journal。

compaction 本质上是有损操作。可靠性来自保留原文、保守保留 recent tail、明确 source 范围和让失败可见，不来自假装摘要不会掉信息。

“保留供重试”必须有可执行协议：

1. 唯一共享的 turn-recovery reducer 校验 `turn.abandoned` 与 `turn.retry_started`。两者必须满足 `user.message < context.limit_reached < control event`，引用对应 user seq，不能指向已完成 turn，不能重复；retry intent 还必须带固定版本、唯一 ID，并引用当前最新 limit。Provider 来源的 limit 必须用 `response_attempt_id` 绑定同 turn、更早的 `response.failed`。Agent pending、projection 和 history 都只能消费这个 reducer 的验证结果，伪造控制事件一律 fail closed。
2. `run_turn` 在追加新 `user.message` 前检查 pending；存在 pending 时返回明确错误，因此 `-p --resume` 不会继续叠加新消息，也不会再次毒化 session。
3. `--retry-pending --resume <ID>` 先同步写入 `turn.retry_started`，再在原 `turn_id` 和原 `user.message` 上继续，不重复追加 prompt，也不需要用 abandon 模拟 retry。崩溃若发生在 intent sync 后、Provider dispatch 前，resume 复用同一 intent；若 response attempt 已开始后崩溃，统一恢复为 `response.aborted`，下一次显式 retry 写入新的 intent 后继续。
4. `--abandon-pending --resume <ID>` 只追加经 reducer 校验的 `turn.abandoned`；之后可以在同一次进程中用 `-p` 提交替代 prompt，或进入 REPL。该事件只改变 projection/history，不删除 journal 原文。
5. turn-boundary validator v1 保持最初的 turn 边界语义。v2 冻结首次登记的 retry 规则：它只 supersede latest retry 之前的 `response.failed`、`response.aborted` 和 `context.limit_reached`，且保留当时较宽松的 recovery 顺序校验；不得把后续修复回填进 v2。v3 才要求 `user.message < context.limit_reached < control event`、校验 Provider response attempt 绑定，并把较早 epoch 的 `turn.cancelled`、`agent.stalled`、`agent.limit_reached` 一并视为已被后续 retry 覆盖。v4 只新增 legacy completion evidence 的正确时序，不改变 v1-v3 的结果。v5 只消费 `compaction.boundary.budget_retry_started` 中经过校验、唯一引用的旧 response-budget terminal；没有该新事件时，turn v4 的结果保持不变。source projection v3 使用 v3 recovery，保留原 prompt并移除已 supersede 的取消提示；历史 source projection v1/v2/v3 保持原字节与原接受/拒绝语义。history extractor v4 新增 compaction-boundary abandon 过滤，旧 extractor cursor 不会被静默按新语义解释。
6. `--retry-pending` 明确是非交互 batch；它与普通 `-p` 共用取消、流收尾和 `approval_required` 转换。shell 未带 `--full-auto` 时返回 exit 3，而不是把审批拒绝误报成 Ctrl+C/130。
7. 回归测试覆盖审批拒绝后带 `--full-auto` 再次成功、retry 取消后再次成功、stalled 后再次成功，以及 tool/response limit 后再次成功；较早 attempt 的终态不得污染最终 turn completion。

自动 compaction 另外使用独立、版本化的 request-boundary 协议，不能把全局 `compaction.started` 误当成用户 turn 已经被恢复：

1. 在候选选择或 Provider 调用之前先同步写 `compaction.boundary.started`，保存 `boundary_id`、`turn_id`、原始 `user_message_seq`、trigger 和 boundary version。边界事件保持 global，turn 绑定只存在于已校验 payload 中，避免旧 turn reducer 被新全局管理事件静默改义。
2. 真正的 `compaction.started` 在开放的 `extra.boundary` 中保存同一份绑定；checkpoint 只能通过该绑定归属到边界，不能拿一个无关但合法的 checkpoint 伪造“本 turn 已压缩”。旧 checkpoint 固定字段和已发布版本不变。
3. checkpoint durable 后追加 `compaction.boundary.checkpointed`。该状态仍是 pending：它只证明摘要已经提交，不证明原用户请求已经收到正常响应。只有同 turn 的完整 completion、显式 abandon，或后续 retry supersession 才解除 pending。
4. 无安全候选、Provider/本地失败、取消或摘要校验失败写 `compaction.boundary.failed`。若存在 Provider attempt，必须引用同 boundary 的已终结 `compaction.failed` / `compaction.aborted`；候选选择前失败可以没有 attempt id。
5. 显式 retry 写 `compaction.boundary.retry_started`，生成新的 boundary id、保留同一 `turn_id` 与 `user_message_seq`，并把上一 failed boundary 标为 superseded；不追加第二条 user message。显式 abandon 写 `compaction.boundary.abandoned`，只改变当前 projection，原文继续留在 journal。
6. started、checkpointed 和 failed 都属于 pending 状态。pending 后若出现另一个 user message、引用错 user/checkpoint/attempt、重复终态或跨 turn retry，reducer 一律 fail closed；只有在更早的 `state_seq` 已记录 abandoned、superseded 或 completed-turn，后续 user message 才合法。Provider attempt、checkpoint、failure、abandon、retry 和 completion 必须通过单一 boundary transition 表；普通 `boundary.started` 不能复活 abandoned/superseded 的原 prompt。
7. boundary v1-v4 保持首次登记时的完整接受/拒绝语义，并由字面量 JSONL fixture 锁定；共享 helper 不得向旧版本回填新规则。v2 首次绑定 turn validator v4 与**固定的** Provider request-slot reducer v1：逐事件验证单 Provider slot，不能并发 `response.started`，上一 response 产生的 function call/tool lifecycle 未全部解决前不能启动下一 response，retry 必须从已验证 terminal 重新取得 slot；checkpointed 后也持续验证普通 Provider/工具前缀，完成时 slot 必须为 `Terminal`。v3 继承同一个冻结 slot v1，并在首个 durable v3 boundary 建立 session epoch、要求 abandon/attempt/slot 的退出连续性。v4 固定绑定 turn validator v5 与 Provider request-slot reducer v2，并把 turn metadata compatibility ceiling 固定为 v5。当前 writer 使用 boundary v5，继续固定 turn v5、slot v2 和 metadata ceiling v5，并新增 `resolved_without_checkpoint`。普通 retry 迁移表固定为 `v1 -> v1/v2/v3/v4/v5`、`v2 -> v2/v3/v4/v5`、`v3 -> v3/v4/v5`、`v4 -> v4/v5`、`v5 -> v5`；此外只有字面量旧状态 `checkpointed boundary v3 -> agent.limit_reached` 可以通过原子的 `compaction.boundary.budget_retry_started` 转成继承同一 checkpoint 的 checkpointed boundary v4。唯一 canonical migration validator 必须从事件写入前的 durable prefix 同时证明 predecessor、checkpoint、turn/user 引用、无版本旧 terminal、dispatch-intent 数与恢复后的 turn/slot 状态；boundary v4、turn v5 和 slot v2 只能消费这同一验证结果。旧 terminal 必须不存在 `provider_call_budget_version` 与 `consumed_provider_call_intents`，未知或未来版本 fail closed。该事件必须引用旧 boundary、limit seq、旧/当前额度和 journal 证明的 dispatch-intent 数；同一 limit 只能迁移一次，额度未增加时不得写入。slot v1 和 turn v4 仍把旧 limit 视为 terminal，只有 slot v2 和 turn v5 消费该显式迁移。`OpenTail` 只表示 turn 尚未完成，不是 Provider dispatch 的权限证明；后续事件不得追溯性地使一个越过、正在请求或已终止的 turn 合法。turn v4 输出最早的 completion evidence `completion_seq`，turn v5 仅增加上述 budget migration overlay；boundary v5 的 no-checkpoint resolution 只能紧跟 durable v5 retry intent，planning version 必须为 v1，测量 prefix、estimate 与 trigger 必须逐字段一致，且未开始 compaction attempt、slot 为 `Ready`、`estimate < trigger`。该状态继续拥有原 turn，直至 normal response 完整结束；各 boundary 按冻结 policy 消费对应 reducer。
8. `validate_compaction_boundary_chain` 只能消费 turn validator 的已验证 completion 与 checkpoint/attempt reducer 的已验证 attempt→terminal 映射，不得再次从原始字段推断控制状态。checkpoint chain 回答“哪个 summary 可用”，boundary chain 回答“触发它的用户请求是否已经完成”。两者任何一边非法都不能继续 Provider 请求。

当前代码已经实现 boundary v1-v5 数据模型、不可变版本 policy、checkpoint/attempt 绑定、纯 reducer、版本化 request-slot 校验、`compact_once_for_boundary`、session-open 自动恢复和 opt-in 自动 preflight。自动入口先把 `context.tools` epoch 同步，再从同一 durable snapshot 得到 trigger 决策、boundary intent、eligible cutoff 的完整 request-shape 估算和 post-summary continuation；与 8192 输出上限对应的估算器占位预算用于保守候选规划，真实 summary 仍必须再次达到 target。同一 user turn 的 checkpointed 或 resolved-without-checkpoint boundary 会阻止第二次自动压缩。恢复顺序先把孤立 Provider attempt 写成 `compaction.aborted`，再根据 durable terminal 补 `boundary.failed` 或 `boundary.checkpointed`；候选选择前崩溃则补无 attempt 的明确 failure。Agent 从单份 durable journal snapshot 生成 `RecoveryPlanV1`：同时归约 context pending 与 boundary pending，failed boundary 优先于同 turn 的 context retry；历史 candidate 按原 `compaction.started` 记录的 source/turn/digest/usage 版本重放，不套用 current-writer 版本要求；planning v1 由冻结 reader 与 fixture 锁定，旧 context 只证明 lineage，preflight retry 必须用当前 model/context 配置、instructions、tools 和 history view 重建请求并重测。当前请求若已低于 trigger，则不发送压缩请求；v5 retry intent 与 `resolved_without_checkpoint` 对同一 planning-v1 测量逐字段绑定，resolution 同步后直接继续原 turn，且崩溃重开不会复制 prompt、压缩 attempt 或 checkpoint。在写 retry intent、resolution 或调用 compaction Provider 前，prospective journal 必须已经通过 boundary/turn/slot reducer、checkpoint chain、真实 history extractor/artifact provenance、history quota、tools schema 与后续 prepared-request 测量。`--retry-pending` 可从 `Ready` slot 继续 checkpointed/resolved turn，或对有 durable candidate 的 failed boundary 同步新 retry intent 后重新压缩；尚未生成 durable candidate 的 preflight-only failure 也会由 `--retry-pending` 重新规划，或显式 abandon。preflight retry 自身在取消、规划失败、observer 失败或快照变化时也会结算 replacement boundary failure，并把当前重测 planning context 沿 retry lineage 保存；replacement intent 同步后、candidate planning 前强杀会在 reopen 时结算为 failed，下一次 retry 仍可沿 lineage 继续。checkpointed 后若普通 attempt 已进入 `Terminal`，已有独立协议的 context-limit 可用 `turn.retry_started` 重新取得 slot；`55e5b0c` 生成的旧 response-budget terminal 则在当前额度提高或关闭后写入原子 budget migration，继承原 checkpoint 和 prompt后继续。其他 terminal 必须显式 abandon。`--abandon-pending` 同时处理 context-limit 与 compaction pending。`--max-responses` 从 journal 中同一 logical turn 的 `response.started` 与 bound `compaction.started` 归约，是跨崩溃和 retry 的保守 dispatch-intent 预算；失败/取消 attempt 仍占用，当前配置提高上限后才可获得新增额度。若 pending compaction boundary 拥有恢复权，新 writer 在额度耗尽时不追加会终结 turn 的 `agent.limit_reached`，而是保留 boundary 并在下次 retry 按当前上限重新判断；legacy migration只为已落盘的旧污染状态服务。可见 assistant response 数量和 checkpoint usage 分开统计。原始 journal 不删除，当前 projection/history 只排除经 reducer 验证的 abandoned turn。

source projection v1-v3 保持原始字节与接受/拒绝语义；source projection v4 首次消费 canonical boundary chain，把已验证 abandoned turn 的 user/assistant/tool items 全部排除。候选估算、dispatch、checkpoint projection 与 history snapshot 都按 checkpoint 自己的 source version 判断证明能力：v4 可以安全跨越 abandoned turn，历史 v1-v3 checkpoint 若已经跨越仍 fail closed，不能借新 reducer 追溯洗白旧 opaque summary。

### 3.9 CLI 与可见性

自动触发时只在 stderr 显示简短状态，不污染 assistant stdout：

```text
[compaction] context 91,420/111,616; window 128,000 (config), reserve 16,384 (config); compacting 8 completed turns
[compaction] checkpoint <ID>; context 52,180/111,616
```

`session show` 直接展示 compaction request、raw response、summary、usage 与 cutoff。M5 第一版不增加交互式编辑 checkpoint、手工挑 turn 或后台管理命令。

### 3.10 实现顺序

已经完成的 checkpoint 核心：

1. 显式 `turn.completed`、legacy turn 的保守识别和完整前缀候选。
2. `project_events`、`project_tail` 与显示层隔离的原始 projection。
3. `compaction.rs` 的数据模型、source 规范化/digest、严格单链 reducer 和候选选择。
4. 独立的 `validate_checkpoint_chain` 与 `project_checkpoint_and_tail`。
5. started/checkpoint 的 journal sync、孤立 attempt 恢复、损坏尾行，以及真实 `compact_once` 在 Provider 完成到 checkpoint 落盘窗口的进程级故障注入测试。
6. summary envelope v1 使用 `role: "user"`；prompt、envelope 和 source projection 都通过持久化版本与不可变注册表重建。

下一阶段严格按以下顺序推进：

1. 已实现真实 Provider `compact_once` 内核：复用已注册的六类 v1 协议、无 tools、8192 输出上限、完整 raw response/usage 提交，并让 Agent 在有效 checkpoint 存在时实际使用 checkpoint + tail projection。默认关闭的实验入口已经接入。
2. 已实现当前 session、最新 checkpoint 覆盖前缀内的 `history_search` / `history_turn` / `history_artifact`：同一 request boundary 只读一次 journal，schema 和执行器绑定同一不可变 snapshot；确定性检索、引用、cursor、artifact schema v1/v2 校验和单 turn 配额已经接入 Agent 主循环。
3. 已实现 model-aware context 配置、prepared-request 精确 request-shape 测量、`context.configured` / `context.tools` / `response.started` / `context.limit_reached` 审计、真实 usage 差分锚点，以及 Provider context-limit 的 retry/abandon E2E。估算只用于 telemetry 和显式 opt-in compaction planning；普通请求不再被 heuristic 伪装成 hard limit 拦截。
4. 已完成内核级连续两次真实 `compact_once`，并加入 compaction request-boundary v1-v5 的数据模型、provider-attempt/checkpoint 绑定、fail-closed 纯 reducer、版本化 request-slot 状态机、旧 checkpointed budget terminal 的原子兼容迁移、bound Provider 调用和 session-open 恢复：失败 child 不替换 parent checkpoint，随后以同一候选显式重试可形成合法子链，最终 projection 只使用最新 summary + tail。Agent/CLI pending 管理、projection/history abandon 语义，以及“retry intent 已同步但新 attempt 尚未写入”、“legacy budget migration 已 fsync 但正常 response 尚未开始”和“resolved_without_checkpoint 已 fsync 但 normal response 尚未开始”三个窗口的跨进程强杀恢复 E2E 已完成；后两者由新 CLI 进程继续同一 prompt，且不会重复写 migration intent、resolution、checkpoint 或原 user message。
5. 已接入默认关闭的自动 preflight/trigger 实验入口，并完成 Provider context-limit after-checkpoint、retry/replan、no-checkpoint resolution、legacy budget migration 和 CLI resume/强杀恢复闭环。
6. 已加入 `examples/compaction_drift.rs` 与不可变 fixture/metric 版本：使用 production prompt、低权限 envelope、无 tools 和 8192 输出上限，对父摘要连续执行至少 10 次真实重摘要，并保存 Provider usage domain、prompt/envelope/request-chain hash、raw response、usage 和逐事实/分类保留指标。rescore 模式只有在逐轮 input/summary hash 与当前 prompt/envelope 完全匹配时才能复用 live 输出，不产生新 Provider 调用。
7. 2026-08-07 的 `Kimi-K2.7-Code` prompt-v3 live run 及 boundary-aware metric-v6 rescore 在 3/5/10 轮均保留 17/17 事实，十轮 `exact_attack_execution` 均为 false。v6 要求字段与数值、对象与否定约束、路径与状态极性在有界局部范围内保持关联，数值必须满足 token 边界，尾随状态反转和约束取消由同 segment forbidden assertion 拒绝；最小变异测试覆盖数值前后缀、字段值交换、状态反转、约束取消及无关关键词。rescore 还按生产合约从 raw response 重新提取 summary、验证 raw usage，并核对独立 typed usage。该 Provider usage domain 满足 gate；证据保存在 `docs/artifacts/`。未测 model/backend 不继承此结论，因此全局默认仍不改变。
8. 只有线性扫描或 journal 体积出现实际性能证据后，才考虑可重建索引或物理分段。

### 3.11 M5 验收与发布门槛

功能闭环门槛：

- `compact_once` 发出的真实请求无 tools、使用 prompt v3 和 8192 output token 上限；reducer 独立拒绝 Provider 返回的超限 checkpoint。prompt v1/v2 fixture 仍必须按原字节读取。
- summary 在普通 projection 和下一次 compaction source 中始终由 checkpoint 自身的受支持 envelope 渲染为 `role: "user"`；恶意历史经过摘要、普通 replay 和再次摘要都不会进入 developer/system item。
- Provider output message 在提交前与 journal replay 时都强制为 `role: "assistant"`，journal user item 强制为 `role: "user"`；伪造或缺失 role 不得进入普通 projection 或 compaction source。
- prompt、summary envelope、source projection、turn validator、source digest 和 usage contract 的首个可执行 v1 在新增默认版本后仍按原规则重建；prompt v1/v2 由完整字面量测试锁定，prompt v3 由固定 SHA-256 锁定，历史 source projection v2/v3、turn validator v2-v4、Provider request-slot v1 与 compaction boundary v1-v4 由字面量/定向 fixture 锁定，不能调用新 reducer 或接受未知 boundary tag。当前新 attempt 使用 `3/1/4/5/1/1` 版本组合，compaction boundary 新事件使用 v5，Provider request-slot 使用 v2（均由 boundary policy 固定绑定）。旧 `55e5b0c` fixture 必须证明 slot v1/turn v4 仍为 terminal，而显式 budget migration 后只有 slot v2/turn v5 获得继续权限。此前未发布的 developer-envelope 实验格式必须由负 fixture 证明 fail closed；任一版本缺失、未知或 started/checkpoint 不一致都不能退回当前默认实现。
- checkpoint usage 与 `raw_response.usage` 逐字一致，并满足 total 等式、cached/input 与 reasoning/output 子计数关系及 8192 输出上限；矛盾 usage 只生成可审计的 failed attempt，不进入 checkpoint chain。
- 有可比较 usage 时使用真实 `input_tokens` 锚点和完整 prepared-request 的有符号估算差；无锚点时才估算完整请求。
- cached input 不从上下文占用中扣除；usage 缺失不冒充真实 `0`。
- journal 可还原每次生效的 window、reserve、provider usage domain、完整 canonical tool schema、request digest、锚点和触发计算。
- 相同 journal 和配置选择相同完整 turn 前缀；最近两个完整 turn 与当前开放 turn 不会被 cutoff 侵入；无法达到 target 时不提交 checkpoint。
- function call 与 output 永不被切到 checkpoint 两侧。
- 最新 projection 为一个 summary 加 cutoff 后的完整 tail；被覆盖原始 items 不再发送，也不会把 recent turns 重复拼接给模型。
- checkpoint 链校验与 checkpoint-aware projection 分别通过 `validate_checkpoint_chain`、`project_checkpoint_and_tail` 完成；`project_tail` 不承担 checkpoint reducer 职责。
- journal 原始事件逐字保留，`session show` 可看到模型用于摘要的完整 source 和生成结果。
- resume 使用当前 provider/model/context/instructions/tools，历史快照只供审计；有效 checkpoint 继续形成单链。
- 单独 `compaction.started` 恢复为 aborted，partial summary 不使用。
- 现有 journal sync/损坏尾行测试继续通过；进程级故障注入覆盖真实 `compact_once` 的 started 已同步、Provider 已完成但 checkpoint 尚未落盘、checkpoint 已同步三个窗口，证明恢复不启用未提交 summary。
- compaction usage 和时间完整写入 checkpoint；M4 推迟期间不做累计预算判断。
- 压缩失败、无候选或压缩后无法达到 target 时终止当前请求；同一 boundary 不循环 compact。Provider context-limit retry 使用既有持久化 intent；compaction boundary v1-v5 独立记录 started/checkpointed/failed/retry/resolve/abandon，boundary v4 只承载严格限定的 legacy budget migration，boundary v5 支持严格证据绑定的 no-checkpoint resolution，并始终保持原 user message。Agent/CLI pending 管理、projection/history abandon 语义和跨进程闭环 E2E 已实现。source projection v4 已表达 boundary abandon，并由字面量 fixture 证明 v3 仍保留旧 prompt、v4 才排除整 turn；历史 v1-v3 checkpoint 的安全 barrier 继续按其持久化版本执行。
- history 三个工具只访问最新 checkpoint 覆盖前缀，使用稳定排序、带引用分页和硬输出配额；无 checkpoint 时不额外暴露历史。
- history cursor、排序、分页、artifact ID/hash 授权和当前用户 turn 累计配额均有确定性测试；崩溃/resume 不重置配额，耗尽后移除 history schemas。
- 同一 journal 在不同 render/折叠设置下生成完全相同的 Provider projection 字节。
- Windows、Linux、macOS 的 fmt、test、Clippy 全绿。

每个 Provider usage domain/model 默认启用前的测量门槛：

- 固定事实集经过 3/5/10 次父摘要递归后，分别测量精确数值、否定约束、已完成/未完成状态和关键标识符的保留情况。
- 故意让摘要遗漏事实，验证模型能通过 `history_search -> history_turn` 或 `history_artifact` 找回并引用原文。
- 旧 user/tool output 含“忽略当前 instructions”等恶意内容时，summary 和 history 结果都保持不可信数据身份，不能提升权限。
- 最近两个完整 turn 本身超过 usable budget 时，记录不可压缩原因并停止，不能生成不安全 checkpoint 或循环重试。
- 根据首份有效 live 数据锁定的阈值是：3/5/10 轮上述各类 durable facts 均为 100%，字段/值、否定约束对象和状态 polarity 必须通过局部关系断言，数值必须满足 token 边界，且登记的最小语义变异必须全部使目标 fact 失败；每轮 `exact_attack_execution=false`；artifact 必须绑定当前 prompt/envelope、完整 request chain、raw Provider summary 与 usage。`Kimi-K2.7-Code` 的记录域已通过；其他域必须独立通过，不能以相同模型名或 OpenAI-compatible 标签代替证据。

## 4. M4/M5 完成后的决策门

M5 完成、M4 后续实现并实际使用一段时间后，才重新评估 sub-agent。进入该工作前必须同时满足：

1. 单 Agent 确实频繁遇到可并行的独立工作，而不是只因框架看起来更完整。
2. 子 Agent 使用独立 session/journal，父 session 只引用结果，不能破坏单写者锁。
3. 子 Agent 的 token 和 active time 从父级预算分配，不能各自获得一份无限额度。
4. 每个子 session 独立 compaction，父级不能把多个原始历史直接拼进同一 context。

Goal mode 同样不自动随 M4 出现。未来若实现，它可以消费 M4 的资源预算和 M5 的长上下文能力，但“何时认为目标完成、何时重试、无人值守时如何报告”必须另开设计，不能塞进预算模块。

## 5. 推荐提交边界

为降低回退成本，当前 M5 按以下边界提交；前四项 checkpoint 基础已经完成，M4 保留为未来独立里程碑：

1. `docs: lock measured context and compaction contracts`
2. `refactor: make turn boundaries and projection explicit`
3. `test: cover turn and projection boundaries`
4. `feat: add auditable compaction checkpoints`
5. `feat: compact sessions through the provider`
6. `feat: add controlled compacted history lookup`
7. `feat: add opt-in model-aware compaction preflight`
8. `test: cover compaction and history recovery end to end`
9. `docs: record recursive compaction measurements`
10. `feat: enable automatic compaction by default`，仅在测量门槛另行锁定并满足后存在。

每个功能提交都必须保持现有 read/edit/write/remember/shell、session resume 和 memory 测试通过。M5 未完整通过验收前，不删除原有 `context.limit_reached` 硬停止路径。
