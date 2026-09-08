# Oxidra Friction Log

用于记录当前使用过程中已经观察到的摩擦点，作为后续产品与工程改进的输入。这里先记录问题，不在本文中提前确定具体实现方案或优先级。

## Session 管理

### 磁盘 reader 的预算不能替代内存 API 的前置校验

公开 helper 和 reducer 可以接收调用方直接构造的 `JournalEvent` / `Value`，并不必然经过
`SessionStore`。已用子进程回归复现并修复 history 输出计费、compaction boundary 解析、
MCP 结果展示及 turn→MCP 参数读取的深层 JSON 栈溢出。递归操作前复用迭代式深度检查，
展示采用固定容量 writer；测试同时保留历史 reader 可接受的深度上界。后续新增公共 JSON
入口必须说明它消费的是已验证的 owner 还是裸 fixture，不能仅以“journal 已有预算”作为依据。
这不等于任意外部 DTO 操作有界，也未消除 Provider 多份 canonical/projection 副本的峰值开销。

### 文件系统边界仍依赖 pathname

- Unix data/session/artifact/memory 状态已收紧到目录 mode `0700`、文件 mode `0600`，但没有移除额外 POSIX/extended ACL 或证明远程文件系统按本地 mode 语义执行；Windows 继续依赖 data-root ACL。builtin/history 的 bounded read 会 no-follow 打开最终组件、验证 exact handle 为 regular file，并限制真实读取字节数。
- 但 session `open/list/inspect/export/delete`、history artifact 目录解析和 builtin 的 parent canonicalization 尚未改为 `openat`/NT handle-relative traversal。同一 OS principal 的并发进程仍可在验证后替换父目录、junction/reparse point 或 pathname；当前模式位和 canonicalization 只覆盖非对抗性 namespace。若产品要把同用户插件也视为攻击者，必须引入独立 principal/sandbox 或可信的 handle-relative filesystem broker，不能继续在每个调用点追加 pathname recheck。
- `edit` 的 full-file SHA-256 和发布前复查能发现复查之前的普通并发写入，但 portable rename 不是 compare-and-swap；复查后到原子替换前仍有窄窗口可覆盖同用户 writer 的新内容。要关闭这一点，需要平台 inode/file-ID 绑定的交换/回滚协议或 broker，而不是再加一次 pathname read。

### `session` 命令需要删除能力

- 需要提供 `oxidra session delete <SESSION_ID>`。
- 删除 session 时应同时清理对应的 journal 和 artifact。
- 不能删除仍被其他进程打开的 session。
- 删除不存在的 session 应有明确、可理解的结果。

状态：已在当前工作区实现，尚待发布。

### `--resume` 不会显示历史对话

- 使用 `oxidra --resume <SESSION_ID>` 后，模型侧会重放 session 历史，但终端不会先展示已有对话。
- 用户看到的是一个空白的新 REPL，体验上像打开了新对话。
- 用户难以确认恢复的是哪个任务、此前讨论了什么，以及当前工作进行到了哪里。
- 恢复时需要提供可读的历史展示或清晰摘要，同时避免把工具原始事件全部倾倒到终端。

### Session 缺少可读标题

- 同一个项目目录里可能同时存在多个 session，随机 session ID 无法让用户快速判断它们分别对应什么任务。
- `session list` 只展示 ID 和时间时，用户需要逐个 resume 或查看原始 journal 才能确认目标。
- 新建 session 时应支持设置可读标题，并允许后续修改；标题应在 list、show 和 resume 选择中展示。
- 标题是用户导航用的元数据，不应替代不可变的 session ID，也不应改变 journal 的审计身份。

## 对话编辑与输入修正

### Ctrl+C 后拒绝 in-doubt 解决会退出整个 REPL

- 取消 turn 后进入 in-doubt 解决提示，回答 N 时 `ApprovalRequired` 沿错误链传播，直接退出 REPL 进程。
- 用户的直觉是"取消当前轮、继续会话"，而不是被迫立即做出 in-doubt 决定否则丢掉会话。
- 未解决的 in-doubt 调用本身已经会阻止下一个 turn 开始，安全性不依赖强制退出。

状态：已在当前工作区实现（REPL 内拒绝后回到提示符，下一轮继续询问），尚待发布。

### 已发送的对话无法编辑

- 用户说错内容后，目前只能按 `Ctrl+C` 取消当前回合，再重新发送一条消息。
- 取消并重新发送会在 session 中留下错误消息、取消事件和修正消息，使对话历史变得不干净。
- 如果错误消息已经触发了模型响应或工具调用，简单取消还可能留下不完整 response 或需要恢复的状态。
- 需要支持编辑最近一条用户消息，并以明确的 journal 语义替换或修订该消息及其后续派生响应。
- 编辑操作应保留审计记录，同时让后续上下文只使用修订后的对话分支，避免把错误输入和旧分支重复发给模型。
- 需要明确编辑发生在响应开始前、响应进行中、工具调用后等不同阶段时的取消、回滚和副作用处理规则。

## Provider 与网络可靠性

### 标准 reasoning summary 事件被误报为未知事件

- `gpt-5.6-sol` 会流式发送 `response.reasoning_summary_part.*` 和 `response.reasoning_summary_text.*` 事件。
- provider 只识别文本与工具参数增量时，会把这些标准进度事件逐条打印为 `[provider] ignored unknown event ...`，短时间内造成大量重复日志。
- 日志恰好出现在 Ctrl+C 附近时，用户会误以为取消没有生效；实际上这些是取消前已到达的 SSE 帧，与工具或请求继续执行不是同一件事。
- 已知但无需展示的进度事件应静默处理；真正未知的协议事件仍需保留诊断，但后续应关注去重或限流，避免新版协议事件再次淹没终端。

状态：已在当前工作区实现（reasoning summary 的四类进度事件登记为已知 no-op，并保留真正未知事件诊断），尚待发布。

### SSE 无数据挂起会永久阻塞

- HTTP client 此前只有 connect timeout，SSE 流建立后若服务端停止发送数据，读取会永久阻塞。
- `-p` 非交互模式下没有人工 Ctrl+C，一次服务端挂起就会挂死整个进程。
- keep-alive 帧和流式 delta 都会重置空闲计时，长响应不受影响。

状态：已在当前工作区实现（reqwest `read_timeout` 300 秒，超时走既有 transport error 路径），尚待发布。

### SSE 断流会直接中止整个任务

- 当前在收到首个 SSE 事件后发生断流时不会自动重连。
- 普通网络波动就可能导致当前 response aborted，并直接中止整个任务。
- 长时间运行或包含多次工具调用的任务更容易受临时网络问题影响。
- 需要安全的断流恢复或自动重连机制，同时避免重复展示文本、重复提交 response，以及重复执行副作用未知的工具调用。
- 恢复策略需要利用 Responses API 能力、已接收事件状态和 session journal 明确区分“可以安全续传”与“不能安全重试”。

### 需要支持多个 API 协议

- 当前内核只接入 OpenAI Responses API，实际使用中还需要兼容 Anthropic Claude Messages API 和 OpenAI Chat Completions API。
- 三种协议在请求格式、系统提示字段、流式事件、文本增量、工具调用参数、工具结果回填、usage 统计和取消语义上都不完全一致。
- 不能把协议差异泄漏到 Agent 主循环；应在 provider 适配层统一为同一套响应、流式事件、工具调用和中断结果契约。
- 需要保留原始响应，保证 session journal 可审计、跨进程恢复和未知字段前向兼容；不同协议的原始 payload 不能被过早压成只含可见文本的格式。
- 测试至少覆盖：纯文本流、工具调用流、工具结果回填、reasoning/扩展事件、错误与重试、Ctrl+C 中断，以及非流式兼容端点。

状态：记录为后续协议适配需求，当前不实现；先维持 Responses API 的单协议基线。

## 安全与凭据

### 未签名的 Windows release 曾触发 Defender ML 误报

- 本地 `cargo test --release` 期间，Defender 曾将 `oxidra.exe` 判为 `Trojan:Win32/Bearfoos.A!ml`；源码、锁文件和构建链审计均未发现异常，`DidThreatExecute=False`，属于基于二进制形态与低信誉的启发式命中。
- 取消 `strip = "symbols"` 后，标准 release 构建、Defender 定点扫描、`--help` 冒烟和完整 release E2E 均通过；该调整只缓解当前产物，不能保证未来编译器或代码布局变化后永不复发。
- 长期发布需要 Authenticode 签名，并在再次命中时向 Microsoft 提交对应 SHA256 和样本复核；不能把要求用户关闭实时保护或排除整个安装目录作为发布方案。

状态：当前 release profile 已保留符号以规避已观察到的误报；代码签名与误报提交流程待后续发布工程处理。

### `ProviderConfig` 的 Debug 会明文打印 API key

- `ProviderConfig` derive 了 `Debug` 且 `api_key` 是公开 String，任何 `{:?}` 打印（日志、错误上下文）都会泄漏 key。
- provider 层已手写 Debug 隐藏 key，config 层未对齐。

状态：已在当前工作区实现（手写 Debug 将 `api_key` 显示为 `<redacted>`，含回归测试），尚待发布。

## 终端输出与交互体验

### 工具调用没有折叠

- 每次工具调用的参数和结果都会直接展开显示。
- `read`、`shell` 等输出较长时会占据大量终端空间。
- 多轮工具调用后，很难快速定位 assistant 的结论、失败点和最终验证结果。
- 需要区分默认摘要视图与按需查看完整详情的能力。

### 命令与工具信息大量堆积在终端

- shell 命令、工具参数、工具结果、provider 诊断和回合指标连续输出。
- 信息缺少稳定的视觉层级，重要结果容易被过程日志淹没。
- 长任务会产生大量滚屏，回看成本高。
- 需要更清晰地区分进行中状态、成功摘要、错误详情和可展开的原始输出。

### 代码没有语法高亮

- assistant 输出的代码块目前按普通文本显示。
- diff 只有有限的红绿显示，普通代码、配置和日志没有语言感知高亮。
- 阅读较长代码片段时辨识结构较困难。
- 需要考虑终端能力检测、非 TTY 降级以及重定向输出保持纯文本的要求。

### 没有 TUI

- 当前是线性 stdout/stderr 输出，缺少固定的会话、任务和工具状态区域。
- 无法在不滚屏的情况下查看当前执行阶段、工具调用、上下文和 token 状态。
- 无法方便地折叠或展开工具详情。
- 缺少历史消息导航、选择和快捷操作。
- TUI 需要继续保持取消、流式输出、日志审计及非交互模式可用。

### Markdown 没有格式化渲染

- assistant 返回的 Markdown 当前基本按原始文本输出。
- 标题、列表、引用、表格、链接和代码块缺少终端友好的格式化。
- Markdown 与工具诊断混排时，内容层级不够清楚。
- 需要支持终端渲染，并在 `-p`、管道和重定向场景下保持稳定的纯文本输出。

## 长任务与上下文管理

### 自动 compact 仍然是显式 opt-in

- 默认不会自动 compact；用户显式传入 `--experimental-auto-compact` 后，当前模型才会按完整 prepared-request 估算尝试压缩。
- 每次交接都需要重新向模型解释大量背景，耗时且容易遗漏关键约束。
- `remember` 不适合交接大型项目，只能保存零散的长期记忆，无法替代完整的任务状态、决策链和工作上下文。
- 当前体验在长项目中很差，尤其不适合需要持续积累上下文的逆向分析和测试工作。

状态：checkpoint 数据模型、链校验、projection、真实 Provider 摘要调用、故障恢复、压缩前缀历史回查、递归摘要漂移 gate 和默认关闭的 `--experimental-auto-compact` 入口已实现；当前实现完成的是显式 opt-in 闭环。由于质量证据仍绑定具体 model/backend，不能据此对所有默认模型开启自动压缩。

### 磁盘保留完整历史不等于模型能回查历史

- checkpoint 可以让 journal 永久保留压缩前原文，但压缩后的 Provider 请求默认只看到 summary 与 cutoff 后的 tail。
- summary 遗漏精确数值、错误文本或旧 artifact 时，仅靠 `session show` 能让用户审计，不能让 agent 自己恢复事实。
- 自动 compaction 在缺少受控历史回查时启用，会让“磁盘可恢复”和“模型可利用”之间出现功能断层。
- 需要让模型只在当前 session 的 checkpoint 覆盖前缀内做确定性、带引用、有限额的回查；查询结果仍是不可信 tool output，不能获得 instructions 权限。

状态：`history_search` / `history_turn` / `history_artifact` 已实现并通过配额、授权和跨平台测试；checkpoint 后的普通 Agent 请求可按边界和配额向模型暴露这些工具。详细契约保存在 `docs/m4-m5-roadmap.md`。

## 工具生态与扩展能力

### MCP kernel 已实现，Agent policy 尚未接通

实际工程需要接入外部专业工具，固定需求包括：

- Chrome DevTools MCP
- JADX MCP
- IDA Pro MCP
- Tavily MCP
- SSH MCP

当前已实现有界、版本化的 MCP stdio transport/session kernel、不可变 prepared
execution plan、显式 project-config reader 和 session-scoped namespaced registry，
支持 modern `2026-07-28` discovery
和冻结的 `2025-11-25` legacy fallback，并覆盖进程树、显式环境 allowlist、
分页/大小限制、spawn 前取消、启动前 execution-plan digest、discovery 后 registry
digest 以及 `in_doubt`。Windows 使用 suspended Job Object；Linux stdio kernel v1 在
exec 前用 seccomp 禁止独立子进程和逃逸操作，以 `PDEATHSIG` 覆盖宿主强杀，并以 pidfd
固定唯一 server process 的身份，不再依赖 `/proc` descendant 推断。该版本因此暂不
支持需要 subprocess 或二次 launcher spawn 的 MCP server；缺少等价 containment 的
macOS 当前在 MCP spawn 前 fail closed。
execution trust 明确是授予当前 OS 用户权限的 path/command capability trust，不是脚本
或依赖内容证明；继承环境的秘密值也不进入公开 digest。no-subprocess seccomp 只负责
lifecycle containment，不限制文件或网络权限；未来 per-tool approval 只是请求意图确认
与审计，不是进程 sandbox。固定 JSON Schema profile v1 已在 dispatch 前验证参数、在
complete result 后验证 structured output，并由 registry digest 绑定。durable execution
coordinator core、registry epoch activation、call-chain validator v4 与 crash recovery 已接入
journal。新的 writer-side tool-surface snapshot 已能把 live registry alias、definition/
output-schema digest 与 builtin/history 工具表合并并在写入前拒绝名称碰撞；generic journal
writer 也会在 MCP-sensitive event fsync 前运行冻结 reducer。live coordinator 和公开的 typed
Provider/context writer 绑定当前 runtime journal handle；首次 activation 还会在 spawn 前消费该
generation 的 one-shot startup slot。coordinator 与独立 native transport reaper 共同持有 session
lock execution lease；kill 只是请求，只有 direct child 已 reap 且 Windows Job 的 active process
归零才释放最后一份 lease，所以 journal/coordinator 或 Tokio runtime 单独 drop 后不能在旧 MCP
  transport 完成退出前 reopen。session-bound execution guardian 还持有独立 generation gate：
  READY 前先 fsync active-generation record，正常 host death 时先终止并等待已注册 Linux pidfd
  target 退出 / Windows per-server Job 归零，再 fsync matching clean record 并允许 reopen；若
  guardian 自身先被强杀，OS lock 虽会释放，但 durable active state 使 session 永久 fail closed，
  且 v1 不支持原地恢复。正式出口只有 `oxidra session export <ID> <ARCHIVE>.oxidra-session-export`：在普通 session lock
  下写入 non-journal manifest 后附未经 repair 的 exact 原始 JSONL bytes，使 archive 不能被误作
  新 session resume，同时不清除 gate、不重新授权 dispatch。destination 父目录必须由 operator
  控制且不能允许不可信并发 writer；v1 pathname publisher 不防御同用户 namespace race。
  Windows 由单线程 guardian 创建 Job、stdio pipes 和 suspended child，通过
`PROC_THREAD_ATTRIBUTE_JOB_LIST`/`HANDLE_LIST` 从 process birth 起原子完成 containment，
再把 host-side handles 复制给 exact host 并等待一次性 resume 决定；这也避免了 host 内并发
std/tokio/第三方 spawn 继承临时 pipe handles。guardian 还会在 READY 前证明自己不属于任何 supervisor Job，无法
  完全 breakaway 时 fail closed。该 guardian 与
  MCP server 仍属于同一 OS 用户，普通 lock path 和 durable state 也不是权限隔离；主动终止 guardian
  会牺牲 session 可用性，而替换 gate 或篡改其他同用户状态仍在保证之外。若把
server 视为主动对抗代码，仍需低权限 token/AppContainer、独立账户或可信系统服务。旧 authority
即使 session/registry digest 未变也不能继续写入或 dispatch；generic Provider admission 会拒绝
MCP-owned start 与 activated-alias completion。activation/call-chain v3
reader 已能严格证明 activation、global `context.tools`、request context 与
`response.started.mcp_surface` 的 exact relation，并阻止删除 claim 后把 activated alias 降级成
generic response；绑定的 input schema 和 lifecycle outer/nested provenance 也会按冻结 profile
重验。展示用 output-schema digest 仍不能证明 runtime structured validation；current v4 writer
已接入 model-facing result envelope v1：raw MCP result 只作有界 parsed-JSON 审计值，
model-facing projection 只允许严格 text-only 且由 offline reader 从 raw 重派生。v4 typed
Provider request admission 还会把 exact durable `context.tools`、`PreparedResponseRequest` 的
canonical body/sealed body bytes（仅由 crate-sealed MCP transport 消费）、digest/full measurement、protocol/usage domain 与 outcome
reserve 一次性绑定。CLI 参数、Agent approval 和 Agent glue 尚未接通，因此用户现在仍然只能使用固定内置工具，
不能把上述 MCP server 暴露给模型。

统一 protocol epoch 已升级为 call-chain v4、turn v8、Provider slot v5、source/history v8 与
compaction boundary v8；turn/source/history v8 按 owning `user.message` 选择 recovery grammar，
不再按 journal 最大版本追溯解释旧 turn。下一步让 Agent/CLI 消费已有的 session-open resume capability，并把 CLI
execution trust、Agent approval、typed Provider request admission 与 coordinator 的一次性 dispatch permit 接成唯一事实源，
不能退回 public generic Value writer。现有 CLI 的 durable `in_doubt` resolution transaction 必须复用，
不能再实现一套 MCP 专用终态 writer。
完整顺序与 release gate 见 `docs/mcp-roadmap.md`；不能把 kernel 的存在误报为已完成
用户入口。

### Skill 暂不作为当前重点

目前只使用 `grill-me` skill。Skill 扩展可以暂不考虑，优先解决 MCP 接入、长任务上下文管理和可恢复交接问题。

## 延后设计

### 多 Provider 凭据与切换

当前认证只支持一个活动 Provider：`config.toml` 保存 base URL/model，凭据存储保存一个与规范化 base URL 绑定的 API key。这样可以避免把 key 发给后来切换的代理地址，但不提供 Provider 列表、别名、按 Provider 保存多套模型参数或交互式切换。

如果实际使用中出现以下需求，再单独设计 Provider registry：

- 需要在官方 API、个人代理和本地兼容服务之间频繁切换。
- 同时维护多套 key、base URL、model 和 context 参数。
- 需要导入/导出、轮换或按 session 固定 Provider。

在出现这些使用证据前，不把单 Provider 认证扩展成新的插件或配置框架。
