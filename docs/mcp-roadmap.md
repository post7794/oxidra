# Oxidra MCP 接入路线

状态：MCP stdio transport/session kernel v1、显式 project-config reader v1、
execution-plan digest v1、JSON Schema profile v1、session-scoped tool registry v1、
durable execution coordinator core v2 和 MCP call-chain validator v2 已实现；v1 reader
保持冻结兼容，尚未接入 Agent 或 CLI 参数。
当前代码只能由 Rust 调用方显式加载绝对 config path、批准 execution plan 与 registry
surface，并把 coordinator 绑定到 session journal；它不是已经对用户开放的插件入口。

## 1. 边界与原则

MCP 不只是“从外部加载一组函数”。一次 `tools/call` 可能修改远程系统，
而客户端在写出请求后崩溃、超时或断线时，无法仅凭本地状态判断副作用是否
发生。因此 Agent 接入必须先解决以下问题，不能先把工具塞进 Provider 请求：

1. **execution approval 是进程级信任。** 启动/discovery 发生在任何 tool call 之前；
   获批 server 拥有当前 OS 用户的文件和网络权限，也可能在 startup/discovery 产生
   副作用。Linux seccomp 只约束生命周期和后代进程，不是权限 sandbox。未来的
   per-tool approval 只能确认请求意图并形成审计证据，不能反向限制已运行的进程。
2. **工具表是版本化输入。** Provider 看到的名称、描述和 schema 必须进入
   `context.tools` snapshot/epoch/digest；调用只能绑定生成该 tool call 时的工具表。
3. **授权先于 durable start。** 未通过项目 trust 和 per-tool approval 时，不能写
   `tool.started`，更不能向 MCP server 发送请求。
4. **写出后未知即 `in_doubt`。** 只有经过校验的 complete result 能关闭副作用
   不确定窗口；JSON-RPC error 也不能证明服务端已回滚。
5. **未知副作用不自动重试。** `tool.in_doubt` 必须复用现有人工解决协议，不能因
   transport 重启、turn retry 或 compaction 自动重放。
6. **历史协议有限且显式。** 只支持登记的协议版本和 reducer 版本；未知版本、
   动态 schema 变化和未支持的交互一律 fail closed。

## 2. 已实现：stdio kernel v1

实现位于 `src/mcp.rs`，集成测试位于 `tests/mcp_stdio.rs`。MCP 尚未进入 CLI/Agent 用户
路径，也未对外发布；journal 目前仅由显式 Rust coordinator API 写入。因此首次可持久化
版本直接登记当前实现为 kernel v1，内部提交序号不保留成伪历史协议。

### 协议范围

| 路径 | 冻结版本 | 行为 |
| --- | --- | --- |
| modern | `2026-07-28` | 先调用 `server/discover`；每个 request 携带协议、client info 和 client capabilities metadata；校验 complete/cache 字段、tools capability 和 modern `resultType`。 |
| legacy | `2025-11-25` | discovery 未被识别为 modern version rejection 时，先终止原进程，再启动新进程执行 `initialize` + `notifications/initialized`。 |

Modern discovery 的 self-reported server info 从
`_meta["io.modelcontextprotocol/serverInfo"]` 读取；该字段按规范是可选信息，不能
作为 executable 或项目 trust 的身份凭证。明确、结构完整的 modern unsupported
version error 会阻止降级；普通 method error、无响应、EOF 或 transport I/O failure
只会触发一次干净的 legacy restart，不会在同一进程混用两套握手。

参考的冻结规范：

- <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports>
- <https://modelcontextprotocol.io/specification/2026-07-28/server/discover>
- <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>

### 资源与进程边界

- stdio 使用单个长生命周期 JSON-RPC 进程，复用已发现的工具表。
- executable 必须是可 canonicalize 的绝对文件路径；cwd 必须是现存目录。配置加载
  会生成不可变 prepared execution plan；canonical executable/cwd、参数、环境继承权限
  和 config SHA 在任何 server 启动前进入独立 execution-plan digest，spawn 不再重新解释
  原始路径。prepared plan 会冻结本次 spawn 使用的实际环境值，但公开 digest 不包含这些
  值，避免把短 token 或低熵密码变成离线猜测 oracle。
- 子进程先 `env_clear()`，只继承显式 allowlist 和显式配置值；环境变量名按
  ASCII 不区分大小写去重，避免同一配置在 Windows 与 Unix 上产生不同含义。
- `ProcessTree` 在 Windows 使用 `CREATE_SUSPENDED` 启动 MCP 进程，先关联带
  `KILL_ON_JOB_CLOSE` 的 Job Object，再恢复主线程。Linux stdio kernel v1 在 `exec`
  已批准的 server 代码前安装 seccomp：允许同一 thread group 内的线程，但拒绝独立
  `fork`/`vfork`/`clone`/`clone3`、namespace/session/process-group escape，并禁止清除
  `PDEATHSIG` 或通过 credential mutation 触发内核清除；Oxidra 同时用 pidfd 固定唯一
  server PID 的身份。宿主被 `SIGKILL` 时，
  唯一 server process 由 `PDEATHSIG` 终止；受控清理使用 pidfd，不再扫描 `/proc`、
  推断 adopted lineage 或按可复用的数值 PID 杀进程。Linux x86_64/aarch64 缺少
  seccomp/pidfd 时，以及其他 Unix（包括当前 macOS）缺少等价边界时，都会 fail closed。
  受支持平台上的连接失败、取消、协议错误、in-doubt、shutdown 或宿主强杀不会留下
  MCP 后代进程。
- Linux kernel v1 的 lifecycle 保证来自“禁止 server 创建独立子进程”，不是启动后补扫后代。
  因此当前不支持需要 subprocess 的 MCP server，也不支持依赖 `npx`、shell wrapper
  等二次 spawn 的启动链；应直接配置最终 interpreter/executable。若未来需要允许
  subprocess，必须新增基于 PID namespace/cgroup 或等价 ownership primitive 的 kernel
  版本，不能放宽 v1 的冻结语义。x86_64 与 aarch64 的 classic-BPF instruction stream
  各有固定 SHA-256 fixture，修改 syscall policy 必须升级 kernel/registry 版本。
- 该 containment **不限制**已批准 server 以当前 OS 用户权限读写文件或访问网络；
  它解决的是受支持平台上的 spawn/cleanup ownership，不是插件权限隔离。需要运行
  不可信插件时，必须另行设计 AppContainer、低权限账户、namespace/cgroup、文件与
  网络 capability 等权限边界，不能把 per-tool approval 或 seccomp no-subprocess 当替代品。
- server stderr 使用持续 drain 的 64 KiB 有界捕获，不直接继承交互终端；诊断快照
  带 server 来源前缀，并清理终端控制字符、bidi、零宽字符和 Unicode 行分隔符，
  避免污染后续 trust/approval 界面。
- 已经 cancelled 的 connect 在第一次 spawn 前返回；modern fallback 到 legacy 前会
  再检查 cancellation，不会为已取消的连接执行 server 初始化代码。
- 单条 JSONL 上限 1 MiB；工具表上限 512 KiB、512 个工具、64 页；单次工具
  result 上限 50 KiB。
- `inputSchema` 与可选 `outputSchema` 必须通过固定 JSON Schema profile v1，根类型
  为 object。profile 支持登记的 type/object/array/string/number/composition 关键词，
  拒绝 `$ref` 和所有未知关键词。为避免 serde_json 默认 f64 在 wire 解析时先舍入，
  schema 和 instance 内所有 decimal/exponent/f64 数字 fail closed；profile v1 只接受
  serde_json 可无损保存的 i64/u64 数字。对象相等递归且键序无关；`enum`、`const`、
  `uniqueItems` 共用同一规范化 identity。实例先以迭代式结构扫描验证深度、节点数和
  数字表示，之后才进入任何递归 serializer/evaluator；调用参数随后以有界 JSON writer
  检查至多 256 KiB。实例最多 16,384 个节点、65,536 次验证访问，`uniqueItems`
  数组最多 4,096 项并使用规范化 identity 的有界判重，避免 O(n²) 回扫。
  Session 和 registry 的公开 `call_tool` 都是同步外壳：在构造 future 前把裸 `Value`
  放入带迭代式 `Drop` 的 owning wrapper，并完成结构 preflight。future 在首次 poll 前
  被丢弃也不会递归析构深层输入；扫描与释放都使用 container iterator frame，辅助空间
  为 O(depth)，不会为宽容器复制一份 O(nodes) worklist。通过 preflight 后才允许把有界
  value 移入 request future。
  evaluator 使用 typed outcome 区分 schema mismatch、resource limit、unsupported value
  和 internal failure；`anyOf`/`oneOf`/`not` 只能吞掉真正的 mismatch，其余错误必须
  传播。超限或无法精确表示的数字均 fail closed。
  调用参数在序列化 `tools/call` 前验证；失败返回
  `validation_error`、`in_doubt=false` 且 server 收不到请求。声明 output schema 时，
  complete result 必须包含满足 schema 的 `structuredContent`；失败按已写出协议错误
  返回 `in_doubt=true` 并关闭 transport。它是有限 profile，不声称实现完整 JSON Schema。
- tool name 只接受 MCP 登记的 ASCII `[A-Za-z0-9_.-]` 子集，Agent 层仍需映射为
  独立、稳定、无碰撞的 Provider tool name。
- server 若声明 `tools.listChanged=true`，或会话中发送
  `notifications/tools/list_changed`，当前 kernel 拒绝继续。动态工具 epoch 尚未实现。
- cancellation 会尽力发送 `notifications/cancelled`，随后永久关闭 transport；
  已写出的取消、超时、EOF、I/O、协议错误和 JSON-RPC error 都返回 `in_doubt`。
- modern `input_required` 等 nonterminal result 当前作为 unsupported interaction，
  关闭 transport 并返回 `in_doubt`。

## 3. 已实现的 policy 基础

### 3.1 显式 project config v1

- 不自动发现仓库文件；调用方必须显式提供位于 project root 内的绝对 config path。
- config 必须是非 symlink、UTF-8、至多 64 KiB，并声明 `version = 1`。
- 最多 16 个 server；名称唯一，command 为绝对文件，cwd 为 project 内相对目录。
- project config 只允许环境变量 inherit allowlist，不接受明文 `[servers.env]` secret。
- 原始 config bytes 计算 SHA-256；effective canonical command/cwd、args、继承环境变量名
  和显式环境变量名进入启动前可得的 execution-plan digest v1。路径按平台使用无损
  OS-native 编码，不通过 `to_string_lossy()` 生成执行身份；实际环境值不进入公开
  SHA-256，避免为低熵 secret 建立离线猜测 oracle。
- execution-plan v1 是 **path/command capability trust**，不是代码内容 attestation。
  它批准 canonical command、cwd、args 和环境权限；不会散列解释器参数所指脚本、
  executable 的依赖闭包或文件内容。文件在相同路径被原地替换时 digest 不变。若未来
  需要“批准具体代码字节”，必须新增独立、版本化的 content-identity 协议，不能原地
  扩大 v1 的含义。
- `McpProjectConfig::load()` 只被动生成 immutable prepared plan；
  `approve_execution(expected_digest)` 才生成 Registry connect 所需的 capability。
  trust UI 与 spawn 必须消费同一个 prepared plan，digest mismatch 在启动任何代码前失败。

### 3.2 session-scoped registry v1

- 合并 server 工具后仍限制为 512 tools / 512 KiB，不把 per-server 限额误当全局限额。
- raw identity `(server, tool)` 映射为满足 Responses function-name 约束的稳定 64-byte
  namespace；alias 带 identity hash，且仍执行实际 collision 检查。
- input/output schema、raw/provider name、server 协议版本、execution-plan v1、stdio
  kernel v1 和 JSON Schema profile v1 进入 registry-digest v1；字面量 fixture 固定
  其 SHA-256。coordinator activation 首次把该 v1 identity 写入 journal；不存在需要兼容的
  v2-v4 伪历史 digest。
- registry 可统一 shutdown 全部长连接进程，但真实 dispatch 已不是公开方法；surface
  digest 匹配后生成的 `ApprovedMcpRegistry` 只能交给 execution coordinator。registry
  内部 dispatch 还要求 coordinator 私有、按值消费且不可 clone 的 `DispatchPermit`。
  `McpStdioSession::call_tool` 仍保留为显式高级调用方使用的低层 API，不属于 Agent 的
  正常执行路径，也不提供 journal/approval 语义。

execution-plan digest 与 registry digest 是单向的两层证据：前者在启动任何外部代码
之前授权“按哪些路径、参数和环境权限执行”，后者只能在 discovery 之后冻结“模型能
看到哪些工具”。工具表 digest 不能反向充当 executable 的执行许可；path trust 也不能
被表述成具体代码内容已经得到认证。

### 3.3 durable execution coordinator core v1/v2

`McpExecutionCoordinator` 是正常 registry dispatch 的唯一 capability owner。Rust 可见性
和私有类型建立以下边界，而不是依赖调用约定：

```text
McpRegistry::approve_surface(expected digest)
→ ApprovedMcpRegistry
→ McpExecutionCoordinator::activate(session journal)
→ private single-use DispatchPermit
→ pub(super) registry dispatch
```

- 当前 writer 使用 coordinator v2；v1 activation reader 保持原有 `provider_names` 语义。
  activation 同步写入 `mcp.registry.activated`，绑定 session、coordinator ID、registry
  epoch、config SHA、execution-plan digest、registry digest，以及 kernel/schema/registry/
  coordinator 的具体版本；v2 还持久化排序后的
  `provider alias → server/raw tool/protocol` binding snapshot，供离线 reducer 查表证明
  provenance。live coordinator 只能写入同一 session journal。
- 每次调用先对参数完成同步 bounded ownership/preflight，再验证 durable
  `response.completed.output_items` 中存在唯一、同 turn/call ID、同 provider name、同参数
  digest 的 Provider call；对应的 `response.started` 还必须显式记录当前
  `mcp_registry_epoch_id` 与 `mcp_registry_digest`，并且该 response 必须在 activation 之后。
  schema preparation 失败也不能借另一个真实 call ID 写 terminal。
- per-call approval 前和通过后都从 journal snapshot 重建 candidate，并用冻结的 Provider
  request-slot reducer v2 验证假想 `tool.started`。approval handler 不持有 journal，不能在
  approval await 期间另行写入同一 writer；请求同时提供完整、有界的 `arguments_json`，
  `arguments_display` 只是终端安全的展示摘要，不能作为审批策略的唯一输入。
- approval 通过后先 fsync `tool.started`，再生成不可构造、不可 clone、按值消费的 permit。
  permit 绑定 turn/call、provider/raw tool identity、registry epoch/digest、协议版本、server
  attempt、参数 digest、coordinator ID 和 durable started seq；registry 与 session 在发送前
  再核对 authority、binding、attempt 和参数。
- validated complete result 写 `tool.completed`；请求可能写出但没有 validated complete
  result 时写 `tool.in_doubt`；dispatch 前的已知拒绝不会产生 `tool.started`；started 后的
  已知失败 terminal 必须引用 `started_seq`。terminal fsync 报错会 poison 当前 journal
  writer；reopen 后只按实际可见的 durable prefix 保守归约，并且绝不自动重发。
- Session 的公开裸 `Value` 入口有 50,000 层 unpolled-future 回归；registry/coordinator
  不再暴露同类入口，只消费已经完成 bounded preflight 的 owning type 或 journal parser
  产生的有界 durable value。future、approval await 和 dispatch permit 不重新持有未受保护的
  深层裸 `Value`。
- coordinator 从 durable Provider call 派生参数，不接受调用方另传一份可错配的裸参数；
  每个 session 只允许一个 registry activation。已有 `tool.started`/`tool.in_doubt` 未
  解决时，新的 MCP dispatch 统一 fail closed，禁止把 remaining calls 交给调用方约定跳过。
- activation 不允许跨越 pending compaction boundary；已经结束的旧 boundary 使用其
  activation 前兼容视图，后来的 v2 registry epoch 不会追溯改变冻结的 boundary v6 语义。

coordinator core 当前仍不是 Agent 集成完成的声明。`McpExecutionCoordinator::resume()` 已能在
session reopen/recovery 后，用重新取得 execution trust 与 surface trust 的 live registry 复用
原 durable epoch：config、execution plan、Provider surface、registry digest 和 activation policy
必须逐项一致；未恢复的 pre-start MCP call 会 fail closed，且不会写第二条 activation。
resume 的启动顺序由类型而不是注释约定：只有 `SessionStore::open` 返回的同一 journal handle
能一次性签发 `McpResumeEligibility`；`McpRegistry::connect_for_resume` 在 spawn 前消费它，并返回
独立的 `McpResumeRegistry`；其 surface approval 生成 `ApprovedMcpResumeRegistry`，而
`McpExecutionCoordinator::resume` 不接受普通 `connect` 产生的 `ApprovedMcpRegistry`。eligibility
同时绑定 open-handle nonce、session、activation seq/版本、config SHA、execution-plan digest、
registry epoch/digest；配置不一致会在执行任何 MCP 代码前失败，同一 open handle 不能重复启动。
但 Agent 尚未消费该 reader，也尚未把 `context.tools` snapshot writer 改为在
`response.started` 填充上述 registry epoch 字段。Agent 必须从同一 prepared request snapshot
写入这些字段，证明 Provider request 所使用的 `context.tools`、返回 call、approval、started
和 permit 属于同一个 epoch；完成这条绑定前不能把 MCP definitions 放进 Agent 请求。

### 3.4 MCP call-chain validator v1/v2

MCP terminal 的语义权限现由单一、冻结的 call-chain validator 授予，不再要求 turn、slot、
projection 和 history 各自“碰巧做出相同判断”：

- v1 仍由 coordinator v1、turn v6、Provider slot v3、source projection v5、history
  extractor v5 和 compaction boundary v6 按字面量解释。当前 writer 持久化
  `call_chain_validator_version = 2`；turn v7、Provider slot v4、source projection v6、
  history extractor v6 和 compaction boundary v7 冻结兼容集合 `{v1, v2}`，按 activation
  声明选择 exact reducer，并拒绝未来版本，而不是读取可变默认值。
- validator 从 activation 之后、显式带同一 registry epoch/digest 的 `response.started` 与唯一
  `response.completed` 重建 durable MCP call；activation 之前的同名普通工具保持历史语义，
  不会被未来 registry 追溯解释。
- lifecycle 必须使用 canonical `call_id`。generic reducer 兼容的 `id` alias 不能结算 MCP
  call；turn/call/provider、参数 digest、started seq、registry/execution provenance 和 terminal
  状态迁移均由同一 validator 证明。
- session reopen 在写入任何自动 recovery terminal 之前先验证已有 MCP chain。未开始调用仅
  能由 `journal.recovered` marker 授权的 `tool.skipped_due_to_recovery` 关闭，并绑定原始
  response seq、参数 digest 和 marker 中的 exact unstarted-call authorization；同时要求
  `response_seq < recovery_marker_seq < skip_seq`。其他 generic `tool.skipped_due_to_*` 在
  v1 中不能结算 MCP call。
- 同一 Provider response attempt 必须只有一个 terminal；session recovery 还会在写入 skip
  前后运行冻结的 generic Provider slot v2 consistency check，非法 response/tool ordering
  不会先被自动 recovery 写入污染。
- v2 将单个 Provider response 的全部 function calls（包括 MCP 与内置工具混合批次）限制为
  4096；Agent 在 `response.completed` 持久化前使用同一常量，超限只写 `response.failed`。
  v1 在该限制发布前可接受更大的历史批次，因此 recovery 不修改 v1 接受集合，而是先完整
  预检 authorization，再按每个 marker 至多 4096 条分片写入；每个自动 skip 只绑定其所属
  marker。恢复中途再次崩溃时，下一次 reopen 仅为剩余调用生成新的有界 marker。
- schema profile v1 也是 validator v1 的冻结传递依赖；历史 `tool.started` 不读取未来默认
  profile。未知 call-chain、activation、provenance 或 profile 版本一律 fail closed。

call-chain validator 解决的是 durable 事实解释，不会自动恢复 live server。下一阶段仍需在 session
reopen 后按已批准 execution plan 重建或替换 live registry epoch，并把实际 request 的
`context.tools` snapshot 与 `response.started` epoch 一次性绑定；完成前不能向 Agent 暴露
MCP definitions。

## 4. 尚未实现：Agent 与 CLI policy

下一阶段必须按以下顺序推进。

execution coordinator core 已建立；CLI、Agent 和 recovery 不能再直接持有 registry
dispatch primitive，也不能分别推断“是否获批”“是否已 dispatch”或“如何终态化”。
它们只能消费 coordinator 从同一 durable snapshot 生成的版本化调用计划：

```text
durable execution trust
→ registry snapshot / epoch
→ per-call approval
→ tool.started fsync
→ dispatch
→ exactly one immediate outcome: tool.completed | tool.in_doubt

tool.in_doubt
→ eventual tool.in_doubt_resolved terminal
```

`ApprovedMcpProjectConfig` 只是启动 capability 的类型约束，不是 durable approval 的
事实源。Agent 接入还必须把以下身份锁定为同一 snapshot，不能只因 provider alias 相同
就授权调用：

```text
context.tools registry digest/epoch
= Provider request registry digest/epoch
= returned call identity
= approval request epoch
= tool.started provenance
= DispatchPermit epoch
```

### 4.1 CLI trust

config reader 已实现，但 CLI 还不能选择它。用户入口必须：

- server 默认禁用，不能自动读取其他 MCP 客户端配置；
- 启动前显示 prepared canonical executable、cwd、args、inherit-env names、config
  SHA-256 和 execution-plan digest；spawn 必须消费被展示的同一个 prepared plan；
- 非交互模式必须显式绑定 config SHA-256，不能只用 `--full-auto` 跳过；
- resume 时 execution-plan digest 变化必须在启动前重新取得 execution trust；registry
  digest 变化则在 discovery 后重新取得 tool-surface trust，二者不能混为一次批准；
- 第一版只接 stdio，不接 HTTP、OAuth、远程 discovery 或自动安装。

### 4.2 Agent tool registry

底层 registry 已能建立 snapshot；Agent 仍需：

- raw identity 为 `(server_name, raw_tool_name)`；
- 生成满足 Provider 约束的稳定 namespace，长度超限或 alias collision 时 fail closed；
- 保存原始 MCP schema、Provider 投影 schema、server protocol、kernel version、
  config digest、schema-profile version 和全表 digest；
- 直接消费已登记的 MCP JSON Schema profile v1 验证结果，不能改用会忽略未知关键词
  的内置 `validate_json_schema()`；
- 合并内置/history/MCP 工具前做全局 collision 检查；
- registry snapshot 进入 `context.tools`，同一 prepared request 与后续调用必须使用
  同一 epoch，不能在中途重新 list。

### 4.3 journal 与恢复

优先复用现有 turn/tool reducer，不再建立第二套终态事实源：

- approval 通过后、dispatch 前同步 `tool.started`，附带 MCP provenance、参数、
  registry epoch/digest 和 server attempt ID；
- validated complete result 同步 `tool.completed`；MCP `isError=true` 是已知 terminal
  error，不是 `in_doubt`；
- request 可能已经写出但没有 validated complete result 时同步 `tool.in_doubt`；
- transport/kernel 的 `in_doubt` 只能由现有 `tool.in_doubt_resolved` 流程显式解决；
- session reopen 必须在启动 MCP server 前先归约 journal；存在 unresolved in-doubt 时
  禁止继续 Provider turn；
- session reopen 在自动写入 `response.aborted`、recovery skip 或 boundary repair 之前先运行
  MCP call-chain validator，并在 repair 后再次验证完整 journal；
- projection/history 只消费同时通过冻结 call-chain validator 与 turn reducer 的标准 tool
  terminal，不自行建立第二套 MCP terminal 事实源。

### 4.4 approval 与结果投影

- 第一版所有 MCP tool 默认需要 approval；不能让 `--full-auto` 自动授权远程副作用。
  该 approval 只确认本次 `tools/call` 意图和 durable journal 顺序，不是 MCP 进程权限
  sandbox，也不能覆盖 startup/discovery 已经可能产生的副作用。
- 后续若增加只读 policy，权限必须来自本地配置，不信任 server annotations 自报。
- MCP `content`、`structuredContent` 和 `_meta` 是不可信 tool output；投给模型前使用
  有界、确定的 envelope，不提升为 instructions。
- 图片、resource link、embedded resource 等内容类型必须逐类登记；未登记类型不能
  通过字符串拼接静默降级。

## 5. 暂不支持

- Streamable HTTP、OAuth、远程 server discovery；
- prompts、resources、sampling、roots；
- elicitation / modern input-required 续交互；
- `tools/list_changed` 和会话内 schema 热更新；
- 自动安装 executable、从 shell `PATH` 猜测命令；
- MCP server annotations 直接授予只读或免审批权限；
- in-doubt MCP call 的自动 retry。

## 6. Agent 接入完成门槛

在用户可见入口启用前至少需要：

1. 配置/trust 的字面量 fixture 与跨平台 canonicalization 测试；
2. tool namespace、长度和 collision 反例；
3. `context.tools` epoch/digest 与 resume 配置漂移测试；
4. `started fsync -> 强杀 -> reopen -> in_doubt` 进程故障注入；
5. complete、MCP `isError`、RPC error、取消、timeout、server exit、超限结果测试；
6. unresolved in-doubt 阻止 Provider 继续和人工 resolution E2E；
7. approval 未通过时 journal 无 `tool.started` 且 server 未收到 `tools/call`；
8. schema-invalid 参数不 dispatch、未知关键词 fail closed、output mismatch 进入
   `in_doubt` 的 fixture；
9. Debug/Release、Clippy、Rustdoc、fmt、`git diff --check` 和三平台 CI。

真正的完成标准不是“模型能调用一个 MCP tool”，而是：**schema、授权、durable
dispatch、副作用不确定性与 resume 都由同一个版本化证据链约束。**
