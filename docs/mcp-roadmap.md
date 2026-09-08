# Oxidra MCP 接入路线

状态：MCP stdio transport/session kernel v1、显式 project-config reader v1、
execution-plan digest v1、JSON Schema profile v1、session-scoped tool registry v1、
durable execution coordinator core v4 和当前 MCP call-chain validator v4 已实现；v1-v3 reader
保持冻结兼容。v3 首次冻结 activation、Provider-visible tool surface 与 model-facing result
profile；v4 在同一 surface 关系上增加 versioned prepared-request envelope（canonical Provider
body、digest 和完整 measurement）以及发送 sealed body bytes 的 typed Provider request
admission。turn v8、Provider slot v5、source projection v8、history extractor v8 与 compaction
boundary v8 已同步升级到同一 compatibility epoch。Agent 与 CLI 参数仍未接入。
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
- Windows execution guardian 使用 `CREATE_SUSPENDED` 启动 MCP 进程，并通过
  `PROC_THREAD_ATTRIBUTE_JOB_LIST` 让进程从 birth 起属于带 `KILL_ON_JOB_CLOSE` 的
  Job Object，再恢复主线程。Linux stdio kernel v1 在 `exec`
  已批准的 server 代码前安装 seccomp：允许同一 thread group 内的线程，但拒绝独立
  `fork`/`vfork`/`clone`/`clone3`、namespace/session/process-group escape，并禁止清除
  `PDEATHSIG` 或通过 credential mutation 触发内核清除；Oxidra 同时用 pidfd 固定唯一
  server PID 的身份。宿主被 `SIGKILL` 时，
  唯一 server process 由 `PDEATHSIG` 终止；受控清理使用 pidfd，不再扫描 `/proc`、
  推断 adopted lineage 或按可复用的数值 PID 杀进程。Linux x86_64/aarch64 缺少
  seccomp/pidfd 时，以及其他 Unix（包括当前 macOS）缺少等价边界时，都会 fail closed。
  受支持平台上的连接失败、取消、协议错误、in-doubt 和受控 shutdown 不会留下 MCP
  后代进程。被动宿主强杀时，process-external guardian 继续持有 gate 直到 containment exact
  empty；guardian 自身先被强杀时，已 fsync 的 active-generation record 会让后续 reopen 永久
  fail closed。v1 不提供原地恢复：durable record 不包含足以机器验证旧 containment 已清空的
  平台身份，删除 gate 或强写 clean 都会重新打开 generation overlap。正式出口仅为
  `oxidra session export <ID> <ARCHIVE>.oxidra-session-export` 的只读 archive；它持有普通 session lock，但跳过
  execution gate、不会 repair/修改源 journal、不会清除 quarantine，也不能用于 resume/dispatch。
  API 强制专用 `.oxidra-session-export` 后缀，因此即使目标位于另一份 Store 的 `sessions`、
  `locks` 或 `artifacts` 树中，也不能占用其 `.jsonl`/lock/合法 session-id namespace。
  archive 首行是版本化的 non-journal manifest，后接 exact 原始 JSONL bytes 和 digest；因此把
  archive 放入另一个 `SessionStore` 也不会被误识别为可 resume journal。若 crash prefix 的末行
  不完整，manifest 还记录 complete-prefix offset、tail 长度和 tail SHA-256；export 不会替源
  journal 截断或补换行。destination 父目录必须由 operator 控制，不能允许不可信并发 writer；
  v1 pathname publisher 不防御同用户 namespace race。这里的 exact 只表示普通 session lock
  持有期间实际读取到的 bytes；v1
  不声称抵抗仍以同一 OS principal 运行的旧 MCP 对 source、destination 或 archive 的主动篡改，
  需要该保证时仍必须使用独立权限的 exporter/guardian 或外部签名边界。
  该方案选择 safety 而不是 guardian-crash 后的 availability，且仍假设同一 OS principal 没有
  主动篡改 gate state。
- stdio transport 把 `Child`、`ProcessTree` 和最后一份 execution lease 交给独立的原生 reaper
  thread；kill 只是请求，只有 direct child 的同步 `try_wait` 已完成 reap，且 Windows Job 的
  `ActiveProcesses` 已降为零，才会释放 lease 并发布完成。session、runtime 或已 started 调用的
  future 在 `Drop` 中通过复制的 Linux pidfd / Windows Job handle 同步请求终止；即使
  current-thread runtime 不再驱动或已整体销毁，reap 与锁释放也不依赖 Tokio 再次 poll。
- session-bound MCP 还会启动独立 execution guardian 持有第二个 generation gate。Linux MCP
  child 在 `exec` 前向 guardian 注册 exact pidfd。Windows 则由单线程 guardian 创建 per-server
  Job 与 stdio pipes，并使用 `STARTUPINFOEXW` 的 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 和
  `HANDLE_LIST` 原子创建 suspended child；只有 guardian 内的三个 child pipe ends 会在该次
  `CreateProcessW` 临界区短暂设为 inheritable，不与 host 中 std/tokio/第三方 spawn 的私有锁
  竞争。guardian 把 Job、process 与 host-side stdio handles 复制给 exact host，收到 host 已成功
  接管这些 handles 的一次性 resume 决定后才恢复 exact primary thread。因此既不存在
  CreateProcess→Assign/guardian-register 窗口，也不存在 host-wide inheritable-handle 窗口。
  host control pipe 关闭后，
  guardian 在 READY 前先追加并 fsync durable active-generation record；随后终止全部已注册
  containment，并在 Linux pidfd 全部退出、Windows Job `ActiveProcesses == 0` 后追加并 fsync
  matching clean record，最后才释放 gate。OS lock 只负责 live guardian 的互斥；durable state
  负责 guardian-first crash 后的 fail-closed safety。active、残缺、未知或状态机不匹配的 gate
  state 都会在 journal repair/恢复写入前拒绝 reopen，不会自动猜测旧 containment 已退出。
  Windows guardian 使用 `CREATE_BREAKAWAY_FROM_JOB`，并在
  READY 前用 `IsProcessInJob(..., NULL)` 证明已离开所有 supervisor Jobs；无法完全 breakaway 时
  MCP startup 在任何 server birth 前 fail closed，部署方必须显式允许 guardian breakaway。
  该 v1 guardian 在 host-first crash 时自动恢复，在 guardian-first crash 时选择 durable poison；
  poison 是永久 quarantine，不存在 `--recover` 或原地 clean 转换；只能在无 live session writer
  时导出带 non-journal manifest 的只读 archive，保留源 journal 与 gate 作为审计证据。
  它不是对同一 security principal 的权限隔离：当前用户权限的已批准 server 仍可能主动终止 guardian、unlink/替换
  普通 lock path，或攻击其他用户态状态。若威胁模型包含这种主动攻击，发布前必须把 guardian
  放入更高 integrity/独立账户/系统服务，或把 MCP 放入更低权限 token/AppContainer；不能把
  当前 helper 进程描述成不可绕过的恶意插件 sandbox。
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
  result 的**解析后 canonical JSON 表示**上限为 50 KiB。该上限不是原始 wire-byte
  审计（重复 key、空白和数字词法在 `serde_json::Value` 阶段已不可恢复）；收到超过
  canonical 上限的完整 result 仍是 post-dispatch `in_doubt`，不能伪装成 pre-dispatch/
  output-limit 已知失败，必须经过现有人工 resolution。
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
- 磁盘 JSON profile 不为调用方直接构造的内存 `JournalEvent` / `Value` 背书。
  公共 projection、compaction、history 输出计费及 turn→MCP reducer 路径，在递归
  Clone/Serialize 之前使用同一迭代式深度检查；这里保留历史 reader 的 128 层上界，
  不把新增节点或 decoded-byte 预算追溯施加到 legacy journal。`JournalEvent` 与
  `CompactionSource` 的 Clone/Drop 采用迭代实现。结果展示的 JSON 编码缓冲至多
  64 KiB，再产生至多 16 KiB 的清理后文本；不能先编码完整结果再截断。
  这些保证覆盖库内消费路径，不意味着任意外部 Rust 代码可以安全地递归打印、序列化或
  析构自己保存的裸 `Value`，也不构成整个 Provider 路径的单副本峰值内存保证。
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
- registry 可统一 shutdown 全部长连接进程，但真实 dispatch 已不是公开方法；无 session
  lease 的普通 `McpRegistry::connect` 也不再是公开入口。首次 activation 必须由
  `McpRegistry::connect_for_activation(session journal, ...)` 在 spawn 前消费 exact journal
  generation 的一次性 activation-start slot、校验无既有 activation/待结 compaction boundary，
  并捕获 lock lease；digest 匹配后生成的 `ApprovedMcpRegistry` 只能交给 execution coordinator。
  registry 内部 dispatch
  还要求 coordinator 私有、按值消费且不可 clone 的 `DispatchPermit`。
  `McpStdioSession::call_tool` 仍保留为显式高级调用方使用的低层 API，不属于 Agent 的
  正常执行路径，也不提供 journal/approval 语义。

execution-plan digest 与 registry digest 是单向的两层证据：前者在启动任何外部代码
之前授权“按哪些路径、参数和环境权限执行”，后者只能在 discovery 之后冻结“模型能
看到哪些工具”。工具表 digest 不能反向充当 executable 的执行许可；path trust 也不能
被表述成具体代码内容已经得到认证。

### 3.3 durable execution coordinator core v1/v2/v4

`McpExecutionCoordinator` 是正常 registry dispatch 的唯一 capability owner。Rust 可见性
和私有类型建立以下边界，而不是依赖调用约定：

```text
McpRegistry::connect_for_activation(session journal, ...)
→ approve_surface(expected digest)
→ ApprovedMcpRegistry
→ McpExecutionCoordinator::activate(session journal)
→ private single-use DispatchPermit
→ pub(super) registry dispatch
```

- 当前 writer 使用 coordinator v4；v1/v2 activation reader 保持各自原有语义。
  activation 同步写入 `mcp.registry.activated`，绑定 session、coordinator ID、registry
  epoch、config SHA、execution-plan digest、registry digest，以及 kernel/schema/registry/
  coordinator 的具体版本；v2 持久化排序后的
  `provider alias → server/raw tool/protocol` identity，v4 持久化完整的 definition/output-schema
  digest binding snapshot 与 surface claim version，供离线 reducer 查表证明 provenance。live
  coordinator 只能写入同一 session journal。
- 首次 activation 由 coordinator 私有构造、按值消费的一次性 bootstrap token 提交；之后
  MCP-reserved journal event 必须携带同一 live coordinator 为 exact session/activation/epoch
  **以及 exact runtime journal handle** 生成的 opaque writer capability。handle identity 不写入
  journal，也不参与 durable digest。coordinator 同时持有该 journal 原始 OS lock handle 的
  runtime-only execution lease；每个 transport native reaper 也保留 lease 到 native exit/reap，单独
  drop `SessionJournal` 或 coordinator 不会在旧 MCP transport 仍存活时释放 writer lock。只有
  coordinator/registry shutdown 或 Drop 先 revoke writer、终止 transport，并且 native reaper
  完成后才允许 reopen；新 handle 仍会使旧 capability 在任何验证
  或 dispatch 前 fail closed。不存在 crate-wide raw MCP append 或
  可公开构造的 capability；shutdown/Drop 的 revoke 与已开始的同步 append 通过同一 gate 线性化，
  revoke 返回后不会再有晚到写入。为避免阻塞中的 journal fsync 把 server termination 卡在 gate
  后面，coordinator 会先发布 revoke 并通过 native containment handle 同步终止所有 transport，
  再等待已进入 gate 的 writer 完成。底层 journal capability 为 crate-private；公开 v1 Provider
  response writer 会校验并绑定 active parent turn reserve，同时创建一次性的 Provider outcome
  reservation，并绑定 live coordinator proof 与 exact response identity；父 turn admission 可跨同一
  turn 的顺序 Provider attempts 保持存活。未提交 terminal 的 guard Drop 会把 handle 标为
  reopen-required。`response.completed` 的公开 commit 结果还区分“第一字节前拒绝、允许同一 guard
  写 bounded failed fallback”和“Fatal、必须 close/reopen”；后者会立即 poison 当前 handle，不能靠
  错误文案猜测是否可重试。start/completed 的不可信内存 JSON 在任何 clone/serialize 前同时执行
  O(depth) 的 depth、node 与精确 encoded-byte preflight，并在 coordinator 注入 identity 后复验最终
  canonical data。tool lifecycle/recovery 继续要求更窄的 coordinator/session typed admission。
- 每次调用先对参数完成同步 bounded ownership/preflight，再验证 durable
  `response.completed.output_items` 中存在唯一、同 turn/call ID、同 provider name、同参数
  digest 的 Provider call；对应的 `response.started` 还必须显式记录当前
  `mcp_registry_epoch_id` 与 `mcp_registry_digest`，并且该 response 必须在 activation 之后。
  schema preparation 失败也不能借另一个真实 call ID 写 terminal。
- per-call approval 前和通过后都从 journal snapshot 重建 candidate，并用当前 Provider
  slot v5 policy（内部复用已冻结的 slot state-machine core）验证假想 `tool.started`。当前 trait
  已 sealed，公开入口只能选择 crate-owned 的固定 allow/deny policy，不能安装会读取 journal、
  捕获状态或产生副作用的 pre-start callback。coordinator 内部仍为该次审批生成随机 opaque
  subject；Provider 控制的 call/tool/binding identity 以及可对低熵参数执行字典枚举的确定性
  digest 全部留在私有 exact-call context。未来若需要 interactive 或 argument-aware approval，
  必须先定义并 fsync 独立的
  `approval_requested -> granted | in_doubt` 生命周期及 recovery，而不能重新把
  `arguments_json` 加回这个单阶段 callback。
- approval 通过后先 fsync `tool.started`，再生成不可构造、不可 clone、按值消费的 permit。
  permit 绑定 turn/call、provider/raw tool identity、registry epoch/digest、协议版本、server
  attempt、参数 digest、coordinator ID 和 durable started seq；registry 与 session 在发送前
  再核对 authority、binding、attempt 和参数。
- `tool.started` 本身由一次性的 MCP dispatch admission 写入：在任何 `tools/call` 请求前，
  journal 同时保留有界 terminal 空间和从 prospective prefix 计算出的完整 crash-recovery
  debt；terminal 必须通过同一 capability 绑定 exact `started_seq`。没有 active turn admission
  的 standalone coordinator 仅接受不存在其他 unstarted sibling 的单调用 response；多调用
  batch 必须由 turn admission 持有并转移其 recovery debt，不能借 standalone reserve 绕过。
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
  activation 前兼容视图，后来的 registry epoch 不会追溯改变冻结的旧 boundary 语义。

coordinator core 当前仍不是 Agent 集成完成的声明。`McpExecutionCoordinator::resume()` 已能在
session reopen/recovery 后，用重新取得 execution trust 与 surface trust 的 live registry 复用
原 durable epoch：config、execution plan、Provider surface、registry digest 和 activation policy
必须逐项一致；未恢复的 pre-start MCP call 会 fail closed，且不会写第二条 activation。
resume 的启动顺序由类型而不是注释约定：只有 `SessionStore::open` 返回的同一 journal handle
能一次性签发 `McpResumeEligibility`；`McpRegistry::connect_for_resume` 在 spawn 前消费它，并返回
独立的 `McpResumeRegistry`；其 surface approval 生成 `ApprovedMcpResumeRegistry`，而
`McpExecutionCoordinator::resume` 不接受 activation 路径产生的 `ApprovedMcpRegistry`。eligibility
同时绑定 open-handle nonce、session、activation seq/版本、config SHA、execution-plan digest、
registry epoch/digest；配置不一致会在执行任何 MCP 代码前失败，同一 open handle 不能重复启动。
这里的 one-shot resume nonce 与 coordinator/capability 的 runtime handle binding/execution lease
是两道不同门：
前者证明“本次 startup 之前已经 open/reduce”，后者证明“后续 writer/dispatch 仍在使用签发它们的
同一个 live journal handle”，并让该 coordinator 的 transport lifetime 排他地覆盖 session lock
generation。coordinator shutdown/Drop 发起 transport 终止，native reaper 在 exit/reap 后释放最后的 lease，
随后才可能发生下一次 reopen；旧 capability 不能复用。
未解决的 `tool.in_doubt` 同样会在 eligibility 签发前阻止 MCP 启动；discovery 后、coordinator
重新绑定 registry 前还会再次检查当前 journal，避免启动期间的状态漂移绕过恢复门槛。
但 Agent 尚未消费该 reader。coordinator v4 已提供 typed prepared-request admission：Provider
先把 logical `ResponseRequest` 封装成 `PreparedResponseRequest`，同时冻结 canonical body、同一份
serialized body bytes、Provider protocol 与 usage domain；capability 在 dispatch 前持有该 exact
prepared request、parent turn/outcome admission 与 live coordinator proof，重新测量 body/bytes，
并要求 request tools 等于 exact durable `context.tools` snapshot。随后 `response.started` 写入
registry epoch/digest、`mcp_surface` event/digest，以及包含 `{version, digest, body}` 的
`mcp_prepared_request` envelope；只有 crate 内 sealed、受信的 MCP exact-wire transport 才能消费该
capability，并发送其持有的同一份 sealed bytes。公开可实现的 `PreparedResponseProvider` 仍是
legacy/custom transport TCB，不能进入 MCP exact-wire admission；因此该保证不声称由 Rust 类型
强制任意外部 Provider 的网络行为。内建 transport 禁止 HTTP redirect 和环境/system proxy
自动发现；需要代理时必须把代理显式配置为 API base URL，使实际接收方进入 usage-domain
provenance，而不是在 durable admission 之后静默改变网络接收方。
Provider 返回后先由不可观察的 outcome owner 持有完整 `AssistantTurn`；该类型没有 pre-commit
result accessor。`commit_v1()` 会先验证 bounded JSON、canonical `output_items`、tool-call projection
和批次上限，再 fsync 唯一 terminal，只有成功后才返回 `McpCommittedProviderResponseV1`。exact MCP
stream 在此之前完全沉默：text、function-argument delta、unknown payload 和 retry 的值、次数、
时序都不会越过 observer 边界，因为 custom Provider 可以用任何这些维度编码受控字节。已提交的 `tool_calls` 仍只是后续 durable call/batch reducer 的输入，不是可复制
的 execution permit；Agent 接入必须继续从 exact lifecycle state 获取一次性执行 authority。
generic Agent 的 pre-commit sink 同样丢弃全部 Provider events；`AgentObserver` 已 sealed，外部调用方
只能使用无 callback 的 silent observer。crate-owned CLI observer 只接收 durable lifecycle 之后的
display projection，完整 `ToolCall`、Provider call ID 与 arguments 不跨越该接口。未来若增加 renderer、
queue 或 hook，也必须先证明它接收数据时已经存在对应 durable owner，不能仅靠 DTO 字段改名宣称安全。
  generic Agent preparation 现在会把 `context.tools` 当作 durable input：surface 变化或新的
  Agent epoch 需要写入时先 fsync，然后重新读取 journal、重建 projection/materials/measurement，
  只有稳定 snapshot 才返回，因此首个 tools epoch 的 request cutoff 不再落后于 surface；进程内
  cache 只用于确认本次 preparation 已接管最新 event，不能替代 journal 事实源。Agent 仍必须把
  这一步与 exact seal/admission 收敛到一个无 await 的 typed 构造点，不能先调用 generic Provider
  writer，或从同一 logical request 重建第二份 body。

当前 `ToolSurfaceSnapshotV1` / `McpProviderSurfaceV1` 已把 live registry 的 alias、
definition digest、output-schema digest、registry epoch/digest 与 Provider-visible 工具顺序
合并为 writer-side snapshot，并在写入前拒绝 builtin/history/MCP 名称碰撞。公开 serde 类型可以
被解析或构造出内部自洽的值，因此真正的 authority 边界是 coordinator 写入时对 exact live registry
binding snapshot 的逐项比较，而不是“类型不可构造”。旧 `ToolSnapshot` v1 保持字节兼容。validator v3 登记了严格、可离线的关系：
activation 保存 full binding digest，`response.started` 引用 activation 之后、start 之前的唯一
global `context.tools`，并要求 `mcp_surface.event_seq == context.tools_event_seq`；snapshot、claim、
activation 的 epoch/digest/full bindings 必须一致。删除 response claim 不能把实际使用 MCP
surface 或返回 activated alias 的 response 降级为 generic。Serde 会忽略的 snapshot/tool/binding
额外字段也由 parsed-JSON canonical reader 拒绝；该保证针对 journal 已解析后的语义形状，不声称
保留重复 key、对象原始顺序或数字词法。绑定到 MCP alias 的 input schema 会重新通过冻结的
schema profile v1；v3 lifecycle 的 outer data 与 nested provenance 都是 closed profile，并把 exact
response/surface/definition identity 传递到 terminal。v4 保留该冻结关系，并额外对 versioned
`mcp_prepared_request` body 做 bounded preflight，重算 canonical body bytes、body digest 与完整
`context.measurement`，校验冻结的 Responses body shape，并要求 body tools 等于 durable surface。
writer-side typed capability 再把这些 durable 事实绑定到自己实际持有并 dispatch 的 sealed bytes。

该 v3 reader 还不把 `output_schema_digest` 误当 runtime validation-schema identity：surface 中的
digest 仍来自展示 schema，structured output 验证必须继续由 stdio kernel 的冻结 schema profile
完成。v4 current writer 使用 model-result profile v1：在该 profile
中，`mcp_raw_result` 只作有界的 parsed-JSON 审计值，`output` 必须是严格 text-only、带
`trust = untrusted_mcp_tool_output` 的模型 envelope；offline reader 会从 raw 重新派生并 exact
compare，禁止 `_meta`、annotations、structuredContent、image/resource/audio 或未知 content
item 进入模型。旧 v1/v2 writer 仍按其冻结契约解释 bounded raw result，不能把 v3/v4 reader
约束倒灌进历史接受集合。v4 writer 的 projection/profile/大小失败统一写 `tool.in_doubt` 并
关闭旧 transport；这仍不等于 Agent 已接入。

### 3.4 MCP call-chain validator v1-v4

MCP terminal 的语义权限现由单一、冻结的 call-chain validator 授予，不再要求 turn、slot、
projection 和 history 各自“碰巧做出相同判断”：

- v1 仍由 coordinator v1、turn v6、Provider slot v3、source projection v5、history
  extractor v5 和 compaction boundary v6 按字面量解释；v2 由 turn v7、Provider slot v4、
  source projection v6、history extractor v6 和 compaction boundary v7 解释。旧 match arm
  保持冻结，不读取可变默认值。
- v3 是完整 surface/result offline epoch；v4 是当前 writer，在 v3 之上增加 prepared-request
  body envelope、完整 measurement 与 exact serialized-byte binding。turn v8、Provider slot v5、source projection v8、history extractor v8 与
  compaction boundary v8 的 compatibility ceiling 均为 call-chain v4。任何较旧 ceiling 对
  v4 journal 必须 fail closed，不能只推进 MCP 常量而让 session reopen/projection 拒绝刚写出的
  journal。turn/source/history v8 同时把 recovery grammar 绑定到 owning `user.message` 的版本，
  禁止后写 terminal、compaction metadata 或 journal 最大版本追溯升级旧 turn；v1-v7 reader 保持字面量冻结。
- validator v2 先由 activation 之后、显式带同一 registry epoch/digest 的
  `response.started` 确定整个 response transaction 的 MCP 所有权；unfinished、failed、aborted
  以及只含内置工具的 response 仍属于该 epoch。typed response envelope 保存 exact start、
  `(turn_id, response_attempt_id)` 和 terminal；recovery `response.aborted` 必须使用冻结字段
  profile、引用 exact start seq，普通 terminal 不能携带 recovery provenance。每个 attempt
  至多一个 terminal；completed terminal 要求 canonical `output_items`，且批次限制在区分
  MCP/内置 binding 前应用。activation 之前的同名普通工具保持历史语义，不会被未来 registry
  追溯解释。v1 reader 保留原先按 MCP alias 识别 call 的冻结行为。
- Agent 的 `response.failed.error` 与普通 `response.aborted.reason` writer 在首次 fsync 前使用
  validator v2 共用的 UTF-8 byte limit/truncation profile；Provider 错误可以比 durable status
  字段更大，但不能先写入一个冻结 reader 必然拒绝的 terminal。
- Provider context-limit 使用独立的 intent v1：其 error 的空值、16 KiB byte limit、UTF-8
  截断边界和 `<truncated>` 后缀均由独立 v1 profile 冻结，不依赖 MCP 当前 status helper。
  新 turn 在首次 `user.message` fsync 前先取得冻结的 1 MiB turn transaction admission；容量
  不足时 journal 不产生该 user event，也不进入 preparation、compaction 或 Provider dispatch。
  普通 `response.started` 只有在 Provider dispatch 前取得 typed durable-outcome admission 后才可
  同步；只有确定的 pre-start capacity denial 可以消费 turn reserve 写 bounded cancellation，
  protocol、sequence、serialization、poison 或 I/O 错误均 fail closed，不能伪装成容量不足。
  `response.failed` 绑定 exact `response.started` seq、attempt、bounded error 与 context
  snapshot，随后 `context.limit_reached` 反向引用 exact intent seq，并只用一次 durability
  barrier；若 crash prefix 只有 started，reserve 足以写 recovery abort + marker；若只保留完整
  intent，session-open 会在任何其他 recovery 写入前验证并补全 projection。未知版本、字段漂移
  或 snapshot 不一致均 fail closed。
- turn、普通 response 与 compaction 的 admission capability 都是一次性 guard；若 future 在首次
  terminal 前被 timeout/drop/abort，guard 的 `Drop` 会把当前 journal handle 标记为
  reopen-required。该 handle 不得继续读取或追加；关闭后由统一 session-open reducer按磁盘上
  实际完整 prefix补 bare-turn cancellation、response/compaction abort 和必要 marker/boundary repair。
  coordinator 的 MCP dispatch 也在 `tool.started` fsync 后持有同类 guard；future/task 若在
  terminal 前被丢弃，只能 fail-stop 并 reopen，不能在 `Drop` 中猜测副作用后补写成功或失败；
  同一个 live coordinator/stdio transport 也会永久 poison，只允许 shutdown，必须重新 connect/
  resume 后才能 dispatch，避免迟到 response 被误归属给下一次调用。
- compaction Provider dispatch 在 `compaction.started` 前保护冻结的 2 MiB bounded
  outcome/recovery headroom。attempt terminal 与可选 boundary terminal 作为一个预构建
  transaction、一次 durability barrier提交；full checkpoint 或 raw-response audit 容量不足时
  primary transaction 零写入，并用同一 capability提交带 raw-response byte count/SHA-256 的
  bounded `compaction.failed`，不会把已执行 attempt 留给无空间可用的后续恢复。
- lifecycle 必须使用 canonical `call_id`。generic reducer 兼容的 `id` alias 不能结算 MCP
  call；turn/call/provider、参数 digest、started seq、registry/execution provenance 和 terminal
  状态迁移均由同一 validator 证明。
- session reopen 在写入任何自动 recovery terminal 之前先验证已有 MCP chain。未开始调用仅
  能由 `journal.recovered` marker 授权的 `tool.skipped_due_to_recovery` 关闭，并绑定原始
  response seq、参数 digest 和 marker 中的 exact unstarted-call authorization；同时要求
  `response_seq < recovery_marker_seq < skip_seq`。其他 generic `tool.skipped_due_to_*` 在
  v1 中不能结算 MCP call。live cancellation、tool limit、stall 和 sibling in-doubt 收尾也先按
  durable binding 区分 MCP 与内置调用：MCP siblings 统一以 marker + recovery skip 批量结算，
  内置调用才保留 generic skip kind，父 turn terminal 必须排在全部子调用 outcome 之后。
- 同一 Provider response attempt 必须只有一个 terminal；session recovery 会先在内存中构造
  response/compaction abort、boundary terminal、recovery marker 与全部 skip 的完整 prospective
  transaction，并在首笔 journal 写入前运行 call-chain 与批量 generic Provider slot v2
  consistency check、精确计算 JSONL 容量。容量不足时零写入；成功事务只使用一次 fsync。
- v2 将单个 Provider response 的全部 function calls（包括 MCP 与内置工具混合批次）限制为
  4096；Agent 在 `response.completed` 持久化前使用同一常量，超限只写 `response.failed`。
  v1 在该限制发布前可接受更大的历史批次，因此 recovery 不修改 v1 接受集合，而是先完整
  预检 authorization，再按每个 marker 至多 4096 条分片写入；每个自动 skip 只绑定其所属
  marker。marker authorization、pending/unstarted identity 与 slot call 状态均使用一次构建的
  索引；in-doubt lineage 在一次前向扫描中维护按 started seq 排序的 pending map，每个 marker
  只处理自身 payload，不再为每个 marker 复制、排序完整 pending 集合。恢复中途再次崩溃时，
  下一次 reopen 仅为剩余调用生成新的有界 marker。
- `response.completed` 产生 function-call batch 时，active turn capability 会在首次 fsync 前按
  durable output 重新计算 marker、全部未启动 skip、in-doubt resolution slots 和父 turn
  finalization 的 recovery debt；journal 只有在仍能保留该 headroom 时才接受 completed event。
  retry/resume continuation 必须重新取得同一 turn admission，不能在无 reserve 状态下写批次。
  后续 `tool.started`/`tool.in_doubt` 会把新增 lifecycle debt计入同一 reservation；只有所有子调用
  已结算，或 debt 原子转移为 explicit in-doubt resolution headroom 后，父 turn 才能 terminalize
  并释放容量。固定 1 MiB 只是批次出现前的 floor，不再被当作 4096-call recovery 的上限。
- schema profile v1 也是 validator v1 的冻结传递依赖；历史 `tool.started` 不读取未来默认
  profile。未知 call-chain、activation、provenance 或 profile 版本一律 fail closed。
- coordinator 不再独立扫描 `response.completed`；它只消费 call-chain validator 按 activation
  版本产出的 canonical durable-call snapshot，其中 Provider alias、参数及 digest、registry
  epoch/digest 和 exact response start/completion seq 已由同一 response envelope 证明。
- legacy public journal writer 在写 MCP-claimed response、recovery marker 或 exact MCP-owned
  tool lifecycle 前，会先验证完整 prospective prefix；移除 provenance 也不能把 MCP terminal
  降级为 generic event 并先 fsync 一个 reader 必然拒绝的 journal。这个兼容检查只闭合
  writer/reader 接受集合，不授予 dispatch 权限；未来 Agent 正常路径仍必须由 coordinator
  capability 独占，不能把“格式合法”解释成“已获批准”。
- 当前 generic Provider response admission 只拥有容量与普通 Provider lifecycle 权限，不能与
  registry 字符串拼接出 MCP authority：完整/部分旧 claim、v3/v4 surface/request relation，以及
  `response.completed` 中的 activated alias 都必须在首笔相关 fsync 前 fail closed。专用 typed
  MCP request writer 已校验并绑定 parent turn reserve、创建一次性 outcome reservation，绑定
  live coordinator capability、exact surface 和 exact request；同一 guard 提交 exact terminal，
  并用 typed commit error 证明是否仍允许 bounded fallback。未来 Agent 接入必须直接消费该
  writer，不能先用 generic admission 写 start，再另行“补”MCP provenance。

call-chain validator 解决的是 durable 事实解释，不会自动恢复 live server。resume 与 typed
request binding 的内核路径已建立；下一阶段是让 Agent/CLI 只消费这些 capability，并接通 execution
trust、surface approval 与 per-call approval，不能向 Agent 暴露绕过该路径的 MCP definitions。

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

底层 registry 与 `ToolSurfaceSnapshotV1` 已能建立稳定 alias、完整 binding snapshot、schema
profile 结果和 builtin/history/MCP 的全局 collision proof。Agent glue 仍需只消费这些既有原语，
不得重新实现或旁路它们，并且必须：

- 从 canonical journal projection、当前 instructions 和 exact surface 构造 logical
  `ResponseRequest`；任意调用方自建 input/history 后再绑定一个正确 digest，不构成完整 request authority；
- 保持 raw identity `(server_name, raw_tool_name)` 与既有稳定 Provider alias 的一一关系；
- 直接消费既有 registry/schema/binding snapshot，不能改用会忽略未知关键词的内置
  `validate_json_schema()`，也不能自行重新 list 或重算另一份工具表；
- 把 exact snapshot 写入 `context.tools`，并让同一 sealed prepared request、Provider response
  和后续调用使用同一 epoch。

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
