# Oxidra MCP 接入路线

状态：MCP stdio transport/session kernel v1 已实现，尚未接入 Agent、CLI
配置或 session journal。当前代码只能由 Rust 调用方显式构造
`McpStdioSession`；它不是已经对用户开放的插件入口。

## 1. 边界与原则

MCP 不只是“从外部加载一组函数”。一次 `tools/call` 可能修改远程系统，
而客户端在写出请求后崩溃、超时或断线时，无法仅凭本地状态判断副作用是否
发生。因此 Agent 接入必须先解决以下问题，不能先把工具塞进 Provider 请求：

1. **工具表是版本化输入。** Provider 看到的名称、描述和 schema 必须进入
   `context.tools` snapshot/epoch/digest；调用只能绑定生成该 tool call 时的工具表。
2. **授权先于 durable start。** 未通过项目 trust 和 per-tool approval 时，不能写
   `tool.started`，更不能向 MCP server 发送请求。
3. **写出后未知即 `in_doubt`。** 只有经过校验的 complete result 能关闭副作用
   不确定窗口；JSON-RPC error 也不能证明服务端已回滚。
4. **未知副作用不自动重试。** `tool.in_doubt` 必须复用现有人工解决协议，不能因
   transport 重启、turn retry 或 compaction 自动重放。
5. **历史协议有限且显式。** 只支持登记的协议版本和 reducer 版本；未知版本、
   动态 schema 变化和未支持的交互一律 fail closed。

## 2. 已实现：stdio kernel v1

实现位于 `src/mcp.rs`，集成测试位于 `tests/mcp_stdio.rs`。

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
- executable 必须是可 canonicalize 的绝对文件路径；cwd 必须是现存目录。
- 子进程先 `env_clear()`，只继承显式 allowlist 和显式配置值；环境变量名按
  ASCII 不区分大小写去重，避免同一配置在 Windows 与 Unix 上产生不同含义。
- `ProcessTree` 在 Windows 使用 Job Object、Unix 使用 process group；连接失败、
  取消、协议错误、in-doubt 或 shutdown 都不会把后代进程留在后台。
- 单条 JSONL 上限 1 MiB；工具表上限 512 KiB、512 个工具、64 页；单次工具
  result 上限 50 KiB。
- `inputSchema` 必须声明 object root；可选 `outputSchema` 同样保留在 `McpTool`
  中并要求 object root。当前 kernel 只验证 result 的结构性义务，不声称完整执行
  JSON Schema 的全部断言关键词。
- tool name 只接受 MCP 登记的 ASCII `[A-Za-z0-9_.-]` 子集，Agent 层仍需映射为
  独立、稳定、无碰撞的 Provider tool name。
- server 若声明 `tools.listChanged=true`，或会话中发送
  `notifications/tools/list_changed`，当前 kernel 拒绝继续。动态工具 epoch 尚未实现。
- cancellation 会尽力发送 `notifications/cancelled`，随后永久关闭 transport；
  已写出的取消、超时、EOF、I/O、协议错误和 JSON-RPC error 都返回 `in_doubt`。
- modern `input_required` 等 nonterminal result 当前作为 unsupported interaction，
  关闭 transport 并返回 `in_doubt`。

## 3. 尚未实现：Agent 与 CLI policy

下一阶段必须按以下顺序推进。

### 3.1 项目配置与 trust

先定义版本化项目配置，而不是直接读取任意 MCP 客户端配置：

- server name、绝对 executable、args、cwd；
- 环境变量 inherit allowlist 与显式值，但凭据不得写入项目仓库；
- server 默认禁用，必须由用户对当前项目根显式信任；
- 配置解析后保存 canonical executable/cwd 和配置 digest；resume 时配置变化必须
  重新取得 trust，不能沿用旧批准；
- 第一版只接 stdio，不接 HTTP、OAuth、远程 discovery 或自动安装。

### 3.2 session-scoped tool registry

连接所有已批准 server 后，一次性建立 registry：

- raw identity 为 `(server_name, raw_tool_name)`；
- 生成满足 Provider 约束的稳定 namespace，长度超限或 alias collision 时 fail closed；
- 保存原始 MCP schema、Provider 投影 schema、server protocol、kernel version、
  config digest 和全表 digest；
- 为 MCP schema 登记有限、版本化的 JSON Schema profile，或引入完整且固定版本的
  validator。现有 `validate_json_schema()` 会忽略未知关键词，只适合内置工具，不能
  作为远程 MCP schema 的安全/正确性 authority；
- 合并内置/history/MCP 工具前做全局 collision 检查；
- registry snapshot 进入 `context.tools`，同一 prepared request 与后续调用必须使用
  同一 epoch，不能在中途重新 list。

### 3.3 journal 与恢复

优先复用现有 turn/tool reducer，不再建立第二套终态事实源：

- approval 通过后、dispatch 前同步 `tool.started`，附带 MCP provenance、参数、
  registry epoch/digest 和 server attempt ID；
- validated complete result 同步 `tool.completed`；MCP `isError=true` 是已知 terminal
  error，不是 `in_doubt`；
- request 可能已经写出但没有 validated complete result 时同步 `tool.in_doubt`；
- transport/kernel 的 `in_doubt` 只能由现有 `tool.in_doubt_resolved` 流程显式解决；
- session reopen 必须在启动 MCP server 前先归约 journal；存在 unresolved in-doubt 时
  禁止继续 Provider turn；
- projection/history 继续只消费经过 turn reducer 验证的标准 tool terminal，不直接
  扫描 MCP 私有字段。

### 3.4 approval 与结果投影

- 第一版所有 MCP tool 默认需要 approval；不能让 `--full-auto` 自动授权远程副作用。
- 后续若增加只读 policy，权限必须来自本地配置，不信任 server annotations 自报。
- MCP `content`、`structuredContent` 和 `_meta` 是不可信 tool output；投给模型前使用
  有界、确定的 envelope，不提升为 instructions。
- 图片、resource link、embedded resource 等内容类型必须逐类登记；未登记类型不能
  通过字符串拼接静默降级。

## 4. 暂不支持

- Streamable HTTP、OAuth、远程 server discovery；
- prompts、resources、sampling、roots；
- elicitation / modern input-required 续交互；
- `tools/list_changed` 和会话内 schema 热更新；
- 自动安装 executable、从 shell `PATH` 猜测命令；
- MCP server annotations 直接授予只读或免审批权限；
- in-doubt MCP call 的自动 retry。

## 5. Agent 接入完成门槛

在用户可见入口启用前至少需要：

1. 配置/trust 的字面量 fixture 与跨平台 canonicalization 测试；
2. tool namespace、长度和 collision 反例；
3. `context.tools` epoch/digest 与 resume 配置漂移测试；
4. `started fsync -> 强杀 -> reopen -> in_doubt` 进程故障注入；
5. complete、MCP `isError`、RPC error、取消、timeout、server exit、超限结果测试；
6. unresolved in-doubt 阻止 Provider 继续和人工 resolution E2E；
7. approval 未通过时 journal 无 `tool.started` 且 server 未收到 `tools/call`；
8. Debug/Release、Clippy、Rustdoc、fmt、`git diff --check` 和三平台 CI。

真正的完成标准不是“模型能调用一个 MCP tool”，而是：**schema、授权、durable
dispatch、副作用不确定性与 resume 都由同一个版本化证据链约束。**
