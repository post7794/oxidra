# Oxidra MVP 设计

状态：MVP 核心已实现，并已在 Windows MSVC 与 Windows GNU 的 Rust 1.85 上完成 check、test、Clippy 和 fake-runtime 验收；仓库已配置 Linux、macOS CI，仍需远端首次运行确认。

Oxidra 是一个使用 Rust 编写的轻量、可扩展 CLI coding agent。它借鉴 pi 的交互式 agent loop 和 lazy.nvim 的声明式插件体验，但不兼容 Neovim 的 Lua ABI，也不复制 pi 的完整 TUI。

## 1. 产品边界

### MVP 必须完成

- 交互式 REPL 和单次 print 模式。
- OpenAI Responses API，SSE 流式输出。
- read -> edit -> shell 工具闭环。
- Ctrl+C 取消当前 LLM 请求和正在执行的工具。
- 项目根目录内的 canonical path 校验。
- 本地 append-only session journal 和 --resume。
- 项目级 trust gate。
- 本地 MCP stdio 插件：发现 tools、调用 tools、lazy on-call 激活。
- 跨平台进程树终止。

Windows 进程树由核心创建并持有 Job Object，启用 `KILL_ON_JOB_CLOSE`；Unix/macOS 为每个工具或插件创建独立 process group。清理不依赖 leader 仍然存活。

### 明确后置

- Goal mode 的实现。
- compaction 算法。
- 远程插件安装、registry 和 build hooks。
- steering/follow-up 消息队列。
- TUI、slash commands、RPC 用户界面。
- 动态 tools/list_changed、resources、prompts、sampling、elicitation。
- Rust 第三方插件 ABI 或动态库加载。

Goal 必须在 compaction 可用后实现；完整本地重放没有 compaction 无法支撑长期无人值守任务。

## 2. 命名与目录

~~~text
产品名：Oxidra
CLI：oxidra
Cargo package：oxidra
项目配置目录：.oxidra/
环境变量前缀：OXIDRA_
~~~

项目配置：

~~~text
.oxidra/config.toml
.oxidra/lock.toml
~~~

用户数据放在平台用户数据目录，不写入项目：

- Windows：%LOCALAPPDATA%/oxidra
- macOS：~/Library/Application Support/oxidra
- Linux：$XDG_STATE_HOME/oxidra，否则 ~/.local/state/oxidra

## 3. 核心架构

内核由以下职责组成：

~~~text
CLI
  -> Agent loop
      -> Responses provider
      -> Tool registry
          -> 内置 Rust tools
          -> MCP plugin supervisor
      -> Approval policy
      -> Session journal
      -> Context projector
~~~

外部扩展唯一稳定接口是 MCP stdio。Rust Tool、Provider、SessionStore 等 trait 只作为 Oxidra 内部实现契约，MVP 不承诺第三方 Rust crate API 或动态库 ABI。

## 4. Provider

### 默认配置

~~~text
API_KEY       必需
API_BASE_URL  可选，默认 https://api.openai.com/v1
MODEL         默认 gpt-5.6-sol
~~~

请求固定为：

~~~text
POST {API_BASE_URL}/responses
Authorization: Bearer API_KEY
stream: true
store: false
~~~

兼容环境变量按完整配置组解析，不能交叉拼接：

1. API_KEY、API_BASE_URL、MODEL
2. 若第一组没有 key，再尝试 OPENAI_API_KEY、OPENAI_BASE_URL、OPENAI_MODEL

不扫描 .env、浏览器登录、其他 CLI 凭证或任意系统文件；不联网探测 Provider 能力，不调用 /models 猜测兼容性。

### SSE 解析

- 使用成熟 SSE parser，不手写字符串切割。
- 通过 item_id/call_id 组装 function-call arguments。
- 只在 arguments 完成且 JSON Schema 校验通过后执行工具。
- 不假设 output[0] 是文本。
- response.completed 是 assistant response 的提交点。
- 未知事件保留 raw 数据并跳过，不导致 CLI 崩溃。
- 流结束前没有 terminal event，记为 transport error/aborted，绝不自动重试。

重点事件：

~~~text
response.output_text.delta
response.function_call_arguments.delta
response.function_call_arguments.done
response.completed
response.failed
error
~~~

### 重试

- 首个 SSE 事件前的连接失败、408/429/5xx：最多 3 次指数退避，遵守 Retry-After，单次等待最多 60 秒。
- 400/401/403/404 不重试。
- 首个 SSE 事件后断流不自动重试，避免产生第二份不确定的 tool call。
- Ctrl+C 可取消请求和退避等待。

## 5. Agent loop

### 普通交互

- 一个用户输入开启一个 turn。
- 一次 assistant response 可能包含多个 tool call；MVP 按出现顺序串行执行。
- 普通工具错误回填为结构化 tool result，继续处理同批次剩余调用。
- Ctrl+C 停止当前调用，并把未执行调用标记为 skipped_due_to_cancel。
- 没有默认 max responses/tools 硬限制；调用数、工具数、token、耗时只做可见计量。
- 可选 --max-responses、--max-tools 作为用户显式保险丝，默认关闭。
- 同一工具、规范化参数、相同错误连续 3 次且无状态变化时暂停为 stalled。
- Provider 网络重试与模型工具循环分开计数。

强模型不是不设策略的理由，但 raw call count 不能区分正常长任务和循环；策略应针对重复错误、权限拒绝、上下文溢出和可取消性。

### Goal（后置）

Goal 是无人值守授权，不是普通 turn 的放大版：

- Segment 是调度切片，到点 checkpoint 后自动继续，不弹用户确认。
- 生命周期预算可选：unlimited、token、金额、active time 或 deadline。
- 非交互创建 Goal 必须显式选择预算策略；不隐式设置小上限。
- 若用户选择有限预算，耗尽后安全 checkpoint，状态为 paused_budget。
- 预算跨 continuation、resume、compaction 和未来 sub-agent 累计，不得通过重启 segment 重置。
- raw call count 仅作遥测或极高的实现保险丝。

## 6. 内置工具

### read

~~~text
path, offset?, byte_offset?, limit?
-> text, full_file_sha256, range, truncated?
~~~

只允许项目根目录内的 canonical path，显式拒绝 `..` 和符号链接逃逸。默认最多返回 2000 行或 50 KiB；大文件使用 offset/limit 分段读取，超长单行可用 `byte_offset` 续读。单文件读取上限为 16 MiB。

### edit

~~~text
path, old_text, new_text, expected_sha256
-> replaced_count, new_sha256
~~~

- old_text 必须恰好匹配一次。
- hash 变化返回 stale_file，禁止覆盖。
- 不做模糊匹配。
- 同目录临时文件 + 原子替换，保留原文件权限。
- MVP 只处理 UTF-8 文本；write/delete/move 后置。

### shell

~~~text
command, timeout?
-> exit_code, stdout, stderr, truncated?, artifact_id?
~~~

- Unix 默认 /bin/sh -lc。
- Windows 默认 powershell.exe -NoProfile -NonInteractive。
- system prompt 注入 shell_kind。
- 默认超时 120 秒，允许单次显式延长；跨平台硬上限由执行器统一控制。
- 输出最多向模型返回 2000 行或 50 KiB；完整输出写入 artifact，并在结果中保留 hash/id。

稳定错误码包括：not_found、permission_denied、stale_file、timeout、cancelled、validation_error、process_exit、context_limit。

## 7. MCP 插件

固定 MCP 2025-11-25 的 stdio 子集：

~~~text
initialize
notifications/initialized
ping
tools/list
tools/call
notifications/cancelled
~~~

通信为 newline-delimited JSON-RPC；stdout 只放协议，stderr 只放日志。

### 文件职责

~~~text
.oxidra/config.toml     项目意图：启用哪些插件、activation
.oxidra/lock.toml       revision/checksum/protocol/schema hash
plugin/manifest.json    命令、协议版本、静态 tools schema
~~~

MVP 只支持显式本地插件，不自动下载或执行 build hook。

### Lazy 生命周期

~~~text
Dormant -> Starting -> Ready
                  \-> Failed
~~~

启动 CLI 时只读取静态 manifest 并注册 schema；首次 tools/call 才：

~~~text
spawn -> initialize -> tools/list -> schema hash 校验 -> call
~~~

启动后进程驻留至 session 结束。动态 schema 插件必须声明 eager，否则不可用。

manifest 与实际 tools/list 对工具名、描述和 input schema 做 canonical JSON + SHA-256 校验。静态 manifest 必须声明匹配的 `schemaHash`；动态 schema 可省略该字段，但必须在 `eager` 握手后以运行时 schema 注册。若静态 hash 存在且不一致，插件标记为 Failed，不执行调用。

插件工具命名为 <plugin>.<tool>，不能覆盖内置工具名。

### 崩溃

- initialize 失败：最多自动重试一次。
- 已发送 tools/call 后崩溃：当前调用为 in_doubt，不自动重放。
- 空闲崩溃：下一次用户明确调用可重新启动并重新握手。
- 同一 session 不无限重启。

插件默认只继承最小环境；API_KEY、云凭证、SSH 凭证等必须由 manifest 显式声明。环境白名单是减少泄露，不是安全沙箱。

## 8. Trust 与授权

### 项目根

- --cwd 存在时使用其 canonical path，不向上搜索。
- 否则从当前目录向上寻找最近的 .oxidra/config.toml。
- 找不到配置时当前目录就是根。
- 不自动使用 Git root。
- session 记录 root，resume 时不能换项目。

### Trust gate

- 未信任项目不启动任何扩展。
- 信任记录在项目目录之外。
- 信任绑定 canonical root + config/lock/manifest 的执行 hash。
- 命令、checksum、权限声明变化立即撤销信任。
- 信任后插件等同于用户主动运行的本地程序；不实现 OS 级沙箱。

### 动作授权

~~~text
read       根目录内自动执行
edit       根目录内自动执行
shell      每条命令确认
plugin     已信任插件自动执行
~~~

--full-auto 只对当前进程/session 生效，不写入项目配置。非交互 -p 未开启时返回 approval_required；Goal 未开启时进入 waiting_user。

项目指令只能指导编码风格，不能修改 root、trust、权限、预算、model 或 full-auto。只自动加载 <project-root>/AGENTS.md，最大 32 KiB。

## 9. Session journal

session 是单写者 append-only JSONL：

~~~json
{
  "schema": 1,
  "seq": 42,
  "ts": "2026-07-19T01:23:45Z",
  "kind": "response.completed",
  "session_id": "...",
  "turn_id": "...",
  "data": {}
}
~~~

- seq 单调递增。
- Provider 原始 payload 原样保存，未知字段不能丢。
- session lock 防止两个进程同时写入。
- 尾部不完整 JSON 行作为崩溃尾巴处理并追加 recovery marker。
- 关键提交事件 flush，必要时 fsync。
- session 数据和 artifact 不写项目目录。

### 提交语义

~~~text
stream delta             只展示，不进入 canonical history
response.completed       追加完整 output items
tool.started             调用前追加
tool.completed           正常完成后追加完整结果/ artifact 引用
tool.cancelled           Ctrl+C 后追加取消结果
未完成 tool.started      恢复时标记 in_doubt，禁止自动重试
~~~

重放以原始 Responses item 为准，保留 encrypted reasoning、phase、tool call id 和未知字段。journal 是真相源，model context 是可替换 projection。

## 10. Context 与 compaction

- journal 永远保留完整历史。
- model context 从 journal 派生。
- MVP 不实现 compaction 算法。
- 接近 context_window - reserve_tokens 时停止请求并返回 context_limit，不静默截断。
- journal 预留 compaction.checkpoint 事件；未来只改变 projection 边界，不删除历史。

## 11. CLI

~~~text
oxidra
oxidra -p "修复测试"
oxidra --resume <session-id>
~~~

通用参数：--full-auto、--model、--cwd、--config，以及可选 --max-responses、--max-tools。

运行期间不支持 steering/follow-up；用户先 Ctrl+C，再输入新消息。

stdout/stderr：

- stdout：assistant 文本增量；-p 最终输出只在 stdout。
- stderr：工具状态、shell 确认、诊断和错误。
- TTY 可用 ANSI；非 TTY 自动关闭控制序列。
- 不显示隐藏 reasoning。

退出码：

~~~text
0    正常完成
1    Provider/Agent 错误
2    配置/参数错误
3    需要用户授权
4    上下文窗口耗尽
5    Goal 预算暂停
130  用户中断
~~~

## 12. 平台与工具链

Tier-1：

~~~text
Windows x86_64 (MSVC)
Linux x86_64 (GNU)
macOS aarch64
~~~

Rust edition 2024，MSRV 1.85。跨平台差异由 shell adapter、process group/Job Object、path canonicalization 和 session lock 屏蔽。

目标：单 crate、单 binary；strip 后小于 20 MiB；无插件/无网络冷启动到输入提示小于 150 ms；空闲 REPL 目标小于 40 MiB。

## 13. 第一阶段验收

必须通过：

1. 三个平台启动并读取 API_KEY。
2. fake Responses SSE 驱动 read -> edit -> shell。
3. edit hash 冲突拒绝覆盖。
4. Ctrl+C 取消 LLM 和 shell 子进程树。
5. -p stdout 只有最终文本，工具诊断在 stderr。
6. journal 崩溃恢复和 in_doubt 标记。
7. 本地 MCP 插件完成握手、发现和调用。
8. manifest/schema hash 不一致时插件不可用。
9. trust/config hash 变化触发重新确认。
10. context 到阈值时干净暂停，不静默截断。

测试使用 fake provider 和 fake MCP plugin，不依赖真实 API key 或付费请求。

当前自动化过程级测试还覆盖：SSE delta 在 `response.completed` 前可见、shell cancellation、跨进程 `--resume` 对完整 output items（含 encrypted reasoning/phase）的重放，以及 MCP on-call 握手、长连接复用和 shutdown。
