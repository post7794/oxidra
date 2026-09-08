// Oxidra Showcase Data Store
// 数据来源：Oxidra 源码 (Rust 1.85 Edition 2024)、docs/oxidra-mvp.md、docs/m4-m5-roadmap.md、docs/mcp-roadmap.md

export const PROJECT_INFO = {
  name: "Oxidra",
  tagline: "轻量级个人 CLI 编码 Agent",
  subtagline: "基于 Rust 构建 · 极简 · 本地可审计 · 确定性与安全优先",
  version: "v0.1.0",
  rustVersion: "Rust 1.85 (Edition 2024)",
  repository: "https://github.com/post7794/oxidra",
  license: "MIT",
  stats: [
    { label: "内置核心工具", value: "5 个", desc: "read / edit / write / shell / remember" },
    { label: "日志真相源", value: "100%", desc: "Append-Only 本地 JSONL 审计" },
    { label: "漂移基线保留率", value: "17 / 17", desc: "10 轮测试 100% 事实留存 & 0 注入执行" },
    { label: "系统级沙箱治理", value: "Kernel-Level", desc: "Windows Job Object & Linux seccomp" }
  ]
};

export const MILESTONES = [
  {
    id: "m1",
    code: "M1",
    title: "核心循环与内置工具",
    status: "completed",
    statusLabel: "已完成 · 稳定",
    summary: "打通完整 CLI 编码闭环，包含 OpenAI Responses 流式交互、5 大原生 Rust 工具与不可篡改本地审计日志。",
    deliverables: [
      "基于 OpenAI Responses API 的流式交互（启用 store: false 保护隐私）",
      "提交前严格静默：直到 response.completed durable commit 后才渲染输出",
      "5 大安全受限内置工具：read, edit, write, shell, remember",
      "本地 append-only session journal，保证每次操作可追溯与可重放",
      "原生 Ctrl+C 信号拦截与安全的底层进程树清理",
      "模型用量 Token 结构化统计（input/cached/output/reasoning）"
    ],
    techAnchor: "src/agent.rs, src/tools.rs, src/provider.rs"
  },
  {
    id: "m2",
    code: "M2",
    title: "持久记忆与安全凭据",
    status: "completed",
    statusLabel: "已完成 · 稳定",
    summary: "操作系统级密钥安全存储管理，以及具备严格人工全量审查确认的跨 Session 记忆系统。",
    deliverables: [
      "系统级 Keyring 存储集成（Windows Credential Manager / macOS Keychain / Secret Service）",
      "明文文件降级隔离（仅在显式配置 credential_store = 'file' 时开启）",
      "CLI 凭据管理子命令：oxidra auth login / status / logout",
      "remember 记忆持久化：保存为平台用户数据目录下的原生 Markdown 文件",
      "出处元数据溯源：自动记录创建时间与所属项目路径，注入模型前安全剥离",
      "强制交互确认：即使在 --full-auto 模式下，记忆写入也必须经用户全量审阅"
    ],
    techAnchor: "src/auth.rs, src/memory.rs"
  },
  {
    id: "m3",
    code: "M3",
    title: "会话管理与故障恢复",
    status: "completed",
    statusLabel: "已完成 · 稳定",
    summary: "会话级生命周期审计、支持跨进程断点续传与被隔离会话的只读归档导出。",
    deliverables: [
      "会话日志存储与操作系统平台解耦，统一存放在 LocalAppData 用户数据目录",
      "断点续传机制：oxidra --resume <SESSION_ID> 恢复中断的任务",
      "异常崩溃恢复：--retry-pending 与 --abandon-pending 显式控制未完成 turn",
      "会话归档导出：oxidra session export 导出版本化、防篡改的 .oxidra-session-export",
      "进程树治理：Windows Job Object 与 Unix Process Group 阻止孤儿进程泄露"
    ],
    techAnchor: "src/session.rs, src/process.rs, src/turn.rs"
  },
  {
    id: "m4",
    code: "M4",
    title: "Session 预算硬保险丝",
    status: "postponed",
    statusLabel: "已规划 · 暂缓推进",
    summary: "设计防止任务失控与无限消耗的 Token 和执行时间硬保险丝。契约已锁定，按实际需求让路 M5 上下文治理。",
    deliverables: [
      "参数配置：--max-session-tokens 与 --max-session-seconds",
      "硬保险丝定义：旨在防御无限循环，而非精确计费账单器",
      "Active Time 测量：仅计算 LLM 与工具实际执行时长，排除人工等待输入时长",
      "超限干净暂停：写入 budget.exhausted 事件，保留现场可继续 resume"
    ],
    techAnchor: "docs/m4-m5-roadmap.md (Section 2)"
  },
  {
    id: "m5",
    code: "M5",
    title: "自动 Compaction 与 Checkpoint",
    status: "experimental",
    statusLabel: "主线已就绪 · 实验性启用",
    summary: "长上下文自动压缩与可审计 Checkpoint 机制，搭配 3 个历史深度回查工具与零注入事实保留保障。",
    deliverables: [
      "锚点差分上下文测量：基于实际 usage 锚点精确测算下一次请求体大小",
      "自适应压缩水线：80% usable 自动触发，紧凑压缩至 50% 目标空间",
      "低权限 Checkpoint Envelope：限制 8192 Token 输出上限，保留最新 2 轮完整 turn",
      "受控历史回查工具集：history_search, history_turn, history_artifact",
      "显式实验开关：--experimental-auto-compact，崩溃安全 replanning 闭环",
      "Kimi-K2.7-Code 10 轮漂移基线：17/17 事实完全保留，无注入攻击越权执行"
    ],
    techAnchor: "src/compaction.rs, src/history.rs, docs/compaction-drift.md"
  },
  {
    id: "mcp",
    code: "MCP",
    title: "模型上下文协议底层架构",
    status: "kernel_ready",
    statusLabel: "底座就绪 · 待接入用户层",
    summary: "实现高安全等级的 MCP Stdio 进程内核、沙箱隔离与持久协调器，待用户交互层批准接入。",
    deliverables: [
      "Stdio 协议内核：支持 modern 2026-07-28 与 legacy 2025-11-25 安全自适应协商",
      "操作系统级沙箱：Linux pre-exec seccomp + pidfd + PDEATHSIG，Windows Job Object 原子归属",
      "执行计划摘要 (Execution-Plan Digest)：不可变环境参数与环境继承过滤",
      "Session-Scoped Tool Registry 与版本化 JSON Schema 严格校验",
      "Durable Coordinator v4：协调器故障恢复债务与 Leases 治理，副作用严格隔离"
    ],
    techAnchor: "src/mcp.rs, src/mcp/coordinator.rs, docs/mcp-roadmap.md"
  }
];

export const BUILTIN_TOOLS = [
  {
    name: "read",
    title: "受限安全读取",
    badge: "Read Only",
    badgeColor: "emerald",
    summary: "读取项目根目录内的 UTF-8 文本文件。强制路径规范化，采用 no-follow 打开防止符号链接竞争。",
    limits: "单次上限 2,000 行 / 50 KiB，支持 offset 行偏移与 byte_offset 字节精准断点。",
    securityGuard: "返回全文件 SHA-256 哈希，强制作为后续 edit 修改操作的原子版本校验锁。",
    schema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "项目根内的相对路径" },
        offset: { type: "integer", description: "起始行号（0-based）" },
        byte_offset: { type: "integer", description: "长行切片续读字节偏移" },
        limit: { type: "integer", description: "读取行数上限（最大 2000）" }
      }
    },
    exampleCall: `{\n  "name": "read",\n  "arguments": {\n    "path": "src/main.rs",\n    "offset": 0,\n    "limit": 50\n  }\n}`,
    exampleOutput: `{\n  "text": "fn main() { ... }",\n  "full_file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",\n  "range": { "offset": 0, "returned_lines": 50, "total_lines": 128 },\n  "truncated": false\n}`
  },
  {
    name: "edit",
    title: "哈希防脏写编辑",
    badge: "Guarded Mutation",
    badgeColor: "cyan",
    summary: "单处文本精确替换。必须携带由 read 获得的全文件 SHA-256。若文件被外部改动，立刻拒绝编辑，杜绝误写与脏写。",
    limits: "只允许精确匹配单一代码块；替换内容在终端中提供 ANSI 红绿彩色 Diff 预览。",
    securityGuard: "SHA-256 不一致或出现多处相同匹配时立刻抛出错误，保证编辑确定性。",
    schema: {
      type: "object",
      required: ["path", "old_text", "new_text", "expected_sha256"],
      properties: {
        path: { type: "string", description: "要修改的文件相对路径" },
        old_text: { type: "string", description: "要替换的既有精确文本" },
        new_text: { type: "string", description: "替换后的新代码" },
        expected_sha256: { type: "string", pattern: "^[0-9a-fA-F]{64}$", description: "read 返回的文件哈希" }
      }
    },
    exampleCall: `{\n  "name": "edit",\n  "arguments": {\n    "path": "src/lib.rs",\n    "old_text": "let timeout = 60;",\n    "new_text": "let timeout = 120;",\n    "expected_sha256": "a7b3c...9f2"\n  }\n}`,
    exampleOutput: `{\n  "applied": true,\n  "new_file_sha256": "4d89e...1b0",\n  "diff": "@@ -14,3 +14,3 @@\\n- let timeout = 60;\\n+ let timeout = 120;"\n}`
  },
  {
    name: "write",
    title: "原子创建新文件",
    badge: "New Files Only",
    badgeColor: "indigo",
    summary: "在项目根目录中创建新 UTF-8 文件。绝不允许覆盖已存在的文件（防覆写误伤），父目录必须已存在。",
    limits: "单个文件上限限制在 16 MiB 以内。",
    securityGuard: "杜绝覆盖写与静默覆写；若需改动已有文件，必须通过 read -> edit 的安全闭环完成。",
    schema: {
      type: "object",
      required: ["path", "content"],
      properties: {
        path: { type: "string", description: "新文件相对路径" },
        content: { type: "string", description: "文件初始完整 UTF-8 文本内容" }
      }
    },
    exampleCall: `{\n  "name": "write",\n  "arguments": {\n    "path": "tests/test_parser.rs",\n    "content": "#[test]\\nfn test_parse() { ... }"\n  }\n}`,
    exampleOutput: `{\n  "created": true,\n  "bytes_written": 248,\n  "sha256": "c82b1...7f3"\n}`
  },
  {
    name: "shell",
    title: "受控原生 Shell 执行",
    badge: "Process Contained",
    badgeColor: "amber",
    summary: "在项目根目录执行原生命令（Windows PowerShell / Linux sh）。默认限制 120 秒超时，挂载到操作系统作业对象中。",
    limits: "输出内容双通道缓冲，超限部分截断并持久化保存为审计 Artifact。",
    securityGuard: "默认逐条命令人工确认；--full-auto 跳过确认；Ctrl+C 触发子进程树强制清理，杜绝残留。",
    schema: {
      type: "object",
      required: ["command"],
      properties: {
        command: { type: "string", description: "要执行的命令行指令" },
        timeout: { type: "integer", minimum: 1, maximum: 3600, description: "超时秒数，默认 120s" }
      }
    },
    exampleCall: `{\n  "name": "shell",\n  "arguments": {\n    "command": "cargo test --offline",\n    "timeout": 60\n  }\n}`,
    exampleOutput: `{\n  "exit_code": 0,\n  "stdout": "test result: ok. 14 passed; 0 failed;",\n  "stderr": "",\n  "duration_ms": 1420\n}`
  },
  {
    name: "remember",
    title: "跨会话经验记忆",
    badge: "Audited Memory",
    badgeColor: "rose",
    summary: "持久化跨 session 的重要经验、项目约定与偏好。记忆以 Markdown 文件形式保存在操作系统全局用户目录中。",
    limits: "包含两字段出处元数据（项目来源、记录时间戳），向模型注入时自动剥离元数据以节约 Token。",
    securityGuard: "哪怕开启 --full-auto，记忆写入也必须经过用户对全量内容的显式审查确认。",
    schema: {
      type: "object",
      required: ["content"],
      properties: {
        content: { type: "string", description: "需要长期记忆的自然语言描述" }
      }
    },
    exampleCall: `{\n  "name": "remember",\n  "arguments": {\n    "content": "该项目在 Windows MSVC 编译时需要确保 link.exe 在 PATH 中。"\n  }\n}`,
    exampleOutput: `{\n  "saved": true,\n  "memory_id": "mem_01j7b9k4...m2",\n  "path": "%LOCALAPPDATA%/oxidra/memories/..."\n}`
  }
];

export const HISTORY_TOOLS = [
  {
    name: "history_search",
    title: "压缩前缀全文搜索",
    desc: "在被 Checkpoint 压缩的历史对话前缀中进行确定性文本检索，返回不可信事实证据片段。"
  },
  {
    name: "history_turn",
    title: "特定轮次精准查阅",
    desc: "按 turn_id 精确提取历史压缩轮次的原始用户输入、模型回复与工具调用的逐行输出。"
  },
  {
    name: "history_artifact",
    title: "历史命令产物提取",
    desc: "按块提取被截断的历史 shell 执行产物二进制数据（Base64 返回），还原关键构建日志。"
  }
];

export const ARCHITECTURE_PILLARS = [
  {
    title: "Append-Only 本地审计日志",
    subtitle: "Local Truth & Resumability",
    desc: "所有用户事件、模型输出与工具副作用均实时 fsync 落盘至 JSONL 文件。不依赖远端服务器存储，会话可随时中断、重放与验证。",
    icon: "journal"
  },
  {
    title: "提交前严格静默",
    subtitle: "Silent Pre-commit Stream",
    desc: "OpenAI Responses 流式 token 不在终端肆意飞溅。只有在 response.completed 且经原子校验写入日志后，才呈现在标准输出中。",
    icon: "shield"
  },
  {
    title: "操作系统级进程沙箱",
    subtitle: "OS-Level Process Isolation",
    desc: "Windows 下使用 Job Object 原子归属与 suspended birth；Linux 下应用 pre-exec seccomp + pidfd，杜绝孤儿后代进程与逃逸。",
    icon: "cpu"
  },
  {
    title: "确定性优先于可用性",
    subtitle: "Determinism Over Speculation",
    desc: "网络或命令超时不冒进猜测结果，未确认副作用一律归入 in_doubt 状态，由用户审查恢复，拒绝隐式覆写与臆造。",
    icon: "lock"
  }
];

export const TERMINAL_SCENARIOS = {
  "test-fix": {
    name: "修复项目测试",
    command: "oxidra -p \"修复 src/tools.rs 中的测试断言并运行验证\" --full-auto",
    steps: [
      { type: "info", text: "oxidra: session started (id: sess_01j8m4k9a2px7, model: gpt-5.6-sol)" },
      { type: "user", text: "> 修复 src/tools.rs 中的测试断言并运行验证" },
      { type: "action", text: "⚡ [Tool Call] read(path=\"src/tools.rs\", offset=1960, limit=25)" },
      { type: "output", text: "✔ read 25 lines (sha256: f4b189c...281d)" },
      { type: "action", text: "⚡ [Tool Call] edit(path=\"src/tools.rs\", old_text=\"assert_eq!(res, 42);\", new_text=\"assert_eq!(res, 48);\", expected_sha256=\"f4b189c...281d\")" },
      { type: "diff", text: "@@ -1969,3 +1969,3 @@\n-   assert_eq!(res, 42);\n+   assert_eq!(res, 48);" },
      { type: "output", text: "✔ edit applied successfully (new sha256: b8e321a...992c)" },
      { type: "action", text: "⚡ [Tool Call] shell(command=\"cargo test --test tools\", timeout=60)" },
      { type: "output", text: "   Compiling oxidra v0.1.0\n   Running tests/tools.rs\ntest result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" },
      { type: "success", text: "✨ 已修复 src/tools.rs 中对应测试断言，并通过 cargo test 离线验证。" },
      { type: "telemetry", text: "stderr: model: gpt-5.6-sol | tokens: 2,410 in / 380 out (total: 2,790) | context: ~18,400 tokens" }
    ]
  },
  "auth-status": {
    name: "凭据状态查询",
    command: "oxidra auth status",
    steps: [
      { type: "output", text: "Oxidra Credential Status:" },
      { type: "output", text: "  Credential Store: keyring (OS Secure Storage)" },
      { type: "output", text: "  API Base URL:     https://api.openai.com/v1" },
      { type: "output", text: "  Active Model:     gpt-5.6-sol (override supported)" },
      { type: "output", text: "  Key Status:       Configured & Verified (Keyring item: 'oxidra/api.openai.com')" },
      { type: "success", text: "✔ Local credentials are valid and secure." }
    ]
  },
  "session-list": {
    name: "查看历史会话",
    command: "oxidra session list",
    steps: [
      { type: "output", text: "Available Local Sessions (%LOCALAPPDATA%/oxidra/sessions):" },
      { type: "output", text: "  SESSION ID               TURNS   STATUS       LAST UPDATED            TOKENS" },
      { type: "output", text: "  sess_01j8m4k9a2px7       4       completed    2026-09-09 05:42:18     12,450" },
      { type: "output", text: "  sess_01j8m1v5c7b39       12      resumable    2026-09-08 22:15:02     48,920" },
      { type: "output", text: "  sess_01j8k8e2q901m       28      compacted    2026-09-08 19:30:11     142,300" },
      { type: "info", text: "Tip: Use 'oxidra --resume <SESSION_ID>' to continue an existing session." }
    ]
  },
  "compact-demo": {
    name: "上下文自适应压缩",
    command: "oxidra -p \"深入重构分析\" --resume sess_01j8k8e2q901m --experimental-auto-compact",
    steps: [
      { type: "info", text: "oxidra: resuming session sess_01j8k8e2q901m (28 turns loaded)" },
      { type: "telemetry", text: "Preflight: estimated next input ~104,200 tokens >= trigger 102,400 (80% usable)" },
      { type: "action", text: "⚙ [Compaction] auto-compact triggered for prefix turns [0..25] (preserving 2 recent complete turns)" },
      { type: "output", text: "   Dispatching compact_once with summary budget 8,192 tokens..." },
      { type: "output", text: "   Summary received: 4,120 tokens. Measuring post-compaction request..." },
      { type: "output", text: "✔ Post-compaction input ~46,800 tokens <= target 64,000 (50% usable). Checkpoint committed!" },
      { type: "success", text: "✨ Checkpoint #1 fsynced to journal. Replaying prompt with compacted context & history tools..." },
      { type: "action", text: "⚡ [Tool Call] history_search(query=\"database migration schema\")" },
      { type: "output", text: "✔ history_search: 2 excerpts matched in compacted turn #8 and #14" },
      { type: "telemetry", text: "stderr: turn completed successfully | tokens: 5,200 in / 890 out | current context: ~48,200 tokens" }
    ]
  }
};
