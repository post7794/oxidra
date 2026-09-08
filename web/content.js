// Editorial snapshot, verified against the working tree on 2026-09-08.
// This is an introduction site, not an API client or an Agent control surface.
export const tools = {
  read: {
    index: '01 — READ', title: '先理解，再动手。', filename: 'src/lib.rs',
    description: '读取项目中的文件，为下一步修改建立上下文。文件工具的访问范围限定在你选择的项目根目录内。',
    tags: ['项目范围内读取', '有界文件内容'], footnote: '只读操作，不修改项目文件',
    lines: [
      { text: '// 理解现有代码，从这里开始', tone: 'comment' },
      { text: 'pub fn add(a: i32, b: i32) -> i32 {' },
      { text: '    a - b' }, { text: '}' }, { text: '' },
      { text: '// 下一步：定位问题，精准修改', tone: 'comment' },
    ],
  },
  edit: {
    index: '02 — EDIT', title: '改对的地方，不多改一行。', filename: 'src/lib.rs · diff',
    description: '用精确的文本匹配修改代码，并校验读取时的文件 SHA-256。文件已变化或匹配不唯一时停止，而不是猜着覆盖。',
    tags: ['精确替换', 'SHA-256 校验'], footnote: '单次替换一个匹配项，避免覆盖未预期的变化',
    lines: [
      { text: 'pub fn add(a: i32, b: i32) -> i32 {' },
      { text: '−   a - b', tone: 'removed' },
      { text: '+   a + b', tone: 'added' }, { text: '}' }, { text: '' },
      { text: '// 小改动，明确的意图。', tone: 'comment' },
    ],
  },
  write: {
    index: '03 — WRITE', title: '把下一块拼图，写进项目。', filename: 'tests/addition.rs · new file',
    description: '在项目根内创建 UTF-8 文件。已有文件不会被覆盖，父目录需要预先存在；新增和修改，各自有清晰的职责。',
    tags: ['仅创建新文件', '不覆盖已有路径'], footnote: '示例假设 tests 目录已存在',
    lines: [
      { text: '// 给这次修复留下一条回归测试', tone: 'comment' },
      { text: '#[test]', tone: 'green' },
      { text: 'fn addition_works() {' },
      { text: '    assert_eq!(add(2, 2), 4);', tone: 'added' },
      { text: '}' }, { text: '' },
    ],
  },
  shell: {
    index: '04 — SHELL', title: '不只说完成，亲自验证。', filename: 'terminal · cargo test',
    description: '从项目根运行命令，把测试与构建结果带回 Agent。命令默认需要你逐次确认；Windows 使用 PowerShell，Unix 使用 /bin/sh。',
    tags: ['默认逐次确认', 'Ctrl + C 取消'], footnote: 'Shell 具有当前用户权限，不是项目文件沙箱',
    lines: [
      { text: '$ cargo test', tone: 'green' },
      { text: '// 以下输出为流程演示', tone: 'comment' },
      { text: 'running 1 test' },
      { text: 'test addition_works ... ok', tone: 'green' },
      { text: '' },
      { text: 'test result: ok.', tone: 'added' },
    ],
  },
  remember: {
    index: '05 — REMEMBER', title: '好约定，不用反复交代。', filename: 'memory · Markdown',
    description: '经过你的完整内容确认，把重要约定保存为本地 Markdown。记忆可查看、可删除，来源信息也会被记录下来。',
    tags: ['保存前完整内容确认', '可管理的长期记忆'], footnote: '--full-auto 不会跳过记忆保存确认',
    lines: [
      { text: '# 项目工作约定', tone: 'green' }, { text: '' },
      { text: '修改后运行相关测试。' },
      { text: '优先小而可验证的改动。' }, { text: '' },
      { text: '// 确认后保存，下一次继续沿用', tone: 'comment' },
    ],
  },
};

export const installs = {
  source: {
    language: 'SHELL',
    command: '# 在已克隆的 Oxidra 项目根目录执行\ncargo install --path .\n\n# 配置凭据，然后开始对话\noxidra auth login\noxidra',
    requirements: '需要 Rust 1.85+ 与平台 C/C++ 工具链。Windows MSVC 还需 Visual Studio C++ Build Tools 和 Windows SDK。',
  },
  windows: {
    language: 'POWERSHELL',
    command: '# 下载并运行仓库提供的安装脚本\nirm https://raw.githubusercontent.com/post7794/oxidra/main/install.ps1 -OutFile $env:TEMP\\oxidra-install.ps1\npowershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\\oxidra-install.ps1 -AddToPath',
    requirements: '此方式要求公开可读的 Windows Release。脚本会校验 SHA-256；安装后重新打开终端。Release 不可用时，请从当前源码构建。',
  },
  run: {
    language: 'SHELL',
    command: '# 安全输入并保存 API 凭据\noxidra auth login\n\n# 在你的项目目录中执行\noxidra doctor\noxidra -p "阅读项目，修复测试并运行验证"',
    requirements: '默认使用系统凭据存储。请先配置所需 Provider / 模型；相关上下文会通过 Responses API 发送。Shell 执行仍需逐次确认。',
  },
};

// Only locally authored markup is rendered here; URL parameters and remote content
// are never inserted as HTML. Raw repository documents open separately as text.
export const documents = {
  overview: {
    title: '项目概览', source: 'README.md',
    body: `<p>Oxidra 是一个用 Rust 编写的轻量个人 CLI 编程 Agent。当前版本为 <code>0.1.0</code>，使用 Responses API，并提供五个内置工具与本地、只追加的会话日志。</p>
      <h3>已经打通的工作流</h3><pre><code>用户输入 → 模型响应 → 内置工具
        → 工具结果回填 → 运行验证
        → append-only session journal</code></pre>
      <p>可使用交互式 REPL，或通过 <code>-p</code> 运行单次任务。已提供凭据管理、会话恢复、持久记忆和 <code>doctor</code> 环境诊断。</p>
      <h3>正在生长，而不是已经全能</h3><ul><li>M1–M3 核心能力已实现。</li><li>M5 上下文与 checkpoint 已实现；自动压缩仍是显式实验功能。</li><li>MCP 已有 Rust 底层内核，但尚未接入面向用户的 CLI、Agent 和审批链路。</li><li>M4 会话预算处于规划 / 暂缓状态。</li></ul>
      <p class="doc-notice">本介绍依据 2026-09-08 的当前工作区。终端和代码片段是交互示意，不是在线运行结果；页面不会调用模型或执行命令。</p>`,
  },
  start: {
    title: '快速开始', source: 'README.md',
    body: `<h3>1. 从当前源码安装</h3><p>准备 Rust 1.85+ 与平台编译工具链，在已经克隆的 Oxidra 项目根目录执行：</p><pre><code>cargo install --path .</code></pre><p>Windows MSVC 需要 Visual Studio Build Tools 的 C++ 桌面开发工作负载与 Windows SDK；Linux / macOS 需要平台 C 编译器和开发工具。</p>
      <h3>2. 配置 Provider 与凭据</h3><p>通过用户配置文件设置 API base URL 和模型；Windows 配置位于 <code>%APPDATA%\\oxidra\\config.toml</code>。不要把 API key 写入项目或普通配置。</p><pre><code>oxidra auth login
oxidra auth status</code></pre><p>默认使用系统 keyring。显式配置 file 模式会以明文保存凭据。凭据绑定 API base URL；修改 URL 后需重新配置。</p>
      <h3>3. 在你的项目中开始</h3><pre><code>oxidra doctor
oxidra
# 或运行一个任务
oxidra -p "修复当前项目的测试并运行验证"</code></pre><p>也可用 <code>--cwd</code> 显式指定项目。只有明确希望跳过 shell 逐次确认时，才使用 <code>--full-auto</code>。</p>`,
  },
  tools: {
    title: '五个内置工具', source: 'docs/oxidra-mvp.md',
    body: `<h3>read：先读清楚</h3><p>读取项目根内的 UTF-8 文本，可按行偏移继续读取。单次输出不超过 2,000 行与 50 KiB，返回完整文件的 SHA-256 供后续编辑校验。</p><h3>edit：精确修改</h3><p>携带 <code>expected_sha256</code> 并精确替换一个字面量匹配。文件已变更或匹配不唯一时拒绝编辑，避免静默覆盖。</p><h3>write：只负责新文件</h3><p>创建项目根内的新 UTF-8 文件，不覆盖已有路径；父目录必须已存在。</p><h3>shell：运行验证</h3><p>在项目目录调用 PowerShell 或 <code>/bin/sh</code>。默认逐次确认，输出有界，超长输出保留为本地 artifact。</p><h3>remember：保存重要约定</h3><p>完整内容经用户确认后，保存为本地 Markdown。来源项目和创建时间作为 provenance 记录。</p><p class="doc-notice">文件工具的项目边界不等于 shell 沙箱。Shell 拥有当前操作系统用户权限；不要把命令确认当成隔离机制。</p>`,
  },
  sessions: {
    title: '本地会话与恢复', source: 'README.md',
    body: `<p>会话 journal 是 append-only JSONL，存放在平台用户数据目录，而不是项目仓库。原始事件是事实来源，projection 只决定下一次请求重放什么。</p><h3>查看与继续</h3><pre><code>oxidra session list
oxidra session show &lt;SESSION_ID&gt;
oxidra --resume &lt;SESSION_ID&gt;</code></pre><h3>显式处理 pending turn</h3><pre><code>oxidra --resume &lt;SESSION_ID&gt; --retry-pending
oxidra --resume &lt;SESSION_ID&gt; --abandon-pending</code></pre><p>重试或放弃不会追加第二份原始 prompt。未知工具副作用不自动重试；需要遵守会话的恢复检查。</p><h3>归档不是恢复</h3><pre><code>oxidra session export &lt;SESSION_ID&gt; archive.oxidra-session-export</code></pre><p>export 保存带版本清单的原始 journal 字节，不清除隔离 gate，也不能将导出归档直接作为会话恢复。受 guardian 隔离的 session 不支持原地恢复。</p>`,
  },
  memory: {
    title: '可管理的持久记忆', source: 'README.md',
    body: `<p>重要约定可以通过 <code>remember</code> 保存为本地 Markdown 文件。交互确认展示完整内容，而不是截断预览；<code>--full-auto</code> 也不能跳过此确认。</p><h3>你始终可以查看和删除</h3><pre><code>oxidra memory list
oxidra memory show &lt;ID&gt;
oxidra memory forget &lt;ID&gt;</code></pre><p>这些本地管理命令不需要 API key。由工具创建的记忆记录来源项目与创建时间，管理命令可见这些信息；模型注入前去掉 provenance frontmatter，并按确定的大小规则装入上下文。</p><p class="doc-notice">记忆保存在本地，但被选入上下文的内容会发送给你配置的模型 Provider。不要保存不希望进入模型上下文的秘密。</p>`,
  },
  context: {
    title: '上下文与 checkpoint', source: 'docs/m4-m5-roadmap.md',
    body: `<p>上下文压缩改变的是下一次发送给模型的 projection，不删除、覆盖或重写原始 journal。</p><h3>已经实现</h3><ul><li>版本化 checkpoint、summary envelope 与 checkpoint + tail projection。</li><li>真实 Provider 摘要调用、受控历史回查与 model-aware 测量。</li><li>上下文超限后的显式 retry / abandon，以及崩溃边界恢复。</li></ul><h3>自动压缩仍需显式开启</h3><pre><code>oxidra --experimental-auto-compact</code></pre><p>当前估算器用于规划和遥测，不是 tokenizer 支撑的精确硬边界。压缩失败时留下明确的 pending 状态，不静默截断历史。</p><p class="doc-notice">2026-08-07 记录的 Kimi-K2.7-Code prompt-v3 基线在十轮中保留 17/17 个冻结事实；证据只适用于记录的模型与后端。其他模型并未自动通过相同 gate，因此不能宣传为普遍的无损记忆。</p>`,
  },
  mcp: {
    title: 'MCP：内核已就绪，入口仍在建设', source: 'docs/mcp-roadmap.md',
    body: `<p class="doc-notice">当前 CLI 用户还不能接入 MCP 工具。底层协议实现不等于完整可用的扩展功能。</p><h3>已有基础</h3><ul><li>stdio transport / session kernel。</li><li>显式项目配置、execution-plan digest、固定 JSON Schema profile。</li><li>session-scoped registry 与 durable execution coordinator / journal policy。</li><li>Guardian 执行 gate 与崩溃隔离基础。</li></ul><h3>还要完成的用户链路</h3><ul><li>CLI 显式配置选择与 execution trust。</li><li>Agent 的工具面、registry epoch 与请求身份统一。</li><li>用户审批、journal 与 in-doubt 人工 resolution。</li><li>完整端到端与跨平台验收。</li></ul><p>第一版路线聚焦 stdio，不包含 HTTP、OAuth、远端 discovery 或自动安装。批准外部进程仍授予当前 OS 用户的权限，不是低权限插件沙箱。</p>`,
  },
  budget: {
    title: 'M4：会话预算的下一步', source: 'docs/m4-m5-roadmap.md',
    body: `<p class="doc-notice">M4 按真实使用数据暂缓。下述是设计规划，不是已生效的 CLI 能力。</p><h3>计划解决什么</h3><p>为每个 session 设定累计 token 与活跃执行时间的保险丝，避免长任务无边界地消耗资源。当前不承诺发布日期。</p><h3>不要与现有选项混淆</h3><p><code>--max-responses</code> 与 <code>--max-tools</code> 是已存在的、每逻辑 turn 的调用次数限制，不是会话 token 或时长预算。</p><h3>明确不做</h3><p>规划不是美元计费封顶、任务调度器或 Goal mode。Provider usage 和可恢复的 journal 仍应是可审计证据来源。</p>`,
  },
  boundaries: {
    title: '把边界说清楚', source: 'README.md',
    body: `<h3>本地优先，不是完全离线</h3><p>工具、会话和记忆由本地进程管理；模型推理通过 Responses API 进行。请求中的 <code>store: false</code> 不是不联网，也不能替代 Provider 的数据政策。</p><h3>确认不是沙箱</h3><p>read / edit / write 的访问范围限定在项目根。Shell 与经授权的外部程序拥有当前 OS 用户权限；对抗性隔离需要独立权限主体或系统级沙箱。</p><h3>先提交，再展示</h3><p>Provider 的 pre-commit stream 保持静默；响应通过校验并持久提交后才展示最终助手文本。页面中逐步播放的是工具流程示意，不是模型 token 流式输出。</p><h3>未知副作用不自动重试</h3><p>工具调用不是事务。中断无法撤销已经发生的文件或外部副作用，因此需要显式恢复，而不是盲目重新执行。</p><h3>刻意保持小</h3><p>当前不提供 TUI、sub-agent、Goal mode、自动安装插件或默认开启的自动压缩。先保证一个清楚、可验证的编码闭环。</p>`,
  },
};

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

export function renderCodeLines(lines) {
  const tones = { comment: 'syntax-comment', green: 'syntax-green', removed: 'is-removed', added: 'is-added' };
  return '<code>' + lines.map((line, index) =>
    `<span class="code-line ${tones[line.tone] || ''}"><span class="line-no">${index + 1}</span>${escapeHtml(line.text)}</span>`
  ).join('') + '</code>';
}

export function renderCommand(command) {
  return '<code>' + command.split('\n').map(line => line.trimStart().startsWith('#')
    ? `<span class="install-comment">${escapeHtml(line)}</span>` : escapeHtml(line)
  ).join('\n') + '</code>';
}
