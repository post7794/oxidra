# Oxidra 产品介绍站

暖白 / 墨绿 / 青柠配色的响应式单页。原生 HTML、CSS、ES Modules；零第三方运行依赖、无外部字体、无分析追踪，不修改 Rust Agent。

## 本地运行

需要 Node.js 20+。在 PowerShell 中：

```powershell
Set-Location 'C:\Users\wdnmd\Documents\Agent\web'
npm run dev
```

默认地址：`http://127.0.0.1:5173`。无需先运行 `npm install`。端口被占用时：

```powershell
npm run dev -- --port 5174
```

## 验证与部署

```powershell
npm test
npm run build
node server.mjs --dist --port 5174
```

`dist/` 可独立部署到静态托管服务，包括子目录托管；资源使用相对路径。不要以项目根目录启动通用文件服务器。这里的预览服务只监听回环地址，且只暴露精确白名单中的前端资源与四份只读参考文档。

生产静态托管可沿用 `server.mjs` 中的安全响应头，至少保留 `X-Content-Type-Options: nosniff`、同源脚本策略和 `connect-src 'none'`。

## 已实现的交互

- 本地模拟 `read → edit → shell`，可重播、切换事件摘要视图；不执行任何真实命令。
- 五个工具标签切换说明和代码示例，支持左右方向键 / Home / End。
- 开发进度筛选；M4 暂缓归入“建设中”，卡片保留明确的“已规划 · 暂缓”标记。
- 源码安装 / Windows 安装 / 首次运行切换与命令复制；失败时明确提示手动复制。
- 原生 `dialog` 文档阅读器，支持 Escape、背景关闭、焦点约束和返回触发元素。
- 移动导航、FAQ、语义化锚点、减少动态效果设置。

## 内容依据和更新

内容快照：**2026-09-08 当前工作区**，不是对远端 main 或最新 Release 的声明。已读取 README、源文件、规划文档，并核对当前 `target/debug/oxidra.exe --help`；没有运行真实模型请求，也没有重新执行 Rust 全量测试。

| 页面内容 | 项目依据 |
| --- | --- |
| 五个内置工具、读写保护、确认 | `src/tools.rs`、`src/agent.rs` |
| 可用 CLI 选项 / 管理命令 | `src/cli.rs`、当前二进制 `--help` |
| 本地会话、凭据、恢复和导出 | `README.md` |
| M1–M3 及明确的 MVP 范围 | `docs/oxidra-mvp.md` |
| M5 显式实验入口 / M4 暂缓 | `docs/m4-m5-roadmap.md` |
| MCP 只有底层基础、未接入用户链路 | `docs/mcp-roadmap.md` |

主要文件：
- `index.html`：静态正文、路线图状态、语义结构。禁用 JS 仍可阅读正文和安装命令。
- `styles.css`：设计 token、布局、移动断点、减少动态效果。
- `content.js`：可切换工具示例、安装命令和经过编辑的文档摘要。
- `app.js`：所有交互。不读取 key、用户会话或本地存储，不包含 fetch / WebSocket。
- `server.mjs`：只读白名单预览服务。
- `scripts/build.mjs`：生成静态目录并复制四份参考文档。
- `tests/site.test.mjs`：内容、转义、路由隔离与生产构建测试。

功能进度变化时，同时更新 `index.html` 中的可见摘要、`content.js` 文档和快照日期；再运行测试、构建和浏览器验收。参考文档在开发时读取当前仓库白名单文件，在构建时被复制成快照。不要仅根据规划中的代码示例声称某个 CLI 参数已可用。

终端“已通过”的测试、文件 diff、JSONL 事件摘要全部是明确标记的 UI 演示，不是实际运行日志。网站是项目介绍，而不是新增的 Web Agent 控制台。Windows 安装命令来自当前 README；远端 Release 是否公开可读未由本次任务确认，因此默认提供当前源码构建方式。


## 本次浏览器验收（2026-09-08）

- Chromium 实际页面检查：1440 桌面、1024 / 768 中间尺寸、390 手机和 320 窄屏；页面无水平滚动溢出。
- 五个工具切换、方向键切换、四种路线图筛选、三个安装页签、九份文档页、FAQ 展开 / 收起、终端重播和日志视图均通过。
- 移动菜单 / 文档弹窗 / Escape 关闭 / 焦点返回通过；文档内容在小屏内独立滚动。
- 命令复制使用模拟 Clipboard 对象检查准确内容、拒绝权限提示与快速重复点击后的图标恢复，未读取系统剪贴板；减少动画分支使用受控 MediaQueryList 模拟检查。
- 页面错误 / 警告控制台为空；初始资源均来自本站，无外部请求。
- `npm test`：11 / 11；`npm run build`：9 份可独立部署的静态文件。
