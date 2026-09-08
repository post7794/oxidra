# Oxidra Agent 产品与演进介绍前端展示页

这是一个专为 **Oxidra**（基于 Rust 构建的轻量级个人 CLI 编码 Agent）打造的高质感、交互式前端产品与研发进度展示网页。

---

## 🌟 特性与内容亮点

1. **工程演进全景矩阵 (Roadmap Matrix)**：
   - 动态筛选器：查看 **全部 / 已完成 · 稳定 (M1-M3) / 主线已就绪 · 实验性 (M5) / 底座就绪 (MCP) / 已规划 · 暂缓 (M4)**。
   - 详细列出各个阶段的交付物清单（如流式静默提交、系统 Keyring、会话隔离归档、80% 触发 50% 目标压缩、17/17 事实留存无注入测试、Windows Job / Linux seccomp 强沙箱等）及源码锚点。
2. **5 大内置 Rust 工具交互体验 (Built-in Tools)**：
   - 包含 `read`、`edit`、`write`、`shell`、`remember`。
   - 提供工具权限、限制边界（如 2000 行限制、SHA-256 哈希校验防脏写锁、Windows Job 挂载等）、JSON Schema 及模型请求与持久化返回值预览。
3. **M5 上下文自适应压缩引擎 (Auto-Compaction)**：
   - 详细图解 80% usable 触发线、50% usable 压缩目标线与 8,192 Token 摘要包络。
   - Anchor 差分预测公式与 Kimi-K2.7-Code 10 轮漂移基准测试成果。
   - 3 个受控历史回查工具（`history_search`, `history_turn`, `history_artifact`）。
4. **交互式 CLI 终端沙盒模拟器 (Terminal Sandbox)**：
   - 模拟 `read -> edit -> shell -> audit commit` 完整运行闭环，具备真实打字机流式输出、红绿彩色 Diff 高亮、命令切换与重播功能。
5. **四大不可破坏安全契约**：
   - Append-Only 本地审计日志
   - 提交前严格静默 (Silent Pre-commit Stream)
   - 操作系统级进程沙箱
   - 确定性优先于可用性
6. **零外部运行依赖 (Zero Dependencies)**：
   - 纯原生 HTML5 + 现代化 CSS3 (Glassmorphism / 科技暗色系) + ES6+ Modules。
   - 离线可用，无需 `npm install`。

---

## 🚀 启动与预览方式

### 方式一：直接在浏览器中双击打开
直接双击打开 `showcase/index.html` 即可完整浏览（所有样式与图标均内嵌或采用相对路径）。

### 方式二：使用自带轻量服务运行（推荐，支持 ES 模块完整体验）
如果你的系统安装了 Node.js（Node 18+），在命令行中执行：

```powershell
node showcase/server.mjs
```

或者进入 `showcase` 目录执行：

```powershell
cd showcase
npm start
```

服务将自动启动并监听在：`http://127.0.0.1:3000`。

### 方式三：使用任意本地静态服务器
```powershell
# 使用 Python
python -m http.server 3000 --directory showcase

# 或者使用 npx serve
npx serve showcase
```
