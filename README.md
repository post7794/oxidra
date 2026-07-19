# Oxidra

Oxidra is a lightweight, extensible CLI coding agent written in Rust. It uses
the OpenAI Responses API and keeps an auditable, append-only local session
journal. External tools use a long-lived MCP stdio JSON-RPC process; built-in
tools are Rust implementations.

The design and the explicit MVP boundary are documented in
[docs/oxidra-mvp.md](docs/oxidra-mvp.md).

## Prerequisites

- Rust 1.85 (edition 2024).
- Windows: the MSVC target also needs Visual Studio Build Tools with the
  **Desktop development with C++** workload and a Windows SDK. Build from a
  Developer PowerShell so `link.exe` is on `PATH`.
- Windows GNU is supported for development validation, but needs a complete
  MinGW toolchain; Rust's small self-contained linker directory alone cannot
  compile C dependencies such as `ring`.
- Linux/macOS: the platform C compiler/linker and standard development
  packages.

Check the project without making a network request:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo check --offline
```

## Quick Start

Set the API credential in the environment. `API_KEY` is the primary variable;
`OPENAI_API_KEY` is accepted as a compatibility fallback.

```powershell
$env:API_KEY = "..."
cargo run -- -p "修复当前项目的测试并运行验证" --full-auto
```

Interactive mode shows streamed assistant text on stdout and tool/provider
diagnostics on stderr:

```powershell
cargo run
```

Press `Ctrl+C` to cancel the active Responses request or tool process. A
single shell command requires confirmation unless `--full-auto` is explicitly
provided for the current process.

Useful options:

```text
-p, --print <PROMPT>       run one non-interactive turn
    --resume <SESSION_ID>  resume a local JSONL session
    --cwd <DIR>            select the project root
    --config <FILE>        select <project>/.oxidra/config.toml
    --model <MODEL>        override the default gpt-5.6-sol model
    --full-auto            skip per-command shell confirmation
    --max-responses <N>    optional per-turn insurance limit
    --max-tools <N>        optional per-turn insurance limit
```

Session journals and shell artifacts are stored in the platform user-data
directory, never in the project. A session id is printed on startup.

## Project Plugins

Only plugins explicitly listed in `.oxidra/config.toml` are considered; Oxidra
does not scan `PATH` for plugins. A minimal project config is:

```toml
[[plugins]]
name = "fixture"
manifest = "plugins/fixture/manifest.json"
activation = "on_call" # or "eager" for runtime-generated schemas
```

The manifest declares an MCP stdio executable and static tool schemas. The
command may be an absolute path, a path relative to the manifest, or a command
resolved from an absolute `PATH` entry. Oxidra resolves it before launch and
re-checks the project execution hash before every activation/call. A dynamic
schema may omit `schemaHash`, but it must use `activation = "eager"`.

The first use of an untrusted project asks for confirmation. Trust is stored
outside the project and is invalidated when the config, lockfile, manifest,
declared executable, or manifest-referenced script changes. Trust is not an OS
sandbox: an accepted plugin runs with the current user's permissions.

## Verification

The end-to-end test uses a fake Responses SSE server and never contacts a real
provider or consumes a real API key:

```powershell
cargo fmt --all -- --check
cargo test --offline
cargo clippy --all-targets --offline -- -D warnings
```

The canonical acceptance flow is `read -> edit -> shell`, with a real file
change and command result verified by the test in `tests/e2e_cli.rs`.

The integration suite also verifies that interactive text deltas arrive before
`response.completed`, `--resume` replays complete raw output items, shell
cancellation returns promptly, and a real Python MCP stdio fixture performs the
lazy handshake and reuses one long-lived connection. CI runs Rust 1.85 on
Windows, Linux, and macOS via `.github/workflows/ci.yml`.
