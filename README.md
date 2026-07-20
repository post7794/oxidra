# Oxidra

Oxidra is a lightweight personal CLI coding agent written in Rust. It uses the
OpenAI Responses API, provides four built-in Rust tools (`read`, `edit`,
`write`, and `shell`), and keeps an auditable append-only local session journal.

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

### Install on Windows

Download and verify the latest release into the current user's application
directory:

```powershell
irm https://raw.githubusercontent.com/post7794/oxidra/main/install.ps1 -OutFile $env:TEMP\oxidra-install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\oxidra-install.ps1 -AddToPath
```

Open a new terminal after installation. To install a specific release or use a
custom directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\oxidra-install.ps1 `
  -Version 0.1.0 -InstallDir "$HOME\bin" -AddToPath
```

The installer downloads the Windows MSVC archive and its release checksum,
verifies SHA256 before extracting, and installs only `oxidra.exe`. Without
`-AddToPath`, it prints the directory that must be added to the user `PATH`.

To build from source instead, use `cargo install --path .` from this checkout.
The raw script and release assets must be anonymously readable for these
commands, so this installation path is intended for a public GitHub repository.

### Run

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

At the end of each completed turn, stderr prints the model, accumulated token
usage, and the estimated context size for the next request. In an interactive
TTY, edit replacement lines are shown in red/green; `-p` and redirected output
remain plain text.

Useful options:

```text
-p, --print <PROMPT>       run one non-interactive turn
    --resume <SESSION_ID>  resume a local JSONL session
    --cwd <DIR>            select the project root; otherwise discover .git upward
    --model <MODEL>        override the default gpt-5.6-sol model
    --full-auto            skip per-command shell confirmation
    --max-responses <N>    optional per-turn insurance limit
    --max-tools <N>        optional per-turn insurance limit
```

Session journals and shell artifacts are stored in the platform user-data
directory, never in the project. A session id is printed on startup.

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
cancellation returns promptly, and project-root boundaries hold across file
tools. CI runs Rust 1.85 on Windows, Linux, and macOS via
`.github/workflows/ci.yml`.

Oxidra has no extension system. The removed experimental implementation is
retained only as historical source at the `archive/mcp-mvp` tag.
