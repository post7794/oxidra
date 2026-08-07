# Oxidra

Oxidra is a lightweight personal CLI coding agent written in Rust. It uses the
OpenAI Responses API, provides five built-in Rust tools (`read`, `edit`,
`write`, `shell`, and `remember`), and keeps an auditable append-only local
session journal.

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
The release workflow pins third-party Actions to full commit SHAs and publishes
a GitHub build-provenance attestation for the archive. The checksum protects
transport integrity; the provenance record is the separate build-origin
evidence.

To build from source instead, use `cargo install --path .` from this checkout.
The raw script and release assets must be anonymously readable for these
commands, so this installation path is intended for a public GitHub repository.

### Run

Use `API_KEY` for a shell-scoped override, or persist the credential separately
from normal configuration with `oxidra auth login`. `OPENAI_API_KEY` remains a
compatibility fallback.

```powershell
$env:API_KEY = "..."
cargo run -- -p "修复当前项目的测试并运行验证" --full-auto
```

The persistent config file is `%APPDATA%\oxidra\config.toml` on Windows. It
contains non-secret provider settings only:

```toml
[provider]
api_base_url = "https://api.openai.com/v1"
model = "gpt-5.6-sol"

[auth]
credential_store = "keyring"

[context]
context_window = 128000
reserve_tokens = 16384

[context.models."gpt-5.6-sol"]
context_window = 1000000
reserve_tokens = 65536
```

```powershell
oxidra auth login
oxidra auth status
oxidra auth logout
```

`keyring` is the default and uses the operating-system credential store. Set
`credential_store = "file"` only as an explicit fallback; it stores plaintext
credentials in `auth.json` beside `config.toml`. A stored credential is bound to
the normalized API base URL and is rejected after the URL changes. Environment
variables override persistent settings and credentials.

Context values resolve independently in this order: CLI override, environment
variable, exact model entry, global `[context]`, then the built-in default.
`OXIDRA_CONTEXT_WINDOW` and `OXIDRA_RESERVE_TOKENS` are the environment
overrides. The reserve must be smaller than the selected window.

The legacy `[provider].api_key` field is intentionally rejected. Remove it from
an existing config file, then run `oxidra auth login` to migrate the credential
into the selected store.

Interactive mode shows streamed assistant text on stdout and tool/provider
diagnostics on stderr:

```powershell
cargo run
```

Press `Ctrl+C` to cancel the active Responses request or tool process. A
single shell command requires confirmation unless `--full-auto` is explicitly
provided for the current process.

At the end of each completed turn, stderr prints the model, accumulated token
usage, and the approximate context size for the next request. The estimate is
telemetry, not a tokenizer-backed hard limit. A structured Provider context
limit becomes a recoverable pending turn. In an interactive TTY, edit
replacement lines are shown in red/green; `-p` and redirected output remain
plain text.

Automatic compaction remains an explicit experiment. Passing
`--experimental-auto-compact` lets the current model-aware context estimate
trigger one checkpoint attempt for the active user turn. The planner keeps at
least two complete turns, estimates every eligible cutoff with the full
prepared-request shape and an estimator-side placeholder for the 8192-token
summary budget, and commits only if the real summary rebuild reaches the 50%
target. A failed or unavailable attempt stops the request and leaves a pending
boundary for explicit recovery: durable Provider attempts can be retried,
while a preflight-only failure must currently be abandoned. The flag does not
turn the heuristic into a tokenizer-backed hard limit and is not enabled by
default.

Useful options:

```text
-p, --print <PROMPT>       run one non-interactive turn
    --resume <SESSION_ID>  resume a local JSONL session
    --cwd <DIR>            select the project root; defaults to the current directory
    --model <MODEL>        override the default gpt-5.6-sol model
    --full-auto            skip per-command shell confirmation
    --max-responses <N>    optional per-turn insurance limit
    --max-tools <N>        optional per-turn insurance limit
    --context-window <N>   override the effective model context window
    --reserve-tokens <N>   override the reserved token allowance
    --experimental-auto-compact
                            opt in to estimated-trigger automatic compaction
    --retry-pending        retry one pending context-limit or compaction request
    --abandon-pending      abandon pending context-limit/compaction requests
```

Both pending-turn options require `--resume` and never append a second copy of
the original prompt. Context-limit retries sync `turn.retry_started`; failed
compaction retries sync `compaction.boundary.retry_started` and replay the last
durable candidate. A checkpointed boundary resumes only from a validated
`Ready` Provider slot; another terminal outcome must use its own validated
retry protocol (currently context-limit) or be explicitly abandoned.
`--abandon-pending` can be combined with `-p` to submit a replacement prompt;
the original journal bytes remain available for audit.

Local management commands do not require an API key:

```text
oxidra auth status
oxidra auth logout
oxidra memory list
oxidra memory show <ID>
oxidra memory forget <ID>
oxidra session delete <SESSION_ID>
```

Session journals and shell artifacts are stored in the platform user-data
directory, never in the project. A session id is printed on startup.
Persistent memories are stored as plain Markdown under the same user-data
directory and are injected only after deterministic size packing. Memories
created by the tool record their source project and creation time in two-field
frontmatter; this provenance is visible to management commands but is stripped
before model injection.

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
