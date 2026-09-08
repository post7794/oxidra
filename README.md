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

Interactive mode renders assistant text on stdout only after the Provider
response has been validated and durably committed. Its text is derived only
from the canonical output items, including an explicitly empty final text;
pre-commit text deltas cannot fill it back in. Tool/provider diagnostics use
stderr. Both interactive and batch stdout escape terminal/Unicode presentation
controls, preserve tabs and line breaks, and render CRLF as LF. This is a
display-only transformation: journals and Provider replay retain the raw text.

```powershell
cargo run
```

Press `Ctrl+C` to cancel the active Responses request or tool process. A
single shell command requires confirmation unless `--full-auto` is explicitly
provided for the current process.

Three consecutive identical tool failures pause the turn. In batch mode
(`-p` or `--retry-pending`), this exits with code 1 and no success text on stdout;
metrics and the failure reason remain on stderr. Interactive mode keeps the
REPL open so another prompt can be entered.

At the end of each completed turn, stderr prints the model, accumulated token
usage, and the approximate context size for the next request. The estimate is
telemetry, not a tokenizer-backed hard limit. A structured Provider context
limit becomes a recoverable pending turn; its durable failure intent can
reconstruct a missing or partial audit event after a crash. In an interactive TTY, edit
replacement lines are shown in red/green; `-p` and redirected output remain
plain text.

Automatic compaction remains an explicit opt-in. Passing
`--experimental-auto-compact` lets the current model-aware context estimate
trigger one checkpoint attempt for the active user turn. The planner keeps at
least two complete turns, estimates every eligible cutoff with the full
prepared-request shape and an estimator-side placeholder for the 8192-token
summary budget, and commits only if the real summary rebuild reaches the 50%
target. A failed or unavailable attempt stops the request and leaves a pending
boundary for explicit recovery: durable Provider attempts can be retried, and
a preflight-only failure is replanned by `--retry-pending`. The flag does not
turn the heuristic into a tokenizer-backed hard limit. Replanning validates
the frozen planning-v1 audit record but measures
the request again with the current model/context configuration, instructions,
tools, and history view. If the current request is now below the trigger, the
v5 boundary records a durable `resolved_without_checkpoint` result, skips the
compaction Provider call and checkpoint, and continues the original turn. A
crash after that resolution is synced resumes the same prompt with
`--retry-pending` without duplicating the user message or compaction attempt.
The reproducible live 3/5/10-round drift benchmark is documented in
`docs/compaction-drift.md`. Prompt v3 retained all 17 frozen facts through ten
rounds on the recorded `Kimi-K2.7-Code` Provider usage domain without executing
the quoted injection. Automatic compaction is still not enabled universally:
quality evidence is model/backend-specific, and the configured/default models
must pass the same recorded gate rather than inheriting another model's result.

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

`--max-responses` is a journal-derived, per-logical-turn Provider dispatch
budget. Durable `response.started` and bound `compaction.started` intents count
across crashes and explicit retries, including attempts that later fail or
abort. Raising the option on resume can permit further calls; retrying with the
same exhausted limit cannot reset it. When a compaction boundary owns recovery,
budget exhaustion leaves that boundary pending instead of writing a conflicting
turn-terminal event, so a later higher limit can resume it. The reported
assistant-response count still excludes an internal summary call. Journals
written by the earlier `55e5b0c` behavior may already contain a checkpointed
boundary followed by `agent.limit_reached`; `--retry-pending` recognizes that
literal legacy state and, only after the current limit is raised or disabled,
syncs a versioned `compaction.boundary.budget_retry_started` migration before
resuming the same prompt and checkpoint. The usage line includes usage returned
by an automatic compaction checkpoint when the turn completes in the same
process.

Both pending-turn options require `--resume` and never append a second copy of
the original prompt. Context-limit retries sync `turn.retry_started`; failed
compaction retries sync `compaction.boundary.retry_started` and replay the last
durable candidate. A checkpointed boundary resumes only from a validated
`Ready` Provider slot. The two validated terminal recovery paths are a
context-limit `turn.retry_started` and the narrowly scoped legacy budget
migration above; any other terminal outcome must be explicitly abandoned.
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
oxidra session export <SESSION_ID> <ARCHIVE>.oxidra-session-export
```

Session journals and shell artifacts are stored in the platform user-data
directory, never in the project. A session id is printed on startup.
Persistent memories are stored as plain Markdown under the same user-data
directory and are injected only after deterministic size packing. Memories
created by the tool record their source project and creation time in two-field
frontmatter; this provenance is visible to management commands but is stripped
before model injection. Before saving a `remember` result, interactive approval
shows the complete escaped content, not the truncated diagnostic preview;
`--full-auto` never substitutes for this confirmation.

On Unix, Oxidra tightens its data root and state directories to mode `0700`
and durable files to `0600`; on Windows it relies on the ACL inherited by the
selected data root. The Unix helper does not remove additional POSIX/extended
ACL entries or attest remote-filesystem permission semantics, so the operator
must also control those. These are privacy defaults, not a sandbox against
another process running as the same OS user. Session management,
history artifacts, memories, and built-in project tools still resolve parent
components through pathname-based filesystem APIs. After canonical resolution,
bounded file reads use a no-follow open where the platform exposes it, so that
exact final component cannot silently change into a link before the handle is
checked; an in-root symlink already resolved to an in-root target is still
allowed. A concurrent same-user writer can also replace a parent directory
after validation. Deployments requiring an adversarial namespace boundary need
a separate principal/sandbox or handle-relative broker rather than relying on
canonicalization and mode bits.

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
`tests/cli_output_contract.rs` additionally exercises full-content memory
approval, terminal-safe display with unchanged journal/replay bytes, canonical
empty-text handling, and stalled batch/retry exit codes across real CLI processes.

The integration suite also verifies that the entire Provider pre-commit stream
is silent: text, function-argument and unknown payloads, plus retry values,
counts and timing, cannot reach a caller callback before `response.completed`.
The committed text is rendered afterward. It also verifies that `--resume`
replays complete raw output items,
shell cancellation returns promptly, and project-root boundaries hold across
file tools. CI runs Rust 1.85 on Windows, Linux, and macOS via
`.github/workflows/ci.yml`.

The main branch contains an MCP stdio kernel, explicit project-config reader,
execution-plan approval capability, fixed JSON Schema profile, a
session-scoped registry, and the durable coordinator/journal policy core. These
are still Rust foundations: MCP is not yet wired into the CLI, Agent tool
surface, or user approval flow, so users still have only the built-in tools.
The MCP exact-wire claim is limited to the crate-sealed built-in OpenAI
transport; public custom prepared transports remain a trusted TCB and are
not admitted by the MCP coordinator. The built-in exact path also disables
HTTP redirects and implicit environment/system proxies; a required proxy must
be configured as the explicit API base URL so it is part of durable endpoint
provenance.
Approving an MCP execution plan grants that
local program the authority of the current OS user; future per-tool approval is
request audit/intent confirmation, not a filesystem or network sandbox. A
sealed approval boundary currently exposes only crate-owned fixed allow/deny
policies; interactive or argument-aware approval requires a separate durable
approval-attempt protocol before it can be added safely. A
process-external guardian now keeps a session execution gate across passive
host death until all registered Linux pidfd targets have exited or Windows Jobs
report no active processes. Before publishing READY it also fsyncs a durable
active-generation record; only an exact containment-empty proof can fsync the
matching clean record. If the guardian itself is killed first, the OS lock may
disappear but the session remains permanently quarantined rather than risking
overlapping generations. There is no in-place recovery because the durable v1
record cannot prove that the old containment is empty; `oxidra session export
<ID> <ARCHIVE>.oxidra-session-export` writes a versioned, non-resumable archive manifest followed by the
exact unchanged journal bytes, without clearing the gate or authorizing
resume. “Exact” means the bytes observed while holding the ordinary session
lock; it is not an authenticity guarantee against a still-running process with
the same OS-user authority. The destination parent directory must be controlled
by the operator and must not permit untrusted concurrent writers; the v1
pathname-based publisher does not defend against same-user namespace races.
Publication fsyncs a complete sibling first; Unix then hard-links without
replacement, removes the sibling, and fsyncs the parent directory, while
Windows uses no-replace `MoveFileExW` with `WRITE_THROUGH`. A failure after the
publish point is reported as durability-uncertain because the complete
destination may already exist and must not be blindly retried at the same path.
Windows children enter a
guardian-owned Job atomically at process birth, before their suspended primary
thread can run. This is a safety-over-availability crash ordering guarantee,
not a privilege boundary:
an approved same-user process can still attack the guardian, its lock path, or
other user-owned state. Adversarial plugin isolation still requires a lower
privilege principal/AppContainer/service or an equivalent OS boundary. See
`docs/mcp-roadmap.md` for the remaining integration and recovery gates.
