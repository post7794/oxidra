use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agent::{
    Agent, AgentObserver, ApprovalHandler, ToolRegistry, TurnOutcome, load_project_instructions,
};
use crate::config::{ContextLimits, ProjectContext, ProviderConfig};
use crate::error::{OxidraError, Result};
use crate::plugin::{PluginActivation, PluginSupervisor, resolve_executable_path};
use crate::provider::{OpenAiResponsesProvider, ProviderEvent};
use crate::session::{InDoubtTool, SessionHeader, SessionJournal, SessionStore};
use crate::tools::BuiltinTools;
use crate::trust::{TrustStore, execution_hash};
use crate::types::{ToolCall, ToolResult};

const DISPLAY_VALUE_LIMIT: usize = 4 * 1024;
const DISPLAY_DIFF_LIMIT: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "oxidra",
    version,
    about = "A lightweight, extensible CLI coding agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Run one non-interactive turn and print only the completed assistant text.
    #[arg(short = 'p', long = "print", value_name = "PROMPT")]
    prompt: Option<String>,

    /// Resume an existing local session.
    #[arg(long, value_name = "SESSION_ID")]
    resume: Option<String>,

    /// Allow shell commands without per-command confirmation for this process.
    #[arg(long)]
    full_auto: bool,

    /// Override the provider model.
    #[arg(long, value_name = "MODEL")]
    model: Option<String>,

    /// Use this directory as the project root without searching parents.
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Load a specific project config file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Stop a turn after this many Responses API calls.
    #[arg(long, value_name = "COUNT", value_parser = parse_positive_usize)]
    max_responses: Option<usize>,

    /// Stop a turn after this many tool calls.
    #[arg(long, value_name = "COUNT", value_parser = parse_positive_usize)]
    max_tools: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check local configuration and report actionable problems.
    Doctor,
    /// Inspect locally persisted sessions.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Inspect or revoke project plugin trust.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// List sessions, newest first.
    List,
    /// Print the canonical journal for a session.
    Show { session_id: String },
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// List trusted project plugin configurations.
    List,
    /// Revoke all plugin trust for a project path.
    Revoke { path: PathBuf },
}

/// Synchronous binary entry point. The CLI owns its Tokio runtime so the core
/// stays usable by synchronous launchers and tests.
pub fn main_entry() -> Result<()> {
    let cli = Cli::parse();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let Cli {
        command,
        prompt,
        resume,
        full_auto,
        model,
        cwd,
        config,
        max_responses,
        max_tools,
    } = cli;
    if let Some(command) = command {
        return run_management_command(command, cwd, config, model);
    }
    let interactive = prompt.is_none();
    let project = ProjectContext::resolve(cwd, config)?;
    let provider_config = ProviderConfig::resolve(None, None, model)?;
    let context_limits = ContextLimits::load(None, None)?;
    let config_hash = execution_hash(&project)?;
    let store = SessionStore::platform_default()?;

    let journal = match resume.as_deref() {
        Some(session_id) => {
            let mut journal = store.open(session_id)?;
            validate_resumed_session(&journal, &project, &provider_config.model, &config_hash)?;
            resolve_in_doubt(&mut journal, interactive)?;
            journal
        }
        None => {
            let header = SessionHeader::new(
                project.root.clone(),
                config_hash.clone(),
                provider_config.model.clone(),
            );
            store.create(header)?
        }
    };

    let plugins = load_plugins(&project, &config_hash)?;
    verify_plugin_checksums(&project)?;
    ensure_project_trust(&project, &config_hash, &plugins, interactive)?;

    let instructions = build_instructions(&project, &journal)?;
    let builtins = BuiltinTools::new(
        &project.root,
        journal.artifact_dir(),
        full_auto,
        interactive,
    )?;
    let registry = ToolRegistry::new(builtins, plugins)?;
    let provider = Arc::new(OpenAiResponsesProvider::new(provider_config)?);
    let mut agent = Agent::new(
        provider,
        journal,
        registry,
        instructions,
        context_limits,
        max_responses,
        max_tools,
    );

    eprintln!(
        "Oxidra session {} (root: {})",
        agent.session_id(),
        project.root.display()
    );

    let session_result = async {
        if let Err(error) = activate_eager_with_interrupt(&agent).await {
            if matches!(&error, OxidraError::Interrupted) {
                return Err(error);
            }
            eprintln!("plugin activation warning: {error}");
        }

        match prompt.as_deref() {
            Some(prompt) => run_batch_turn(&mut agent, prompt, full_auto).await,
            None => run_repl(&mut agent, full_auto).await,
        }
    }
    .await;

    let shutdown_result = agent.shutdown().await;
    match (session_result, shutdown_result) {
        (Err(error), Err(shutdown_error)) => {
            eprintln!("plugin shutdown warning: {shutdown_error}");
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn run_management_command(
    command: Command,
    cwd: Option<PathBuf>,
    config: Option<PathBuf>,
    model: Option<String>,
) -> Result<()> {
    match command {
        Command::Doctor => run_doctor(cwd, config, model),
        Command::Session { command } => run_session_command(command),
        Command::Trust { command } => run_trust_command(command),
    }
}

fn run_session_command(command: SessionCommand) -> Result<()> {
    let store = SessionStore::platform_default()?;
    match command {
        SessionCommand::List => {
            let sessions = store.list()?;
            if sessions.is_empty() {
                println!("No sessions.");
                return Ok(());
            }
            for session in sessions {
                println!(
                    "{}\t{}\t{}\t{} events\t{}",
                    session.session_id,
                    session.last_activity.to_rfc3339(),
                    session.header.model,
                    session.event_count,
                    session.header.project_root.display()
                );
            }
            Ok(())
        }
        SessionCommand::Show { session_id } => {
            let events = store.inspect(&session_id)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
            Ok(())
        }
    }
}

fn run_trust_command(command: TrustCommand) -> Result<()> {
    let mut store = TrustStore::load()?;
    match command {
        TrustCommand::List => {
            let projects = store.projects();
            if projects.is_empty() {
                println!("No trusted projects.");
                return Ok(());
            }
            for project in projects {
                match project.project_root {
                    Some(root) => println!("{}\t{}", root.display(), project.execution_hash),
                    None => println!("<legacy path unavailable>\t{}", project.execution_hash),
                }
            }
            Ok(())
        }
        TrustCommand::Revoke { path } => {
            let root = fs::canonicalize(&path).map_err(|error| {
                OxidraError::Config(format!(
                    "cannot resolve project path {}: {error}",
                    path.display()
                ))
            })?;
            if store.revoke(&root)? {
                println!("Revoked plugin trust for {}", root.display());
            } else {
                println!("No plugin trust record for {}", root.display());
            }
            Ok(())
        }
    }
}

fn run_doctor(cwd: Option<PathBuf>, config: Option<PathBuf>, model: Option<String>) -> Result<()> {
    let mut failed = false;
    println!("Oxidra {}", env!("CARGO_PKG_VERSION"));
    println!(
        "platform: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    match SessionStore::platform_default() {
        Ok(store) => println!("data directory: ok ({})", store.layout().data_dir.display()),
        Err(error) => {
            println!("data directory: FAILED ({error})");
            failed = true;
        }
    }

    match ProviderConfig::resolve(None, None, model) {
        Ok(provider) => {
            println!("API configuration: ok ({})", provider.api_base_url);
            println!("model: {}", provider.model);
        }
        Err(error) => {
            println!("API configuration: FAILED ({error})");
            failed = true;
        }
    }

    match ProjectContext::resolve(cwd, config) {
        Ok(project) => {
            println!("project: ok ({})", project.root.display());
            println!("plugins: {} declared", project.config.plugins.len());
            if let Err(error) = verify_plugin_checksums(&project) {
                println!("plugin checksums: FAILED ({error})");
                failed = true;
            } else {
                println!("plugin checksums: ok");
            }
        }
        Err(error) => {
            println!("project: FAILED ({error})");
            failed = true;
        }
    }

    if failed {
        Err(OxidraError::Config(
            "doctor found one or more problems".to_owned(),
        ))
    } else {
        println!("status: healthy");
        Ok(())
    }
}

fn load_plugins(project: &ProjectContext, config_hash: &str) -> Result<Vec<Arc<PluginSupervisor>>> {
    project
        .config
        .plugins
        .iter()
        .map(|plugin| {
            let activation = PluginActivation::parse(&plugin.activation)?;
            let mut supervisor = PluginSupervisor::from_manifest(
                &plugin.name,
                &plugin.manifest,
                &project.root,
                activation,
            )?;
            supervisor.bind_trust(project.clone(), config_hash.to_owned());
            Ok(Arc::new(supervisor))
        })
        .collect()
}

fn verify_plugin_checksums(project: &ProjectContext) -> Result<()> {
    let lock_path = project.root.join(".oxidra").join("lock.toml");
    if !lock_path.is_file() {
        return Ok(());
    }
    let text = fs::read_to_string(&lock_path)?;
    let lock: toml::Value = toml::from_str(&text)?;
    for plugin in &project.config.plugins {
        let Some(checksum) = lockfile_checksum(&lock, &plugin.name) else {
            continue;
        };
        let expected = checksum
            .strip_prefix("sha256:")
            .unwrap_or(&checksum)
            .to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(OxidraError::Config(format!(
                "lockfile checksum for plugin {} is not SHA-256",
                plugin.name
            )));
        }
        let manifest_path = project.resolve_manifest(&plugin.manifest);
        let manifest_text = fs::read_to_string(&manifest_path)?;
        let manifest: Value = serde_json::from_str(&manifest_text)?;
        let command = manifest
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                OxidraError::Config(format!(
                    "plugin {} manifest has no executable command",
                    plugin.name
                ))
            })?;
        let command_path = resolve_executable_path(
            command,
            manifest_path.parent().unwrap_or_else(|| Path::new(".")),
        )
        .map_err(|error| {
            OxidraError::Config(format!(
                "cannot resolve executable for plugin {} checksum: {error}",
                plugin.name
            ))
        })?;
        let bytes = fs::read(&command_path).map_err(|error| {
            OxidraError::Config(format!(
                "cannot read executable {} for plugin {} checksum: {error}",
                command_path.display(),
                plugin.name
            ))
        })?;
        let actual = hex::encode(Sha256::digest(bytes));
        if actual != expected {
            return Err(OxidraError::Config(format!(
                "lockfile checksum mismatch for plugin {}: expected {}, found {}",
                plugin.name, expected, actual
            )));
        }
    }
    Ok(())
}

fn lockfile_checksum(lock: &toml::Value, plugin_name: &str) -> Option<String> {
    let plugins = lock.get("plugins")?;
    if let Some(table) = plugins.as_table() {
        let entry = table.get(plugin_name)?;
        return entry
            .get("checksum")
            .or_else(|| entry.get("sha256"))
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned);
    }
    let entries = plugins.as_array()?;
    entries.iter().find_map(|entry| {
        if entry.get("name").and_then(toml::Value::as_str) != Some(plugin_name) {
            return None;
        }
        entry
            .get("checksum")
            .or_else(|| entry.get("sha256"))
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn ensure_project_trust(
    project: &ProjectContext,
    config_hash: &str,
    plugins: &[Arc<PluginSupervisor>],
    interactive: bool,
) -> Result<()> {
    if plugins.is_empty() {
        return Ok(());
    }

    let mut trust = TrustStore::load()?;
    if trust.is_trusted(&project.root, config_hash) {
        return Ok(());
    }

    eprintln!("This project declares local executable plugins:");
    for plugin in plugins {
        let manifest = plugin.manifest();
        let args = if manifest.args.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                manifest
                    .args
                    .iter()
                    .map(|arg| escape_terminal(arg))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        eprintln!(
            "  {}: {}{}",
            escape_terminal(&manifest.name),
            escape_terminal(&manifest.command),
            args
        );
        if !manifest.env.inherit.is_empty() {
            eprintln!(
                "    inherited env: {}",
                manifest
                    .env
                    .inherit
                    .iter()
                    .map(|name| escape_terminal(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !manifest.env.set.is_empty() {
            eprintln!(
                "    fixed env names: {}",
                manifest
                    .env
                    .set
                    .keys()
                    .map(|name| escape_terminal(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    eprintln!(
        "Trusted plugins run with your full user permissions. cwd/env limits are not a sandbox."
    );

    if !interactive {
        return Err(OxidraError::ApprovalRequired(format!(
            "project plugins are not trusted for {}",
            project.root.display()
        )));
    }
    if !prompt_yes_no("Trust this exact project plugin configuration? [y/N] ")? {
        return Err(OxidraError::ApprovalRequired(
            "project plugin trust was declined".to_owned(),
        ));
    }

    trust.trust(&project.root, config_hash.to_owned())
}

fn validate_resumed_session(
    journal: &SessionJournal,
    project: &ProjectContext,
    model: &str,
    config_hash: &str,
) -> Result<()> {
    let header = journal.header()?.ok_or_else(|| {
        OxidraError::Session(format!(
            "session {} has no session.started header",
            journal.session_id()
        ))
    })?;
    if !same_project_path(&header.project_root, &project.root) {
        return Err(OxidraError::Session(format!(
            "session belongs to {}, not {}",
            header.project_root.display(),
            project.root.display()
        )));
    }
    if header.config_hash != config_hash {
        eprintln!("Project execution configuration changed since this session was created.");
    }
    if header.model != model {
        eprintln!(
            "Session model changed from {} to {} for this process.",
            header.model, model
        );
    }
    let recovery = journal.recovery_info();
    if let Some(tail) = &recovery.truncated_tail {
        eprintln!(
            "Recovered an incomplete journal tail ({} bytes, sha256 {}).",
            tail.byte_count, tail.sha256
        );
    }
    if recovery.aborted_responses > 0 {
        eprintln!(
            "Recovered {} unterminated model response(s) as aborted.",
            recovery.aborted_responses
        );
    }
    if recovery.skipped_before_start > 0 {
        eprintln!(
            "Recovered {} tool call(s) that were never dispatched as skipped.",
            recovery.skipped_before_start
        );
    }
    Ok(())
}

fn same_project_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
        let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
        left.len() == right.len()
            && left.iter().zip(right.iter()).all(|(left, right)| {
                let fold = |unit: u16| {
                    if ((b'A' as u16)..=(b'Z' as u16)).contains(&unit) {
                        unit + (b'a' - b'A') as u16
                    } else {
                        unit
                    }
                };
                fold(*left) == fold(*right)
            })
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn resolve_in_doubt(journal: &mut SessionJournal, interactive: bool) -> Result<()> {
    let pending = report_in_doubt(journal)?;
    if pending.is_empty() {
        return Ok(());
    }

    if !interactive {
        return Err(OxidraError::ApprovalRequired(
            "resumed session has in-doubt tool calls; inspect their side effects and resolve interactively"
                .to_owned(),
        ));
    }
    if !prompt_yes_no(
        "After checking side effects, record all calls above as failed and continue? [y/N] ",
    )? {
        return Err(OxidraError::ApprovalRequired(
            "in-doubt tool calls were not resolved".to_owned(),
        ));
    }

    resolve_reported_in_doubt(journal, pending)
}

async fn resolve_in_doubt_async(
    journal: &mut SessionJournal,
    input: &mut StdinLines,
) -> Result<()> {
    let pending = report_in_doubt(journal)?;
    if pending.is_empty() {
        return Ok(());
    }
    eprint!("After checking side effects, record all calls above as failed and continue? [y/N] ");
    io::stderr().flush()?;
    let confirmed = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            false
        }
        answer = input.read_line() => answer?.is_some_and(|answer| {
            matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        }),
    };
    if !confirmed {
        return Err(OxidraError::ApprovalRequired(
            "in-doubt tool calls were not resolved".to_owned(),
        ));
    }
    resolve_reported_in_doubt(journal, pending)
}

fn report_in_doubt(journal: &SessionJournal) -> Result<Vec<InDoubtTool>> {
    let pending = journal.in_doubt()?;
    if pending.is_empty() {
        return Ok(pending);
    }
    eprintln!(
        "Session {} contains {} tool call(s) with unknown side effects:",
        journal.session_id(),
        pending.len()
    );
    for tool in &pending {
        let name = in_doubt_tool_name(tool).unwrap_or("unknown");
        let call_id = tool.call_id.as_deref().unwrap_or("unknown");
        eprintln!(
            "  seq {}: {} (call_id {}) arguments={}",
            tool.started_seq,
            name,
            call_id,
            display_value(tool.arguments.as_ref().unwrap_or(&Value::Null))
        );
    }
    Ok(pending)
}

fn resolve_reported_in_doubt(
    journal: &mut SessionJournal,
    pending: Vec<InDoubtTool>,
) -> Result<()> {
    for tool in pending {
        resolve_one_in_doubt(journal, tool)?;
    }
    Ok(())
}

fn resolve_one_in_doubt(journal: &mut SessionJournal, tool: InDoubtTool) -> Result<()> {
    let call_id = tool
        .call_id
        .as_deref()
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "cannot resolve in-doubt tool at seq {} without a call_id",
                tool.started_seq
            ))
        })?
        .to_owned();
    let tool_name = in_doubt_tool_name(&tool).unwrap_or("unknown").to_owned();
    let output = json!({
        "error": {
            "code": "in_doubt",
            "message": "tool side effects were unknown after interruption; user inspected the state and chose to continue treating the call as failed"
        }
    });
    journal.append_and_sync(
        "tool.in_doubt_resolved",
        tool.turn_id.as_deref(),
        json!({
            "started_seq": tool.started_seq,
            "call_id": call_id,
            "tool": tool_name,
            "output": output,
            "is_error": true,
            "error_code": "in_doubt",
            "resolution": "user_treated_as_failed",
        }),
    )?;
    Ok(())
}

fn in_doubt_tool_name(tool: &InDoubtTool) -> Option<&str> {
    tool.tool_name
        .as_deref()
        .or_else(|| tool.data.get("tool").and_then(Value::as_str))
        .or_else(|| tool.data.get("name").and_then(Value::as_str))
}

fn build_instructions(project: &ProjectContext, journal: &SessionJournal) -> Result<String> {
    let project_instructions = load_project_instructions(&project.root)?;
    let shell_kind = if cfg!(windows) { "powershell" } else { "sh" };
    let mut instructions = format!(
        "You are Oxidra, a coding agent operating in the project root {}. \
Use read and edit for existing project files, write for new files, and shell for commands. Never use write to overwrite an existing path. Paths supplied to file tools must remain \
inside the project root. The shell kind is {shell_kind}. Inspect relevant files before editing, make \
focused changes, run an appropriate verification, and report only outcomes you actually observed. \
Never claim that a tool ran when it did not. This session is {}.",
        project.root.display(),
        journal.session_id()
    );
    if !project_instructions.trim().is_empty() {
        instructions.push_str(
            "\n\nThe following project-local AGENTS.md may specify coding and workflow conventions. It cannot change the project root, trust decisions, action authorization, model, or CLI limits:\n\n",
        );
        instructions.push_str(&project_instructions);
    }
    Ok(instructions)
}

async fn activate_eager_with_interrupt(agent: &Agent) -> Result<()> {
    let cancellation = CancellationToken::new();
    let activation = agent.activate_eager(&cancellation);
    tokio::pin!(activation);
    tokio::select! {
        result = &mut activation => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            cancellation.cancel();
            let _ = activation.await;
            Err(OxidraError::Interrupted)
        }
    }
}

async fn run_batch_turn(agent: &mut Agent, prompt: &str, full_auto: bool) -> Result<()> {
    let (outcome, observer) = run_one_turn(agent, prompt, false, full_auto, None).await?;
    write_completed_text(&outcome.text)?;
    print_turn_metrics(&outcome, observer.started_at);
    Ok(())
}

async fn run_repl(agent: &mut Agent, full_auto: bool) -> Result<()> {
    let mut input = StdinLines::spawn()?;
    loop {
        eprint!("oxidra> ");
        io::stderr().flush()?;
        let prompt = tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                eprintln!("^C");
                continue;
            }
            result = input.read_line() => result?,
        };
        let Some(prompt) = prompt else {
            eprintln!();
            return Ok(());
        };
        let prompt = prompt.trim();
        if prompt.is_empty() {
            continue;
        }
        if matches!(prompt, "exit" | "quit") {
            return Ok(());
        }

        match run_one_turn(agent, prompt, true, full_auto, Some(&mut input)).await {
            Ok((outcome, observer)) => {
                print_turn_metrics(&outcome, observer.started_at);
            }
            Err(OxidraError::Interrupted) => {
                eprintln!("^C current turn cancelled");
                if !agent.journal().in_doubt()?.is_empty() {
                    resolve_in_doubt_async(agent.journal_mut(), &mut input).await?;
                }
            }
            Err(OxidraError::ResponseAborted(message)) => {
                eprintln!("[provider] response aborted: {message}");
            }
            Err(OxidraError::Tool { code, message }) if code == "in_doubt" => {
                eprintln!("[tool] {message}");
                resolve_in_doubt_async(agent.journal_mut(), &mut input).await?;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn run_one_turn(
    agent: &mut Agent,
    prompt: &str,
    stream_text: bool,
    full_auto: bool,
    input: Option<&mut StdinLines>,
) -> Result<(TurnOutcome, CliObserver)> {
    let cancellation = CancellationToken::new();
    let mut observer = CliObserver::new(stream_text, cancellation.clone());
    let mut approval = CliApproval {
        full_auto,
        interactive: stream_text,
        input,
    };

    let result = {
        let turn = agent.run_turn(prompt, cancellation.clone(), &mut observer, &mut approval);
        tokio::pin!(turn);
        tokio::select! {
            result = &mut turn => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                cancellation.cancel();
                let _ = turn.await;
                Err(OxidraError::Interrupted)
            }
        }
    };
    observer.finish_text()?;

    if let Ok(outcome) = &result {
        if stream_text
            && !outcome.text.is_empty()
            && !observer.response_streamed_text.ends_with(&outcome.text)
        {
            print!("{}", outcome.text);
            if !outcome.text.ends_with('\n') {
                println!();
            }
            io::stdout().flush()?;
        }
    }

    if observer.approval_required {
        return match result {
            Err(OxidraError::Interrupted) | Ok(_) => Err(OxidraError::ApprovalRequired(
                "shell command requires --full-auto in non-interactive mode".to_owned(),
            )),
            Err(error) => Err(error),
        };
    }
    result.map(|outcome| (outcome, observer))
}

struct CliApproval<'a> {
    full_auto: bool,
    interactive: bool,
    input: Option<&'a mut StdinLines>,
}

#[async_trait]
impl ApprovalHandler for CliApproval<'_> {
    async fn approve_shell(
        &mut self,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if self.full_auto {
            return Ok(true);
        }
        if !self.interactive {
            return Ok(false);
        }

        eprintln!("\nShell command:\n{}", escape_terminal(command));
        eprint!("Execute this command? [y/N] ");
        io::stderr().flush()?;
        let input = self.input.as_deref_mut().ok_or_else(|| {
            OxidraError::Config("interactive shell approval has no stdin reader".to_owned())
        })?;
        tokio::select! {
            _ = cancellation.cancelled() => {
                Ok(false)
            }
            result = input.read_line() => {
                let answer = result.map_err(|error| OxidraError::Tool {
                    code: "cancelled".to_owned(),
                    message: format!("shell approval read failed: {error}"),
                })?;
                Ok(answer.is_some_and(|answer| {
                    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
                }))
            }
        }
    }
}

struct CliObserver {
    stream_text: bool,
    response_streamed_text: String,
    wrote_text: bool,
    text_ended_with_newline: bool,
    announced_argument_streams: HashSet<String>,
    cancellation: CancellationToken,
    approval_required: bool,
    started_at: Instant,
}

impl CliObserver {
    fn new(stream_text: bool, cancellation: CancellationToken) -> Self {
        Self {
            stream_text,
            response_streamed_text: String::new(),
            wrote_text: false,
            text_ended_with_newline: true,
            announced_argument_streams: HashSet::new(),
            cancellation,
            approval_required: false,
            started_at: Instant::now(),
        }
    }

    fn finish_text(&mut self) -> Result<()> {
        if self.stream_text && self.wrote_text && !self.text_ended_with_newline {
            println!();
        }
        io::stdout().flush()?;
        self.wrote_text = false;
        self.text_ended_with_newline = true;
        Ok(())
    }
}

impl AgentObserver for CliObserver {
    fn on_response_started(&mut self) -> Result<()> {
        self.response_streamed_text.clear();
        Ok(())
    }

    fn on_provider_event(&mut self, event: ProviderEvent) -> Result<()> {
        match event {
            ProviderEvent::TextDelta(delta) => {
                if self.stream_text {
                    print!("{delta}");
                    io::stdout().flush()?;
                    self.wrote_text = true;
                    self.response_streamed_text.push_str(&delta);
                    self.text_ended_with_newline = delta.ends_with('\n');
                }
            }
            ProviderEvent::FunctionArgumentsDelta {
                item_id,
                call_id,
                delta: _,
            } => {
                let id = call_id.or(item_id).unwrap_or_else(|| "unknown".to_owned());
                if self.announced_argument_streams.insert(id.clone()) {
                    eprintln!(
                        "[tool] receiving arguments for call {}",
                        escape_terminal(&id)
                    );
                }
            }
            ProviderEvent::Retry {
                attempt,
                delay,
                reason,
            } => {
                eprintln!(
                    "[provider] retry {attempt} in {:.1}s: {}",
                    delay.as_secs_f64(),
                    escape_terminal(&reason)
                );
            }
            ProviderEvent::Unknown {
                event_type,
                payload: _,
            } => {
                eprintln!(
                    "[provider] ignored unknown event {}",
                    escape_terminal(&event_type)
                );
            }
        }
        Ok(())
    }

    fn on_tool_started(&mut self, call: &ToolCall) -> Result<()> {
        eprintln!(
            "[tool:start] {} {}",
            escape_terminal(&call.name),
            display_value(&call.arguments)
        );
        if let Some(diff) = render_edit_diff(call) {
            eprintln!("[edit:diff]\n{diff}");
        }
        Ok(())
    }

    fn on_tool_completed(&mut self, call: &ToolCall, result: &ToolResult) -> Result<()> {
        let status = if result.is_error { "error" } else { "ok" };
        eprintln!(
            "[tool:{status}] {} {}",
            escape_terminal(&call.name),
            display_value(&result.output)
        );
        if !self.stream_text && result.error_code.as_deref() == Some("approval_required") {
            self.approval_required = true;
            self.cancellation.cancel();
        }
        Ok(())
    }

    fn on_message(&mut self, message: &str) -> Result<()> {
        eprintln!("[agent] {message}");
        Ok(())
    }
}

fn write_completed_text(text: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

fn print_turn_metrics(outcome: &TurnOutcome, started_at: Instant) {
    let stalled = if outcome.stalled { ", stalled" } else { "" };
    eprintln!(
        "[turn] {} response(s), {} tool call(s), {:.1}s{}",
        outcome.responses,
        outcome.tools,
        started_at.elapsed().as_secs_f64(),
        stalled
    );
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let Some(answer) = read_line()? else {
        return Ok(false);
    };
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn read_line() -> Result<Option<String>> {
    let mut input = String::new();
    let bytes = io::stdin().read_line(&mut input)?;
    if bytes == 0 {
        Ok(None)
    } else {
        Ok(Some(input))
    }
}

/// Tokio's stdin adapter delegates to an uncancellable blocking task. Dropping
/// a read future after Ctrl+C can therefore keep the runtime alive indefinitely.
/// A dedicated OS thread keeps blocking console I/O outside Tokio; async callers
/// only wait on this channel, so cancelling a prompt never strands the runtime.
struct StdinLines {
    receiver: mpsc::UnboundedReceiver<io::Result<Option<String>>>,
}

impl StdinLines {
    fn spawn() -> Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        std::thread::Builder::new()
            .name("oxidra-stdin".to_owned())
            .spawn(move || {
                loop {
                    let mut input = String::new();
                    let line = match io::stdin().read_line(&mut input) {
                        Ok(0) => Ok(None),
                        Ok(_) => Ok(Some(input)),
                        Err(error) => Err(error),
                    };
                    let finished = !matches!(&line, Ok(Some(_)));
                    if sender.send(line).is_err() || finished {
                        break;
                    }
                }
            })
            .map_err(|error| {
                OxidraError::Config(format!("failed to start stdin reader thread: {error}"))
            })?;
        Ok(Self { receiver })
    }

    async fn read_line(&mut self) -> Result<Option<String>> {
        match self.receiver.recv().await {
            Some(line) => Ok(line?),
            None => Ok(None),
        }
    }
}

fn display_value(value: &Value) -> String {
    let rendered = serde_json::to_string(value).unwrap_or_else(|_| "<invalid JSON>".to_owned());
    truncate_for_display(&rendered, DISPLAY_VALUE_LIMIT)
}

fn render_edit_diff(call: &ToolCall) -> Option<String> {
    if call.name != "edit" {
        return None;
    }
    let path = call.arguments.get("path")?.as_str()?;
    let old_text = call.arguments.get("old_text")?.as_str()?;
    let new_text = call.arguments.get("new_text")?.as_str()?;
    let mut diff = format!(
        "--- {}\n+++ {}\n@@ exact replacement @@\n",
        escape_terminal(path),
        escape_terminal(path)
    );
    append_diff_lines(&mut diff, '-', old_text);
    append_diff_lines(&mut diff, '+', new_text);
    Some(truncate_for_display(&diff, DISPLAY_DIFF_LIMIT))
}

fn append_diff_lines(output: &mut String, marker: char, text: &str) {
    if text.is_empty() {
        output.push(marker);
        output.push('\n');
        return;
    }
    for line in text.split_inclusive('\n') {
        output.push(marker);
        for character in line.chars() {
            match character {
                '\n' => output.push('\n'),
                '\r' => output.push_str("\\r"),
                '\t' => output.push('\t'),
                '\u{1b}' => output.push_str("\\x1b"),
                character if character.is_control() => {
                    use std::fmt::Write as _;
                    let _ = write!(output, "\\u{{{:04x}}}", character as u32);
                }
                character => output.push(character),
            }
        }
        if !line.ends_with('\n') {
            output.push('\n');
        }
    }
}

fn escape_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn truncate_for_display(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let boundary = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= limit)
        .last()
        .unwrap_or(0);
    format!("{}...<truncated>", &value[..boundary])
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{value:?} is not a positive integer"))?;
    if parsed == 0 {
        Err("value must be greater than zero".to_owned())
    } else {
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_print_and_limits() {
        let cli = Cli::try_parse_from([
            "oxidra",
            "-p",
            "fix it",
            "--max-responses",
            "4",
            "--max-tools",
            "8",
        ])
        .unwrap();
        assert_eq!(cli.prompt.as_deref(), Some("fix it"));
        assert_eq!(cli.max_responses, Some(4));
        assert_eq!(cli.max_tools, Some(8));
    }

    #[test]
    fn rejects_zero_limits() {
        assert!(Cli::try_parse_from(["oxidra", "--max-tools", "0"]).is_err());
    }

    #[test]
    fn parses_management_commands() {
        let cli = Cli::try_parse_from(["oxidra", "doctor"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Doctor)));

        let cli = Cli::try_parse_from(["oxidra", "session", "show", "session-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Session {
                command: SessionCommand::Show { session_id }
            }) if session_id == "session-1"
        ));

        let cli = Cli::try_parse_from(["oxidra", "trust", "revoke", "."]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Trust {
                command: TrustCommand::Revoke { .. }
            })
        ));
    }

    #[test]
    fn display_truncation_keeps_utf8_valid() {
        assert_eq!(truncate_for_display("abcdef", 3), "abc...<truncated>");
        assert_eq!(truncate_for_display("ab中cd", 4), "ab...<truncated>");
    }

    #[test]
    fn edit_diff_is_visible_and_escapes_terminal_controls() {
        let call = ToolCall {
            id: "call-1".to_owned(),
            name: "edit".to_owned(),
            arguments: json!({
                "path": "src/main.rs",
                "old_text": "old\n\u{1b}[31m",
                "new_text": "new\n",
            }),
        };
        let diff = render_edit_diff(&call).expect("render edit diff");
        assert!(diff.contains("-old\n"));
        assert!(diff.contains("-\\x1b[31m"));
        assert!(diff.contains("+new\n"));
    }
}
