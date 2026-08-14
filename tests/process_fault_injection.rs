use std::collections::VecDeque;
use std::env;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use oxidra::agent::{Agent, AgentObserver, DenyApproval};
use oxidra::compaction::{
    COMPACTION_ABORTED_KIND, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
    COMPACTION_BOUNDARY_FAILED_KIND, COMPACTION_BOUNDARY_RESOLVED_WITHOUT_CHECKPOINT_KIND,
    COMPACTION_BOUNDARY_RETRY_STARTED_KIND, COMPACTION_BOUNDARY_STARTED_KIND,
    COMPACTION_CHECKPOINT_KIND, COMPACTION_PROMPT_VERSION, COMPACTION_STARTED_KIND,
    CompactionBoundary, CompactionBoundaryFailed, CompactionBoundaryStarted, CompactionCandidate,
    CompactionStarted, MAX_COMPACTION_OUTPUT_TOKENS, SOURCE_DIGEST_VERSION,
    SUMMARY_ENVELOPE_VERSION, USAGE_CONTRACT_VERSION, build_compaction_source, compact_once,
    compaction_instructions, validate_checkpoint_chain, validate_compaction_boundary_chain,
};
use oxidra::config::{ContextLimits, ContextValueSource};
use oxidra::context::AUTOMATIC_COMPACTION_PLANNING_VERSION;
use oxidra::error::Result;
use oxidra::projection::SOURCE_PROJECTION_VERSION;
use oxidra::provider::{ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver};
use oxidra::session::{JOURNAL_SCHEMA, JournalEvent, SessionHeader, SessionJournal, SessionStore};
use oxidra::tools::BuiltinTools;
use oxidra::turn::{
    CompletePrefix, CompletionEvidence, TURN_BOUNDARY_VALIDATOR_VERSION, TURN_BOUNDARY_VERSION,
    TurnState, complete_prefix_candidates, segment_turns,
};
use oxidra::types::{AssistantTurn, ToolCall, ToolResult, Usage};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const CHILD_MODE_ENV: &str = "OXIDRA_FAULT_INJECTION_CHILD";
const DATA_DIR_ENV: &str = "OXIDRA_FAULT_INJECTION_DATA_DIR";
const COMPACTION_SCENARIO_ENV: &str = "OXIDRA_COMPACTION_FAULT_SCENARIO";
const SESSION_ID: &str = "process-fault-session";
const RETRY_SESSION_ID: &str = "retry-fault-session";
const COMPACTION_REPLAN_SESSION_ID: &str = "compaction-replan-fault-session";
const COMPACTION_REPLAN_SYNC_LABEL: &str = "compaction.boundary.retry_started";
const COMPACTION_RESOLUTION_SESSION_ID: &str = "compaction-resolution-fault-session";
const COMPACTION_RESOLUTION_SYNC_LABEL: &str = "compaction.boundary.resolved_without_checkpoint";
const BUDGET_MIGRATION_SESSION_ID: &str = "budget-migration-fault-session";
const BUDGET_MIGRATION_SYNC_LABEL: &str = "compaction.boundary.budget_retry_started";
const PROJECT_ROOT_ENV: &str = "OXIDRA_FAULT_INJECTION_PROJECT_ROOT";
const TURN_ID: &str = "turn-1";
const RESPONSE_ATTEMPT_ID: &str = "attempt-1";
const SYNC_PREFIX: &str = "OXIDRA_FAULT_SYNC:";
const SYNC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncPoint {
    SessionStarted,
    UserMessage,
    ResponseStarted,
    InlineResponseCompleted,
    TurnCompleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetrySyncPoint {
    IntentSynced,
    ResponseStarted,
    TurnCompleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactionSyncPoint {
    Started,
    ProviderCompleted,
    CheckpointSynced,
    CheckpointWithoutNewline,
    CheckpointPartialLine,
}

impl CompactionSyncPoint {
    const ALL: [Self; 5] = [
        Self::Started,
        Self::ProviderCompleted,
        Self::CheckpointSynced,
        Self::CheckpointWithoutNewline,
        Self::CheckpointPartialLine,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Started => "compaction.started",
            Self::ProviderCompleted => "compaction.provider-completed",
            Self::CheckpointSynced => "compaction.checkpoint-synced",
            Self::CheckpointWithoutNewline => "compaction.checkpoint-no-newline",
            Self::CheckpointPartialLine => "compaction.checkpoint-partial-line",
        }
    }

    fn parse(value: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|point| point.label() == value)
            .unwrap_or_else(|| panic!("unknown compaction fault scenario {value:?}"))
    }
}

impl SyncPoint {
    const ALL: [Self; 5] = [
        Self::SessionStarted,
        Self::UserMessage,
        Self::ResponseStarted,
        Self::InlineResponseCompleted,
        Self::TurnCompleted,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::SessionStarted => "session.started",
            Self::UserMessage => "user.message",
            Self::ResponseStarted => "response.started",
            Self::InlineResponseCompleted => "response.completed-inline",
            Self::TurnCompleted => "turn.completed",
        }
    }

    fn persisted_kinds(self) -> &'static [&'static str] {
        match self {
            Self::SessionStarted => &["session.started"],
            Self::UserMessage => &["session.started", "user.message"],
            Self::ResponseStarted => &["session.started", "user.message", "response.started"],
            Self::InlineResponseCompleted => &[
                "session.started",
                "user.message",
                "response.started",
                "response.completed",
            ],
            Self::TurnCompleted => &[
                "session.started",
                "user.message",
                "response.started",
                "response.completed",
                "turn.completed",
            ],
        }
    }
}

impl RetrySyncPoint {
    const ALL: [Self; 3] = [
        Self::IntentSynced,
        Self::ResponseStarted,
        Self::TurnCompleted,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::IntentSynced => "turn.retry_started",
            Self::ResponseStarted => "turn.retry-response-started",
            Self::TurnCompleted => "turn.retry-completed",
        }
    }
}

#[test]
fn force_kill_after_each_synced_turn_boundary_is_recoverable() {
    for sync_point in SyncPoint::ALL {
        let temp = tempfile::tempdir().expect("create fault-injection data directory");
        let child = spawn_fault_child(temp.path());
        stop_child_at(child, sync_point);

        let store = SessionStore::new(temp.path()).expect("open session store after child exit");
        let persisted = store
            .inspect(SESSION_ID)
            .expect("inspect journal before recovery");
        assert_eq!(
            event_kinds(&persisted),
            sync_point.persisted_kinds(),
            "child wrote past {} before it was killed",
            sync_point.label()
        );
        assert_eq!(
            persisted.iter().map(|event| event.seq).collect::<Vec<_>>(),
            (1..=persisted.len() as u64).collect::<Vec<_>>(),
            "persisted sequence is not contiguous after {}",
            sync_point.label()
        );

        let journal = store
            .open(SESSION_ID)
            .expect("recover journal after forced process exit");
        let recovery = journal.recovery_info().clone();
        let recovered = journal.read_events().expect("read recovered journal");
        drop(journal);

        assert_recovered_state(
            sync_point,
            &recovered,
            recovery.aborted_responses,
            recovery.cancelled_turns,
        );
    }
}

#[test]
fn force_kill_during_compaction_commits_only_complete_checkpoints() {
    for sync_point in CompactionSyncPoint::ALL {
        let temp = tempfile::tempdir().expect("create compaction fault data directory");
        let child = spawn_compaction_fault_child(temp.path(), sync_point);
        stop_child_at_label(
            child,
            sync_point.label(),
            &CompactionSyncPoint::ALL.map(CompactionSyncPoint::label),
        );

        let store = SessionStore::new(temp.path()).expect("open store after compaction crash");
        if sync_point != CompactionSyncPoint::CheckpointPartialLine {
            let persisted = store
                .inspect(SESSION_ID)
                .expect("inspect complete compaction journal lines");
            let checkpoint_committed = matches!(
                sync_point,
                CompactionSyncPoint::CheckpointSynced
                    | CompactionSyncPoint::CheckpointWithoutNewline
            );
            let production_path = matches!(
                sync_point,
                CompactionSyncPoint::Started
                    | CompactionSyncPoint::ProviderCompleted
                    | CompactionSyncPoint::CheckpointSynced
            );
            let mut expected = vec!["session.started"];
            for _ in 0..if production_path { 3 } else { 1 } {
                expected.extend(["user.message", "response.completed", "turn.completed"]);
            }
            expected.push(COMPACTION_STARTED_KIND);
            if checkpoint_committed {
                expected.push(COMPACTION_CHECKPOINT_KIND);
            }
            assert_eq!(event_kinds(&persisted), expected, "{}", sync_point.label());
        }

        let journal = store
            .open(SESSION_ID)
            .expect("recover journal after compaction crash");
        let recovery = journal.recovery_info().clone();
        let recovered = journal
            .read_events()
            .expect("read recovered compaction journal");
        drop(journal);

        match sync_point {
            CompactionSyncPoint::Started | CompactionSyncPoint::ProviderCompleted => {
                assert_eq!(recovery.aborted_compactions, 1);
                assert_eq!(count_kind(&recovered, COMPACTION_CHECKPOINT_KIND), 0);
                assert_recovered_compaction_abort(&recovered);
            }
            CompactionSyncPoint::CheckpointSynced
            | CompactionSyncPoint::CheckpointWithoutNewline => {
                assert_eq!(
                    recovery.normalized_missing_newline,
                    sync_point == CompactionSyncPoint::CheckpointWithoutNewline
                );
                assert!(recovery.truncated_tail.is_none());
                assert_eq!(recovery.aborted_compactions, 0);
                assert_eq!(count_kind(&recovered, COMPACTION_CHECKPOINT_KIND), 1);
                assert_eq!(count_kind(&recovered, COMPACTION_ABORTED_KIND), 0);
            }
            CompactionSyncPoint::CheckpointPartialLine => {
                assert!(recovery.truncated_tail.is_some());
                assert_eq!(recovery.aborted_compactions, 1);
                assert_eq!(count_kind(&recovered, COMPACTION_CHECKPOINT_KIND), 0);
                assert_recovered_compaction_abort(&recovered);
            }
        }

        let chain = validate_checkpoint_chain(&recovered)
            .expect("recovered compaction journal has a valid checkpoint chain");
        assert_eq!(
            chain.len(),
            usize::from(matches!(
                sync_point,
                CompactionSyncPoint::CheckpointSynced
                    | CompactionSyncPoint::CheckpointWithoutNewline
            )),
            "only a complete checkpoint may enter the chain at {}",
            sync_point.label()
        );

        let reopened = store
            .open(SESSION_ID)
            .expect("reopen recovered compaction journal");
        assert_eq!(
            count_kind(&reopened.read_events().unwrap(), COMPACTION_ABORTED_KIND),
            usize::from(!matches!(
                sync_point,
                CompactionSyncPoint::CheckpointSynced
                    | CompactionSyncPoint::CheckpointWithoutNewline
            )),
            "recovery must be idempotent at {}",
            sync_point.label()
        );
    }
}

#[test]
fn force_kill_during_retry_preserves_the_original_prompt_and_intent() {
    for sync_point in RetrySyncPoint::ALL {
        let temp = tempfile::tempdir().expect("create retry fault data directory");
        let child = spawn_retry_fault_child(temp.path());
        stop_child_at_label(
            child,
            sync_point.label(),
            &RetrySyncPoint::ALL.map(RetrySyncPoint::label),
        );

        let store = SessionStore::new(temp.path()).expect("open retry fault store");
        let persisted = store
            .inspect(RETRY_SESSION_ID)
            .expect("inspect retry journal before recovery");
        assert_eq!(count_kind(&persisted, "user.message"), 1);
        assert_eq!(count_kind(&persisted, "turn.retry_started"), 1);
        assert_eq!(count_kind(&persisted, "turn.abandoned"), 0);

        let journal = store
            .open(RETRY_SESSION_ID)
            .expect("recover retry journal after forced exit");
        let recovery = journal.recovery_info().clone();
        let recovered = journal.read_events().expect("read recovered retry journal");
        drop(journal);

        match sync_point {
            RetrySyncPoint::IntentSynced => {
                assert_eq!(recovery.aborted_responses, 0);
                assert_eq!(count_kind(&recovered, "response.started"), 0);
                assert_eq!(count_kind(&recovered, "turn.completed"), 0);
            }
            RetrySyncPoint::ResponseStarted => {
                assert_eq!(recovery.aborted_responses, 1);
                assert_eq!(count_kind(&recovered, "response.aborted"), 1);
                assert_eq!(count_kind(&recovered, "turn.completed"), 0);
            }
            RetrySyncPoint::TurnCompleted => {
                assert_eq!(recovery.aborted_responses, 0);
                assert_eq!(count_kind(&recovered, "turn.completed"), 1);
                assert!(matches!(
                    segment_turns(&recovered)
                        .expect("segment completed retry")
                        .last()
                        .map(|turn| turn.state),
                    Some(TurnState::Complete(_))
                ));
            }
        }
    }
}

#[test]
fn force_kill_after_compaction_recovery_intent_can_retry_after_reopen() {
    let temp = tempfile::tempdir().expect("create compaction replan fault data directory");
    let child = spawn_compaction_replan_fault_child(temp.path());
    stop_child_at_label(
        child,
        COMPACTION_REPLAN_SYNC_LABEL,
        &[COMPACTION_REPLAN_SYNC_LABEL],
    );

    let store = SessionStore::new(temp.path()).expect("open compaction replan fault store");
    let persisted = store
        .inspect(COMPACTION_REPLAN_SESSION_ID)
        .expect("inspect compaction replan journal before recovery");
    assert_eq!(count_kind(&persisted, "user.message"), 7);
    assert_eq!(count_kind(&persisted, COMPACTION_BOUNDARY_STARTED_KIND), 1);
    assert_eq!(
        count_kind(&persisted, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
        1
    );
    assert_eq!(count_kind(&persisted, COMPACTION_BOUNDARY_FAILED_KIND), 1);
    assert_eq!(count_kind(&persisted, COMPACTION_STARTED_KIND), 0);

    let journal = store
        .open(COMPACTION_REPLAN_SESSION_ID)
        .expect("recover replacement compaction boundary after forced exit");
    let recovered = journal
        .read_events()
        .expect("read recovered compaction replan journal");
    assert_eq!(count_kind(&recovered, COMPACTION_BOUNDARY_FAILED_KIND), 2);
    let recovered_chain = validate_compaction_boundary_chain(&recovered)
        .expect("recovered boundary lineage remains valid");
    assert_eq!(recovered_chain.pending().len(), 1);
    assert_eq!(
        recovered_chain.pending()[0].state,
        oxidra::compaction::CompactionBoundaryState::Failed
    );

    let project_root = temp.path().join("project");
    let tools = BuiltinTools::new(
        &project_root,
        journal.artifact_dir(),
        temp.path().join("memory"),
        false,
        false,
    )
    .expect("create recovery tools");
    let provider = std::sync::Arc::new(RecoveryProvider::new([
        recovery_compaction_summary(),
        recovery_final_turn(),
    ]));
    let mut agent = Agent::new(
        provider.clone(),
        journal,
        tools,
        "fault recovery instructions",
        compaction_replan_context_limits(),
        None,
        None,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create recovery runtime");
    let outcome = runtime
        .block_on(agent.retry_pending_turn(
            CancellationToken::new(),
            &mut NoopAgentObserver,
            &mut DenyApproval,
        ))
        .expect("retry recovered compaction boundary");
    assert_eq!(outcome.text, "recovered answer");
    assert_eq!(provider.requests().len(), 2);
    assert_eq!(provider.requests()[0].max_output_tokens, Some(8_192));
    assert_eq!(provider.requests()[1].max_output_tokens, None);

    let completed = agent
        .journal()
        .read_events()
        .expect("read completed compaction replan journal");
    assert_eq!(count_kind(&completed, "user.message"), 7);
    assert_eq!(
        count_kind(&completed, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
        2
    );
    assert_eq!(count_kind(&completed, COMPACTION_STARTED_KIND), 1);
    assert_eq!(count_kind(&completed, COMPACTION_CHECKPOINT_KIND), 1);
    assert!(
        validate_compaction_boundary_chain(&completed)
            .expect("completed recovery boundary chain is valid")
            .pending()
            .is_empty()
    );
}

#[test]
fn force_kill_after_no_checkpoint_resolution_resumes_via_cli() {
    let temp = tempfile::tempdir().expect("create compaction resolution fault directory");
    let project_root = temp.path().join("project");
    std::fs::create_dir_all(&project_root).expect("create compaction resolution project root");
    let data_dir = isolated_cli_data_dir(temp.path());
    let child = spawn_compaction_resolution_fault_child(&data_dir, &project_root);
    stop_child_at_label(
        child,
        COMPACTION_RESOLUTION_SYNC_LABEL,
        &[COMPACTION_RESOLUTION_SYNC_LABEL],
    );

    let store = SessionStore::new(&data_dir).expect("open compaction resolution fault store");
    let persisted = store
        .inspect(COMPACTION_RESOLUTION_SESSION_ID)
        .expect("inspect synced no-checkpoint resolution before CLI resume");
    assert_eq!(
        count_kind(&persisted, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
        1
    );
    assert_eq!(
        count_kind(
            &persisted,
            COMPACTION_BOUNDARY_RESOLVED_WITHOUT_CHECKPOINT_KIND
        ),
        1
    );
    assert_eq!(count_kind(&persisted, COMPACTION_STARTED_KIND), 0);
    assert_eq!(count_kind(&persisted, COMPACTION_CHECKPOINT_KIND), 0);
    assert_eq!(count_kind(&persisted, "response.started"), 0);
    let persisted_chain = validate_compaction_boundary_chain(&persisted)
        .expect("synced no-checkpoint resolution has a valid boundary lineage");
    assert_eq!(persisted_chain.pending().len(), 1);
    assert_eq!(
        persisted_chain.pending()[0].state,
        oxidra::compaction::CompactionBoundaryState::ResolvedWithoutCheckpoint
    );

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind no-checkpoint resume server");
    let address = listener
        .local_addr()
        .expect("read no-checkpoint resume server address");
    let server =
        thread::spawn(move || serve_one_final_response(listener, "resumed without a checkpoint"));

    let local_data = temp.path().join("local");
    let roaming_data = temp.path().join("roaming");
    let xdg_config = temp.path().join("config");
    let xdg_state = temp.path().join("state");
    let home = temp.path().join("home");
    for directory in [&local_data, &roaming_data, &xdg_config, &xdg_state, &home] {
        std::fs::create_dir_all(directory).expect("create isolated CLI directory");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_oxidra"))
        .arg("--resume")
        .arg(COMPACTION_RESOLUTION_SESSION_ID)
        .arg("--retry-pending")
        .arg("--cwd")
        .arg(&project_root)
        .env("API_KEY", "fake")
        .env("API_BASE_URL", format!("http://{address}/v1/"))
        .env("MODEL", "fault-injection-model")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OPENAI_MODEL")
        .env("LOCALAPPDATA", &local_data)
        .env("APPDATA", &roaming_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_STATE_HOME", &xdg_state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("resume no-checkpoint resolution through the CLI");

    let stdout = String::from_utf8(output.stdout).expect("CLI stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    let server_result = server.join().expect("no-checkpoint resume server panicked");
    assert!(
        output.status.success(),
        "CLI resume failed with {}\nstdout:\n{}\nstderr:\n{}\nserver: {:?}",
        output.status,
        stdout,
        stderr,
        server_result
    );
    let request = server_result.expect("no-checkpoint resume server failed");
    assert_eq!(
        stdout.replace("\r\n", "\n"),
        "resumed without a checkpoint\n"
    );
    let request_input =
        serde_json::to_string(&request["input"]).expect("serialize resumed Provider input");
    assert!(request_input.contains("retry compaction after config change"));

    let completed = store
        .inspect(COMPACTION_RESOLUTION_SESSION_ID)
        .expect("inspect completed no-checkpoint recovery");
    assert_eq!(
        count_kind(
            &completed,
            COMPACTION_BOUNDARY_RESOLVED_WITHOUT_CHECKPOINT_KIND
        ),
        1,
        "CLI resume must reuse the durable no-checkpoint resolution"
    );
    assert_eq!(count_kind(&completed, COMPACTION_STARTED_KIND), 0);
    assert_eq!(count_kind(&completed, COMPACTION_CHECKPOINT_KIND), 0);
    assert_eq!(count_kind(&completed, "response.started"), 1);
    assert!(
        validate_compaction_boundary_chain(&completed)
            .expect("completed no-checkpoint recovery has a valid boundary lineage")
            .pending()
            .is_empty()
    );
}

#[test]
fn force_kill_after_budget_migration_sync_resumes_via_cli() {
    let temp = tempfile::tempdir().expect("create budget migration fault directory");
    let project_root = temp.path().join("project");
    std::fs::create_dir_all(&project_root).expect("create budget migration project root");
    let data_dir = isolated_cli_data_dir(temp.path());
    let child = spawn_budget_migration_fault_child(&data_dir, &project_root);
    stop_child_at_label(
        child,
        BUDGET_MIGRATION_SYNC_LABEL,
        &[BUDGET_MIGRATION_SYNC_LABEL],
    );

    let store = SessionStore::new(&data_dir).expect("open budget migration fault store");
    let persisted = store
        .inspect(BUDGET_MIGRATION_SESSION_ID)
        .expect("inspect synced budget migration before CLI resume");
    assert_eq!(
        count_kind(&persisted, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND),
        1
    );
    assert_eq!(count_kind(&persisted, "response.started"), 0);
    let persisted_chain = validate_compaction_boundary_chain(&persisted)
        .expect("synced migration has a valid boundary lineage");
    assert_eq!(persisted_chain.pending().len(), 1);
    assert_eq!(persisted_chain.pending()[0].boundary.version, 4);

    let listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("bind budget migration resume server");
    let address = listener
        .local_addr()
        .expect("read budget migration resume server address");
    let server = thread::spawn(move || {
        serve_one_final_response(listener, "resumed after forced migration crash")
    });

    let local_data = temp.path().join("local");
    let roaming_data = temp.path().join("roaming");
    let xdg_config = temp.path().join("config");
    let xdg_state = temp.path().join("state");
    let home = temp.path().join("home");
    for directory in [&local_data, &roaming_data, &xdg_config, &xdg_state, &home] {
        std::fs::create_dir_all(directory).expect("create isolated CLI directory");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_oxidra"))
        .arg("--resume")
        .arg(BUDGET_MIGRATION_SESSION_ID)
        .arg("--retry-pending")
        .arg("--max-responses")
        .arg("2")
        .arg("--cwd")
        .arg(&project_root)
        .env("API_KEY", "fake")
        .env("API_BASE_URL", format!("http://{address}/v1/"))
        .env("MODEL", "test-model")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OPENAI_MODEL")
        .env("LOCALAPPDATA", &local_data)
        .env("APPDATA", &roaming_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_STATE_HOME", &xdg_state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("resume budget migration through the CLI");

    let stdout = String::from_utf8(output.stdout).expect("CLI stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    let server_result = server
        .join()
        .expect("budget migration resume server panicked");
    assert!(
        output.status.success(),
        "CLI resume failed with {}\nstdout:\n{}\nstderr:\n{}\nserver: {:?}",
        output.status,
        stdout,
        stderr,
        server_result
    );
    let request = server_result.expect("budget migration resume server failed");
    assert_eq!(
        stdout.replace("\r\n", "\n"),
        "resumed after forced migration crash\n"
    );
    let request_input =
        serde_json::to_string(&request["input"]).expect("serialize resumed Provider input");
    assert!(request_input.contains("summary v2"));
    assert!(request_input.contains("prompt"));

    let completed = store
        .inspect(BUDGET_MIGRATION_SESSION_ID)
        .expect("inspect completed CLI recovery");
    assert_eq!(
        count_kind(&completed, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND),
        1,
        "CLI resume must not duplicate the durable migration intent"
    );
    assert_eq!(count_kind(&completed, "user.message"), 2);
    assert_eq!(count_kind(&completed, "response.started"), 1);
    assert!(
        validate_compaction_boundary_chain(&completed)
            .expect("completed CLI recovery has a valid boundary lineage")
            .pending()
            .is_empty()
    );
    assert!(matches!(
        segment_turns(&completed)
            .expect("segment completed CLI recovery")
            .last()
            .map(|turn| turn.state),
        Some(TurnState::Complete(_))
    ));
}

// This ignored test is a helper process, not a standalone test. The parent
// launches this same integration-test binary and kills it while a synced
// journal writer is deliberately blocked on stdin.
#[test]
#[ignore = "launched by force_kill_after_each_synced_turn_boundary_is_recoverable"]
fn fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let data_dir = env::var_os(DATA_DIR_ENV).expect("fault child data directory is set");
    let store = SessionStore::new(&data_dir).expect("create child session store");
    let mut journal = store
        .create_with_id(
            SESSION_ID,
            SessionHeader::new(&data_dir, "fault-injection-model"),
        )
        .expect("create child journal");
    sync_barrier(SyncPoint::SessionStarted);

    let user = journal
        .append_and_sync(
            "user.message",
            Some(TURN_ID),
            json!({
                "item": {"role": "user", "content": "test a crash boundary"},
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append user message");
    sync_barrier(SyncPoint::UserMessage);

    journal
        .append_and_sync(
            "response.started",
            Some(TURN_ID),
            json!({
                "response_attempt_id": RESPONSE_ATTEMPT_ID,
                "response_index": 1,
            }),
        )
        .expect("append response start");
    sync_barrier(SyncPoint::ResponseStarted);

    let response_seq = journal.next_seq();
    let response = journal
        .append_and_sync(
            "response.completed",
            Some(TURN_ID),
            json!({
                "response_attempt_id": RESPONSE_ATTEMPT_ID,
                "raw_response": {"id": "response-1", "output": []},
                "output_items": [],
                "text": "done",
                "turn_completion": {
                    "turn_boundary_version": TURN_BOUNDARY_VERSION,
                    "covers_from_seq": user.seq,
                    "final_response_seq": response_seq,
                    "covers_through_seq": response_seq,
                },
            }),
        )
        .expect("append inline response completion");
    assert_eq!(response.seq, response_seq);
    sync_barrier(SyncPoint::InlineResponseCompleted);

    let marker_seq = journal.next_seq();
    journal
        .append_and_sync(
            "turn.completed",
            Some(TURN_ID),
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": user.seq,
                "final_response_seq": response.seq,
                "covers_through_seq": marker_seq,
            }),
        )
        .expect("append turn completion marker");
    sync_barrier(SyncPoint::TurnCompleted);
}

// 该 helper 由父测试启动，并在 retry 的已同步边界上被强制终止。
#[test]
#[ignore = "launched by force_kill_during_retry_preserves_the_original_prompt_and_intent"]
fn retry_fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let data_dir = env::var_os(DATA_DIR_ENV).expect("retry fault child data directory is set");
    let store = SessionStore::new(&data_dir).expect("create retry child session store");
    let mut journal = store
        .create_with_id(
            RETRY_SESSION_ID,
            SessionHeader::new(&data_dir, "fault-injection-model"),
        )
        .expect("create retry child journal");
    let user = journal
        .append_and_sync(
            "user.message",
            Some(TURN_ID),
            json!({
                "item":{"role":"user","content":"retry after context limit"},
                "turn_boundary_version":TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append retry user message");
    journal
        .append_and_sync(
            "response.failed",
            Some(TURN_ID),
            json!({
                "response_attempt_id":"initial-context-limit",
                "error":"context_length_exceeded",
            }),
        )
        .expect("append initial context failure");
    let limit = journal
        .append_and_sync(
            "context.limit_reached",
            Some(TURN_ID),
            json!({"error":"context_length_exceeded"}),
        )
        .expect("append initial context limit");
    journal
        .append_and_sync(
            "turn.retry_started",
            Some(TURN_ID),
            json!({
                "retry_version":1,
                "retry_id":"fault-retry",
                "user_message_seq":user.seq,
                "context_limit_seq":limit.seq,
            }),
        )
        .expect("append retry intent");
    sync_barrier_label(RetrySyncPoint::IntentSynced.label());

    journal
        .append_and_sync(
            "response.started",
            Some(TURN_ID),
            json!({
                "response_attempt_id":"retry-attempt",
                "response_index":1,
            }),
        )
        .expect("append retry response start");
    sync_barrier_label(RetrySyncPoint::ResponseStarted.label());

    let response_seq = journal.next_seq();
    let response = journal
        .append_and_sync(
            "response.completed",
            Some(TURN_ID),
            json!({
                "response_attempt_id":"retry-attempt",
                "raw_response":{"id":"retry-response","output":[]},
                "output_items":[],
                "text":"done",
                "turn_completion":{
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                    "covers_from_seq":user.seq,
                    "final_response_seq":response_seq,
                    "covers_through_seq":response_seq,
                },
            }),
        )
        .expect("append retry response completion");
    let marker_seq = journal.next_seq();
    journal
        .append_and_sync(
            "turn.completed",
            Some(TURN_ID),
            json!({
                "turn_boundary_version":TURN_BOUNDARY_VERSION,
                "covers_from_seq":user.seq,
                "final_response_seq":response.seq,
                "covers_through_seq":marker_seq,
            }),
        )
        .expect("append retry completion marker");
    sync_barrier_label(RetrySyncPoint::TurnCompleted.label());
}

#[test]
#[ignore = "launched by force_kill_after_budget_migration_sync_resumes_via_cli"]
fn budget_migration_fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let data_dir = PathBuf::from(
        env::var_os(DATA_DIR_ENV).expect("budget migration child data directory is set"),
    );
    let project_root = PathBuf::from(
        env::var_os(PROJECT_ROOT_ENV).expect("budget migration child project root is set"),
    );
    let project_root = std::fs::canonicalize(&project_root)
        .expect("canonicalize budget migration child project root");
    let fixture = include_str!("fixtures/checkpointed_budget_limit_55e5b0c.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<JournalEvent>(line).expect("literal 55e5b0c JSONL"))
        .collect::<Vec<_>>();
    let store = SessionStore::new(&data_dir).expect("create budget migration child store");
    let mut journal = store
        .create_with_id(
            BUDGET_MIGRATION_SESSION_ID,
            SessionHeader::new(&project_root, "test-model"),
        )
        .expect("create budget migration child journal");
    for event in fixture.into_iter().skip(1) {
        journal
            .append_and_sync(&event.kind, event.turn_id.as_deref(), event.data)
            .expect("append literal legacy budget event");
    }
    let tools = BuiltinTools::new(
        &project_root,
        journal.artifact_dir(),
        data_dir.join("memory"),
        false,
        false,
    )
    .expect("create budget migration child tools");
    let mut agent = Agent::new(
        std::sync::Arc::new(UnexpectedRecoveryProvider),
        journal,
        tools,
        "instructions",
        ContextLimits::default(),
        Some(2),
        None,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create budget migration child runtime");
    let error = runtime
        .block_on(agent.retry_pending_turn(
            CancellationToken::new(),
            &mut BudgetMigrationSyncObserver,
            &mut DenyApproval,
        ))
        .expect_err("parent should kill the child after migration fsync");
    panic!("budget migration child unexpectedly resumed: {error}");
}

#[test]
#[ignore = "launched by force_kill_after_compaction_recovery_intent_can_retry_after_reopen"]
fn compaction_replan_fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let data_dir = env::var_os(DATA_DIR_ENV).expect("compaction replan data directory is set");
    let project_root = Path::new(&data_dir).join("project");
    std::fs::create_dir_all(&project_root).expect("create compaction replan project root");
    let store = SessionStore::new(&data_dir).expect("create compaction replan child store");
    let mut journal = store
        .create_with_id(
            COMPACTION_REPLAN_SESSION_ID,
            SessionHeader::new(&project_root, "fault-injection-model"),
        )
        .expect("create compaction replan child journal");
    for index in 0..6 {
        append_large_replan_turn(&mut journal, index);
    }
    let user = journal
        .append_and_sync(
            "user.message",
            Some(TURN_ID),
            json!({
                "item":{"role":"user","content":"retry compaction after a crash"},
                "turn_boundary_version":TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append compaction replan user message");
    let boundary = CompactionBoundary::new("initial-replan-boundary", TURN_ID, user.seq);
    let extra = json!({
        "planning_version": AUTOMATIC_COMPACTION_PLANNING_VERSION,
        "context": planning_context_v1(user.seq),
    })
    .as_object()
    .expect("planning extra is an object")
    .clone();
    journal
        .append_and_sync(
            COMPACTION_BOUNDARY_STARTED_KIND,
            None,
            serde_json::to_value(CompactionBoundaryStarted {
                boundary: boundary.clone(),
                trigger: "estimated_context_threshold".to_owned(),
                extra,
            })
            .expect("encode initial compaction boundary"),
        )
        .expect("append initial compaction boundary");
    journal
        .append_and_sync(
            COMPACTION_BOUNDARY_FAILED_KIND,
            None,
            serde_json::to_value(CompactionBoundaryFailed {
                boundary_id: boundary.boundary_id,
                code: "cancelled".to_owned(),
                message: "injected preflight-only failure".to_owned(),
                attempt_id: None,
                extra: Default::default(),
            })
            .expect("encode initial compaction boundary failure"),
        )
        .expect("append initial compaction boundary failure");

    let tools = BuiltinTools::new(
        &project_root,
        journal.artifact_dir(),
        Path::new(&data_dir).join("memory"),
        false,
        false,
    )
    .expect("create compaction replan child tools");
    let mut agent = Agent::new(
        std::sync::Arc::new(UnexpectedRecoveryProvider),
        journal,
        tools,
        "fault recovery instructions",
        compaction_replan_context_limits(),
        None,
        None,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create compaction replan child runtime");
    let error = runtime
        .block_on(agent.retry_pending_turn(
            CancellationToken::new(),
            &mut CompactionRecoverySyncObserver,
            &mut DenyApproval,
        ))
        .expect_err("parent should kill the child at the durable retry intent");
    panic!("compaction replan child unexpectedly resumed: {error}");
}

#[test]
#[ignore = "launched by force_kill_after_no_checkpoint_resolution_resumes_via_cli"]
fn compaction_resolution_fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let data_dir = env::var_os(DATA_DIR_ENV).expect("compaction resolution data directory is set");
    let project_root = env::var_os(PROJECT_ROOT_ENV)
        .map(PathBuf::from)
        .expect("compaction resolution project root is set");
    std::fs::create_dir_all(&project_root).expect("create compaction resolution project root");
    let project_root = std::fs::canonicalize(&project_root)
        .expect("canonicalize compaction resolution project root");
    let store = SessionStore::new(&data_dir).expect("create compaction resolution child store");
    let mut journal = store
        .create_with_id(
            COMPACTION_RESOLUTION_SESSION_ID,
            SessionHeader::new(&project_root, "fault-injection-model"),
        )
        .expect("create compaction resolution child journal");
    for index in 0..3 {
        append_large_replan_turn(&mut journal, index);
    }
    let user = journal
        .append_and_sync(
            "user.message",
            Some(TURN_ID),
            json!({
                "item":{"role":"user","content":"retry compaction after config change"},
                "turn_boundary_version":TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append compaction resolution user message");
    let boundary = CompactionBoundary::new("initial-resolution-boundary", TURN_ID, user.seq);
    let extra = json!({
        "planning_version": AUTOMATIC_COMPACTION_PLANNING_VERSION,
        "context": planning_context_v1(user.seq),
    })
    .as_object()
    .expect("planning extra is an object")
    .clone();
    journal
        .append_and_sync(
            COMPACTION_BOUNDARY_STARTED_KIND,
            None,
            serde_json::to_value(CompactionBoundaryStarted {
                boundary: boundary.clone(),
                trigger: "estimated_context_threshold".to_owned(),
                extra,
            })
            .expect("encode initial compaction resolution boundary"),
        )
        .expect("append initial compaction resolution boundary");
    journal
        .append_and_sync(
            COMPACTION_BOUNDARY_FAILED_KIND,
            None,
            serde_json::to_value(CompactionBoundaryFailed {
                boundary_id: boundary.boundary_id,
                code: "cancelled".to_owned(),
                message: "injected preflight-only failure".to_owned(),
                attempt_id: None,
                extra: Default::default(),
            })
            .expect("encode initial compaction resolution failure"),
        )
        .expect("append initial compaction resolution failure");

    let tools = BuiltinTools::new(
        &project_root,
        journal.artifact_dir(),
        Path::new(&data_dir).join("memory"),
        false,
        false,
    )
    .expect("create compaction resolution child tools");
    let mut agent = Agent::new(
        std::sync::Arc::new(UnexpectedRecoveryProvider),
        journal,
        tools,
        "fault recovery instructions",
        ContextLimits {
            context_window: Some(10_000_000),
            reserve_tokens: 0,
            context_window_source: ContextValueSource::Cli,
            reserve_tokens_source: ContextValueSource::Cli,
        },
        None,
        None,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create compaction resolution child runtime");
    let error = runtime
        .block_on(agent.retry_pending_turn(
            CancellationToken::new(),
            &mut CompactionResolutionSyncObserver,
            &mut DenyApproval,
        ))
        .expect_err("parent should kill the child after resolution fsync");
    panic!("compaction resolution child unexpectedly resumed: {error}");
}

struct CompactionRecoverySyncObserver;

struct CompactionResolutionSyncObserver;

struct BudgetMigrationSyncObserver;

impl AgentObserver for BudgetMigrationSyncObserver {
    fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }

    fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
        Ok(())
    }

    fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
        Ok(())
    }

    fn on_message(&mut self, _message: &str) -> Result<()> {
        Ok(())
    }

    fn on_compaction_budget_recovery_intent_synced(&mut self) -> Result<()> {
        sync_barrier_label(BUDGET_MIGRATION_SYNC_LABEL);
        Ok(())
    }
}

impl AgentObserver for CompactionRecoverySyncObserver {
    fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }

    fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
        Ok(())
    }

    fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
        Ok(())
    }

    fn on_message(&mut self, _message: &str) -> Result<()> {
        Ok(())
    }

    fn on_compaction_recovery_intent_synced(&mut self) -> Result<()> {
        sync_barrier_label(COMPACTION_REPLAN_SYNC_LABEL);
        Ok(())
    }
}

impl AgentObserver for CompactionResolutionSyncObserver {
    fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }

    fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
        Ok(())
    }

    fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
        Ok(())
    }

    fn on_message(&mut self, _message: &str) -> Result<()> {
        Ok(())
    }

    fn on_compaction_resolution_synced(&mut self) -> Result<()> {
        sync_barrier_label(COMPACTION_RESOLUTION_SYNC_LABEL);
        Ok(())
    }
}

struct NoopAgentObserver;

impl AgentObserver for NoopAgentObserver {
    fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }

    fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
        Ok(())
    }

    fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
        Ok(())
    }

    fn on_message(&mut self, _message: &str) -> Result<()> {
        Ok(())
    }
}

struct UnexpectedRecoveryProvider;

#[async_trait]
impl ResponseProvider for UnexpectedRecoveryProvider {
    async fn respond(
        &self,
        _request: ResponseRequest,
        _observer: &mut dyn StreamObserver,
        _cancellation: CancellationToken,
    ) -> Result<AssistantTurn> {
        panic!("Provider dispatch occurred before the recovery intent sync hook")
    }
}

struct RecoveryProvider {
    responses: Mutex<VecDeque<AssistantTurn>>,
    requests: Mutex<Vec<ResponseRequest>>,
}

impl RecoveryProvider {
    fn new(responses: impl IntoIterator<Item = AssistantTurn>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ResponseRequest> {
        self.requests
            .lock()
            .expect("lock recovery requests")
            .clone()
    }
}

#[async_trait]
impl ResponseProvider for RecoveryProvider {
    async fn respond(
        &self,
        request: ResponseRequest,
        _observer: &mut dyn StreamObserver,
        _cancellation: CancellationToken,
    ) -> Result<AssistantTurn> {
        self.requests
            .lock()
            .expect("lock recovery requests")
            .push(request);
        Ok(self
            .responses
            .lock()
            .expect("lock recovery responses")
            .pop_front()
            .expect("scripted recovery response"))
    }
}

struct FaultCompactionProvider {
    scenario: CompactionSyncPoint,
}

#[async_trait]
impl ResponseProvider for FaultCompactionProvider {
    async fn respond(
        &self,
        request: ResponseRequest,
        _observer: &mut dyn StreamObserver,
        _cancellation: CancellationToken,
    ) -> Result<AssistantTurn> {
        assert!(request.tools.is_empty());
        assert_eq!(
            request.max_output_tokens,
            Some(MAX_COMPACTION_OUTPUT_TOKENS)
        );
        if self.scenario == CompactionSyncPoint::Started {
            sync_barrier_label(self.scenario.label());
        }
        let output_items = vec![json!({
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "fault-injection summary"}],
        })];
        Ok(AssistantTurn {
            raw_response: json!({
                "id": "fault-injection-compaction-response",
                "status": "completed",
                "output": output_items,
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "total_tokens": 120,
                },
            }),
            output_items,
            text: "fault-injection summary".to_owned(),
            tool_calls: Vec::new(),
            usage: Usage {
                input_tokens: 100,
                output_tokens: 20,
                total_tokens: 120,
                ..Usage::default()
            },
            unknown_stream_events: Vec::new(),
        })
    }
}

struct NoopStreamObserver;

impl StreamObserver for NoopStreamObserver {
    fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "launched by force_kill_during_compaction_commits_only_complete_checkpoints"]
fn compaction_fault_injection_child() {
    if env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let scenario = CompactionSyncPoint::parse(
        &env::var(COMPACTION_SCENARIO_ENV).expect("compaction fault scenario is set"),
    );
    let data_dir = env::var_os(DATA_DIR_ENV).expect("fault child data directory is set");
    let store = SessionStore::new(&data_dir).expect("create child session store");
    let mut journal = store
        .create_with_id(
            SESSION_ID,
            SessionHeader::new(&data_dir, "fault-injection-model"),
        )
        .expect("create child journal");
    let marker = append_completed_compaction_turn(&mut journal, TURN_ID, 1);
    let production_path = matches!(
        scenario,
        CompactionSyncPoint::Started
            | CompactionSyncPoint::ProviderCompleted
            | CompactionSyncPoint::CheckpointSynced
    );
    if production_path {
        append_completed_compaction_turn(&mut journal, "turn-2", 2);
        append_completed_compaction_turn(&mut journal, "turn-3", 3);
    }
    let source = build_compaction_source(
        &journal
            .read_events()
            .expect("read compaction fixture events"),
        None,
        marker.seq,
    )
    .expect("build compaction fixture source");
    let source_digest = source.digest().expect("digest compaction fixture source");

    if production_path {
        let candidate = CompactionCandidate {
            parent_checkpoint_id: None,
            covers_through_seq: marker.seq,
            newly_compacted_complete_turns: 1,
            estimated_input_tokens_after: 40,
            prompt_version: COMPACTION_PROMPT_VERSION,
            summary_envelope_version: SUMMARY_ENVELOPE_VERSION,
            source_projection_version: SOURCE_PROJECTION_VERSION,
            turn_boundary_validator_version: TURN_BOUNDARY_VALIDATOR_VERSION,
            source_digest_version: SOURCE_DIGEST_VERSION,
            usage_contract_version: USAGE_CONTRACT_VERSION,
            source,
            source_digest,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create compaction fault runtime");
        let provider = FaultCompactionProvider { scenario };
        let checkpoint = runtime
            .block_on(compact_once(
                &provider,
                &mut journal,
                &candidate,
                "fault-injection-model",
                &mut NoopStreamObserver,
                CancellationToken::new(),
                |summary| {
                    assert_eq!(summary, "fault-injection summary");
                    if scenario == CompactionSyncPoint::ProviderCompleted {
                        sync_barrier_label(scenario.label());
                    }
                    Ok(())
                },
            ))
            .expect("complete production compaction attempt");
        assert_eq!(checkpoint.covers_through_seq, marker.seq);
        if scenario == CompactionSyncPoint::CheckpointSynced {
            sync_barrier_label(scenario.label());
        }
        return;
    }

    journal
        .append_and_sync(
            COMPACTION_STARTED_KIND,
            None,
            serde_json::to_value(CompactionStarted {
                attempt_id: "compaction-attempt-1".to_owned(),
                parent_checkpoint_id: None,
                covers_through_seq: marker.seq,
                source,
                source_digest: source_digest.clone(),
                instructions: compaction_instructions(COMPACTION_PROMPT_VERSION)
                    .expect("current prompt is registered")
                    .to_owned(),
                prompt_version: COMPACTION_PROMPT_VERSION,
                summary_envelope_version: SUMMARY_ENVELOPE_VERSION,
                source_projection_version: SOURCE_PROJECTION_VERSION,
                turn_boundary_validator_version: TURN_BOUNDARY_VALIDATOR_VERSION,
                source_digest_version: SOURCE_DIGEST_VERSION,
                usage_contract_version: USAGE_CONTRACT_VERSION,
                model: "fault-injection-model".to_owned(),
                extra: Default::default(),
            })
            .expect("encode compaction fixture start"),
        )
        .expect("append compaction start");

    match scenario {
        CompactionSyncPoint::CheckpointWithoutNewline => {
            append_raw_checkpoint(
                journal.journal_path(),
                journal.next_seq(),
                marker.seq,
                &source_digest,
                false,
            );
            sync_barrier_label(scenario.label());
        }
        CompactionSyncPoint::CheckpointPartialLine => {
            append_raw_checkpoint(
                journal.journal_path(),
                journal.next_seq(),
                marker.seq,
                &source_digest,
                true,
            );
            sync_barrier_label(scenario.label());
        }
        CompactionSyncPoint::Started
        | CompactionSyncPoint::ProviderCompleted
        | CompactionSyncPoint::CheckpointSynced => unreachable!("production path returned above"),
    }
}

fn append_completed_compaction_turn(
    journal: &mut SessionJournal,
    turn_id: &str,
    index: usize,
) -> JournalEvent {
    let user = journal
        .append_and_sync(
            "user.message",
            Some(turn_id),
            json!({
                "item": {"role": "user", "content": format!("compact turn {index}")},
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append compaction fixture user message");
    let response_seq = journal.next_seq();
    let response = journal
        .append_and_sync(
            "response.completed",
            Some(turn_id),
            json!({
                "response_attempt_id": format!("compaction-fixture-response-{index}"),
                "raw_response": {
                    "id": format!("compaction-fixture-response-{index}"),
                    "output": [{
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done"}],
                    }],
                },
                "output_items": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "done"}],
                }],
                "text": "done",
                "turn_completion": {
                    "turn_boundary_version": TURN_BOUNDARY_VERSION,
                    "covers_from_seq": user.seq,
                    "final_response_seq": response_seq,
                    "covers_through_seq": response_seq,
                },
            }),
        )
        .expect("append compaction fixture response");
    let marker_seq = journal.next_seq();
    journal
        .append_and_sync(
            "turn.completed",
            Some(turn_id),
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": user.seq,
                "final_response_seq": response.seq,
                "covers_through_seq": marker_seq,
            }),
        )
        .expect("append compaction fixture turn marker")
}

fn append_large_replan_turn(journal: &mut SessionJournal, index: usize) {
    let turn_id = format!("large-replan-turn-{index}");
    let user = journal
        .append_and_sync(
            "user.message",
            Some(&turn_id),
            json!({
                "item": {
                    "role": "user",
                    "content": format!("old question {index}:{}", "q".repeat(40_000)),
                },
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
            }),
        )
        .expect("append large replan user message");
    let response_seq = journal.next_seq();
    let text = format!("old answer {index}:{}", "a".repeat(40_000));
    let item = json!({
        "type": "message",
        "role": "assistant",
        "content": [{"type":"output_text","text":text}],
    });
    let response = journal
        .append_and_sync(
            "response.completed",
            Some(&turn_id),
            json!({
                "response_attempt_id": format!("large-replan-response-{index}"),
                "raw_response": {
                    "id": format!("large-replan-response-{index}"),
                    "output": [item.clone()],
                },
                "output_items": [item],
                "text": text,
                "turn_completion": {
                    "turn_boundary_version": TURN_BOUNDARY_VERSION,
                    "covers_from_seq": user.seq,
                    "final_response_seq": response_seq,
                    "covers_through_seq": response_seq,
                },
            }),
        )
        .expect("append large replan response");
    let marker_seq = journal.next_seq();
    journal
        .append_and_sync(
            "turn.completed",
            Some(&turn_id),
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": user.seq,
                "final_response_seq": response.seq,
                "covers_through_seq": marker_seq,
            }),
        )
        .expect("append large replan turn marker");
}

fn planning_context_v1(request_journal_through_seq: u64) -> serde_json::Value {
    json!({
        "measurement": {
            "measurement_version": 2,
            "estimator_version": 1,
            "request_shape_version": 1,
            "request_digest": "fault-replan-recorded-request",
            "estimated_input_tokens": 120_000,
            "serialized_request_bytes": 480_000,
        },
        "provider_usage_domain": "fault-injection-provider",
        "method": "full_request",
        "anchor_response_seq": null,
        "anchor_response_attempt_id": null,
        "anchor_reported_input_tokens": null,
        "anchor_estimated_input_tokens": null,
        "estimate_delta_tokens": null,
        "anchor_rejection_reason": null,
        "estimated_next_input_tokens": 120_000,
        "context_window": 130_000,
        "reserve_tokens": 10_000,
        "usable_tokens": 120_000,
        "trigger_tokens": 96_000,
        "target_tokens": 60_000,
        "request_journal_through_seq": request_journal_through_seq,
        "checkpoint_id": null,
        "checkpoint_covers_through_seq": null,
        "instructions_event_seq": null,
        "configured_event_seq": null,
        "tools_event_seq": 0,
    })
}

fn compaction_replan_context_limits() -> ContextLimits {
    ContextLimits {
        context_window: Some(130_000),
        reserve_tokens: 10_000,
        context_window_source: ContextValueSource::Cli,
        reserve_tokens_source: ContextValueSource::Cli,
    }
}

fn recovery_compaction_summary() -> AssistantTurn {
    recovery_turn("recovery-compaction", "recovered checkpoint summary", 20)
}

fn recovery_final_turn() -> AssistantTurn {
    recovery_turn("recovery-final", "recovered answer", 10)
}

fn recovery_turn(id: &str, text: &str, output_tokens: u64) -> AssistantTurn {
    let output_items = vec![json!({
        "type": "message",
        "role": "assistant",
        "content": [{"type":"output_text","text":text}],
    })];
    AssistantTurn {
        raw_response: json!({
            "id": id,
            "status": "completed",
            "output": output_items,
            "usage": {
                "input_tokens": 100,
                "output_tokens": output_tokens,
                "total_tokens": 100 + output_tokens,
            },
        }),
        output_items,
        text: text.to_owned(),
        tool_calls: Vec::new(),
        usage: Usage {
            input_tokens: 100,
            output_tokens,
            total_tokens: 100 + output_tokens,
            ..Usage::default()
        },
        unknown_stream_events: Vec::new(),
    }
}

fn isolated_cli_data_dir(root: &Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return root.join("local").join("oxidra");
    }
    #[cfg(target_os = "macos")]
    {
        return root
            .join("home")
            .join("Library")
            .join("Application Support")
            .join("oxidra");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return root.join("state").join("oxidra");
    }
    #[allow(unreachable_code)]
    root.join("oxidra")
}

fn serve_one_final_response(
    listener: TcpListener,
    text: &str,
) -> std::result::Result<Value, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set resume listener nonblocking: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for CLI resume request".to_owned());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("accept CLI resume request: {error}")),
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("set CLI resume stream blocking: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("set CLI resume request timeout: {error}"))?;
    let request = read_json_http_request(&mut stream)?;
    let body = final_text_sse("budget-migration-resume", text);
    write_http_response(&mut stream, &body)?;
    Ok(request)
}

fn read_json_http_request(stream: &mut TcpStream) -> std::result::Result<Value, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index;
        }
        let mut buffer = [0_u8; 8 * 1024];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read CLI request headers: {error}"))?;
        if count == 0 {
            return Err("CLI closed before request headers completed".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 128 * 1024 {
            return Err("CLI request headers exceeded 128 KiB".to_owned());
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| format!("CLI request headers were not UTF-8: {error}"))?;
    let content_length = headers
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .ok_or_else(|| "CLI request has no valid Content-Length".to_owned())?;
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(content_length)
        .ok_or_else(|| "CLI request body length overflowed".to_owned())?;
    while bytes.len() < body_end {
        let mut buffer = [0_u8; 8 * 1024];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read CLI request body: {error}"))?;
        if count == 0 {
            return Err("CLI closed before request body completed".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    serde_json::from_slice(&bytes[body_start..body_end])
        .map_err(|error| format!("parse CLI request JSON: {error}"))
}

fn final_text_sse(response_id: &str, text: &str) -> String {
    let item = json!({
        "type":"message",
        "id":"message_final",
        "role":"assistant",
        "status":"completed",
        "content":[{"type":"output_text","text":text,"annotations":[]}],
    });
    let completed = json!({
        "id":response_id,
        "object":"response",
        "status":"completed",
        "output":[item.clone()],
        "usage":{
            "input_tokens":1,
            "input_tokens_details":{"cached_tokens":0},
            "output_tokens":1,
            "output_tokens_details":{"reasoning_tokens":0},
            "total_tokens":2,
        },
    });
    let mut body = String::new();
    push_sse(
        &mut body,
        "response.created",
        json!({"type":"response.created","response":{"id":response_id}}),
    );
    push_sse(
        &mut body,
        "response.output_text.delta",
        json!({
            "type":"response.output_text.delta",
            "output_index":0,
            "content_index":0,
            "delta":text,
        }),
    );
    push_sse(
        &mut body,
        "response.output_item.done",
        json!({"type":"response.output_item.done","output_index":0,"item":item}),
    );
    push_sse(
        &mut body,
        "response.completed",
        json!({"type":"response.completed","response":completed}),
    );
    body
}

fn push_sse(body: &mut String, event: &str, payload: Value) {
    body.push_str("event: ");
    body.push_str(event);
    body.push('\n');
    body.push_str("data: ");
    body.push_str(&serde_json::to_string(&payload).expect("serialize SSE payload"));
    body.push_str("\n\n");
}

fn write_http_response(stream: &mut TcpStream, body: &str) -> std::result::Result<(), String> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("write CLI resume response: {error}"))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn spawn_fault_child(data_dir: &std::path::Path) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command.spawn().expect("spawn fault-injection child")
}

fn spawn_retry_fault_child(data_dir: &Path) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "retry_fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command.spawn().expect("spawn retry fault-injection child")
}

fn spawn_compaction_replan_fault_child(data_dir: &Path) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "compaction_replan_fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command
        .spawn()
        .expect("spawn compaction replan fault-injection child")
}

fn spawn_compaction_resolution_fault_child(data_dir: &Path, project_root: &Path) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "compaction_resolution_fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .env(PROJECT_ROOT_ENV, project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command
        .spawn()
        .expect("spawn compaction resolution fault-injection child")
}

fn spawn_budget_migration_fault_child(data_dir: &Path, project_root: &Path) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "budget_migration_fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .env(PROJECT_ROOT_ENV, project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command
        .spawn()
        .expect("spawn budget migration fault-injection child")
}

fn spawn_compaction_fault_child(data_dir: &Path, scenario: CompactionSyncPoint) -> Child {
    let mut command = Command::new(env::current_exe().expect("locate integration-test binary"));
    command
        .args([
            "--ignored",
            "--exact",
            "compaction_fault_injection_child",
            "--nocapture",
        ])
        .env(CHILD_MODE_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .env(COMPACTION_SCENARIO_ENV, scenario.label())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    suppress_windows_console(&mut command);
    command
        .spawn()
        .expect("spawn compaction fault-injection child")
}

fn stop_child_at(child: Child, target: SyncPoint) {
    stop_child_at_label(child, target.label(), &SyncPoint::ALL.map(SyncPoint::label));
}

fn stop_child_at_label(child: Child, target: &str, known_labels: &[&str]) {
    let mut child = ChildGuard::new(child);
    let stdout = child
        .child
        .stdout
        .take()
        .expect("fault child stdout is piped");
    let mut stdin = child
        .child
        .stdin
        .take()
        .expect("fault child stdin is piped");
    let (lines_tx, lines_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match stdout.read_line(&mut line) {
                Ok(0) => {
                    let _ = lines_tx.send(Ok(None));
                    return;
                }
                Ok(_) => {
                    if lines_tx.send(Ok(Some(line))).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = lines_tx.send(Err(error.to_string()));
                    return;
                }
            }
        }
    });
    let expected = format!("{SYNC_PREFIX}{target}");
    let mut transcript = String::new();

    loop {
        let line = match lines_rx.recv_timeout(SYNC_TIMEOUT) {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => {
                let status = child
                    .reap_or_kill()
                    .expect("reap fault child after its output closed");
                reader.join().expect("join fault child stdout reader");
                let stderr = read_child_stderr(&mut child.child);
                panic!(
                    "fault child exited before {expected}: {status}\nstdout:\n{transcript}\nstderr:\n{stderr}"
                );
            }
            Ok(Err(error)) => panic!("could not read fault child output: {error}"),
            Err(RecvTimeoutError::Timeout) => {
                child
                    .kill_and_wait()
                    .expect("kill and reap timed-out fault child");
                reader.join().expect("join timed-out child stdout reader");
                let stderr = read_child_stderr(&mut child.child);
                panic!(
                    "timed out after {SYNC_TIMEOUT:?} waiting for {expected}\nstdout:\n{transcript}\nstderr:\n{stderr}"
                );
            }
        };
        transcript.push_str(&line);
        let Some(marker) = line.find(SYNC_PREFIX) else {
            continue;
        };
        let observed = line[marker + SYNC_PREFIX.len()..].trim();
        if observed == target {
            let status = child
                .kill_and_wait()
                .expect("force-kill and reap fault child");
            drop(stdin);
            reader.join().expect("join killed child stdout reader");
            assert!(
                !status.success(),
                "force-killed child unexpectedly exited successfully at {}",
                target
            );
            return;
        }

        assert!(
            known_labels.contains(&observed),
            "fault child reported unknown sync point {observed:?}"
        );
        stdin
            .write_all(b"continue\n")
            .expect("release child to next sync point");
        stdin.flush().expect("flush child continuation");
    }
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn kill_and_wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.kill()?;
        self.wait()
    }

    fn reap_or_kill(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.child.try_wait()? {
            self.reaped = true;
            return Ok(status);
        }
        self.kill_and_wait()
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn sync_barrier(sync_point: SyncPoint) {
    sync_barrier_label(sync_point.label());
}

fn sync_barrier_label(label: &str) {
    println!("{SYNC_PREFIX}{label}");
    std::io::stdout()
        .flush()
        .expect("flush fault child notification");
    let mut acknowledgement = String::new();
    std::io::stdin()
        .read_line(&mut acknowledgement)
        .expect("read parent acknowledgement");
    assert_eq!(acknowledgement.trim(), "continue");
}

fn append_raw_checkpoint(
    path: &Path,
    seq: u64,
    covers_through_seq: u64,
    source_digest: &str,
    partial: bool,
) {
    let event = JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq,
        ts: Utc::now(),
        kind: COMPACTION_CHECKPOINT_KIND.to_owned(),
        session_id: SESSION_ID.to_owned(),
        turn_id: None,
        data: checkpoint_data(covers_through_seq, source_digest),
    };
    let encoded = serde_json::to_vec(&event).expect("encode raw checkpoint event");
    let bytes = if partial {
        &encoded[..encoded.len() / 2]
    } else {
        encoded.as_slice()
    };
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open journal for raw checkpoint append");
    file.write_all(bytes)
        .expect("write raw checkpoint fault payload");
    file.flush().expect("flush raw checkpoint fault payload");
    file.sync_data().expect("sync raw checkpoint fault payload");
}

fn checkpoint_data(covers_through_seq: u64, source_digest: &str) -> serde_json::Value {
    json!({
        "attempt_id": "compaction-attempt-1",
        "checkpoint_id": "checkpoint-1",
        "parent_checkpoint_id": null,
        "covers_through_seq": covers_through_seq,
        "source_digest": source_digest,
        "summary": "complete checkpoint summary",
        "model": "fault-injection-model",
        "prompt_version": COMPACTION_PROMPT_VERSION,
        "summary_envelope_version": SUMMARY_ENVELOPE_VERSION,
        "source_projection_version": SOURCE_PROJECTION_VERSION,
        "turn_boundary_validator_version": TURN_BOUNDARY_VALIDATOR_VERSION,
        "source_digest_version": SOURCE_DIGEST_VERSION,
        "usage_contract_version": USAGE_CONTRACT_VERSION,
        "usage": {
            "input_tokens": 10,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 5,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 15
        },
        "duration_ms": 1,
        "raw_response": {
            "id": "fault-response",
            "status": "completed",
            "usage": {
                "input_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 5,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 15
            },
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": "complete checkpoint summary",
                }],
            }],
        },
    })
}

fn assert_recovered_state(
    sync_point: SyncPoint,
    events: &[oxidra::session::JournalEvent],
    aborted_responses: usize,
    cancelled_turns: usize,
) {
    let turns = segment_turns(events).expect("segment recovered journal");
    let prefixes = complete_prefix_candidates(events).expect("derive recovered cutoffs");

    match sync_point {
        SyncPoint::SessionStarted => {
            assert!(turns.is_empty());
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 0);
            assert_eq!(cancelled_turns, 0);
        }
        SyncPoint::UserMessage => {
            assert_eq!(turns.len(), 1);
            assert_eq!(turns[0].state, TurnState::Cancelled);
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 0);
            assert_eq!(cancelled_turns, 1);
            assert!(events.iter().any(|event| {
                event.kind == "turn.cancelled"
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            }));
            assert!(events.iter().any(|event| event.kind == "journal.recovered"));
        }
        SyncPoint::ResponseStarted => {
            assert_eq!(turns.len(), 1);
            assert_eq!(turns[0].state, TurnState::Aborted);
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 1);
            assert_eq!(cancelled_turns, 0);
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.kind == "response.aborted")
                    .count(),
                1
            );
            assert!(events.iter().any(|event| event.kind == "journal.recovered"));
        }
        SyncPoint::InlineResponseCompleted => {
            assert_eq!(turns.len(), 1);
            assert_eq!(
                turns[0].state,
                TurnState::Complete(CompletionEvidence::InlineResponse)
            );
            assert_eq!(
                prefixes,
                vec![CompletePrefix {
                    turn_count: 1,
                    covers_through_seq: 4,
                }]
            );
            assert_eq!(aborted_responses, 0);
            assert_eq!(cancelled_turns, 0);
        }
        SyncPoint::TurnCompleted => {
            assert_eq!(turns.len(), 1);
            assert_eq!(
                turns[0].state,
                TurnState::Complete(CompletionEvidence::ExplicitMarker)
            );
            assert_eq!(
                prefixes,
                vec![CompletePrefix {
                    turn_count: 1,
                    covers_through_seq: 5,
                }]
            );
            assert_eq!(aborted_responses, 0);
            assert_eq!(cancelled_turns, 0);
        }
    }
}

fn event_kinds(events: &[oxidra::session::JournalEvent]) -> Vec<&str> {
    events.iter().map(|event| event.kind.as_str()).collect()
}

fn count_kind(events: &[JournalEvent], kind: &str) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

fn assert_recovered_compaction_abort(events: &[JournalEvent]) {
    let started = events
        .iter()
        .find(|event| event.kind == COMPACTION_STARTED_KIND)
        .expect("journal contains compaction.started");
    let aborted = events
        .iter()
        .find(|event| event.kind == COMPACTION_ABORTED_KIND)
        .expect("recovery appended compaction.aborted");
    assert_eq!(aborted.data["attempt_id"], started.data["attempt_id"]);
    assert_eq!(aborted.data["started_seq"], started.seq);
    assert_eq!(aborted.data["code"], "interrupted");
    assert_eq!(aborted.data["recovered"], true);
}

fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)
            .expect("read fault child stderr");
    }
    stderr
}

fn suppress_windows_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    #[cfg(not(windows))]
    let _ = command;
}
