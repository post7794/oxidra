use std::env;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use oxidra::compaction::{
    COMPACTION_ABORTED_KIND, COMPACTION_CHECKPOINT_KIND, COMPACTION_PROMPT_VERSION,
    COMPACTION_STARTED_KIND, CompactionCandidate, CompactionStarted, MAX_COMPACTION_OUTPUT_TOKENS,
    SOURCE_DIGEST_VERSION, SUMMARY_ENVELOPE_VERSION, USAGE_CONTRACT_VERSION,
    build_compaction_source, compact_once, compaction_instructions, validate_checkpoint_chain,
};
use oxidra::error::Result;
use oxidra::projection::SOURCE_PROJECTION_VERSION;
use oxidra::provider::{ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver};
use oxidra::session::{JOURNAL_SCHEMA, JournalEvent, SessionHeader, SessionJournal, SessionStore};
use oxidra::turn::{
    CompletePrefix, CompletionEvidence, TURN_BOUNDARY_VALIDATOR_VERSION, TURN_BOUNDARY_VERSION,
    TurnState, complete_prefix_candidates, segment_turns,
};
use oxidra::types::{AssistantTurn, Usage};
use serde_json::json;
use tokio_util::sync::CancellationToken;

const CHILD_MODE_ENV: &str = "OXIDRA_FAULT_INJECTION_CHILD";
const DATA_DIR_ENV: &str = "OXIDRA_FAULT_INJECTION_DATA_DIR";
const COMPACTION_SCENARIO_ENV: &str = "OXIDRA_COMPACTION_FAULT_SCENARIO";
const SESSION_ID: &str = "process-fault-session";
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

        assert_recovered_state(sync_point, &recovered, recovery.aborted_responses);
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
) {
    let turns = segment_turns(events).expect("segment recovered journal");
    let prefixes = complete_prefix_candidates(events).expect("derive recovered cutoffs");

    match sync_point {
        SyncPoint::SessionStarted => {
            assert!(turns.is_empty());
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 0);
        }
        SyncPoint::UserMessage => {
            assert_eq!(turns.len(), 1);
            assert_eq!(turns[0].state, TurnState::OpenTail);
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 0);
        }
        SyncPoint::ResponseStarted => {
            assert_eq!(turns.len(), 1);
            assert_eq!(turns[0].state, TurnState::Aborted);
            assert!(prefixes.is_empty());
            assert_eq!(aborted_responses, 1);
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
