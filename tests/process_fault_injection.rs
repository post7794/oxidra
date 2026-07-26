use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use oxidra::session::{SessionHeader, SessionStore};
use oxidra::turn::{
    CompletePrefix, CompletionEvidence, TURN_BOUNDARY_VERSION, TurnState,
    complete_prefix_candidates, segment_turns,
};
use serde_json::json;

const CHILD_MODE_ENV: &str = "OXIDRA_FAULT_INJECTION_CHILD";
const DATA_DIR_ENV: &str = "OXIDRA_FAULT_INJECTION_DATA_DIR";
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

fn stop_child_at(child: Child, target: SyncPoint) {
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
    let expected = format!("{SYNC_PREFIX}{}", target.label());
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
        if observed == target.label() {
            let status = child
                .kill_and_wait()
                .expect("force-kill and reap fault child");
            drop(stdin);
            reader.join().expect("join killed child stdout reader");
            assert!(
                !status.success(),
                "force-killed child unexpectedly exited successfully at {}",
                target.label()
            );
            return;
        }

        assert!(
            SyncPoint::ALL
                .iter()
                .any(|sync_point| sync_point.label() == observed),
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
    println!("{SYNC_PREFIX}{}", sync_point.label());
    std::io::stdout()
        .flush()
        .expect("flush fault child notification");
    let mut acknowledgement = String::new();
    std::io::stdin()
        .read_line(&mut acknowledgement)
        .expect("read parent acknowledgement");
    assert_eq!(acknowledgement.trim(), "continue");
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
