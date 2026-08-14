use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compaction::{
    COMPACTION_ABORTED_KIND, COMPACTION_BOUNDARY_CHECKPOINTED_KIND,
    COMPACTION_BOUNDARY_FAILED_KIND, COMPACTION_CHECKPOINT_KIND, COMPACTION_FAILED_KIND,
    COMPACTION_STARTED_KIND, CompactionBoundary, CompactionBoundaryRecoveryAction,
    CompactionBoundaryState, compaction_boundary_recovery_actions, validate_checkpoint_chain,
    validate_compaction_boundary_chain,
};
use crate::error::{OxidraError, Result};
use crate::event_kind::{
    is_compaction_lifecycle, is_compaction_terminal, is_response_terminal, is_tool_lifecycle,
    is_tool_terminal,
};
use crate::mcp::{
    MAX_MCP_CALLS_PER_RESPONSE, MAX_RESPONSE_STATUS_TEXT_BYTES_V2, response_status_text_for_journal,
};
use crate::turn::{TurnState, segment_turns, validate_provider_request_slots_v2};

pub const JOURNAL_SCHEMA: u32 = 1;
pub const SESSION_STARTED_KIND: &str = "session.started";
pub const RECOVERY_KIND: &str = "journal.recovered";
const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;

/// A provider context-limit response is a two-event business transaction:
/// the response terminal carries a durable intent and the following context
/// event is its audit/reducer projection.  The intent version is deliberately
/// independent from the turn reducer versions so a future profile can be
/// added without changing the meaning of already-published turn validators.
pub(crate) const PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1: u64 = 1;
const PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD: &str = "provider_context_limit_intent_version";
const PROVIDER_CONTEXT_LIMIT_INTENT_SEQ_FIELD: &str = "provider_context_limit_intent_seq";
const PROVIDER_CONTEXT_LIMIT_STARTED_SEQ_FIELD: &str = "response_started_seq";
const PROVIDER_CONTEXT_LIMIT_ERROR_CODE: &str = "provider_context_limit";
const MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1: usize = 16 * 1024;
const PROVIDER_CONTEXT_LIMIT_EMPTY_ERROR_V1: &str = "unspecified response status";
const PROVIDER_CONTEXT_LIMIT_TRUNCATION_SUFFIX_V1: &str = "<truncated>";
const MAX_PROVIDER_CONTEXT_LIMIT_CONTEXT_BYTES_V1: usize = 64 * 1024;
const MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1: usize = 16 * 1024;
const MAX_TURN_STATUS_BYTES_V1: usize = 16 * 1024;
const TURN_STATUS_EMPTY_V1: &str = "unspecified turn status";
const TURN_STATUS_TRUNCATION_SUFFIX_V1: &str = "<truncated>";
/// Frozen reserve acquired before the first durable event of a new user turn.
/// It covers a bounded same-process cancellation or the crash-recovery
/// cancellation plus `journal.recovered`. Nested Provider attempts may require
/// a larger reserve, but ordinary appends can never consume this floor while
/// the turn capability remains active.
const TURN_OUTCOME_HEADROOM_BYTES_V1: u64 = 1024 * 1024;
const COMPACTION_OUTCOME_HEADROOM_BYTES_V1: u64 = 2 * 1024 * 1024;
/// Frozen dispatch-admission reserve for one bounded response terminal, the
/// two-event context-limit transaction, or crash recovery's abort + marker.
/// The literal maximum profiles are serialized in a regression test; changing
/// any accepted field budget requires a new admission version or a larger
/// reserve before the writer can dispatch Provider code.
const PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1: u64 = 1024 * 1024;
const _: () =
    assert!(MAX_RESPONSE_STATUS_TEXT_BYTES_V2 <= MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JournalEvent {
    pub schema: u32,
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub data: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionHeader {
    /// Binary version that created this session. Missing in pre-M3 journals.
    #[serde(default = "legacy_session_version")]
    pub version: String,
    pub project_root: PathBuf,
    pub model: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SessionHeader {
    pub fn new(project_root: impl Into<PathBuf>, model: impl Into<String>) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            project_root: project_root.into(),
            model: model.into(),
            extra: Map::new(),
        }
    }
}

fn legacy_session_version() -> String {
    "pre-v0.1".to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLayout {
    pub data_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub locks_dir: PathBuf,
}

impl SessionLayout {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            sessions_dir: data_dir.join("sessions"),
            artifacts_dir: data_dir.join("artifacts"),
            locks_dir: data_dir.join("locks"),
            data_dir,
        }
    }

    pub fn platform_default() -> Result<Self> {
        Ok(Self::new(user_data_dir()?))
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.sessions_dir)?;
        fs::create_dir_all(&self.artifacts_dir)?;
        fs::create_dir_all(&self.locks_dir)?;
        Ok(())
    }

    pub fn journal_path(&self, session_id: &str) -> Result<PathBuf> {
        validate_session_id(session_id)?;
        Ok(self.sessions_dir.join(format!("{session_id}.jsonl")))
    }

    pub fn artifact_dir(&self, session_id: &str) -> Result<PathBuf> {
        validate_session_id(session_id)?;
        Ok(self.artifacts_dir.join(session_id))
    }

    pub fn lock_path(&self, session_id: &str) -> Result<PathBuf> {
        validate_session_id(session_id)?;
        Ok(self.locks_dir.join(format!("{session_id}.lock")))
    }
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    layout: SessionLayout,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionSummary {
    pub session_id: String,
    pub header: SessionHeader,
    pub event_count: usize,
    pub last_activity: DateTime<Utc>,
}

impl SessionStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let layout = SessionLayout::new(data_dir);
        layout.ensure()?;
        Ok(Self { layout })
    }

    pub fn platform_default() -> Result<Self> {
        let layout = SessionLayout::platform_default()?;
        layout.ensure()?;
        Ok(Self { layout })
    }

    pub fn layout(&self) -> &SessionLayout {
        &self.layout
    }

    /// Lists sessions without opening, locking, or recovering them. This keeps
    /// an administrative read from mutating the append-only journal.
    pub fn list(&self) -> Result<Vec<SessionSummary>> {
        let mut summaries = Vec::new();
        for entry in fs::read_dir(&self.layout.sessions_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("jsonl")
            {
                continue;
            }
            let Some(session_id) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if validate_session_id(session_id).is_err() {
                continue;
            }
            ensure_journal_size(&path)?;
            let events = parse_complete_events(&fs::read(&path)?, session_id)?;
            let Some(first) = events.first() else {
                continue;
            };
            if first.kind != SESSION_STARTED_KIND {
                return Err(OxidraError::Session(format!(
                    "session {session_id} has no session.started header"
                )));
            }
            let header = serde_json::from_value(first.data.clone())?;
            let last_activity = events.last().map(|event| event.ts).unwrap_or(first.ts);
            summaries.push(SessionSummary {
                session_id: session_id.to_owned(),
                header,
                event_count: events.len(),
                last_activity,
            });
        }
        summaries.sort_by(|left, right| right.last_activity.cmp(&left.last_activity));
        Ok(summaries)
    }

    /// Reads a journal for display without applying crash recovery.
    pub fn inspect(&self, session_id: &str) -> Result<Vec<JournalEvent>> {
        validate_session_id(session_id)?;
        let path = self.layout.journal_path(session_id)?;
        if !path.is_file() {
            return Err(OxidraError::Session(format!(
                "session not found: {session_id}"
            )));
        }
        ensure_journal_size(&path)?;
        parse_complete_events(&fs::read(path)?, session_id)
    }

    /// Permanently deletes a session journal and its shell artifacts. The
    /// session lock prevents deletion while another process has it open.
    ///
    /// The journal is first renamed to a `.jsonl.deleting` tombstone so that a
    /// partial failure can never leave a discoverable session whose artifacts
    /// are already gone; a later delete of the same id resumes the cleanup.
    ///
    /// The lock file is deliberately left in place. Journal, artifacts, and
    /// lock live in three separate paths, so plain file operations cannot
    /// delete all of them atomically: removing the lock last leaves a crash
    /// window with an orphan lock nothing will clean up, and unlink-after-drop
    /// races a concurrent open of the same id into two independent lock
    /// inodes on Unix. An empty leftover lock file is harmless and is reused
    /// by any future session with the same id.
    pub fn delete(&self, session_id: &str) -> Result<bool> {
        validate_session_id(session_id)?;
        let journal_path = self.layout.journal_path(session_id)?;
        let tombstone_path = journal_path.with_extension("jsonl.deleting");
        // Check before locking so a mistyped id does not manufacture a lock file.
        if !journal_path.is_file() && !tombstone_path.is_file() {
            return Ok(false);
        }
        let _lock_file = acquire_lock(&self.layout, session_id)?;
        if !journal_path.is_file() && !tombstone_path.is_file() {
            return Ok(false);
        }

        if journal_path.is_file() {
            if tombstone_path.is_file() {
                fs::remove_file(&tombstone_path)?;
            }
            fs::rename(&journal_path, &tombstone_path)?;
        }

        let artifact_dir = self.layout.artifact_dir(session_id)?;
        match fs::symlink_metadata(&artifact_dir) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&artifact_dir)?,
            Ok(_) => {
                return Err(OxidraError::Session(format!(
                    "artifact path is not a directory: {}",
                    artifact_dir.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&tombstone_path)?;
        Ok(true)
    }

    pub fn create(&self, header: SessionHeader) -> Result<SessionJournal> {
        self.create_with_id(Uuid::now_v7().to_string(), header)
    }

    pub fn create_with_id(
        &self,
        session_id: impl Into<String>,
        header: SessionHeader,
    ) -> Result<SessionJournal> {
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        self.layout.ensure()?;

        let lock_file = acquire_lock(&self.layout, &session_id)?;
        let journal_path = self.layout.journal_path(&session_id)?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(&journal_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    OxidraError::Session(format!("session already exists: {session_id}"))
                } else {
                    error.into()
                }
            })?;
        fs::create_dir_all(self.layout.artifact_dir(&session_id)?)?;

        let mut journal = SessionJournal {
            session_id: session_id.clone(),
            journal_path,
            artifact_dir: self.layout.artifact_dir(&session_id)?,
            file,
            _lock_file: lock_file,
            next_seq: 1,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit: MAX_SESSION_BYTES,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            mcp_resume_open_id: None,
            mcp_resume_eligibility_issued: false,
        };
        journal.append_and_sync(SESSION_STARTED_KIND, None, serde_json::to_value(header)?)?;
        Ok(journal)
    }

    pub fn open(&self, session_id: &str) -> Result<SessionJournal> {
        self.open_with_byte_limit(session_id, MAX_SESSION_BYTES)
    }

    fn open_with_byte_limit(&self, session_id: &str, byte_limit: u64) -> Result<SessionJournal> {
        validate_session_id(session_id)?;
        self.layout.ensure()?;

        let lock_file = acquire_lock(&self.layout, session_id)?;
        let journal_path = self.layout.journal_path(session_id)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    OxidraError::Session(format!("session not found: {session_id}"))
                } else {
                    error.into()
                }
            })?;

        let scan = scan_and_repair_tail(&mut file, session_id)?;
        let JournalScan {
            events: mut prospective_events,
            truncated_tail,
            normalized_missing_newline,
        } = scan;
        validate_events(&prospective_events, session_id)?;
        let provider_context_limit_actions =
            provider_context_limit_recovery_actions_v1(&prospective_events)?;
        let provider_context_limit_recovery_turns = provider_context_limit_actions
            .iter()
            .map(|action| action.turn_id.clone())
            .collect::<HashSet<_>>();
        let next_seq = match prospective_events.last() {
            Some(event) => event
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence is exhausted".to_owned()))?,
            None => 1,
        };
        let unfinished_responses = unfinished_responses(&prospective_events)?;
        let previously_aborted_responses = prospective_events
            .iter()
            .filter(|event| {
                event.kind == "response.aborted"
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let aborted_responses = previously_aborted_responses + unfinished_responses.len();
        let unfinished_compactions = unfinished_compactions(&prospective_events);
        let previously_aborted_compactions = prospective_events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_ABORTED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let aborted_compactions = previously_aborted_compactions + unfinished_compactions.len();
        let failed_compaction_boundaries = prospective_events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_BOUNDARY_FAILED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let checkpointed_compaction_boundaries = prospective_events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_BOUNDARY_CHECKPOINTED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let previously_cancelled_turns = prospective_events
            .iter()
            .filter(|event| {
                event.kind == "turn.cancelled"
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
                    && event
                        .data
                        .get("turn_outcome_admission_version")
                        .and_then(Value::as_u64)
                        == Some(1)
            })
            .count();
        crate::mcp::validate_mcp_call_chain(&prospective_events)?;
        let unstarted_tools = unstarted_tool_calls(&prospective_events);
        // Build every authorization payload before the first recovery write.
        // Legacy call-chain v1 could durably contain more than the current
        // per-response maximum, so recovery chunks that old batch into
        // multiple independently bounded v1 markers instead of rewriting the
        // frozen validator or poisoning the journal midway through repair.
        preflight_recovery_authorization_batches(&unstarted_tools)?;
        let previously_skipped = prospective_events
            .iter()
            .filter(|event| event.kind == "tool.skipped_due_to_recovery")
            .count();
        let skipped_before_start = previously_skipped + unstarted_tools.len();
        let in_doubt = pending_tools(&prospective_events);
        let mut recovery = RecoveryInfo {
            truncated_tail,
            normalized_missing_newline,
            in_doubt,
            marker_seq: None,
            skipped_before_start,
            aborted_responses,
            aborted_compactions,
            failed_compaction_boundaries,
            checkpointed_compaction_boundaries,
            recovered_provider_context_limits: provider_context_limit_actions.len(),
            cancelled_turns: previously_cancelled_turns,
        };

        let mut journal = SessionJournal {
            session_id: session_id.to_owned(),
            journal_path,
            artifact_dir: self.layout.artifact_dir(session_id)?,
            file,
            _lock_file: lock_file,
            next_seq,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            // This nonce identifies the exact recovered journal handle that
            // authorized a later MCP resume.  A newly-created journal cannot
            // mint that capability, and reopening after dropping this handle
            // produces a different nonce.
            mcp_resume_open_id: Some(Uuid::now_v7().to_string()),
            mcp_resume_eligibility_issued: false,
        };
        fs::create_dir_all(&journal.artifact_dir)?;

        let original_event_count = prospective_events.len();
        let mut planned_events = Vec::new();
        let mut planned_seq = journal.next_seq();
        for action in provider_context_limit_actions {
            stage_recovery_event(
                session_id,
                &mut planned_seq,
                &mut planned_events,
                &mut prospective_events,
                "context.limit_reached",
                Some(&action.turn_id),
                action.data,
            )?;
        }
        if !provider_context_limit_recovery_actions_v1(&prospective_events)?.is_empty() {
            return Err(OxidraError::Session(
                "provider context-limit recovery did not reach a stable state".to_owned(),
            ));
        }
        validate_provider_context_limit_turns_v1(
            &prospective_events,
            &provider_context_limit_recovery_turns,
        )?;
        let recovered_unfinished_response = !unfinished_responses.is_empty();
        for response in unfinished_responses {
            stage_recovery_event(
                session_id,
                &mut planned_seq,
                &mut planned_events,
                &mut prospective_events,
                "response.aborted",
                response.turn_id.as_deref(),
                json!({
                    "response_attempt_id": response.response_attempt_id,
                    "started_seq": response.started_seq,
                    "reason": "process stopped before a terminal response event was committed",
                    "recovered": true,
                }),
            )?;
        }

        let recovered_unfinished_compaction = !unfinished_compactions.is_empty();
        for attempt in unfinished_compactions {
            stage_recovery_event(
                session_id,
                &mut planned_seq,
                &mut planned_events,
                &mut prospective_events,
                COMPACTION_ABORTED_KIND,
                None,
                json!({
                    "attempt_id": attempt.attempt_id,
                    "started_seq": attempt.started_seq,
                    "code": "interrupted",
                    "message": "compaction was interrupted before a terminal event was committed",
                    "recovered": true,
                }),
            )?;
        }

        let boundary_actions = compaction_boundary_recovery_actions(&prospective_events)?;
        let mut recovered_boundaries = RecoveredCompactionBoundaries::default();
        for action in boundary_actions {
            match action {
                CompactionBoundaryRecoveryAction::Checkpointed(payload) => {
                    stage_recovery_event(
                        session_id,
                        &mut planned_seq,
                        &mut planned_events,
                        &mut prospective_events,
                        COMPACTION_BOUNDARY_CHECKPOINTED_KIND,
                        None,
                        serde_json::to_value(payload)?,
                    )?;
                    recovered_boundaries.checkpointed =
                        recovered_boundaries.checkpointed.saturating_add(1);
                }
                CompactionBoundaryRecoveryAction::Failed(payload) => {
                    stage_recovery_event(
                        session_id,
                        &mut planned_seq,
                        &mut planned_events,
                        &mut prospective_events,
                        COMPACTION_BOUNDARY_FAILED_KIND,
                        None,
                        serde_json::to_value(payload)?,
                    )?;
                    recovered_boundaries.failed = recovered_boundaries.failed.saturating_add(1);
                }
            }
        }
        if !compaction_boundary_recovery_actions(&prospective_events)?.is_empty() {
            return Err(OxidraError::Session(
                "compaction boundary recovery did not reach a stable state".to_owned(),
            ));
        }
        recovery.failed_compaction_boundaries = recovery
            .failed_compaction_boundaries
            .saturating_add(recovered_boundaries.failed);
        recovery.checkpointed_compaction_boundaries = recovery
            .checkpointed_compaction_boundaries
            .saturating_add(recovered_boundaries.checkpointed);
        let mcp_turn_ids = crate::mcp::mcp_turn_ids(&prospective_events)?;
        validate_provider_request_slots_v2(&prospective_events, &mcp_turn_ids)?;
        recovery.marker_seq =
            matching_recovery_marker(&prospective_events[..original_event_count], &recovery);
        let provisional_marker_required_without_tools = unstarted_tools.is_empty()
            && (recovery.truncated_tail.is_some()
                || recovered_unfinished_response
                || recovered_unfinished_compaction
                || (!recovery.in_doubt.is_empty() && recovery.marker_seq.is_none())
                || (recovery.skipped_before_start > 0 && recovery.marker_seq.is_none())
                || (recovery.aborted_responses > 0 && recovery.marker_seq.is_none())
                || (recovery.aborted_compactions > 0 && recovery.marker_seq.is_none())
                || (recovery.failed_compaction_boundaries > 0 && recovery.marker_seq.is_none())
                || (recovery.checkpointed_compaction_boundaries > 0
                    && recovery.marker_seq.is_none())
                || (recovery.cancelled_turns > 0 && recovery.marker_seq.is_none()));
        let mut provisional_recovery = recovery.clone();
        let provisional_mcp_events = plan_mcp_recovery_events(
            journal.session_id(),
            planned_seq,
            &mut provisional_recovery,
            &unstarted_tools,
            provisional_marker_required_without_tools,
        )?;
        let mut after_lifecycle_recovery = prospective_events.clone();
        after_lifecycle_recovery.extend(provisional_mcp_events);
        let recoverable_turns = recoverable_open_turns_v1(&after_lifecycle_recovery)?;
        recovery.cancelled_turns = recovery
            .cancelled_turns
            .saturating_add(recoverable_turns.len());
        let recovered_open_turn = !recoverable_turns.is_empty();
        recovery.marker_seq =
            matching_recovery_marker(&prospective_events[..original_event_count], &recovery);
        let marker_required_without_tools = unstarted_tools.is_empty()
            && (provisional_marker_required_without_tools
                || (!recoverable_turns.is_empty() && recovery.marker_seq.is_none()));
        // Freeze every recovery event before any transaction byte is written.
        // This includes generic aborts, compaction boundary terminals, MCP
        // markers and all authorized skips.
        let mcp_recovery_events = plan_mcp_recovery_events(
            journal.session_id(),
            planned_seq,
            &mut recovery,
            &unstarted_tools,
            marker_required_without_tools,
        )?;
        if let Some(last) = mcp_recovery_events.last() {
            planned_seq = last
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
        }
        prospective_events.extend(mcp_recovery_events.iter().cloned());
        planned_events.extend(mcp_recovery_events);
        for turn in recoverable_turns {
            stage_recovery_event(
                session_id,
                &mut planned_seq,
                &mut planned_events,
                &mut prospective_events,
                "turn.cancelled",
                Some(&turn.turn_id),
                json!({
                    "reason": "process stopped before the user turn acquired a durable outcome owner",
                    "user_message_seq": turn.user_message_seq,
                    "turn_outcome_admission_version": 1,
                    "recovered": true,
                }),
            )?;
        }
        crate::mcp::validate_mcp_call_chain(&prospective_events)?;
        validate_provider_request_slots_v2(&prospective_events, &mcp_turn_ids)?;
        if recovered_open_turn {
            segment_turns(&prospective_events)?;
        }
        journal.append_prebuilt_batch(&planned_events)?;
        journal.recovery = recovery;
        Ok(journal)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RecoveryInfo {
    pub truncated_tail: Option<TruncatedTail>,
    pub normalized_missing_newline: bool,
    pub in_doubt: Vec<InDoubtTool>,
    pub marker_seq: Option<u64>,
    #[serde(default)]
    pub skipped_before_start: usize,
    #[serde(default)]
    pub aborted_responses: usize,
    #[serde(default)]
    pub aborted_compactions: usize,
    #[serde(default)]
    pub failed_compaction_boundaries: usize,
    #[serde(default)]
    pub checkpointed_compaction_boundaries: usize,
    #[serde(default)]
    pub recovered_provider_context_limits: usize,
    #[serde(default)]
    pub cancelled_turns: usize,
}

impl RecoveryInfo {
    pub fn recovered(&self) -> bool {
        self.marker_seq.is_some()
            || self.normalized_missing_newline
            || self.recovered_provider_context_limits > 0
            || self.cancelled_turns > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TruncatedTail {
    pub byte_count: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InDoubtTool {
    pub started_seq: u64,
    pub turn_id: Option<String>,
    pub call_id: Option<String>,
    pub tool_name: Option<String>,
    pub arguments: Option<Value>,
    pub data: Value,
}

pub struct SessionJournal {
    session_id: String,
    journal_path: PathBuf,
    artifact_dir: PathBuf,
    file: File,
    _lock_file: File,
    next_seq: u64,
    recovery: RecoveryInfo,
    poisoned: bool,
    reopen_required: Arc<AtomicBool>,
    byte_limit: u64,
    active_turn: Option<ActiveTurnReservationV1>,
    active_provider_response: Option<ActiveProviderResponseReservationV1>,
    active_compaction: Option<ActiveCompactionReservationV1>,
    mcp_resume_open_id: Option<String>,
    mcp_resume_eligibility_issued: bool,
}

#[derive(Clone, Debug)]
struct ActiveTurnReservationV1 {
    reservation_id: String,
    turn_id: String,
    user_message_seq: u64,
    headroom_bytes: u64,
}

#[derive(Clone, Debug)]
struct ActiveProviderResponseReservationV1 {
    reservation_id: String,
    turn_id: String,
    response_attempt_id: String,
    response_started_seq: u64,
    context: Value,
    headroom_bytes: u64,
}

#[derive(Clone, Debug)]
struct ActiveCompactionReservationV1 {
    reservation_id: String,
    attempt_id: String,
    started_seq: u64,
    boundary: Option<Value>,
    headroom_bytes: u64,
}

/// One-shot capability proving that `response.started` was synced only after
/// reserving enough journal space for every bounded immediate terminal and
/// the crash-recovery abort transaction. The token is intentionally neither
/// `Clone` nor constructible outside this module.
#[derive(Debug)]
pub(crate) struct ProviderResponseDispatchAdmissionV1 {
    reservation_id: String,
    consumed: bool,
    reopen_required: Arc<AtomicBool>,
}

/// One-shot capability proving that a new turn's `user.message` was synced
/// only after protecting enough capacity to settle a pre-dispatch failure or
/// crash. The token is deliberately owned by the `run_turn` future: abnormal
/// future destruction marks the journal handle reopen-required.
#[derive(Debug)]
pub(crate) struct TurnTransactionAdmissionV1 {
    reservation_id: String,
    consumed: bool,
    reopen_required: Arc<AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct CompactionProviderDispatchAdmissionV1 {
    reservation_id: String,
    consumed: bool,
    reopen_required: Arc<AtomicBool>,
}

#[derive(Debug)]
pub(crate) enum DispatchAdmissionErrorV1 {
    CapacityDeniedBeforeStart(OxidraError),
    Fatal(OxidraError),
}

#[derive(Debug)]
pub(crate) enum DurableOutcomeCommitErrorV1 {
    CapacityDenied(OxidraError),
    Fatal(OxidraError),
}

impl DurableOutcomeCommitErrorV1 {
    pub(crate) fn into_error(self) -> OxidraError {
        match self {
            Self::CapacityDenied(error) | Self::Fatal(error) => error,
        }
    }
}

impl DispatchAdmissionErrorV1 {
    pub(crate) fn into_error(self) -> OxidraError {
        match self {
            Self::CapacityDeniedBeforeStart(error) | Self::Fatal(error) => error,
        }
    }
}

impl std::fmt::Display for DispatchAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityDeniedBeforeStart(error) | Self::Fatal(error) => {
                std::fmt::Display::fmt(error, formatter)
            }
        }
    }
}

impl Drop for ProviderResponseDispatchAdmissionV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.reopen_required.store(true, Ordering::Release);
        }
    }
}

impl Drop for TurnTransactionAdmissionV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.reopen_required.store(true, Ordering::Release);
        }
    }
}

impl Drop for CompactionProviderDispatchAdmissionV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.reopen_required.store(true, Ordering::Release);
        }
    }
}

impl SessionJournal {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn artifact_dir(&self) -> &Path {
        &self.artifact_dir
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn recovery_info(&self) -> &RecoveryInfo {
        &self.recovery
    }

    #[cfg(test)]
    pub(crate) fn set_byte_limit_for_tests(&mut self, byte_limit: u64) {
        self.byte_limit = byte_limit;
    }

    /// Produce the one-shot journal-gate capability required to start MCP
    /// processes for a durable registry epoch.
    ///
    /// Only a journal returned by [`SessionStore::open`] can mint this
    /// capability.  The capability is bound to this exact open handle and is
    /// consumed by [`crate::mcp::McpRegistry::connect_for_resume`].
    pub fn mcp_resume_eligibility(&mut self) -> Result<crate::mcp::McpResumeEligibility<'_>> {
        crate::mcp::McpResumeEligibility::from_recovered_journal(self)
    }

    pub(crate) fn mcp_resume_open_id(&self) -> Option<&str> {
        self.mcp_resume_open_id.as_deref()
    }

    pub(crate) fn claim_mcp_resume_open_id(&mut self) -> Result<String> {
        let open_id = self.mcp_resume_open_id.clone().ok_or_else(|| {
            OxidraError::Session(
                "MCP resume eligibility requires a journal returned by SessionStore::open"
                    .to_owned(),
            )
        })?;
        if self.mcp_resume_eligibility_issued {
            return Err(OxidraError::Session(
                "MCP resume eligibility was already issued for this journal handle".to_owned(),
            ));
        }
        self.mcp_resume_eligibility_issued = true;
        Ok(open_id)
    }

    pub(crate) fn mark_reopen_required(&self) {
        self.reopen_required.store(true, Ordering::Release);
    }

    pub fn header(&self) -> Result<Option<SessionHeader>> {
        self.read_events()?
            .into_iter()
            .find(|event| event.kind == SESSION_STARTED_KIND)
            .map(|event| serde_json::from_value(event.data).map_err(OxidraError::from))
            .transpose()
    }

    pub fn append(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        self.ensure_healthy()?;
        if self.active_provider_response.is_some() {
            return Err(OxidraError::Session(
                "an admitted Provider response must be terminalized through its dispatch capability"
                    .to_owned(),
            ));
        }
        if self.active_compaction.is_some() {
            return Err(OxidraError::Session(
                "an admitted compaction attempt must be terminalized through its dispatch capability"
                    .to_owned(),
            ));
        }
        let byte_limit = self.generic_append_byte_limit_v1()?;
        self.append_with_limit(kind, turn_id, data, byte_limit)
    }

    fn append_with_limit(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
        byte_limit: u64,
    ) -> Result<JournalEvent> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err(OxidraError::Session(
                "journal event kind cannot be empty".to_owned(),
            ));
        }
        let next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;

        let event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: self.next_seq,
            ts: Utc::now(),
            kind,
            session_id: self.session_id.clone(),
            turn_id: turn_id.map(str::to_owned),
            data,
        };
        let encoded = serde_json::to_vec(&event)?;
        let metadata_result = self.file.metadata();
        let current_size = self.finish_io(metadata_result)?.len();
        if current_size
            .saturating_add(encoded.len() as u64)
            .saturating_add(1)
            > byte_limit
        {
            return Err(OxidraError::Session(format!(
                "session journal would exceed the {}-byte safety limit",
                byte_limit
            )));
        }
        // Recovered journals need a read/write handle so Windows permits
        // truncating an incomplete tail. The session lock guarantees a single
        // writer; seeking here preserves append-only writes for that handle.
        let seek_result = self.file.seek(SeekFrom::End(0));
        self.finish_io(seek_result)?;
        let write_result = self.file.write_all(&encoded);
        self.finish_io(write_result)?;
        let newline_result = self.file.write_all(b"\n");
        self.finish_io(newline_result)?;
        self.next_seq = next_seq;
        Ok(event)
    }

    fn generic_append_byte_limit_v1(&self) -> Result<u64> {
        match &self.active_turn {
            Some(active) => self
                .byte_limit
                .checked_sub(active.headroom_bytes)
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "session journal cannot protect the {}-byte turn outcome headroom",
                        active.headroom_bytes
                    ))
                }),
            None => Ok(self.byte_limit),
        }
    }

    pub fn append_and_sync(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let event = self.append(kind, turn_id, data)?;
        self.sync()?;
        Ok(event)
    }

    /// Start a new user turn only after protecting enough space to recover or
    /// cancel every crash prefix that precedes the first Provider dispatch.
    pub(crate) fn append_user_message_with_turn_admission_v1(
        &mut self,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<TurnTransactionAdmissionV1, DispatchAdmissionErrorV1> {
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.active_turn.is_some()
            || self.active_provider_response.is_some()
            || self.active_compaction.is_some()
        {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a durable turn or Provider response admission is already active".to_owned(),
            )));
        }

        let user_message_seq = self.next_seq();
        user_message_seq.checked_add(2).ok_or_else(|| {
            DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "journal sequence cannot represent a recoverable user turn".to_owned(),
            ))
        })?;
        let mut planned_seq = user_message_seq;
        let user_event = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "user.message",
            Some(turn_id),
            data,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let mut prospective = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        prospective.push(user_event.clone());
        segment_turns(&prospective).map_err(DispatchAdmissionErrorV1::Fatal)?;

        let admission_limit = self
            .byte_limit
            .checked_sub(TURN_OUTCOME_HEADROOM_BYTES_V1)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(OxidraError::Session(
                    format!(
                        "session journal cannot reserve the {TURN_OUTCOME_HEADROOM_BYTES_V1}-byte turn outcome headroom"
                    ),
                ))
            })?;
        if !self
            .preflight_prebuilt_batch_capacity(&[user_event.clone()], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?
        {
            return Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(
                OxidraError::Session(format!(
                    "session journal cannot append user.message while preserving the {TURN_OUTCOME_HEADROOM_BYTES_V1}-byte turn outcome headroom"
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(&[user_event], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let reservation_id = Uuid::now_v7().to_string();
        self.active_turn = Some(ActiveTurnReservationV1 {
            reservation_id: reservation_id.clone(),
            turn_id: turn_id.to_owned(),
            user_message_seq,
            headroom_bytes: TURN_OUTCOME_HEADROOM_BYTES_V1,
        });
        Ok(TurnTransactionAdmissionV1 {
            reservation_id,
            consumed: false,
            reopen_required: Arc::clone(&self.reopen_required),
        })
    }

    /// Release a turn admission after proving that the durable turn is already
    /// owned by a terminal or explicit retry/abandon protocol. If the caller
    /// returns an error before such an owner exists, consume the protected
    /// reserve with one bounded `turn.cancelled` event.
    pub(crate) fn finish_turn_transaction_v1(
        &mut self,
        admission: &mut TurnTransactionAdmissionV1,
        cancellation_reason: Option<&str>,
    ) -> Result<()> {
        let active = self.active_turn_v1(admission)?.clone();
        let events = self.read_events()?;
        if turn_transaction_is_settled_v1(&events, &active.turn_id, active.user_message_seq)? {
            self.active_turn = None;
            admission.consumed = true;
            return Ok(());
        }

        let Some(reason) = cancellation_reason else {
            return Err(OxidraError::Session(format!(
                "turn {} returned successfully without a durable terminal or recovery owner",
                active.turn_id
            )));
        };
        let reason = bounded_status_text_v1(
            reason,
            MAX_TURN_STATUS_BYTES_V1,
            TURN_STATUS_EMPTY_V1,
            TURN_STATUS_TRUNCATION_SUFFIX_V1,
        );
        let mut planned_seq = self.next_seq();
        let cancelled = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "turn.cancelled",
            Some(&active.turn_id),
            json!({
                "reason": reason,
                "user_message_seq": active.user_message_seq,
                "turn_outcome_admission_version": 1,
            }),
        )?;
        let encoded_bytes = encoded_journal_events_bytes(&[cancelled.clone()])?;
        if encoded_bytes > active.headroom_bytes {
            return Err(OxidraError::Session(format!(
                "turn cancellation requires {encoded_bytes} bytes, exceeding its reserved {}-byte outcome headroom",
                active.headroom_bytes
            )));
        }
        let mut prospective = events;
        prospective.push(cancelled.clone());
        segment_turns(&prospective)?;
        self.append_prebuilt_batch_with_limit(&[cancelled], self.byte_limit)?;
        self.active_turn = None;
        admission.consumed = true;
        Ok(())
    }

    fn active_turn_v1(
        &self,
        admission: &TurnTransactionAdmissionV1,
    ) -> Result<&ActiveTurnReservationV1> {
        if admission.consumed {
            return Err(OxidraError::Session(
                "turn transaction admission was already consumed".to_owned(),
            ));
        }
        self.active_turn
            .as_ref()
            .filter(|active| active.reservation_id == admission.reservation_id)
            .ok_or_else(|| {
                OxidraError::Session(
                    "turn transaction admission does not match the active journal reservation"
                        .to_owned(),
                )
            })
    }

    /// Admit one Provider dispatch only after syncing `response.started` with
    /// a protected durable-outcome reserve. No other generic append is allowed
    /// until the returned capability commits exactly one response terminal.
    pub(crate) fn append_provider_response_started_v1(
        &mut self,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<ProviderResponseDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.active_provider_response.is_some() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a Provider response dispatch admission is already active".to_owned(),
            )));
        }
        if self.active_compaction.is_some() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a compaction dispatch admission is already active".to_owned(),
            )));
        }
        if let Some(active_turn) = &self.active_turn {
            if active_turn.turn_id != turn_id {
                return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "Provider response admission does not belong to the active turn transaction"
                        .to_owned(),
                )));
            }
        }
        let durable_prefix = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        ensure_provider_dispatch_recovery_profile_v1(&durable_prefix)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let response_attempt_id = data
            .get("response_attempt_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "response.started has no response_attempt_id for dispatch admission".to_owned(),
                ))
            })?
            .to_owned();
        let context = data.get("context").cloned().ok_or_else(|| {
            DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "response.started has no context snapshot for dispatch admission".to_owned(),
            ))
        })?;
        let response_started_seq = self.next_seq();
        validate_provider_context_limit_writer_input_v1(
            turn_id,
            &response_attempt_id,
            response_started_seq,
            &context,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        response_started_seq.checked_add(3).ok_or_else(|| {
            DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "journal sequence cannot represent a Provider outcome transaction".to_owned(),
            ))
        })?;

        let mut planned_seq = response_started_seq;
        let started = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.started",
            Some(turn_id),
            data,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let protected_headroom =
            self.active_turn
                .as_ref()
                .map_or(PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1, |turn| {
                    turn.headroom_bytes
                        .max(PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1)
                });
        let admission_limit = self
            .byte_limit
            .checked_sub(protected_headroom)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(OxidraError::Session(
                    format!(
                        "session journal cannot reserve the {protected_headroom}-byte Provider outcome headroom"
                    ),
                ))
            })?;
        if !self
            .preflight_prebuilt_batch_capacity(&[started.clone()], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?
        {
            return Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(
                OxidraError::Session(format!(
                    "session journal cannot append response.started while preserving the {protected_headroom}-byte Provider outcome headroom"
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(&[started], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let reservation_id = Uuid::now_v7().to_string();
        self.active_provider_response = Some(ActiveProviderResponseReservationV1 {
            reservation_id: reservation_id.clone(),
            turn_id: turn_id.to_owned(),
            response_attempt_id,
            response_started_seq,
            context,
            headroom_bytes: PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1,
        });
        Ok(ProviderResponseDispatchAdmissionV1 {
            reservation_id,
            consumed: false,
            reopen_required: Arc::clone(&self.reopen_required),
        })
    }

    pub(crate) fn append_provider_response_failed_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        error: &str,
    ) -> Result<JournalEvent> {
        let active = self.active_provider_response_v1(admission)?.clone();
        let error = provider_response_status_for_outcome_v1(error)?;
        let mut planned_seq = self.next_seq();
        let event = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.failed",
            Some(&active.turn_id),
            json!({
                "response_attempt_id": active.response_attempt_id,
                "error": error,
            }),
        )?;
        self.commit_provider_response_events_v1(admission, &[event.clone()], true)?;
        Ok(event)
    }

    pub(crate) fn append_provider_response_aborted_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        reason: &str,
    ) -> Result<JournalEvent> {
        let active = self.active_provider_response_v1(admission)?.clone();
        let reason = provider_response_status_for_outcome_v1(reason)?;
        let mut planned_seq = self.next_seq();
        let event = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.aborted",
            Some(&active.turn_id),
            json!({
                "response_attempt_id": active.response_attempt_id,
                "reason": reason,
            }),
        )?;
        self.commit_provider_response_events_v1(admission, &[event.clone()], true)?;
        Ok(event)
    }

    pub(crate) fn append_provider_response_completed_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        data: Value,
    ) -> Result<JournalEvent> {
        let active = self.active_provider_response_v1(admission)?.clone();
        if data.get("response_attempt_id").and_then(Value::as_str)
            != Some(active.response_attempt_id.as_str())
        {
            return Err(OxidraError::Session(
                "response.completed does not bind its admitted response attempt".to_owned(),
            ));
        }
        let mut planned_seq = self.next_seq();
        let event = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.completed",
            Some(&active.turn_id),
            data,
        )?;
        self.commit_provider_response_events_v1(admission, &[event.clone()], false)?;
        Ok(event)
    }

    /// Commit the crash-recoverable Provider context-limit protocol using the
    /// capacity protected before Provider code was dispatched.
    ///
    /// `response.failed` is serialized first as the authoritative intent. If
    /// this process stops after that complete line but before the audit event
    /// is durable, [`SessionStore::open`] reconstructs the exact
    /// `context.limit_reached` payload from the validated intent and its bound
    /// `response.started`.
    pub(crate) fn append_provider_context_limit_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        reason: &str,
    ) -> Result<(JournalEvent, JournalEvent)> {
        let active = self.active_provider_response_v1(admission)?.clone();
        validate_provider_context_limit_writer_input_v1(
            &active.turn_id,
            &active.response_attempt_id,
            active.response_started_seq,
            &active.context,
        )?;
        let error = provider_context_limit_error_for_journal_v1(reason);
        let mut planned_seq = self.next_seq();
        let failed = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.failed",
            Some(&active.turn_id),
            provider_context_limit_failed_data_v1(
                &active.response_attempt_id,
                active.response_started_seq,
                &error,
                active.context.clone(),
            ),
        )?;
        let limit = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "context.limit_reached",
            Some(&active.turn_id),
            provider_context_limit_event_data_v1(
                &active.response_attempt_id,
                failed.seq,
                &error,
                active.context,
            ),
        )?;
        let mut prospective = self.read_events()?;
        prospective.extend([failed.clone(), limit.clone()]);
        if !provider_context_limit_recovery_actions_v1(&prospective)?.is_empty() {
            return Err(OxidraError::Session(
                "provider context-limit writer did not construct a complete v1 transaction"
                    .to_owned(),
            ));
        }
        validate_provider_context_limit_turns_v1(&prospective, &HashSet::from([active.turn_id]))?;
        self.commit_provider_response_events_v1(admission, &[failed.clone(), limit.clone()], true)?;
        Ok((failed, limit))
    }

    fn active_provider_response_v1(
        &self,
        admission: &ProviderResponseDispatchAdmissionV1,
    ) -> Result<&ActiveProviderResponseReservationV1> {
        if admission.consumed {
            return Err(OxidraError::Session(
                "Provider response dispatch admission was already consumed".to_owned(),
            ));
        }
        self.active_provider_response
            .as_ref()
            .filter(|active| active.reservation_id == admission.reservation_id)
            .ok_or_else(|| {
                OxidraError::Session(
                    "Provider response dispatch admission does not match the active journal reservation"
                        .to_owned(),
                )
            })
    }

    fn commit_provider_response_events_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        events: &[JournalEvent],
        must_fit_headroom: bool,
    ) -> Result<()> {
        let active = self.active_provider_response_v1(admission)?.clone();
        let encoded_bytes = encoded_journal_events_bytes(events)?;
        if must_fit_headroom && encoded_bytes > active.headroom_bytes {
            return Err(OxidraError::Session(format!(
                "Provider response terminal requires {encoded_bytes} bytes, exceeding its reserved {}-byte durable outcome headroom",
                active.headroom_bytes
            )));
        }
        let byte_limit = if must_fit_headroom {
            self.byte_limit
        } else {
            self.generic_append_byte_limit_v1()?
        };
        self.append_prebuilt_batch_with_limit(events, byte_limit)?;
        self.active_provider_response = None;
        admission.consumed = true;
        Ok(())
    }

    /// Admit one compaction Provider dispatch after syncing the exact
    /// `compaction.started` intent while protecting a bounded failure/recovery
    /// transaction. Boundary-owned attempts bind that same durable boundary
    /// into the capability.
    pub(crate) fn append_compaction_started_v1(
        &mut self,
        data: Value,
    ) -> std::result::Result<CompactionProviderDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.active_provider_response.is_some() || self.active_compaction.is_some() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a Provider dispatch admission is already active".to_owned(),
            )));
        }
        let attempt_id = data
            .get("attempt_id")
            .and_then(Value::as_str)
            .filter(|value| valid_provider_context_limit_identity_v1(value))
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "compaction.started has no valid attempt_id for dispatch admission".to_owned(),
                ))
            })?
            .to_owned();
        let boundary = data.get("boundary").cloned();
        if let Some(active_turn) = &self.active_turn {
            let boundary_turn_id = boundary
                .as_ref()
                .and_then(|value| value.get("turn_id"))
                .and_then(Value::as_str);
            let boundary_user_seq = boundary
                .as_ref()
                .and_then(|value| value.get("user_message_seq"))
                .and_then(Value::as_u64);
            if boundary_turn_id != Some(active_turn.turn_id.as_str())
                || boundary_user_seq != Some(active_turn.user_message_seq)
            {
                return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "compaction dispatch does not bind the active turn transaction".to_owned(),
                )));
            }
        }

        let durable_prefix = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        ensure_compaction_dispatch_recovery_profile_v1(&durable_prefix, boundary.as_ref())
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let started_seq = self.next_seq();
        started_seq.checked_add(3).ok_or_else(|| {
            DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "journal sequence cannot represent a compaction outcome transaction".to_owned(),
            ))
        })?;
        let mut planned_seq = started_seq;
        let started = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            COMPACTION_STARTED_KIND,
            None,
            data,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let mut prospective = durable_prefix;
        prospective.push(started.clone());
        validate_checkpoint_chain(&prospective).map_err(DispatchAdmissionErrorV1::Fatal)?;
        validate_compaction_boundary_chain(&prospective)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let protected_headroom =
            self.active_turn
                .as_ref()
                .map_or(COMPACTION_OUTCOME_HEADROOM_BYTES_V1, |turn| {
                    turn.headroom_bytes
                        .max(COMPACTION_OUTCOME_HEADROOM_BYTES_V1)
                });
        let admission_limit = self
            .byte_limit
            .checked_sub(protected_headroom)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(OxidraError::Session(
                    format!(
                        "session journal cannot reserve the {protected_headroom}-byte compaction outcome headroom"
                    ),
                ))
            })?;
        if !self
            .preflight_prebuilt_batch_capacity(&[started.clone()], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?
        {
            return Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(
                OxidraError::Session(format!(
                    "session journal cannot append compaction.started while preserving the {protected_headroom}-byte compaction outcome headroom"
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(&[started], admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let reservation_id = Uuid::now_v7().to_string();
        self.active_compaction = Some(ActiveCompactionReservationV1 {
            reservation_id: reservation_id.clone(),
            attempt_id,
            started_seq,
            boundary,
            headroom_bytes: COMPACTION_OUTCOME_HEADROOM_BYTES_V1,
        });
        Ok(CompactionProviderDispatchAdmissionV1 {
            reservation_id,
            consumed: false,
            reopen_required: Arc::clone(&self.reopen_required),
        })
    }

    /// Commit one complete compaction attempt transaction. Capacity denial is
    /// reported before the first byte so the caller may consume the same
    /// capability with a bounded failure fallback; all other failures are
    /// fatal and must not trigger a second write attempt.
    pub(crate) fn commit_compaction_outcome_v1(
        &mut self,
        admission: &mut CompactionProviderDispatchAdmissionV1,
        compaction_kind: &str,
        compaction_data: Value,
        boundary_terminal: Option<(&str, Value)>,
        must_fit_headroom: bool,
    ) -> std::result::Result<Vec<JournalEvent>, DurableOutcomeCommitErrorV1> {
        let active = self
            .active_compaction_v1(admission)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
            .clone();
        if !matches!(
            compaction_kind,
            COMPACTION_CHECKPOINT_KIND | COMPACTION_FAILED_KIND | COMPACTION_ABORTED_KIND
        ) {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "invalid compaction outcome kind".to_owned(),
            )));
        }
        if compaction_data.get("attempt_id").and_then(Value::as_str)
            != Some(active.attempt_id.as_str())
        {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "compaction outcome does not bind its admitted attempt".to_owned(),
            )));
        }
        if compaction_kind != COMPACTION_CHECKPOINT_KIND
            && compaction_data.get("started_seq").and_then(Value::as_u64)
                != Some(active.started_seq)
        {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "compaction failure does not bind its exact admitted start".to_owned(),
            )));
        }
        if active.boundary.is_some() != boundary_terminal.is_some() {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "compaction outcome does not settle its admitted boundary".to_owned(),
            )));
        }

        let mut planned_seq = self.next_seq();
        let terminal = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            compaction_kind,
            None,
            compaction_data,
        )
        .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let mut events = vec![terminal];
        if let Some((kind, data)) = boundary_terminal {
            events.push(
                planned_recovery_event(self.session_id(), &mut planned_seq, kind, None, data)
                    .map_err(DurableOutcomeCommitErrorV1::Fatal)?,
            );
        }

        let mut prospective = self
            .read_events()
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        prospective.extend(events.iter().cloned());
        validate_checkpoint_chain(&prospective).map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        validate_compaction_boundary_chain(&prospective)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let encoded_bytes =
            encoded_journal_events_bytes(&events).map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        if must_fit_headroom && encoded_bytes > active.headroom_bytes {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                format!(
                    "bounded compaction outcome requires {encoded_bytes} bytes, exceeding its reserved {}-byte headroom",
                    active.headroom_bytes
                ),
            )));
        }
        if !self
            .preflight_prebuilt_batch_capacity(&events, self.byte_limit)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
        {
            return Err(DurableOutcomeCommitErrorV1::CapacityDenied(
                OxidraError::Session(format!(
                    "compaction outcome transaction would exceed the {}-byte safety limit",
                    self.byte_limit
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(&events, self.byte_limit)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        self.active_compaction = None;
        admission.consumed = true;
        Ok(events)
    }

    fn active_compaction_v1(
        &self,
        admission: &CompactionProviderDispatchAdmissionV1,
    ) -> Result<&ActiveCompactionReservationV1> {
        if admission.consumed {
            return Err(OxidraError::Session(
                "compaction dispatch admission was already consumed".to_owned(),
            ));
        }
        self.active_compaction
            .as_ref()
            .filter(|active| active.reservation_id == admission.reservation_id)
            .ok_or_else(|| {
                OxidraError::Session(
                    "compaction dispatch admission does not match the active journal reservation"
                        .to_owned(),
                )
            })
    }

    /// Append a fully prebuilt durable transaction after proving the exact
    /// encoded batch fits. No journal byte is written when the reservation
    /// fails, and successful batches use one durability barrier.
    fn append_prebuilt_batch(&mut self, events: &[JournalEvent]) -> Result<()> {
        self.append_prebuilt_batch_with_limit(events, self.byte_limit)
    }

    /// Validate and size a prebuilt transaction without writing any byte.
    /// `false` is the only capacity-denial result; malformed state,
    /// serialization, metadata, and I/O failures remain fatal and must not be
    /// rewritten by callers as a benign admission denial.
    fn preflight_prebuilt_batch_capacity(
        &mut self,
        events: &[JournalEvent],
        byte_limit: u64,
    ) -> Result<bool> {
        self.ensure_healthy()?;
        if events.is_empty() {
            return Ok(true);
        }
        let mut expected_seq = self.next_seq;
        for event in events {
            if event.schema != JOURNAL_SCHEMA
                || event.session_id != self.session_id
                || event.seq != expected_seq
                || event.kind.trim().is_empty()
            {
                return Err(OxidraError::Session(
                    "invalid prebuilt journal transaction".to_owned(),
                ));
            }
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
        }
        let encoded_bytes = encoded_journal_events_bytes(events)?;
        let metadata_result = self.file.metadata();
        let current_size = self.finish_io(metadata_result)?.len();
        Ok(current_size
            .checked_add(encoded_bytes)
            .is_some_and(|size| size <= byte_limit))
    }

    fn append_prebuilt_batch_with_limit(
        &mut self,
        events: &[JournalEvent],
        byte_limit: u64,
    ) -> Result<()> {
        self.ensure_healthy()?;
        if events.is_empty() {
            return Ok(());
        }

        let mut expected_seq = self.next_seq;
        let mut encoded_bytes = 0u64;
        for event in events {
            if event.schema != JOURNAL_SCHEMA
                || event.session_id != self.session_id
                || event.seq != expected_seq
                || event.kind.trim().is_empty()
            {
                return Err(OxidraError::Session(
                    "invalid prebuilt journal transaction".to_owned(),
                ));
            }
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
            let event_len = u64::try_from(serde_json::to_vec(event)?.len())
                .map_err(|_| OxidraError::Session("recovery event is too large".to_owned()))?;
            encoded_bytes = encoded_bytes
                .checked_add(event_len)
                .and_then(|size| size.checked_add(1))
                .ok_or_else(|| {
                    OxidraError::Session("journal transaction size overflow".to_owned())
                })?;
        }

        let metadata_result = self.file.metadata();
        let current_size = self.finish_io(metadata_result)?.len();
        if current_size
            .checked_add(encoded_bytes)
            .is_none_or(|size| size > byte_limit)
        {
            return Err(OxidraError::Session(format!(
                "session journal transaction would exceed the {byte_limit}-byte safety limit"
            )));
        }

        // The exact reservation above is complete before this first seek or
        // write. Callers must order events so every complete-line prefix is
        // replayable: recovery markers precede the skips they authorize, and
        // the Provider context-limit intent precedes its derived audit event.
        let seek_result = self.file.seek(SeekFrom::End(0));
        self.finish_io(seek_result)?;
        for event in events {
            let encoded = serde_json::to_vec(event)?;
            let write_result = self.file.write_all(&encoded);
            self.finish_io(write_result)?;
            let newline_result = self.file.write_all(b"\n");
            self.finish_io(newline_result)?;
        }
        self.next_seq = expected_seq;
        self.sync()
    }

    pub fn flush(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        let flush_result = self.file.flush();
        self.finish_io(flush_result)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.flush()?;
        let sync_result = self.file.sync_data();
        self.finish_io(sync_result)
    }

    pub fn read_events(&self) -> Result<Vec<JournalEvent>> {
        self.ensure_healthy()?;
        ensure_journal_size(&self.journal_path)?;
        let bytes = fs::read(&self.journal_path)?;
        parse_complete_events(&bytes, &self.session_id)
    }

    pub fn read_raw_events(&self) -> Result<Vec<Value>> {
        self.ensure_healthy()?;
        ensure_journal_size(&self.journal_path)?;
        let bytes = fs::read(&self.journal_path)?;
        parse_json_lines(&bytes)
    }

    pub fn in_doubt(&self) -> Result<Vec<InDoubtTool>> {
        Ok(pending_tools(&self.read_events()?))
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(OxidraError::Session(
                "journal write state is indeterminate after an I/O error; close and reopen the session"
                    .to_owned(),
            ));
        }
        if self.reopen_required.load(Ordering::Acquire) {
            return Err(OxidraError::Session(
                "a durable transaction capability was dropped before terminalization; close and reopen the session"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn finish_io<T>(&mut self, result: std::io::Result<T>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                // A write may have reached the page cache even when flush or
                // fsync reports failure. Do not let this process decide that
                // the visible bytes are a committed event; recovery owns that
                // decision after this handle is closed.
                self.poisoned = true;
                Err(error.into())
            }
        }
    }
}

pub fn user_data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(path) = nonempty_env_path("LOCALAPPDATA") {
            return Ok(path.join("oxidra"));
        }
        let base = directories::BaseDirs::new().ok_or_else(|| {
            OxidraError::Session("could not determine the Windows user data directory".to_owned())
        })?;
        return Ok(base.data_local_dir().join("oxidra"));
    }

    #[cfg(target_os = "macos")]
    {
        let base = directories::BaseDirs::new().ok_or_else(|| {
            OxidraError::Session("could not determine the macOS home directory".to_owned())
        })?;
        return Ok(base.home_dir().join("Library/Application Support/oxidra"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(path) = nonempty_env_path("XDG_STATE_HOME").filter(|path| path.is_absolute()) {
            return Ok(path.join("oxidra"));
        }
        let base = directories::BaseDirs::new().ok_or_else(|| {
            OxidraError::Session("could not determine the Unix home directory".to_owned())
        })?;
        return Ok(base.home_dir().join(".local/state/oxidra"));
    }

    #[allow(unreachable_code)]
    Err(OxidraError::Session(
        "unsupported platform for session storage".to_owned(),
    ))
}

#[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn validate_session_id(session_id: &str) -> Result<()> {
    let valid = !session_id.is_empty()
        && session_id.len() <= 128
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(OxidraError::Session(format!(
            "invalid session id: {session_id:?}"
        )))
    }
}

fn acquire_lock(layout: &SessionLayout, session_id: &str) -> Result<File> {
    let path = layout.lock_path(session_id)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.try_lock_exclusive().map_err(|error| {
        OxidraError::Session(format!(
            "session {session_id} is already open by another writer: {error}"
        ))
    })?;
    Ok(file)
}

struct JournalScan {
    events: Vec<JournalEvent>,
    truncated_tail: Option<TruncatedTail>,
    normalized_missing_newline: bool,
}

fn scan_and_repair_tail(file: &mut File, session_id: &str) -> Result<JournalScan> {
    let size = file.metadata()?.len();
    if size > MAX_SESSION_BYTES {
        return Err(OxidraError::Session(format!(
            "session journal exceeds the {MAX_SESSION_BYTES}-byte safety limit"
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    let ends_with_newline = bytes.last().is_none_or(|byte| *byte == b'\n');
    let last_newline = bytes.iter().rposition(|byte| *byte == b'\n');
    let complete_len = last_newline.map_or(0, |position| position + 1);
    let tail = &bytes[complete_len..];
    let mut truncated_tail = None;
    let mut normalized_missing_newline = false;

    let valid_len = if tail.is_empty() {
        bytes.len()
    } else if serde_json::from_slice::<JournalEvent>(tail).is_ok() {
        normalized_missing_newline = true;
        bytes.len()
    } else {
        truncated_tail = Some(TruncatedTail {
            byte_count: tail.len() as u64,
            sha256: hex::encode(Sha256::digest(tail)),
        });
        complete_len
    };

    if truncated_tail.is_some() {
        file.set_len(valid_len as u64)?;
        file.seek(SeekFrom::End(0))?;
        file.sync_data()?;
    } else if !ends_with_newline && !bytes.is_empty() {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
        file.sync_data()?;
    }

    let events = parse_complete_events(&bytes[..valid_len], session_id)?;
    Ok(JournalScan {
        events,
        truncated_tail,
        normalized_missing_newline,
    })
}

fn ensure_journal_size(path: &Path) -> Result<()> {
    let size = fs::metadata(path)?.len();
    if size > MAX_SESSION_BYTES {
        return Err(OxidraError::Session(format!(
            "session journal exceeds the {MAX_SESSION_BYTES}-byte safety limit"
        )));
    }
    Ok(())
}

fn parse_complete_events(bytes: &[u8], session_id: &str) -> Result<Vec<JournalEvent>> {
    let mut events = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let event = serde_json::from_slice(line).map_err(|error| {
            OxidraError::Session(format!(
                "invalid JSON in session {session_id} at line {}: {error}",
                index + 1
            ))
        })?;
        events.push(event);
    }
    validate_events(&events, session_id)?;
    Ok(events)
}

fn parse_json_lines(bytes: &[u8]) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        values.push(serde_json::from_slice(line).map_err(|error| {
            OxidraError::Session(format!(
                "invalid journal JSON at line {}: {error}",
                index + 1
            ))
        })?);
    }
    Ok(values)
}

fn validate_events(events: &[JournalEvent], session_id: &str) -> Result<()> {
    let mut previous_seq = None;
    for event in events {
        if event.schema != JOURNAL_SCHEMA {
            return Err(OxidraError::Session(format!(
                "unsupported journal schema {} at seq {}",
                event.schema, event.seq
            )));
        }
        if event.session_id != session_id {
            return Err(OxidraError::Session(format!(
                "journal session id mismatch at seq {}: expected {session_id}, got {}",
                event.seq, event.session_id
            )));
        }
        if previous_seq.is_some_and(|previous| event.seq <= previous) {
            return Err(OxidraError::Session(format!(
                "journal sequence is not strictly increasing at seq {}",
                event.seq
            )));
        }
        previous_seq = Some(event.seq);
    }
    Ok(())
}

fn pending_tools(events: &[JournalEvent]) -> Vec<InDoubtTool> {
    let mut pending = BTreeMap::<u64, InDoubtTool>::new();
    // A malformed/provider-replayed response may reuse a call_id. Keep all
    // sequence numbers instead of letting a later call erase earlier
    // in-doubt evidence.
    let mut call_ids = HashMap::<(Option<String>, String), PendingCallSequences>::new();

    for event in events {
        match event.kind.as_str() {
            "tool.started" => {
                let call_id = string_field(&event.data, &["call_id", "id"]);
                let tool = InDoubtTool {
                    started_seq: event.seq,
                    turn_id: event.turn_id.clone(),
                    call_id: call_id.clone(),
                    tool_name: string_field(&event.data, &["name", "tool_name", "tool"]),
                    arguments: event.data.get("arguments").cloned(),
                    data: event.data.clone(),
                };
                if let Some(call_id) = call_id {
                    call_ids
                        .entry((event.turn_id.clone(), call_id))
                        .or_default()
                        .insert(event.seq);
                }
                pending.insert(event.seq, tool);
            }
            "tool.in_doubt" => {
                record_in_doubt_tool(event, &mut pending, &mut call_ids);
            }
            kind if is_tool_terminal(kind) => {
                resolve_tool(event, &mut pending, &mut call_ids);
            }
            _ => {}
        }
    }
    pending.into_values().collect()
}

fn record_in_doubt_tool(
    event: &JournalEvent,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut HashMap<(Option<String>, String), PendingCallSequences>,
) {
    let call_id = string_field(&event.data, &["call_id", "id"]);
    let identity = call_id
        .as_ref()
        .map(|call_id| (event.turn_id.clone(), call_id.clone()));
    let referenced_seq = event.data.get("started_seq").and_then(Value::as_u64);
    let existing_seq = referenced_seq
        .filter(|seq| {
            pending.get(seq).is_some_and(|tool| {
                pending_tool_matches_event_identity(tool, event, call_id.as_deref())
            })
        })
        .or_else(|| {
            identity.as_ref().and_then(|identity| {
                call_ids
                    .get_mut(identity)
                    .and_then(PendingCallSequences::latest)
            })
        });

    if let Some(started_seq) = existing_seq {
        let updated_ids = pending.get_mut(&started_seq).map(|tool| {
            let previous_turn_id = tool.turn_id.clone();
            let previous_call_id = tool.call_id.clone();
            tool.turn_id = event.turn_id.clone().or_else(|| tool.turn_id.clone());
            tool.call_id = call_id.or_else(|| tool.call_id.clone());
            tool.tool_name = string_field(&event.data, &["name", "tool_name", "tool"])
                .or_else(|| tool.tool_name.clone());
            tool.arguments = event
                .data
                .get("arguments")
                .cloned()
                .or_else(|| tool.arguments.clone());
            tool.data = event.data.clone();
            (
                previous_turn_id,
                previous_call_id,
                tool.turn_id.clone(),
                tool.call_id.clone(),
            )
        });
        if let Some((previous_turn_id, previous_call_id, current_turn_id, current_call_id)) =
            updated_ids
        {
            if previous_turn_id != current_turn_id || previous_call_id != current_call_id {
                if let Some(previous_call_id) = previous_call_id {
                    remove_call_id_seq(
                        call_ids,
                        &(previous_turn_id, previous_call_id),
                        started_seq,
                    );
                }
                if let Some(current_call_id) = current_call_id {
                    call_ids
                        .entry((current_turn_id, current_call_id))
                        .or_default()
                        .insert(started_seq);
                }
            }
        }
        return;
    }

    let started_seq = referenced_seq.unwrap_or(event.seq);
    let tool = InDoubtTool {
        started_seq,
        turn_id: event.turn_id.clone(),
        call_id: call_id.clone(),
        tool_name: string_field(&event.data, &["name", "tool_name", "tool"]),
        arguments: event.data.get("arguments").cloned(),
        data: event.data.clone(),
    };
    if let Some(call_id) = call_id {
        call_ids
            .entry((event.turn_id.clone(), call_id))
            .or_default()
            .insert(started_seq);
    }
    pending.insert(started_seq, tool);
}

fn resolve_tool(
    event: &JournalEvent,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut HashMap<(Option<String>, String), PendingCallSequences>,
) {
    let data = &event.data;
    let call_id = string_field(data, &["call_id", "id"]);
    if let Some(started_seq) = data.get("started_seq").and_then(Value::as_u64) {
        let matches_identity = pending.get(&started_seq).is_some_and(|tool| {
            pending_tool_matches_event_identity(tool, event, call_id.as_deref())
        });
        if matches_identity {
            let tool = pending
                .remove(&started_seq)
                .expect("checked pending tool identity");
            if let Some(call_id) = tool.call_id {
                remove_call_id_seq(call_ids, &(tool.turn_id, call_id), started_seq);
            }
        }
        return;
    }
    if let Some(call_id) = call_id {
        let identity = (event.turn_id.clone(), call_id);
        if let Some(started_seq) = call_ids
            .get_mut(&identity)
            .and_then(PendingCallSequences::latest)
        {
            remove_call_id_seq(call_ids, &identity, started_seq);
            pending.remove(&started_seq);
        }
    }
}

fn pending_tool_matches_event_identity(
    tool: &InDoubtTool,
    event: &JournalEvent,
    event_call_id: Option<&str>,
) -> bool {
    tool.turn_id == event.turn_id
        && event_call_id.is_none_or(|call_id| tool.call_id.as_deref() == Some(call_id))
}

#[derive(Default)]
struct PendingCallSequences {
    insertion_order: Vec<u64>,
    active: HashSet<u64>,
}

impl PendingCallSequences {
    fn insert(&mut self, seq: u64) {
        self.insertion_order.push(seq);
        self.active.insert(seq);
    }

    fn remove(&mut self, seq: u64) {
        self.active.remove(&seq);
    }

    fn latest(&mut self) -> Option<u64> {
        while self
            .insertion_order
            .last()
            .is_some_and(|seq| !self.active.contains(seq))
        {
            self.insertion_order.pop();
        }
        self.insertion_order.last().copied()
    }

    fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

fn remove_call_id_seq(
    call_ids: &mut HashMap<(Option<String>, String), PendingCallSequences>,
    identity: &(Option<String>, String),
    seq: u64,
) {
    let empty = {
        let Some(sequences) = call_ids.get_mut(identity) else {
            return;
        };
        sequences.remove(seq);
        sequences.is_empty()
    };
    if empty {
        call_ids.remove(identity);
    }
}

fn string_field(data: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| data.get(*field).and_then(Value::as_str))
        .map(str::to_owned)
}

fn valid_provider_context_limit_identity_v1(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn bounded_status_text_v1(input: &str, max_bytes: usize, empty: &str, suffix: &str) -> String {
    let input = if input.is_empty() { empty } else { input };
    if input.len() <= max_bytes {
        return input.to_owned();
    }

    let mut end = max_bytes.saturating_sub(suffix.len()).min(input.len());
    while !input.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut output = input[..end].to_owned();
    output.push_str(suffix);
    output
}

fn provider_context_limit_error_for_journal_v1(input: &str) -> String {
    bounded_status_text_v1(
        input,
        MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1,
        PROVIDER_CONTEXT_LIMIT_EMPTY_ERROR_V1,
        PROVIDER_CONTEXT_LIMIT_TRUNCATION_SUFFIX_V1,
    )
}

fn provider_response_status_for_outcome_v1(input: &str) -> Result<String> {
    let status = response_status_text_for_journal(input);
    if status.len() > MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1 {
        return Err(OxidraError::Session(format!(
            "response status exceeds the frozen {MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1}-byte Provider outcome profile"
        )));
    }
    Ok(status)
}

fn valid_provider_context_limit_error_v1(value: &str) -> bool {
    provider_context_limit_error_for_journal_v1(value) == value
}

fn valid_provider_context_limit_context_v1(context: &Value) -> bool {
    context.is_object()
        && serde_json::to_vec(context)
            .is_ok_and(|encoded| encoded.len() <= MAX_PROVIDER_CONTEXT_LIMIT_CONTEXT_BYTES_V1)
}

fn validate_provider_context_limit_writer_input_v1(
    turn_id: &str,
    response_attempt_id: &str,
    response_started_seq: u64,
    context: &Value,
) -> Result<()> {
    if !valid_provider_context_limit_identity_v1(turn_id) {
        return Err(OxidraError::Session(
            "provider context-limit intent has an invalid turn_id".to_owned(),
        ));
    }
    if !valid_provider_context_limit_identity_v1(response_attempt_id) {
        return Err(OxidraError::Session(
            "provider context-limit intent has an invalid response_attempt_id".to_owned(),
        ));
    }
    if response_started_seq == 0 {
        return Err(OxidraError::Session(
            "provider context-limit intent has an invalid response_started_seq".to_owned(),
        ));
    }
    if !valid_provider_context_limit_context_v1(context) {
        return Err(OxidraError::Session(
            "provider context-limit intent context must be a bounded object".to_owned(),
        ));
    }
    Ok(())
}

fn provider_context_limit_failed_data_v1(
    response_attempt_id: &str,
    response_started_seq: u64,
    error: &str,
    context: Value,
) -> Value {
    json!({
        "response_attempt_id": response_attempt_id,
        "response_started_seq": response_started_seq,
        "error": error,
        "error_code": PROVIDER_CONTEXT_LIMIT_ERROR_CODE,
        "provider_context_limit_intent_version": PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1,
        "context": context,
    })
}

fn provider_context_limit_event_data_v1(
    response_attempt_id: &str,
    provider_context_limit_intent_seq: u64,
    error: &str,
    context: Value,
) -> Value {
    json!({
        "error": error,
        "source": "provider",
        "response_attempt_id": response_attempt_id,
        "context": context,
        "provider_context_limit_intent_version": PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1,
        "provider_context_limit_intent_seq": provider_context_limit_intent_seq,
    })
}

#[derive(Clone, Debug, PartialEq)]
struct ProviderContextLimitRecoveryAction {
    turn_id: String,
    data: Value,
}

#[derive(Clone, Debug)]
struct ValidatedProviderContextLimitIntentV1 {
    failed_seq: u64,
    turn_id: String,
    response_attempt_id: String,
    error: String,
    context: Value,
}

/// Validate the complete provider context-limit transaction and return only
/// the audit events that are absent from an otherwise valid crash prefix.
///
/// Legacy `response.failed(error_code=provider_context_limit)` events without
/// the versioned intent field retain their historical meaning. Once any v1
/// intent field is present, however, the literal v1 profile is authoritative
/// and unknown or partial profiles fail before recovery writes begin.
fn provider_context_limit_recovery_actions_v1(
    events: &[JournalEvent],
) -> Result<Vec<ProviderContextLimitRecoveryAction>> {
    type Identity = (String, String);

    let mut starts = HashMap::<Identity, Vec<&JournalEvent>>::new();
    let mut terminals = HashMap::<Identity, Vec<&JournalEvent>>::new();
    for event in events {
        if !matches!(
            event.kind.as_str(),
            "response.started" | "response.completed" | "response.failed" | "response.aborted"
        ) {
            continue;
        }
        let (Some(turn_id), Some(response_attempt_id)) = (
            event.turn_id.as_deref(),
            event
                .data
                .get("response_attempt_id")
                .and_then(Value::as_str),
        ) else {
            continue;
        };
        let identity = (turn_id.to_owned(), response_attempt_id.to_owned());
        if event.kind == "response.started" {
            starts.entry(identity).or_default().push(event);
        } else {
            terminals.entry(identity).or_default().push(event);
        }
    }

    let mut intents = BTreeMap::<u64, ValidatedProviderContextLimitIntentV1>::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "response.failed")
    {
        let Some(data) = event.data.as_object() else {
            continue;
        };
        let has_version = data.contains_key(PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD);
        let has_started_seq = data.contains_key(PROVIDER_CONTEXT_LIMIT_STARTED_SEQ_FIELD);
        if !has_version {
            if has_started_seq {
                return Err(OxidraError::Session(format!(
                    "response.failed at seq {} carries a partial provider context-limit intent",
                    event.seq
                )));
            }
            continue;
        }
        let version = data
            .get(PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "response.failed at seq {} has no provider context-limit intent version",
                    event.seq
                ))
            })?;
        if version != PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1 {
            return Err(OxidraError::Session(format!(
                "unsupported provider context-limit intent version {version} at seq {}",
                event.seq
            )));
        }
        let turn_id = event
            .turn_id
            .as_deref()
            .filter(|value| valid_provider_context_limit_identity_v1(value))
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "provider context-limit intent at seq {} has no valid turn_id",
                    event.seq
                ))
            })?;
        let response_attempt_id = data
            .get("response_attempt_id")
            .and_then(Value::as_str)
            .filter(|value| valid_provider_context_limit_identity_v1(value))
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "provider context-limit intent at seq {} has no valid response_attempt_id",
                    event.seq
                ))
            })?;
        let response_started_seq = data
            .get(PROVIDER_CONTEXT_LIMIT_STARTED_SEQ_FIELD)
            .and_then(Value::as_u64)
            .filter(|seq| *seq > 0)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "provider context-limit intent at seq {} has no valid response_started_seq",
                    event.seq
                ))
            })?;
        let error = data
            .get("error")
            .and_then(Value::as_str)
            .filter(|value| valid_provider_context_limit_error_v1(value))
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "provider context-limit intent at seq {} has no bounded non-empty error",
                    event.seq
                ))
            })?;
        if data.get("error_code").and_then(Value::as_str) != Some(PROVIDER_CONTEXT_LIMIT_ERROR_CODE)
        {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} has the wrong error_code",
                event.seq
            )));
        }
        let context = data
            .get("context")
            .filter(|value| valid_provider_context_limit_context_v1(value))
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "provider context-limit intent at seq {} has no bounded context object",
                    event.seq
                ))
            })?;
        let expected = provider_context_limit_failed_data_v1(
            response_attempt_id,
            response_started_seq,
            error,
            context.clone(),
        );
        if event.data != expected {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} does not match the frozen v1 profile",
                event.seq
            )));
        }

        let identity = (turn_id.to_owned(), response_attempt_id.to_owned());
        let matching_starts = starts.get(&identity).map(Vec::as_slice).unwrap_or_default();
        if matching_starts.len() != 1 || matching_starts[0].seq != response_started_seq {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} does not bind one exact response.started seq {}",
                event.seq, response_started_seq
            )));
        }
        let start = matching_starts[0];
        if start.seq >= event.seq || start.data.get("context") != Some(context) {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} does not inherit its response.started context",
                event.seq
            )));
        }
        let matching_terminals = terminals
            .get(&identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if matching_terminals.len() != 1 || matching_terminals[0].seq != event.seq {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} is not the unique response terminal",
                event.seq
            )));
        }
        intents.insert(
            event.seq,
            ValidatedProviderContextLimitIntentV1 {
                failed_seq: event.seq,
                turn_id: turn_id.to_owned(),
                response_attempt_id: response_attempt_id.to_owned(),
                error: error.to_owned(),
                context: context.clone(),
            },
        );
    }

    let mut limits_by_identity = HashMap::<Identity, Vec<&JournalEvent>>::new();
    let mut completed_intents = HashMap::<u64, &JournalEvent>::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "context.limit_reached")
    {
        let Some(data) = event.data.as_object() else {
            continue;
        };
        if let (Some(turn_id), Some(response_attempt_id)) = (
            event.turn_id.as_deref(),
            data.get("response_attempt_id").and_then(Value::as_str),
        ) {
            limits_by_identity
                .entry((turn_id.to_owned(), response_attempt_id.to_owned()))
                .or_default()
                .push(event);
        }

        let has_version = data.contains_key(PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD);
        let has_intent_seq = data.contains_key(PROVIDER_CONTEXT_LIMIT_INTENT_SEQ_FIELD);
        if !has_version && !has_intent_seq {
            continue;
        }
        if !has_version || !has_intent_seq {
            return Err(OxidraError::Session(format!(
                "context.limit_reached at seq {} carries a partial provider context-limit intent binding",
                event.seq
            )));
        }
        let version = data
            .get(PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "context.limit_reached at seq {} has no provider context-limit intent version",
                    event.seq
                ))
            })?;
        if version != PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1 {
            return Err(OxidraError::Session(format!(
                "unsupported provider context-limit intent version {version} at seq {}",
                event.seq
            )));
        }
        let intent_seq = data
            .get(PROVIDER_CONTEXT_LIMIT_INTENT_SEQ_FIELD)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "context.limit_reached at seq {} has no provider context-limit intent seq",
                    event.seq
                ))
            })?;
        let intent = intents.get(&intent_seq).ok_or_else(|| {
            OxidraError::Session(format!(
                "context.limit_reached at seq {} references unknown provider context-limit intent seq {intent_seq}",
                event.seq
            ))
        })?;
        if event.turn_id.as_deref() != Some(intent.turn_id.as_str())
            || event.seq <= intent.failed_seq
        {
            return Err(OxidraError::Session(format!(
                "context.limit_reached at seq {} does not follow its exact provider context-limit intent",
                event.seq
            )));
        }
        let expected = provider_context_limit_event_data_v1(
            &intent.response_attempt_id,
            intent.failed_seq,
            &intent.error,
            intent.context.clone(),
        );
        if event.data != expected {
            return Err(OxidraError::Session(format!(
                "context.limit_reached at seq {} does not match its frozen provider context-limit intent",
                event.seq
            )));
        }
        if completed_intents.insert(intent_seq, event).is_some() {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {intent_seq} has more than one context.limit_reached event"
            )));
        }
    }

    let mut actions = Vec::new();
    for intent in intents.values() {
        let identity = (intent.turn_id.clone(), intent.response_attempt_id.clone());
        let matching_limits = limits_by_identity
            .get(&identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if matching_limits.is_empty() {
            actions.push(ProviderContextLimitRecoveryAction {
                turn_id: intent.turn_id.clone(),
                data: provider_context_limit_event_data_v1(
                    &intent.response_attempt_id,
                    intent.failed_seq,
                    &intent.error,
                    intent.context.clone(),
                ),
            });
            continue;
        }
        if matching_limits.len() != 1
            || completed_intents
                .get(&intent.failed_seq)
                .is_none_or(|event| event.seq != matching_limits[0].seq)
        {
            return Err(OxidraError::Session(format!(
                "provider context-limit intent at seq {} has an ambiguous context.limit_reached projection",
                intent.failed_seq
            )));
        }
    }
    Ok(actions)
}

fn validate_provider_context_limit_turns_v1(
    events: &[JournalEvent],
    turn_ids: &HashSet<String>,
) -> Result<()> {
    if turn_ids.is_empty() {
        return Ok(());
    }
    let mut scoped = HashMap::<&str, Vec<JournalEvent>>::new();
    for event in events {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        if turn_ids.contains(turn_id) {
            scoped.entry(turn_id).or_default().push(event.clone());
        }
    }
    for turn_id in turn_ids {
        let events = scoped
            .get(turn_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        crate::turn::validate_turn_recovery(events).map_err(|error| {
            OxidraError::Session(format!(
                "provider context-limit transaction for turn {turn_id} fails the canonical turn recovery reducer: {error}"
            ))
        })?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct UnstartedTool {
    response_seq: u64,
    turn_id: Option<String>,
    call_id: String,
    tool_name: Option<String>,
    arguments: Option<Value>,
}

#[derive(Clone, Debug)]
struct UnfinishedResponse {
    started_seq: u64,
    turn_id: Option<String>,
    response_attempt_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnfinishedCompaction {
    started_seq: u64,
    attempt_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverableOpenTurnV1 {
    turn_id: String,
    user_message_seq: u64,
}

fn turn_transaction_is_settled_v1(
    events: &[JournalEvent],
    turn_id: &str,
    user_message_seq: u64,
) -> Result<bool> {
    let turns = segment_turns(events)?;
    let turn = turns
        .iter()
        .find(|turn| turn.turn_id == turn_id)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "turn transaction {turn_id} has no durable user.message"
            ))
        })?;
    if turn.covers_from_seq != user_message_seq {
        return Err(OxidraError::Session(format!(
            "turn transaction {turn_id} expected user.message seq {user_message_seq}, found {}",
            turn.covers_from_seq
        )));
    }
    if turn.state != TurnState::OpenTail {
        return Ok(true);
    }

    let boundary_chain = validate_compaction_boundary_chain(events)?;
    Ok(boundary_chain.pending().iter().any(|boundary| {
        boundary.boundary.turn_id == turn_id
            && boundary.boundary.user_message_seq == user_message_seq
    }))
}

fn recoverable_open_turns_v1(events: &[JournalEvent]) -> Result<Vec<RecoverableOpenTurnV1>> {
    let user_messages = events
        .iter()
        .filter(|event| event.kind == "user.message")
        .filter_map(|event| {
            event.turn_id.as_ref().map(|turn_id| RecoverableOpenTurnV1 {
                turn_id: turn_id.clone(),
                user_message_seq: event.seq,
            })
        })
        .collect::<Vec<_>>();
    if user_messages.is_empty() {
        return Ok(Vec::new());
    }
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    Ok(user_messages
        .into_iter()
        .filter(|turn| {
            !boundary_chain.pending().iter().any(|boundary| {
                boundary.boundary.turn_id == turn.turn_id
                    && boundary.boundary.user_message_seq == turn.user_message_seq
            })
        })
        .filter(|turn| {
            !events.iter().any(|event| {
                event.seq > turn.user_message_seq
                    && event.turn_id.as_deref() == Some(turn.turn_id.as_str())
                    && matches!(
                        event.kind.as_str(),
                        "response.started"
                            | "response.completed"
                            | "response.failed"
                            | "response.aborted"
                            | "turn.completed"
                            | "turn.cancelled"
                            | "turn.abandoned"
                            | "turn.retry_started"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                            | "tool.started"
                            | "tool.completed"
                            | "tool.failed"
                            | "tool.in_doubt"
                            | "tool.in_doubt_resolved"
                            | "tool.skipped_due_to_recovery"
                            | "tool.skipped_due_to_cancel"
                            | "tool.skipped_due_to_limit"
                            | "tool.skipped_due_to_in_doubt"
                            | "tool.skipped_due_to_stalled"
                    )
            })
        })
        .collect())
}

fn unfinished_responses(events: &[JournalEvent]) -> Result<Vec<UnfinishedResponse>> {
    // A response attempt is scoped to its turn.  Keeping only the attempt ID
    // here would let a terminal from one turn settle an unfinished response
    // belonging to another turn when a provider reuses an ID.  It would also
    // silently overwrite a duplicate start in the same turn, losing durable
    // recovery evidence.  Treat the exact (turn, attempt) pair as the
    // lifecycle identity and fail closed on duplicate starts.
    let mut unfinished = BTreeMap::<(Option<String>, String), UnfinishedResponse>::new();
    let mut started = HashSet::<(Option<String>, String)>::new();
    for event in events {
        match event.kind.as_str() {
            "response.started" => {
                if let Some(response_attempt_id) =
                    string_field(&event.data, &["response_attempt_id"])
                {
                    let identity = (event.turn_id.clone(), response_attempt_id.clone());
                    if !started.insert(identity.clone()) {
                        return Err(OxidraError::Session(format!(
                            "duplicate response.started for turn {:?}, attempt {} at seq {}",
                            identity.0, response_attempt_id, event.seq
                        )));
                    }
                    unfinished.insert(
                        identity,
                        UnfinishedResponse {
                            started_seq: event.seq,
                            turn_id: event.turn_id.clone(),
                            response_attempt_id,
                        },
                    );
                }
            }
            kind if is_response_terminal(kind) => {
                if let Some(response_attempt_id) =
                    string_field(&event.data, &["response_attempt_id"])
                {
                    unfinished.remove(&(event.turn_id.clone(), response_attempt_id));
                }
            }
            _ => {}
        }
    }
    let mut responses = unfinished.into_values().collect::<Vec<_>>();
    responses.sort_by_key(|response| response.started_seq);
    Ok(responses)
}

fn unfinished_compactions(events: &[JournalEvent]) -> Vec<UnfinishedCompaction> {
    let mut unfinished = BTreeMap::<String, Vec<UnfinishedCompaction>>::new();
    for event in events {
        if !is_compaction_lifecycle(&event.kind) {
            continue;
        }
        if event.kind == COMPACTION_STARTED_KIND {
            if let Some(attempt_id) = string_field(&event.data, &["attempt_id"]) {
                unfinished
                    .entry(attempt_id.clone())
                    .or_default()
                    .push(UnfinishedCompaction {
                        started_seq: event.seq,
                        attempt_id,
                    });
            }
        } else if is_compaction_terminal(&event.kind) {
            if let Some(attempt_id) = string_field(&event.data, &["attempt_id"]) {
                let remove_entry = unfinished.get_mut(&attempt_id).is_some_and(|attempts| {
                    attempts.pop();
                    attempts.is_empty()
                });
                if remove_entry {
                    unfinished.remove(&attempt_id);
                }
            }
        }
    }
    let mut attempts = unfinished.into_values().flatten().collect::<Vec<_>>();
    attempts.sort_by_key(|attempt| attempt.started_seq);
    attempts
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RecoveredCompactionBoundaries {
    failed: usize,
    checkpointed: usize,
}

fn unstarted_tool_calls(events: &[JournalEvent]) -> Vec<UnstartedTool> {
    let mut unstarted = BTreeMap::<u64, UnstartedTool>::new();
    let mut pending_by_identity =
        std::collections::HashMap::<(Option<String>, String), Vec<u64>>::new();
    let mut next_key = 0u64;
    for event in events {
        match event.kind.as_str() {
            "response.completed" => {
                let items = event
                    .data
                    .get("output_items")
                    .or_else(|| {
                        event
                            .data
                            .get("raw_response")
                            .and_then(|response| response.get("output"))
                    })
                    .and_then(Value::as_array);
                let Some(items) = items else { continue };
                for item in items {
                    if item.get("type").and_then(Value::as_str) != Some("function_call") {
                        continue;
                    }
                    let Some(call_id) = item
                        .get("call_id")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let arguments = item.get("arguments").map(|arguments| match arguments {
                        Value::String(arguments) => serde_json::from_str(arguments)
                            .unwrap_or_else(|_| Value::String(arguments.clone())),
                        arguments => arguments.clone(),
                    });
                    let key = next_key;
                    next_key = next_key.saturating_add(1);
                    unstarted.insert(
                        key,
                        UnstartedTool {
                            response_seq: event.seq,
                            turn_id: event.turn_id.clone(),
                            call_id: call_id.to_owned(),
                            tool_name: string_field(item, &["name", "tool"]),
                            arguments,
                        },
                    );
                    pending_by_identity
                        .entry((event.turn_id.clone(), call_id.to_owned()))
                        .or_default()
                        .push(key);
                }
            }
            kind if is_tool_lifecycle(kind) => {
                if let Some(call_id) = string_field(&event.data, &["call_id", "id"]) {
                    let identity = (event.turn_id.clone(), call_id);
                    if let Some(key) = pending_by_identity.get_mut(&identity).and_then(Vec::pop) {
                        unstarted.remove(&key);
                    }
                    if pending_by_identity
                        .get(&identity)
                        .is_some_and(Vec::is_empty)
                    {
                        pending_by_identity.remove(&identity);
                    }
                }
            }
            _ => {}
        }
    }
    unstarted.into_values().collect()
}

fn preflight_recovery_authorization_batches(unstarted_tools: &[UnstartedTool]) -> Result<()> {
    for tools in unstarted_tools.chunks(MAX_MCP_CALLS_PER_RESPONSE) {
        recovery_authorizations(tools)?;
    }
    Ok(())
}

fn planned_recovery_event(
    session_id: &str,
    next_seq: &mut u64,
    kind: &str,
    turn_id: Option<&str>,
    data: Value,
) -> Result<JournalEvent> {
    let event = JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq: *next_seq,
        ts: Utc::now(),
        kind: kind.to_owned(),
        session_id: session_id.to_owned(),
        turn_id: turn_id.map(str::to_owned),
        data,
    };
    *next_seq = next_seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    Ok(event)
}

fn encoded_journal_events_bytes(events: &[JournalEvent]) -> Result<u64> {
    events.iter().try_fold(0u64, |total, event| {
        let event_len = u64::try_from(serde_json::to_vec(event)?.len())
            .map_err(|_| OxidraError::Session("journal event is too large".to_owned()))?;
        total
            .checked_add(event_len)
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| OxidraError::Session("journal transaction size overflow".to_owned()))
    })
}

#[cfg(test)]
fn provider_response_outcome_headroom_required_v1(
    session_id: &str,
    turn_id: &str,
    response_attempt_id: &str,
    response_started_seq: u64,
    context: Value,
) -> Result<u64> {
    let context_limit_error = "\0".repeat(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1);
    let generic_status = "\0".repeat(MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1);

    let mut pair_seq = response_started_seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    let failed = planned_recovery_event(
        session_id,
        &mut pair_seq,
        "response.failed",
        Some(turn_id),
        provider_context_limit_failed_data_v1(
            response_attempt_id,
            response_started_seq,
            &context_limit_error,
            context.clone(),
        ),
    )?;
    let limit = planned_recovery_event(
        session_id,
        &mut pair_seq,
        "context.limit_reached",
        Some(turn_id),
        provider_context_limit_event_data_v1(
            response_attempt_id,
            failed.seq,
            &context_limit_error,
            context,
        ),
    )?;
    let context_limit_bytes = encoded_journal_events_bytes(&[failed, limit])?;

    let mut terminal_seq = response_started_seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    let generic_failed = planned_recovery_event(
        session_id,
        &mut terminal_seq,
        "response.failed",
        Some(turn_id),
        json!({
            "response_attempt_id": response_attempt_id,
            "error": generic_status,
        }),
    )?;
    let generic_failed_bytes = encoded_journal_events_bytes(&[generic_failed])?;

    let mut aborted_seq = response_started_seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    let generic_aborted = planned_recovery_event(
        session_id,
        &mut aborted_seq,
        "response.aborted",
        Some(turn_id),
        json!({
            "response_attempt_id": response_attempt_id,
            "reason": "\0".repeat(MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1),
        }),
    )?;
    let generic_aborted_bytes = encoded_journal_events_bytes(&[generic_aborted])?;

    let mut recovery_seq = response_started_seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    let recovered_abort = planned_recovery_event(
        session_id,
        &mut recovery_seq,
        "response.aborted",
        Some(turn_id),
        json!({
            "response_attempt_id": response_attempt_id,
            "started_seq": response_started_seq,
            "reason": "process stopped before a terminal response event was committed",
            "recovered": true,
        }),
    )?;
    let recovery = RecoveryInfo {
        truncated_tail: Some(TruncatedTail {
            byte_count: u64::MAX,
            sha256: "f".repeat(64),
        }),
        skipped_before_start: usize::MAX,
        aborted_responses: usize::MAX,
        aborted_compactions: usize::MAX,
        failed_compaction_boundaries: usize::MAX,
        checkpointed_compaction_boundaries: usize::MAX,
        ..RecoveryInfo::default()
    };
    let marker = planned_recovery_event(
        session_id,
        &mut recovery_seq,
        RECOVERY_KIND,
        None,
        recovery_marker_data(&recovery, &[])?,
    )?;
    let recovery_bytes = encoded_journal_events_bytes(&[recovered_abort, marker])?;

    Ok(context_limit_bytes
        .max(generic_failed_bytes)
        .max(generic_aborted_bytes)
        .max(recovery_bytes))
}

fn ensure_provider_dispatch_recovery_profile_v1(events: &[JournalEvent]) -> Result<()> {
    if !provider_context_limit_recovery_actions_v1(events)?.is_empty() {
        return Err(OxidraError::Session(
            "Provider dispatch requires all context-limit intents to be recovered first".to_owned(),
        ));
    }
    if !unfinished_responses(events)?.is_empty() {
        return Err(OxidraError::Session(
            "Provider dispatch requires every prior response attempt to be terminal".to_owned(),
        ));
    }
    if !unfinished_compactions(events).is_empty() {
        return Err(OxidraError::Session(
            "Provider dispatch requires every compaction attempt to be terminal".to_owned(),
        ));
    }
    if !compaction_boundary_recovery_actions(events)?.is_empty() {
        return Err(OxidraError::Session(
            "Provider dispatch requires every compaction boundary recovery action to be settled"
                .to_owned(),
        ));
    }
    if !pending_tools(events).is_empty() || !unstarted_tool_calls(events).is_empty() {
        return Err(OxidraError::Session(
            "Provider dispatch requires every prior tool call to have a durable lifecycle outcome"
                .to_owned(),
        ));
    }
    Ok(())
}

fn ensure_compaction_dispatch_recovery_profile_v1(
    events: &[JournalEvent],
    boundary_value: Option<&Value>,
) -> Result<()> {
    if !provider_context_limit_recovery_actions_v1(events)?.is_empty() {
        return Err(OxidraError::Session(
            "compaction dispatch requires all context-limit intents to be recovered first"
                .to_owned(),
        ));
    }
    if !unfinished_responses(events)?.is_empty() {
        return Err(OxidraError::Session(
            "compaction dispatch requires every response attempt to be terminal".to_owned(),
        ));
    }
    if !unfinished_compactions(events).is_empty() {
        return Err(OxidraError::Session(
            "compaction dispatch requires every prior compaction attempt to be terminal".to_owned(),
        ));
    }
    if !pending_tools(events).is_empty() || !unstarted_tool_calls(events).is_empty() {
        return Err(OxidraError::Session(
            "compaction dispatch requires every tool call to have a durable lifecycle outcome"
                .to_owned(),
        ));
    }

    let boundary_actions = compaction_boundary_recovery_actions(events)?;
    match boundary_value {
        None if !boundary_actions.is_empty() => Err(OxidraError::Session(
            "unbound compaction dispatch cannot bypass a pending boundary recovery action"
                .to_owned(),
        )),
        None => Ok(()),
        Some(value) => {
            let boundary: CompactionBoundary =
                serde_json::from_value(value.clone()).map_err(|error| {
                    OxidraError::Session(format!(
                        "invalid compaction boundary in dispatch admission: {error}"
                    ))
                })?;
            let chain = validate_compaction_boundary_chain(events)?;
            let pending = chain.latest_pending().ok_or_else(|| {
                OxidraError::Session(format!(
                    "compaction boundary {} is not pending at dispatch admission",
                    boundary.boundary_id
                ))
            })?;
            if pending.boundary != boundary || pending.state != CompactionBoundaryState::Started {
                return Err(OxidraError::Session(format!(
                    "compaction boundary {} is not the current unattempted boundary",
                    boundary.boundary_id
                )));
            }
            if boundary_actions.len() != 1 {
                return Err(OxidraError::Session(format!(
                    "compaction boundary {} has an ambiguous pre-dispatch recovery state",
                    boundary.boundary_id
                )));
            }
            Ok(())
        }
    }
}

fn stage_recovery_event(
    session_id: &str,
    next_seq: &mut u64,
    planned: &mut Vec<JournalEvent>,
    prospective: &mut Vec<JournalEvent>,
    kind: &str,
    turn_id: Option<&str>,
    data: Value,
) -> Result<JournalEvent> {
    let event = planned_recovery_event(session_id, next_seq, kind, turn_id, data)?;
    planned.push(event.clone());
    prospective.push(event.clone());
    Ok(event)
}

fn recovery_tool_skip_data(tool: &UnstartedTool, recovery_marker_seq: u64) -> Value {
    json!({
        "response_seq": tool.response_seq,
        "call_id": tool.call_id,
        "tool": tool.tool_name,
        "arguments": tool.arguments,
        "reason": "process stopped before tool.started was committed",
        "output": {
            "error": {
                "code": "interrupted_before_start",
                "message": "tool was not executed because the previous process stopped before dispatch",
            }
        },
        "is_error": true,
        "error_code": "interrupted_before_start",
        "recovery_marker_seq": recovery_marker_seq,
    })
}

fn plan_mcp_recovery_events(
    session_id: &str,
    first_seq: u64,
    recovery: &mut RecoveryInfo,
    unstarted_tools: &[UnstartedTool],
    marker_required_without_tools: bool,
) -> Result<Vec<JournalEvent>> {
    let mut next_seq = first_seq;
    let mut events = Vec::with_capacity(
        unstarted_tools
            .len()
            .saturating_add(unstarted_tools.len().div_ceil(MAX_MCP_CALLS_PER_RESPONSE))
            .saturating_add(usize::from(marker_required_without_tools)),
    );
    if !unstarted_tools.is_empty() {
        for tools in unstarted_tools.chunks(MAX_MCP_CALLS_PER_RESPONSE) {
            let marker = planned_recovery_event(
                session_id,
                &mut next_seq,
                RECOVERY_KIND,
                None,
                recovery_marker_data(recovery, tools)?,
            )?;
            let marker_seq = marker.seq;
            recovery.marker_seq = Some(marker_seq);
            events.push(marker);
            for tool in tools {
                events.push(planned_recovery_event(
                    session_id,
                    &mut next_seq,
                    "tool.skipped_due_to_recovery",
                    tool.turn_id.as_deref(),
                    recovery_tool_skip_data(tool, marker_seq),
                )?);
            }
        }
    } else if marker_required_without_tools {
        let marker = planned_recovery_event(
            session_id,
            &mut next_seq,
            RECOVERY_KIND,
            None,
            recovery_marker_data(recovery, unstarted_tools)?,
        )?;
        recovery.marker_seq = Some(marker.seq);
        events.push(marker);
    }
    Ok(events)
}

fn matching_recovery_marker(events: &[JournalEvent], recovery: &RecoveryInfo) -> Option<u64> {
    if recovery.in_doubt.is_empty()
        && recovery.skipped_before_start == 0
        && recovery.aborted_responses == 0
        && recovery.aborted_compactions == 0
        && recovery.failed_compaction_boundaries == 0
        && recovery.checkpointed_compaction_boundaries == 0
        && recovery.cancelled_turns == 0
    {
        return None;
    }

    let expected_in_doubt_keys = sorted_in_doubt_keys(&recovery.in_doubt);

    events
        .iter()
        .rev()
        .filter(|event| event.kind == RECOVERY_KIND)
        .find_map(|event| {
            let marked = event.data.get("in_doubt")?.clone();
            let marked = serde_json::from_value::<Vec<InDoubtTool>>(marked).ok()?;
            let marked_skipped = event
                .data
                .get("skipped_before_start")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            let marked_aborted = event
                .data
                .get("aborted_responses")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            let marked_aborted_compactions = event
                .data
                .get("aborted_compactions")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            let marked_failed_compaction_boundaries = event
                .data
                .get("failed_compaction_boundaries")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            let marked_checkpointed_compaction_boundaries = event
                .data
                .get("checkpointed_compaction_boundaries")
                .and_then(Value::as_u64)
                .unwrap_or_default()
                as usize;
            let marked_cancelled_turns = event
                .data
                .get("cancelled_turns")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            (sorted_in_doubt_keys(&marked) == expected_in_doubt_keys
                && marked_skipped == recovery.skipped_before_start
                && marked_aborted == recovery.aborted_responses
                && marked_aborted_compactions == recovery.aborted_compactions
                && marked_failed_compaction_boundaries == recovery.failed_compaction_boundaries
                && marked_checkpointed_compaction_boundaries
                    == recovery.checkpointed_compaction_boundaries
                && marked_cancelled_turns == recovery.cancelled_turns)
                .then_some(event.seq)
        })
}

fn sorted_in_doubt_keys(tools: &[InDoubtTool]) -> Vec<(u64, String, String)> {
    let mut keys = tools
        .iter()
        .map(|tool| {
            (
                tool.started_seq,
                tool.call_id.as_deref().unwrap_or_default().to_owned(),
                tool.tool_name.as_deref().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn recovery_marker_data(
    recovery: &RecoveryInfo,
    unstarted_tools: &[UnstartedTool],
) -> Result<Value> {
    // Keep the writer aligned with the frozen validator even when this helper
    // is called independently of SessionStore::open's pre-write scan.
    if unstarted_tools.len() > MAX_MCP_CALLS_PER_RESPONSE {
        return Err(OxidraError::Session(format!(
            "recovery marker exceeds the {MAX_MCP_CALLS_PER_RESPONSE}-call authorization limit"
        )));
    }
    let mut data = json!({
        "reason": if recovery.truncated_tail.is_some() {
            "incomplete_tail"
        } else if recovery.aborted_responses > 0 {
            "response_aborted"
        } else if recovery.aborted_compactions > 0 {
            "compaction_aborted"
        } else if recovery.failed_compaction_boundaries > 0 {
            "compaction_boundary_failed"
        } else if recovery.checkpointed_compaction_boundaries > 0 {
            "compaction_boundary_checkpointed"
        } else if recovery.cancelled_turns > 0 {
            "turn_cancelled"
        } else if recovery.skipped_before_start > 0 {
            "tool_not_started"
        } else {
            "in_doubt_tool"
        },
        "truncated_tail": recovery.truncated_tail,
        "in_doubt": recovery.in_doubt,
        "skipped_before_start": recovery.skipped_before_start,
        "aborted_responses": recovery.aborted_responses,
        "aborted_compactions": recovery.aborted_compactions,
        "failed_compaction_boundaries": recovery.failed_compaction_boundaries,
        "checkpointed_compaction_boundaries": recovery.checkpointed_compaction_boundaries,
        "cancelled_turns": recovery.cancelled_turns,
    });
    if !unstarted_tools.is_empty() {
        let authorizations = recovery_authorizations(unstarted_tools)?;
        data["tool_skip_authorization_version"] = Value::from(1);
        data["unstarted_tool_calls"] = Value::Array(authorizations);
    }
    Ok(data)
}

fn recovery_authorizations(unstarted_tools: &[UnstartedTool]) -> Result<Vec<Value>> {
    unstarted_tools
        .iter()
        .map(|tool| {
            let arguments = tool.arguments.as_ref().unwrap_or(&Value::Null);
            Ok(json!({
                "response_seq": tool.response_seq,
                "turn_id": tool.turn_id,
                "call_id": tool.call_id,
                "tool": tool.tool_name,
                "arguments_sha256": crate::mcp::argument_digest_v1(arguments)?,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn header(root: &Path) -> SessionHeader {
        SessionHeader::new(root, "test-model")
    }

    fn append_provider_context_limit_intent_prefix(
        journal: &mut SessionJournal,
        turn_id: &str,
        response_attempt_id: &str,
    ) -> (JournalEvent, JournalEvent, Value) {
        journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":"oversized prompt"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let context = json!({
            "measurement": {"request_digest": "context-digest"},
            "estimated_next_input_tokens": 1_000_000,
            "tools_event_seq": 1,
        });
        let started = journal
            .append_and_sync(
                "response.started",
                Some(turn_id),
                json!({
                    "response_attempt_id":response_attempt_id,
                    "response_index":1,
                    "context":context.clone(),
                }),
            )
            .unwrap();
        let failed = journal
            .append_and_sync(
                "response.failed",
                Some(turn_id),
                provider_context_limit_failed_data_v1(
                    response_attempt_id,
                    started.seq,
                    "context_length_exceeded",
                    context.clone(),
                ),
            )
            .unwrap();
        (started, failed, context)
    }

    #[test]
    fn creates_layout_and_round_trips_raw_events() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let layout = store.layout();
        assert!(layout.sessions_dir.is_dir());
        assert!(layout.artifacts_dir.is_dir());
        assert!(layout.locks_dir.is_dir());

        let mut journal = store
            .create_with_id("session-1", header(temp.path()))
            .unwrap();
        let event = journal
            .append(
                "response.completed",
                Some("turn-1"),
                json!({"raw": {"future_field": [1, 2, 3]}}),
            )
            .unwrap();
        assert_eq!(event.seq, 2);
        journal.flush().unwrap();

        let raw = journal.read_raw_events().unwrap();
        assert_eq!(raw[1]["data"]["raw"]["future_field"], json!([1, 2, 3]));
        assert_eq!(journal.header().unwrap().unwrap().model, "test-model");
        assert!(journal.artifact_dir().is_dir());
    }

    #[test]
    fn write_failure_poison_prevents_same_process_from_using_visible_bytes() {
        let temp = TempDir::new().unwrap();
        let journal_path = temp.path().join("poisoned.jsonl");
        fs::write(&journal_path, b"").unwrap();
        let file = OpenOptions::new().read(true).open(&journal_path).unwrap();
        let lock_path = temp.path().join("poisoned.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .unwrap();
        let mut journal = SessionJournal {
            session_id: "poisoned".to_owned(),
            journal_path,
            artifact_dir: temp.path().join("artifacts"),
            file,
            _lock_file: lock_file,
            next_seq: 1,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit: MAX_SESSION_BYTES,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            mcp_resume_open_id: None,
            mcp_resume_eligibility_issued: false,
        };

        let first_error = journal
            .append_and_sync("test.event", None, json!({"value": 1}))
            .expect_err("a read-only journal handle must reject writes");
        assert!(matches!(first_error, OxidraError::Io(_)));

        for error in [
            journal.read_events().unwrap_err(),
            journal
                .append("test.event", None, json!({"value": 2}))
                .unwrap_err(),
            journal.sync().unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("write state is indeterminate"),
                "{error}"
            );
        }
    }

    #[test]
    fn holds_an_exclusive_writer_lock() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store.create_with_id("locked", header(temp.path())).unwrap();
        let error = store.open("locked").err().unwrap();
        assert!(error.to_string().contains("already open"));
        drop(journal);
        store.open("locked").unwrap();
    }

    #[test]
    fn deletes_session_journal_and_artifacts_after_releasing_lock() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("deletable", header(temp.path()))
            .unwrap();
        let journal_path = journal.journal_path().to_owned();
        let artifact_dir = journal.artifact_dir().to_owned();
        fs::write(artifact_dir.join("output.txt"), "artifact").unwrap();
        drop(journal);

        assert!(store.delete("deletable").unwrap());
        assert!(!journal_path.exists());
        assert!(!artifact_dir.exists());
        assert!(!store.delete("deletable").unwrap());
        // The leftover lock file is deliberate and must not block re-creating
        // a session with the same id.
        store
            .create_with_id("deletable", header(temp.path()))
            .unwrap();
    }

    #[test]
    fn deleting_a_missing_session_leaves_no_lock_file() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        assert!(!store.delete("never-existed").unwrap());
        assert!(!store.layout().lock_path("never-existed").unwrap().exists());
    }

    #[test]
    fn delete_resumes_cleanup_from_a_leftover_tombstone() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("half-deleted", header(temp.path()))
            .unwrap();
        let journal_path = journal.journal_path().to_owned();
        let artifact_dir = journal.artifact_dir().to_owned();
        drop(journal);

        // Simulate a delete that failed after the tombstone rename.
        let tombstone = journal_path.with_extension("jsonl.deleting");
        fs::rename(&journal_path, &tombstone).unwrap();
        assert!(store.list().unwrap().is_empty());

        assert!(store.delete("half-deleted").unwrap());
        assert!(!tombstone.exists());
        assert!(!journal_path.exists());
        assert!(!artifact_dir.exists());
    }

    #[test]
    fn refuses_to_delete_an_open_session() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("open-delete", header(temp.path()))
            .unwrap();
        let error = store.delete("open-delete").unwrap_err();
        assert!(error.to_string().contains("already open"));
        drop(journal);
    }

    #[test]
    fn truncates_an_incomplete_tail_and_appends_recovery_marker() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("crashed", header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{"schema":1,"seq":2,"ts":"#)
            .unwrap();

        let mut recovered = store.open("crashed").unwrap();
        let info = recovered.recovery_info();
        assert!(info.truncated_tail.as_ref().unwrap().byte_count > 0);
        assert_eq!(info.marker_seq, Some(2));
        assert_eq!(recovered.read_events().unwrap()[1].kind, RECOVERY_KIND);
        assert_eq!(
            recovered
                .append("user.message", Some("turn-1"), json!({"text": "hi"}))
                .unwrap()
                .seq,
            3
        );
    }

    #[test]
    fn pending_tools_remain_in_doubt_without_duplicate_recovery_markers() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("pending", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "tool.started",
                Some("turn-7"),
                json!({"call_id": "call-1", "name": "shell", "arguments": {"command": "pwd"}}),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("pending").unwrap();
        assert_eq!(recovered.recovery_info().in_doubt.len(), 1);
        assert_eq!(
            recovered.recovery_info().in_doubt[0].call_id.as_deref(),
            Some("call-1")
        );
        let marker_seq = recovered.recovery_info().marker_seq;
        drop(recovered);

        let reopened = store.open("pending").unwrap();
        assert_eq!(reopened.recovery_info().in_doubt.len(), 1);
        assert_eq!(reopened.in_doubt().unwrap().len(), 1);
        assert_eq!(reopened.recovery_info().marker_seq, marker_seq);
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1
        );
    }

    #[test]
    fn duplicate_call_ids_do_not_erase_older_pending_calls() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("duplicate-call-id", header(temp.path()))
            .unwrap();
        journal
            .append(
                "tool.started",
                Some("turn"),
                json!({"call_id": "same", "tool": "first"}),
            )
            .unwrap();
        journal
            .append(
                "tool.started",
                Some("turn"),
                json!({"call_id": "same", "tool": "second"}),
            )
            .unwrap();
        journal
            .append(
                "tool.completed",
                Some("turn"),
                json!({"call_id": "same", "output": "second"}),
            )
            .unwrap();
        journal.flush().unwrap();

        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name.as_deref(), Some("first"));
    }

    #[test]
    fn explicit_in_doubt_event_persists_until_resolved() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("explicit-in-doubt", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-8"),
                json!({
                    "call_id": "call-2",
                    "tool": "shell",
                    "arguments": {"query": "value"},
                    "error_code": "in_doubt"
                }),
            )
            .unwrap();
        drop(journal);

        let mut recovered = store.open("explicit-in-doubt").unwrap();
        let pending = recovered.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].started_seq, 2);
        assert_eq!(pending[0].call_id.as_deref(), Some("call-2"));
        assert_eq!(pending[0].tool_name.as_deref(), Some("shell"));

        recovered
            .append_and_sync(
                "tool.in_doubt_resolved",
                Some("turn-8"),
                json!({"call_id": "call-2", "output": {"error": "treated as failed"}}),
            )
            .unwrap();
        assert!(recovered.in_doubt().unwrap().is_empty());
        drop(recovered);

        let reopened = store.open("explicit-in-doubt").unwrap();
        assert!(reopened.recovery_info().in_doubt.is_empty());
        assert!(reopened.in_doubt().unwrap().is_empty());
    }

    #[test]
    fn tool_in_doubt_keeps_a_started_call_pending() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("started-in-doubt", header(temp.path()))
            .unwrap();
        journal
            .append(
                "tool.started",
                Some("turn-9"),
                json!({"call_id": "call-3", "tool": "write", "arguments": {}}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-9"),
                json!({"call_id": "call-3", "tool": "write", "error_code": "in_doubt"}),
            )
            .unwrap();
        drop(journal);

        let reopened = store.open("started-in-doubt").unwrap();
        let pending = reopened.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].started_seq, 2);
        assert_eq!(pending[0].call_id.as_deref(), Some("call-3"));
    }

    #[test]
    fn reopens_provider_context_limit_intent_as_one_pending_audit_event() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-intent", header(temp.path()))
            .unwrap();
        let (_started, failed, context) = append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-context-limit",
            "attempt-context-limit",
        );
        drop(journal);

        let recovered = store.open("provider-context-limit-intent").unwrap();
        assert_eq!(
            recovered.recovery_info().recovered_provider_context_limits,
            1
        );
        assert_eq!(recovered.recovery_info().aborted_responses, 0);
        assert!(recovered.recovery_info().recovered());
        let events = recovered.read_events().unwrap();
        let limits = events
            .iter()
            .filter(|event| event.kind == "context.limit_reached")
            .collect::<Vec<_>>();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0].turn_id.as_deref(), Some("turn-context-limit"));
        assert_eq!(
            limits[0].data,
            provider_context_limit_event_data_v1(
                "attempt-context-limit",
                failed.seq,
                "context_length_exceeded",
                context,
            )
        );
        crate::turn::validate_turn_recovery(&events)
            .expect("recovered context limit must satisfy the turn recovery reducer");
        drop(recovered);

        let reopened = store.open("provider-context-limit-intent").unwrap();
        assert_eq!(
            reopened.recovery_info().recovered_provider_context_limits,
            0
        );
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "context.limit_reached")
                .count(),
            1
        );
    }

    #[test]
    fn reopens_provider_context_limit_after_truncating_partial_audit_event() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-partial", header(temp.path()))
            .unwrap();
        append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-context-limit",
            "attempt-context-limit",
        );
        journal
            .file
            .write_all(br#"{"schema":1,"seq":5,"kind":"context.limit_reached"#)
            .unwrap();
        journal.sync().unwrap();
        drop(journal);

        let recovered = store.open("provider-context-limit-partial").unwrap();
        assert!(recovered.recovery_info().truncated_tail.is_some());
        assert_eq!(
            recovered.recovery_info().recovered_provider_context_limits,
            1
        );
        assert_eq!(
            recovered
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "context.limit_reached")
                .count(),
            1
        );
    }

    #[test]
    fn complete_provider_context_limit_transaction_is_not_duplicated() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-complete", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-context-limit"),
                json!({
                    "item":{"role":"user","content":"oversized prompt"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let context = json!({"measurement":{"request_digest":"context-digest"}});
        let mut admission = journal
            .append_provider_response_started_v1(
                "turn-context-limit",
                json!({
                    "response_attempt_id":"attempt-context-limit",
                    "response_index":1,
                    "context":context.clone(),
                }),
            )
            .unwrap();
        journal
            .append_provider_context_limit_v1(&mut admission, "context_length_exceeded")
            .unwrap();
        drop(journal);

        let reopened = store.open("provider-context-limit-complete").unwrap();
        assert_eq!(
            reopened.recovery_info().recovered_provider_context_limits,
            0
        );
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "context.limit_reached")
                .count(),
            1
        );
    }

    #[test]
    fn provider_context_limit_intent_v1_literal_profile_is_frozen() {
        assert_eq!(PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_V1, 1);
        let context = json!({
            "measurement":{"request_digest":"frozen-context-digest"},
            "estimated_next_input_tokens":1234,
        });
        assert_eq!(
            provider_context_limit_failed_data_v1(
                "attempt-frozen",
                17,
                "context_length_exceeded",
                context.clone(),
            ),
            json!({
                "response_attempt_id":"attempt-frozen",
                "response_started_seq":17,
                "error":"context_length_exceeded",
                "error_code":"provider_context_limit",
                "provider_context_limit_intent_version":1,
                "context":context,
            })
        );
        assert_eq!(
            provider_context_limit_event_data_v1(
                "attempt-frozen",
                18,
                "context_length_exceeded",
                context.clone(),
            ),
            json!({
                "error":"context_length_exceeded",
                "source":"provider",
                "response_attempt_id":"attempt-frozen",
                "context":context,
                "provider_context_limit_intent_version":1,
                "provider_context_limit_intent_seq":18,
            })
        );
    }

    #[test]
    fn provider_context_limit_error_profile_v1_is_byte_exact_and_independent() {
        assert_eq!(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1, 16 * 1024);
        assert_eq!(
            provider_context_limit_error_for_journal_v1(""),
            "unspecified response status"
        );

        let exact = "x".repeat(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1);
        assert_eq!(provider_context_limit_error_for_journal_v1(&exact), exact);

        let oversized = "x".repeat(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1 + 1);
        let truncated = provider_context_limit_error_for_journal_v1(&oversized);
        assert_eq!(truncated.len(), MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1);
        assert!(truncated.ends_with("<truncated>"));
        assert!(valid_provider_context_limit_error_v1(&truncated));

        let multibyte = format!(
            "{}zz",
            "界".repeat(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1 / 3)
        );
        let truncated = provider_context_limit_error_for_journal_v1(&multibyte);
        assert!(truncated.len() <= MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(truncated.ends_with("<truncated>"));
    }

    #[test]
    fn provider_dispatch_headroom_covers_frozen_bounded_outcomes() {
        let context_overhead = serde_json::to_vec(&json!({"blob":""})).unwrap().len();
        let context = json!({
            "blob": "x".repeat(MAX_PROVIDER_CONTEXT_LIMIT_CONTEXT_BYTES_V1 - context_overhead),
        });
        assert_eq!(
            serde_json::to_vec(&context).unwrap().len(),
            MAX_PROVIDER_CONTEXT_LIMIT_CONTEXT_BYTES_V1
        );
        let required = provider_response_outcome_headroom_required_v1(
            &"s".repeat(128),
            &"t".repeat(128),
            &"a".repeat(128),
            u64::MAX - 3,
            context,
        )
        .unwrap();
        assert!(
            required <= PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1,
            "frozen bounded outcomes require {required} bytes"
        );
    }

    #[test]
    fn provider_dispatch_admission_is_exclusive_and_single_use() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-dispatch-capability", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-provider"),
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let mut admission = journal
            .append_provider_response_started_v1(
                "turn-provider",
                json!({
                    "response_attempt_id":"attempt-provider",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();

        let append_error = journal
            .append_and_sync("note", Some("turn-provider"), json!({"unsafe":true}))
            .expect_err("generic appends must not consume protected headroom");
        assert!(append_error.to_string().contains("dispatch capability"));

        journal
            .append_provider_response_failed_v1(&mut admission, "provider failed")
            .unwrap();
        let reuse_error = journal
            .append_provider_response_failed_v1(&mut admission, "duplicate")
            .expect_err("dispatch capability must be one-shot");
        assert!(reuse_error.to_string().contains("already consumed"));
        journal
            .append_and_sync("note", Some("turn-provider"), json!({"safe":true}))
            .expect("generic appends resume after terminal consumption");
    }

    #[test]
    fn provider_dispatch_headroom_survives_crash_recovery_at_the_same_limit() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-dispatch-recovery-headroom", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-provider"),
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let current_size = journal.file.metadata().unwrap().len();
        let byte_limit = current_size + PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1 + 16 * 1024;
        journal.set_byte_limit_for_tests(byte_limit);
        let admission = journal
            .append_provider_response_started_v1(
                "turn-provider",
                json!({
                    "response_attempt_id":"attempt-provider",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect("the exact dispatch reserve must fit");
        drop(admission);
        drop(journal);

        let reopened = store
            .open_with_byte_limit("provider-dispatch-recovery-headroom", byte_limit)
            .expect("the protected headroom must fit response.abort plus recovery marker");
        let events = reopened.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind == "response.aborted"
                        && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
                })
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1
        );
        assert!(reopened.file.metadata().unwrap().len() <= byte_limit);
    }

    #[test]
    fn provider_context_limit_pair_consumes_dispatch_time_headroom() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id(
                "provider-context-limit-dispatch-headroom",
                header(temp.path()),
            )
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-provider"),
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let current_size = journal.file.metadata().unwrap().len();
        let byte_limit = current_size + PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1 + 16 * 1024;
        journal.set_byte_limit_for_tests(byte_limit);
        let mut admission = journal
            .append_provider_response_started_v1(
                "turn-provider",
                json!({
                    "response_attempt_id":"attempt-provider",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect("dispatch admission must reserve the complete bounded outcome");
        journal
            .append_provider_context_limit_v1(
                &mut admission,
                &"x".repeat(MAX_PROVIDER_CONTEXT_LIMIT_ERROR_BYTES_V1 + 1),
            )
            .expect("the context-limit pair must fit the dispatch-time reserve");
        assert!(journal.file.metadata().unwrap().len() <= byte_limit);
        assert!(journal.active_provider_response.is_none());
    }

    #[test]
    fn turn_admission_denies_provider_before_user_message_when_only_terminal_headroom_fits() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("turn-admission-before-provider", header(temp.path()))
            .unwrap();
        let base = journal.file.metadata().unwrap().len();
        journal.set_byte_limit_for_tests(base + TURN_OUTCOME_HEADROOM_BYTES_V1 + 4096);

        let mut turn_admission = journal
            .append_user_message_with_turn_admission_v1(
                "turn-admission",
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .expect("user.message should fit while preserving turn headroom");
        let after_user = journal.file.metadata().unwrap().len();
        journal.set_byte_limit_for_tests(after_user + TURN_OUTCOME_HEADROOM_BYTES_V1 - 1);
        let error = journal
            .append_provider_response_started_v1(
                "turn-admission",
                json!({
                    "response_attempt_id":"attempt-admission",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect_err(
                "Provider dispatch must be denied when its own outcome reserve no longer fits",
            );
        assert!(matches!(
            error,
            DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(_)
        ));
        journal
            .finish_turn_transaction_v1(
                &mut turn_admission,
                Some("Provider outcome capacity denied"),
            )
            .unwrap();
        let events = journal.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "user.message")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.started")
                .count(),
            0
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.cancelled")
                .count(),
            1
        );
    }

    #[test]
    fn malformed_provider_admission_is_fatal_and_writes_no_fake_capacity_cancellation() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-admission-fatal", header(temp.path()))
            .unwrap();
        let mut turn_admission = journal
            .append_user_message_with_turn_admission_v1(
                "turn-fatal",
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let event_count = journal.read_events().unwrap().len();
        let error = journal
            .append_provider_response_started_v1(
                "turn-fatal",
                json!({
                    "response_attempt_id":"attempt-fatal",
                    "response_index":1,
                }),
            )
            .expect_err("missing context is a fatal protocol error, not capacity denial");
        assert!(matches!(error, DispatchAdmissionErrorV1::Fatal(_)));
        let events = journal.read_events().unwrap();
        assert_eq!(events.len(), event_count);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.cancelled")
                .count(),
            0
        );
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("test cleanup"))
            .unwrap();
    }

    #[test]
    fn dropping_an_unfinished_turn_capability_requires_reopen_and_recovery() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("turn-admission-drop", header(temp.path()))
            .unwrap();
        let admission = journal
            .append_user_message_with_turn_admission_v1(
                "turn-drop",
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        drop(admission);
        let error = journal
            .read_events()
            .expect_err("dropping the capability must not leave a silently reusable handle");
        assert!(error.to_string().contains("reopen"));
        drop(journal);

        let reopened = store.open("turn-admission-drop").unwrap();
        let events = reopened.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.cancelled")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1
        );
        assert_eq!(reopened.recovery_info().cancelled_turns, 1);
    }

    #[test]
    fn dropping_an_unfinished_response_capability_requires_reopen() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("response-admission-drop", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-response-drop"),
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let admission = journal
            .append_provider_response_started_v1(
                "turn-response-drop",
                json!({
                    "response_attempt_id":"attempt-response-drop",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();
        drop(admission);
        assert!(journal.read_events().is_err());
        drop(journal);
        let reopened = store.open("response-admission-drop").unwrap();
        let events = reopened.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind == "response.aborted"
                        && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
                })
                .count(),
            1
        );
    }

    #[test]
    fn provider_context_limit_writer_validates_the_exact_start_before_writing() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-writer", header(temp.path()))
            .unwrap();
        let context = json!({"measurement":{"request_digest":"context-digest"}});
        let mut admission = journal
            .append_provider_response_started_v1(
                "turn-context-limit",
                json!({
                    "response_attempt_id":"attempt-context-limit",
                    "response_index":1,
                    "context":context.clone(),
                }),
            )
            .unwrap();
        let original_count = journal.read_events().unwrap().len();
        journal
            .active_provider_response
            .as_mut()
            .expect("active admission")
            .context = json!({"measurement":{"request_digest":"different"}});

        let error = journal
            .append_provider_context_limit_v1(&mut admission, "context_length_exceeded")
            .expect_err("the writer must inherit the exact response.started context");
        assert!(error.to_string().contains("does not inherit"));
        assert_eq!(journal.read_events().unwrap().len(), original_count);
    }

    #[test]
    fn provider_context_limit_pair_reserves_capacity_before_the_intent_write() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-capacity", header(temp.path()))
            .unwrap();
        let context = json!({"measurement":{"request_digest":"context-digest"}});
        let started = journal
            .append_and_sync(
                "response.started",
                Some("turn-context-limit"),
                json!({
                    "response_attempt_id":"attempt-context-limit",
                    "response_index":1,
                    "context":context.clone(),
                }),
            )
            .unwrap();
        let mut next_seq = journal.next_seq();
        let failed = planned_recovery_event(
            journal.session_id(),
            &mut next_seq,
            "response.failed",
            Some("turn-context-limit"),
            provider_context_limit_failed_data_v1(
                "attempt-context-limit",
                started.seq,
                "context_length_exceeded",
                context.clone(),
            ),
        )
        .unwrap();
        let limit = planned_recovery_event(
            journal.session_id(),
            &mut next_seq,
            "context.limit_reached",
            Some("turn-context-limit"),
            provider_context_limit_event_data_v1(
                "attempt-context-limit",
                failed.seq,
                "context_length_exceeded",
                context,
            ),
        )
        .unwrap();
        let original_size = journal.file.metadata().unwrap().len();
        let original_seq = journal.next_seq();
        let first_event_bytes = serde_json::to_vec(&failed).unwrap().len() as u64 + 1;

        let error = journal
            .append_prebuilt_batch_with_limit(&[failed, limit], original_size + first_event_bytes)
            .expect_err("capacity for only the intent must reject the whole pair");
        assert!(
            error
                .to_string()
                .contains("journal transaction would exceed")
        );
        assert_eq!(journal.file.metadata().unwrap().len(), original_size);
        assert_eq!(journal.next_seq(), original_seq);
    }

    #[test]
    fn malformed_provider_context_limit_intents_fail_before_recovery_writes() {
        for suffix in ["unknown-version", "missing-context", "changed-context"] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("provider-context-limit-{suffix}");
            let mut journal = store
                .create_with_id(&session_id, header(temp.path()))
                .unwrap();
            journal
                .append_and_sync(
                    "user.message",
                    Some("turn-context-limit"),
                    json!({
                        "item":{"role":"user","content":"oversized prompt"},
                        "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                    }),
                )
                .unwrap();
            let context = json!({
                "measurement":{"request_digest":"context-digest"},
                "estimated_next_input_tokens":1_000_000,
            });
            let started = journal
                .append_and_sync(
                    "response.started",
                    Some("turn-context-limit"),
                    json!({
                        "response_attempt_id":"attempt-context-limit",
                        "response_index":1,
                        "context":context.clone(),
                    }),
                )
                .unwrap();
            let mut data = provider_context_limit_failed_data_v1(
                "attempt-context-limit",
                started.seq,
                "context_length_exceeded",
                context,
            );
            match suffix {
                "unknown-version" => {
                    data[PROVIDER_CONTEXT_LIMIT_INTENT_VERSION_FIELD] = Value::from(2);
                }
                "missing-context" => {
                    data.as_object_mut().unwrap().remove("context");
                }
                "changed-context" => {
                    data["context"]["estimated_next_input_tokens"] = Value::from(42);
                }
                _ => unreachable!("fixed mutation table"),
            }
            journal
                .append_and_sync("response.failed", Some("turn-context-limit"), data)
                .unwrap();
            let original_count = journal.read_events().unwrap().len();
            drop(journal);

            let error = match store.open(&session_id) {
                Ok(_) => panic!("malformed intent {suffix} must fail closed"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("provider context-limit intent"),
                "unexpected {suffix} error: {error}"
            );
            assert_eq!(store.inspect(&session_id).unwrap().len(), original_count);
        }
    }

    #[test]
    fn recovers_unfinished_response_once() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("unfinished-response", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("turn-response"),
                json!({"response_attempt_id":"attempt-1"}),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("unfinished-response").unwrap();
        assert_eq!(recovered.recovery_info().aborted_responses, 1);
        let events = recovered.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.aborted")
                .count(),
            1
        );
        drop(recovered);

        let reopened = store.open("unfinished-response").unwrap();
        assert_eq!(reopened.recovery_info().aborted_responses, 1);
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "response.aborted")
                .count(),
            1
        );
    }

    #[test]
    fn unfinished_response_terminal_is_scoped_to_turn() {
        let ts = Utc::now();
        let event = |seq, kind: &str, turn_id: &str, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts,
            kind: kind.to_owned(),
            session_id: "response-turn-scope".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let events = vec![
            event(
                1,
                "response.started",
                "turn-a",
                json!({"response_attempt_id":"attempt-reused"}),
            ),
            event(
                2,
                "response.started",
                "turn-b",
                json!({"response_attempt_id":"attempt-reused"}),
            ),
            event(
                3,
                "response.failed",
                "turn-b",
                json!({"response_attempt_id":"attempt-reused"}),
            ),
        ];
        let unfinished = unfinished_responses(&events).expect("turn-scoped identities");
        assert_eq!(unfinished.len(), 1);
        assert_eq!(unfinished[0].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(unfinished[0].response_attempt_id, "attempt-reused");
        assert_eq!(unfinished[0].started_seq, 1);
    }

    #[test]
    fn reopen_recovers_cross_turn_reused_response_attempt() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("cross-turn-response-recovery", header(temp.path()))
            .unwrap();
        journal
            .append(
                "response.started",
                Some("turn-a"),
                json!({"response_attempt_id":"attempt-reused"}),
            )
            .unwrap();
        journal
            .append(
                "response.started",
                Some("turn-b"),
                json!({"response_attempt_id":"attempt-reused"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.failed",
                Some("turn-b"),
                json!({"response_attempt_id":"attempt-reused"}),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("cross-turn-response-recovery").unwrap();
        let events = recovered.read_events().unwrap();
        let aborted = events
            .iter()
            .find(|event| event.kind == "response.aborted")
            .expect("turn-a response must be recovered");
        assert_eq!(aborted.turn_id.as_deref(), Some("turn-a"));
        assert_eq!(aborted.data["response_attempt_id"], "attempt-reused");
    }

    #[test]
    fn duplicate_response_start_in_same_turn_fails_closed() {
        let ts = Utc::now();
        let event = |seq| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts,
            kind: "response.started".to_owned(),
            session_id: "duplicate-response-start".to_owned(),
            turn_id: Some("turn-a".to_owned()),
            data: json!({"response_attempt_id":"attempt-duplicate"}),
        };
        let error = unfinished_responses(&[event(1), event(2)])
            .expect_err("duplicate response starts must be rejected");
        assert!(error.to_string().contains("duplicate response.started"));
    }

    #[test]
    fn reopen_rejects_duplicate_response_start_without_writing_recovery() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("duplicate-response-recovery", header(temp.path()))
            .unwrap();
        journal
            .append(
                "response.started",
                Some("turn-a"),
                json!({"response_attempt_id":"attempt-duplicate"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("turn-a"),
                json!({"response_attempt_id":"attempt-duplicate"}),
            )
            .unwrap();
        let original_count = journal.read_events().unwrap().len();
        drop(journal);

        let error = match store.open("duplicate-response-recovery") {
            Ok(_) => panic!("duplicate response starts must fail before recovery"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("duplicate response.started"));
        assert_eq!(
            store.inspect("duplicate-response-recovery").unwrap().len(),
            original_count
        );
    }

    #[test]
    fn recovers_unfinished_compaction_once() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("unfinished-compaction", header(temp.path()))
            .unwrap();
        let started = journal
            .append_and_sync(
                COMPACTION_STARTED_KIND,
                None,
                json!({
                    "attempt_id": "compact-1",
                    "parent_checkpoint_id": null,
                    "covers_through_seq": 0,
                    "source": [],
                    "source_digest": "digest",
                    "instructions": "summarize",
                    "prompt_version": 1,
                    "model": "test-model",
                }),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("unfinished-compaction").unwrap();
        assert_eq!(recovered.recovery_info().aborted_compactions, 1);
        let events = recovered.read_events().unwrap();
        let aborted = events
            .iter()
            .find(|event| event.kind == COMPACTION_ABORTED_KIND)
            .unwrap();
        assert_eq!(aborted.data["attempt_id"], "compact-1");
        assert_eq!(aborted.data["started_seq"], started.seq);
        assert_eq!(aborted.data["code"], "interrupted");
        assert_eq!(aborted.data["recovered"], true);
        drop(recovered);

        let reopened = store.open("unfinished-compaction").unwrap();
        assert_eq!(reopened.recovery_info().aborted_compactions, 1);
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == COMPACTION_ABORTED_KIND)
                .count(),
            1
        );
    }

    #[test]
    fn recovers_compaction_boundary_before_provider_attempt_once() {
        use crate::compaction::{
            COMPACTION_BOUNDARY_FAILED_KIND, CompactionBoundary, CompactionBoundaryStarted,
            validate_compaction_boundary_chain,
        };
        use crate::turn::TURN_BOUNDARY_VERSION;

        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("unfinished-compaction-boundary", header(temp.path()))
            .unwrap();
        let user = journal
            .append_and_sync(
                "user.message",
                Some("turn-boundary"),
                json!({
                    "item":{"role":"user","content":"continue after recovery"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                crate::compaction::COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: CompactionBoundary::new(
                        "boundary-before-attempt",
                        "turn-boundary",
                        user.seq,
                    ),
                    trigger: "context_trigger".to_owned(),
                    extra: Map::new(),
                })
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("unfinished-compaction-boundary").unwrap();
        assert_eq!(recovered.recovery_info().failed_compaction_boundaries, 1);
        let events = recovered.read_events().unwrap();
        let failed = events
            .iter()
            .find(|event| event.kind == COMPACTION_BOUNDARY_FAILED_KIND)
            .expect("session-open recovery appends a boundary failure");
        assert_eq!(failed.data["boundary_id"], "boundary-before-attempt");
        assert_eq!(failed.data["code"], "interrupted_before_attempt");
        assert_eq!(failed.data["recovered"], true);
        assert!(
            validate_compaction_boundary_chain(&events)
                .unwrap()
                .latest_pending()
                .is_some()
        );
        drop(recovered);

        let reopened = store.open("unfinished-compaction-boundary").unwrap();
        assert_eq!(reopened.recovery_info().failed_compaction_boundaries, 1);
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == COMPACTION_BOUNDARY_FAILED_KIND)
                .count(),
            1
        );
    }

    #[test]
    fn terminal_compaction_events_settle_attempts() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("terminal-compactions", header(temp.path()))
            .unwrap();
        for (index, terminal_kind) in [
            COMPACTION_CHECKPOINT_KIND,
            COMPACTION_FAILED_KIND,
            COMPACTION_ABORTED_KIND,
        ]
        .into_iter()
        .enumerate()
        {
            let attempt_id = format!("compact-{index}");
            journal
                .append_and_sync(
                    COMPACTION_STARTED_KIND,
                    None,
                    json!({"attempt_id": attempt_id}),
                )
                .unwrap();
            journal
                .append_and_sync(terminal_kind, None, json!({"attempt_id": attempt_id}))
                .unwrap();
        }
        drop(journal);

        let reopened = store.open("terminal-compactions").unwrap();
        assert_eq!(reopened.recovery_info().aborted_compactions, 0);
        assert!(
            !reopened
                .read_events()
                .unwrap()
                .iter()
                .any(|event| event.kind == COMPACTION_ABORTED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true))
        );
    }

    #[test]
    fn recovers_function_call_that_never_started() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("unstarted-tool", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "response.completed",
                Some("turn-tool"),
                json!({
                    "response_attempt_id":"attempt-2",
                    "output_items":[{
                        "type":"function_call",
                        "id":"call-from-id",
                        "name":"read",
                        "arguments":"{\"path\":\"calc.py\"}"
                    }]
                }),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("unstarted-tool").unwrap();
        assert_eq!(recovered.recovery_info().skipped_before_start, 1);
        let events = recovered.read_events().unwrap();
        let skipped = events
            .iter()
            .find(|event| event.kind == "tool.skipped_due_to_recovery")
            .unwrap();
        assert_eq!(skipped.data["call_id"], "call-from-id");
        assert_eq!(
            skipped.data["recovery_marker_seq"].as_u64(),
            recovered.recovery_info().marker_seq
        );
        assert!(recovered.recovery_info().marker_seq.unwrap() < skipped.seq);
        drop(recovered);

        let reopened = store.open("unstarted-tool").unwrap();
        assert_eq!(reopened.recovery_info().skipped_before_start, 1);
        assert_eq!(
            reopened
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "tool.skipped_due_to_recovery")
                .count(),
            1
        );
    }

    #[test]
    fn legacy_oversized_unstarted_batch_is_preflighted_in_bounded_markers() {
        let tools = (0..=MAX_MCP_CALLS_PER_RESPONSE)
            .map(|index| UnstartedTool {
                response_seq: 4,
                turn_id: Some("turn-tool".to_owned()),
                call_id: format!("call-{index}"),
                tool_name: Some("read".to_owned()),
                arguments: Some(json!({"index":index})),
            })
            .collect::<Vec<_>>();
        preflight_recovery_authorization_batches(&tools)
            .expect("all marker payloads must be valid before recovery writes");
        let recovery = RecoveryInfo {
            skipped_before_start: tools.len(),
            ..RecoveryInfo::default()
        };
        let markers = tools
            .chunks(MAX_MCP_CALLS_PER_RESPONSE)
            .map(|chunk| recovery_marker_data(&recovery, chunk).expect("bounded marker"))
            .collect::<Vec<_>>();
        assert_eq!(markers.len(), 2);
        assert_eq!(
            markers[0]["unstarted_tool_calls"]
                .as_array()
                .expect("first authorization batch")
                .len(),
            MAX_MCP_CALLS_PER_RESPONSE
        );
        assert_eq!(
            markers[1]["unstarted_tool_calls"]
                .as_array()
                .expect("second authorization batch")
                .len(),
            1
        );
        assert!(recovery_marker_data(&recovery, &tools).is_err());
    }

    #[test]
    fn recovery_transaction_reserves_all_events_before_writing() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("recovery-capacity", header(temp.path()))
            .unwrap();
        let tools = vec![UnstartedTool {
            response_seq: 2,
            turn_id: Some("turn-tool".to_owned()),
            call_id: "call-1".to_owned(),
            tool_name: Some("read".to_owned()),
            arguments: Some(json!({"path":"calc.py"})),
        }];
        let mut recovery = RecoveryInfo {
            skipped_before_start: 1,
            ..RecoveryInfo::default()
        };
        let mut planned_seq = journal.next_seq();
        let mut events = vec![
            planned_recovery_event(
                journal.session_id(),
                &mut planned_seq,
                "response.aborted",
                Some("turn-tool"),
                json!({
                    "response_attempt_id":"attempt-1",
                    "started_seq":2,
                    "reason":"recovered",
                    "recovered":true
                }),
            )
            .unwrap(),
        ];
        events.extend(
            plan_mcp_recovery_events(
                journal.session_id(),
                planned_seq,
                &mut recovery,
                &tools,
                false,
            )
            .unwrap(),
        );
        assert_eq!(events.len(), 3);
        let first_event_bytes = serde_json::to_vec(&events[0]).unwrap().len() as u64 + 1;
        let original_size = journal.file.metadata().unwrap().len();
        let original_seq = journal.next_seq();

        let error = journal
            .append_prebuilt_batch_with_limit(&events, original_size + first_event_bytes)
            .expect_err("the complete transaction must not fit")
            .to_string();
        assert!(error.contains("journal transaction would exceed"));
        assert_eq!(journal.file.metadata().unwrap().len(), original_size);
        assert_eq!(journal.next_seq(), original_seq);
        assert!(!journal.poisoned);
    }

    #[test]
    fn unstarted_call_lifecycle_index_is_scoped_by_turn() {
        let base = Utc::now();
        let event = |seq, kind: &str, turn_id: &str, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: base,
            kind: kind.to_owned(),
            session_id: "turn-scoped".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let events = vec![
            event(
                1,
                "response.completed",
                "turn-a",
                json!({"output_items":[{
                    "type":"function_call", "call_id":"shared", "name":"read", "arguments":{}
                }]}),
            ),
            event(
                2,
                "response.completed",
                "turn-b",
                json!({"output_items":[{
                    "type":"function_call", "call_id":"shared", "name":"read", "arguments":{}
                }]}),
            ),
            event(3, "tool.completed", "turn-a", json!({"call_id":"shared"})),
        ];

        let pending = unstarted_tool_calls(&events);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].turn_id.as_deref(), Some("turn-b"));
    }

    #[test]
    fn pending_call_lifecycle_index_is_scoped_by_turn() {
        let base = Utc::now();
        let event = |seq, kind: &str, turn_id: &str, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: base,
            kind: kind.to_owned(),
            session_id: "pending-turn-scoped".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let events = vec![
            event(
                1,
                "tool.started",
                "turn-a",
                json!({"call_id":"shared","tool":"read"}),
            ),
            event(
                2,
                "tool.started",
                "turn-b",
                json!({"call_id":"shared","tool":"read"}),
            ),
            event(
                3,
                "tool.completed",
                "turn-a",
                json!({"call_id":"shared","output":"ok"}),
            ),
        ];

        let pending = pending_tools(&events);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].started_seq, 2);
        assert_eq!(pending[0].turn_id.as_deref(), Some("turn-b"));
    }

    #[test]
    fn pending_call_started_seq_cannot_cross_identity() {
        let base = Utc::now();
        let event = |seq, kind: &str, turn_id: &str, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: base,
            kind: kind.to_owned(),
            session_id: "pending-started-seq".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let events = vec![
            event(
                1,
                "tool.started",
                "turn-a",
                json!({"call_id":"call-a","tool":"read"}),
            ),
            event(
                2,
                "tool.started",
                "turn-b",
                json!({"call_id":"call-b","tool":"read"}),
            ),
            event(
                3,
                "tool.completed",
                "turn-b",
                json!({"call_id":"call-b","started_seq":1,"output":"ok"}),
            ),
        ];

        let pending = pending_tools(&events);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].started_seq, 1);
        assert_eq!(pending[0].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(pending[1].started_seq, 2);
        assert_eq!(pending[1].turn_id.as_deref(), Some("turn-b"));
    }

    #[test]
    fn invalid_mcp_response_chain_is_rejected_before_recovery_writes() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("invalid-mcp-response", header(temp.path()))
            .unwrap();
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        journal
            .append_and_sync(
                "mcp.registry.activated",
                None,
                json!({
                    "coordinator_version":1,
                    "call_chain_validator_version":1,
                    "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000001",
                    "registry_epoch_id":epoch,
                    "registry_version":1,
                    "stdio_kernel_version":1,
                    "schema_profile_version":1,
                    "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "registry_digest":digest,
                    "provider_names":["mcp_fixture_echo_deadbeef"]
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-mcp"),
                json!({"turn_boundary_version":6}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("turn-mcp"),
                json!({
                    "response_attempt_id":"attempt-1",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest
                }),
            )
            .unwrap();
        for call_id in ["call-1", "call-2"] {
            journal
                .append_and_sync(
                    "response.completed",
                    Some("turn-mcp"),
                    json!({
                        "response_attempt_id":"attempt-1",
                        "output_items":[{
                            "type":"function_call",
                            "call_id":call_id,
                            "name":"mcp_fixture_echo_deadbeef",
                            "arguments":"{}"
                        }]
                    }),
                )
                .unwrap();
        }
        let original_count = journal.read_events().unwrap().len();
        drop(journal);

        let error = store
            .open("invalid-mcp-response")
            .err()
            .expect("invalid MCP chain must fail before recovery")
            .to_string();
        assert!(
            error.contains("has 2 terminals"),
            "unexpected error: {error}"
        );
        assert_eq!(
            store.inspect("invalid-mcp-response").unwrap().len(),
            original_count
        );
    }

    #[test]
    fn completed_tools_are_not_in_doubt() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("completed", header(temp.path()))
            .unwrap();
        journal
            .append("tool.started", Some("turn"), json!({"call_id": "call"}))
            .unwrap();
        journal
            .append_and_sync("tool.completed", Some("turn"), json!({"call_id": "call"}))
            .unwrap();
        drop(journal);

        let reopened = store.open("completed").unwrap();
        assert!(reopened.recovery_info().in_doubt.is_empty());
    }

    #[test]
    fn normalizes_a_complete_final_line_without_a_newline() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("no-newline", header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let mut bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(&path, bytes).unwrap();

        let reopened = store.open("no-newline").unwrap();
        assert!(reopened.recovery_info().normalized_missing_newline);
        assert!(reopened.recovery_info().truncated_tail.is_none());
        assert!(fs::read(&path).unwrap().ends_with(b"\n"));
    }

    #[test]
    fn rejects_path_like_session_ids() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        assert!(store.open("../escape").is_err());
        assert!(store.open("nested/session").is_err());
    }

    #[test]
    fn lists_and_inspects_sessions_without_opening_them() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store.create_with_id("listed", header(temp.path())).unwrap();
        journal
            .append_and_sync("user.message", Some("turn"), json!({"text": "hello"}))
            .unwrap();
        drop(journal);

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].session_id, "listed");
        assert_eq!(summaries[0].event_count, 2);
        assert_eq!(summaries[0].header.model, "test-model");

        let events = store.inspect("listed").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].kind, "user.message");
        assert!(store.inspect("missing").is_err());
    }

    #[test]
    fn legacy_session_header_gets_pre_v01_version() {
        let header: SessionHeader = serde_json::from_value(json!({
            "project_root": "project",
            "model": "test-model",
        }))
        .unwrap();
        assert_eq!(header.version, "pre-v0.1");
        assert_eq!(
            SessionHeader::new("project", "test-model").version,
            env!("CARGO_PKG_VERSION")
        );
    }
}
