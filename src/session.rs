use std::collections::BTreeMap;
#[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compaction::{
    COMPACTION_ABORTED_KIND, COMPACTION_BOUNDARY_CHECKPOINTED_KIND,
    COMPACTION_BOUNDARY_FAILED_KIND, COMPACTION_STARTED_KIND, CompactionBoundaryRecoveryAction,
    compaction_boundary_recovery_actions,
};
#[cfg(test)]
use crate::compaction::{COMPACTION_CHECKPOINT_KIND, COMPACTION_FAILED_KIND};
use crate::error::{OxidraError, Result};
use crate::event_kind::{
    is_compaction_lifecycle, is_compaction_terminal, is_response_terminal, is_tool_lifecycle,
    is_tool_terminal,
};
use crate::mcp::MAX_MCP_CALLS_PER_RESPONSE;
use crate::turn::provider_request_slot_state_for_version;

pub const JOURNAL_SCHEMA: u32 = 1;
pub const SESSION_STARTED_KIND: &str = "session.started";
pub const RECOVERY_KIND: &str = "journal.recovered";
const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;

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
            mcp_resume_open_id: None,
            mcp_resume_eligibility_issued: false,
        };
        journal.append_and_sync(SESSION_STARTED_KIND, None, serde_json::to_value(header)?)?;
        Ok(journal)
    }

    pub fn open(&self, session_id: &str) -> Result<SessionJournal> {
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
        validate_events(&scan.events, session_id)?;
        let next_seq = match scan.events.last() {
            Some(event) => event
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence is exhausted".to_owned()))?,
            None => 1,
        };
        let unfinished_responses = unfinished_responses(&scan.events);
        let previously_aborted_responses = scan
            .events
            .iter()
            .filter(|event| {
                event.kind == "response.aborted"
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let aborted_responses = previously_aborted_responses + unfinished_responses.len();
        let unfinished_compactions = unfinished_compactions(&scan.events);
        let previously_aborted_compactions = scan
            .events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_ABORTED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let aborted_compactions = previously_aborted_compactions + unfinished_compactions.len();
        let failed_compaction_boundaries = scan
            .events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_BOUNDARY_FAILED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        let checkpointed_compaction_boundaries = scan
            .events
            .iter()
            .filter(|event| {
                event.kind == COMPACTION_BOUNDARY_CHECKPOINTED_KIND
                    && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
            })
            .count();
        crate::mcp::validate_mcp_call_chain(&scan.events)?;
        let unstarted_tools = unstarted_tool_calls(&scan.events);
        // Build every authorization payload before the first recovery write.
        // Legacy call-chain v1 could durably contain more than the current
        // per-response maximum, so recovery chunks that old batch into
        // multiple independently bounded v1 markers instead of rewriting the
        // frozen validator or poisoning the journal midway through repair.
        preflight_recovery_authorization_batches(&unstarted_tools)?;
        let previously_skipped = scan
            .events
            .iter()
            .filter(|event| event.kind == "tool.skipped_due_to_recovery")
            .count();
        let skipped_before_start = previously_skipped + unstarted_tools.len();
        let in_doubt = pending_tools(&scan.events);
        let mut recovery = RecoveryInfo {
            truncated_tail: scan.truncated_tail,
            normalized_missing_newline: scan.normalized_missing_newline,
            in_doubt,
            marker_seq: None,
            skipped_before_start,
            aborted_responses,
            aborted_compactions,
            failed_compaction_boundaries,
            checkpointed_compaction_boundaries,
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
            // This nonce identifies the exact recovered journal handle that
            // authorized a later MCP resume.  A newly-created journal cannot
            // mint that capability, and reopening after dropping this handle
            // produces a different nonce.
            mcp_resume_open_id: Some(Uuid::now_v7().to_string()),
            mcp_resume_eligibility_issued: false,
        };
        fs::create_dir_all(&journal.artifact_dir)?;

        let recovered_unfinished_response = !unfinished_responses.is_empty();
        for response in unfinished_responses {
            journal.append_and_sync(
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
            journal.append_and_sync(
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

        let recovered_boundaries = recover_compaction_boundaries(&mut journal)?;
        recovery.failed_compaction_boundaries = recovery
            .failed_compaction_boundaries
            .saturating_add(recovered_boundaries.failed);
        recovery.checkpointed_compaction_boundaries = recovery
            .checkpointed_compaction_boundaries
            .saturating_add(recovered_boundaries.checkpointed);
        let mcp_turn_ids = crate::mcp::mcp_turn_ids(&journal.read_events()?)?;
        for turn_id in &mcp_turn_ids {
            // Use the frozen generic slot v2 as a recovery-consistency check;
            // slot v3 calls back into the MCP validator and is therefore not
            // used from inside this validator-owned repair window.
            provider_request_slot_state_for_version(2, &journal.read_events()?, turn_id)?;
        }
        recovery.marker_seq = matching_recovery_marker(
            &scan.events,
            &recovery.in_doubt,
            recovery.skipped_before_start,
            recovery.aborted_responses,
            recovery.aborted_compactions,
            recovery.failed_compaction_boundaries,
            recovery.checkpointed_compaction_boundaries,
        );

        let recovered_unstarted = !unstarted_tools.is_empty();
        if recovered_unstarted {
            for tools in unstarted_tools.chunks(MAX_MCP_CALLS_PER_RESPONSE) {
                let event = journal.append_and_sync(
                    RECOVERY_KIND,
                    None,
                    recovery_marker_data(&recovery, tools)?,
                )?;
                recovery.marker_seq = Some(event.seq);

                // Each skip binds to the exact bounded marker that authorized
                // its call. If recovery is interrupted, the next reopen may
                // append a fresh marker for only the remaining calls; unused
                // markers are harmless and the frozen validator stays valid.
                for tool in tools {
                    append_recovery_tool_skip(&mut journal, tool, event.seq)?;
                }
            }
        } else if recovery.truncated_tail.is_some()
            || recovered_unfinished_response
            || recovered_unfinished_compaction
            || (!recovery.in_doubt.is_empty() && recovery.marker_seq.is_none())
            || (recovery.skipped_before_start > 0 && recovery.marker_seq.is_none())
            || (recovery.aborted_responses > 0 && recovery.marker_seq.is_none())
            || (recovery.aborted_compactions > 0 && recovery.marker_seq.is_none())
            || (recovery.failed_compaction_boundaries > 0 && recovery.marker_seq.is_none())
            || (recovery.checkpointed_compaction_boundaries > 0 && recovery.marker_seq.is_none())
        {
            let event = journal.append_and_sync(
                RECOVERY_KIND,
                None,
                recovery_marker_data(&recovery, &unstarted_tools)?,
            )?;
            recovery.marker_seq = Some(event.seq);
        }
        crate::mcp::validate_mcp_call_chain(&journal.read_events()?)?;
        let final_events = journal.read_events()?;
        for turn_id in &mcp_turn_ids {
            provider_request_slot_state_for_version(2, &final_events, turn_id)?;
        }
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
}

impl RecoveryInfo {
    pub fn recovered(&self) -> bool {
        self.marker_seq.is_some() || self.normalized_missing_newline
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
    mcp_resume_open_id: Option<String>,
    mcp_resume_eligibility_issued: bool,
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
            > MAX_SESSION_BYTES
        {
            return Err(OxidraError::Session(format!(
                "session journal would exceed the {MAX_SESSION_BYTES}-byte safety limit"
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
    let mut call_ids = BTreeMap::<String, Vec<u64>>::new();

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
                    call_ids.entry(call_id).or_default().push(event.seq);
                }
                pending.insert(event.seq, tool);
            }
            "tool.in_doubt" => {
                record_in_doubt_tool(event, &mut pending, &mut call_ids);
            }
            kind if is_tool_terminal(kind) => {
                resolve_tool(&event.data, &mut pending, &mut call_ids);
            }
            _ => {}
        }
    }
    pending.into_values().collect()
}

fn record_in_doubt_tool(
    event: &JournalEvent,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut BTreeMap<String, Vec<u64>>,
) {
    let call_id = string_field(&event.data, &["call_id", "id"]);
    let referenced_seq = event.data.get("started_seq").and_then(Value::as_u64);
    let existing_seq = referenced_seq
        .filter(|seq| pending.contains_key(seq))
        .or_else(|| {
            call_id.as_ref().and_then(|id| {
                call_ids
                    .get(id)
                    .and_then(|sequences| sequences.last().copied())
            })
        });

    if let Some(started_seq) = existing_seq {
        let updated_ids = pending.get_mut(&started_seq).map(|tool| {
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
            (previous_call_id, tool.call_id.clone())
        });
        if let Some((previous_call_id, current_call_id)) = updated_ids {
            if previous_call_id != current_call_id {
                if let Some(previous_call_id) = previous_call_id {
                    remove_call_id_seq(call_ids, &previous_call_id, started_seq);
                }
                if let Some(current_call_id) = current_call_id {
                    call_ids
                        .entry(current_call_id)
                        .or_default()
                        .push(started_seq);
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
        call_ids.entry(call_id).or_default().push(started_seq);
    }
    pending.insert(started_seq, tool);
}

fn resolve_tool(
    data: &Value,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut BTreeMap<String, Vec<u64>>,
) {
    if let Some(started_seq) = data.get("started_seq").and_then(Value::as_u64) {
        if let Some(tool) = pending.remove(&started_seq) {
            if let Some(call_id) = tool.call_id {
                remove_call_id_seq(call_ids, &call_id, started_seq);
            }
        }
        return;
    }
    if let Some(call_id) = string_field(data, &["call_id", "id"]) {
        if let Some(started_seq) = call_ids
            .get(&call_id)
            .and_then(|sequences| sequences.last().copied())
        {
            remove_call_id_seq(call_ids, &call_id, started_seq);
            pending.remove(&started_seq);
        }
    }
}

fn remove_call_id_seq(call_ids: &mut BTreeMap<String, Vec<u64>>, call_id: &str, seq: u64) {
    let empty = {
        let Some(sequences) = call_ids.get_mut(call_id) else {
            return;
        };
        if let Some(index) = sequences.iter().position(|candidate| *candidate == seq) {
            sequences.remove(index);
        }
        sequences.is_empty()
    };
    if empty {
        call_ids.remove(call_id);
    }
}

fn string_field(data: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| data.get(*field).and_then(Value::as_str))
        .map(str::to_owned)
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

fn unfinished_responses(events: &[JournalEvent]) -> Vec<UnfinishedResponse> {
    let mut unfinished = BTreeMap::<String, UnfinishedResponse>::new();
    for event in events {
        match event.kind.as_str() {
            "response.started" => {
                if let Some(response_attempt_id) =
                    string_field(&event.data, &["response_attempt_id"])
                {
                    unfinished.insert(
                        response_attempt_id.clone(),
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
                    unfinished.remove(&response_attempt_id);
                }
            }
            _ => {}
        }
    }
    unfinished.into_values().collect()
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

fn recover_compaction_boundaries(
    journal: &mut SessionJournal,
) -> Result<RecoveredCompactionBoundaries> {
    let events = journal.read_events()?;
    let actions = compaction_boundary_recovery_actions(&events)?;
    let mut recovered = RecoveredCompactionBoundaries::default();
    for action in actions {
        match action {
            CompactionBoundaryRecoveryAction::Checkpointed(payload) => {
                journal.append_and_sync(
                    COMPACTION_BOUNDARY_CHECKPOINTED_KIND,
                    None,
                    serde_json::to_value(payload)?,
                )?;
                recovered.checkpointed = recovered.checkpointed.saturating_add(1);
            }
            CompactionBoundaryRecoveryAction::Failed(payload) => {
                journal.append_and_sync(
                    COMPACTION_BOUNDARY_FAILED_KIND,
                    None,
                    serde_json::to_value(payload)?,
                )?;
                recovered.failed = recovered.failed.saturating_add(1);
            }
        }
    }

    // Re-run the pure reducer against the committed bytes.  Recovery must not
    // merely append plausible-looking events; the resulting protocol state
    // must be self-consistent and require no second repair pass.
    let remaining = compaction_boundary_recovery_actions(&journal.read_events()?)?;
    if !remaining.is_empty() {
        return Err(OxidraError::Session(
            "compaction boundary recovery did not reach a stable state".to_owned(),
        ));
    }
    Ok(recovered)
}

fn unstarted_tool_calls(events: &[JournalEvent]) -> Vec<UnstartedTool> {
    let mut unstarted = BTreeMap::<u64, UnstartedTool>::new();
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
                }
            }
            kind if is_tool_lifecycle(kind) => {
                if let Some(call_id) = string_field(&event.data, &["call_id", "id"]) {
                    if let Some(key) = unstarted
                        .iter()
                        .rev()
                        .find_map(|(key, tool)| (tool.call_id == call_id).then_some(*key))
                    {
                        unstarted.remove(&key);
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

fn append_recovery_tool_skip(
    journal: &mut SessionJournal,
    tool: &UnstartedTool,
    recovery_marker_seq: u64,
) -> Result<()> {
    journal.append_and_sync(
        "tool.skipped_due_to_recovery",
        tool.turn_id.as_deref(),
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
        }),
    )?;
    Ok(())
}

fn matching_recovery_marker(
    events: &[JournalEvent],
    in_doubt: &[InDoubtTool],
    skipped_before_start: usize,
    aborted_responses: usize,
    aborted_compactions: usize,
    failed_compaction_boundaries: usize,
    checkpointed_compaction_boundaries: usize,
) -> Option<u64> {
    if in_doubt.is_empty()
        && skipped_before_start == 0
        && aborted_responses == 0
        && aborted_compactions == 0
        && failed_compaction_boundaries == 0
        && checkpointed_compaction_boundaries == 0
    {
        return None;
    }

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
            (same_in_doubt_set(&marked, in_doubt)
                && marked_skipped == skipped_before_start
                && marked_aborted == aborted_responses
                && marked_aborted_compactions == aborted_compactions
                && marked_failed_compaction_boundaries == failed_compaction_boundaries
                && marked_checkpointed_compaction_boundaries == checkpointed_compaction_boundaries)
                .then_some(event.seq)
        })
}

fn same_in_doubt_set(left: &[InDoubtTool], right: &[InDoubtTool]) -> bool {
    let mut left_keys = left
        .iter()
        .map(|tool| {
            (
                tool.started_seq,
                tool.call_id.as_deref().unwrap_or_default().to_owned(),
                tool.tool_name.as_deref().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let mut right_keys = right
        .iter()
        .map(|tool| {
            (
                tool.started_seq,
                tool.call_id.as_deref().unwrap_or_default().to_owned(),
                tool.tool_name.as_deref().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    left_keys.sort();
    right_keys.sort();
    left_keys == right_keys
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
