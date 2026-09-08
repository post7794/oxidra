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
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
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
use crate::execution_guardian::{ExecutionGuardianLeaseV1, ensure_execution_gate_quiescent_v1};
use crate::fs_security::{enforce_private_file, ensure_private_dir, private_create_options};
use crate::mcp::{
    LiveMcpJournalWriteProofV1, MAX_MCP_CALLS_PER_RESPONSE, MAX_RESPONSE_STATUS_TEXT_BYTES_V2,
    McpJournalWriteCapabilityV1, McpRegistryActivationAdmissionV1,
    response_status_text_for_journal,
};
use crate::turn::{
    PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION, ProviderRequestSlotState, TurnState,
    provider_request_slot_state_for_version, segment_turns, validate_provider_request_slots_v2,
};

pub const JOURNAL_SCHEMA: u32 = 1;
pub const SESSION_STARTED_KIND: &str = "session.started";
pub const RECOVERY_KIND: &str = "journal.recovered";
const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;
/// Journal schema 1 predates a bounded decoded-JSON profile.  New sessions
/// opt into profile 2 in `session.started`; an absent marker means the literal
/// legacy schema-1 language and must not be reinterpreted retroactively.
/// This marker lives in the serialized `JournalEvent` envelope, not inside
/// `session.started.data`. Historical callers could populate arbitrary
/// flattened header data, so a data-level marker could retroactively
/// reinterpret a legitimate schema-1 session as a newer bounded profile.
const JOURNAL_JSON_PROFILE_FIELD: &str = "journal_json_profile";
const JOURNAL_JSON_PROFILE_V2: u64 = 2;
/// Frozen profile for journals created by the current writer.  Data depth stays
/// below serde_json's default recursion limit after accounting for the event
/// envelope; the aggregate ledger bounds wide collections on reopen.
const MAX_JOURNAL_DATA_DEPTH_V2: usize = 96;
const MAX_JOURNAL_DATA_NODES_V2: usize = 262_144;
const MAX_JOURNAL_EVENT_DEPTH_V2: usize = 110;
const MAX_JOURNAL_EVENT_NODES_V2: usize = 524_288;
const MAX_JOURNAL_EVENT_BYTES_V2: usize = 128 * 1024 * 1024;
const MAX_JOURNAL_EVENTS_V2: usize = 1_000_000;
const MAX_JOURNAL_DECODED_NODES_V2: u64 = 8_000_000;
const MAX_JOURNAL_DECODED_BYTES_V2: u64 = 512 * 1024 * 1024;
const JOURNAL_JSON_PROFILE_NAME_V2: &str = "bounded-json-v2";
/// The historical serde writer could not safely emit JSON anywhere near this
/// depth. Capping the crash-tail grammar stack keeps classification memory
/// independent of a malicious 256 MiB run of opening delimiters while still
/// covering legacy prefixes far beyond serde_json's published recursion limit.
const MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1: usize = 4_096;
const CUSTOM_EVENT_ENVELOPE_FIELD_V1: &str = "custom_event";
const CUSTOM_EVENT_ENVELOPE_VERSION_V1: u64 = 1;
/// Read-only archives deliberately use a suffix that the SessionStore journal
/// scanner can never interpret as a resumable `.jsonl` session. Requiring the
/// suffix at the writer boundary keeps an archive harmless even if an operator
/// selects another SessionStore's `sessions` directory as the destination.
const READ_ONLY_SESSION_EXPORT_EXTENSION_V1: &str = "oxidra-session-export";

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
/// Frozen reserve for one standalone MCP dispatch.  A coordinator call may
/// be admitted without an active Provider turn reservation, so this reserve
/// covers the largest bounded immediate terminal in addition to the
/// prospective crash-recovery debt computed from the whole journal prefix.
/// The MCP transport caps complete results at 50 KiB and coordinator
/// diagnostics use bounded status profiles; one MiB leaves room for the
/// journal envelope without depending on a caller's output value.
const MCP_TOOL_OUTCOME_HEADROOM_BYTES_V1: u64 = 1024 * 1024;
/// Minimum per-call terminal slot retained for an explicit in-doubt
/// resolution.  The actual reservation is larger when the durable call/tool
/// identity itself is larger: provider call IDs are not currently bounded by
/// this profile, so a fixed 16 KiB slot alone would make a valid long-ID call
/// impossible to resolve.
const MIN_IN_DOUBT_RESOLUTION_HEADROOM_BYTES_V1: u64 = 16 * 1024;
/// Extra envelope margin above the exact canonical resolution event.  This
/// covers timestamp/sequence representation changes within journal schema v1
/// without turning an exact-size estimate into a fail-open promise.
const IN_DOUBT_RESOLUTION_ENVELOPE_MARGIN_BYTES_V1: u64 = 4096;
/// Frozen authority carried by `journal.recovered` while an in-doubt
/// resolution transaction is pending.  Versioned markers may continue to
/// authorize the same lineage after a crash has durably resolved only a
/// subset of the calls; unversioned historical markers remain readable but
/// cannot waive capacity for a future recovery marker.
const IN_DOUBT_RESOLUTION_AUTHORIZATION_VERSION_V1: u64 = 1;
/// A tool-start lifecycle can cause the same argument/data payload to appear
/// in the old skip authorization, the recovered in-doubt event, and one or
/// more future recovery markers.  Keep the live ledger O(1) per event with a
/// deliberately conservative multiplier rather than rescanning the journal
/// for every call in a wide Provider batch.  The turn's fixed 1 MiB floor
/// absorbs most envelope variance; a separate margin is charged at most once
/// per live turn rather than once per call, or the frozen 4096-call surface
/// would exceed the entire journal limit even when every lifecycle payload is
/// tiny.
const RECOVERY_LIFECYCLE_DUPLICATION_FACTOR_V1: u64 = 8;
const RECOVERY_LIFECYCLE_MARGIN_BYTES_V1: u64 = 64 * 1024;
const _: () =
    assert!(MAX_RESPONSE_STATUS_TEXT_BYTES_V2 <= MAX_PROVIDER_RESPONSE_STATUS_BYTES_FOR_OUTCOME_V1);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct JournalEvent {
    pub schema: u32,
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub data: Value,
}

impl Clone for JournalEvent {
    fn clone(&self) -> Self {
        Self {
            schema: self.schema,
            seq: self.seq,
            ts: self.ts,
            kind: self.kind.clone(),
            session_id: self.session_id.clone(),
            turn_id: self.turn_id.clone(),
            // `JournalEvent` is a public fixture type, so a safe caller can
            // construct a Value far deeper than serde_json's recursive Clone
            // can tolerate. Runtime reducers clone events while normalizing a
            // frozen view; keep that path iterative just like Drop.
            data: clone_json_value_iteratively_v1(&self.data),
        }
    }
}

#[derive(Serialize)]
struct ProfiledSessionStartedEventV2<'a> {
    schema: u32,
    seq: u64,
    ts: &'a DateTime<Utc>,
    kind: &'a str,
    session_id: &'a str,
    turn_id: &'a Option<String>,
    data: &'a Value,
    #[serde(rename = "journal_json_profile")]
    json_profile: JournalJsonProfileClaimV2,
}

#[derive(Debug)]
enum JournalJsonProfileClaimPresenceV2 {
    Absent,
    Present(JournalJsonProfileClaimV2),
}

impl Default for JournalJsonProfileClaimPresenceV2 {
    fn default() -> Self {
        Self::Absent
    }
}

impl<'de> Deserialize<'de> for JournalJsonProfileClaimPresenceV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        JournalJsonProfileClaimV2::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
struct JournalJsonProfileProbeV2 {
    kind: String,
    #[serde(default, rename = "journal_json_profile")]
    claim: JournalJsonProfileClaimPresenceV2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum JournalJsonProfile {
    /// Literal pre-profile schema-1 behavior.  serde_json's historical parser
    /// limit remains the compatibility boundary and no aggregate decoded
    /// ledger is imposed retroactively.
    LegacyV1,
    /// Explicitly activated bounded writer/reader profile.
    #[default]
    BoundedV2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalJsonProfileClaimV2 {
    name: String,
    version: u64,
}

impl JournalJsonProfileClaimV2 {
    fn current() -> Self {
        Self {
            name: JOURNAL_JSON_PROFILE_NAME_V2.to_owned(),
            version: JOURNAL_JSON_PROFILE_V2,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.name != JOURNAL_JSON_PROFILE_NAME_V2 || self.version != JOURNAL_JSON_PROFILE_V2 {
            return Err(OxidraError::Session(format!(
                "unsupported journal JSON profile {} version {}",
                self.name, self.version
            )));
        }
        Ok(())
    }
}

impl JournalEvent {
    /// Extract the owned payload without invoking serde_json's recursive
    /// destructor. This is primarily useful to fixture/projection code that
    /// consumes a complete event.
    pub fn into_data(mut self) -> Value {
        std::mem::replace(&mut self.data, Value::Null)
    }
}

/// `JournalEvent` is public for projection/fixture compatibility, so callers
/// can still construct one directly with an adversarially deep `Value`.  A
/// custom destructor keeps every rejection/fixture cleanup path iterative;
/// otherwise merely returning an encoding error could overflow the host stack.
impl Drop for JournalEvent {
    fn drop(&mut self) {
        let value = std::mem::replace(&mut self.data, Value::Null);
        crate::mcp::drop_json_value_iteratively(value);
    }
}

enum BorrowedJsonDepthFrameV1<'a> {
    Value(&'a Value, usize),
    Array(std::slice::Iter<'a, Value>, usize),
    Object(serde_json::map::Iter<'a>, usize),
}

/// Check a caller-constructed JSON tree before recursive serde operations.
/// This does not select or narrow a durable journal profile; consumers pass
/// the historical depth ceiling already enforced at their wire boundary.
pub(crate) fn validate_borrowed_json_depth_v1(
    value: &Value,
    maximum_depth: usize,
    profile: &str,
    label: &str,
) -> Result<()> {
    let mut pending = vec![BorrowedJsonDepthFrameV1::Value(value, 0)];
    while let Some(frame) = pending.pop() {
        match frame {
            BorrowedJsonDepthFrameV1::Value(value, depth) => {
                if depth > maximum_depth {
                    return Err(OxidraError::Session(format!(
                        "{label} exceeds the {maximum_depth}-level {profile} depth profile"
                    )));
                }
                match value {
                    Value::Array(values) => pending.push(BorrowedJsonDepthFrameV1::Array(
                        values.iter(),
                        depth.saturating_add(1),
                    )),
                    Value::Object(values) => pending.push(BorrowedJsonDepthFrameV1::Object(
                        values.iter(),
                        depth.saturating_add(1),
                    )),
                    _ => {}
                }
            }
            BorrowedJsonDepthFrameV1::Array(mut values, depth) => {
                if let Some(value) = values.next() {
                    pending.push(BorrowedJsonDepthFrameV1::Array(values, depth));
                    pending.push(BorrowedJsonDepthFrameV1::Value(value, depth));
                }
            }
            BorrowedJsonDepthFrameV1::Object(mut values, depth) => {
                if let Some((_, value)) = values.next() {
                    pending.push(BorrowedJsonDepthFrameV1::Object(values, depth));
                    pending.push(BorrowedJsonDepthFrameV1::Value(value, depth));
                }
            }
        }
    }
    Ok(())
}

enum JsonCloneFrameV1<'a> {
    Array {
        remaining: std::slice::Iter<'a, Value>,
        output: Vec<Value>,
    },
    Object {
        remaining: serde_json::map::Iter<'a>,
        output: Map<String, Value>,
        pending_key: String,
    },
}

/// Clone a JSON tree without recursion.
///
/// Durable readers already bound parsed depth, but crate-public reducers also
/// accept caller-constructed `JournalEvent` fixtures. Those values have not
/// crossed the journal profile, so recursive `Value::clone()` would let safe
/// Rust input overflow the process stack before a reducer can reject or ignore
/// it.
pub(crate) fn clone_json_value_iteratively_v1(root: &Value) -> Value {
    let mut frames = Vec::<JsonCloneFrameV1<'_>>::new();
    let mut current = root;

    loop {
        let mut completed = match current {
            Value::Null => Value::Null,
            Value::Bool(value) => Value::Bool(*value),
            Value::Number(value) => Value::Number(value.clone()),
            Value::String(value) => Value::String(value.clone()),
            Value::Array(values) => {
                let mut remaining = values.iter();
                let output = Vec::with_capacity(values.len());
                if let Some(next) = remaining.next() {
                    frames.push(JsonCloneFrameV1::Array { remaining, output });
                    current = next;
                    continue;
                }
                Value::Array(output)
            }
            Value::Object(values) => {
                let mut remaining = values.iter();
                let output = Map::new();
                if let Some((key, next)) = remaining.next() {
                    frames.push(JsonCloneFrameV1::Object {
                        remaining,
                        output,
                        pending_key: key.clone(),
                    });
                    current = next;
                    continue;
                }
                Value::Object(output)
            }
        };

        loop {
            let Some(frame) = frames.pop() else {
                return completed;
            };
            match frame {
                JsonCloneFrameV1::Array {
                    mut remaining,
                    mut output,
                } => {
                    output.push(completed);
                    if let Some(next) = remaining.next() {
                        frames.push(JsonCloneFrameV1::Array { remaining, output });
                        current = next;
                        break;
                    }
                    completed = Value::Array(output);
                }
                JsonCloneFrameV1::Object {
                    mut remaining,
                    mut output,
                    pending_key,
                } => {
                    output.insert(pending_key, completed);
                    if let Some((key, next)) = remaining.next() {
                        frames.push(JsonCloneFrameV1::Object {
                            remaining,
                            output,
                            pending_key: key.clone(),
                        });
                        current = next;
                        break;
                    }
                    completed = Value::Object(output);
                }
            }
        }
    }
}

struct JournalValueOwnerV2 {
    value: Option<Value>,
}

impl JournalValueOwnerV2 {
    fn new(value: Value) -> Result<Self> {
        let owner = Self { value: Some(value) };
        validate_journal_data_value_v2(owner.as_value())?;
        Ok(owner)
    }

    fn as_value(&self) -> &Value {
        self.value.as_ref().expect("journal value owner")
    }

    fn into_value(mut self) -> Value {
        self.value.take().expect("journal value owner")
    }
}

impl Drop for JournalValueOwnerV2 {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            crate::mcp::drop_json_value_iteratively(value);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct JournalJsonMetricsV2 {
    nodes: usize,
    encoded_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct JournalDecodeBudgetV2 {
    events: usize,
    nodes: u64,
    decoded_bytes: u64,
}

impl JournalDecodeBudgetV2 {
    fn account(&mut self, metrics: JournalJsonMetricsV2) -> Result<()> {
        self.events = self
            .events
            .checked_add(1)
            .ok_or_else(|| OxidraError::Session("journal event count overflow".to_owned()))?;
        if self.events > MAX_JOURNAL_EVENTS_V2 {
            return Err(OxidraError::Session(format!(
                "journal exceeds the {MAX_JOURNAL_EVENTS_V2}-event decoded profile"
            )));
        }

        let nodes = u64::try_from(metrics.nodes)
            .map_err(|_| OxidraError::Session("journal JSON node count overflow".to_owned()))?;
        self.nodes = self.nodes.checked_add(nodes).ok_or_else(|| {
            OxidraError::Session("journal decoded JSON node count overflow".to_owned())
        })?;
        if self.nodes > MAX_JOURNAL_DECODED_NODES_V2 {
            return Err(OxidraError::Session(format!(
                "journal exceeds the {MAX_JOURNAL_DECODED_NODES_V2}-node decoded profile"
            )));
        }

        // A JSON node materialized by serde_json carries enum/container
        // bookkeeping in addition to its source bytes. Charge a deliberately
        // conservative fixed allocation estimate per node, plus the exact
        // encoded bytes retained by String/object-key storage. The estimate
        // is a protocol budget rather than a Rust layout promise: changing it
        // requires a new reader profile instead of silently widening reopen.
        const DECODED_NODE_ALLOCATION_BYTES_V2: u64 = 64;
        let encoded = u64::try_from(metrics.encoded_bytes).map_err(|_| {
            OxidraError::Session("journal decoded byte estimate overflow".to_owned())
        })?;
        let estimated = nodes
            .checked_mul(DECODED_NODE_ALLOCATION_BYTES_V2)
            .and_then(|bytes| bytes.checked_add(encoded))
            .ok_or_else(|| {
                OxidraError::Session("journal decoded byte estimate overflow".to_owned())
            })?;
        self.decoded_bytes = self.decoded_bytes.checked_add(estimated).ok_or_else(|| {
            OxidraError::Session("journal decoded byte budget overflow".to_owned())
        })?;
        if self.decoded_bytes > MAX_JOURNAL_DECODED_BYTES_V2 {
            return Err(OxidraError::Session(format!(
                "journal exceeds the {MAX_JOURNAL_DECODED_BYTES_V2}-byte decoded profile"
            )));
        }
        Ok(())
    }
}

enum JournalJsonValueFrameV2<'a> {
    Value(&'a Value, usize),
    Array(std::slice::Iter<'a, Value>, usize),
    Object(serde_json::map::Iter<'a>, usize),
}

fn validate_journal_data_value_v2(value: &Value) -> Result<()> {
    let mut nodes = 0usize;
    let mut encoded_bytes = 0usize;
    let mut pending = vec![JournalJsonValueFrameV2::Value(value, 0)];
    while let Some(frame) = pending.pop() {
        match frame {
            JournalJsonValueFrameV2::Value(value, depth) => {
                if depth > MAX_JOURNAL_DATA_DEPTH_V2 {
                    return Err(OxidraError::Session(format!(
                        "journal event data exceeds the {MAX_JOURNAL_DATA_DEPTH_V2}-level JSON depth profile"
                    )));
                }
                nodes = nodes.checked_add(1).ok_or_else(|| {
                    OxidraError::Session("journal event JSON node count overflow".to_owned())
                })?;
                if nodes > MAX_JOURNAL_DATA_NODES_V2 {
                    return Err(OxidraError::Session(format!(
                        "journal event data exceeds the {MAX_JOURNAL_DATA_NODES_V2}-node JSON profile"
                    )));
                }
                match value {
                    Value::Array(values) => {
                        add_journal_json_bytes_v2(&mut encoded_bytes, 2)?;
                        add_journal_json_bytes_v2(
                            &mut encoded_bytes,
                            values.len().saturating_sub(1),
                        )?;
                        pending.push(JournalJsonValueFrameV2::Array(values.iter(), depth + 1));
                    }
                    Value::Object(values) => {
                        add_journal_json_bytes_v2(&mut encoded_bytes, 2)?;
                        add_journal_json_bytes_v2(
                            &mut encoded_bytes,
                            values.len().saturating_sub(1),
                        )?;
                        for key in values.keys() {
                            add_journal_json_bytes_v2(
                                &mut encoded_bytes,
                                journal_json_string_encoded_len_v2(key)?,
                            )?;
                            add_journal_json_bytes_v2(&mut encoded_bytes, 1)?;
                        }
                        pending.push(JournalJsonValueFrameV2::Object(values.iter(), depth + 1));
                    }
                    Value::Null => add_journal_json_bytes_v2(&mut encoded_bytes, 4)?,
                    Value::Bool(value) => {
                        add_journal_json_bytes_v2(&mut encoded_bytes, if *value { 4 } else { 5 })?
                    }
                    Value::Number(value) => {
                        add_journal_json_bytes_v2(&mut encoded_bytes, value.to_string().len())?
                    }
                    Value::String(value) => add_journal_json_bytes_v2(
                        &mut encoded_bytes,
                        journal_json_string_encoded_len_v2(value)?,
                    )?,
                }
            }
            JournalJsonValueFrameV2::Array(mut values, depth) => {
                if let Some(value) = values.next() {
                    pending.push(JournalJsonValueFrameV2::Array(values, depth));
                    pending.push(JournalJsonValueFrameV2::Value(value, depth));
                }
            }
            JournalJsonValueFrameV2::Object(mut values, depth) => {
                if let Some((_, value)) = values.next() {
                    pending.push(JournalJsonValueFrameV2::Object(values, depth));
                    pending.push(JournalJsonValueFrameV2::Value(value, depth));
                }
            }
        }
    }
    Ok(())
}

fn add_journal_json_bytes_v2(total: &mut usize, additional: usize) -> Result<()> {
    *total = total
        .checked_add(additional)
        .ok_or_else(|| OxidraError::Session("journal JSON encoded size overflow".to_owned()))?;
    if *total > MAX_JOURNAL_EVENT_BYTES_V2 {
        return Err(OxidraError::Session(format!(
            "journal event data exceeds the {MAX_JOURNAL_EVENT_BYTES_V2}-byte JSON profile"
        )));
    }
    Ok(())
}

fn journal_json_string_encoded_len_v2(value: &str) -> Result<usize> {
    value.chars().try_fold(2usize, |total, character| {
        let encoded = match character {
            '"' | '\\' | '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        total.checked_add(encoded).ok_or_else(|| {
            OxidraError::Session("journal JSON string encoded size overflow".to_owned())
        })
    })
}

struct JournalJsonTextBudgetV2 {
    nodes: usize,
    max_depth: usize,
    max_nodes: usize,
}

impl JournalJsonTextBudgetV2 {
    fn enter<E>(&mut self, depth: usize) -> std::result::Result<(), E>
    where
        E: serde::de::Error,
    {
        if depth > self.max_depth {
            return Err(E::custom(format_args!(
                "journal JSON exceeds validation depth {}",
                self.max_depth
            )));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.max_nodes {
            return Err(E::custom(format_args!(
                "journal JSON exceeds validation node budget {}",
                self.max_nodes
            )));
        }
        Ok(())
    }
}

struct JournalJsonTextSeedV2<'a> {
    budget: &'a mut JournalJsonTextBudgetV2,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JournalJsonTextSeedV2<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.enter::<D::Error>(self.depth)?;
        deserializer.deserialize_any(JournalJsonTextVisitorV2 {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct JournalJsonTextVisitorV2<'a> {
    budget: &'a mut JournalJsonTextBudgetV2,
    depth: usize,
}

impl<'de> Visitor<'de> for JournalJsonTextVisitorV2<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded journal JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_borrowed_str<E>(self, _value: &'de str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_string<E>(self, _value: String) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(JournalJsonTextSeedV2 {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(JournalJsonTextSeedV2 {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            })?;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum JournalJsonPreflightErrorV2 {
    Profile(OxidraError),
    Json(serde_json::Error),
}

fn preflight_journal_json_bytes_raw_v2(
    bytes: &[u8],
) -> std::result::Result<JournalJsonMetricsV2, JournalJsonPreflightErrorV2> {
    if bytes.len() > MAX_JOURNAL_EVENT_BYTES_V2 {
        return Err(JournalJsonPreflightErrorV2::Profile(OxidraError::Session(
            format!("journal event exceeds the {MAX_JOURNAL_EVENT_BYTES_V2}-byte JSON profile"),
        )));
    }
    let mut budget = JournalJsonTextBudgetV2 {
        nodes: 0,
        max_depth: MAX_JOURNAL_EVENT_DEPTH_V2,
        max_nodes: MAX_JOURNAL_EVENT_NODES_V2,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    JournalJsonTextSeedV2 {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(JournalJsonPreflightErrorV2::Json)?;
    deserializer
        .end()
        .map_err(JournalJsonPreflightErrorV2::Json)?;
    Ok(JournalJsonMetricsV2 {
        nodes: budget.nodes,
        encoded_bytes: bytes.len(),
    })
}

fn preflight_journal_json_bytes_v2(bytes: &[u8]) -> Result<JournalJsonMetricsV2> {
    preflight_journal_json_bytes_raw_v2(bytes).map_err(|error| match error {
        JournalJsonPreflightErrorV2::Profile(error) => error,
        JournalJsonPreflightErrorV2::Json(error) => {
            OxidraError::Session(format!("invalid bounded journal JSON: {error}"))
        }
    })
}

/// Encode one event only after the iterative data scan and the exact reader
/// profile have accepted it.  All typed and prebuilt writers use this helper;
/// it is `pub(crate)` so the MCP projection validator cannot accidentally
/// reintroduce an unbounded serializer call.
fn encode_journal_event_with_metrics_v2(
    event: &JournalEvent,
) -> Result<(Vec<u8>, JournalJsonMetricsV2)> {
    validate_journal_data_value_v2(&event.data)?;
    let encoded = if event.kind == SESSION_STARTED_KIND && event.seq == 1 {
        serde_json::to_vec(&ProfiledSessionStartedEventV2 {
            schema: event.schema,
            seq: event.seq,
            ts: &event.ts,
            kind: &event.kind,
            session_id: &event.session_id,
            turn_id: &event.turn_id,
            data: &event.data,
            json_profile: JournalJsonProfileClaimV2::current(),
        })?
    } else {
        serde_json::to_vec(event)?
    };
    let metrics = preflight_journal_json_bytes_v2(&encoded)?;
    if metrics.encoded_bytes > MAX_JOURNAL_EVENT_BYTES_V2 {
        return Err(OxidraError::Session(format!(
            "journal event exceeds the {MAX_JOURNAL_EVENT_BYTES_V2}-byte JSON profile"
        )));
    }
    Ok((encoded, metrics))
}

pub(crate) fn encode_journal_event_v2(event: &JournalEvent) -> Result<Vec<u8>> {
    encode_journal_event_with_metrics_v2(event).map(|(encoded, _)| encoded)
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

fn session_header_data_for_journal_v1(header: SessionHeader) -> Result<Value> {
    let SessionHeader {
        version,
        project_root,
        model,
        extra,
    } = header;
    // Take ownership of every extension value before any error path can drop
    // an adversarially deep tree recursively. On rejection,
    // JournalValueOwnerV2 performs an iterative teardown.
    let extra = JournalValueOwnerV2::new(Value::Object(extra))?;
    if extra
        .as_value()
        .as_object()
        .expect("SessionHeader.extra is encoded as an object")
        .contains_key(JOURNAL_JSON_PROFILE_FIELD)
    {
        return Err(OxidraError::Session(format!(
            "{JOURNAL_JSON_PROFILE_FIELD} is reserved for the journal writer profile"
        )));
    }
    let Value::Object(extra) = extra.into_value() else {
        unreachable!("SessionHeader.extra is encoded as an object")
    };
    let data = serde_json::to_value(SessionHeader {
        version,
        project_root,
        model,
        extra,
    })
    .map_err(OxidraError::from)?;
    JournalValueOwnerV2::new(data).map(JournalValueOwnerV2::into_value)
}

fn legacy_session_version() -> String {
    "pre-v0.1".to_owned()
}

fn session_header_from_event_data_v1(data: &Value) -> Result<SessionHeader> {
    serde_json::from_value(data.clone()).map_err(OxidraError::from)
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
        ensure_private_dir(&self.data_dir)?;
        ensure_private_dir(&self.sessions_dir)?;
        ensure_private_dir(&self.artifacts_dir)?;
        ensure_private_dir(&self.locks_dir)?;
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

    pub fn execution_gate_path_v1(&self, session_id: &str) -> Result<PathBuf> {
        validate_session_id(session_id)?;
        Ok(self
            .locks_dir
            .join(format!("{session_id}.mcp-execution-v1.lock")))
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
    ///
    /// A syntactically incomplete final record fails closed instead of being
    /// projected from only the complete prefix: `SessionSummary` has no field
    /// that can carry crash-tail provenance. Use
    /// [`SessionStore::export_read_only_snapshot`] when the exact incomplete
    /// bytes must be preserved for inspection.
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
            let header = session_header_from_event_data_v1(&first.data)?;
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

    /// Reads a journal for display without applying crash recovery. Like
    /// [`SessionStore::list`], this rejects an incomplete final record because
    /// the return type cannot report omitted crash-tail evidence; read-only
    /// export is the lossless administrative path for such a prefix.
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

    /// Copies a session journal into a versioned archive without opening,
    /// repairing, or otherwise mutating the source session.  This is
    /// intentionally the only supported escape hatch for a fail-closed
    /// execution quarantine.
    ///
    /// The first line is a non-journal manifest followed by the exact original
    /// JSONL bytes, including any incomplete final record. Keeping the archive
    /// deliberately outside the journal grammar prevents it from being placed
    /// in another `SessionStore` and accidentally resumed without the
    /// quarantined execution gate.
    pub fn export_read_only_snapshot(
        &self,
        session_id: &str,
        destination: impl AsRef<Path>,
    ) -> Result<u64> {
        validate_session_id(session_id)?;
        let destination = destination.as_ref();
        validate_read_only_export_destination_v1(destination)?;
        let source = self.layout.journal_path(session_id)?;
        if !source.is_file() {
            return Err(OxidraError::Session(format!(
                "session not found: {session_id}"
            )));
        }

        // Hold the normal session writer lock while taking the immutable
        // snapshot.  We deliberately do not inspect the execution gate: an
        // ACTIVE/torn gate is exactly the quarantined state this API is meant
        // to export, and no source mutation or MCP startup occurs here.
        let _lock_file = acquire_lock(&self.layout, session_id)?;
        ensure_journal_size(&source)?;
        let bytes = fs::read(&source)?;
        ensure_journal_size(&source)?;
        // Reuse the same byte-boundary analysis as crash recovery, but do not
        // apply either of its mutations.  A quarantined journal may end in a
        // partially written JSON line; its complete prefix must still be a
        // valid journal, while the exact incomplete tail remains evidence
        // that the archive preserves verbatim.
        let scan = match scan_journal_bytes(&bytes, session_id) {
            Ok(scan) => scan,
            Err(_) => scan_journal_bytes_for_export_v1(&bytes, session_id)?,
        };
        let incomplete_tail = scan.truncated_tail.as_ref().map(|tail| {
            json!({
                "offset": scan.valid_len,
                "bytes": tail.byte_count,
                "sha256": tail.sha256,
            })
        });

        let manifest = serde_json::to_vec(&json!({
            "format": "oxidra.session.read_only_export",
            "version": 1,
            "session_id": session_id,
            "journal_schema": JOURNAL_SCHEMA,
            "journal_bytes": bytes.len(),
            "journal_sha256": hex::encode(Sha256::digest(&bytes)),
            "journal_complete_prefix_bytes": scan.valid_len,
            "journal_incomplete_tail": incomplete_tail,
            "journal_missing_final_newline": scan.normalized_missing_newline,
            "resume_allowed": false,
            "quarantine_cleared": false,
        }))?;
        let archive_bytes = manifest
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(bytes.len()))
            .ok_or_else(|| OxidraError::Session("session export size is exhausted".to_owned()))?;

        write_new_file_atomically(destination, |output| {
            output.write_all(&manifest)?;
            output.write_all(b"\n")?;
            output.write_all(&bytes)
        })
        .map_err(|error| match error {
            AtomicNewFileError::BeforePublish(error) => OxidraError::Io(error),
            AtomicNewFileError::PublishedButDurabilityUncertain(error) => {
                OxidraError::Session(format!(
                    "read-only archive may already be completely published, but namespace durability or cleanup could not be confirmed; inspect the requested destination and retry only with a different .{READ_ONLY_SESSION_EXPORT_EXTENSION_V1} path: {error}"
                ))
            }
        })?;
        Ok(u64::try_from(archive_bytes).expect("session export length fits u64"))
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
        ensure_execution_gate_quiescent_v1(&self.layout.execution_gate_path_v1(session_id)?)?;
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
        // This must precede every filesystem/error path: a caller may put a
        // deeply nested Value in SessionHeader.extra, and returning before
        // ownership transfer would invoke serde_json's recursive destructor.
        let header_data = session_header_data_for_journal_v1(header)?;
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        self.layout.ensure()?;

        let lock_file = acquire_lock(&self.layout, &session_id)?;
        let execution_gate_path = self.layout.execution_gate_path_v1(&session_id)?;
        ensure_execution_gate_quiescent_v1(&execution_gate_path)?;
        let journal_path = self.layout.journal_path(&session_id)?;
        let artifact_dir = self.layout.artifact_dir(&session_id)?;
        let initial_event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 1,
            ts: Utc::now(),
            kind: SESSION_STARTED_KIND.to_owned(),
            session_id: session_id.clone(),
            turn_id: None,
            data: header_data,
        };
        validate_raw_protocol_event_shape_v1(&initial_event)?;
        validate_events(std::slice::from_ref(&initial_event), &session_id)?;
        let (encoded_header, header_metrics) =
            encode_journal_event_with_metrics_v2(&initial_event)?;
        let initial_bytes = u64::try_from(encoded_header.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| OxidraError::Session("session header size is exhausted".to_owned()))?;
        if initial_bytes > MAX_SESSION_BYTES {
            return Err(OxidraError::Session(format!(
                "session header would exceed the {MAX_SESSION_BYTES}-byte journal safety limit"
            )));
        }
        let mut decode_budget = JournalDecodeBudgetV2::default();
        decode_budget.account(header_metrics)?;

        // `session.started` is the creation commit, not an ordinary recoverable
        // append. Publish a complete, synced first record with no-clobber
        // semantics so a crash can expose either no journal or the exact
        // header, never an empty/partial discoverable `.jsonl` file.
        write_new_file_atomically(&journal_path, |output| {
            output.write_all(&encoded_header)?;
            output.write_all(b"\n")
        })
        .map_err(|error| match error {
            AtomicNewFileError::BeforePublish(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&journal_path).is_ok() =>
            {
                OxidraError::Session(format!("session already exists: {session_id}"))
            }
            AtomicNewFileError::BeforePublish(error) => OxidraError::Io(error),
            AtomicNewFileError::PublishedButDurabilityUncertain(error) => {
                OxidraError::Session(format!(
                    "session {session_id} header may already be completely published, but namespace durability could not be confirmed; do not retry creation until the storage state has been inspected: {error}"
                ))
            }
        })?;

        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&journal_path)
            .map_err(|error| {
                OxidraError::Session(format!(
                    "session {session_id} header is fully published, but its live journal handle could not be opened; reopen the existing session instead of retrying creation: {error}"
                ))
            })?;
        enforce_private_file(&journal_path)?;
        // Ancillary artifact setup happens only after the journal creation
        // commit. If it fails, the discoverable session still has a complete
        // header and can be opened later; it is never a repairable empty file.
        ensure_private_dir(&artifact_dir).map_err(|error| {
            OxidraError::Session(format!(
                "session {session_id} header is fully published, but its artifact directory could not be prepared; reopen the existing session instead of retrying creation: {error}"
            ))
        })?;
        let handle_id = Uuid::now_v7().to_string();

        let journal = SessionJournal {
            session_id: session_id.clone(),
            handle_id: handle_id.clone(),
            journal_path,
            artifact_dir,
            file,
            execution_lease: SessionExecutionLeaseV1::new(lock_file, &session_id, &handle_id),
            execution_gate_path,
            next_seq: 2,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit: MAX_SESSION_BYTES,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            active_mcp_tool: None,
            recovery_headroom_bytes: 0,
            json_profile: JournalJsonProfile::BoundedV2,
            decode_budget,
            mcp_resume_open_id: None,
            mcp_activation_present_at_open: false,
            mcp_activation_startup_issued: false,
            mcp_resume_eligibility_issued: false,
        };
        Ok(journal)
    }

    pub fn open(&self, session_id: &str) -> Result<SessionJournal> {
        self.open_with_byte_limit(session_id, MAX_SESSION_BYTES)
    }

    fn open_with_byte_limit(&self, session_id: &str, byte_limit: u64) -> Result<SessionJournal> {
        validate_session_id(session_id)?;
        self.layout.ensure()?;

        // Match `delete`: a typo must not create an otherwise permanent lock
        // file in the session namespace.  Recheck by opening after the lock is
        // held below; a concurrent legitimate delete already leaves its lock
        // inode intentionally, so this preflight does not create a new race
        // cleanup obligation.
        let journal_path = self.layout.journal_path(session_id)?;
        if !journal_path.is_file() {
            return Err(OxidraError::Session(format!(
                "session not found: {session_id}"
            )));
        }
        let lock_file = acquire_lock(&self.layout, session_id)?;
        let execution_gate_path = self.layout.execution_gate_path_v1(session_id)?;
        // This check happens before tail repair, recovery markers, or any
        // other journal mutation. An older guardian retains the gate until its
        // old MCP containment has produced an exact exit proof.
        ensure_execution_gate_quiescent_v1(&execution_gate_path)?;
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
        enforce_private_file(&journal_path)?;

        let scan = scan_and_repair_tail(&mut file, session_id)?;
        let JournalScan {
            events: mut prospective_events,
            json_profile,
            decode_budget,
            valid_len,
            truncated_tail,
            normalized_missing_newline,
        } = scan;
        let tail_repair_needed = truncated_tail.is_some();
        validate_events(&prospective_events, session_id)?;
        // Recovery is a mutating reader.  A bounded-profile journal must first
        // prove that every already-complete protocol record belongs to the
        // current writer language; otherwise a valid-looking torn suffix could
        // authorize truncation or recovery writes over an earlier malformed
        // user turn that history/projection can never consume.
        validate_bounded_recovery_prefix_v2(&prospective_events, json_profile)?;
        validate_generic_recovery_skips_v1(&prospective_events)?;
        // A complete final line without its newline is still a durable
        // protocol record, not crash debris. Validate the candidate with the
        // same frozen shape/reducer boundary used by reopen before the
        // normalization branch below can mutate it. This is deliberately
        // restricted to the missing-newline path: legacy journals may contain
        // an unfinished compaction/provider prefix which the recovery planner
        // is authorized to settle, but a complete malformed record must never
        // gain validity merely because one LF is appended.
        if normalized_missing_newline {
            validate_normalization_candidate_v1(&prospective_events, session_id, json_profile)?;
        }
        // Resume startup is only authorized from a journal generation that
        // was opened with an already-durable MCP activation.  A newly-created
        // journal may activate MCP during this handle, but that first
        // activation must be closed and reopened before it can mint the
        // pre-start recovery gate.  This keeps the gate causally tied to the
        // prefix that SessionStore::open actually reduced.
        let mcp_activation_present_at_open = prospective_events
            .iter()
            .any(|event| event.kind == crate::mcp::MCP_REGISTRY_ACTIVATED_KIND);
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
        let (mcp_unstarted_tools, generic_unstarted_tools) =
            partition_unstarted_tools_v1(&prospective_events, &unstarted_tools)?;
        // Build every authorization payload before the first recovery write.
        // Legacy call-chain v1 could durably contain more than the current
        // per-response maximum, so recovery chunks that old batch into
        // multiple independently bounded v1 markers instead of rewriting the
        // frozen validator or poisoning the journal midway through repair.
        preflight_recovery_authorization_batches(&mcp_unstarted_tools)?;
        let previously_skipped = prospective_events
            .iter()
            .filter(|event| {
                event.kind == "tool.skipped_due_to_recovery" || is_generic_recovery_skip_v1(event)
            })
            .count();
        let skipped_before_start = previously_skipped + unstarted_tools.len();
        let (in_doubt, explicitly_in_doubt_started_seqs) =
            pending_tools_with_explicit_in_doubt(&prospective_events);
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

        let handle_id = Uuid::now_v7().to_string();
        let mut journal = SessionJournal {
            session_id: session_id.to_owned(),
            handle_id: handle_id.clone(),
            journal_path,
            artifact_dir: self.layout.artifact_dir(session_id)?,
            file,
            execution_lease: SessionExecutionLeaseV1::new(lock_file, session_id, &handle_id),
            execution_gate_path,
            next_seq,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            active_mcp_tool: None,
            recovery_headroom_bytes: 0,
            json_profile,
            decode_budget,
            // This nonce identifies the exact recovered journal handle that
            // authorized a later MCP resume.  A newly-created journal cannot
            // mint that capability, and reopening after dropping this handle
            // produces a different nonce.
            mcp_resume_open_id: Some(Uuid::now_v7().to_string()),
            mcp_activation_present_at_open,
            mcp_activation_startup_issued: false,
            mcp_resume_eligibility_issued: false,
        };
        fs::create_dir_all(&journal.artifact_dir)?;

        let original_event_count = prospective_events.len();
        let existing_recovery_authorizations =
            recovery_authorization_index(&prospective_events[..original_event_count])?;
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
        // A durable `tool.started` with no terminal becomes explicitly
        // in-doubt after a process boundary.  Persist that exact transition
        // before exposing manual resolution; otherwise the Provider-slot and
        // MCP reducers still see a merely-started call and must reject
        // `tool.in_doubt_resolved` on the next reopen.
        let recovered_started_tools = recovery
            .in_doubt
            .iter()
            .filter(|tool| !explicitly_in_doubt_started_seqs.contains(&tool.started_seq))
            .cloned()
            .collect::<Vec<_>>();
        for tool in recovered_started_tools {
            stage_recovery_event(
                session_id,
                &mut planned_seq,
                &mut planned_events,
                &mut prospective_events,
                "tool.in_doubt",
                tool.turn_id.as_deref(),
                recovered_in_doubt_data_v1(&tool)?,
            )?;
        }
        recovery.in_doubt = pending_tools(&prospective_events);
        let mcp_turn_ids = crate::mcp::mcp_turn_ids(&prospective_events)?;
        validate_provider_request_slots_v2(&prospective_events, &mcp_turn_ids)?;
        recovery.marker_seq =
            matching_recovery_marker(&prospective_events[..original_event_count], &recovery);
        let provisional_marker_required_without_tools = mcp_unstarted_tools.is_empty()
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
            &mcp_unstarted_tools,
            provisional_marker_required_without_tools,
            Some(&existing_recovery_authorizations),
        )?;
        let mut after_lifecycle_recovery = prospective_events.clone();
        after_lifecycle_recovery.extend(provisional_mcp_events.clone());
        let provisional_generic_seq = provisional_mcp_events
            .last()
            .map(|event| event.seq.saturating_add(1))
            .unwrap_or(planned_seq);
        after_lifecycle_recovery.extend(plan_generic_recovery_skip_events(
            journal.session_id(),
            provisional_generic_seq,
            &generic_unstarted_tools,
        )?);
        validate_generic_recovery_skips_v1(&after_lifecycle_recovery)?;
        let recoverable_turns = recoverable_open_turns_v1(&after_lifecycle_recovery, json_profile)?;
        let recovered_turn_ids = recoverable_turns
            .iter()
            .map(|turn| turn.turn_id.clone())
            .collect::<Vec<_>>();
        recovery.cancelled_turns = recovery
            .cancelled_turns
            .saturating_add(recoverable_turns.len());
        let recovered_open_turn = !recoverable_turns.is_empty();
        recovery.marker_seq =
            matching_recovery_marker(&prospective_events[..original_event_count], &recovery);
        let marker_required_without_tools = mcp_unstarted_tools.is_empty()
            && (provisional_marker_required_without_tools
                || (!recoverable_turns.is_empty() && recovery.marker_seq.is_none()));
        // Freeze every recovery event before any transaction byte is written.
        // This includes generic aborts, compaction boundary terminals, MCP
        // markers and all authorized skips.
        let mcp_recovery_events = plan_mcp_recovery_events(
            journal.session_id(),
            planned_seq,
            &mut recovery,
            &mcp_unstarted_tools,
            marker_required_without_tools,
            Some(&existing_recovery_authorizations),
        )?;
        if let Some(last) = mcp_recovery_events.last() {
            planned_seq = last
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
        }
        prospective_events.extend(mcp_recovery_events.iter().cloned());
        planned_events.extend(mcp_recovery_events);
        let generic_recovery_events = plan_generic_recovery_skip_events(
            journal.session_id(),
            planned_seq,
            &generic_unstarted_tools,
        )?;
        if let Some(last) = generic_recovery_events.last() {
            planned_seq = last
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
        }
        prospective_events.extend(generic_recovery_events.iter().cloned());
        planned_events.extend(generic_recovery_events);
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
        validate_generic_recovery_skips_v1(&prospective_events)?;
        validate_provider_request_slots_v2(&prospective_events, &mcp_turn_ids)?;
        for turn_id in &recovered_turn_ids {
            if !turn_uses_started_lifecycle_v1(&prospective_events, turn_id) {
                continue;
            }
            let slot = provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &prospective_events,
                turn_id,
            )?;
            if slot != ProviderRequestSlotState::Terminal {
                return Err(OxidraError::Session(format!(
                    "recovered turn {turn_id} did not reach a terminal Provider request slot"
                )));
            }
        }
        if recovered_open_turn {
            // The JSON resource profile is deliberately orthogonal to the
            // durable turn protocol. Journals written before bounded-json-v2
            // may already carry any registered turn-boundary version, so an
            // absent JSON claim must not downgrade their lifecycle reducer.
            segment_turns(&prospective_events)?;
        }
        // Recovery markers are not the end of the in-doubt transaction.  Keep
        // a bounded resolution slot after the marker/skips have been written,
        // and reject the open before the first recovery byte if that complete
        // lifecycle cannot fit.
        let resolution_headroom = in_doubt_transaction_headroom_v1(
            &journal.session_id,
            &prospective_events,
            &recovery.in_doubt,
            &[],
        )?;
        let recovery_limit = byte_limit
            .checked_sub(resolution_headroom)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "session journal cannot reserve {resolution_headroom}-byte in-doubt resolution headroom"
                ))
            })?;

        // Tail repair is destructive, so defer the physical truncation until
        // the complete recovery transaction has passed its capacity
        // admission.  If this check fails, the exact crash bytes remain
        // available for read-only export and a later operator retry can make
        // the same decision from the unchanged journal.
        if tail_repair_needed {
            let current_size = journal.file.metadata()?.len();
            let recovery_bytes = encoded_journal_events_bytes(&planned_events)?;
            if current_size
                .checked_add(recovery_bytes)
                .is_none_or(|size| size > recovery_limit)
            {
                return Err(OxidraError::Session(format!(
                    "session journal tail repair plus recovery transaction would exceed the {recovery_limit}-byte safety limit"
                )));
            }
            journal.file.set_len(valid_len as u64)?;
            journal.file.seek(SeekFrom::End(0))?;
            journal.file.sync_data()?;
        }

        // A complete final JSON record without its physical newline is only
        // normalized after every frozen reducer above has accepted the
        // prospective prefix.  Otherwise a semantically invalid record (for
        // example a tool.started without call_id) could make open() fail
        // after mutating the source by one byte.  Account for that byte before
        // publishing it so a tight byte limit cannot create a new failure
        // window between normalization and the recovery batch.
        if normalized_missing_newline {
            let current_size = journal.file.metadata()?.len();
            let recovery_bytes = encoded_journal_events_bytes(&planned_events)?;
            if current_size
                .checked_add(1)
                .and_then(|size| size.checked_add(recovery_bytes))
                .is_none_or(|size| size > recovery_limit)
            {
                return Err(OxidraError::Session(format!(
                    "session journal normalization plus recovery transaction would exceed the {recovery_limit}-byte safety limit"
                )));
            }
            journal.file.seek(SeekFrom::End(0))?;
            journal.file.write_all(b"\n")?;
            journal.file.sync_data()?;
        }
        journal.append_prebuilt_batch_with_limit(&planned_events, recovery_limit)?;
        journal.recovery = recovery;
        journal.recovery_headroom_bytes = resolution_headroom;
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

/// One MCP call that is still unstarted and is being settled by a live
/// recovery-marker transaction.  The response sequence and exact arguments
/// bind the skip to the canonical Provider output rather than to a caller's
/// in-memory ToolCall alone.
#[derive(Clone, Debug)]
pub(crate) struct McpRecoverySkipV1 {
    pub(crate) response_seq: u64,
    pub(crate) call_id: String,
    pub(crate) tool_name: String,
    pub(crate) arguments: Value,
}

/// Runtime ownership of one session execution generation.
///
/// This lease is intentionally crate-private and can only be minted by the
/// already-locked [`SessionJournal`]. It shares the original `File` through an
/// `Arc` instead of duplicating the descriptor/handle, avoiding platform
/// differences in `flock`/`LockFileEx` duplicate-handle semantics. As long as
/// either the journal or an MCP coordinator retains a lease, the original
/// locked handle remains open and `SessionStore::open` must fail closed.
///
/// Once MCP startup is claimed, every clone also references a process-external
/// guardian. Transport native reapers retain that reference until exact native
/// exit/reap; the final release asks the guardian to verify its registered
/// pidfds/Jobs before the separate cross-process gate is unlocked. The ordinary
/// writer lock covers live-host ownership, while the guardian gate is the
/// authority that survives an independently terminated host.
pub(crate) struct SessionExecutionLeaseV1 {
    _lock_file: Arc<File>,
    guardian: Option<ExecutionGuardianLeaseV1>,
    session_id: String,
    journal_handle_id: String,
}

impl SessionExecutionLeaseV1 {
    fn new(lock_file: File, session_id: &str, journal_handle_id: &str) -> Self {
        Self {
            _lock_file: Arc::new(lock_file),
            guardian: None,
            session_id: session_id.to_owned(),
            journal_handle_id: journal_handle_id.to_owned(),
        }
    }

    pub(crate) fn clone_v1(&self) -> Self {
        Self {
            _lock_file: Arc::clone(&self._lock_file),
            guardian: self
                .guardian
                .as_ref()
                .map(ExecutionGuardianLeaseV1::clone_v1),
            session_id: self.session_id.clone(),
            journal_handle_id: self.journal_handle_id.clone(),
        }
    }

    pub(crate) fn matches_journal(&self, journal: &SessionJournal) -> bool {
        self.session_id == journal.session_id && self.journal_handle_id == journal.handle_id
    }

    fn with_guardian_v1(&self, guardian: ExecutionGuardianLeaseV1) -> Self {
        Self {
            _lock_file: Arc::clone(&self._lock_file),
            guardian: Some(guardian),
            session_id: self.session_id.clone(),
            journal_handle_id: self.journal_handle_id.clone(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_linux_guardian_registration_v1(
        &self,
    ) -> Result<crate::execution_guardian::LinuxGuardianRegistrationV1<'_>> {
        self.guardian
            .as_ref()
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP transport startup has no process-external execution guardian".to_owned(),
                )
            })?
            .prepare_linux_registration()
    }

    #[cfg(windows)]
    pub(crate) fn spawn_windows_guardian_process_v1(
        &self,
        command: &Path,
        args: &[String],
        cwd: Option<&Path>,
        inherited_env: &BTreeMap<String, std::ffi::OsString>,
        explicit_env: &BTreeMap<String, String>,
    ) -> Result<crate::process::WindowsContainedSpawnV1> {
        self.guardian
            .as_ref()
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP transport startup has no process-external execution guardian".to_owned(),
                )
            })?
            .spawn_windows_process(command, args, cwd, inherited_env, explicit_env)
    }
}

pub struct SessionJournal {
    session_id: String,
    /// Runtime-only identity of this exact locked journal handle. Reopening
    /// the same durable session creates a new value so stale coordinators and
    /// writer capabilities cannot cross the process-local ownership boundary.
    handle_id: String,
    journal_path: PathBuf,
    artifact_dir: PathBuf,
    file: File,
    execution_lease: SessionExecutionLeaseV1,
    execution_gate_path: PathBuf,
    next_seq: u64,
    recovery: RecoveryInfo,
    poisoned: bool,
    reopen_required: Arc<AtomicBool>,
    byte_limit: u64,
    active_turn: Option<ActiveTurnReservationV1>,
    active_provider_response: Option<ActiveProviderResponseReservationV1>,
    active_compaction: Option<ActiveCompactionReservationV1>,
    active_mcp_tool: Option<ActiveMcpToolReservationV1>,
    /// Capacity retained after reopen for explicit in-doubt resolutions.
    recovery_headroom_bytes: u64,
    /// JSON acceptance profile selected by the first session.started event.
    /// Legacy schema-1 journals remain on their historical parser language;
    /// newly-created sessions explicitly activate bounded profile 2.
    json_profile: JournalJsonProfile,
    /// Decoded-memory budget already committed by the journal prefix.
    decode_budget: JournalDecodeBudgetV2,
    mcp_resume_open_id: Option<String>,
    /// Whether this open generation reduced a prefix that already contained
    /// a durable MCP activation.  A first activation appended to a newly
    /// opened handle must be closed and reopened before it can authorize MCP
    /// startup.
    mcp_activation_present_at_open: bool,
    /// A fresh activation may start untrusted MCP code only once per locked
    /// journal generation.  Reopening creates a new runtime generation; an
    /// existing durable activation is still rejected independently.
    mcp_activation_startup_issued: bool,
    mcp_resume_eligibility_issued: bool,
}

#[derive(Clone, Debug)]
struct ActiveTurnReservationV1 {
    reservation_id: String,
    turn_id: String,
    user_message_seq: u64,
    headroom_bytes: u64,
    lifecycle_margin_reserved: bool,
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

#[derive(Clone, Debug)]
struct ActiveMcpToolReservationV1 {
    reservation_id: String,
    turn_id: String,
    started_seq: u64,
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
pub struct TurnTransactionAdmissionV1 {
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

/// One-shot capability proving that a standalone MCP `tool.started` event
/// was synced only after reserving space for its bounded terminal and every
/// prospective crash-recovery event. Dropping it poisons the journal handle
/// so a caller cannot continue appending after an abandoned external dispatch.
#[derive(Debug)]
pub(crate) struct McpToolDispatchAdmissionV1 {
    reservation_id: String,
    turn_id: String,
    started_seq: u64,
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
    FallbackPermittedBeforeWrite(OxidraError),
    Fatal(OxidraError),
}

impl DurableOutcomeCommitErrorV1 {
    pub(crate) fn into_error(self) -> OxidraError {
        match self {
            Self::FallbackPermittedBeforeWrite(error) | Self::Fatal(error) => error,
        }
    }
}

impl std::fmt::Display for DurableOutcomeCommitErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FallbackPermittedBeforeWrite(error) | Self::Fatal(error) => {
                std::fmt::Display::fmt(error, formatter)
            }
        }
    }
}

impl std::error::Error for DurableOutcomeCommitErrorV1 {}

fn provider_response_candidate_error_v1(
    error: OxidraError,
    fallback_permitted_before_write: bool,
) -> DurableOutcomeCommitErrorV1 {
    if fallback_permitted_before_write {
        DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(error)
    } else {
        DurableOutcomeCommitErrorV1::Fatal(error)
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

impl ProviderResponseDispatchAdmissionV1 {
    pub(crate) fn mark_reopen_required_v1(&self) {
        self.reopen_required.store(true, Ordering::Release);
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

impl Drop for McpToolDispatchAdmissionV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.reopen_required.store(true, Ordering::Release);
        }
    }
}

impl McpToolDispatchAdmissionV1 {
    pub(crate) fn started_seq(&self) -> u64 {
        self.started_seq
    }
}

impl SessionJournal {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn handle_id(&self) -> &str {
        &self.handle_id
    }

    #[cfg(test)]
    pub(crate) fn retain_execution_lease_v1(&self) -> SessionExecutionLeaseV1 {
        self.execution_lease.clone_v1()
    }

    pub(crate) fn retain_guarded_execution_lease_v1(&self) -> Result<SessionExecutionLeaseV1> {
        let guardian = ExecutionGuardianLeaseV1::start(&self.execution_gate_path)?;
        Ok(self.execution_lease.with_guardian_v1(guardian))
    }

    /// Consume the one startup slot for a first MCP activation on this exact
    /// locked journal generation.  The prefix is checked before any server is
    /// spawned, so an existing activation or pending compaction boundary
    /// cannot execute discovery code and fail only later in the coordinator.
    pub(crate) fn claim_mcp_activation_startup_v1(&mut self) -> Result<SessionExecutionLeaseV1> {
        self.ensure_healthy()?;
        if self.mcp_activation_startup_issued {
            return Err(OxidraError::Session(
                "MCP activation startup was already claimed for this session journal handle"
                    .to_owned(),
            ));
        }
        let events = self.read_events()?;
        crate::mcp::validate_mcp_call_chain(&events)?;
        if events
            .iter()
            .any(|event| event.kind == crate::mcp::MCP_REGISTRY_ACTIVATED_KIND)
        {
            return Err(OxidraError::Session(
                "MCP activation startup cannot replace an existing registry activation".to_owned(),
            ));
        }
        if let Some(pending) = validate_compaction_boundary_chain(&events)?.latest_pending() {
            return Err(OxidraError::Session(format!(
                "MCP activation startup cannot cross pending compaction boundary {}",
                pending.boundary.boundary_id
            )));
        }
        let execution_lease = self.retain_guarded_execution_lease_v1()?;
        self.mcp_activation_startup_issued = true;
        Ok(execution_lease)
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
        if !self.mcp_activation_present_at_open {
            return Err(OxidraError::Session(
                "MCP resume eligibility requires an activation present when SessionStore::open reduced the journal"
                    .to_owned(),
            ));
        }
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
            .map(|event| session_header_from_event_data_v1(&event.data))
            .transpose()
    }

    pub(crate) fn append(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        self.append_with_mcp_authority(kind, turn_id, data, false)
    }

    /// Append an application extension event. Protocol namespaces are
    /// intentionally unavailable through this public safe API: core lifecycle
    /// events must be emitted by their typed writer so a successful fsync is
    /// already known to belong to the reopen language. Caller data is stored
    /// below the versioned `data.custom_event.payload` envelope rather than at
    /// the event-data root: frozen schema-1 reducers historically inspect a
    /// few root field names independently of `kind`, so exposing arbitrary
    /// custom keys there would let an extension accidentally acquire protocol
    /// semantics.
    ///
    /// The two raw protocol writers are deliberately crate-private:
    ///
    /// ```compile_fail
    /// use oxidra::session::SessionJournal;
    /// use serde_json::json;
    /// fn cannot_append_protocol(journal: &mut SessionJournal) {
    ///     let _ = journal.append("tool.started", None, json!({}));
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use oxidra::session::SessionJournal;
    /// use serde_json::json;
    /// fn cannot_sync_protocol(journal: &mut SessionJournal) {
    ///     let _ = journal.append_and_sync("user.message", None, json!({}));
    /// }
    /// ```
    pub fn append_custom(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        // Take ownership before any kind/identity error can return and invoke
        // serde_json's recursive destructor on an adversarially deep value.
        let data = JournalValueOwnerV2::new(data)?;
        let kind = kind.into();
        let valid_kind = kind.strip_prefix("custom.").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 128
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        });
        if !valid_kind {
            return Err(OxidraError::Session(
                "public extension events must use a bounded ASCII custom.* kind".to_owned(),
            ));
        }
        // Unknown turn-scoped events are not projection-neutral: historical
        // turn reducers inspect some payload fields (for example the frozen
        // inline-completion marker) across all events carrying that turn_id.
        // Keep the extension namespace global until a versioned custom-event
        // projection contract exists.
        if turn_id.is_some() {
            return Err(OxidraError::Session(
                "public custom.* events must be global (turn_id must be None)".to_owned(),
            ));
        }
        let mut custom_event = Map::new();
        custom_event.insert(
            "version".to_owned(),
            Value::from(CUSTOM_EVENT_ENVELOPE_VERSION_V1),
        );
        custom_event.insert("payload".to_owned(), data.into_value());
        let mut envelope = Map::new();
        envelope.insert(
            CUSTOM_EVENT_ENVELOPE_FIELD_V1.to_owned(),
            Value::Object(custom_event),
        );
        let envelope = JournalValueOwnerV2::new(Value::Object(envelope))?;
        self.append_with_mcp_authority_owned(kind, None, envelope, false)
    }

    fn append_mcp_event_and_sync_v1(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let event = self.append_with_mcp_authority(kind, turn_id, data, true)?;
        self.sync()?;
        Ok(event)
    }

    /// Commit the exact activation payload carried by the coordinator's
    /// one-shot bootstrap token.  The method is crate-visible only because the
    /// coordinator lives in a sibling module; the token itself is not
    /// constructible outside that coordinator module.
    pub(crate) fn append_mcp_registry_activation_v1(
        &mut self,
        admission: McpRegistryActivationAdmissionV1,
    ) -> Result<JournalEvent> {
        let data = admission.into_data_for_journal(&self.session_id, self.next_seq)?;
        self.append_mcp_event_and_sync_v1("mcp.registry.activated", None, data)
    }

    #[cfg(test)]
    pub(crate) fn append_mcp_event_with_capability_v1(
        &mut self,
        capability: &McpJournalWriteCapabilityV1,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let kind = kind.into();
        capability.append_event_to_journal_for_test(self, kind, turn_id, data)
    }

    pub(crate) fn append_mcp_context_tools_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        data: Value,
    ) -> Result<JournalEvent> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())?;
        self.append_mcp_event_and_sync_v1("context.tools", None, data)
    }

    #[cfg(test)]
    pub(crate) fn append_mcp_event_with_live_proof_for_test_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        kind: String,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())?;
        self.append_mcp_event_and_sync_v1(kind, turn_id, data)
    }

    pub(crate) fn append_mcp_tool_cancelled_before_start_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        turn_id: &str,
        data: Value,
    ) -> Result<JournalEvent> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())?;
        self.append_mcp_event_and_sync_v1("tool.cancelled", Some(turn_id), data)
    }

    pub(crate) fn append_mcp_tool_completed_before_start_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        turn_id: &str,
        data: Value,
    ) -> Result<JournalEvent> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())?;
        self.append_mcp_event_and_sync_v1("tool.completed", Some(turn_id), data)
    }

    #[cfg(test)]
    pub(crate) fn append_mcp_event_for_test_v1(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        self.append_mcp_event_and_sync_v1(kind, turn_id, data)
    }

    fn validate_mcp_journal_write_capability_v1(
        &self,
        capability: &McpJournalWriteCapabilityV1,
    ) -> Result<()> {
        let events = self.read_events()?;
        capability.validate_for_journal_unlocked(&self.session_id, &self.handle_id, &events)
    }

    fn append_with_mcp_authority(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
        mcp_authorized: bool,
    ) -> Result<JournalEvent> {
        let data = JournalValueOwnerV2::new(data)?;
        self.append_with_mcp_authority_owned(kind, turn_id, data, mcp_authorized)
    }

    fn append_with_mcp_authority_owned(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: JournalValueOwnerV2,
        mcp_authorized: bool,
    ) -> Result<JournalEvent> {
        self.ensure_healthy()?;
        if self.active_mcp_tool.is_some() {
            return Err(OxidraError::Session(
                "an admitted MCP tool call must be terminalized through its dispatch capability"
                    .to_owned(),
            ));
        }
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
        self.append_with_limit(kind, turn_id, data, byte_limit, mcp_authorized)
    }

    fn append_with_limit(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: JournalValueOwnerV2,
        byte_limit: u64,
        mcp_authorized: bool,
    ) -> Result<JournalEvent> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err(OxidraError::Session(
                "journal event kind cannot be empty".to_owned(),
            ));
        }
        if kind == "tool.in_doubt_resolved" {
            return Err(OxidraError::Session(
                "tool.in_doubt_resolved must use the typed, synced resolution transaction writer"
                    .to_owned(),
            ));
        }
        if self.recovery_headroom_bytes > 0 {
            return Err(OxidraError::Session(
                "journal appends are blocked until the typed in-doubt resolution transaction completes"
                    .to_owned(),
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
            data: data.into_value(),
        };
        validate_raw_protocol_event_shape_v1(&event)?;
        let generic_recovery_candidate = is_generic_recovery_skip_v1(&event);
        // Generic callers are still supported for historical/builtin journal
        // events, but an MCP-claimed lifecycle edge must never be the first
        // durable byte that the reader later rejects. Typed Provider/MCP
        // writers already run this check as part of their admission; mirror
        // the same prospective-prefix check here for the legacy public writer
        // before it reaches the page cache. Tool lifecycle events use an exact
        // `(turn_id, call_id)` lookup so stripping the marker cannot downgrade
        // an MCP call; this O(journal) compatibility cost is confined to the
        // legacy generic writer rather than the typed dispatch path.
        let mut mcp_prefix = None;
        let mut mcp_authority_required = generic_event_has_explicit_mcp_claim_v1(&event);
        if mcp_authority_required {
            mcp_prefix = Some(self.read_events()?);
        } else if event.kind == "response.started" {
            // v3 derives response ownership from the exact context.tools
            // event referenced by the response context.  There need not be a
            // flat registry claim on the start, so inspect the prefix before
            // allowing the legacy generic writer to author it.  The v2/v3
            // readers also validate every post-activation response identity,
            // including generic Provider attempts.  Keep that reader/profile
            // check separate from the authority decision so mutating both
            // halves of an identity cannot make an invalid MCP-era response
            // edge skip prospective validation.
            let prefix = self.read_events()?;
            mcp_authority_required = response_started_references_mcp_surface_v1(&prefix, &event);
            if mcp_authority_required || mcp_activation_present_v1(&prefix) {
                mcp_prefix = Some(prefix);
            }
        } else if is_response_terminal(&event.kind) {
            let prefix = self.read_events()?;
            let uses_activated_alias = response_completed_uses_activated_alias_v1(&prefix, &event);
            if uses_activated_alias
                && !response_terminal_has_exact_claimed_mcp_start_v1(&prefix, &event)
            {
                return Err(OxidraError::Session(
                    "response.completed uses an activated MCP alias without an exact MCP-owned response.started"
                        .to_owned(),
                ));
            }
            mcp_authority_required =
                response_terminal_may_belong_to_claimed_mcp_attempt_v1(&prefix, &event)
                    || uses_activated_alias;
            if mcp_authority_required || mcp_activation_present_v1(&prefix) {
                mcp_prefix = Some(prefix);
            }
        } else if is_tool_lifecycle(&event.kind) {
            let prefix = self.read_events()?;
            let exact_call_is_mcp = generic_tool_lifecycle_identity_v1(&event)
                .map(|(turn_id, call_id)| {
                    crate::mcp::validated_durable_mcp_call_if_present(&prefix, turn_id, call_id)
                })
                .transpose()?
                .is_some_and(|call| call.is_some());
            // Ownership is per canonical call, not per response/turn. A
            // claimed response may legally contain builtin and MCP calls in
            // the same batch; proven builtin identities must keep using the
            // generic Agent writer. Identity mutations that still claim an
            // MCP call are rejected by the prospective frozen-reader pass
            // below.
            mcp_authority_required = exact_call_is_mcp;
            // Once an MCP activation exists, run the frozen reader against
            // every prospective tool edge, even when this particular edge
            // looks like a builtin one.  The reader must be allowed to reject
            // a wrong-turn/legacy-id mutation that claims an existing MCP
            // call; otherwise the generic writer could fsync an event that
            // reopen would reject.  This is deliberately separate from the
            // authority decision so valid builtin lifecycle events remain
            // usable after an MCP activation.
            if mcp_authority_required
                || generic_recovery_candidate
                || mcp_activation_present_v1(&prefix)
            {
                mcp_prefix = Some(prefix);
            }
        }
        if let Some(prospective) = mcp_prefix.as_mut() {
            prospective.push(event.clone());
            crate::mcp::validate_mcp_call_chain(prospective)?;
            if generic_recovery_candidate {
                validate_generic_recovery_skips_v1(prospective)?;
            }
        }
        // The capability is intentionally scoped to the MCP-reserved event
        // vocabulary.  It proves *who* may author an MCP edge; it must not
        // become a general-purpose bypass around the public journal writer
        // for unrelated Agent/CLI events.
        if mcp_authorized && !mcp_authority_required {
            return Err(OxidraError::Session(format!(
                "{} is not an MCP-reserved event and cannot use the MCP journal capability",
                event.kind
            )));
        }
        // Run the frozen reader before reporting the authority error.  This
        // preserves the more useful fail-closed diagnostic for malformed
        // orphan claims, while a valid MCP event still cannot be authored by
        // the public generic writer.
        if mcp_authority_required && !mcp_authorized {
            return Err(OxidraError::Session(format!(
                "{} is MCP-reserved and requires typed MCP authority (use the typed MCP append path)",
                event.kind
            )));
        }
        let (encoded, event_metrics) = encode_journal_event_with_metrics_v2(&event)?;
        let mut next_decode_budget = self.decode_budget;
        if self.json_profile == JournalJsonProfile::BoundedV2 {
            next_decode_budget.account(event_metrics)?;
        }
        let metadata_result = self.file.metadata();
        let current_size = self.finish_io(metadata_result)?.len();
        let mut effective_limit = byte_limit;
        let mut next_turn_headroom = None;
        let mut next_lifecycle_margin_reserved = None;
        if let Some(active) = self.active_turn.clone() {
            if event.kind == "response.completed" {
                let mut prospective = self.read_events()?;
                prospective.push(event.clone());
                provider_request_slot_state_for_version(
                    PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                    &prospective,
                    &active.turn_id,
                )?;
                let required_headroom = active_turn_recovery_headroom_v1(
                    &self.session_id,
                    &prospective,
                    &active.turn_id,
                    active.user_message_seq,
                )?;
                let new_headroom = TURN_OUTCOME_HEADROOM_BYTES_V1.max(required_headroom);
                effective_limit = byte_limit.min(self.limit_preserving_headroom_v1(new_headroom)?);
                next_turn_headroom = Some(new_headroom);
                next_lifecycle_margin_reserved = Some(active.lifecycle_margin_reserved);
            } else if matches!(event.kind.as_str(), "tool.started" | "tool.in_doubt") {
                let event_bytes = u64::try_from(encoded.len())
                    .map_err(|_| {
                        OxidraError::Session("tool lifecycle event is too large".to_owned())
                    })?
                    .checked_add(1)
                    .ok_or_else(|| {
                        OxidraError::Session("tool lifecycle debt overflow".to_owned())
                    })?;
                let increment = event_bytes
                    .checked_mul(RECOVERY_LIFECYCLE_DUPLICATION_FACTOR_V1)
                    .and_then(|size| {
                        if active.lifecycle_margin_reserved {
                            Some(size)
                        } else {
                            size.checked_add(RECOVERY_LIFECYCLE_MARGIN_BYTES_V1)
                        }
                    })
                    .ok_or_else(|| {
                        OxidraError::Session("tool lifecycle debt overflow".to_owned())
                    })?;
                let new_headroom =
                    active
                        .headroom_bytes
                        .checked_add(increment)
                        .ok_or_else(|| {
                            OxidraError::Session("turn recovery debt overflow".to_owned())
                        })?;
                effective_limit = byte_limit.min(self.limit_preserving_headroom_v1(new_headroom)?);
                next_turn_headroom = Some(new_headroom);
                next_lifecycle_margin_reserved = Some(true);
            } else if matches!(
                event.kind.as_str(),
                "turn.cancelled"
                    | "turn.completed"
                    | "agent.stalled"
                    | "agent.limit_reached"
                    | "context.limit_reached"
            ) {
                let mut prospective = self.read_events()?;
                prospective.push(event.clone());
                let slot = provider_request_slot_state_for_version(
                    PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                    &prospective,
                    &active.turn_id,
                )?;
                if slot != ProviderRequestSlotState::Terminal {
                    return Err(OxidraError::Session(format!(
                        "{} cannot be appended while turn {}'s Provider request slot is {slot:?}",
                        event.kind, active.turn_id
                    )));
                }
                effective_limit =
                    byte_limit.min(self.limit_preserving_headroom_v1(active.headroom_bytes)?);
                next_turn_headroom = Some(active.headroom_bytes);
                next_lifecycle_margin_reserved = Some(active.lifecycle_margin_reserved);
            } else {
                effective_limit =
                    byte_limit.min(self.limit_preserving_headroom_v1(active.headroom_bytes)?);
                next_turn_headroom = Some(active.headroom_bytes);
                next_lifecycle_margin_reserved = Some(active.lifecycle_margin_reserved);
            }
        }
        if current_size
            .saturating_add(encoded.len() as u64)
            .saturating_add(1)
            > effective_limit
        {
            return Err(OxidraError::Session(format!(
                "session journal would exceed the {}-byte safety limit",
                effective_limit
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
        self.decode_budget = next_decode_budget;
        if let (Some(new_headroom), Some(current)) = (next_turn_headroom, self.active_turn.as_mut())
        {
            current.headroom_bytes = new_headroom;
            if let Some(reserved) = next_lifecycle_margin_reserved {
                current.lifecycle_margin_reserved = reserved;
            }
        }
        Ok(event)
    }

    fn generic_append_byte_limit_v1(&self) -> Result<u64> {
        let protected = self
            .active_turn
            .as_ref()
            .map_or(0, |active| active.headroom_bytes)
            .checked_add(self.recovery_headroom_bytes)
            .ok_or_else(|| OxidraError::Session("journal recovery debt overflow".to_owned()))?;
        self.byte_limit.checked_sub(protected).ok_or_else(|| {
            OxidraError::Session(format!(
                "session journal cannot protect the {protected}-byte durable recovery debt"
            ))
        })
    }

    fn limit_preserving_headroom_v1(&self, additional: u64) -> Result<u64> {
        let protected = additional
            .checked_add(self.recovery_headroom_bytes)
            .ok_or_else(|| OxidraError::Session("journal recovery debt overflow".to_owned()))?;
        self.byte_limit.checked_sub(protected).ok_or_else(|| {
            OxidraError::Session(format!(
                "session journal cannot protect the {protected}-byte durable recovery debt"
            ))
        })
    }

    pub(crate) fn append_and_sync(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let event = self.append(kind, turn_id, data)?;
        self.sync()?;
        Ok(event)
    }

    pub fn append_custom_and_sync(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let event = self.append_custom(kind, turn_id, data)?;
        self.sync()?;
        Ok(event)
    }

    /// Raw synced protocol fixture escape hatch for external integration
    /// tests and offline migration tooling.
    ///
    /// # Safety
    ///
    /// The caller must prove that the exact event is accepted by every
    /// applicable durable reducer and remains recoverable at this prefix. An
    /// external unsafe caller therefore joins the migration/fixture trusted
    /// computing base; this escape hatch is not covered by the safe durable
    /// writer-language guarantee.
    #[doc(hidden)]
    pub unsafe fn append_protocol_event_and_sync_unchecked_v1(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        let event = self.append(kind, turn_id, data)?;
        self.sync()?;
        Ok(event)
    }

    /// Admit one MCP tool dispatch after syncing its exact `tool.started`
    /// intent while protecting both a bounded immediate terminal and the
    /// complete prospective crash-recovery transaction.  The recovery debt
    /// is derived from the whole journal prefix so standalone calls cannot
    /// ignore still-unstarted siblings from the same Provider response.
    pub(crate) fn append_mcp_tool_started_v1(
        &mut self,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<McpToolDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        let data = JournalValueOwnerV2::new(data).map_err(DispatchAdmissionErrorV1::Fatal)?;
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.recovery_headroom_bytes > 0 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "MCP dispatch is blocked until every in-doubt tool is resolved".to_owned(),
            )));
        }
        if self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "another durable dispatch admission is already active".to_owned(),
            )));
        }
        if self
            .active_turn
            .as_ref()
            .is_some_and(|active| active.turn_id != turn_id)
        {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "MCP dispatch does not belong to the active turn transaction".to_owned(),
            )));
        }

        let mut prospective = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let started_seq = self.next_seq();
        let mut planned_seq = started_seq;
        let started = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "tool.started",
            Some(turn_id),
            data.into_value(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        prospective.push(started.clone());
        crate::mcp::validate_mcp_call_chain(&prospective)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let unstarted = unstarted_tool_calls(&prospective);
        // Without an active turn admission there is no owner capable of
        // transferring recovery debt for sibling calls after this standalone
        // call terminalizes.  Keep the standalone surface single-call rather
        // than misusing `recovery_headroom_bytes` as a batch reservation.
        if self.active_turn.is_none() && !unstarted.is_empty() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "standalone MCP dispatch requires a single-call Provider response or an active turn admission"
                    .to_owned(),
            )));
        }
        let protected_headroom = mcp_tool_dispatch_required_headroom_v1(
            self.session_id(),
            &mut prospective,
            &started,
            self.active_turn.as_ref(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let admission_limit = self
            .byte_limit
            .checked_sub(protected_headroom)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(OxidraError::Session(
                    format!(
                        "session journal cannot reserve the {protected_headroom}-byte MCP outcome and recovery headroom"
                    ),
                ))
            })?;
        if !self
            .preflight_prebuilt_batch_capacity(std::slice::from_ref(&started), admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?
        {
            return Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(
                OxidraError::Session(format!(
                    "session journal cannot append tool.started while preserving the {protected_headroom}-byte MCP outcome and recovery headroom"
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(std::slice::from_ref(&started), admission_limit)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if let Some(active_turn) = self.active_turn.as_mut() {
            active_turn.headroom_bytes = protected_headroom;
            active_turn.lifecycle_margin_reserved = true;
        }

        let reservation_id = Uuid::now_v7().to_string();
        self.active_mcp_tool = Some(ActiveMcpToolReservationV1 {
            reservation_id: reservation_id.clone(),
            turn_id: turn_id.to_owned(),
            started_seq,
            headroom_bytes: protected_headroom,
        });
        Ok(McpToolDispatchAdmissionV1 {
            reservation_id,
            turn_id: turn_id.to_owned(),
            started_seq,
            consumed: false,
            reopen_required: Arc::clone(&self.reopen_required),
        })
    }

    /// Commit the sole terminal authorized by an MCP dispatch admission.
    /// The event must fit the pre-dispatch reservation together with any
    /// remaining sibling/in-doubt recovery debt; otherwise the handle is left
    /// fail-closed for process-boundary recovery.
    pub(crate) fn commit_mcp_tool_terminal_v1(
        &mut self,
        admission: &mut McpToolDispatchAdmissionV1,
        kind: &str,
        data: Value,
    ) -> Result<JournalEvent> {
        let data = JournalValueOwnerV2::new(data)?;
        let active = self.active_mcp_tool_v1(admission)?.clone();
        if !matches!(kind, "tool.completed" | "tool.cancelled" | "tool.in_doubt") {
            return Err(OxidraError::Session(
                "invalid MCP dispatch terminal kind".to_owned(),
            ));
        }
        if admission.turn_id != active.turn_id || admission.started_seq != active.started_seq {
            return Err(OxidraError::Session(
                "MCP dispatch admission no longer matches its exact tool.started".to_owned(),
            ));
        }
        if data.as_value().get("started_seq").and_then(Value::as_u64) != Some(active.started_seq) {
            return Err(OxidraError::Session(
                "MCP terminal does not reference its exact admitted tool.started".to_owned(),
            ));
        }

        let mut planned_seq = self.next_seq();
        let terminal = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            kind,
            Some(&active.turn_id),
            data.into_value(),
        )?;
        let mut prospective = self.read_events()?;
        prospective.push(terminal.clone());
        crate::mcp::validate_mcp_call_chain(&prospective)?;

        if let Some(active_turn) = &self.active_turn {
            if active_turn.turn_id != active.turn_id {
                return Err(OxidraError::Session(
                    "MCP terminal does not belong to the active turn transaction".to_owned(),
                ));
            }
        }
        let pending = pending_tools(&prospective);
        let residual_headroom = mcp_tool_terminal_residual_headroom_v1(
            self.session_id(),
            &prospective,
            self.active_turn.as_ref(),
        )?;

        let terminal_bytes = encoded_journal_events_bytes(std::slice::from_ref(&terminal))?;
        if terminal_bytes > MCP_TOOL_OUTCOME_HEADROOM_BYTES_V1 {
            self.mark_reopen_required();
            return Err(OxidraError::Session(format!(
                "MCP terminal requires {terminal_bytes} bytes, exceeding its frozen {MCP_TOOL_OUTCOME_HEADROOM_BYTES_V1}-byte outcome profile"
            )));
        }
        if terminal_bytes
            .checked_add(residual_headroom)
            .is_none_or(|required| required > active.headroom_bytes)
        {
            self.mark_reopen_required();
            return Err(OxidraError::Session(format!(
                "MCP terminal plus recovery debt exceeds its {}-byte dispatch reservation",
                active.headroom_bytes
            )));
        }
        let commit_limit = self.limit_preserving_headroom_v1(residual_headroom)?;
        if !self.preflight_prebuilt_batch_capacity(std::slice::from_ref(&terminal), commit_limit)? {
            self.mark_reopen_required();
            return Err(OxidraError::Session(
                "MCP terminal no longer fits its dispatch reservation".to_owned(),
            ));
        }
        self.append_prebuilt_batch_with_limit(std::slice::from_ref(&terminal), commit_limit)?;

        if let Some(active_turn) = self.active_turn.as_mut() {
            active_turn.headroom_bytes = residual_headroom;
        } else if residual_headroom > 0 {
            self.recovery_headroom_bytes = residual_headroom;
            self.recovery.in_doubt = pending;
        }
        self.active_mcp_tool = None;
        admission.consumed = true;
        Ok(terminal)
    }

    fn active_mcp_tool_v1(
        &self,
        admission: &McpToolDispatchAdmissionV1,
    ) -> Result<&ActiveMcpToolReservationV1> {
        if admission.consumed {
            return Err(OxidraError::Session(
                "MCP tool dispatch admission was already consumed".to_owned(),
            ));
        }
        self.active_mcp_tool
            .as_ref()
            .filter(|active| active.reservation_id == admission.reservation_id)
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP tool dispatch admission does not match the active journal reservation"
                        .to_owned(),
                )
            })
    }

    /// Atomically settle selected unstarted MCP siblings under a fresh
    /// recovery marker.  Live cancellation/limit/in-doubt paths cannot use
    /// generic skip kinds because the MCP reducer requires the same marker
    /// authority as crash recovery.
    pub(crate) fn append_mcp_recovery_skips_v1(
        &mut self,
        turn_id: &str,
        calls: &[McpRecoverySkipV1],
    ) -> Result<()> {
        self.ensure_healthy()?;
        if calls.is_empty() {
            return Ok(());
        }
        if self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(OxidraError::Session(
                "MCP recovery skips require every Provider dispatch capability to be settled"
                    .to_owned(),
            ));
        }
        let active = self
            .active_turn
            .as_ref()
            .filter(|active| active.turn_id == turn_id)
            .cloned()
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP recovery skips require an active matching turn admission".to_owned(),
                )
            })?;
        let events = self.read_events()?;
        let unstarted = unstarted_tool_calls(&events);
        let (mcp_unstarted, _generic_unstarted) =
            partition_unstarted_tools_v1(&events, &unstarted)?;
        let mut selected = Vec::with_capacity(calls.len());
        let mut identities = HashSet::new();
        for call in calls {
            if !identities.insert((call.response_seq, call.call_id.clone())) {
                return Err(OxidraError::Session(format!(
                    "duplicate MCP recovery skip for call {}",
                    call.call_id
                )));
            }
            let tool = mcp_unstarted
                .iter()
                .find(|tool| {
                    tool.response_seq == call.response_seq
                        && tool.turn_id.as_deref() == Some(turn_id)
                        && tool.call_id == call.call_id
                        && tool.tool_name.as_deref() == Some(call.tool_name.as_str())
                        && tool.arguments.as_ref() == Some(&call.arguments)
                })
                .cloned()
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "MCP recovery skip for call {} does not match an unstarted durable call",
                        call.call_id
                    ))
                })?;
            selected.push(tool);
        }

        let mut recovery = RecoveryInfo {
            in_doubt: pending_tools(&events),
            skipped_before_start: selected.len(),
            ..RecoveryInfo::default()
        };
        let planned = plan_mcp_recovery_events(
            self.session_id(),
            self.next_seq(),
            &mut recovery,
            &selected,
            true,
            None,
        )?;
        let mut prospective = events.clone();
        prospective.extend(planned.iter().cloned());
        crate::mcp::validate_mcp_call_chain(&prospective)?;
        let required_headroom = active_turn_recovery_headroom_v1(
            self.session_id(),
            &prospective,
            &active.turn_id,
            active.user_message_seq,
        )?;
        let new_headroom = TURN_OUTCOME_HEADROOM_BYTES_V1.max(required_headroom);
        let limit = self.limit_preserving_headroom_v1(new_headroom)?;
        if !self.preflight_prebuilt_batch_capacity(&planned, limit)? {
            return Err(OxidraError::Session(
                "MCP recovery skip transaction does not fit the reserved journal headroom"
                    .to_owned(),
            ));
        }
        self.append_prebuilt_batch_with_limit(&planned, limit)?;
        if let Some(active) = self.active_turn.as_mut() {
            active.headroom_bytes = new_headroom;
        }
        Ok(())
    }

    /// Resolve the exact current in-doubt set as one synced transaction.  A
    /// caller-supplied snapshot is accepted only when it still equals the
    /// journal-derived pending set; this prevents stale UI state from
    /// resolving a different call.  The writer also appends the parent
    /// `turn.cancelled` immediately after the last resolution for each valid
    /// turn, so a later user message cannot turn the old request into a
    /// permanently incomplete segment.
    pub(crate) fn resolve_all_in_doubt_v1(
        &mut self,
        expected: &[InDoubtTool],
    ) -> Result<Vec<JournalEvent>> {
        self.ensure_healthy()?;
        if self.active_turn.is_some()
            || self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(OxidraError::Session(
                "in-doubt resolution requires every live dispatch capability to be suspended"
                    .to_owned(),
            ));
        }
        if self.recovery_headroom_bytes == 0 {
            return Err(OxidraError::Session(
                "in-doubt resolution has no protected durable capacity".to_owned(),
            ));
        }

        let durable_prefix = self.read_events()?;
        let pending = pending_tools(&durable_prefix);
        if pending.is_empty() {
            return Err(OxidraError::Session(
                "in-doubt resolution found no pending tool call".to_owned(),
            ));
        }
        if !unstarted_tool_calls(&durable_prefix).is_empty() {
            return Err(OxidraError::Session(
                "in-doubt resolution requires every unstarted sibling call to be settled first"
                    .to_owned(),
            ));
        }
        if in_doubt_resolution_identities(&pending) != in_doubt_resolution_identities(expected) {
            return Err(OxidraError::Session(
                "in-doubt resolution snapshot no longer matches the durable pending calls"
                    .to_owned(),
            ));
        }

        let finalizations = in_doubt_turn_finalizations_v1(&durable_prefix, &pending)?;
        let finalization_by_turn = finalizations
            .iter()
            .map(|turn| (turn.turn_id.clone(), turn.clone()))
            .collect::<HashMap<_, _>>();
        let mut remaining_by_turn = pending.iter().filter_map(|tool| tool.turn_id.clone()).fold(
            HashMap::<String, usize>::new(),
            |mut counts, turn_id| {
                *counts.entry(turn_id).or_default() += 1;
                counts
            },
        );
        let consumed_headroom =
            in_doubt_transaction_headroom_v1(&self.session_id, &durable_prefix, &pending, &[])?;
        if consumed_headroom != self.recovery_headroom_bytes {
            return Err(OxidraError::Session(format!(
                "in-doubt resolution debt drifted: journal requires {consumed_headroom} bytes, reservation holds {}",
                self.recovery_headroom_bytes
            )));
        }

        let mut planned_seq = self.next_seq();
        let mut planned =
            Vec::with_capacity(pending.len().saturating_add(finalization_by_turn.len()));
        let mut prospective = durable_prefix;
        for tool in &pending {
            let resolution = planned_recovery_event(
                self.session_id(),
                &mut planned_seq,
                "tool.in_doubt_resolved",
                tool.turn_id.as_deref(),
                in_doubt_resolution_data_v1(tool)?,
            )?;
            ensure_resolution_matches_pending_v1(&prospective, &resolution)?;
            let event_bytes = encoded_journal_events_bytes(std::slice::from_ref(&resolution))?;
            let slot_headroom = in_doubt_resolution_slot_headroom_v1(&self.session_id, tool)?;
            if event_bytes > slot_headroom {
                return Err(OxidraError::Session(format!(
                    "tool.in_doubt_resolved requires {event_bytes} bytes, exceeding its reserved {slot_headroom}-byte v1 profile"
                )));
            }
            prospective.push(resolution.clone());
            planned.push(resolution);

            let Some(turn_id) = tool.turn_id.as_ref() else {
                continue;
            };
            let remaining = remaining_by_turn.get_mut(turn_id).ok_or_else(|| {
                OxidraError::Session(
                    "in-doubt resolution lost its parent turn accounting".to_owned(),
                )
            })?;
            *remaining = remaining.checked_sub(1).ok_or_else(|| {
                OxidraError::Session("in-doubt turn accounting underflow".to_owned())
            })?;
            if *remaining == 0 {
                if let Some(turn) = finalization_by_turn.get(turn_id) {
                    let terminal = planned_recovery_event(
                        self.session_id(),
                        &mut planned_seq,
                        "turn.cancelled",
                        Some(&turn.turn_id),
                        in_doubt_turn_terminal_data_v1(turn),
                    )?;
                    prospective.push(terminal.clone());
                    planned.push(terminal);
                }
            }
        }

        crate::mcp::validate_mcp_call_chain(&prospective)?;
        for turn in &finalizations {
            let slot = provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &prospective,
                &turn.turn_id,
            )?;
            if slot != ProviderRequestSlotState::Terminal {
                return Err(OxidraError::Session(format!(
                    "resolved in-doubt turn {} did not reach a terminal Provider request slot",
                    turn.turn_id
                )));
            }
        }
        if !finalizations.is_empty() {
            segment_turns(&prospective)?;
        }
        let encoded_bytes = encoded_journal_events_bytes(&planned)?;
        if encoded_bytes > consumed_headroom {
            return Err(OxidraError::Session(format!(
                "in-doubt resolution transaction requires {encoded_bytes} bytes, exceeding its {consumed_headroom}-byte reservation"
            )));
        }
        self.append_prebuilt_batch_with_limit(&planned, self.byte_limit)?;
        self.recovery_headroom_bytes = 0;
        self.recovery.in_doubt.clear();
        Ok(planned)
    }

    /// Record the exact current in-doubt snapshot as failed after the caller
    /// has explicitly inspected the possible side effects. Stale or partial
    /// snapshots are rejected, and the complete resolution transaction is
    /// committed with the journal's protected recovery capacity.
    pub fn resolve_all_in_doubt_as_failed(
        &mut self,
        expected: &[InDoubtTool],
    ) -> Result<Vec<JournalEvent>> {
        self.resolve_all_in_doubt_v1(expected)
    }

    /// Start a new user turn only after protecting enough space to recover or
    /// cancel every crash prefix that precedes the first Provider dispatch.
    pub(crate) fn append_user_message_with_turn_admission_v1(
        &mut self,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<TurnTransactionAdmissionV1, DispatchAdmissionErrorV1> {
        let data = JournalValueOwnerV2::new(data).map_err(DispatchAdmissionErrorV1::Fatal)?;
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.recovery_headroom_bytes > 0 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a new turn is blocked until every in-doubt tool is resolved".to_owned(),
            )));
        }
        if self.active_turn.is_some()
            || self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
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
            data.into_value(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let mut prospective = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        prospective.push(user_event.clone());
        segment_turns(&prospective).map_err(DispatchAdmissionErrorV1::Fatal)?;

        let admission_limit = self
            .limit_preserving_headroom_v1(TURN_OUTCOME_HEADROOM_BYTES_V1)
            .map_err(|_| {
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
            lifecycle_margin_reserved: false,
        });
        Ok(TurnTransactionAdmissionV1 {
            reservation_id,
            consumed: false,
            reopen_required: Arc::clone(&self.reopen_required),
        })
    }

    /// Start one durable turn while reserving the recovery capacity that every
    /// subsequent external dispatch must preserve.  The returned opaque token
    /// is the only public way to prove ownership of that active turn.
    pub fn begin_turn_transaction_v1(
        &mut self,
        turn_id: &str,
        data: Value,
    ) -> Result<TurnTransactionAdmissionV1> {
        self.append_user_message_with_turn_admission_v1(turn_id, data)
            .map_err(DispatchAdmissionErrorV1::into_error)
    }

    /// Re-acquire the turn-level outcome reserve for a continuation that
    /// reuses an already durable `user.message`.  Recovery intents are allowed
    /// to be appended while this capability is active; the caller must obtain
    /// it before writing those intents or dispatching another Provider
    /// request.  This is deliberately separate from the new-turn writer so a
    /// retry can never silently run with the full journal limit.
    pub(crate) fn admit_turn_continuation_v1(
        &mut self,
        turn_id: &str,
        user_message_seq: u64,
    ) -> std::result::Result<TurnTransactionAdmissionV1, DispatchAdmissionErrorV1> {
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.recovery_headroom_bytes > 0 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "turn continuation is blocked until every in-doubt tool is resolved".to_owned(),
            )));
        }
        if self.active_turn.is_some()
            || self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a durable turn or Provider dispatch admission is already active".to_owned(),
            )));
        }
        let events = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let user = events.iter().find(|event| {
            event.kind == "user.message"
                && event.turn_id.as_deref() == Some(turn_id)
                && event.seq == user_message_seq
        });
        if user.is_none() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "turn continuation does not bind the exact durable user.message".to_owned(),
            )));
        }
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &events,
            turn_id,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if !matches!(
            slot,
            ProviderRequestSlotState::Ready | ProviderRequestSlotState::Terminal
        ) {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                format!(
                    "turn continuation cannot acquire Provider request slot from state {slot:?}"
                ),
            )));
        }
        let current_size = self
            .file
            .metadata()
            .map_err(|error| DispatchAdmissionErrorV1::Fatal(error.into()))?
            .len();
        let protected_headroom = TURN_OUTCOME_HEADROOM_BYTES_V1
            .checked_add(self.recovery_headroom_bytes)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "turn continuation recovery debt overflow".to_owned(),
                ))
            })?;
        if current_size
            .checked_add(protected_headroom)
            .is_none_or(|size| size > self.byte_limit)
        {
            return Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(
                OxidraError::Session(format!(
                    "turn continuation cannot reserve the {protected_headroom}-byte outcome headroom"
                )),
            ));
        }
        let reservation_id = Uuid::now_v7().to_string();
        self.active_turn = Some(ActiveTurnReservationV1 {
            reservation_id: reservation_id.clone(),
            turn_id: turn_id.to_owned(),
            user_message_seq,
            headroom_bytes: TURN_OUTCOME_HEADROOM_BYTES_V1,
            lifecycle_margin_reserved: false,
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
    pub fn finish_turn_transaction_v1(
        &mut self,
        admission: &mut TurnTransactionAdmissionV1,
        cancellation_reason: Option<&str>,
    ) -> Result<()> {
        let active = self.active_turn_v1(admission)?.clone();
        if self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(OxidraError::Session(
                "turn transaction cannot be finalized while a Provider dispatch capability is active"
                    .to_owned(),
            ));
        }
        let mut events = self.read_events()?;
        let (pending, explicitly_in_doubt_started_seqs) =
            pending_tools_with_explicit_in_doubt(&events);
        let pending = pending
            .into_iter()
            .filter(|tool| tool.turn_id.as_deref() == Some(active.turn_id.as_str()))
            .collect::<Vec<_>>();
        if !pending.is_empty() {
            let all_explicit_in_doubt = pending
                .iter()
                .all(|tool| explicitly_in_doubt_started_seqs.contains(&tool.started_seq));
            if !all_explicit_in_doubt {
                self.mark_reopen_required();
                return Err(OxidraError::Session(format!(
                    "turn {} has {} started tool call(s) without a durable complete result; reopen is required",
                    active.turn_id,
                    pending.len()
                )));
            }

            // `tool.in_doubt` is a deliberate suspended owner, not permission
            // to write a parent terminal over an unresolved call.  Close any
            // later calls that never started, then transfer the turn reserve
            // into exact per-call resolution slots so the live CLI can ask the
            // user without first poisoning/reopening this handle.
            let unstarted = unstarted_tool_calls(&events)
                .into_iter()
                .filter(|tool| tool.turn_id.as_deref() == Some(active.turn_id.as_str()))
                .collect::<Vec<_>>();
            let (mcp_unstarted, generic_unstarted) =
                partition_unstarted_tools_v1(&events, &unstarted)
                    .inspect_err(|_| self.mark_reopen_required())?;
            let planned_seq = self.next_seq();
            let mut recovery = RecoveryInfo {
                in_doubt: pending.clone(),
                // `journal.recovered` authorizes only the MCP-owned sibling
                // skips emitted by `plan_mcp_recovery_events`. Generic
                // siblings are settled by their own event profile below and
                // must not drift this marker's replay/audit count.
                skipped_before_start: mcp_unstarted.len(),
                ..RecoveryInfo::default()
            };
            // MCP pre-start calls may only be settled by a versioned recovery
            // marker.  Generate the marker and all sibling skips as one
            // bounded batch so live in-doubt suspension has the same
            // authority/order contract as crash recovery.
            let mut planned = plan_mcp_recovery_events(
                self.session_id(),
                planned_seq,
                &mut recovery,
                &mcp_unstarted,
                true,
                None,
            )?;
            let generic_seq = planned
                .last()
                .map(|event| {
                    event.seq.checked_add(1).ok_or_else(|| {
                        OxidraError::Session("journal sequence exhausted".to_owned())
                    })
                })
                .transpose()?
                .unwrap_or(planned_seq);
            planned.extend(plan_generic_skip_events_v1(
                self.session_id(),
                generic_seq,
                &generic_unstarted,
                "tool.skipped_due_to_in_doubt",
                "in_doubt",
                "in_doubt",
            )?);
            events.extend(planned.iter().cloned());
            crate::mcp::validate_mcp_call_chain(&events)
                .inspect_err(|_| self.mark_reopen_required())?;
            let pending_after_skips = pending_tools_for_turn(&events, &active.turn_id);
            let slot = provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                &active.turn_id,
            )?;
            if slot != ProviderRequestSlotState::AwaitingTools || pending_after_skips.is_empty() {
                self.mark_reopen_required();
                return Err(OxidraError::Session(format!(
                    "turn {} cannot suspend its in-doubt transaction from Provider request slot {slot:?}",
                    active.turn_id
                )));
            }
            let resolution_headroom = in_doubt_transaction_headroom_v1(
                &self.session_id,
                &events,
                &pending_after_skips,
                &[],
            )?;
            let encoded_bytes = encoded_journal_events_bytes(&planned)?;
            if encoded_bytes
                .checked_add(resolution_headroom)
                .is_none_or(|required| required > active.headroom_bytes)
            {
                self.mark_reopen_required();
                return Err(OxidraError::Session(format!(
                    "turn {} cannot transfer its {}-byte reserve into {encoded_bytes} bytes of skips plus {resolution_headroom} bytes of in-doubt resolution debt",
                    active.turn_id, active.headroom_bytes
                )));
            }
            let resolution_limit = self
                .byte_limit
                .checked_sub(resolution_headroom)
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "session journal cannot protect the {resolution_headroom}-byte in-doubt resolution debt"
                    ))
                })?;
            self.append_prebuilt_batch_with_limit(&planned, resolution_limit)
                .inspect_err(|_| self.mark_reopen_required())?;
            self.active_turn = None;
            self.recovery_headroom_bytes = resolution_headroom;
            admission.consumed = true;
            return Ok(());
        }
        if turn_transaction_is_settled_v1(
            &events,
            &active.turn_id,
            active.user_message_seq,
            self.json_profile,
        )? {
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
        // A response may have durably produced several function calls before
        // approval/observer code failed.  Settle every still-unstarted call
        // first, then append the parent turn terminal in one prebuilt batch.
        // This makes every complete-line prefix recoverable and prevents the
        // Provider-slot reducer from observing a parent terminal over pending
        // calls.
        let unstarted = unstarted_tool_calls(&events)
            .into_iter()
            .filter(|tool| tool.turn_id.as_deref() == Some(active.turn_id.as_str()))
            .collect::<Vec<_>>();
        let (mcp_unstarted, generic_unstarted) = partition_unstarted_tools_v1(&events, &unstarted)
            .inspect_err(|_| self.mark_reopen_required())?;
        let mut recovery = RecoveryInfo {
            skipped_before_start: mcp_unstarted.len(),
            ..RecoveryInfo::default()
        };
        let mut planned = plan_mcp_recovery_events(
            self.session_id(),
            self.next_seq(),
            &mut recovery,
            &mcp_unstarted,
            false,
            None,
        )?;
        let mut planned_seq = match planned.last() {
            Some(event) => event
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?,
            None => self.next_seq(),
        };
        for tool in &generic_unstarted {
            planned.push(planned_recovery_event(
                self.session_id(),
                &mut planned_seq,
                "tool.skipped_due_to_cancel",
                Some(&active.turn_id),
                cancellation_skip_data(tool, &reason),
            )?);
        }
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
        let refreshed_headroom =
            TURN_OUTCOME_HEADROOM_BYTES_V1.max(active_turn_recovery_headroom_v1(
                &self.session_id,
                &events,
                &active.turn_id,
                active.user_message_seq,
            )?);
        planned.push(cancelled);
        let mut prospective = events;
        prospective.extend(planned.iter().cloned());
        segment_turns(&prospective)?;
        crate::mcp::validate_mcp_call_chain(&prospective)
            .inspect_err(|_| self.mark_reopen_required())?;
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &prospective,
            &active.turn_id,
        )?;
        if slot != ProviderRequestSlotState::Terminal {
            self.mark_reopen_required();
            return Err(OxidraError::Session(format!(
                "turn {} cancellation batch leaves Provider request slot in state {slot:?}",
                active.turn_id
            )));
        }
        let encoded_bytes = encoded_journal_events_bytes(&planned)?;
        if encoded_bytes > refreshed_headroom {
            self.mark_reopen_required();
            return Err(OxidraError::Session(format!(
                "turn cancellation batch requires {encoded_bytes} bytes, exceeding its reserved {}-byte outcome headroom",
                refreshed_headroom
            )));
        }
        if !self
            .preflight_prebuilt_batch_capacity(&planned, self.byte_limit)
            .inspect_err(|_| self.mark_reopen_required())?
        {
            self.mark_reopen_required();
            return Err(OxidraError::Session(
                "turn cancellation batch no longer fits the journal".to_owned(),
            ));
        }
        self.append_prebuilt_batch_with_limit(&planned, self.byte_limit)?;
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
        turn_admission: &TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<ProviderResponseDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        self.append_provider_response_started_inner_v1(turn_admission, turn_id, data, false)
    }

    pub(crate) fn append_mcp_provider_response_started_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        turn_admission: &TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<ProviderResponseDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        self.append_provider_response_started_inner_v1(turn_admission, turn_id, data, true)
    }

    fn append_provider_response_started_inner_v1(
        &mut self,
        turn_admission: &TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
        mcp_authorized: bool,
    ) -> std::result::Result<ProviderResponseDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        let data = JournalValueOwnerV2::new(data).map_err(DispatchAdmissionErrorV1::Fatal)?;
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.recovery_headroom_bytes > 0 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "Provider dispatch is blocked until every in-doubt tool is resolved".to_owned(),
            )));
        }
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
        if self.active_mcp_tool.is_some() {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "an MCP tool dispatch admission is already active".to_owned(),
            )));
        }
        let active_turn = self
            .active_turn_v1(turn_admission)
            .map_err(DispatchAdmissionErrorV1::Fatal)?
            .clone();
        if active_turn.turn_id != turn_id {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "Provider response admission does not belong to the active turn transaction"
                    .to_owned(),
            )));
        }
        let durable_prefix = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        ensure_provider_dispatch_recovery_profile_v1(&durable_prefix)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &durable_prefix,
            turn_id,
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if slot != ProviderRequestSlotState::Ready {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                format!(
                    "Provider response dispatch requires turn {turn_id}'s request slot to be Ready, found {slot:?}"
                ),
            )));
        }
        let response_attempt_id = data
            .as_value()
            .get("response_attempt_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "response.started has no response_attempt_id for dispatch admission".to_owned(),
                ))
            })?
            .to_owned();
        let context = data.as_value().get("context").cloned().ok_or_else(|| {
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
            data.into_value(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let mcp_owned = response_started_references_mcp_surface_v1(&durable_prefix, &started);
        if mcp_owned && !mcp_authorized {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "generic Provider response admission cannot author an MCP-owned response.started; use the typed MCP Provider writer"
                    .to_owned(),
            )));
        }
        if !mcp_owned && mcp_authorized {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "typed MCP Provider response admission requires an explicit MCP-owned response.started"
                    .to_owned(),
            )));
        }
        let refreshed_turn_headroom = active_turn_recovery_headroom_v1(
            &self.session_id,
            &durable_prefix,
            &active_turn.turn_id,
            active_turn.user_message_seq,
        )
        .map(|required| TURN_OUTCOME_HEADROOM_BYTES_V1.max(required))
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        // The writer must never fsync a Provider start that the frozen MCP
        // reducer would reject on the next open.  In particular, a partial or
        // mismatched registry claim must fail before the external Provider is
        // dispatched; otherwise the admission token can only preserve bytes,
        // not the journal's semantic recoverability.
        let mut prospective = durable_prefix;
        prospective.push(started.clone());
        crate::mcp::validate_mcp_call_chain(&prospective)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let outcome_headroom = provider_response_outcome_headroom_required_v1(
            self.session_id(),
            turn_id,
            &response_attempt_id,
            response_started_seq,
            context.clone(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if outcome_headroom > PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                format!(
                    "Provider outcome profile requires {outcome_headroom} bytes, exceeding its frozen {PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1}-byte admission ceiling"
                ),
            )));
        }
        let protected_headroom = refreshed_turn_headroom
            .checked_add(outcome_headroom)
            .and_then(|size| size.checked_add(self.recovery_headroom_bytes))
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "Provider and turn recovery debt overflow".to_owned(),
                ))
            })?;
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
        if let Some(turn) = self.active_turn.as_mut() {
            turn.headroom_bytes = refreshed_turn_headroom;
        }

        let reservation_id = Uuid::now_v7().to_string();
        self.active_provider_response = Some(ActiveProviderResponseReservationV1 {
            reservation_id: reservation_id.clone(),
            turn_id: turn_id.to_owned(),
            response_attempt_id,
            response_started_seq,
            context,
            headroom_bytes: outcome_headroom,
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
        (|| {
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
            match self.commit_provider_response_events_v1(admission, &[event.clone()], true, false)
            {
                Ok(()) => {}
                Err(DurableOutcomeCommitErrorV1::Fatal(error)) => {
                    admission.mark_reopen_required_v1();
                    return Err(error);
                }
                Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(error)) => {
                    return Err(error);
                }
            }
            Ok(event)
        })()
    }

    pub(crate) fn append_mcp_provider_response_failed_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        error: &str,
    ) -> Result<JournalEvent> {
        if let Err(error) =
            self.validate_mcp_provider_response_admission_with_live_proof_v1(proof, admission)
        {
            admission.mark_reopen_required_v1();
            return Err(error);
        }
        self.append_provider_response_failed_v1(admission, error)
    }

    pub(crate) fn append_provider_response_aborted_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        reason: &str,
    ) -> Result<JournalEvent> {
        (|| {
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
            match self.commit_provider_response_events_v1(admission, &[event.clone()], true, false)
            {
                Ok(()) => {}
                Err(DurableOutcomeCommitErrorV1::Fatal(error)) => {
                    admission.mark_reopen_required_v1();
                    return Err(error);
                }
                Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(error)) => {
                    return Err(error);
                }
            }
            Ok(event)
        })()
    }

    pub(crate) fn append_mcp_provider_response_aborted_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        reason: &str,
    ) -> Result<JournalEvent> {
        if let Err(error) =
            self.validate_mcp_provider_response_admission_with_live_proof_v1(proof, admission)
        {
            admission.mark_reopen_required_v1();
            return Err(error);
        }
        self.append_provider_response_aborted_v1(admission, reason)
    }

    pub(crate) fn append_provider_response_completed_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        data: Value,
    ) -> std::result::Result<JournalEvent, DurableOutcomeCommitErrorV1> {
        let result = self.append_provider_response_completed_inner_v1(admission, data, false);
        if matches!(result, Err(DurableOutcomeCommitErrorV1::Fatal(_))) {
            admission.mark_reopen_required_v1();
        }
        result
    }

    pub(crate) fn append_mcp_provider_response_completed_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        data: Value,
    ) -> std::result::Result<JournalEvent, DurableOutcomeCommitErrorV1> {
        if let Err(error) =
            self.validate_mcp_provider_response_admission_with_live_proof_v1(proof, admission)
        {
            admission.mark_reopen_required_v1();
            return Err(DurableOutcomeCommitErrorV1::Fatal(error));
        }
        let result = self.append_provider_response_completed_inner_v1(admission, data, true);
        if matches!(result, Err(DurableOutcomeCommitErrorV1::Fatal(_))) {
            admission.mark_reopen_required_v1();
        }
        result
    }

    fn append_provider_response_completed_inner_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        data: Value,
        mcp_authorized: bool,
    ) -> std::result::Result<JournalEvent, DurableOutcomeCommitErrorV1> {
        let data = JournalValueOwnerV2::new(data)
            .map_err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite)?;
        let active = self
            .active_provider_response_v1(admission)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
            .clone();
        if data
            .as_value()
            .get("response_attempt_id")
            .and_then(Value::as_str)
            != Some(active.response_attempt_id.as_str())
        {
            return Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(
                OxidraError::Session(
                    "response.completed does not bind its admitted response attempt".to_owned(),
                ),
            ));
        }
        let mut planned_seq = self.next_seq();
        let event = planned_recovery_event(
            self.session_id(),
            &mut planned_seq,
            "response.completed",
            Some(&active.turn_id),
            data.into_value(),
        )
        .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let durable_prefix = self
            .read_events()
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        crate::mcp::validate_mcp_call_chain(&durable_prefix)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let baseline_slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &durable_prefix,
            &active.turn_id,
        )
        .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        if baseline_slot != ProviderRequestSlotState::ResponseInFlight {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                format!(
                    "Provider response completion requires an in-flight response slot, found {baseline_slot:?}"
                ),
            )));
        }
        let mcp_owned = generic_event_has_explicit_mcp_claim_v1(&event)
            || response_completed_uses_activated_alias_v1(&durable_prefix, &event);
        if mcp_owned && !mcp_authorized {
            return Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(
                OxidraError::Session(
                    "generic Provider response admission cannot author an MCP-owned response.completed; use the typed MCP Provider writer"
                        .to_owned(),
                ),
            ));
        }
        self.commit_provider_response_events_v1(admission, &[event.clone()], false, true)?;
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
        (|| {
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
            validate_provider_context_limit_turns_v1(
                &prospective,
                &HashSet::from([active.turn_id]),
            )?;
            match self.commit_provider_response_events_v1(
                admission,
                &[failed.clone(), limit.clone()],
                true,
                false,
            ) {
                Ok(()) => {}
                Err(DurableOutcomeCommitErrorV1::Fatal(error)) => {
                    admission.mark_reopen_required_v1();
                    return Err(error);
                }
                Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(error)) => {
                    return Err(error);
                }
            }
            Ok((failed, limit))
        })()
    }

    pub(crate) fn append_mcp_provider_context_limit_with_live_proof_v1(
        &mut self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        reason: &str,
    ) -> Result<(JournalEvent, JournalEvent)> {
        if let Err(error) =
            self.validate_mcp_provider_response_admission_with_live_proof_v1(proof, admission)
        {
            admission.mark_reopen_required_v1();
            return Err(error);
        }
        self.append_provider_context_limit_v1(admission, reason)
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

    fn validate_mcp_provider_response_admission_with_live_proof_v1(
        &self,
        proof: &LiveMcpJournalWriteProofV1<'_>,
        admission: &ProviderResponseDispatchAdmissionV1,
    ) -> Result<()> {
        self.validate_mcp_journal_write_capability_v1(proof.capability())?;
        let active = self.active_provider_response_v1(admission)?;
        let events = self.read_events()?;
        let exact_owned_start = events.iter().any(|event| {
            event.kind == "response.started"
                && event.seq == active.response_started_seq
                && event.turn_id.as_deref() == Some(active.turn_id.as_str())
                && event
                    .data
                    .get("response_attempt_id")
                    .and_then(Value::as_str)
                    == Some(active.response_attempt_id.as_str())
                && response_started_references_mcp_surface_v1(&events, event)
        });
        if !exact_owned_start {
            return Err(OxidraError::Session(
                "typed MCP Provider response admission is not bound to its exact durable MCP response.started"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn commit_provider_response_events_v1(
        &mut self,
        admission: &mut ProviderResponseDispatchAdmissionV1,
        events: &[JournalEvent],
        must_fit_headroom: bool,
        fallback_permitted_before_write: bool,
    ) -> std::result::Result<(), DurableOutcomeCommitErrorV1> {
        let active = self
            .active_provider_response_v1(admission)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
            .clone();
        let active_turn = self
            .active_turn
            .as_ref()
            .ok_or_else(|| {
                DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                    "Provider response terminal cannot be committed without an active turn transaction"
                        .to_owned(),
                ))
            })?
            .clone();
        if active_turn.turn_id != active.turn_id {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "Provider response terminal does not match the active turn transaction".to_owned(),
            )));
        }
        let durable_prefix = self
            .read_events()
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        crate::mcp::validate_mcp_call_chain(&durable_prefix)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let baseline_slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &durable_prefix,
            &active.turn_id,
        )
        .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        if baseline_slot != ProviderRequestSlotState::ResponseInFlight {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                format!(
                    "Provider response terminal requires an in-flight response slot, found {baseline_slot:?}"
                ),
            )));
        }
        let mut prospective = durable_prefix;
        prospective.extend(events.iter().cloned());
        // Keep the production writer's acceptance set inside the frozen MCP
        // reader's acceptance set.  This is deliberately before any append;
        // callers may still use the same admission to write the bounded
        // response.failed fallback when a completed response is malformed.
        crate::mcp::validate_mcp_call_chain(&prospective).map_err(|error| {
            provider_response_candidate_error_v1(error, fallback_permitted_before_write)
        })?;
        let encoded_bytes = encoded_journal_events_bytes(events).map_err(|error| {
            provider_response_candidate_error_v1(error, fallback_permitted_before_write)
        })?;
        if must_fit_headroom && encoded_bytes > active.headroom_bytes {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                format!(
                    "Provider response terminal requires {encoded_bytes} bytes, exceeding its reserved {}-byte durable outcome headroom",
                    active.headroom_bytes
                ),
            )));
        }
        let mut next_turn_headroom = None;
        let byte_limit = if must_fit_headroom {
            self.limit_preserving_headroom_v1(active_turn.headroom_bytes)
                .map_err(|_| {
                    DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(format!(
                        "Provider terminal cannot preserve the {}-byte turn recovery debt",
                        active_turn.headroom_bytes
                    )))
                })?
        } else {
            let turn = active_turn.clone();
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &prospective,
                &turn.turn_id,
            )
            .map_err(|error| {
                provider_response_candidate_error_v1(error, fallback_permitted_before_write)
            })?;
            let required_headroom = active_turn_recovery_headroom_v1(
                &self.session_id,
                &prospective,
                &turn.turn_id,
                turn.user_message_seq,
            )
            .map_err(|error| {
                provider_response_candidate_error_v1(error, fallback_permitted_before_write)
            })?;
            let protected_headroom = TURN_OUTCOME_HEADROOM_BYTES_V1.max(required_headroom);
            let limit = self
                .limit_preserving_headroom_v1(protected_headroom)
                .map_err(|_| {
                    provider_response_candidate_error_v1(
                        OxidraError::Session(format!(
                            "response completion cannot reserve the {protected_headroom}-byte tool-batch recovery debt"
                        )),
                        fallback_permitted_before_write,
                    )
                })?;
            next_turn_headroom = Some(protected_headroom);
            limit
        };
        if !self
            .preflight_prebuilt_batch_capacity(events, byte_limit)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
        {
            return Err(provider_response_candidate_error_v1(
                OxidraError::Session(format!(
                    "journal transaction would exceed the {byte_limit}-byte safety limit while committing the Provider response terminal"
                )),
                fallback_permitted_before_write,
            ));
        }
        self.append_prebuilt_batch_with_limit(events, byte_limit)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        if let (Some(headroom), Some(turn)) = (next_turn_headroom, self.active_turn.as_mut()) {
            turn.headroom_bytes = headroom;
        }
        self.active_provider_response = None;
        admission.consumed = true;
        Ok(())
    }

    /// Admit one compaction Provider dispatch after syncing the exact
    /// `compaction.started` intent while protecting a bounded failure/recovery
    /// transaction. Boundary-owned attempts bind that same durable boundary
    /// into the capability.
    pub(crate) fn validate_compaction_dispatch_owner_v1(
        &self,
        turn_admission: Option<&TurnTransactionAdmissionV1>,
        boundary: Option<&CompactionBoundary>,
    ) -> Result<()> {
        match (&self.active_turn, turn_admission) {
            (Some(active_turn), Some(admission)) => {
                let admitted = self.active_turn_v1(admission)?;
                if admitted.reservation_id != active_turn.reservation_id {
                    return Err(OxidraError::Session(
                        "compaction dispatch admission does not match the active turn reservation"
                            .to_owned(),
                    ));
                }
                let boundary = boundary.ok_or_else(|| {
                    OxidraError::Session(
                        "compaction dispatch requires a boundary bound to the active turn"
                            .to_owned(),
                    )
                })?;
                if boundary.turn_id != active_turn.turn_id
                    || boundary.user_message_seq != active_turn.user_message_seq
                {
                    return Err(OxidraError::Session(
                        "compaction dispatch does not bind the active turn transaction".to_owned(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(OxidraError::Session(
                    "compaction dispatch requires the active turn admission capability".to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(OxidraError::Session(
                    "compaction dispatch admission does not match an active turn transaction"
                        .to_owned(),
                ));
            }
            (None, None) => {}
        }
        Ok(())
    }

    pub(crate) fn append_compaction_started_v1(
        &mut self,
        turn_admission: Option<&TurnTransactionAdmissionV1>,
        data: Value,
    ) -> std::result::Result<CompactionProviderDispatchAdmissionV1, DispatchAdmissionErrorV1> {
        let data = JournalValueOwnerV2::new(data).map_err(DispatchAdmissionErrorV1::Fatal)?;
        self.ensure_healthy()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        if self.recovery_headroom_bytes > 0 {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "compaction dispatch is blocked until every in-doubt tool is resolved".to_owned(),
            )));
        }
        if self.active_provider_response.is_some()
            || self.active_compaction.is_some()
            || self.active_mcp_tool.is_some()
        {
            return Err(DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                "a Provider dispatch admission is already active".to_owned(),
            )));
        }
        let attempt_id = data
            .as_value()
            .get("attempt_id")
            .and_then(Value::as_str)
            .filter(|value| valid_provider_context_limit_identity_v1(value))
            .ok_or_else(|| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                    "compaction.started has no valid attempt_id for dispatch admission".to_owned(),
                ))
            })?
            .to_owned();
        let boundary = data.as_value().get("boundary").cloned();
        let boundary_identity = boundary
            .as_ref()
            .map(|value| serde_json::from_value::<CompactionBoundary>(value.clone()))
            .transpose()
            .map_err(|error| {
                DispatchAdmissionErrorV1::Fatal(OxidraError::Session(format!(
                    "invalid compaction boundary for dispatch admission: {error}"
                )))
            })?;
        self.validate_compaction_dispatch_owner_v1(turn_admission, boundary_identity.as_ref())
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let active_turn = self.active_turn.clone();

        let durable_prefix = self
            .read_events()
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        ensure_compaction_dispatch_recovery_profile_v1(&durable_prefix, boundary.as_ref())
            .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let refreshed_turn_headroom = active_turn.as_ref().map(|turn| {
            active_turn_recovery_headroom_v1(
                &self.session_id,
                &durable_prefix,
                &turn.turn_id,
                turn.user_message_seq,
            )
            .map(|required| TURN_OUTCOME_HEADROOM_BYTES_V1.max(required))
        });
        let refreshed_turn_headroom = match refreshed_turn_headroom {
            Some(result) => Some(result.map_err(DispatchAdmissionErrorV1::Fatal)?),
            None => None,
        };
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
            data.into_value(),
        )
        .map_err(DispatchAdmissionErrorV1::Fatal)?;
        let mut prospective = durable_prefix;
        prospective.push(started.clone());
        validate_checkpoint_chain(&prospective).map_err(DispatchAdmissionErrorV1::Fatal)?;
        validate_compaction_boundary_chain(&prospective)
            .map_err(DispatchAdmissionErrorV1::Fatal)?;

        let protected_headroom = active_turn.as_ref().map_or_else(
            || {
                COMPACTION_OUTCOME_HEADROOM_BYTES_V1
                    .checked_add(self.recovery_headroom_bytes)
                    .ok_or_else(|| {
                        DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                            "compaction recovery debt overflow".to_owned(),
                        ))
                    })
            },
            |turn| {
                refreshed_turn_headroom
                    .unwrap_or(turn.headroom_bytes)
                    .checked_add(COMPACTION_OUTCOME_HEADROOM_BYTES_V1)
                    .and_then(|size| size.checked_add(self.recovery_headroom_bytes))
                    .ok_or_else(|| {
                        DispatchAdmissionErrorV1::Fatal(OxidraError::Session(
                            "compaction and turn recovery debt overflow".to_owned(),
                        ))
                    })
            },
        )?;
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
        if let (Some(headroom), Some(turn)) = (refreshed_turn_headroom, self.active_turn.as_mut()) {
            turn.headroom_bytes = headroom;
        }

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
        let compaction_data = JournalValueOwnerV2::new(compaction_data)
            .map_err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite)?;
        let boundary_terminal = boundary_terminal
            .map(|(kind, data)| JournalValueOwnerV2::new(data).map(|data| (kind, data)))
            .transpose()
            .map_err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite)?;
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
        if compaction_data
            .as_value()
            .get("attempt_id")
            .and_then(Value::as_str)
            != Some(active.attempt_id.as_str())
        {
            return Err(DurableOutcomeCommitErrorV1::Fatal(OxidraError::Session(
                "compaction outcome does not bind its admitted attempt".to_owned(),
            )));
        }
        if compaction_kind != COMPACTION_CHECKPOINT_KIND
            && compaction_data
                .as_value()
                .get("started_seq")
                .and_then(Value::as_u64)
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
            compaction_data.into_value(),
        )
        .map_err(DurableOutcomeCommitErrorV1::Fatal)?;
        let mut events = vec![terminal];
        if let Some((kind, data)) = boundary_terminal {
            events.push(
                planned_recovery_event(
                    self.session_id(),
                    &mut planned_seq,
                    kind,
                    None,
                    data.into_value(),
                )
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
        let commit_limit = match self.active_turn.as_ref() {
            Some(turn) => self
                .limit_preserving_headroom_v1(turn.headroom_bytes)
                .map_err(DurableOutcomeCommitErrorV1::Fatal)?,
            None => self
                .limit_preserving_headroom_v1(0)
                .map_err(DurableOutcomeCommitErrorV1::Fatal)?,
        };
        if !self
            .preflight_prebuilt_batch_capacity(&events, commit_limit)
            .map_err(DurableOutcomeCommitErrorV1::Fatal)?
        {
            return Err(DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(
                OxidraError::Session(format!(
                    "compaction outcome transaction would exceed the {}-byte safety limit",
                    commit_limit
                )),
            ));
        }
        self.append_prebuilt_batch_with_limit(&events, commit_limit)
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
            let metadata_result = self.file.metadata();
            return Ok(self.finish_io(metadata_result)?.len() <= byte_limit);
        }
        let mut expected_seq = self.next_seq;
        let mut next_decode_budget = self.decode_budget;
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
            let (_, metrics) = encode_journal_event_with_metrics_v2(event)?;
            if self.json_profile == JournalJsonProfile::BoundedV2 {
                next_decode_budget.account(metrics)?;
            }
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
            let metadata_result = self.file.metadata();
            let current_size = self.finish_io(metadata_result)?.len();
            if current_size > byte_limit {
                return Err(OxidraError::Session(format!(
                    "session journal transaction would exceed the {byte_limit}-byte safety limit"
                )));
            }
            return Ok(());
        }

        let mut expected_seq = self.next_seq;
        let mut encoded_bytes = 0u64;
        let mut encoded_events = Vec::with_capacity(events.len());
        let mut next_decode_budget = self.decode_budget;
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
            let (encoded, metrics) = encode_journal_event_with_metrics_v2(event)?;
            if self.json_profile == JournalJsonProfile::BoundedV2 {
                next_decode_budget.account(metrics)?;
            }
            let event_len = u64::try_from(encoded.len())
                .map_err(|_| OxidraError::Session("recovery event is too large".to_owned()))?;
            encoded_bytes = encoded_bytes
                .checked_add(event_len)
                .and_then(|size| size.checked_add(1))
                .ok_or_else(|| {
                    OxidraError::Session("journal transaction size overflow".to_owned())
                })?;
            encoded_events.push(encoded);
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
        for encoded in encoded_events {
            let write_result = self.file.write_all(&encoded);
            self.finish_io(write_result)?;
            let newline_result = self.file.write_all(b"\n");
            self.finish_io(newline_result)?;
        }
        self.next_seq = expected_seq;
        self.decode_budget = next_decode_budget;
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

fn validate_read_only_export_destination_v1(destination: &Path) -> Result<()> {
    if destination.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(OxidraError::Session(
            "read-only session export destination contains an embedded NUL".to_owned(),
        ));
    }
    #[cfg(windows)]
    if destination
        .file_name()
        .is_some_and(|name| name.as_encoded_bytes().contains(&b':'))
    {
        return Err(OxidraError::Session(
            "read-only session export destination cannot use a Windows alternate data stream"
                .to_owned(),
        ));
    }
    if destination.extension().and_then(|value| value.to_str())
        == Some(READ_ONLY_SESSION_EXPORT_EXTENSION_V1)
    {
        return Ok(());
    }
    Err(OxidraError::Session(format!(
        "read-only session export destination must end with .{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}; this non-journal suffix prevents an archive from being mistaken for a resumable .jsonl session"
    )))
}

fn acquire_lock(layout: &SessionLayout, session_id: &str) -> Result<File> {
    let path = layout.lock_path(session_id)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    private_create_options(&mut options);
    let file = options.open(&path)?;
    enforce_private_file(&path)?;
    file.try_lock_exclusive().map_err(|error| {
        OxidraError::Session(format!(
            "session {session_id} is already open by another writer: {error}"
        ))
    })?;
    Ok(file)
}

/// Writes a complete sibling file before atomically publishing it at
/// `destination` without replacing a racing destination.
///
/// Unix uses hard-link publication followed by temporary-link removal and a
/// parent-directory fsync. Windows has no supported equivalent of fsync on a
/// directory handle, so it uses MoveFileExW without REPLACE_EXISTING and with
/// WRITE_THROUGH, the platform namespace-durability primitive. Filesystems
/// that cannot provide the selected primitive fail closed rather than exposing
/// a partially written destination file.
fn write_new_file_atomically(
    destination: &Path,
    write_contents: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> std::result::Result<(), AtomicNewFileError> {
    let temporary_path =
        destination.with_file_name(format!(".oxidra-session-export-{}.tmp", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_create_options(&mut options);
    let mut output = options
        .open(&temporary_path)
        .map_err(AtomicNewFileError::BeforePublish)?;
    enforce_private_file(&temporary_path).map_err(AtomicNewFileError::BeforePublish)?;
    // Arm cleanup only after create_new proves this invocation owns the path.
    // If a collision ever occurs, we must not remove somebody else's file.
    let cleanup = TemporaryExportFile::new(temporary_path.clone());
    let write_result = write_contents(&mut output).and_then(|()| output.sync_all());
    drop(output);
    write_result.map_err(AtomicNewFileError::BeforePublish)?;

    publish_temporary_export(&temporary_path, destination, cleanup)
}

#[derive(Debug)]
enum AtomicNewFileError {
    BeforePublish(std::io::Error),
    PublishedButDurabilityUncertain(std::io::Error),
}

struct TemporaryExportFile {
    path: Option<PathBuf>,
}

impl TemporaryExportFile {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    #[cfg(not(windows))]
    fn remove(mut self) -> std::io::Result<()> {
        let path = self.path.take().expect("temporary export path is armed");
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Re-arm the Drop fallback for errors where a second removal
                // attempt can still succeed after the handle state settles.
                self.path = Some(path);
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    fn disarm(mut self) {
        self.path.take();
    }
}

impl Drop for TemporaryExportFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(not(windows))]
fn publish_temporary_export(
    temporary_path: &Path,
    destination: &Path,
    cleanup: TemporaryExportFile,
) -> std::result::Result<(), AtomicNewFileError> {
    publish_temporary_export_with_parent_sync(
        temporary_path,
        destination,
        cleanup,
        sync_parent_directory,
    )
}

#[cfg(not(windows))]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(windows))]
fn publish_temporary_export_with_parent_sync(
    temporary_path: &Path,
    destination: &Path,
    cleanup: TemporaryExportFile,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::result::Result<(), AtomicNewFileError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Unlike rename on Unix, hard_link fails rather than replacing an
    // existing destination created by a racing writer.
    fs::hard_link(temporary_path, destination).map_err(AtomicNewFileError::BeforePublish)?;
    cleanup
        .remove()
        .map_err(AtomicNewFileError::PublishedButDurabilityUncertain)?;
    // File fsync does not make either namespace update durable. Flush the
    // containing directory only after both the final link and temporary-link
    // removal have completed.
    sync_parent(parent).map_err(AtomicNewFileError::PublishedButDurabilityUncertain)
}

#[cfg(windows)]
fn publish_temporary_export(
    temporary_path: &Path,
    destination: &Path,
    cleanup: TemporaryExportFile,
) -> std::result::Result<(), AtomicNewFileError> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    // Rust's filesystem APIs add verbatim prefixes for long absolute paths;
    // raw Win32 FFI does not. Canonicalize the existing sibling and its parent
    // so MoveFileExW receives the same long-path-safe form as OpenOptions.
    let temporary_path =
        fs::canonicalize(temporary_path).map_err(AtomicNewFileError::BeforePublish)?;
    let destination_parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let destination_name = destination.file_name().ok_or_else(|| {
        AtomicNewFileError::BeforePublish(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session export destination has no final file name",
        ))
    })?;
    let destination = fs::canonicalize(destination_parent)
        .map_err(AtomicNewFileError::BeforePublish)?
        .join(destination_name);
    let temporary_path: Vec<u16> = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // Deliberately omit MOVEFILE_REPLACE_EXISTING: a racing destination must
    // make publication fail. WRITE_THROUGH waits for the namespace move to be
    // flushed because Windows cannot reliably FlushFileBuffers on a directory
    // handle as Unix can fsync a directory.
    let result = unsafe {
        MoveFileExW(
            temporary_path.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(AtomicNewFileError::BeforePublish(error))
        } else {
            Err(AtomicNewFileError::PublishedButDurabilityUncertain(error))
        };
    }
    cleanup.disarm();
    Ok(())
}

struct JournalScan {
    events: Vec<JournalEvent>,
    json_profile: JournalJsonProfile,
    decode_budget: JournalDecodeBudgetV2,
    valid_len: usize,
    truncated_tail: Option<TruncatedTail>,
    normalized_missing_newline: bool,
}

fn journal_json_profile_from_probe_v2(
    first: Option<JournalJsonProfileProbeV2>,
) -> Result<JournalJsonProfile> {
    let Some(first) = first else {
        return Ok(JournalJsonProfile::LegacyV1);
    };
    if first.kind != SESSION_STARTED_KIND {
        // Structural validation reports the missing header where the caller
        // requires one.  Until then, a prefix without an activation claim is
        // interpreted using the literal historical schema-1 JSON language.
        if matches!(first.claim, JournalJsonProfileClaimPresenceV2::Present(_)) {
            return Err(OxidraError::Session(
                "journal JSON profile claim is only valid on the first session.started event"
                    .to_owned(),
            ));
        }
        return Ok(JournalJsonProfile::LegacyV1);
    }
    match first.claim {
        JournalJsonProfileClaimPresenceV2::Absent => Ok(JournalJsonProfile::LegacyV1),
        JournalJsonProfileClaimPresenceV2::Present(claim) => {
            claim.validate()?;
            Ok(JournalJsonProfile::BoundedV2)
        }
    }
}

fn scan_journal_bytes(bytes: &[u8], session_id: &str) -> Result<JournalScan> {
    let last_newline = bytes.iter().rposition(|byte| *byte == b'\n');
    let complete_len = last_newline.map_or(0, |position| position + 1);
    let tail = &bytes[complete_len..];
    let mut truncated_tail = None;
    let mut normalized_missing_newline = false;

    let valid_len = if tail.is_empty() {
        bytes.len()
    } else if journal_tail_is_lexically_incomplete_v1(tail) {
        // Lexical EOF is only a necessary condition for crash debris.  Before
        // truncating, require a concrete completion witness that the frozen
        // JSON/profile/envelope reader accepts.  Otherwise a malformed prefix
        // such as an out-of-range number, lone surrogate, or unsupported
        // schema would be silently deleted merely because a closing brace is
        // absent.
        if journal_tail_has_accepted_completion_v1(bytes, complete_len, session_id)? {
            truncated_tail = Some(TruncatedTail {
                byte_count: u64::try_from(tail.len()).map_err(|_| {
                    OxidraError::Session("incomplete journal tail is too large".to_owned())
                })?,
                sha256: hex::encode(Sha256::digest(tail)),
            });
            complete_len
        } else {
            // Preserve the exact bytes and let the normal reader reject them.
            // A semantic/encoding failure is not crash debris just because the
            // hand-written lexer reached EOF in an open JSON construct.
            bytes.len()
        }
    } else {
        // A complete record, or a record that is already syntactically invalid
        // rather than a valid JSON prefix, is never crash debris merely
        // because the versioned JSON/profile/protocol reader rejects it.
        // Preserve those bytes and fail closed instead of silently truncating
        // a malicious durable record.
        normalized_missing_newline = true;
        bytes.len()
    };

    // An empty complete prefix is meaningful to the read-only export path: it
    // must be able to preserve the exact bytes of a creation crash even though
    // no resumable journal can be derived from it.  `scan_and_repair_tail`
    // rejects this state before any mutation, and `SessionStore::open` applies
    // the same non-empty/first-header invariant below.
    let (events, json_profile, decode_budget) = if valid_len == 0 {
        (
            Vec::new(),
            JournalJsonProfile::LegacyV1,
            JournalDecodeBudgetV2::default(),
        )
    } else {
        parse_complete_events_with_budget_v2(&bytes[..valid_len], session_id)?
    };
    Ok(JournalScan {
        events,
        json_profile,
        decode_budget,
        valid_len,
        truncated_tail,
        normalized_missing_newline,
    })
}

/// Lossless administrative export is permitted to preserve a final record
/// that is not repairable.  Only the newline-terminated prefix is reduced; the
/// exact remaining bytes stay classified as evidence and are never mutated.
fn scan_journal_bytes_for_export_v1(bytes: &[u8], session_id: &str) -> Result<JournalScan> {
    let last_newline = bytes.iter().rposition(|byte| *byte == b'\n');
    let valid_len = last_newline.map_or(0, |position| position + 1);
    let tail = &bytes[valid_len..];
    let (events, json_profile, decode_budget) = if valid_len == 0 {
        (
            Vec::new(),
            JournalJsonProfile::LegacyV1,
            JournalDecodeBudgetV2::default(),
        )
    } else {
        parse_complete_events_with_budget_v2(&bytes[..valid_len], session_id)?
    };
    let truncated_tail = if tail.is_empty() {
        None
    } else {
        Some(TruncatedTail {
            byte_count: u64::try_from(tail.len())
                .map_err(|_| OxidraError::Session("journal export tail is too large".to_owned()))?,
            sha256: hex::encode(Sha256::digest(tail)),
        })
    };
    Ok(JournalScan {
        events,
        json_profile,
        decode_budget,
        valid_len,
        truncated_tail,
        normalized_missing_newline: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalTailSyntaxV1 {
    Complete,
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonObjectStateV1 {
    FirstKeyOrEnd,
    KeyAfterComma,
    Colon,
    Value,
    CommaOrEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonArrayStateV1 {
    FirstValueOrEnd,
    ValueAfterComma,
    CommaOrEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonContainerV1 {
    Object(JournalJsonObjectStateV1),
    Array(JournalJsonArrayStateV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonRootStateV1 {
    Value,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonTokenV1 {
    Complete(usize),
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalJsonExpectationV1 {
    RootValue,
    RootDone,
    ObjectFirstKeyOrEnd,
    ObjectKeyAfterComma,
    ObjectColon,
    ObjectValue,
    ObjectCommaOrEnd,
    ArrayFirstValueOrEnd,
    ArrayValueAfterComma,
    ArrayCommaOrEnd,
}

/// Classify the final physical record as a complete JSON object, a
/// syntactically valid prefix of one, or already-invalid input.  This parser is
/// iterative and never materializes a JSON tree, so a deep but genuinely
/// unfinished crash tail cannot be hidden by the bounded reader's depth error.
/// Conversely, an invalid open container (for example `{"data":!`) is not
/// silently truncated merely because its closing brace is absent.
fn journal_tail_syntax_v1(bytes: &[u8]) -> JournalTailSyntaxV1 {
    let mut containers = Vec::<JournalJsonContainerV1>::new();
    let mut root = JournalJsonRootStateV1::Value;
    let mut index = 0usize;

    loop {
        while index < bytes.len() && is_journal_json_whitespace_v1(bytes[index]) {
            index += 1;
        }

        let expectation = match containers.last().copied() {
            Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::FirstKeyOrEnd)) => {
                JournalJsonExpectationV1::ObjectFirstKeyOrEnd
            }
            Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma)) => {
                JournalJsonExpectationV1::ObjectKeyAfterComma
            }
            Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon)) => {
                JournalJsonExpectationV1::ObjectColon
            }
            Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value)) => {
                JournalJsonExpectationV1::ObjectValue
            }
            Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::CommaOrEnd)) => {
                JournalJsonExpectationV1::ObjectCommaOrEnd
            }
            Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::FirstValueOrEnd)) => {
                JournalJsonExpectationV1::ArrayFirstValueOrEnd
            }
            Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma)) => {
                JournalJsonExpectationV1::ArrayValueAfterComma
            }
            Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::CommaOrEnd)) => {
                JournalJsonExpectationV1::ArrayCommaOrEnd
            }
            None if root == JournalJsonRootStateV1::Value => JournalJsonExpectationV1::RootValue,
            None => JournalJsonExpectationV1::RootDone,
        };

        if index == bytes.len() {
            return if expectation == JournalJsonExpectationV1::RootDone {
                JournalTailSyntaxV1::Complete
            } else {
                JournalTailSyntaxV1::Incomplete
            };
        }

        match expectation {
            JournalJsonExpectationV1::RootDone => return JournalTailSyntaxV1::Invalid,
            JournalJsonExpectationV1::RootValue => {
                // A journal record is always a JSON object. Treat an array or
                // scalar prefix as invalid rather than recoverable debris.
                if bytes[index] != b'{' {
                    return JournalTailSyntaxV1::Invalid;
                }
                if containers.len() == MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1 {
                    return JournalTailSyntaxV1::Invalid;
                }
                containers.push(JournalJsonContainerV1::Object(
                    JournalJsonObjectStateV1::FirstKeyOrEnd,
                ));
                index += 1;
            }
            JournalJsonExpectationV1::ObjectFirstKeyOrEnd => match bytes[index] {
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return JournalTailSyntaxV1::Invalid;
                    }
                }
                b'"' => match scan_journal_json_string_v1(bytes, index) {
                    JournalJsonTokenV1::Complete(next) => {
                        *containers.last_mut().expect("object frame") =
                            JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon);
                        index = next;
                    }
                    JournalJsonTokenV1::Incomplete => return JournalTailSyntaxV1::Incomplete,
                    JournalJsonTokenV1::Invalid => return JournalTailSyntaxV1::Invalid,
                },
                _ => return JournalTailSyntaxV1::Invalid,
            },
            JournalJsonExpectationV1::ObjectKeyAfterComma => {
                if bytes[index] != b'"' {
                    return JournalTailSyntaxV1::Invalid;
                }
                match scan_journal_json_string_v1(bytes, index) {
                    JournalJsonTokenV1::Complete(next) => {
                        *containers.last_mut().expect("object frame") =
                            JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon);
                        index = next;
                    }
                    JournalJsonTokenV1::Incomplete => return JournalTailSyntaxV1::Incomplete,
                    JournalJsonTokenV1::Invalid => return JournalTailSyntaxV1::Invalid,
                }
            }
            JournalJsonExpectationV1::ObjectColon => {
                if bytes[index] != b':' {
                    return JournalTailSyntaxV1::Invalid;
                }
                *containers.last_mut().expect("object frame") =
                    JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value);
                index += 1;
            }
            JournalJsonExpectationV1::ObjectValue
            | JournalJsonExpectationV1::ArrayValueAfterComma => {
                match consume_journal_json_value_v1(bytes, index, &mut containers, &mut root) {
                    JournalJsonTokenV1::Complete(next) => index = next,
                    JournalJsonTokenV1::Incomplete => return JournalTailSyntaxV1::Incomplete,
                    JournalJsonTokenV1::Invalid => return JournalTailSyntaxV1::Invalid,
                }
            }
            JournalJsonExpectationV1::ObjectCommaOrEnd => match bytes[index] {
                b',' => {
                    *containers.last_mut().expect("object frame") =
                        JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma);
                    index += 1;
                }
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return JournalTailSyntaxV1::Invalid;
                    }
                }
                _ => return JournalTailSyntaxV1::Invalid,
            },
            JournalJsonExpectationV1::ArrayFirstValueOrEnd => {
                if bytes[index] == b']' {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return JournalTailSyntaxV1::Invalid;
                    }
                } else {
                    match consume_journal_json_value_v1(bytes, index, &mut containers, &mut root) {
                        JournalJsonTokenV1::Complete(next) => index = next,
                        JournalJsonTokenV1::Incomplete => {
                            return JournalTailSyntaxV1::Incomplete;
                        }
                        JournalJsonTokenV1::Invalid => return JournalTailSyntaxV1::Invalid,
                    }
                }
            }
            JournalJsonExpectationV1::ArrayCommaOrEnd => match bytes[index] {
                b',' => {
                    *containers.last_mut().expect("array frame") =
                        JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma);
                    index += 1;
                }
                b']' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return JournalTailSyntaxV1::Invalid;
                    }
                }
                _ => return JournalTailSyntaxV1::Invalid,
            },
        }
    }
}

fn journal_tail_is_lexically_incomplete_v1(bytes: &[u8]) -> bool {
    journal_tail_syntax_v1(bytes) == JournalTailSyntaxV1::Incomplete
}

fn journal_tail_completion_witness_v1(
    tail: &[u8],
    session_id: &str,
    next_seq: u64,
    template: Option<&ProviderContextLimitRecoveryAction>,
) -> Option<Vec<u8>> {
    let mut candidate = tail.to_vec();
    let mut containers = Vec::<JournalJsonContainerV1>::new();
    let mut root = JournalJsonRootStateV1::Value;
    let mut root_keys = HashSet::<String>::new();
    let mut pending_root_key = None::<String>;
    // The bounded writer serializes nested maps in key order. Preserve the
    // last durable key at each active container depth when selecting a
    // synthetic continuation; prematurely closing a prefix of that key
    // would move the new key backwards during canonical re-encoding.
    let mut last_nested_keys = Vec::<Option<String>>::new();
    let mut index = 0usize;

    loop {
        last_nested_keys.resize_with(containers.len(), || None);
        while index < candidate.len() && is_journal_json_whitespace_v1(candidate[index]) {
            index += 1;
        }
        let expectation = journal_json_expectation_v1(&containers, root);
        if index == candidate.len() {
            match expectation {
                JournalJsonExpectationV1::RootValue => return None,
                JournalJsonExpectationV1::RootDone => return Some(candidate),
                JournalJsonExpectationV1::ObjectFirstKeyOrEnd
                | JournalJsonExpectationV1::ObjectKeyAfterComma => {
                    if containers.len() == 1 {
                        append_missing_journal_envelope_v1(
                            &mut candidate,
                            &root_keys,
                            session_id,
                            next_seq,
                            false,
                            template,
                        );
                    } else {
                        let key = last_nested_keys
                            .last()
                            .and_then(Option::as_deref)
                            .map_or_else(|| "x".to_owned(), |previous| format!("{previous}x"));
                        candidate.extend_from_slice(&serde_json::to_vec(&key).ok()?);
                        candidate.extend_from_slice(b":null");
                    }
                }
                JournalJsonExpectationV1::ObjectColon => {
                    candidate.push(b':');
                    append_journal_envelope_default_value_v1(
                        &mut candidate,
                        pending_root_key.as_deref(),
                        session_id,
                        next_seq,
                        template,
                    );
                }
                JournalJsonExpectationV1::ObjectValue => {
                    append_journal_envelope_default_value_v1(
                        &mut candidate,
                        pending_root_key.as_deref(),
                        session_id,
                        next_seq,
                        template,
                    );
                }
                JournalJsonExpectationV1::ObjectCommaOrEnd => {
                    if containers.len() == 1 {
                        append_missing_journal_envelope_v1(
                            &mut candidate,
                            &root_keys,
                            session_id,
                            next_seq,
                            true,
                            template,
                        );
                    } else {
                        candidate.push(b'}');
                    }
                }
                JournalJsonExpectationV1::ArrayFirstValueOrEnd
                | JournalJsonExpectationV1::ArrayValueAfterComma => {
                    candidate.extend_from_slice(b"null")
                }
                JournalJsonExpectationV1::ArrayCommaOrEnd => candidate.push(b']'),
            }
            continue;
        }

        match expectation {
            JournalJsonExpectationV1::RootDone => return None,
            JournalJsonExpectationV1::RootValue => {
                if candidate[index] != b'{' || containers.len() == MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1
                {
                    return None;
                }
                containers.push(JournalJsonContainerV1::Object(
                    JournalJsonObjectStateV1::FirstKeyOrEnd,
                ));
                index += 1;
            }
            JournalJsonExpectationV1::ObjectFirstKeyOrEnd
            | JournalJsonExpectationV1::ObjectKeyAfterComma => match candidate[index] {
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return None;
                    }
                }
                b'"' => {
                    let key_start = index;
                    match scan_journal_json_string_v1(&candidate, index) {
                        JournalJsonTokenV1::Complete(next) => {
                            let key = serde_json::from_slice::<String>(&candidate[key_start..next])
                                .ok()?;
                            if containers.len() == 1 {
                                root_keys.insert(key.clone());
                                pending_root_key = Some(key);
                            } else {
                                *last_nested_keys.last_mut()? = Some(key);
                            }
                            *containers.last_mut().expect("object frame") =
                                JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon);
                            index = next;
                        }
                        JournalJsonTokenV1::Incomplete => {
                            let previous = if containers.len() > 1 {
                                last_nested_keys.last().and_then(Option::as_deref)
                            } else {
                                None
                            };
                            candidate.extend_from_slice(&journal_key_completion_suffix_v1(
                                &candidate, index, previous,
                            )?);
                        }
                        JournalJsonTokenV1::Invalid => return None,
                    }
                }
                _ => return None,
            },
            JournalJsonExpectationV1::ObjectColon => {
                if candidate[index] != b':' {
                    return None;
                }
                *containers.last_mut().expect("object frame") =
                    JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value);
                index += 1;
            }
            JournalJsonExpectationV1::ObjectValue
            | JournalJsonExpectationV1::ArrayValueAfterComma => {
                // A decimal sequence at EOF is an ambiguous JSON prefix: the
                // writer may have torn the record after any leading digit
                // (for example "seq":1 while the durable value is 12).
                // Extend it to the exact next sequence before handing the
                // bytes to the state machine; consuming 1 first would mark
                // the scalar complete and leave the appended digit in an
                // object-comma state.
                if containers.len() == 1
                    && pending_root_key.as_deref() == Some("seq")
                    && candidate[index].is_ascii_digit()
                {
                    if let Some(suffix) =
                        journal_seq_completion_suffix_v1(&candidate, index, next_seq)
                    {
                        candidate.extend_from_slice(&suffix);
                        continue;
                    }
                }
                match consume_journal_json_value_v1(&candidate, index, &mut containers, &mut root) {
                    JournalJsonTokenV1::Complete(next) => index = next,
                    JournalJsonTokenV1::Incomplete => {
                        candidate.extend_from_slice(&journal_envelope_value_completion_suffix_v1(
                            &candidate,
                            index,
                            if containers.len() == 1 {
                                pending_root_key.as_deref()
                            } else {
                                None
                            },
                            session_id,
                            next_seq,
                            template,
                        )?)
                    }
                    JournalJsonTokenV1::Invalid => return None,
                }
            }
            JournalJsonExpectationV1::ObjectCommaOrEnd => match candidate[index] {
                b',' => {
                    *containers.last_mut().expect("object frame") =
                        JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma);
                    index += 1;
                }
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return None;
                    }
                }
                _ => return None,
            },
            JournalJsonExpectationV1::ArrayFirstValueOrEnd => {
                if candidate[index] == b']' {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return None;
                    }
                } else {
                    match consume_journal_json_value_v1(
                        &candidate,
                        index,
                        &mut containers,
                        &mut root,
                    ) {
                        JournalJsonTokenV1::Complete(next) => index = next,
                        JournalJsonTokenV1::Incomplete => candidate.extend_from_slice(
                            &journal_value_completion_suffix_v1(&candidate, index)?,
                        ),
                        JournalJsonTokenV1::Invalid => return None,
                    }
                }
            }
            JournalJsonExpectationV1::ArrayCommaOrEnd => match candidate[index] {
                b',' => {
                    *containers.last_mut().expect("array frame") =
                        JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma);
                    index += 1;
                }
                b']' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return None;
                    }
                }
                _ => return None,
            },
        }
    }
}

fn journal_json_expectation_v1(
    containers: &[JournalJsonContainerV1],
    root: JournalJsonRootStateV1,
) -> JournalJsonExpectationV1 {
    match containers.last().copied() {
        Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::FirstKeyOrEnd)) => {
            JournalJsonExpectationV1::ObjectFirstKeyOrEnd
        }
        Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma)) => {
            JournalJsonExpectationV1::ObjectKeyAfterComma
        }
        Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon)) => {
            JournalJsonExpectationV1::ObjectColon
        }
        Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value)) => {
            JournalJsonExpectationV1::ObjectValue
        }
        Some(JournalJsonContainerV1::Object(JournalJsonObjectStateV1::CommaOrEnd)) => {
            JournalJsonExpectationV1::ObjectCommaOrEnd
        }
        Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::FirstValueOrEnd)) => {
            JournalJsonExpectationV1::ArrayFirstValueOrEnd
        }
        Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma)) => {
            JournalJsonExpectationV1::ArrayValueAfterComma
        }
        Some(JournalJsonContainerV1::Array(JournalJsonArrayStateV1::CommaOrEnd)) => {
            JournalJsonExpectationV1::ArrayCommaOrEnd
        }
        None if root == JournalJsonRootStateV1::Value => JournalJsonExpectationV1::RootValue,
        None => JournalJsonExpectationV1::RootDone,
    }
}

fn append_missing_journal_envelope_v1(
    candidate: &mut Vec<u8>,
    root_keys: &HashSet<String>,
    session_id: &str,
    next_seq: u64,
    leading_comma: bool,
    template: Option<&ProviderContextLimitRecoveryAction>,
) {
    let session_id = serde_json::to_string(session_id).unwrap_or_else(|_| "\"recovered\"".into());
    let fields = [
        ("schema", format!("\"schema\":{JOURNAL_SCHEMA}")),
        ("seq", format!("\"seq\":{next_seq}")),
        ("ts", "\"ts\":\"1970-01-01T00:00:00Z\"".to_owned()),
        (
            "kind",
            format!(
                "\"kind\":{}",
                serde_json::to_string(
                    template
                        .map(|_| "context.limit_reached")
                        .unwrap_or("custom.recovered")
                )
                .unwrap_or_else(|_| "\"custom.recovered\"".to_owned())
            ),
        ),
        ("session_id", format!("\"session_id\":{session_id}")),
        (
            "turn_id",
            match template {
                Some(action) => format!(
                    "\"turn_id\":{}",
                    serde_json::to_string(&action.turn_id).unwrap()
                ),
                None => "\"turn_id\":null".to_owned(),
            },
        ),
        (
            "data",
            match template {
                Some(action) => {
                    format!("\"data\":{}", serde_json::to_string(&action.data).unwrap())
                }
                None => "\"data\":{}".to_owned(),
            },
        ),
    ];
    let mut wrote_field = false;
    for (key, field) in fields {
        if root_keys.contains(key) {
            continue;
        }
        if wrote_field || leading_comma {
            candidate.push(b',');
        }
        candidate.extend_from_slice(field.as_bytes());
        wrote_field = true;
    }
    candidate.push(b'}');
}

fn append_journal_envelope_default_value_v1(
    candidate: &mut Vec<u8>,
    key: Option<&str>,
    session_id: &str,
    next_seq: u64,
    template: Option<&ProviderContextLimitRecoveryAction>,
) {
    match key {
        Some("schema") => candidate.extend_from_slice(JOURNAL_SCHEMA.to_string().as_bytes()),
        Some("seq") => candidate.extend_from_slice(next_seq.to_string().as_bytes()),
        Some("ts") => candidate.extend_from_slice(br#""1970-01-01T00:00:00Z""#),
        Some("kind") => candidate.extend_from_slice(
            serde_json::to_string(
                template
                    .map(|_| "context.limit_reached")
                    .unwrap_or("custom.recovered"),
            )
            .unwrap()
            .as_bytes(),
        ),
        Some("session_id") => candidate.extend_from_slice(
            serde_json::to_string(session_id)
                .unwrap_or_else(|_| "\"recovered\"".to_owned())
                .as_bytes(),
        ),
        Some("turn_id") => match template {
            Some(action) => candidate
                .extend_from_slice(serde_json::to_string(&action.turn_id).unwrap().as_bytes()),
            None => candidate.extend_from_slice(b"null"),
        },
        Some("data") => match template {
            Some(action) => {
                candidate.extend_from_slice(serde_json::to_string(&action.data).unwrap().as_bytes())
            }
            None => candidate.extend_from_slice(b"{}"),
        },
        None | Some(_) => candidate.extend_from_slice(b"{}"),
    }
}

fn journal_envelope_value_completion_suffix_v1(
    bytes: &[u8],
    index: usize,
    key: Option<&str>,
    session_id: &str,
    next_seq: u64,
    template: Option<&ProviderContextLimitRecoveryAction>,
) -> Option<Vec<u8>> {
    if matches!(key, Some("schema" | "seq")) {
        return journal_number_completion_suffix_v1(bytes, index);
    }
    if bytes.get(index) == Some(&b'"') {
        if key == Some("ts") {
            return journal_timestamp_completion_suffix_v1(bytes, index);
        }
        if key == Some("session_id") {
            return journal_string_exact_value_completion_suffix_v1(bytes, index, session_id);
        }
        if key == Some("kind") && bytes.len() == index + 1 {
            let kind = template
                .map(|_| "context.limit_reached")
                .unwrap_or("custom.recovered");
            return Some(format!("{kind}\"").into_bytes());
        }
        if key == Some("kind") {
            let prefix = bytes.get(index + 1..)?;
            let target = template.map(|_| b"context.limit_reached".as_slice());
            if target.is_some_and(|target| target.starts_with(prefix)) {
                let target = target.expect("template target");
                let mut suffix = target[prefix.len()..].to_vec();
                suffix.push(b'"');
                return Some(suffix);
            }
        }
        return journal_string_completion_suffix_v1(bytes, index);
    }
    if index == bytes.len() {
        let mut suffix = Vec::new();
        append_journal_envelope_default_value_v1(&mut suffix, key, session_id, next_seq, template);
        return Some(suffix);
    }
    journal_value_completion_suffix_v1(bytes, index)
}

fn journal_string_exact_value_completion_suffix_v1(
    bytes: &[u8],
    index: usize,
    target: &str,
) -> Option<Vec<u8>> {
    let prefix = bytes.get(index + 1..)?;
    if !target.as_bytes().starts_with(prefix) {
        return journal_string_completion_suffix_v1(bytes, index);
    }
    let mut suffix = target.as_bytes()[prefix.len()..].to_vec();
    suffix.push(b'"');
    Some(suffix)
}

/// Return the suffix needed to complete a torn `seq` value to the exact
/// sequence that the next journal event must carry. A complete value (or a
/// non-prefix) deliberately returns `None`; only an ambiguous decimal prefix
/// is extended here.
fn journal_seq_completion_suffix_v1(bytes: &[u8], index: usize, next_seq: u64) -> Option<Vec<u8>> {
    let prefix = bytes.get(index..)?;
    if prefix.is_empty() || !prefix.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let target = next_seq.to_string();
    if prefix.len() >= target.len() || !target.as_bytes().starts_with(prefix) {
        return None;
    }
    Some(target.as_bytes()[prefix.len()..].to_vec())
}

/// Complete a torn timestamp using the same RFC3339/chrono representation as
/// the journal writer. The old implementation used one fixed epoch value,
/// which rejected perfectly valid prefixes such as `"2026`. We try only
/// bounded grammar suffixes, parse each candidate, and finally require the
/// serializer's canonical bytes to preserve the exact durable prefix. Thus
/// this is inference of an existing writer value, not normalization of an
/// arbitrary string.
fn journal_timestamp_completion_suffix_v1(bytes: &[u8], index: usize) -> Option<Vec<u8>> {
    let raw = bytes.get(index..)?;
    if raw.first() != Some(&b'"') {
        return None;
    }
    let prefix_bytes = raw.get(1..)?;
    if prefix_bytes
        .iter()
        .any(|byte| *byte < 0x20 || matches!(*byte, b'"' | b'\\') || !byte.is_ascii())
    {
        return None;
    }
    let prefix = std::str::from_utf8(prefix_bytes).ok()?;

    for candidate_text in journal_timestamp_candidate_texts_v1(prefix) {
        let parsed = match DateTime::parse_from_rfc3339(&candidate_text) {
            Ok(value) => value.with_timezone(&Utc),
            Err(_) => continue,
        };
        let canonical = serde_json::to_vec(&parsed).ok()?;
        if canonical.starts_with(raw) && canonical.len() > raw.len() {
            return Some(canonical[raw.len()..].to_vec());
        }
    }
    None
}

fn timestamp_component_completion_v1(
    prefix: &[u8],
    cursor: &mut usize,
    width: usize,
    minimum: u32,
    maximum: u32,
    default: &'static str,
) -> Option<String> {
    if *cursor == prefix.len() {
        return Some(default.to_owned());
    }
    let remaining = &prefix[*cursor..];
    let present = remaining.len().min(width);
    if !remaining[..present]
        .iter()
        .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    if remaining.len() < width {
        for value in minimum..=maximum {
            let candidate = format!("{value:0width$}");
            if candidate.as_bytes().starts_with(remaining) {
                *cursor = prefix.len();
                return Some(candidate);
            }
        }
        return None;
    }
    let value = std::str::from_utf8(&remaining[..width])
        .ok()?
        .parse::<u32>()
        .ok()?;
    if !(minimum..=maximum).contains(&value) {
        return None;
    }
    *cursor += width;
    Some(format!("{value:0width$}"))
}

/// Construct bounded RFC3339 candidates for every lexical position in a
/// timestamp. Numeric components are completed with the smallest value whose
/// fixed-width representation has the durable bytes as a prefix; the final
/// canonical serializer check rejects any value that chrono would normalize.
fn timestamp_delimiter_completion_v1(
    prefix: &[u8],
    cursor: &mut usize,
    delimiter: u8,
) -> Option<()> {
    if *cursor == prefix.len() {
        return Some(());
    }
    if prefix[*cursor] != delimiter {
        return None;
    }
    *cursor += 1;
    Some(())
}

fn journal_timestamp_candidate_texts_v1(prefix: &str) -> Vec<String> {
    let bytes = prefix.as_bytes();
    let mut cursor = 0usize;
    let Some(year) = timestamp_component_completion_v1(bytes, &mut cursor, 4, 1, 9_999, "1970")
    else {
        return Vec::new();
    };
    let mut base = year;
    if timestamp_delimiter_completion_v1(bytes, &mut cursor, b'-').is_none() {
        return Vec::new();
    }
    base.push('-');
    let Some(month) = timestamp_component_completion_v1(bytes, &mut cursor, 2, 1, 12, "01") else {
        return Vec::new();
    };
    base.push_str(&month);
    if timestamp_delimiter_completion_v1(bytes, &mut cursor, b'-').is_none() {
        return Vec::new();
    }
    base.push('-');
    let Some(day) = timestamp_component_completion_v1(bytes, &mut cursor, 2, 1, 31, "01") else {
        return Vec::new();
    };
    base.push_str(&day);
    if timestamp_delimiter_completion_v1(bytes, &mut cursor, b'T').is_none() {
        return Vec::new();
    }
    base.push('T');
    let Some(hour) = timestamp_component_completion_v1(bytes, &mut cursor, 2, 0, 23, "00") else {
        return Vec::new();
    };
    base.push_str(&hour);
    if timestamp_delimiter_completion_v1(bytes, &mut cursor, b':').is_none() {
        return Vec::new();
    }
    base.push(':');
    let Some(minute) = timestamp_component_completion_v1(bytes, &mut cursor, 2, 0, 59, "00") else {
        return Vec::new();
    };
    base.push_str(&minute);
    if timestamp_delimiter_completion_v1(bytes, &mut cursor, b':').is_none() {
        return Vec::new();
    }
    base.push(':');
    let Some(second) = timestamp_component_completion_v1(bytes, &mut cursor, 2, 0, 59, "00") else {
        return Vec::new();
    };
    base.push_str(&second);

    if cursor == bytes.len() {
        return vec![format!("{base}Z")];
    }
    if bytes[cursor] == b'Z' {
        if cursor + 1 != bytes.len() {
            return Vec::new();
        }
        return vec![format!("{base}Z")];
    }
    if bytes[cursor] != b'.' {
        return Vec::new();
    }
    let remainder = &bytes[cursor + 1..];
    let (fraction, _) = match remainder.iter().position(|byte| *byte == b'Z') {
        Some(zone) if zone + 1 == remainder.len() => (&remainder[..zone], true),
        Some(_) => return Vec::new(),
        None => (remainder, false),
    };
    if fraction.len() > 9 || !fraction.iter().all(|byte| byte.is_ascii_digit()) {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    for width in [3usize, 6, 9] {
        if fraction.len() <= width {
            let Ok(mut value) = String::from_utf8(fraction.to_vec()) else {
                return Vec::new();
            };
            value.push_str(&"0".repeat(width - fraction.len()));
            // AutoSi omits zero fractions AND trailing zero groups, e.g.
            // .123000 becomes .123. An unwritten non-zero final digit keeps
            // the chosen precision without changing any durable prefix byte.
            // The canonical-byte check still rejects already-terminated
            // noncanonical fractions such as .123000Z.
            if fraction.len() < width {
                value.replace_range(width - 1.., "1");
            }
            candidates.push(format!("{base}.{value}Z"));
        }
    }
    candidates
}

fn journal_value_completion_suffix_v1(bytes: &[u8], index: usize) -> Option<Vec<u8>> {
    match bytes.get(index).copied()? {
        b'"' => journal_string_completion_suffix_v1(bytes, index),
        b't' => journal_literal_completion_suffix_v1(bytes, index, b"true"),
        b'f' => journal_literal_completion_suffix_v1(bytes, index, b"false"),
        b'n' => journal_literal_completion_suffix_v1(bytes, index, b"null"),
        b'-' | b'0'..=b'9' => journal_number_completion_suffix_v1(bytes, index),
        _ => None,
    }
}

fn journal_literal_completion_suffix_v1(
    bytes: &[u8],
    index: usize,
    literal: &[u8],
) -> Option<Vec<u8>> {
    let available = bytes.len().checked_sub(index)?;
    if available >= literal.len() || bytes[index..] != literal[..available] {
        return None;
    }
    Some(literal[available..].to_vec())
}

fn journal_number_completion_suffix_v1(bytes: &[u8], index: usize) -> Option<Vec<u8>> {
    let tail = &bytes[index..];
    if tail == b"-"
        || tail.ends_with(b".")
        || tail.ends_with(b"e")
        || tail.ends_with(b"E")
        || tail.ends_with(b"e+")
        || tail.ends_with(b"e-")
        || tail.ends_with(b"E+")
        || tail.ends_with(b"E-")
    {
        Some(b"0".to_vec())
    } else {
        None
    }
}

/// Select a nested-key continuation compatible with the bounded writer's
/// sorted map encoding. Never edit the durable key prefix; the completed
/// event still has to pass exact re-encoding and all recovery checks.
fn journal_key_completion_suffix_v1(
    bytes: &[u8],
    index: usize,
    previous: Option<&str>,
) -> Option<Vec<u8>> {
    let mut suffix = journal_string_completion_suffix_v1(bytes, index)?;
    let Some(previous) = previous else {
        return Some(suffix);
    };
    let mut encoded_key = bytes.get(index..)?.to_vec();
    encoded_key.extend_from_slice(&suffix);
    if !matches!(
        scan_journal_json_string_v1(&encoded_key, 0),
        JournalJsonTokenV1::Complete(_)
    ) {
        // A surrogate continuation may need another scanner iteration before
        // the quote is appended. Keep the suffix append-only in that case.
        return Some(suffix);
    }
    let key: String = serde_json::from_slice(&encoded_key).ok()?;
    if key.as_str() <= previous {
        let remaining = previous.strip_prefix(&key)?;
        if suffix.pop()? != b'"' {
            return None;
        }
        let extension = serde_json::to_vec(&format!("{remaining}x")).ok()?;
        suffix.extend_from_slice(&extension[1..]);
    }
    Some(suffix)
}

fn journal_string_completion_suffix_v1(bytes: &[u8], index: usize) -> Option<Vec<u8>> {
    let mut cursor = index.checked_add(1)?;
    // JSON permits a UTF-16 surrogate pair only when a high surrogate is
    // immediately followed by a low-surrogate escape.  serde_json rejects a
    // lone high surrogate, so a syntactically open string ending after
    // `\uD800` still has an accepted completion, but it must append a low
    // surrogate rather than merely a closing quote.
    let mut pending_high_surrogate = false;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => return None,
            b'\\' => {
                cursor += 1;
                let Some(&escape) = bytes.get(cursor) else {
                    return Some(if pending_high_surrogate {
                        br#"uDC00""#.to_vec()
                    } else {
                        br#"u0000""#.to_vec()
                    });
                };
                match escape {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        if pending_high_surrogate {
                            return None;
                        }
                        cursor += 1;
                    }
                    b'u' => {
                        cursor += 1;
                        let start = cursor;
                        while cursor < bytes.len() && cursor - start < 4 {
                            if !bytes[cursor].is_ascii_hexdigit() {
                                return None;
                            }
                            cursor += 1;
                        }
                        let digits = &bytes[start..cursor];
                        if digits.len() < 4 {
                            return unicode_escape_completion_suffix_v1(
                                digits,
                                pending_high_surrogate,
                            );
                        }
                        let code_unit = parse_unicode_escape_code_unit_v1(digits)?;
                        if pending_high_surrogate {
                            if !(0xdc00..=0xdfff).contains(&code_unit) {
                                return None;
                            }
                            pending_high_surrogate = false;
                        } else if (0xd800..=0xdbff).contains(&code_unit) {
                            pending_high_surrogate = true;
                        } else if (0xdc00..=0xdfff).contains(&code_unit) {
                            return None;
                        }
                    }
                    _ => return None,
                }
            }
            0x00..=0x1f | 0x80..=0xbf => return None,
            0xc2..=0xf4 => {
                if pending_high_surrogate {
                    return None;
                }
                let leading = bytes[cursor];
                let width = if leading <= 0xdf {
                    2
                } else if leading <= 0xef {
                    3
                } else {
                    4
                };
                let available = bytes.len() - cursor;
                let present = available.min(width);
                if !valid_utf8_prefix_v1(&bytes[cursor..cursor + present], width) {
                    return None;
                }
                if available < width {
                    let mut suffix = Vec::with_capacity(width - available + 1);
                    for offset in available..width {
                        suffix.push(if offset == 1 {
                            match leading {
                                0xe0 => 0xa0,
                                0xed => 0x80,
                                0xf0 => 0x90,
                                0xf4 => 0x80,
                                _ => 0x80,
                            }
                        } else {
                            0x80
                        });
                    }
                    suffix.push(b'"');
                    return Some(suffix);
                }
                cursor += width;
            }
            0x20..=0x7f => {
                if pending_high_surrogate {
                    return None;
                }
                cursor += 1;
            }
            _ => return None,
        }
    }
    if pending_high_surrogate {
        Some(br#"\uDC00"#.to_vec())
    } else {
        Some(vec![b'"'])
    }
}

fn parse_unicode_escape_code_unit_v1(digits: &[u8]) -> Option<u16> {
    if digits.len() != 4 {
        return None;
    }
    digits.iter().try_fold(0u16, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        Some((value << 4) | u16::from(digit))
    })
}

fn unicode_escape_completion_suffix_v1(
    digits: &[u8],
    require_low_surrogate: bool,
) -> Option<Vec<u8>> {
    if digits.len() > 4 {
        return None;
    }
    let prefix = digits.iter().try_fold(0u16, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        Some((value << 4) | u16::from(digit))
    })?;
    let missing = 4usize.checked_sub(digits.len())?;
    let combinations = 1u32.checked_shl(u32::try_from(missing * 4).ok()?)?;
    for suffix_value in 0..combinations {
        // Shift in a widened type: an empty digit prefix means `missing == 4`
        // and shifting a `u16` by 16 is an overflow in debug builds.  A
        // malformed crash tail must fail closed, never panic the opener.
        let code_unit = u16::try_from((u32::from(prefix) << (missing * 4)) | suffix_value).ok()?;
        let is_high = (0xd800..=0xdbff).contains(&code_unit);
        let is_low = (0xdc00..=0xdfff).contains(&code_unit);
        if require_low_surrogate {
            if !is_low {
                continue;
            }
        } else if is_low {
            continue;
        }
        let mut suffix = Vec::with_capacity(missing + if is_high { 7 } else { 1 });
        for shift in (0..missing).rev() {
            let nibble = ((suffix_value >> (shift * 4)) & 0xf) as u8;
            suffix.push(match nibble {
                0..=9 => b'0' + nibble,
                _ => b'a' + nibble - 10,
            });
        }
        if is_high {
            suffix.extend_from_slice(br#"\uDC00"#);
        } else {
            suffix.push(b'"');
        }
        return Some(suffix);
    }
    None
}

fn valid_utf8_prefix_v1(bytes: &[u8], width: usize) -> bool {
    if bytes.is_empty() || bytes.len() > width {
        return false;
    }
    let leading = bytes[0];
    if bytes.len() > 1 {
        let second = bytes[1];
        let valid_second = match leading {
            0xe0 => (0xa0..=0xbf).contains(&second),
            0xed => (0x80..=0x9f).contains(&second),
            0xf0 => (0x90..=0xbf).contains(&second),
            0xf4 => (0x80..=0x8f).contains(&second),
            _ => (0x80..=0xbf).contains(&second),
        };
        if !valid_second {
            return false;
        }
    }
    bytes
        .iter()
        .skip(2)
        .all(|byte| (0x80..=0xbf).contains(byte))
}

fn journal_tail_has_accepted_completion_v1(
    bytes: &[u8],
    complete_len: usize,
    session_id: &str,
) -> Result<bool> {
    let prefix = &bytes[..complete_len];
    let (events, profile) = if prefix.is_empty() {
        (Vec::new(), JournalJsonProfile::LegacyV1)
    } else {
        let (events, profile, _) = parse_complete_events_with_budget_v2(prefix, session_id)?;
        (events, profile)
    };
    let next_seq = events
        .last()
        .and_then(|event| event.seq.checked_add(1))
        .unwrap_or(1);
    let context_limit_actions = provider_context_limit_recovery_actions_v1(&events)?;
    // A pending context-limit intent is the only authority that may complete
    // an otherwise partial `context.limit_reached` audit line.  Try each
    // exact action as a template; the raw tail remains an immutable prefix and
    // the semantic validator below still has to accept the resulting event.
    let templates = if context_limit_actions.is_empty() {
        vec![None]
    } else {
        context_limit_actions.iter().map(Some).collect::<Vec<_>>()
    };
    for template in templates {
        let Some(candidate) = journal_tail_completion_witness_v1(
            &bytes[complete_len..],
            session_id,
            next_seq,
            template,
        ) else {
            continue;
        };
        // The synthesizer is deliberately append-only, but keep this
        // postcondition at the destructive-repair boundary.  A completion
        // witness is sound only when the proposed event is a *strict* byte
        // extension of the exact torn tail and the resulting bytes are
        // lexically complete.  This prevents a future synthesizer change from
        // normalizing, dropping, or otherwise rewriting malformed prefix
        // bytes before the frozen reader/reducers see them.
        let raw_tail = &bytes[complete_len..];
        if candidate.len() <= raw_tail.len()
            || !candidate.starts_with(raw_tail)
            || journal_tail_syntax_v1(&candidate) != JournalTailSyntaxV1::Complete
        {
            continue;
        }
        if profile == JournalJsonProfile::BoundedV2
            && preflight_journal_json_bytes_v2(&candidate).is_err()
        {
            continue;
        }
        // Candidate decoding below intentionally ignores open-ended envelope
        // fields.  Do not let that compatibility rule erase a torn reserved
        // profile claim on any record after session.started.
        if reject_misplaced_journal_json_profile_claim_v2(
            &candidate,
            session_id,
            events.len().saturating_add(1),
            events.is_empty(),
        )
        .is_err()
        {
            continue;
        }
        let event = match decode_journal_event_line_v1(&candidate, session_id, None, profile) {
            Ok(event) => event,
            Err(_) => continue,
        };
        // `BoundedV2` is not only a reader resource profile: it is activated
        // by the current writer on the creation record.  Destructive repair
        // therefore needs proof that the torn bytes are a prefix of that
        // writer language, not merely that some permissive reader completion
        // exists.  `JournalEvent` intentionally accepts unknown root fields
        // for legacy fixture compatibility; without this exact-wire check a
        // tail such as `{"x":` could be completed as a synthetic
        // `custom.recovered`, erased, and followed by recovery records even
        // though no bounded writer could have emitted that prefix.
        if profile == JournalJsonProfile::BoundedV2 {
            let raw_tail = &bytes[complete_len..];
            match encode_journal_event_v2(&event) {
                Ok(canonical)
                    if canonical.len() > raw_tail.len() && canonical.starts_with(raw_tail) => {}
                Ok(_) | Err(_) => continue,
            }
        }
        let shape_valid = validate_raw_protocol_event_shape_v1(&event).is_ok();
        if !shape_valid && event.kind != "context.limit_reached" {
            continue;
        }
        let is_partial_checkpoint = event.kind == COMPACTION_CHECKPOINT_KIND;
        let mut prospective = events.clone();
        prospective.push(event.clone());
        if validate_tail_completion_prefix_v1(&prospective, session_id, profile).is_ok() {
            return Ok(true);
        }
        // A partially written compaction.checkpoint is not itself a durable
        // terminal: recovery must discard the physical tail and settle the
        // already-durable compaction.started attempt as aborted.  The
        // checkpoint-chain reducer quite correctly rejects the synthetic
        // minimal completion above, so use the exact started-attempt lineage
        // as the recovery witness instead of granting the malformed
        // checkpoint any authority.  The complete prefix still has to pass
        // every frozen reducer before truncation is permitted.
        if is_partial_checkpoint
            && validate_partial_checkpoint_candidate_envelope_v1(&events, &event, session_id)
            && partial_compaction_checkpoint_recovery_witness_v1(
                &events,
                &event,
                &bytes[complete_len..],
            )
            && validate_tail_completion_prefix_v1(&events, session_id, profile).is_ok()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The checkpoint fallback discards the synthetic completion rather than
/// committing it, so `validate_tail_completion_prefix_v1` cannot validate the
/// candidate's envelope for us.  Still require the same immutable envelope
/// invariants before granting the torn checkpoint any recovery authority;
/// otherwise a tail with an unsupported schema, wrong sequence, or foreign
/// session could be erased merely because its `attempt_id` names an unfinished
/// compaction.
fn validate_partial_checkpoint_candidate_envelope_v1(
    prefix: &[JournalEvent],
    candidate: &JournalEvent,
    session_id: &str,
) -> bool {
    if candidate.schema != JOURNAL_SCHEMA
        || candidate.kind != COMPACTION_CHECKPOINT_KIND
        || candidate.session_id != session_id
        || candidate.turn_id.is_some()
    {
        return false;
    }
    let Some(previous) = prefix.last() else {
        return false;
    };
    let Some(expected_seq) = previous.seq.checked_add(1) else {
        return false;
    };
    candidate.seq == expected_seq
}

fn partial_compaction_checkpoint_recovery_witness_v1(
    prefix: &[JournalEvent],
    candidate: &JournalEvent,
    raw_tail: &[u8],
) -> bool {
    if candidate.kind != COMPACTION_CHECKPOINT_KIND {
        return false;
    }
    let Some(attempt_id) = candidate.data.get("attempt_id").and_then(Value::as_str) else {
        return false;
    };
    let unfinished = unfinished_compactions(prefix);
    let matching = unfinished
        .iter()
        .filter(|attempt| attempt.attempt_id == attempt_id)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return false;
    }
    let attempt = matching[0];
    // A compaction outcome is the only event written after its durable
    // `compaction.started` intent and before the admission is settled.  If
    // another event already follows the start, this tail cannot be the
    // production checkpoint transaction; treating it as one would let an
    // unrelated final record borrow an old attempt's recovery authority.
    if prefix.last().map(|event| event.seq) != Some(attempt.started_seq) {
        return false;
    }

    // A matching attempt id alone is not a recovery proof.  The checkpoint
    // writer emits a terminal whose immutable binding is copied from the
    // exact `compaction.started` payload.  A torn or forged tail may contain
    // enough JSON to expose one of those fields even though the remaining
    // provider payload is incomplete; if it does, reject any mismatch before
    // granting destructive tail-repair authority.  Fields not yet reached by
    // the torn prefix remain unknown and are intentionally left to the normal
    // checkpoint reducer once a complete event exists.
    let Some(started_event) = prefix.iter().find(|event| {
        event.kind == COMPACTION_STARTED_KIND
            && event.seq == attempt.started_seq
            && event.data.get("attempt_id").and_then(Value::as_str) == Some(attempt_id)
    }) else {
        return false;
    };
    let Ok(started) =
        serde_json::from_value::<crate::compaction::CompactionStarted>(started_event.data.clone())
    else {
        return false;
    };
    let data = &candidate.data;
    let Some(data_object) = data.as_object() else {
        return false;
    };
    // The current checkpoint writer reaches the provider audit only after it
    // has serialized these immutable fields.  Requiring the complete prefix
    // through `raw_response` keeps a synthetic completion of just
    // `{attempt_id, checkpoint_id}` from borrowing the started attempt's
    // recovery authority.  `raw_tail` is checked as well so the witness is
    // based on bytes that were actually durable, not fields appended by the
    // completion synthesizer.  The key must be directly inside the event's
    // `data` object; a provider payload nested below `raw_response` is not
    // equivalent provenance.
    let required_identity = ["attempt_id", "checkpoint_id", "covers_through_seq"];
    if required_identity
        .iter()
        .any(|field| !data_object.contains_key(*field))
        || !data_object.contains_key("raw_response")
        || raw_tail_key_witness_v1(raw_tail, b"raw_response") != RawTailKeyWitnessV1::Torn
    {
        return false;
    }
    let Some(checkpoint_id) = data_object.get("checkpoint_id").and_then(Value::as_str) else {
        return false;
    };
    if !valid_journal_identity_v1(checkpoint_id) {
        return false;
    }
    if data_object
        .get("duration_ms")
        .and_then(Value::as_u64)
        .is_none()
    {
        return false;
    }
    if data_object.get("prompt_version").and_then(Value::as_u64)
        != Some(u64::from(started.prompt_version))
    {
        return false;
    }
    if let Some(value) = data_object.get("parent_checkpoint_id") {
        let expected = started.parent_checkpoint_id.as_deref();
        if value.as_str() != expected && !(value.is_null() && expected.is_none()) {
            return false;
        }
    }
    if let Some(value) = data_object.get("source_digest") {
        if value.as_str() != Some(started.source_digest.as_str()) {
            return false;
        }
    }
    if let Some(value) = data_object.get("model") {
        if value.as_str() != Some(started.model.as_str()) {
            return false;
        }
    }
    // A production checkpoint reaches `covers_through_seq` before any
    // provider-controlled response/audit payload.  Requiring that immutable
    // field (and checking it against the exact started intent) prevents a
    // tail containing only a copied attempt id from acquiring recovery
    // authority, while still accepting a real crash in the later audit bytes.
    let Some(covers_through_seq) = data_object.get("covers_through_seq") else {
        return false;
    };
    if covers_through_seq.as_u64() != Some(started.covers_through_seq) {
        return false;
    }
    for (field, expected) in [
        ("prompt_version", started.prompt_version),
        ("summary_envelope_version", started.summary_envelope_version),
        (
            "source_projection_version",
            started.source_projection_version,
        ),
        (
            "turn_boundary_validator_version",
            started.turn_boundary_validator_version,
        ),
        ("source_digest_version", started.source_digest_version),
        ("usage_contract_version", started.usage_contract_version),
    ] {
        if let Some(value) = data_object.get(field) {
            if value.as_u64() != Some(u64::from(expected)) {
                return false;
            }
        }
    }
    true
}

/// Return whether the raw, already-durable tail contains a key directly in the
/// journal envelope's `data` object.  The tail parser has already established
/// valid JSON lexical state; this scanner deliberately walks the object/array
/// grammar instead of using a byte substring search.  A substring can be
/// forged by another envelope field, a nested data value, or even the contents
/// of a string (for example `"raw_response":` inside provider-controlled
/// text), which would incorrectly turn a synthesized checkpoint field into
/// recovery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawTailKeyWitnessV1 {
    Absent,
    Torn,
    Complete,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawTailTargetStateV1 {
    Pending,
    InContainer(usize),
    Complete,
}

fn raw_tail_key_witness_v1(raw_tail: &[u8], key: &[u8]) -> RawTailKeyWitnessV1 {
    let mut containers = Vec::<JournalJsonContainerV1>::new();
    let mut root = JournalJsonRootStateV1::Value;
    let mut pending_root_key = None::<String>;
    let mut pending_target_key = false;
    let mut data_object_depth = None::<usize>;
    let mut target_state = None::<RawTailTargetStateV1>;
    let mut index = 0usize;

    loop {
        while index < raw_tail.len() && is_journal_json_whitespace_v1(raw_tail[index]) {
            index += 1;
        }
        let expectation = journal_json_expectation_v1(&containers, root);
        if index == raw_tail.len() {
            return match target_state {
                Some(RawTailTargetStateV1::Pending | RawTailTargetStateV1::InContainer(_)) => {
                    RawTailKeyWitnessV1::Torn
                }
                Some(RawTailTargetStateV1::Complete) => RawTailKeyWitnessV1::Complete,
                None => RawTailKeyWitnessV1::Absent,
            };
        }

        match expectation {
            JournalJsonExpectationV1::RootValue => {
                if raw_tail[index] != b'{' || containers.len() == MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1
                {
                    return RawTailKeyWitnessV1::Absent;
                }
                containers.push(JournalJsonContainerV1::Object(
                    JournalJsonObjectStateV1::FirstKeyOrEnd,
                ));
                index += 1;
            }
            JournalJsonExpectationV1::RootDone => return RawTailKeyWitnessV1::Absent,
            JournalJsonExpectationV1::ObjectFirstKeyOrEnd
            | JournalJsonExpectationV1::ObjectKeyAfterComma => match raw_tail[index] {
                b'}' => {
                    let closing_depth = containers.len();
                    containers.pop();
                    if matches!(
                        target_state,
                        Some(RawTailTargetStateV1::InContainer(depth)) if depth == closing_depth
                    ) {
                        target_state = Some(RawTailTargetStateV1::Complete);
                    }
                    if data_object_depth == Some(closing_depth) {
                        data_object_depth = None;
                    }
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return RawTailKeyWitnessV1::Absent;
                    }
                }
                b'"' => {
                    let key_start = index;
                    match scan_journal_json_string_v1(raw_tail, index) {
                        JournalJsonTokenV1::Complete(next) => {
                            let Some(decoded) =
                                serde_json::from_slice::<String>(&raw_tail[key_start..next]).ok()
                            else {
                                return RawTailKeyWitnessV1::Absent;
                            };
                            if containers.len() == 1 {
                                pending_root_key = Some(decoded.clone());
                            }
                            pending_target_key = target_state.is_none()
                                && data_object_depth == Some(containers.len())
                                && decoded.as_bytes() == key;
                            *containers.last_mut().expect("object frame") =
                                JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon);
                            index = next;
                        }
                        JournalJsonTokenV1::Incomplete => {
                            return raw_tail_witness_after_incomplete_v1(target_state);
                        }
                        JournalJsonTokenV1::Invalid => {
                            return raw_tail_witness_after_invalid_v1(target_state);
                        }
                    }
                }
                _ => return RawTailKeyWitnessV1::Absent,
            },
            JournalJsonExpectationV1::ObjectColon => {
                if raw_tail[index] != b':' {
                    return RawTailKeyWitnessV1::Absent;
                }
                if pending_target_key {
                    target_state = Some(RawTailTargetStateV1::Pending);
                    pending_target_key = false;
                }
                *containers.last_mut().expect("object frame") =
                    JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value);
                index += 1;
            }
            JournalJsonExpectationV1::ObjectValue
            | JournalJsonExpectationV1::ArrayValueAfterComma => {
                let enters_data_object = containers.len() == 1
                    && pending_root_key.as_deref() == Some("data")
                    && raw_tail[index] == b'{';
                let parent_depth = containers.len();
                match consume_journal_json_value_v1(raw_tail, index, &mut containers, &mut root) {
                    JournalJsonTokenV1::Complete(next) => {
                        if matches!(target_state, Some(RawTailTargetStateV1::Pending)) {
                            target_state = if containers.len() > parent_depth {
                                Some(RawTailTargetStateV1::InContainer(containers.len()))
                            } else {
                                Some(RawTailTargetStateV1::Complete)
                            };
                        }
                        if enters_data_object && containers.len() == 2 {
                            data_object_depth = Some(2);
                        }
                        index = next;
                    }
                    JournalJsonTokenV1::Incomplete => {
                        return raw_tail_witness_after_incomplete_v1(target_state);
                    }
                    JournalJsonTokenV1::Invalid => {
                        return raw_tail_witness_after_invalid_v1(target_state);
                    }
                }
            }
            JournalJsonExpectationV1::ObjectCommaOrEnd => match raw_tail[index] {
                b',' => {
                    *containers.last_mut().expect("object frame") =
                        JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma);
                    index += 1;
                }
                b'}' => {
                    let closing_depth = containers.len();
                    containers.pop();
                    if matches!(
                        target_state,
                        Some(RawTailTargetStateV1::InContainer(depth)) if depth == closing_depth
                    ) {
                        target_state = Some(RawTailTargetStateV1::Complete);
                    }
                    if data_object_depth == Some(closing_depth) {
                        data_object_depth = None;
                    }
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return RawTailKeyWitnessV1::Absent;
                    }
                }
                _ => return RawTailKeyWitnessV1::Absent,
            },
            JournalJsonExpectationV1::ArrayFirstValueOrEnd => {
                if raw_tail[index] == b']' {
                    let closing_depth = containers.len();
                    containers.pop();
                    if matches!(
                        target_state,
                        Some(RawTailTargetStateV1::InContainer(depth)) if depth == closing_depth
                    ) {
                        target_state = Some(RawTailTargetStateV1::Complete);
                    }
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return RawTailKeyWitnessV1::Absent;
                    }
                } else {
                    match consume_journal_json_value_v1(raw_tail, index, &mut containers, &mut root)
                    {
                        JournalJsonTokenV1::Complete(next) => index = next,
                        JournalJsonTokenV1::Incomplete => {
                            return raw_tail_witness_after_incomplete_v1(target_state);
                        }
                        JournalJsonTokenV1::Invalid => {
                            return raw_tail_witness_after_invalid_v1(target_state);
                        }
                    }
                }
            }
            JournalJsonExpectationV1::ArrayCommaOrEnd => match raw_tail[index] {
                b',' => {
                    *containers.last_mut().expect("array frame") =
                        JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma);
                    index += 1;
                }
                b']' => {
                    let closing_depth = containers.len();
                    containers.pop();
                    if matches!(
                        target_state,
                        Some(RawTailTargetStateV1::InContainer(depth)) if depth == closing_depth
                    ) {
                        target_state = Some(RawTailTargetStateV1::Complete);
                    }
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return RawTailKeyWitnessV1::Absent;
                    }
                }
                _ => return raw_tail_witness_after_invalid_v1(target_state),
            },
        }
    }
}

fn raw_tail_witness_after_incomplete_v1(
    target_state: Option<RawTailTargetStateV1>,
) -> RawTailKeyWitnessV1 {
    match target_state {
        Some(RawTailTargetStateV1::Pending | RawTailTargetStateV1::InContainer(_)) => {
            RawTailKeyWitnessV1::Torn
        }
        Some(RawTailTargetStateV1::Complete) => RawTailKeyWitnessV1::Complete,
        None => RawTailKeyWitnessV1::Absent,
    }
}

fn raw_tail_witness_after_invalid_v1(
    _target_state: Option<RawTailTargetStateV1>,
) -> RawTailKeyWitnessV1 {
    RawTailKeyWitnessV1::Invalid
}

#[cfg(test)]
fn raw_tail_contains_top_level_key_v1(raw_tail: &[u8], key: &[u8]) -> bool {
    matches!(
        raw_tail_key_witness_v1(raw_tail, key),
        RawTailKeyWitnessV1::Torn | RawTailKeyWitnessV1::Complete
    )
}

/// Validate the semantic prefix that `SessionStore::open` will consume before
/// it appends any recovery events.  A crash-tail witness is not authoritative
/// merely because it decodes as a `JournalEvent`: if the same frozen reducers
/// would reject the prospective prefix, truncating the bytes would erase a
/// durable protocol violation rather than repair crash debris.
fn validate_tail_completion_prefix_v1(
    events: &[JournalEvent],
    session_id: &str,
    json_profile: JournalJsonProfile,
) -> Result<()> {
    validate_events(events, session_id)?;
    validate_bounded_recovery_prefix_v2(events, json_profile)?;
    provider_context_limit_recovery_actions_v1(events)?;
    unfinished_responses(events)?;
    // A syntactically completable tail must not acquire destructive repair
    // authority merely because it decodes into a JournalEvent envelope.  In
    // particular, compaction.checkpoint carries a complete provider/source
    // binding which is validated by the checkpoint-chain reducer; without
    // this call a partial/orphan checkpoint can be replaced by a generic
    // recovery marker and silently disappear from the journal.
    validate_checkpoint_chain(events)?;
    compaction_boundary_recovery_actions(events)?;
    crate::mcp::validate_mcp_call_chain(events)?;
    validate_generic_recovery_skips_v1(events)?;

    // `segment_turns` deliberately classifies an unmarked tail without
    // validating every Provider-slot transition. Validate the candidate event
    // itself when it enters that protocol, so an orphan response terminal
    // cannot manufacture destructive repair authority. Do not retroactively
    // apply the current slot reducer to unrelated historical turns in the
    // already-complete prefix: schema-1 fixtures and legacy journals may use a
    // direct response terminal that predates `response.started`.
    if let Some(candidate) = events
        .last()
        .filter(|event| crate::turn::is_provider_slot_event_kind(&event.kind))
    {
        let turn_id = candidate.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!(
                "{} completion witness at seq {} has no turn_id",
                candidate.kind, candidate.seq
            ))
        })?;
        // Legacy schema-1 journals may use a direct response terminal without
        // the durable response.started slot introduced later.  Do not apply
        // the current slot reducer to that historical language merely because
        // the final record is being normalized with a missing newline.  A
        // legacy turn that actually contains started/tool lifecycle evidence
        // still opts into the strict slot proof for that turn.
        let uses_started_lifecycle = turn_uses_started_lifecycle_v1(events, turn_id);
        if json_profile == JournalJsonProfile::BoundedV2 || uses_started_lifecycle {
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                events,
                turn_id,
            )?;
        }
    }

    let unstarted_tools = unstarted_tool_calls(events);
    let (mcp_unstarted_tools, _generic_unstarted_tools) =
        partition_unstarted_tools_v1(events, &unstarted_tools)?;
    preflight_recovery_authorization_batches(&mcp_unstarted_tools)?;

    // `open` invokes the canonical turn reducer whenever the prefix contains
    // turn-owned evidence.  Run it here as well so an orphan response/tool
    // terminal cannot be mistaken for repairable JSON merely because it has a
    // valid envelope shape.
    let has_turn_evidence = events.iter().any(|event| {
        event.turn_id.is_some()
            || matches!(
                event.kind.as_str(),
                "user.message"
                    | "response.started"
                    | "response.completed"
                    | "response.failed"
                    | "response.aborted"
                    | "tool.started"
                    | "tool.in_doubt"
                    | "tool.completed"
                    | "tool.cancelled"
                    | "tool.in_doubt_resolved"
                    | "tool.skipped_due_to_cancel"
                    | "tool.skipped_due_to_in_doubt"
                    | "tool.skipped_due_to_limit"
                    | "tool.skipped_due_to_stalled"
                    | "tool.skipped_due_to_recovery"
                    | "turn.completed"
                    | "turn.cancelled"
                    | "turn.abandoned"
                    | "agent.stalled"
                    | "agent.limit_reached"
                    | "context.limit_reached"
            )
    });
    if has_turn_evidence {
        // JSON admission and lifecycle protocol selection are independent.
        // The versioned turn reducer already preserves every registered
        // historical turn language; the JSON profile only controls resource
        // accounting and must never force an otherwise-modern journal to v1.
        segment_turns(events)?;
    }
    Ok(())
}

fn is_journal_json_whitespace_v1(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn finish_journal_json_value_v1(
    containers: &mut [JournalJsonContainerV1],
    root: &mut JournalJsonRootStateV1,
) -> bool {
    match containers.last_mut() {
        Some(JournalJsonContainerV1::Object(state))
            if *state == JournalJsonObjectStateV1::Value =>
        {
            *state = JournalJsonObjectStateV1::CommaOrEnd;
            true
        }
        Some(JournalJsonContainerV1::Array(state))
            if matches!(
                *state,
                JournalJsonArrayStateV1::FirstValueOrEnd | JournalJsonArrayStateV1::ValueAfterComma
            ) =>
        {
            *state = JournalJsonArrayStateV1::CommaOrEnd;
            true
        }
        None if *root == JournalJsonRootStateV1::Value => {
            *root = JournalJsonRootStateV1::Done;
            true
        }
        _ => false,
    }
}

fn consume_journal_json_value_v1(
    bytes: &[u8],
    index: usize,
    containers: &mut Vec<JournalJsonContainerV1>,
    root: &mut JournalJsonRootStateV1,
) -> JournalJsonTokenV1 {
    let Some(&byte) = bytes.get(index) else {
        return JournalJsonTokenV1::Incomplete;
    };
    match byte {
        b'{' => {
            if containers.len() == MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1 {
                return JournalJsonTokenV1::Invalid;
            }
            containers.push(JournalJsonContainerV1::Object(
                JournalJsonObjectStateV1::FirstKeyOrEnd,
            ));
            JournalJsonTokenV1::Complete(index + 1)
        }
        b'[' => {
            if containers.len() == MAX_JOURNAL_TAIL_LEXICAL_DEPTH_V1 {
                return JournalJsonTokenV1::Invalid;
            }
            containers.push(JournalJsonContainerV1::Array(
                JournalJsonArrayStateV1::FirstValueOrEnd,
            ));
            JournalJsonTokenV1::Complete(index + 1)
        }
        b'"' => match scan_journal_json_string_v1(bytes, index) {
            JournalJsonTokenV1::Complete(next) => {
                if finish_journal_json_value_v1(containers, root) {
                    JournalJsonTokenV1::Complete(next)
                } else {
                    JournalJsonTokenV1::Invalid
                }
            }
            outcome => outcome,
        },
        b't' => finish_journal_json_scalar_v1(
            scan_journal_json_literal_v1(bytes, index, b"true"),
            containers,
            root,
        ),
        b'f' => finish_journal_json_scalar_v1(
            scan_journal_json_literal_v1(bytes, index, b"false"),
            containers,
            root,
        ),
        b'n' => finish_journal_json_scalar_v1(
            scan_journal_json_literal_v1(bytes, index, b"null"),
            containers,
            root,
        ),
        b'-' | b'0'..=b'9' => finish_journal_json_scalar_v1(
            scan_journal_json_number_v1(bytes, index),
            containers,
            root,
        ),
        _ => JournalJsonTokenV1::Invalid,
    }
}

fn finish_journal_json_scalar_v1(
    outcome: JournalJsonTokenV1,
    containers: &mut [JournalJsonContainerV1],
    root: &mut JournalJsonRootStateV1,
) -> JournalJsonTokenV1 {
    match outcome {
        JournalJsonTokenV1::Complete(next) => {
            if finish_journal_json_value_v1(containers, root) {
                JournalJsonTokenV1::Complete(next)
            } else {
                JournalJsonTokenV1::Invalid
            }
        }
        outcome => outcome,
    }
}

fn scan_journal_json_literal_v1(bytes: &[u8], index: usize, literal: &[u8]) -> JournalJsonTokenV1 {
    let available = bytes.len().saturating_sub(index);
    let compared = available.min(literal.len());
    if bytes[index..index + compared] != literal[..compared] {
        return JournalJsonTokenV1::Invalid;
    }
    if available < literal.len() {
        JournalJsonTokenV1::Incomplete
    } else {
        JournalJsonTokenV1::Complete(index + literal.len())
    }
}

fn scan_journal_json_number_v1(bytes: &[u8], index: usize) -> JournalJsonTokenV1 {
    let mut cursor = index;
    if bytes[cursor] == b'-' {
        cursor += 1;
        if cursor == bytes.len() {
            return JournalJsonTokenV1::Incomplete;
        }
    }

    match bytes[cursor] {
        b'0' => cursor += 1,
        b'1'..=b'9' => {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
        }
        _ => return JournalJsonTokenV1::Invalid,
    }

    if cursor < bytes.len() && bytes[cursor] == b'.' {
        cursor += 1;
        if cursor == bytes.len() {
            return JournalJsonTokenV1::Incomplete;
        }
        if !bytes[cursor].is_ascii_digit() {
            return JournalJsonTokenV1::Invalid;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
    }

    if cursor < bytes.len() && matches!(bytes[cursor], b'e' | b'E') {
        cursor += 1;
        if cursor == bytes.len() {
            return JournalJsonTokenV1::Incomplete;
        }
        if matches!(bytes[cursor], b'+' | b'-') {
            cursor += 1;
            if cursor == bytes.len() {
                return JournalJsonTokenV1::Incomplete;
            }
        }
        if !bytes[cursor].is_ascii_digit() {
            return JournalJsonTokenV1::Invalid;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
    }

    JournalJsonTokenV1::Complete(cursor)
}

fn scan_journal_json_string_v1(bytes: &[u8], index: usize) -> JournalJsonTokenV1 {
    debug_assert_eq!(bytes.get(index), Some(&b'"'));
    let mut cursor = index + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => return JournalJsonTokenV1::Complete(cursor + 1),
            b'\\' => {
                cursor += 1;
                let Some(&escape) = bytes.get(cursor) else {
                    return JournalJsonTokenV1::Incomplete;
                };
                match escape {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => cursor += 1,
                    b'u' => {
                        cursor += 1;
                        for _ in 0..4 {
                            let Some(&digit) = bytes.get(cursor) else {
                                return JournalJsonTokenV1::Incomplete;
                            };
                            if !digit.is_ascii_hexdigit() {
                                return JournalJsonTokenV1::Invalid;
                            }
                            cursor += 1;
                        }
                    }
                    _ => return JournalJsonTokenV1::Invalid,
                }
            }
            0x00..=0x1f => return JournalJsonTokenV1::Invalid,
            0x20..=0x7f => cursor += 1,
            leading => {
                let width = match leading {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => return JournalJsonTokenV1::Invalid,
                };
                let Some(end) = cursor.checked_add(width) else {
                    return JournalJsonTokenV1::Invalid;
                };
                if end > bytes.len() {
                    return JournalJsonTokenV1::Incomplete;
                }
                if std::str::from_utf8(&bytes[cursor..end]).is_err() {
                    return JournalJsonTokenV1::Invalid;
                }
                cursor = end;
            }
        }
    }
    JournalJsonTokenV1::Incomplete
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
    let scan = scan_journal_bytes(&bytes, session_id)?;

    // `session.started` is the creation commit.  Never turn an empty prefix
    // (including a first record truncated before its terminating newline) into
    // a new legacy journal by truncating it and appending recovery metadata.
    // This check intentionally precedes every file mutation.
    if scan.events.is_empty() || (scan.valid_len == 0 && scan.truncated_tail.is_some()) {
        return Err(OxidraError::Session(format!(
            "session {session_id} has no complete session.started header; refusing journal repair"
        )));
    }

    // The caller performs the truncation only after it has admitted the full
    // recovery batch.  Keeping this scanner read-only preserves exact tail
    // evidence whenever capacity or a later recovery preflight fails.
    Ok(scan)
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
    parse_complete_events_with_budget_v2(bytes, session_id).map(|(events, _, _)| events)
}

fn parse_complete_events_with_budget_v2(
    bytes: &[u8],
    session_id: &str,
) -> Result<(Vec<JournalEvent>, JournalJsonProfile, JournalDecodeBudgetV2)> {
    let json_profile = detect_journal_json_profile_v2(bytes, session_id)?;
    let mut events = Vec::new();
    let mut budget = JournalDecodeBudgetV2::default();
    let mut first_record = true;
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let metrics = if json_profile == JournalJsonProfile::BoundedV2 {
            Some(preflight_journal_json_bytes_v2(line).map_err(|error| {
                OxidraError::Session(format!(
                    "invalid JSON profile in session {session_id} at line {}: {error}",
                    index + 1
                ))
            })?)
        } else {
            None
        };
        reject_misplaced_journal_json_profile_claim_v2(line, session_id, index + 1, first_record)?;
        first_record = false;
        if let Some(metrics) = metrics {
            // Charge the whole-journal budget before allocating the Value
            // tree. Legacy schema-1 journals intentionally do not acquire a
            // retroactive aggregate budget.
            budget.account(metrics)?;
        }
        let event = decode_journal_event_line_v1(line, session_id, Some(index + 1), json_profile)?;
        events.push(event);
    }
    validate_events(&events, session_id)?;
    Ok((events, json_profile, budget))
}

fn parse_json_lines(bytes: &[u8]) -> Result<Vec<Value>> {
    let json_profile = detect_journal_json_profile_v2(bytes, "raw journal")?;
    let mut values = Vec::new();
    let mut budget = JournalDecodeBudgetV2::default();
    let mut first_record = true;
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let metrics = if json_profile == JournalJsonProfile::BoundedV2 {
            Some(preflight_journal_json_bytes_v2(line).map_err(|error| {
                OxidraError::Session(format!(
                    "invalid journal JSON profile at line {}: {error}",
                    index + 1
                ))
            })?)
        } else {
            None
        };
        reject_misplaced_journal_json_profile_claim_v2(
            line,
            "raw journal",
            index + 1,
            first_record,
        )?;
        first_record = false;
        if let Some(metrics) = metrics {
            budget.account(metrics)?;
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

/// Scan only the root-object keys of one complete JSONL record without
/// materializing the event or imposing the bounded-v2 depth budget.  Legacy
/// schema-1 records intentionally retain their historical serde recursion
/// boundary; using a serde probe here would silently add a second, newer
/// boundary merely to detect a reserved key on later records.
fn root_object_contains_key_v2(bytes: &[u8], target: &str) -> Result<bool> {
    let mut containers = Vec::<JournalJsonContainerV1>::new();
    let mut root = JournalJsonRootStateV1::Value;
    let mut index = 0usize;

    loop {
        while index < bytes.len() && is_journal_json_whitespace_v1(bytes[index]) {
            index += 1;
        }
        let expectation = journal_json_expectation_v1(&containers, root);
        if index == bytes.len() {
            return if expectation == JournalJsonExpectationV1::RootDone {
                Ok(false)
            } else {
                Err(OxidraError::Session(
                    "incomplete JSON while scanning the journal envelope".to_owned(),
                ))
            };
        }

        match expectation {
            JournalJsonExpectationV1::RootValue => {
                if bytes[index] != b'{' {
                    return Err(OxidraError::Session(
                        "journal envelope root is not an object".to_owned(),
                    ));
                }
                containers.push(JournalJsonContainerV1::Object(
                    JournalJsonObjectStateV1::FirstKeyOrEnd,
                ));
                index += 1;
            }
            JournalJsonExpectationV1::RootDone => {
                return Err(OxidraError::Session(
                    "trailing bytes after the journal envelope".to_owned(),
                ));
            }
            JournalJsonExpectationV1::ObjectFirstKeyOrEnd
            | JournalJsonExpectationV1::ObjectKeyAfterComma => match bytes[index] {
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return Err(OxidraError::Session(
                            "invalid object closure in the journal envelope".to_owned(),
                        ));
                    }
                }
                b'"' => {
                    let start = index;
                    let next = match scan_journal_json_string_v1(bytes, index) {
                        JournalJsonTokenV1::Complete(next) => next,
                        JournalJsonTokenV1::Incomplete => {
                            return Err(OxidraError::Session(
                                "incomplete object key in the journal envelope".to_owned(),
                            ));
                        }
                        JournalJsonTokenV1::Invalid => {
                            return Err(OxidraError::Session(
                                "invalid object key in the journal envelope".to_owned(),
                            ));
                        }
                    };
                    if containers.len() == 1 {
                        let key = serde_json::from_slice::<String>(&bytes[start..next]).map_err(
                            |error| {
                                OxidraError::Session(format!(
                                    "invalid root object key in the journal envelope: {error}"
                                ))
                            },
                        )?;
                        if key == target {
                            return Ok(true);
                        }
                    }
                    *containers.last_mut().expect("object frame") =
                        JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Colon);
                    index = next;
                }
                _ => {
                    return Err(OxidraError::Session(
                        "invalid object key separator in the journal envelope".to_owned(),
                    ));
                }
            },
            JournalJsonExpectationV1::ObjectColon => {
                if bytes[index] != b':' {
                    return Err(OxidraError::Session(
                        "missing colon after a journal envelope key".to_owned(),
                    ));
                }
                *containers.last_mut().expect("object frame") =
                    JournalJsonContainerV1::Object(JournalJsonObjectStateV1::Value);
                index += 1;
            }
            JournalJsonExpectationV1::ObjectValue
            | JournalJsonExpectationV1::ArrayValueAfterComma => {
                index = scan_journal_json_value_v2(bytes, index, &mut containers, &mut root)?;
            }
            JournalJsonExpectationV1::ObjectCommaOrEnd => match bytes[index] {
                b',' => {
                    *containers.last_mut().expect("object frame") =
                        JournalJsonContainerV1::Object(JournalJsonObjectStateV1::KeyAfterComma);
                    index += 1;
                }
                b'}' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return Err(OxidraError::Session(
                            "invalid object closure in the journal envelope".to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(OxidraError::Session(
                        "invalid object terminator in the journal envelope".to_owned(),
                    ));
                }
            },
            JournalJsonExpectationV1::ArrayFirstValueOrEnd => {
                if bytes[index] == b']' {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return Err(OxidraError::Session(
                            "invalid array closure in the journal envelope".to_owned(),
                        ));
                    }
                } else {
                    index = scan_journal_json_value_v2(bytes, index, &mut containers, &mut root)?;
                }
            }
            JournalJsonExpectationV1::ArrayCommaOrEnd => match bytes[index] {
                b',' => {
                    *containers.last_mut().expect("array frame") =
                        JournalJsonContainerV1::Array(JournalJsonArrayStateV1::ValueAfterComma);
                    index += 1;
                }
                b']' => {
                    containers.pop();
                    index += 1;
                    if !finish_journal_json_value_v1(&mut containers, &mut root) {
                        return Err(OxidraError::Session(
                            "invalid array closure in the journal envelope".to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(OxidraError::Session(
                        "invalid array terminator in the journal envelope".to_owned(),
                    ));
                }
            },
        }
    }
}

/// Consume one JSON value lexically and return the next byte.  Nested
/// containers use the same iterative frames as the crash-tail scanner, but
/// deliberately omit its fixed depth cap because this helper is used to keep
/// legacy records outside the bounded-v2 resource profile.
fn scan_journal_json_value_v2(
    bytes: &[u8],
    mut index: usize,
    containers: &mut Vec<JournalJsonContainerV1>,
    root: &mut JournalJsonRootStateV1,
) -> Result<usize> {
    while index < bytes.len() && is_journal_json_whitespace_v1(bytes[index]) {
        index += 1;
    }
    let Some(&byte) = bytes.get(index) else {
        return Err(OxidraError::Session(
            "missing JSON value in the journal envelope".to_owned(),
        ));
    };
    match byte {
        b'{' => {
            containers.push(JournalJsonContainerV1::Object(
                JournalJsonObjectStateV1::FirstKeyOrEnd,
            ));
            Ok(index + 1)
        }
        b'[' => {
            containers.push(JournalJsonContainerV1::Array(
                JournalJsonArrayStateV1::FirstValueOrEnd,
            ));
            Ok(index + 1)
        }
        b'"' => {
            let next = match scan_journal_json_string_v1(bytes, index) {
                JournalJsonTokenV1::Complete(next) => next,
                JournalJsonTokenV1::Incomplete => {
                    return Err(OxidraError::Session(
                        "incomplete JSON string in the journal envelope".to_owned(),
                    ));
                }
                JournalJsonTokenV1::Invalid => {
                    return Err(OxidraError::Session(
                        "invalid JSON string in the journal envelope".to_owned(),
                    ));
                }
            };
            if !finish_journal_json_value_v1(containers, root) {
                return Err(OxidraError::Session(
                    "unexpected scalar in the journal envelope".to_owned(),
                ));
            }
            Ok(next)
        }
        b't' | b'f' | b'n' => {
            let literal = match byte {
                b't' => b"true".as_slice(),
                b'f' => b"false".as_slice(),
                _ => b"null".as_slice(),
            };
            let end = index
                .checked_add(literal.len())
                .ok_or_else(|| OxidraError::Session("JSON literal offset overflow".to_owned()))?;
            if bytes.get(index..end) != Some(literal) {
                return Err(OxidraError::Session(
                    "invalid JSON literal in the journal envelope".to_owned(),
                ));
            }
            if !finish_journal_json_value_v1(containers, root) {
                return Err(OxidraError::Session(
                    "unexpected literal in the journal envelope".to_owned(),
                ));
            }
            Ok(end)
        }
        b'-' | b'0'..=b'9' => {
            let start = index;
            while index < bytes.len()
                && !is_journal_json_whitespace_v1(bytes[index])
                && !matches!(bytes[index], b',' | b']' | b'}')
            {
                index += 1;
            }
            let token = &bytes[start..index];
            let value = serde_json::from_slice::<Value>(token).map_err(|error| {
                OxidraError::Session(format!(
                    "invalid JSON number in the journal envelope: {error}"
                ))
            })?;
            if !value.is_number() || !finish_journal_json_value_v1(containers, root) {
                return Err(OxidraError::Session(
                    "invalid JSON scalar in the journal envelope".to_owned(),
                ));
            }
            Ok(index)
        }
        _ => Err(OxidraError::Session(
            "invalid JSON value in the journal envelope".to_owned(),
        )),
    }
}

fn reject_misplaced_journal_json_profile_claim_v2(
    line: &[u8],
    session_id: &str,
    line_number: usize,
    first_record: bool,
) -> Result<()> {
    if first_record {
        return Ok(());
    }
    if root_object_contains_key_v2(line, JOURNAL_JSON_PROFILE_FIELD).map_err(|error| {
        OxidraError::Session(format!(
            "invalid journal envelope in session {session_id} at line {line_number}: {error}"
        ))
    })? {
        return Err(OxidraError::Session(format!(
            "journal JSON profile claim is only valid on the first session.started event (line {line_number})"
        )));
    }
    Ok(())
}

fn detect_journal_json_profile_v2(bytes: &[u8], session_id: &str) -> Result<JournalJsonProfile> {
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        // Schema 1 historically used serde_json's ordinary recursion limit.
        // Parse a lightweight first-record probe under that literal behavior
        // to discover an envelope-level activation without materializing its
        // potentially wide legacy header data.
        let first: JournalJsonProfileProbeV2 = serde_json::from_slice(line).map_err(|error| {
            OxidraError::Session(format!(
                "invalid {JOURNAL_JSON_PROFILE_FIELD} probe in session {session_id} at line {}: {error}",
                index + 1
            ))
        })?;
        return journal_json_profile_from_probe_v2(Some(first));
    }
    Ok(JournalJsonProfile::LegacyV1)
}

fn decode_journal_event_line_v1(
    line: &[u8],
    session_id: &str,
    line_number: Option<usize>,
    json_profile: JournalJsonProfile,
) -> Result<JournalEvent> {
    // Callers that classify a missing-newline tail invoke this helper after a
    // successful raw preflight. Normal line parsing does the same explicitly
    // so serde_json never materializes an out-of-profile tree.
    let event: JournalEvent = serde_json::from_slice(line).map_err(|error| {
        let location = line_number
            .map(|line| format!(" at line {line}"))
            .unwrap_or_default();
        OxidraError::Session(format!(
            "invalid journal event in session {session_id}{location}: {error}"
        ))
    })?;
    if json_profile == JournalJsonProfile::BoundedV2 {
        validate_journal_data_value_v2(&event.data).map_err(|error| {
            let location = line_number
                .map(|line| format!(" at line {line}"))
                .unwrap_or_default();
            OxidraError::Session(format!(
                "invalid journal event data profile in session {session_id}{location}: {error}"
            ))
        })?;
    }
    Ok(event)
}

fn validate_events(events: &[JournalEvent], session_id: &str) -> Result<()> {
    let Some(first) = events.first() else {
        return Err(OxidraError::Session(format!(
            "session {session_id} journal is empty; missing session.started header"
        )));
    };
    if first.kind != SESSION_STARTED_KIND || first.seq != 1 {
        return Err(OxidraError::Session(format!(
            "session {session_id} journal must begin with session.started at seq 1"
        )));
    }
    let mut previous_seq = None;
    for event in events {
        if event.kind.trim().is_empty() {
            return Err(OxidraError::Session(format!(
                "journal event kind cannot be empty at seq {}",
                event.seq
            )));
        }
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

/// Validate a complete final record before the only mutation allowed for that
/// state: appending its missing JSONL newline.  Basic JSON/envelope parsing is
/// insufficient here because several reducers intentionally tolerate an
/// unfinished prefix for crash recovery.  The candidate must first be a
/// member of the frozen reopen language; otherwise the source bytes remain
/// untouched and `open()` fails closed.
fn validate_normalization_candidate_v1(
    events: &[JournalEvent],
    session_id: &str,
    json_profile: JournalJsonProfile,
) -> Result<()> {
    validate_events(events, session_id)?;
    for event in events {
        validate_raw_protocol_event_shape_v1(event)?;
        // `validate_raw_protocol_event_shape_v1` intentionally stays a
        // lightweight compatibility check for the public append surface:
        // historical callers may still append opaque/legacy payloads.  A
        // complete no-newline record is different: adding the LF is a
        // destructive normalization, so the candidate must already satisfy
        // the reducer's user-input language.  In particular, a bare
        // `data:{}` user.message would otherwise be accepted and rewritten,
        // only to fail later when history/projection materializes it.
        if json_profile == JournalJsonProfile::BoundedV2 {
            validate_bounded_user_message_v2(event)?;
        }
    }

    // Turn segmentation catches turn-scoped rows that reference no durable
    // user turn and validates explicit completion markers.  It still permits
    // open/in-doubt prefixes so the normal recovery planner can settle them
    // after the newline is admitted.
    if events.iter().any(|event| event.turn_id.is_some()) {
        segment_turns(events)?;
    }

    validate_checkpoint_chain(events)?;
    validate_compaction_boundary_chain(events)?;
    crate::mcp::validate_mcp_call_chain(events)?;
    validate_generic_recovery_skips_v1(events)?;
    crate::turn::validate_turn_recovery_dynamic(events)?;

    // Preserve historical direct-response journals which predate the durable
    // response.started slot.  Once a journal uses the current started/tool
    // lifecycle, validate every such turn with the exact Provider slot reducer
    // before allowing normalization.
    let mut strict_turn_ids = Vec::<String>::new();
    for event in events {
        if matches!(
            event.kind.as_str(),
            "response.started" | "tool.started" | "tool.in_doubt"
        ) {
            if let Some(turn_id) = event.turn_id.as_ref() {
                if !strict_turn_ids.iter().any(|known| known == turn_id) {
                    strict_turn_ids.push(turn_id.clone());
                }
            }
        }
    }
    // The JSON resource profile does not select the Provider-slot protocol.
    // A no-claim journal may still contain a modern started/tool lifecycle;
    // validate every turn that carries that durable evidence before adding a
    // missing newline.
    validate_provider_request_slots_v2(events, &strict_turn_ids)?;
    Ok(())
}

fn validate_bounded_recovery_prefix_v2(
    events: &[JournalEvent],
    json_profile: JournalJsonProfile,
) -> Result<()> {
    if json_profile != JournalJsonProfile::BoundedV2 {
        return Ok(());
    }
    for event in events {
        validate_raw_protocol_event_shape_v1(event)?;
        validate_bounded_user_message_v2(event)?;
    }
    Ok(())
}

fn validate_bounded_user_message_v2(event: &JournalEvent) -> Result<()> {
    if event.kind != "user.message" {
        return Ok(());
    }
    let Some(item) = event.data.get("item").and_then(Value::as_object) else {
        return Err(OxidraError::Session(format!(
            "user.message at seq {} has no input item",
            event.seq
        )));
    };
    if item.get("role").and_then(Value::as_str) != Some("user") {
        return Err(OxidraError::Session(format!(
            "user.message at seq {} input item must use role user",
            event.seq
        )));
    }
    if !item.contains_key("content") {
        return Err(OxidraError::Session(format!(
            "user.message at seq {} has no content",
            event.seq
        )));
    }
    if !matches!(
        item.get("content"),
        Some(Value::String(_) | Value::Array(_))
    ) {
        return Err(OxidraError::Session(format!(
            "user.message at seq {} content must be text or an array",
            event.seq
        )));
    }
    Ok(())
}

/// Explicit markers that make a generic event part of the MCP protocol rather
/// than an open-ended builtin/legacy event with a similar kind string.
fn generic_event_has_explicit_mcp_claim_v1(event: &JournalEvent) -> bool {
    event.kind == "mcp.registry.activated"
        || (event.kind == "context.tools"
            && event
                .data
                .as_object()
                .is_some_and(|data| data.contains_key("mcp")))
        || (event.kind == "response.started"
            && (event.data.get("mcp_registry_epoch_id").is_some()
                || event.data.get("mcp_registry_digest").is_some()
                || event.data.get("mcp_surface").is_some()
                || event.data.get("mcp_prepared_request").is_some()))
        || (is_response_terminal(&event.kind)
            && (event.data.get("mcp").is_some()
                || event
                    .data
                    .get("mcp_execution_coordinator_version")
                    .is_some()
                || event.data.get("mcp_registry_epoch_id").is_some()
                || event.data.get("mcp_registry_digest").is_some()
                || event.data.get("mcp_surface").is_some()))
        || (is_tool_lifecycle(&event.kind)
            && (event.data.get("mcp").is_some()
                || event
                    .data
                    .get("mcp_execution_coordinator_version")
                    .is_some()
                || event.data.get("recovery_marker_seq").is_some()
                || (event.data.get("response_seq").is_some()
                    && !is_generic_recovery_skip_v1(event))))
        || (event.kind == RECOVERY_KIND
            && (event.data.get("tool_skip_authorization_version").is_some()
                || event.data.get("unstarted_tool_calls").is_some()
                || event
                    .data
                    .get("in_doubt_resolution_authorization_version")
                    .is_some()))
}

fn valid_journal_identity_v1(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

/// Validate the minimum identity/profile needed for a protocol event before
/// it can become durable.  Full lifecycle reducers still run on the
/// prospective prefix where a complete transition is available; this early
/// check closes the more basic language hole in which a raw public append can
/// fsync an event that recovery cannot even index (for example `{}` tool
/// starts or a user message without a turn).
fn validate_raw_protocol_event_shape_v1(event: &JournalEvent) -> Result<()> {
    let data = event.data.as_object();
    let identity = |field: &str| {
        data.and_then(|data| data.get(field))
            .and_then(Value::as_str)
            .filter(|value| valid_journal_identity_v1(value))
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "{} at seq {} requires a valid {field}",
                    event.kind, event.seq
                ))
            })
    };

    if matches!(event.kind.as_str(), "session.started" | "user.message") {
        if event.kind == "user.message"
            && !event
                .turn_id
                .as_deref()
                .is_some_and(valid_journal_identity_v1)
        {
            return Err(OxidraError::Session(format!(
                "user.message at seq {} has no valid turn_id",
                event.seq
            )));
        }
        if event.kind == "session.started" && event.turn_id.is_some() {
            return Err(OxidraError::Session(format!(
                "session.started at seq {} must not have a turn_id",
                event.seq
            )));
        }
        if data.is_none() {
            return Err(OxidraError::Session(format!(
                "{} at seq {} requires an object payload",
                event.kind, event.seq
            )));
        }
    }

    if is_tool_lifecycle(&event.kind) {
        // Tool lifecycle reducers use call_id as their primary lookup key.
        // A syntactically valid JSON object without that key is not a
        // recoverable prefix, even for legacy standalone calls with no turn.
        let _call_id = identity("call_id").or_else(|_| identity("id"))?;
        if event
            .turn_id
            .as_deref()
            .is_some_and(|value| !valid_journal_identity_v1(value))
        {
            return Err(OxidraError::Session(format!(
                "{} at seq {} has an invalid turn_id",
                event.kind, event.seq
            )));
        }
    }
    validate_generic_recovery_skip_profile_v1(event)?;

    if event.kind == "response.started" {
        if !event
            .turn_id
            .as_deref()
            .is_some_and(valid_journal_identity_v1)
        {
            return Err(OxidraError::Session(format!(
                "response.started at seq {} has no valid turn_id",
                event.seq
            )));
        }
        identity("response_attempt_id")?;
    }

    if is_response_terminal(&event.kind) {
        if event
            .turn_id
            .as_deref()
            .is_some_and(|value| !valid_journal_identity_v1(value))
        {
            return Err(OxidraError::Session(format!(
                "{} at seq {} has an invalid turn_id",
                event.kind, event.seq
            )));
        }
        // Failed/aborted legacy responses may omit the attempt field, but if
        // a caller supplies it it must be a usable lifecycle identity.
        if let Some(value) = data
            .and_then(|data| data.get("response_attempt_id"))
            .and_then(Value::as_str)
        {
            if !valid_journal_identity_v1(value) {
                return Err(OxidraError::Session(format!(
                    "{} at seq {} has an invalid response_attempt_id",
                    event.kind, event.seq
                )));
            }
        }
    }

    if matches!(
        event.kind.as_str(),
        "turn.completed"
            | "turn.cancelled"
            | "turn.abandoned"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
            | "turn.retry_started"
    ) && !event
        .turn_id
        .as_deref()
        .is_some_and(valid_journal_identity_v1)
    {
        return Err(OxidraError::Session(format!(
            "{} at seq {} has no valid turn_id",
            event.kind, event.seq
        )));
    }

    Ok(())
}

fn validate_generic_recovery_skip_profile_v1(event: &JournalEvent) -> Result<()> {
    let version = event.data.get("generic_recovery_skip_version");
    let recovered = event.data.get("recovered").and_then(Value::as_bool);
    if version.is_none() && !(event.kind == "tool.skipped_due_to_cancel" && recovered == Some(true))
    {
        return Ok(());
    }
    let Some(data) = event.data.as_object() else {
        return Err(OxidraError::Session(format!(
            "{} at seq {} has an invalid generic recovery skip profile",
            event.kind, event.seq
        )));
    };
    const EXACT_KEYS: [&str; 10] = [
        "call_id",
        "tool",
        "arguments",
        "response_seq",
        "reason",
        "output",
        "is_error",
        "error_code",
        "generic_recovery_skip_version",
        "recovered",
    ];
    let exact_keys =
        data.len() == EXACT_KEYS.len() && EXACT_KEYS.iter().all(|key| data.contains_key(*key));
    let canonical_output = data
        .get("output")
        .and_then(Value::as_object)
        .filter(|output| output.len() == 1 && output.contains_key("error"))
        .and_then(|output| output.get("error"))
        .and_then(Value::as_object)
        .filter(|error| {
            error.len() == 2 && error.contains_key("code") && error.contains_key("message")
        })
        .is_some_and(|error| {
            error.get("code").and_then(Value::as_str) == Some("cancelled")
                && error.get("message").and_then(Value::as_str)
                    == Some(GENERIC_RECOVERY_SKIP_MESSAGE_V1)
        });
    if event.kind != "tool.skipped_due_to_cancel"
        || !event
            .turn_id
            .as_deref()
            .is_some_and(valid_journal_identity_v1)
        || !exact_keys
        || version.and_then(Value::as_u64) != Some(GENERIC_RECOVERY_SKIP_VERSION_V1)
        || recovered != Some(true)
        || !data
            .get("call_id")
            .and_then(Value::as_str)
            .is_some_and(valid_journal_identity_v1)
        || !data
            .get("tool")
            .and_then(Value::as_str)
            .is_some_and(valid_journal_identity_v1)
        // `response_seq` is part of the exact profile, not an optional
        // compatibility field.  Checking only `and_then(as_u64)` here would
        // accept `null`, strings, booleans, and negative/decimal numbers via
        // `None`; the binding code below would then hit an `expect()` and
        // panic while validating an otherwise untrusted journal.  Require a
        // concrete positive integer that points strictly before this skip.
        || !data
            .get("response_seq")
            .and_then(Value::as_u64)
            .is_some_and(|response_seq| response_seq > 0 && response_seq < event.seq)
        || data.get("reason").and_then(Value::as_str) != Some(GENERIC_RECOVERY_SKIP_REASON_V1)
        || data.get("error_code").and_then(Value::as_str) != Some("cancelled")
        || data.get("is_error").and_then(Value::as_bool) != Some(true)
        || !canonical_output
    {
        return Err(OxidraError::Session(format!(
            "{} at seq {} has an invalid generic recovery skip profile",
            event.kind, event.seq
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PendingGenericFunctionCallV1<'a> {
    response_seq: u64,
    tool_name: Option<&'a str>,
    arguments: Option<&'a Value>,
}

/// Bind every versioned generic crash terminal to the exact, still-unstarted
/// Provider call occurrence that preceded it.  Generic recovery has no MCP
/// marker authority, so the event itself carries the immutable response
/// occurrence plus the exact durable tool/arguments representation.
fn validate_generic_recovery_skips_v1(events: &[JournalEvent]) -> Result<()> {
    for event in events {
        validate_generic_recovery_skip_profile_v1(event)?;
    }
    let mcp_calls = crate::mcp::validated_durable_mcp_calls_index(events)?;
    let mut pending =
        HashMap::<(Option<String>, String), Vec<PendingGenericFunctionCallV1<'_>>>::new();

    for event in events {
        if event.kind == "response.completed" {
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
                pending
                    .entry((event.turn_id.clone(), call_id.to_owned()))
                    .or_default()
                    .push(PendingGenericFunctionCallV1 {
                        response_seq: event.seq,
                        tool_name: item
                            .get("name")
                            .or_else(|| item.get("tool"))
                            .and_then(Value::as_str),
                        arguments: item.get("arguments"),
                    });
            }
            continue;
        }
        if !is_tool_lifecycle(&event.kind) {
            continue;
        }
        let Some(call_id) = event
            .data
            .get("call_id")
            .or_else(|| event.data.get("id"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let identity = (event.turn_id.clone(), call_id.to_owned());
        if !is_generic_recovery_skip_v1(event) {
            if let Some(calls) = pending.get_mut(&identity) {
                calls.pop();
                if calls.is_empty() {
                    pending.remove(&identity);
                }
            }
            continue;
        }

        let turn_id = event
            .turn_id
            .as_deref()
            .expect("the exact generic recovery profile requires turn_id");
        let response_seq = event
            .data
            .get("response_seq")
            .and_then(Value::as_u64)
            .expect("the exact generic recovery profile requires response_seq");
        let tool_name = event
            .data
            .get("tool")
            .and_then(Value::as_str)
            .expect("the exact generic recovery profile requires tool");
        let arguments = event
            .data
            .get("arguments")
            .expect("the exact generic recovery profile requires arguments");
        let owner = pending
            .get(&identity)
            .and_then(|calls| calls.last())
            .copied()
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "generic recovery skip at seq {} has no preceding unstarted Provider call",
                    event.seq
                ))
            })?;
        if owner.response_seq != response_seq
            || owner.tool_name != Some(tool_name)
            || owner.arguments != Some(arguments)
        {
            return Err(OxidraError::Session(format!(
                "generic recovery skip at seq {} does not match its exact durable Provider call",
                event.seq
            )));
        }
        if mcp_calls
            .get(&(turn_id.to_owned(), call_id.to_owned()))
            .is_some_and(|call| call.response_completed_seq == response_seq)
        {
            return Err(OxidraError::Session(format!(
                "generic recovery skip at seq {} cannot settle an MCP-owned Provider call",
                event.seq
            )));
        }
        let calls = pending
            .get_mut(&identity)
            .expect("the exact generic recovery owner was found above");
        calls.pop();
        if calls.is_empty() {
            pending.remove(&identity);
        }
    }
    Ok(())
}

fn generic_tool_lifecycle_identity_v1(event: &JournalEvent) -> Option<(&str, &str)> {
    if !is_tool_lifecycle(&event.kind) {
        return None;
    }
    let turn_id = event.turn_id.as_deref()?;
    let call_id = event
        .data
        .get("call_id")
        .or_else(|| event.data.get("id"))
        .and_then(Value::as_str)?;
    Some((turn_id, call_id))
}

/// MCP-owned response terminals do not repeat the registry claim from their
/// exact `response.started`; bind them to that prior start before deciding
/// whether the generic writer must run the frozen validator.
fn response_terminal_may_belong_to_claimed_mcp_attempt_v1(
    events: &[JournalEvent],
    terminal: &JournalEvent,
) -> bool {
    let terminal_attempt = terminal
        .data
        .get("response_attempt_id")
        .and_then(Value::as_str);
    let mcp_surface_events = mcp_surface_event_seqs_v1(events);
    let surface_protocol_active = mcp_surface_activation_present_v1(events);
    events.iter().any(|event| {
        if event.kind != "response.started"
            || !response_started_references_mcp_surface_v1_with_index(
                &mcp_surface_events,
                surface_protocol_active,
                event,
            )
        {
            return false;
        }
        let attempt = event
            .data
            .get("response_attempt_id")
            .and_then(Value::as_str);
        // If either half of the response identity points at the claimed
        // attempt, keep the terminal on the typed path even when the other
        // half was mutated. The frozen reader must report that mismatch;
        // otherwise the generic writer would persist an event it rejects.
        if terminal_attempt.is_some() && terminal_attempt == attempt {
            return true;
        }
        if terminal.turn_id.is_some() && terminal.turn_id == event.turn_id {
            return true;
        }
        // With both identity fields removed, conservatively reserve a sole
        // claimed attempt. This covers malformed failed/aborted terminals
        // without classifying every generic response terminal in a session.
        terminal_attempt.is_none()
            && terminal.turn_id.is_none()
            && events
                .iter()
                .filter(|candidate| {
                    candidate.kind == "response.started"
                        && response_started_references_mcp_surface_v1_with_index(
                            &mcp_surface_events,
                            surface_protocol_active,
                            candidate,
                        )
                })
                .count()
                == 1
    })
}

fn response_terminal_has_exact_claimed_mcp_start_v1(
    events: &[JournalEvent],
    terminal: &JournalEvent,
) -> bool {
    let Some(turn_id) = terminal.turn_id.as_deref() else {
        return false;
    };
    let Some(response_attempt_id) = terminal
        .data
        .get("response_attempt_id")
        .and_then(Value::as_str)
    else {
        return false;
    };
    let mcp_surface_events = mcp_surface_event_seqs_v1(events);
    let surface_protocol_active = mcp_surface_activation_present_v1(events);
    events.iter().any(|event| {
        event.kind == "response.started"
            && event.turn_id.as_deref() == Some(turn_id)
            && event
                .data
                .get("response_attempt_id")
                .and_then(Value::as_str)
                == Some(response_attempt_id)
            && response_started_references_mcp_surface_v1_with_index(
                &mcp_surface_events,
                surface_protocol_active,
                event,
            )
    })
}

/// Return whether a response start carries MCP ownership either explicitly
/// (v1/v2) or through the v3 relation to a claimed `context.tools` snapshot.
/// The relation is intentionally resolved against the already durable prefix;
/// a caller cannot make the generic writer authoritative by deleting the flat
/// fields while retaining the MCP surface reference.
fn response_started_references_mcp_surface_v1(
    events: &[JournalEvent],
    start: &JournalEvent,
) -> bool {
    response_started_references_mcp_surface_v1_with_index(
        &mcp_surface_event_seqs_v1(events),
        mcp_surface_activation_present_v1(events),
        start,
    )
}

fn response_started_references_mcp_surface_v1_with_index(
    mcp_surface_events: &HashSet<u64>,
    surface_protocol_active: bool,
    start: &JournalEvent,
) -> bool {
    if start.kind != "response.started" {
        return false;
    }
    // Once the durable activation selects v3, every post-activation response
    // is subject to the exact context.tools relation. A malformed or missing
    // relation remains MCP-owned and must be rejected by the typed writer.
    if surface_protocol_active {
        return true;
    }
    if start.data.get("mcp_registry_epoch_id").is_some()
        || start.data.get("mcp_registry_digest").is_some()
        || start.data.get("mcp_surface").is_some()
    {
        return true;
    }
    let Some(tools_event_ref) = start
        .data
        .get("context")
        .and_then(Value::as_object)
        .and_then(|context| context.get("tools_event_seq"))
    else {
        return false;
    };
    let Some(tools_event_seq) = tools_event_ref.as_u64() else {
        // A malformed v3 relation is still MCP-owned once an MCP surface
        // snapshot is present in the durable prefix. Let the frozen reader
        // report the exact relation error instead of allowing a generic
        // writer to persist an event that reader necessarily rejects.
        return !mcp_surface_events.is_empty();
    };
    mcp_surface_events.contains(&tools_event_seq)
}

fn mcp_surface_activation_present_v1(events: &[JournalEvent]) -> bool {
    events.iter().any(|event| {
        event.kind == "mcp.registry.activated"
            && event
                .data
                .get("call_chain_validator_version")
                .and_then(Value::as_u64)
                .is_some_and(|version| version >= 3)
    })
}

fn mcp_activation_present_v1(events: &[JournalEvent]) -> bool {
    events
        .iter()
        .any(|event| event.kind == "mcp.registry.activated")
}

fn mcp_surface_event_seqs_v1(events: &[JournalEvent]) -> HashSet<u64> {
    events
        .iter()
        .filter(|event| {
            event.kind == "context.tools"
                && event.turn_id.is_none()
                && event
                    .data
                    .as_object()
                    .is_some_and(|data| data.contains_key("mcp"))
        })
        .map(|event| event.seq)
        .collect()
}

/// A completed Provider response can carry an activated MCP alias in its
/// canonical output even when an attacker removes the flat response claim.
/// Such a terminal is still an MCP-owned transaction and must not be authored
/// through the generic writer.  This deliberately only recognizes the
/// canonical `output_items` representation; opaque/raw audit fields are not an
/// authority boundary.
fn response_completed_uses_activated_alias_v1(
    events: &[JournalEvent],
    event: &JournalEvent,
) -> bool {
    if event.kind != "response.completed" {
        return false;
    }
    let Some(items) = event.data.get("output_items").and_then(Value::as_array) else {
        return false;
    };
    let mut aliases = HashSet::<&str>::new();
    for activation in events
        .iter()
        .filter(|candidate| candidate.kind == "mcp.registry.activated")
    {
        if let Some(names) = activation
            .data
            .get("provider_names")
            .and_then(Value::as_array)
        {
            aliases.extend(names.iter().filter_map(Value::as_str));
        }
        if let Some(bindings) = activation.data.get("bindings").and_then(Value::as_array) {
            aliases.extend(
                bindings
                    .iter()
                    .filter_map(|binding| binding.get("provider_name").and_then(Value::as_str)),
            );
        }
    }
    !aliases.is_empty()
        && items.iter().any(|item| {
            item.get("type").and_then(Value::as_str) == Some("function_call")
                && item
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| aliases.contains(name))
        })
}

fn pending_tools(events: &[JournalEvent]) -> Vec<InDoubtTool> {
    pending_tools_with_explicit_in_doubt(events).0
}

fn pending_tools_with_explicit_in_doubt(
    events: &[JournalEvent],
) -> (Vec<InDoubtTool>, HashSet<u64>) {
    let mut pending = BTreeMap::<u64, InDoubtTool>::new();
    let mut explicit_in_doubt = HashSet::<u64>::new();
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
                let started_seq = record_in_doubt_tool(event, &mut pending, &mut call_ids);
                explicit_in_doubt.insert(started_seq);
            }
            kind if is_tool_terminal(kind) => {
                if let Some(started_seq) = resolve_tool(event, &mut pending, &mut call_ids) {
                    explicit_in_doubt.remove(&started_seq);
                }
            }
            _ => {}
        }
    }
    (pending.into_values().collect(), explicit_in_doubt)
}

fn pending_tools_for_turn(events: &[JournalEvent], turn_id: &str) -> Vec<InDoubtTool> {
    pending_tools(events)
        .into_iter()
        .filter(|tool| tool.turn_id.as_deref() == Some(turn_id))
        .collect()
}

fn ensure_resolution_matches_pending_v1(
    events: &[JournalEvent],
    resolution: &JournalEvent,
) -> Result<InDoubtTool> {
    let call_id = string_field(&resolution.data, &["call_id", "id"])
        .ok_or_else(|| OxidraError::Session("tool.in_doubt_resolved has no call_id".to_owned()))?;
    let started_seq = resolution.data.get("started_seq").and_then(Value::as_u64);
    let matches = pending_tools(events)
        .into_iter()
        .filter(|tool| tool.turn_id == resolution.turn_id)
        .filter(|tool| tool.call_id.as_deref() == Some(call_id.as_str()))
        .filter(|tool| started_seq.is_none_or(|seq| tool.started_seq == seq))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(OxidraError::Session(format!(
            "tool.in_doubt_resolved does not uniquely match one pending call {call_id}"
        )));
    }
    Ok(matches
        .into_iter()
        .next()
        .expect("one matching pending call"))
}

fn record_in_doubt_tool(
    event: &JournalEvent,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut HashMap<(Option<String>, String), PendingCallSequences>,
) -> u64 {
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
        return started_seq;
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
    started_seq
}

fn resolve_tool(
    event: &JournalEvent,
    pending: &mut BTreeMap<u64, InDoubtTool>,
    call_ids: &mut HashMap<(Option<String>, String), PendingCallSequences>,
) -> Option<u64> {
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
            return Some(started_seq);
        }
        return None;
    }
    if let Some(call_id) = call_id {
        let identity = (event.turn_id.clone(), call_id);
        if let Some(started_seq) = call_ids
            .get_mut(&identity)
            .and_then(PendingCallSequences::latest)
        {
            remove_call_id_seq(call_ids, &identity, started_seq);
            pending.remove(&started_seq);
            return Some(started_seq);
        }
    }
    None
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
/// and unknown or partial profiles fail before recovery writes begin.  The
/// projection is the intent's direct successor; only a final durable intent
/// may be missing that successor after a crash.  A gap followed by any other
/// event is protocol corruption, not authority for retroactive repair.
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
        let expected_seq = intent.failed_seq.checked_add(1).ok_or_else(|| {
            OxidraError::Session(format!(
                "provider context-limit intent sequence is exhausted at seq {}",
                intent.failed_seq
            ))
        })?;
        if event.turn_id.as_deref() != Some(intent.turn_id.as_str()) || event.seq != expected_seq {
            return Err(OxidraError::Session(format!(
                "context.limit_reached at seq {} is not the direct successor of its exact provider context-limit intent",
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
            if events.last().map(|event| event.seq) != Some(intent.failed_seq) {
                return Err(OxidraError::Session(format!(
                    "provider context-limit intent at seq {} is incomplete before the durable journal tail",
                    intent.failed_seq
                )));
            }
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
        // Provider context-limit intent v1 was published against the literal
        // turn-recovery v3 language. Do not route this frozen transaction
        // profile through the movable full-history alias.
        crate::turn::validate_turn_recovery_v3(events).map_err(|error| {
            OxidraError::Session(format!(
                "provider context-limit transaction for turn {turn_id} fails the frozen turn recovery v3 reducer: {error}"
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct InDoubtTurnFinalizationV1 {
    turn_id: String,
    user_message_seq: u64,
}

fn turn_transaction_is_settled_v1(
    events: &[JournalEvent],
    turn_id: &str,
    user_message_seq: u64,
    _json_profile: JournalJsonProfile,
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
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            events,
            turn_id,
        )?;
        if slot == ProviderRequestSlotState::AwaitingTools
            || slot == ProviderRequestSlotState::ResponseInFlight
        {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has terminal-looking state {:?} while Provider request slot is unsettled",
                turn.state
            )));
        }
        return Ok(true);
    }

    let boundary_chain = validate_compaction_boundary_chain(events)?;
    Ok(boundary_chain.pending().iter().any(|boundary| {
        boundary.boundary.turn_id == turn_id
            && boundary.boundary.user_message_seq == user_message_seq
    }))
}

fn recoverable_open_turns_v1(
    events: &[JournalEvent],
    json_profile: JournalJsonProfile,
) -> Result<Vec<RecoverableOpenTurnV1>> {
    if !events.iter().any(|event| event.kind == "user.message") {
        return Ok(Vec::new());
    }
    let turns = segment_turns(events)?;
    if turns.is_empty() {
        return Ok(Vec::new());
    }
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    let pending_boundary_turns = boundary_chain
        .pending()
        .iter()
        .map(|boundary| {
            (
                boundary.boundary.turn_id.clone(),
                boundary.boundary.user_message_seq,
            )
        })
        .collect::<HashSet<_>>();
    let pending_tool_turns = pending_tools(events)
        .into_iter()
        .filter_map(|tool| tool.turn_id)
        .collect::<HashSet<_>>();
    let unstarted_tool_turns = unstarted_tool_calls(events)
        .into_iter()
        .filter_map(|tool| tool.turn_id)
        .collect::<HashSet<_>>();
    let retry_intent_turns = unconsumed_retry_intent_turns_v1(events);
    let mut recoverable = Vec::new();
    for turn in turns {
        if turn.state != TurnState::OpenTail {
            continue;
        }
        let uses_started_lifecycle = turn_uses_started_lifecycle_v1(events, turn.turn_id.as_str());
        if json_profile == JournalJsonProfile::LegacyV1
            && !uses_started_lifecycle
            && legacy_direct_response_tail_is_final_v1(events, turn.turn_id.as_str())
        {
            // Historical direct-response journals did not have the current
            // response.started slot. A final direct assistant response at the
            // physical tail had no explicit completion marker, so leave that
            // ambiguous historical evidence untouched. A direct response that
            // contains function calls is different: once recovery has skipped
            // or settled those calls, the owning turn has no live continuation
            // capability and requires an explicit terminal below.
            continue;
        }
        if pending_boundary_turns.contains(&(turn.turn_id.clone(), turn.covers_from_seq)) {
            continue;
        }
        if retry_intent_turns.contains(&turn.turn_id) {
            continue;
        }
        if pending_tool_turns.contains(&turn.turn_id)
            || unstarted_tool_turns.contains(&turn.turn_id)
        {
            continue;
        }
        // Schema-1 journals predate the durable response.started slot.  A
        // direct response terminal is valid historical evidence, but feeding
        // that prefix to the current slot reducer would claim that the
        // terminal failed to close an attempt that never existed.  Keep the
        // legacy recovery language explicit: only turns which actually use
        // the started/tool lifecycle require the current slot proof.
        if json_profile == JournalJsonProfile::BoundedV2 || uses_started_lifecycle {
            let slot = provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                events,
                &turn.turn_id,
            )?;
            if slot != ProviderRequestSlotState::Ready {
                continue;
            }
        }
        recoverable.push(RecoverableOpenTurnV1 {
            turn_id: turn.turn_id,
            user_message_seq: turn.covers_from_seq,
        });
    }
    Ok(recoverable)
}

fn turn_uses_started_lifecycle_v1(events: &[JournalEvent], turn_id: &str) -> bool {
    events.iter().any(|event| {
        event.turn_id.as_deref() == Some(turn_id)
            && matches!(
                event.kind.as_str(),
                "response.started" | "tool.started" | "tool.in_doubt"
            )
    })
}

fn legacy_direct_response_tail_is_final_v1(events: &[JournalEvent], turn_id: &str) -> bool {
    events
        .iter()
        .rev()
        .find(|event| {
            event.turn_id.as_deref() == Some(turn_id)
                && matches!(
                    event.kind.as_str(),
                    "response.started"
                        | "response.completed"
                        | "response.failed"
                        | "response.aborted"
                )
        })
        .is_some_and(|event| {
            event.kind == "response.completed"
                && !event
                    .data
                    .get("output_items")
                    .or_else(|| {
                        event
                            .data
                            .get("raw_response")
                            .and_then(|response| response.get("output"))
                    })
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().any(|item| {
                            item.get("type").and_then(Value::as_str) == Some("function_call")
                        })
                    })
        })
}

fn unconsumed_retry_intent_turns_v1(events: &[JournalEvent]) -> HashSet<String> {
    let mut latest = HashMap::<String, u64>::new();
    let mut consumed = HashSet::<String>::new();
    for event in events {
        let Some(turn_id) = event.turn_id.as_ref() else {
            continue;
        };
        match event.kind.as_str() {
            "turn.retry_started" => {
                latest.insert(turn_id.clone(), event.seq);
                consumed.remove(turn_id);
            }
            "response.started"
            | "response.completed"
            | "response.failed"
            | "response.aborted"
            | "turn.completed"
            | "turn.cancelled"
            | "turn.abandoned"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached" => {
                if latest.contains_key(turn_id) {
                    consumed.insert(turn_id.clone());
                }
            }
            _ => {}
        }
    }
    latest
        .into_iter()
        .filter_map(|(turn_id, _)| (!consumed.contains(&turn_id)).then_some(turn_id))
        .collect()
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
                    // Retain the exact durable representation for generic and
                    // legacy calls. Reparsing every arguments string here can
                    // allocate a second attacker-sized JSON tree during
                    // reopen. The MCP partition below substitutes the frozen
                    // reader's already-validated canonical Value only for an
                    // actual MCP-owned call.
                    let arguments = item.get("arguments").cloned();
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

/// Partition function calls that have not acquired a durable tool lifecycle
/// edge into MCP-owned and generic/builtin calls.  The MCP recovery marker is
/// an authority for the former only; treating every function call as MCP here
/// would copy builtin arguments into `journal.recovered` and would make the
/// marker claim authority it never received from the registry activation.
///
/// Classification is deliberately derived from the canonical MCP call-chain
/// projection rather than from the tool name.  A name that happens to look
/// like an MCP alias is not enough to mint a recovery authority.
fn partition_unstarted_tools_v1(
    events: &[JournalEvent],
    unstarted: &[UnstartedTool],
) -> Result<(Vec<UnstartedTool>, Vec<UnstartedTool>)> {
    let mcp_calls = crate::mcp::validated_durable_mcp_calls_index(events)?;
    let mut mcp_tools = Vec::new();
    let mut generic_tools = Vec::new();
    for tool in unstarted {
        let Some(turn_id) = tool.turn_id.as_deref() else {
            generic_tools.push(tool.clone());
            continue;
        };
        match mcp_calls.get(&(turn_id.to_owned(), tool.call_id.clone())) {
            Some(call)
                if call.response_completed_seq == tool.response_seq
                    && Some(call.provider_name.as_str()) == tool.tool_name.as_deref() =>
            {
                let mut canonical = tool.clone();
                canonical.arguments = Some(call.arguments.clone());
                mcp_tools.push(canonical);
            }
            Some(_) => {
                return Err(OxidraError::Session(format!(
                    "unstarted tool call {} differs from its durable MCP binding",
                    tool.call_id
                )));
            }
            None => generic_tools.push(tool.clone()),
        }
    }
    Ok((mcp_tools, generic_tools))
}

fn cancellation_skip_data(tool: &UnstartedTool, reason: &str) -> Value {
    skipped_tool_data(tool, reason, "cancelled")
}

const GENERIC_RECOVERY_SKIP_VERSION_V1: u64 = 1;
const GENERIC_RECOVERY_SKIP_REASON_V1: &str = "process stopped before tool.started was committed";
const GENERIC_RECOVERY_SKIP_MESSAGE_V1: &str =
    "tool was not executed: process stopped before tool.started was committed";

/// Generic/builtin recovery has no MCP registry authority.  Reuse the
/// generic cancellation terminal profile, but keep the reason explicit so the
/// audit trail distinguishes process recovery from a user cancellation.
fn generic_recovery_skip_data(tool: &UnstartedTool) -> Value {
    let mut data = cancellation_skip_data(tool, GENERIC_RECOVERY_SKIP_REASON_V1);
    let object = data
        .as_object_mut()
        .expect("generic cancellation data is always an object");
    object.insert(
        "generic_recovery_skip_version".to_owned(),
        Value::from(GENERIC_RECOVERY_SKIP_VERSION_V1),
    );
    object.insert("response_seq".to_owned(), Value::from(tool.response_seq));
    object.insert("recovered".to_owned(), Value::Bool(true));
    data
}

fn is_generic_recovery_skip_v1(event: &JournalEvent) -> bool {
    event.kind == "tool.skipped_due_to_cancel"
        && event
            .data
            .get("generic_recovery_skip_version")
            .and_then(Value::as_u64)
            == Some(GENERIC_RECOVERY_SKIP_VERSION_V1)
        && event.data.get("recovered").and_then(Value::as_bool) == Some(true)
        && event.data.get("reason").and_then(Value::as_str) == Some(GENERIC_RECOVERY_SKIP_REASON_V1)
}

fn plan_generic_recovery_skip_events(
    session_id: &str,
    first_seq: u64,
    tools: &[UnstartedTool],
) -> Result<Vec<JournalEvent>> {
    let mut next_seq = first_seq;
    // Generic lifecycle matching is LIFO for a reused `(turn_id, call_id)`.
    // Emit newer response occurrences first so every complete-line prefix
    // agrees with both the exact v1 binding and the legacy lifecycle reducer.
    let mut ordered = tools.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|tool| std::cmp::Reverse(tool.response_seq));
    ordered
        .into_iter()
        .map(|tool| {
            let event = planned_recovery_event(
                session_id,
                &mut next_seq,
                "tool.skipped_due_to_cancel",
                tool.turn_id.as_deref(),
                generic_recovery_skip_data(tool),
            )?;
            validate_generic_recovery_skip_profile_v1(&event)?;
            Ok(event)
        })
        .collect()
}

fn plan_generic_skip_events_v1(
    session_id: &str,
    first_seq: u64,
    tools: &[UnstartedTool],
    kind: &str,
    reason: &str,
    code: &str,
) -> Result<Vec<JournalEvent>> {
    let mut next_seq = first_seq;
    tools
        .iter()
        .map(|tool| {
            planned_recovery_event(
                session_id,
                &mut next_seq,
                kind,
                tool.turn_id.as_deref(),
                skipped_tool_data(tool, reason, code),
            )
        })
        .collect()
}

fn skipped_tool_data(tool: &UnstartedTool, reason: &str, code: &str) -> Value {
    json!({
        "call_id": tool.call_id,
        "tool": tool.tool_name,
        "arguments": tool.arguments,
        "reason": reason,
        "output": {
            "error": {
                "code": code,
                "message": format!("tool was not executed: {reason}"),
            }
        },
        "is_error": true,
        "error_code": code,
    })
}

/// Compute the durable recovery debt owned by an active turn after a
/// prospective journal event.  A fixed turn reserve is sufficient before a
/// response creates calls, but it is not sufficient once the response has
/// created a wide/large batch: recovery must then retain a marker, every
/// authorized skip, and (when no tool has started) the recovered turn
/// terminal.  The estimate is intentionally conservative for crash metadata
/// so every complete-line prefix remains reopenable.
fn active_turn_recovery_headroom_v1(
    session_id: &str,
    events: &[JournalEvent],
    turn_id: &str,
    user_message_seq: u64,
) -> Result<u64> {
    let unstarted = unstarted_tool_calls(events)
        .into_iter()
        .filter(|tool| tool.turn_id.as_deref() == Some(turn_id))
        .collect::<Vec<_>>();
    let (mcp_unstarted, generic_unstarted) = partition_unstarted_tools_v1(events, &unstarted)?;
    let in_doubt = pending_tools_for_turn(events, turn_id);
    if unstarted.is_empty() && in_doubt.is_empty() {
        return Ok(0);
    }
    let resolution_headroom =
        in_doubt_transaction_headroom_v1(session_id, events, &in_doubt, &mcp_unstarted)?;

    let mut recovery = RecoveryInfo {
        // A crash may leave a truncated final line.  Use maximum-width values
        // here so the live reservation is not smaller than the reopen marker.
        truncated_tail: Some(TruncatedTail {
            byte_count: u64::MAX,
            sha256: "f".repeat(64),
        }),
        normalized_missing_newline: false,
        in_doubt,
        marker_seq: None,
        skipped_before_start: unstarted.len(),
        aborted_responses: usize::MAX,
        aborted_compactions: usize::MAX,
        failed_compaction_boundaries: usize::MAX,
        checkpointed_compaction_boundaries: usize::MAX,
        recovered_provider_context_limits: 0,
        cancelled_turns: usize::MAX,
    };
    let next_seq = events
        .last()
        .map(|event| {
            event
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))
        })
        .transpose()?
        .unwrap_or(1);
    let marker_required_without_tools = true;
    let mut recovery_events = plan_mcp_recovery_events(
        session_id,
        next_seq,
        &mut recovery,
        &mcp_unstarted,
        marker_required_without_tools,
        None,
    )?;
    let generic_seq = recovery_events
        .last()
        .map(|event| {
            event
                .seq
                .checked_add(1)
                .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))
        })
        .transpose()?
        .unwrap_or(next_seq);
    recovery_events.extend(plan_generic_recovery_skip_events(
        session_id,
        generic_seq,
        &generic_unstarted,
    )?);
    let mut prospective = events.to_vec();
    prospective.extend(recovery_events.iter().cloned());
    if recovery.in_doubt.is_empty() && !unstarted.is_empty() {
        let next = recovery_events
            .last()
            .map(|event| {
                event
                    .seq
                    .checked_add(1)
                    .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))
            })
            .transpose()?
            .unwrap_or(next_seq);
        let mut cancelled_seq = next;
        let cancelled = planned_recovery_event(
            session_id,
            &mut cancelled_seq,
            "turn.cancelled",
            Some(turn_id),
            json!({
                "reason": "process stopped before the user turn acquired a durable outcome owner",
                "user_message_seq": user_message_seq,
                "turn_outcome_admission_version": 1,
                "recovered": true,
            }),
        )?;
        recovery_events.push(cancelled.clone());
        prospective.push(cancelled);
    }

    validate_generic_recovery_skips_v1(&prospective)?;
    let slot = provider_request_slot_state_for_version(
        PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
        &prospective,
        turn_id,
    )?;
    if recovery.in_doubt.is_empty() {
        if slot != ProviderRequestSlotState::Terminal {
            return Err(OxidraError::Session(format!(
                "planned turn recovery leaves Provider request slot in state {slot:?}"
            )));
        }
    } else if slot != ProviderRequestSlotState::AwaitingTools {
        return Err(OxidraError::Session(format!(
            "planned in-doubt recovery leaves Provider request slot in state {slot:?}"
        )));
    }
    let bytes = encoded_journal_events_bytes(&recovery_events)?;
    TURN_OUTCOME_HEADROOM_BYTES_V1
        .checked_add(bytes)
        .and_then(|size| size.checked_add(resolution_headroom))
        .ok_or_else(|| OxidraError::Session("turn recovery debt overflow".to_owned()))
}

/// Return the recovery debt that remains after one MCP tool terminal.  This is
/// intentionally shared by pre-dispatch admission and terminal commit: the
/// former must reserve the same post-terminal state that the latter will
/// actually consume, rather than guessing from the current global pending set.
fn mcp_tool_terminal_residual_headroom_v1(
    session_id: &str,
    events: &[JournalEvent],
    active_turn: Option<&ActiveTurnReservationV1>,
) -> Result<u64> {
    let pending = pending_tools(events);
    let unstarted = unstarted_tool_calls(events);
    let (mcp_unstarted, _generic_unstarted) = partition_unstarted_tools_v1(events, &unstarted)?;
    let mut residual =
        in_doubt_transaction_headroom_v1(session_id, events, &pending, &mcp_unstarted)?;
    if let Some(active_turn) = active_turn {
        let turn_headroom = TURN_OUTCOME_HEADROOM_BYTES_V1.max(active_turn_recovery_headroom_v1(
            session_id,
            events,
            &active_turn.turn_id,
            active_turn.user_message_seq,
        )?);
        residual = residual.max(turn_headroom);
    }
    Ok(residual)
}

/// Build a valid, bounded-shape terminal for admission accounting.  The
/// payload is not written; it only lets the reservation calculate the exact
/// recovery state after each frozen immediate-outcome branch.
fn planned_mcp_tool_terminal_profile_v1(
    session_id: &str,
    started: &JournalEvent,
    kind: &str,
) -> Result<JournalEvent> {
    let turn_id = started.turn_id.as_deref().ok_or_else(|| {
        OxidraError::Session("MCP tool.started profile has no turn_id".to_owned())
    })?;
    let call_id = started.data.get("call_id").cloned().ok_or_else(|| {
        OxidraError::Session("MCP tool.started profile has no call_id".to_owned())
    })?;
    let tool =
        started.data.get("tool").cloned().ok_or_else(|| {
            OxidraError::Session("MCP tool.started profile has no tool".to_owned())
        })?;
    let coordinator_version = started
        .data
        .get("mcp")
        .and_then(Value::as_object)
        .and_then(|provenance| provenance.get("execution_coordinator_version"))
        .and_then(Value::as_u64);
    let mut data = match kind {
        // Coordinator v4 freezes a two-view success terminal: the raw MCP
        // result remains audit-only and `output` is its exact model-facing
        // projection.  Admission accounting must use a terminal the v4
        // reader would actually accept; the legacy raw-less `{ok:true}`
        // placeholder would make every prospective `tool.started` fail.
        "tool.completed" if coordinator_version == Some(4) => json!({
            "started_seq": started.seq,
            "call_id": call_id,
            "tool": tool,
            "output": {
                "profile_version": crate::mcp::MCP_MODEL_OUTPUT_PROFILE_VERSION_V1,
                "trust": crate::mcp::MCP_MODEL_OUTPUT_TRUST_V1,
                "is_error": false,
                "content": [""],
            },
            "mcp_raw_result": {
                "content": [{"type":"text", "text":""}],
                "isError": false,
            },
            "is_error": false,
            "error_code": Value::Null,
            "before_dispatch": false,
        }),
        "tool.completed" => json!({
            "started_seq": started.seq,
            "call_id": call_id,
            "tool": tool,
            "output": {"ok": true},
            "is_error": false,
            "error_code": Value::Null,
            "before_dispatch": false,
        }),
        "tool.in_doubt" => json!({
            "started_seq": started.seq,
            "call_id": call_id,
            "tool": tool,
            "output": {"error": {"code": "in_doubt", "message": "unknown"}},
            "is_error": true,
            "error_code": "in_doubt",
            "before_dispatch": false,
        }),
        "tool.cancelled" => json!({
            "started_seq": started.seq,
            "call_id": call_id,
            "tool": tool,
            "output": {"error": {"code": "cancelled", "message": "cancelled"}},
            "is_error": true,
            "error_code": "cancelled",
            "before_dispatch": true,
        }),
        _ => {
            return Err(OxidraError::Session(
                "unsupported MCP terminal profile".to_owned(),
            ));
        }
    };
    if let Some(provenance) = started.data.get("mcp") {
        data["mcp"] = provenance.clone();
    }
    let mut next_seq = started
        .seq
        .checked_add(1)
        .ok_or_else(|| OxidraError::Session("journal sequence exhausted".to_owned()))?;
    planned_recovery_event(session_id, &mut next_seq, kind, Some(turn_id), data)
}

/// Compute the complete durable reserve required before an MCP process is
/// allowed to run.  A crash immediately after `tool.started` and every
/// bounded live terminal branch are separate valid prefixes; the reserve must
/// cover the worst of them, with terminal bytes added to the debt that remains
/// after that branch.
fn mcp_tool_dispatch_required_headroom_v1(
    session_id: &str,
    events_after_started: &mut Vec<JournalEvent>,
    started: &JournalEvent,
    active_turn: Option<&ActiveTurnReservationV1>,
) -> Result<u64> {
    let crash_debt =
        mcp_tool_terminal_residual_headroom_v1(session_id, events_after_started, active_turn)?;
    let prior_debt = active_turn.map_or(0, |turn| turn.headroom_bytes);
    let mut required = crash_debt.max(prior_debt);

    for kind in ["tool.completed", "tool.cancelled", "tool.in_doubt"] {
        let terminal = planned_mcp_tool_terminal_profile_v1(session_id, started, kind)?;
        events_after_started.push(terminal);
        let branch_result = (|| {
            crate::mcp::validate_mcp_call_chain(events_after_started)?;
            mcp_tool_terminal_residual_headroom_v1(session_id, events_after_started, active_turn)
        })();
        events_after_started.pop();
        let residual = branch_result?;
        let branch_debt = MCP_TOOL_OUTCOME_HEADROOM_BYTES_V1
            .checked_add(residual)
            .ok_or_else(|| {
                OxidraError::Session("MCP tool outcome recovery debt overflow".to_owned())
            })?;
        required = required.max(branch_debt);
    }
    Ok(required)
}

fn in_doubt_resolution_headroom_v1(session_id: &str, tools: &[InDoubtTool]) -> Result<u64> {
    tools.iter().try_fold(0u64, |total, tool| {
        total
            .checked_add(in_doubt_resolution_slot_headroom_v1(session_id, tool)?)
            .ok_or_else(|| OxidraError::Session("in-doubt resolution debt overflow".to_owned()))
    })
}

fn in_doubt_resolution_identities(
    tools: &[InDoubtTool],
) -> Vec<(u64, Option<String>, Option<String>)> {
    let mut identities = tools
        .iter()
        .map(|tool| (tool.started_seq, tool.turn_id.clone(), tool.call_id.clone()))
        .collect::<Vec<_>>();
    identities.sort();
    identities
}

fn in_doubt_turn_finalizations_v1(
    events: &[JournalEvent],
    tools: &[InDoubtTool],
) -> Result<Vec<InDoubtTurnFinalizationV1>> {
    let mut turn_ids = tools
        .iter()
        .filter_map(|tool| tool.turn_id.clone())
        .collect::<HashSet<_>>();
    let canonical_turn_ids = events
        .iter()
        .filter(|event| event.kind == "user.message")
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();
    turn_ids.retain(|turn_id| canonical_turn_ids.contains(turn_id));
    if turn_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Older journals may contain standalone tool lifecycle events with a
    // turn_id but no corresponding user.message.  Exclude those unrelated
    // records before invoking the canonical turn segmenter.
    let scoped_events = events
        .iter()
        .filter(|event| {
            event.turn_id.is_none()
                || event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| canonical_turn_ids.contains(turn_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    let turns = segment_turns(&scoped_events)?;
    let mut finalizations = Vec::new();
    let mut ordered_turn_ids = turn_ids.drain().collect::<Vec<_>>();
    ordered_turn_ids.sort();
    for turn_id in ordered_turn_ids {
        let Some(turn) = turns.iter().find(|turn| turn.turn_id == turn_id) else {
            // Legacy journals may contain a standalone tool lifecycle without
            // a user turn.  It still gets an in-doubt resolution slot, but no
            // parent turn terminal can be invented for it.
            continue;
        };
        if !matches!(turn.state, TurnState::InDoubt | TurnState::OpenTail) {
            return Err(OxidraError::Session(format!(
                "in-doubt turn {turn_id} is in non-finalizable state {:?}",
                turn.state
            )));
        }
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            events,
            &turn_id,
        )?;
        if slot != ProviderRequestSlotState::AwaitingTools {
            return Err(OxidraError::Session(format!(
                "in-doubt turn {turn_id} is not awaiting tool resolution (slot {slot:?})"
            )));
        }
        finalizations.push(InDoubtTurnFinalizationV1 {
            turn_id,
            user_message_seq: turn.covers_from_seq,
        });
    }
    Ok(finalizations)
}

fn in_doubt_resolution_data_v1(tool: &InDoubtTool) -> Result<Value> {
    let call_id = tool
        .call_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "cannot resolve in-doubt tool at seq {} without a call_id",
                tool.started_seq
            ))
        })?;
    Ok(json!({
        "started_seq": tool.started_seq,
        "call_id": call_id,
        "tool": tool.tool_name.as_deref().unwrap_or("unknown"),
        "output": {
            "error": {
                "code": "in_doubt",
                "message": "tool side effects were unknown after interruption; user inspected the state and chose to continue treating the call as failed"
            }
        },
        "is_error": true,
        "error_code": "in_doubt",
        "resolution": "user_treated_as_failed",
    }))
}

fn in_doubt_turn_terminal_data_v1(turn: &InDoubtTurnFinalizationV1) -> Value {
    json!({
        "reason": "in-doubt tool calls were resolved as failed after user inspection",
        "user_message_seq": turn.user_message_seq,
        "turn_outcome_admission_version": 1,
        "in_doubt_resolution_version": 1,
    })
}

fn in_doubt_future_marker_headroom_v1(
    session_id: &str,
    events: &[JournalEvent],
    tools: &[InDoubtTool],
    unstarted_tools: &[UnstartedTool],
) -> Result<u64> {
    // Once recovery has durably recorded a marker for this in-doubt lineage,
    // that marker remains valid while resolutions monotonically shrink the
    // pending set.  Requiring a fresh marker for every crash-prefix subset
    // creates recursive debt: after writing marker(B), the reopened handle
    // would have to reserve marker(B) again before resolving B.  A large
    // remaining call can then require twice the originally reserved marker
    // bytes and make a legal partial resolution impossible to reopen.
    if unstarted_tools.is_empty()
        && !tools.is_empty()
        && recovery_marker_covers_current_in_doubt_v1(events, tools)
    {
        return Ok(0);
    }
    let recovery = RecoveryInfo {
        truncated_tail: Some(TruncatedTail {
            byte_count: u64::MAX,
            sha256: "f".repeat(64),
        }),
        normalized_missing_newline: false,
        in_doubt: tools.to_vec(),
        marker_seq: None,
        skipped_before_start: usize::MAX,
        aborted_responses: usize::MAX,
        aborted_compactions: usize::MAX,
        failed_compaction_boundaries: usize::MAX,
        checkpointed_compaction_boundaries: usize::MAX,
        recovered_provider_context_limits: 0,
        cancelled_turns: usize::MAX,
    };
    let chunks = if unstarted_tools.is_empty() {
        vec![unstarted_tools]
    } else {
        unstarted_tools.chunks(MAX_MCP_CALLS_PER_RESPONSE).collect()
    };
    // A crash can occur after a marker line but before any of its skips.  On
    // reopen the remaining authorization set may therefore need to be
    // re-framed into every original chunk again.  Reserve the sum rather than
    // just the largest single marker so legacy batches spanning multiple
    // 4096-call chunks remain fail-closed at the byte limit.
    let mut total = 0u64;
    for chunk in chunks {
        let marker = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: u64::MAX,
            ts: chrono::DateTime::<Utc>::from_timestamp(0, 0)
                .expect("the Unix epoch is a valid UTC timestamp"),
            kind: RECOVERY_KIND.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data: recovery_marker_data(&recovery, chunk)?,
        };
        let marker_bytes = encoded_journal_events_bytes(std::slice::from_ref(&marker))?;
        total = total.checked_add(marker_bytes).ok_or_else(|| {
            OxidraError::Session("in-doubt recovery marker debt overflow".to_owned())
        })?;
    }
    total
        .checked_add(IN_DOUBT_RESOLUTION_ENVELOPE_MARGIN_BYTES_V1)
        .ok_or_else(|| OxidraError::Session("in-doubt recovery marker debt overflow".to_owned()))
}

fn in_doubt_transaction_headroom_v1(
    session_id: &str,
    events: &[JournalEvent],
    tools: &[InDoubtTool],
    unstarted_tools: &[UnstartedTool],
) -> Result<u64> {
    if tools.is_empty() && unstarted_tools.is_empty() {
        return Ok(0);
    }
    let resolutions = in_doubt_resolution_headroom_v1(session_id, tools)?;
    let finalizations = in_doubt_turn_finalizations_v1(events, tools)?;
    let parent_terminals = (finalizations.len() as u64)
        .checked_mul(TURN_OUTCOME_HEADROOM_BYTES_V1)
        .ok_or_else(|| OxidraError::Session("in-doubt parent terminal debt overflow".to_owned()))?;
    let marker = in_doubt_future_marker_headroom_v1(session_id, events, tools, unstarted_tools)?;
    resolutions
        .checked_add(parent_terminals)
        .and_then(|size| size.checked_add(marker))
        .ok_or_else(|| OxidraError::Session("in-doubt transaction debt overflow".to_owned()))
}

/// Size the canonical v1 resolution event for one pending call.  The durable
/// call identity is intentionally preserved verbatim; because historical
/// readers do not impose a small call-id/tool-name limit, the slot must grow
/// with those fields rather than making a fixed-size promise that can strand a
/// valid session.  The margin absorbs timestamp/JSON envelope variance.
fn in_doubt_resolution_slot_headroom_v1(session_id: &str, tool: &InDoubtTool) -> Result<u64> {
    let event = JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq: u64::MAX,
        // A fixed timestamp keeps the reservation byte-exact across reopen
        // and later consumption.  The separate envelope margin covers the
        // longer live RFC 3339 representation.
        ts: chrono::DateTime::<Utc>::from_timestamp(0, 0)
            .expect("the Unix epoch is a valid UTC timestamp"),
        kind: "tool.in_doubt_resolved".to_owned(),
        session_id: session_id.to_owned(),
        turn_id: tool.turn_id.clone(),
        data: in_doubt_resolution_data_v1(tool)?,
    };
    let encoded = u64::try_from(encode_journal_event_v2(&event)?.len())
        .map_err(|_| OxidraError::Session("in-doubt resolution event is too large".to_owned()))?;
    encoded
        .checked_add(1)
        .and_then(|size| size.checked_add(IN_DOUBT_RESOLUTION_ENVELOPE_MARGIN_BYTES_V1))
        .map(|size| size.max(MIN_IN_DOUBT_RESOLUTION_HEADROOM_BYTES_V1))
        .ok_or_else(|| OxidraError::Session("in-doubt resolution debt overflow".to_owned()))
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
        let event_len = u64::try_from(encode_journal_event_v2(event)?.len())
            .map_err(|_| OxidraError::Session("journal event is too large".to_owned()))?;
        total
            .checked_add(event_len)
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| OxidraError::Session("journal transaction size overflow".to_owned()))
    })
}

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

fn recovery_authorization_index(events: &[JournalEvent]) -> Result<HashMap<String, u64>> {
    let mut index = HashMap::new();
    for event in events.iter().filter(|event| event.kind == RECOVERY_KIND) {
        // Reuse only the frozen v1 authorization profile.  A marker without
        // this version (or with a future/legacy version) may still be useful
        // as historical audit data, but it is not an authority that a new
        // recovery skip can safely reference.
        if event.turn_id.is_some()
            || event
                .data
                .get("tool_skip_authorization_version")
                .and_then(Value::as_u64)
                != Some(1)
            || event.seq == 0
        {
            continue;
        }
        let skipped_before_start = event
            .data
            .get("skipped_before_start")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if skipped_before_start == 0 {
            continue;
        }
        let Some(authorizations) = event
            .data
            .get("unstarted_tool_calls")
            .and_then(Value::as_array)
        else {
            continue;
        };
        if authorizations.is_empty()
            || authorizations.len() > MAX_MCP_CALLS_PER_RESPONSE
            || (authorizations.len() as u64) > skipped_before_start
        {
            continue;
        }

        // Validate the canonical fields before indexing.  The MCP reducer
        // performs the same checks when a skip references this marker; doing
        // them here prevents an invalid historical marker from being reused
        // and turning a recoverable prefix into a validator failure.
        let mut seen = HashSet::<(u64, String, String, String, String)>::new();
        let mut keys = Vec::with_capacity(authorizations.len());
        let mut valid = true;
        for authorization in authorizations {
            let Some(response_seq) = authorization.get("response_seq").and_then(Value::as_u64)
            else {
                valid = false;
                break;
            };
            // The frozen reducer requires the recovery authority to be
            // durably recorded after the response that created the call.  An
            // otherwise well-formed, unused historical marker is not rejected
            // until a skip references it, so do not let such a forward claim
            // poison a repair that could instead mint a new valid marker.
            if response_seq == 0 || event.seq <= response_seq {
                valid = false;
                break;
            }
            let Some(turn_id) = authorization.get("turn_id").and_then(Value::as_str) else {
                valid = false;
                break;
            };
            let Some(call_id) = authorization.get("call_id").and_then(Value::as_str) else {
                valid = false;
                break;
            };
            let Some(provider_name) = authorization.get("tool").and_then(Value::as_str) else {
                valid = false;
                break;
            };
            let Some(arguments_sha256) = authorization
                .get("arguments_sha256")
                .and_then(Value::as_str)
            else {
                valid = false;
                break;
            };
            if !valid_recovery_identity_v1(turn_id)
                || !valid_recovery_identity_v1(call_id)
                || !valid_recovery_provider_name_v1(provider_name)
                || !valid_recovery_sha256_v1(arguments_sha256)
            {
                valid = false;
                break;
            }
            let canonical = (
                response_seq,
                turn_id.to_owned(),
                call_id.to_owned(),
                provider_name.to_owned(),
                arguments_sha256.to_owned(),
            );
            if !seen.insert(canonical) {
                valid = false;
                break;
            }
            keys.push(serde_json::to_string(authorization)?);
        }
        if !valid {
            continue;
        }
        for key in keys {
            index.entry(key).or_insert(event.seq);
        }
    }
    Ok(index)
}

fn valid_recovery_identity_v1(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_recovery_provider_name_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_recovery_sha256_v1(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn recovered_in_doubt_data_v1(tool: &InDoubtTool) -> Result<Value> {
    let mut data = tool.data.as_object().cloned().ok_or_else(|| {
        OxidraError::Session(format!(
            "tool.started at seq {} has no object payload for in-doubt recovery",
            tool.started_seq
        ))
    })?;
    // `tool.started` owns the arguments.  A post-start terminal instead uses
    // the frozen exact outer profile and carries only the copied provenance
    // plus the terminal fields below.
    data.remove("arguments");
    data.insert("started_seq".to_owned(), Value::from(tool.started_seq));
    if let Some(call_id) = &tool.call_id {
        data.insert("call_id".to_owned(), Value::String(call_id.clone()));
    }
    if let Some(tool_name) = &tool.tool_name {
        data.insert("tool".to_owned(), Value::String(tool_name.clone()));
    }
    data.insert(
        "output".to_owned(),
        json!({
            "error": {
                "code": "in_doubt",
                "message": "the previous process stopped after tool.started and before a validated complete result"
            }
        }),
    );
    data.insert("is_error".to_owned(), Value::Bool(true));
    data.insert(
        "error_code".to_owned(),
        Value::String("in_doubt".to_owned()),
    );
    data.insert("before_dispatch".to_owned(), Value::Bool(false));
    Ok(Value::Object(data))
}

fn plan_mcp_recovery_events(
    session_id: &str,
    first_seq: u64,
    recovery: &mut RecoveryInfo,
    unstarted_tools: &[UnstartedTool],
    marker_required_without_tools: bool,
    existing_authorizations: Option<&HashMap<String, u64>>,
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
            let authorizations = recovery_authorizations(tools)?;
            let reusable_marker_seqs = existing_authorizations.and_then(|index| {
                let mut seqs = Vec::with_capacity(authorizations.len());
                for authorization in &authorizations {
                    let key = serde_json::to_string(authorization).ok()?;
                    seqs.push(*index.get(&key)?);
                }
                Some(seqs)
            });
            if reusable_marker_seqs.is_none() {
                let marker = planned_recovery_event(
                    session_id,
                    &mut next_seq,
                    RECOVERY_KIND,
                    None,
                    recovery_marker_data(recovery, tools)?,
                )?;
                recovery.marker_seq = Some(marker.seq);
                events.push(marker);
            }
            for (index, tool) in tools.iter().enumerate() {
                let marker_seq = reusable_marker_seqs
                    .as_ref()
                    .and_then(|seqs| seqs.get(index).copied())
                    .or(recovery.marker_seq)
                    .ok_or_else(|| {
                        OxidraError::Session("recovery skip has no marker authorization".to_owned())
                    })?;
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

    let expected_fingerprints = sorted_in_doubt_fingerprints(&recovery.in_doubt);
    let expected_max_started_seq = recovery
        .in_doubt
        .iter()
        .map(|tool| tool.started_seq)
        .max()
        .unwrap_or_default();
    let mut pending = BTreeMap::<u64, InDoubtTool>::new();
    let mut call_ids = HashMap::<(Option<String>, String), PendingCallSequences>::new();
    let mut matching_seq = None;
    for event in events {
        if event.kind == RECOVERY_KIND {
            let marked = event
                .data
                .get("in_doubt")
                .cloned()
                .and_then(|value| serde_json::from_value::<Vec<InDoubtTool>>(value).ok());
            if let Some(marked) = marked {
                let pending_lineage = if recovery.in_doubt.is_empty() {
                    marked.is_empty()
                } else {
                    recovery_marker_matches_pending_v1(
                        event,
                        &pending,
                        &recovery.in_doubt,
                        &expected_fingerprints,
                        expected_max_started_seq,
                    )
                };
                let marked_fingerprints = sorted_in_doubt_fingerprints(&marked);
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
                    .unwrap_or_default()
                    as usize;
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
                let counts_match = marked_skipped == recovery.skipped_before_start
                    && marked_aborted == recovery.aborted_responses
                    && marked_aborted_compactions == recovery.aborted_compactions
                    && marked_failed_compaction_boundaries == recovery.failed_compaction_boundaries
                    && marked_checkpointed_compaction_boundaries
                        == recovery.checkpointed_compaction_boundaries
                    && marked_cancelled_turns == recovery.cancelled_turns;
                if counts_match && (pending_lineage || marked_fingerprints == expected_fingerprints)
                {
                    matching_seq = Some(event.seq);
                }
            }
        }
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
    matching_seq
}

/// Scan the journal once while maintaining the pending-call state.  The old
/// implementation re-ran `pending_tools` for every historical marker, making
/// a long sequence of recovery markers quadratic during reopen.
fn recovery_marker_covers_current_in_doubt_v1(
    events: &[JournalEvent],
    expected_tools: &[InDoubtTool],
) -> bool {
    if expected_tools.is_empty() {
        return false;
    }
    let expected_fingerprints = sorted_in_doubt_fingerprints(expected_tools);
    let expected_max_started_seq = expected_tools
        .iter()
        .map(|tool| tool.started_seq)
        .max()
        .unwrap_or_default();
    let mut pending = BTreeMap::<u64, InDoubtTool>::new();
    let mut call_ids = HashMap::<(Option<String>, String), PendingCallSequences>::new();
    for event in events {
        if event.kind == RECOVERY_KIND
            && recovery_marker_matches_pending_v1(
                event,
                &pending,
                expected_tools,
                &expected_fingerprints,
                expected_max_started_seq,
            )
        {
            return true;
        }
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
    false
}

fn recovery_marker_matches_pending_v1(
    event: &JournalEvent,
    pending: &BTreeMap<u64, InDoubtTool>,
    expected_tools: &[InDoubtTool],
    expected_fingerprints: &[String],
    expected_max_started_seq: u64,
) -> bool {
    if event.kind != RECOVERY_KIND
        || event.turn_id.is_some()
        || expected_tools.is_empty()
        || event
            .data
            .get("in_doubt_resolution_authorization_version")
            .and_then(Value::as_u64)
            != Some(IN_DOUBT_RESOLUTION_AUTHORIZATION_VERSION_V1)
    {
        return false;
    }
    if event.seq <= expected_max_started_seq {
        return false;
    }
    let Some(marked) = event.data.get("in_doubt").cloned() else {
        return false;
    };
    let Ok(mut marked) = serde_json::from_value::<Vec<InDoubtTool>>(marked) else {
        return false;
    };
    if marked.len() != pending.len() {
        return false;
    }
    marked.sort_by_key(|tool| tool.started_seq);
    if !marked
        .iter()
        .zip(pending.values())
        .all(|(marked, durable)| marked == durable)
    {
        return false;
    }
    let marked_fingerprints = sorted_in_doubt_fingerprints(&marked);
    sorted_keys_are_subset(expected_fingerprints, &marked_fingerprints)
}

#[cfg(test)]
fn recovery_marker_covers_in_doubt_v1(
    events: &[JournalEvent],
    marker_index: usize,
    expected_tools: &[InDoubtTool],
) -> bool {
    let Some(event) = events.get(marker_index) else {
        return false;
    };
    if event.kind != RECOVERY_KIND || event.turn_id.is_some() || expected_tools.is_empty() {
        return false;
    }
    if event
        .data
        .get("in_doubt_resolution_authorization_version")
        .and_then(Value::as_u64)
        != Some(IN_DOUBT_RESOLUTION_AUTHORIZATION_VERSION_V1)
    {
        return false;
    }
    if expected_tools
        .last()
        .is_some_and(|tool| event.seq <= tool.started_seq)
    {
        return false;
    }
    let Some(marked) = event.data.get("in_doubt").cloned() else {
        return false;
    };
    let Ok(mut marked) = serde_json::from_value::<Vec<InDoubtTool>>(marked) else {
        return false;
    };
    let mut durable_at_marker = pending_tools(&events[..marker_index]);
    marked.sort_by_key(|tool| tool.started_seq);
    durable_at_marker.sort_by_key(|tool| tool.started_seq);
    if marked != durable_at_marker {
        return false;
    }
    let marked_fingerprints = sorted_in_doubt_fingerprints(&marked);
    let expected_fingerprints = sorted_in_doubt_fingerprints(expected_tools);
    sorted_keys_are_subset(&expected_fingerprints, &marked_fingerprints)
}

fn sorted_keys_are_subset<T: Ord>(subset: &[T], superset: &[T]) -> bool {
    let mut superset_index = 0usize;
    for expected in subset {
        while superset
            .get(superset_index)
            .is_some_and(|candidate| candidate < expected)
        {
            superset_index += 1;
        }
        if superset.get(superset_index) != Some(expected) {
            return false;
        }
        superset_index += 1;
    }
    true
}

fn sorted_in_doubt_fingerprints(tools: &[InDoubtTool]) -> Vec<String> {
    let mut fingerprints = tools
        .iter()
        .map(|tool| {
            canonicalize_session_json_v1(&json!({
                "started_seq": tool.started_seq,
                "turn_id": tool.turn_id,
                "call_id": tool.call_id,
                "tool": tool.tool_name,
                "arguments": tool.arguments,
                "data": tool.data,
            }))
        })
        .map(|value| serde_json::to_string(&value).unwrap_or_default())
        .collect::<Vec<_>>();
    fingerprints.sort();
    fingerprints
}

fn canonicalize_session_json_v1(value: &Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(canonicalize_session_json_v1).collect())
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_session_json_v1(&object[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
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
    if !recovery.in_doubt.is_empty() {
        data["in_doubt_resolution_authorization_version"] =
            Value::from(IN_DOUBT_RESOLUTION_AUTHORIZATION_VERSION_V1);
    }
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

    fn nested_object_value(depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            let mut object = Map::new();
            object.insert("child".to_owned(), value);
            value = Value::Object(object);
        }
        value
    }

    fn write_legacy_session_started(
        store: &SessionStore,
        session_id: &str,
        data: Value,
    ) -> Vec<u8> {
        let event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 1,
            ts: Utc::now(),
            kind: SESSION_STARTED_KIND.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data,
        };
        // Deliberately bypass the current bounded encoder: this helper models
        // a durable schema-1 prefix produced by the historical writer.
        let mut bytes = serde_json::to_vec(&event).expect("encode legacy session header");
        bytes.push(b'\n');
        let path = store.layout().journal_path(session_id).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::create_dir_all(store.layout().artifact_dir(session_id).unwrap()).unwrap();
        bytes
    }

    fn bounded_event_line(session_id: &str, seq: u64, data: Value) -> Vec<u8> {
        encode_journal_event_v2(&JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: "custom.fixture".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data,
        })
        .unwrap()
    }

    fn cheap_custom_event_metrics() -> JournalJsonMetricsV2 {
        let event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 1,
            ts: Utc::now(),
            kind: "custom.budget".to_owned(),
            session_id: "budget".to_owned(),
            turn_id: None,
            data: Value::Null,
        };
        encode_journal_event_with_metrics_v2(&event).unwrap().1
    }

    fn admit_test_turn(journal: &mut SessionJournal, turn_id: &str) -> TurnTransactionAdmissionV1 {
        journal
            .append_user_message_with_turn_admission_v1(
                turn_id,
                json!({
                    "item":{"role":"user","content":"hello"},
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap()
    }

    fn generic_function_call_event(
        session_id: &str,
        seq: u64,
        turn_id: &str,
        call_id: &str,
        tool: &str,
        arguments: Value,
    ) -> JournalEvent {
        JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: "response.completed".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data: json!({
                "output_items":[{
                    "type":"function_call",
                    "call_id":call_id,
                    "name":tool,
                    "arguments":arguments,
                }]
            }),
        }
    }

    fn generic_recovery_skip_event(
        session_id: &str,
        seq: u64,
        response_seq: u64,
        turn_id: &str,
        call_id: &str,
        tool: &str,
        arguments: Value,
    ) -> JournalEvent {
        let tool = UnstartedTool {
            response_seq,
            turn_id: Some(turn_id.to_owned()),
            call_id: call_id.to_owned(),
            tool_name: Some(tool.to_owned()),
            arguments: Some(arguments),
        };
        JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: "tool.skipped_due_to_cancel".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data: generic_recovery_skip_data(&tool),
        }
    }

    fn append_test_mcp_activation_v2(
        journal: &mut SessionJournal,
    ) -> (&'static str, &'static str, &'static str) {
        let epoch = "0190f5e6-7b00-7abc-8000-000000000202";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let provider_name = "mcp_fixture_echo_deadbeef";
        journal
            .append_mcp_event_and_sync_v1(
                "mcp.registry.activated",
                None,
                json!({
                    "coordinator_version":2,
                    "call_chain_validator_version":2,
                    "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000201",
                    "registry_epoch_id":epoch,
                    "registry_version":1,
                    "stdio_kernel_version":1,
                    "schema_profile_version":1,
                    "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "registry_digest":digest,
                    "bindings":[{
                        "provider_name":provider_name,
                        "server_name":"fixture",
                        "raw_tool_name":"echo",
                        "protocol_version":"2026-07-28",
                    }],
                }),
            )
            .unwrap();
        (epoch, digest, provider_name)
    }

    fn test_mcp_provenance_v2(epoch: &str, digest: &str, arguments: &Value) -> Value {
        json!({
            "execution_coordinator_version":2,
            "dispatch_permit_version":1,
            "argument_digest_version":1,
            "registry_version":1,
            "registry_epoch_id":epoch,
            "registry_digest":digest,
            "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "server_name":"fixture",
            "raw_tool_name":"echo",
            "protocol_version":"2026-07-28",
            "server_attempt_id":"0190f5e6-7b00-7abc-8000-000000000203",
            "arguments_sha256":crate::mcp::argument_digest_v1(arguments).unwrap(),
        })
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
    fn new_sessions_activate_the_bounded_json_profile_without_exposing_it_as_header_extra() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("bounded-profile", header(temp.path()))
            .unwrap();

        let events = journal.read_events().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].data.get(JOURNAL_JSON_PROFILE_FIELD).is_none());
        let raw = journal.read_raw_events().unwrap();
        assert_eq!(
            raw[0][JOURNAL_JSON_PROFILE_FIELD],
            json!({
                "name":JOURNAL_JSON_PROFILE_NAME_V2,
                "version":JOURNAL_JSON_PROFILE_V2,
            })
        );
        assert_eq!(journal.json_profile, JournalJsonProfile::BoundedV2);
        assert!(
            !journal
                .header()
                .unwrap()
                .unwrap()
                .extra
                .contains_key(JOURNAL_JSON_PROFILE_FIELD)
        );
    }

    #[test]
    fn session_header_cannot_override_the_writer_json_profile() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut claimed = header(temp.path());
        claimed.extra.insert(
            JOURNAL_JSON_PROFILE_FIELD.to_owned(),
            json!({"name":"legacy-forgery","version":1}),
        );

        let error = store
            .create_with_id("forged-json-profile", claimed)
            .err()
            .expect("the writer profile field is reserved")
            .to_string();
        assert!(error.contains("reserved"), "unexpected error: {error}");
        assert!(
            !store
                .layout()
                .journal_path("forged-json-profile")
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn atomic_session_creation_is_no_clobber() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "atomic-create-no-clobber";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        let original = fs::read(&path).unwrap();
        drop(journal);

        let error = store
            .create_with_id(session_id, header(temp.path()))
            .err()
            .expect("a second atomic creation must not replace the journal")
            .to_string();
        assert!(error.contains("session already exists"), "{error}");
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn legacy_schema_one_without_a_claim_keeps_its_historical_json_language() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "legacy-json-profile";
        let mut data = serde_json::to_value(header(temp.path())).unwrap();
        data.as_object_mut().unwrap().insert(
            "legacy_nested".to_owned(),
            nested_object_value(MAX_JOURNAL_DATA_DEPTH_V2 + 1),
        );
        data.as_object_mut().unwrap().insert(
            JOURNAL_JSON_PROFILE_FIELD.to_owned(),
            serde_json::to_value(JournalJsonProfileClaimV2::current()).unwrap(),
        );
        let source = write_legacy_session_started(&store, session_id, data);

        let (events, profile, budget) =
            parse_complete_events_with_budget_v2(&source, session_id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(profile, JournalJsonProfile::LegacyV1);
        assert_eq!(budget.events, 0);
        assert_eq!(budget.nodes, 0);
        assert_eq!(budget.decoded_bytes, 0);
        assert!(store.inspect(session_id).is_ok());
        assert_eq!(store.list().unwrap().len(), 1);

        let reopened = store.open(session_id).unwrap();
        assert_eq!(reopened.json_profile, JournalJsonProfile::LegacyV1);
        assert!(
            reopened
                .header()
                .unwrap()
                .unwrap()
                .extra
                .contains_key("legacy_nested")
        );
        assert_eq!(
            reopened.header().unwrap().unwrap().extra[JOURNAL_JSON_PROFILE_FIELD],
            serde_json::to_value(JournalJsonProfileClaimV2::current()).unwrap(),
            "a historical flattened header key is data, not a profile activation"
        );
        drop(reopened);

        let destination = temp.path().join("legacy.oxidra-session-export");
        store
            .export_read_only_snapshot(session_id, &destination)
            .unwrap();
        let archive = fs::read(destination).unwrap();
        let manifest_end = archive.iter().position(|byte| *byte == b'\n').unwrap();
        assert_eq!(&archive[manifest_end + 1..], source);
    }

    #[test]
    fn legacy_schema_one_wide_prefix_is_not_charged_to_the_bounded_v2_ledger() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "legacy-wide-json-profile";
        let mut source = write_legacy_session_started(
            &store,
            session_id,
            serde_json::to_value(header(temp.path())).unwrap(),
        );

        // Each historical event is below the new per-event node ceiling, but
        // the complete prefix exceeds bounded-v2's decoded-byte estimate. A
        // schema-1 prefix without an envelope claim must retain the literal
        // pre-profile reader language instead of acquiring that new ledger.
        let mut event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 2,
            ts: Utc::now(),
            kind: "legacy.wide".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data: Value::Array(vec![Value::Null; 251_100]),
        };
        for seq in 2..=32 {
            event.seq = seq;
            serde_json::to_writer(&mut source, &event).unwrap();
            source.push(b'\n');
        }
        assert!(
            source.len() > 38_000_000,
            "unexpected legacy fixture size: {}",
            source.len()
        );
        fs::write(store.layout().journal_path(session_id).unwrap(), &source).unwrap();

        let (_, profile, budget) =
            parse_complete_events_with_budget_v2(&source, session_id).unwrap();
        assert_eq!(profile, JournalJsonProfile::LegacyV1);
        assert_eq!(budget.events, 0);
        assert_eq!(budget.nodes, 0);
        assert_eq!(budget.decoded_bytes, 0);
        assert_eq!(store.inspect(session_id).unwrap().len(), 32);

        let reopened = store.open(session_id).unwrap();
        assert_eq!(reopened.json_profile, JournalJsonProfile::LegacyV1);
        drop(reopened);

        let destination = temp.path().join("legacy-wide.oxidra-session-export");
        store
            .export_read_only_snapshot(session_id, &destination)
            .unwrap();
        let archive = fs::read(destination).unwrap();
        let manifest_end = archive.iter().position(|byte| *byte == b'\n').unwrap();
        assert_eq!(&archive[manifest_end + 1..], source);
    }

    #[test]
    fn legacy_direct_response_without_newline_keeps_historical_slot_semantics() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "legacy-direct-response";
        let mut source = write_legacy_session_started(
            &store,
            session_id,
            serde_json::to_value(header(temp.path())).unwrap(),
        );
        let user = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 2,
            ts: Utc::now(),
            kind: "user.message".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: Some("turn-legacy-direct".to_owned()),
            data: json!({
                "item": {"role": "user", "content": "hello"},
            }),
        };
        serde_json::to_writer(&mut source, &user).unwrap();
        source.push(b'\n');
        let response = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 3,
            ts: Utc::now(),
            kind: "response.completed".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: Some("turn-legacy-direct".to_owned()),
            data: json!({
                "output_items": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "hi"}],
                }],
            }),
        };
        let response_bytes = serde_json::to_vec(&response).unwrap();
        source.extend_from_slice(&response_bytes);
        fs::write(store.layout().journal_path(session_id).unwrap(), &source).unwrap();

        let before = fs::read(store.layout().journal_path(session_id).unwrap()).unwrap();
        let reopened = store.open(session_id).unwrap();
        assert_eq!(reopened.json_profile, JournalJsonProfile::LegacyV1);
        assert!(reopened.recovery_info().normalized_missing_newline);
        assert_eq!(reopened.recovery_info().cancelled_turns, 0);
        drop(reopened);

        let mut expected = before;
        expected.push(b'\n');
        assert_eq!(
            fs::read(store.layout().journal_path(session_id).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn malformed_or_unsupported_bounded_profile_claims_fail_closed_everywhere() {
        for (case, claim) in [
            (
                "unknown-version",
                json!({"name":JOURNAL_JSON_PROFILE_NAME_V2,"version":999}),
            ),
            (
                "unknown-field",
                json!({
                    "name":JOURNAL_JSON_PROFILE_NAME_V2,
                    "version":JOURNAL_JSON_PROFILE_V2,
                    "extra":true,
                }),
            ),
            ("wrong-shape", json!("bounded-json-v2")),
        ] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("bad-profile-{case}");
            let data = serde_json::to_value(header(temp.path())).unwrap();
            let event = JournalEvent {
                schema: JOURNAL_SCHEMA,
                seq: 1,
                ts: Utc::now(),
                kind: SESSION_STARTED_KIND.to_owned(),
                session_id: session_id.clone(),
                turn_id: None,
                data,
            };
            let mut raw = serde_json::to_value(&event).unwrap();
            raw.as_object_mut()
                .unwrap()
                .insert(JOURNAL_JSON_PROFILE_FIELD.to_owned(), claim);
            let mut bytes = serde_json::to_vec(&raw).unwrap();
            bytes.push(b'\n');
            let path = store.layout().journal_path(&session_id).unwrap();
            fs::write(&path, &bytes).unwrap();

            let inspect_error = store.inspect(&session_id).unwrap_err().to_string();
            assert!(
                inspect_error.contains(JOURNAL_JSON_PROFILE_FIELD)
                    || inspect_error.contains("unsupported journal JSON profile"),
                "unexpected inspect error for {case}: {inspect_error}"
            );
            assert!(store.open(&session_id).is_err());
            let destination = temp.path().join(format!("{case}.oxidra-session-export"));
            assert!(
                store
                    .export_read_only_snapshot(&session_id, &destination)
                    .is_err()
            );
            assert!(!destination.exists());
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn public_custom_writer_rejects_reserved_protocol_kinds_before_fsync() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("custom-protocol-boundary", header(temp.path()))
            .unwrap();
        let original = fs::read(journal.journal_path()).unwrap();
        let original_seq = journal.next_seq();

        for (kind, turn_id, data) in [
            ("tool.started", None, json!({})),
            ("user.message", None, json!({"text":"missing turn"})),
        ] {
            let error = journal
                .append_custom_and_sync(kind, turn_id, data)
                .expect_err("public custom writer must not author protocol kinds")
                .to_string();
            assert!(error.contains("custom.*"), "unexpected error: {error}");
            assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
            assert_eq!(journal.next_seq(), original_seq);
        }

        journal
            .append_custom_and_sync("custom.audit", None, json!({"ok":true}))
            .unwrap();
        let session_id = journal.session_id().to_owned();
        drop(journal);
        assert!(store.open(&session_id).is_ok());
    }

    #[test]
    fn public_custom_payload_is_enveloped_away_from_frozen_protocol_markers() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("custom-marker-isolation", header(temp.path()))
            .unwrap();
        let payload = json!({
            "turn_completion":{"version":1},
            "turn_boundary_version":"not-a-protocol-version",
            "mcp":{"forged":true},
            "response_attempt_id":"provider-controlled-looking-value",
        });

        let event = journal
            .append_custom_and_sync("custom.audit", None, payload.clone())
            .unwrap();
        assert!(event.data.get("turn_completion").is_none());
        assert_eq!(
            event.data[CUSTOM_EVENT_ENVELOPE_FIELD_V1]["version"],
            CUSTOM_EVENT_ENVELOPE_VERSION_V1
        );
        assert_eq!(
            event.data[CUSTOM_EVENT_ENVELOPE_FIELD_V1]["payload"],
            payload
        );

        let events = journal.read_events().unwrap();
        assert!(segment_turns(&events).unwrap().is_empty());
        assert!(
            validate_compaction_boundary_chain(&events)
                .unwrap()
                .boundaries()
                .is_empty()
        );
        crate::mcp::validate_mcp_call_chain(&events).unwrap();
        let session_id = journal.session_id().to_owned();
        drop(journal);
        assert!(store.open(&session_id).is_ok());
    }

    #[test]
    fn writer_rejects_deep_values_before_serialization_and_keeps_journal_reopenable() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("deep-writer-profile", header(temp.path()))
            .unwrap();
        let original = fs::read(journal.journal_path()).unwrap();
        let original_seq = journal.next_seq();

        let error = journal
            .append_custom_and_sync(
                "custom.deep",
                None,
                nested_object_value(MAX_JOURNAL_DATA_DEPTH_V2 + 1),
            )
            .expect_err("depth above the writer profile must be rejected")
            .to_string();
        assert!(error.contains("depth profile"), "unexpected error: {error}");
        assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
        assert_eq!(journal.next_seq(), original_seq);

        // A much deeper value exercises the iterative rejection/drop path;
        // no serde serializer or recursive Value destructor may run first.
        let error = journal
            .append_custom_and_sync("custom.very_deep", None, nested_object_value(20_000))
            .expect_err("very deep values must be rejected without stack overflow")
            .to_string();
        assert!(error.contains("depth profile"), "unexpected error: {error}");
        assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
        assert_eq!(journal.next_seq(), original_seq);

        let session_id = journal.session_id().to_owned();
        drop(journal);
        assert!(store.open(&session_id).is_ok());
    }

    #[test]
    fn journal_event_drop_is_iterative_for_deep_public_payloads() {
        drop(JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 1,
            ts: Utc::now(),
            kind: "custom.deep_drop".to_owned(),
            session_id: "deep-drop".to_owned(),
            turn_id: None,
            data: nested_object_value(20_000),
        });
    }

    #[test]
    fn writer_and_reader_share_the_exact_custom_payload_depth_boundary() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("depth-boundary", header(temp.path()))
            .unwrap();
        journal
            .append_custom_and_sync(
                "custom.at_depth_limit",
                None,
                // Public custom data is nested below the two-level versioned
                // envelope (`custom_event.payload`) before it reaches the
                // event-data profile.
                nested_object_value(MAX_JOURNAL_DATA_DEPTH_V2 - 2),
            )
            .unwrap();
        let session_id = journal.session_id().to_owned();
        drop(journal);
        assert!(store.open(&session_id).is_ok());
    }

    #[test]
    fn append_rejects_journal_wide_event_budget_before_writing() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("event-budget", header(temp.path()))
            .unwrap();
        let metrics = cheap_custom_event_metrics();
        journal.decode_budget.events = MAX_JOURNAL_EVENTS_V2;
        journal.decode_budget.nodes = 0;
        journal.decode_budget.decoded_bytes = 0;
        let original = fs::read(journal.journal_path()).unwrap();
        let original_seq = journal.next_seq();

        let error = journal
            .append_custom_and_sync("custom.event_budget", None, Value::Null)
            .expect_err("the next event must exceed the journal-wide budget")
            .to_string();
        assert!(error.contains("event decoded profile"), "{error}");
        assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
        assert_eq!(journal.next_seq(), original_seq);
        assert_eq!(journal.decode_budget.events, MAX_JOURNAL_EVENTS_V2);
        assert!(metrics.nodes > 0);
    }

    #[test]
    fn append_rejects_journal_wide_node_and_decoded_byte_budgets_before_writing() {
        for budget_kind in ["nodes", "decoded_bytes"] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let mut journal = store
                .create_with_id(format!("{budget_kind}-budget"), header(temp.path()))
                .unwrap();
            journal.decode_budget.events = 0;
            match budget_kind {
                "nodes" => {
                    journal.decode_budget.nodes = MAX_JOURNAL_DECODED_NODES_V2;
                    journal.decode_budget.decoded_bytes = 0;
                }
                "decoded_bytes" => {
                    journal.decode_budget.nodes = 0;
                    journal.decode_budget.decoded_bytes = MAX_JOURNAL_DECODED_BYTES_V2;
                }
                _ => unreachable!(),
            }
            let original = fs::read(journal.journal_path()).unwrap();
            let original_seq = journal.next_seq();

            let error = journal
                .append_custom_and_sync("custom.aggregate_budget", None, json!({"value":1}))
                .expect_err("the next event must exceed the aggregate decode budget")
                .to_string();
            assert!(
                error.contains(if budget_kind == "nodes" {
                    "node decoded profile"
                } else {
                    "byte decoded profile"
                }),
                "{budget_kind}: {error}"
            );
            assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
            assert_eq!(journal.next_seq(), original_seq);
        }
    }

    #[test]
    fn reader_rejects_journal_wide_event_budget_before_materializing_extra_lines() {
        let line = bounded_event_line("many-events", 1, Value::Null);
        let line_metrics = preflight_journal_json_bytes_v2(&line).unwrap();
        let mut budget = JournalDecodeBudgetV2 {
            events: MAX_JOURNAL_EVENTS_V2,
            ..JournalDecodeBudgetV2::default()
        };
        let error = budget
            .account(line_metrics)
            .expect_err("reader budget must reject the next line before decode")
            .to_string();
        assert!(error.contains("event decoded profile"), "{error}");
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
        let handle_id = Uuid::now_v7().to_string();
        let mut journal = SessionJournal {
            session_id: "poisoned".to_owned(),
            handle_id: handle_id.clone(),
            journal_path,
            artifact_dir: temp.path().join("artifacts"),
            file,
            execution_lease: SessionExecutionLeaseV1::new(lock_file, "poisoned", &handle_id),
            execution_gate_path: temp.path().join("poisoned.mcp-execution-v1.lock"),
            next_seq: 1,
            recovery: RecoveryInfo::default(),
            poisoned: false,
            reopen_required: Arc::new(AtomicBool::new(false)),
            byte_limit: MAX_SESSION_BYTES,
            active_turn: None,
            active_provider_response: None,
            active_compaction: None,
            active_mcp_tool: None,
            recovery_headroom_bytes: 0,
            json_profile: JournalJsonProfile::BoundedV2,
            decode_budget: JournalDecodeBudgetV2::default(),
            mcp_resume_open_id: None,
            mcp_activation_present_at_open: false,
            mcp_activation_startup_issued: false,
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
    fn exports_an_exact_read_only_journal_snapshot() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("export-source", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync("context.configured", None, json!({"value": 1}))
            .unwrap();
        drop(journal);

        let source = store.layout().journal_path("export-source").unwrap();
        let source_before = fs::read(&source).unwrap();
        let destination = temp.path().join("exported-session.oxidra-session-export");
        let exported = store
            .export_read_only_snapshot("export-source", &destination)
            .unwrap();

        let archive = fs::read(&destination).unwrap();
        assert_eq!(exported, archive.len() as u64);
        let manifest_end = archive.iter().position(|byte| *byte == b'\n').unwrap();
        let manifest: Value = serde_json::from_slice(&archive[..manifest_end]).unwrap();
        assert_eq!(manifest["format"], "oxidra.session.read_only_export");
        assert_eq!(manifest["version"], 1);
        assert_eq!(manifest["session_id"], "export-source");
        assert_eq!(manifest["journal_bytes"], source_before.len());
        assert_eq!(
            manifest["journal_sha256"],
            hex::encode(Sha256::digest(&source_before))
        );
        assert_eq!(
            manifest["journal_complete_prefix_bytes"],
            source_before.len()
        );
        assert!(manifest["journal_incomplete_tail"].is_null());
        assert_eq!(manifest["journal_missing_final_newline"], false);
        assert_eq!(&archive[manifest_end + 1..], source_before);
        assert!(
            parse_complete_events(&archive, "export-source").is_err(),
            "a read-only archive must not also be a resumable session journal"
        );
        assert_eq!(fs::read(&source).unwrap(), source_before);
        assert!(
            store
                .export_read_only_snapshot("export-source", &destination)
                .is_err(),
            "an export must never overwrite an existing destination"
        );
        assert_eq!(fs::read(&destination).unwrap(), archive);
        assert!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".oxidra-session-export-")),
            "a failed no-clobber publish must clean up its temporary sibling"
        );
    }

    #[test]
    fn atomic_new_file_publish_cleans_up_after_a_write_failure() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("archive.jsonl");

        let error = write_new_file_atomically(&destination, |output| {
            output.write_all(b"incomplete archive")?;
            Err(std::io::Error::other("injected export write failure"))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            AtomicNewFileError::BeforePublish(error)
                if error.kind() == std::io::ErrorKind::Other
        ));
        assert!(!destination.exists());
        assert_eq!(
            fs::read_dir(temp.path()).unwrap().count(),
            0,
            "a write error must not leave either the destination or a temporary sibling"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_atomic_publish_removes_temp_before_syncing_parent() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("archive.oxidra-session-export");
        let temporary_path = temp.path().join(".archive.tmp");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .unwrap();
        output.write_all(b"complete archive").unwrap();
        output.sync_all().unwrap();
        drop(output);
        let sync_observed = std::cell::Cell::new(false);

        publish_temporary_export_with_parent_sync(
            &temporary_path,
            &destination,
            TemporaryExportFile::new(temporary_path.clone()),
            |parent| {
                assert_eq!(parent, temp.path());
                assert_eq!(fs::read(&destination).unwrap(), b"complete archive");
                assert!(
                    fs::read_dir(parent)
                        .unwrap()
                        .filter_map(|entry| entry.ok())
                        .all(|entry| entry.file_name().to_string_lossy() != ".archive.tmp"),
                    "the temporary link must be removed before the directory flush"
                );
                sync_observed.set(true);
                sync_parent_directory(parent)
            },
        )
        .unwrap();

        assert!(sync_observed.get());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_post_publish_sync_failure_is_reported_as_uncertain() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("archive.oxidra-session-export");
        let temporary_path = temp.path().join(".archive.tmp");
        fs::write(&temporary_path, b"complete archive").unwrap();

        let error = publish_temporary_export_with_parent_sync(
            &temporary_path,
            &destination,
            TemporaryExportFile::new(temporary_path.clone()),
            |_| Err(std::io::Error::other("injected directory sync failure")),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            AtomicNewFileError::PublishedButDurabilityUncertain(_)
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"complete archive");
        assert!(!temporary_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_write_through_publish_supports_long_paths_and_no_clobber() {
        let temp = TempDir::new().unwrap();
        let mut parent = temp.path().to_path_buf();
        while parent.as_os_str().as_encoded_bytes().len() < 320 {
            parent.push("long-export-parent-component-0123456789");
        }
        fs::create_dir_all(&parent).unwrap();
        let destination = parent.join("archive.oxidra-session-export");

        write_new_file_atomically(&destination, |output| output.write_all(b"first archive"))
            .unwrap();
        let error = write_new_file_atomically(&destination, |output| {
            output.write_all(b"replacement archive")
        })
        .unwrap_err();

        assert!(matches!(error, AtomicNewFileError::BeforePublish(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"first archive");
        assert!(
            fs::read_dir(&parent)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".oxidra-session-export-"))
        );
    }

    #[test]
    fn read_only_export_suffix_cannot_contaminate_another_session_store() {
        let temp = TempDir::new().unwrap();
        let source_store = SessionStore::new(temp.path().join("source-store")).unwrap();
        let journal = source_store
            .create_with_id("export-source", header(temp.path()))
            .unwrap();
        drop(journal);
        let destination_store = SessionStore::new(temp.path().join("destination-store")).unwrap();

        let reserved_destinations = [
            destination_store.layout().sessions_dir.join("poison.jsonl"),
            destination_store.layout().locks_dir.join("poison.lock"),
            destination_store
                .layout()
                .locks_dir
                .join("poison.mcp-execution-v1.lock"),
            destination_store.layout().artifacts_dir.join("poison"),
        ];
        for reserved_destination in reserved_destinations {
            let error = source_store
                .export_read_only_snapshot("export-source", &reserved_destination)
                .unwrap_err();
            assert!(
                error.to_string().contains(".oxidra-session-export"),
                "{error}"
            );
            assert!(
                !reserved_destination.exists(),
                "invalid export suffix must be rejected before touching a reserved SessionStore path"
            );
        }

        let nul_destination = destination_store.layout().sessions_dir.join(format!(
            "victim.jsonl\0.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"
        ));
        let error = source_store
            .export_read_only_snapshot("export-source", &nul_destination)
            .unwrap_err();
        assert!(error.to_string().contains("embedded NUL"), "{error}");
        assert!(
            !destination_store
                .layout()
                .sessions_dir
                .join("victim.jsonl")
                .exists(),
            "an FFI path must not truncate the required suffix at an embedded NUL"
        );

        #[cfg(windows)]
        {
            let ads_destination = destination_store.layout().sessions_dir.join(format!(
                "victim.jsonl:archive.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"
            ));
            let error = source_store
                .export_read_only_snapshot("export-source", &ads_destination)
                .unwrap_err();
            assert!(
                error.to_string().contains("alternate data stream"),
                "{error}"
            );
            assert!(
                !destination_store
                    .layout()
                    .sessions_dir
                    .join("victim.jsonl")
                    .exists(),
                "an export must not target an alternate stream of a reserved journal path"
            );
        }

        let safe_destination = destination_store
            .layout()
            .sessions_dir
            .join("archive.oxidra-session-export");
        source_store
            .export_read_only_snapshot("export-source", &safe_destination)
            .unwrap();
        assert!(safe_destination.is_file());
        assert!(
            destination_store.list().unwrap().is_empty(),
            "the mandatory non-journal suffix must keep archives outside SessionStore discovery"
        );
    }

    #[test]
    fn read_only_export_preserves_an_incomplete_journal_tail() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("partial-export", header(temp.path()))
            .unwrap();
        drop(journal);

        let source = store.layout().journal_path("partial-export").unwrap();
        let complete_prefix = fs::read(&source).unwrap();
        let incomplete_tail = b"{\"schema\":\"oxidra.session.v1\",\"seq\":";
        OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(incomplete_tail)
            .unwrap();
        let source_before = fs::read(&source).unwrap();
        let destination = temp.path().join("partial-export.oxidra-session-export");

        store
            .export_read_only_snapshot("partial-export", &destination)
            .unwrap();

        let archive = fs::read(&destination).unwrap();
        let manifest_end = archive.iter().position(|byte| *byte == b'\n').unwrap();
        let manifest: Value = serde_json::from_slice(&archive[..manifest_end]).unwrap();
        assert_eq!(manifest["journal_bytes"], source_before.len());
        assert_eq!(
            manifest["journal_sha256"],
            hex::encode(Sha256::digest(&source_before))
        );
        assert_eq!(
            manifest["journal_complete_prefix_bytes"],
            complete_prefix.len()
        );
        assert_eq!(
            manifest["journal_incomplete_tail"]["offset"],
            complete_prefix.len()
        );
        assert_eq!(
            manifest["journal_incomplete_tail"]["bytes"],
            incomplete_tail.len()
        );
        assert_eq!(
            manifest["journal_incomplete_tail"]["sha256"],
            hex::encode(Sha256::digest(incomplete_tail))
        );
        assert_eq!(manifest["journal_missing_final_newline"], false);
        assert_eq!(&archive[manifest_end + 1..], source_before);
        assert_eq!(
            fs::read(&source).unwrap(),
            source_before,
            "read-only export must not repair or truncate the source tail"
        );
    }

    #[test]
    fn read_only_export_preserves_a_partial_first_header_with_no_complete_prefix() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "export-partial-header";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let source = journal.journal_path().to_owned();
        drop(journal);

        let complete = fs::read(&source).unwrap();
        let partial = complete[..complete.len() / 2].to_vec();
        assert_eq!(
            journal_tail_syntax_v1(&partial),
            JournalTailSyntaxV1::Incomplete
        );
        fs::write(&source, &partial).unwrap();
        let destination = temp.path().join("partial-header.oxidra-session-export");

        store
            .export_read_only_snapshot(session_id, &destination)
            .unwrap();
        let archive = fs::read(destination).unwrap();
        let manifest_end = archive.iter().position(|byte| *byte == b'\n').unwrap();
        let manifest: Value = serde_json::from_slice(&archive[..manifest_end]).unwrap();
        assert_eq!(manifest["journal_complete_prefix_bytes"], 0);
        assert_eq!(manifest["journal_incomplete_tail"]["bytes"], partial.len());
        assert_eq!(
            manifest["journal_incomplete_tail"]["sha256"],
            hex::encode(Sha256::digest(&partial))
        );
        assert_eq!(&archive[manifest_end + 1..], partial);
        assert_eq!(fs::read(source).unwrap(), partial);
    }

    #[test]
    fn read_only_export_refuses_an_active_session_writer() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("active-export", header(temp.path()))
            .unwrap();
        let destination = temp.path().join("active-export.oxidra-session-export");

        let error = store
            .export_read_only_snapshot("active-export", &destination)
            .unwrap_err();
        assert!(error.to_string().contains("already open"), "{error}");
        assert!(!destination.exists());
        drop(journal);
    }

    #[test]
    fn retained_execution_lease_keeps_the_original_writer_lock_alive() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("execution-lease", header(temp.path()))
            .unwrap();
        let execution_lease = journal.retain_execution_lease_v1();

        drop(journal);
        let error = store.open("execution-lease").err().unwrap();
        assert!(error.to_string().contains("already open"));

        drop(execution_lease);
        store.open("execution-lease").unwrap();
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
    fn tail_repair_capacity_denial_preserves_exact_crash_bytes() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "tail-capacity-denied";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{"schema":1,"seq":2,"ts":"#)
            .unwrap();
        let before = fs::read(&path).unwrap();
        let error = store
            .open_with_byte_limit(session_id, before.len() as u64)
            .err()
            .expect("recovery must be denied when the marker cannot fit");
        assert!(error.to_string().contains("tail repair"), "{error}");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "capacity denial must not destroy the crash-tail evidence"
        );
    }

    #[test]
    fn legacy_tails_repair_only_with_a_valid_reader_completion_witness() {
        type TailFixture = (&'static str, fn(&str) -> Vec<u8>);
        let cases: [TailFixture; 5] = [
            ("utf8", |session_id| {
                let mut tail = format!(
                    "{{\"schema\":1,\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.partial_utf8\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":"
                )
                .into_bytes();
                tail.extend_from_slice(&[b'\"', 0xe2, 0x82]);
                tail
            }),
            ("unicode-escape", |session_id| {
                let mut tail = format!(
                    "{{\"schema\":1,\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.partial_escape\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":"
                )
                .into_bytes();
                tail.extend_from_slice(br#""\u12"#);
                tail
            }),
            ("high-surrogate", |session_id| {
                let mut tail = format!(
                    "{{\"schema\":1,\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.partial_surrogate\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":"
                )
                .into_bytes();
                tail.extend_from_slice(br#""\uD800"#);
                tail
            }),
            ("number", |session_id| {
                format!(
                    "{{\"schema\":1,\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.partial_number\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":1e"
                )
                .into_bytes()
            }),
            ("envelope", |_session_id| br#"{"schema":1,"seq":2"#.to_vec()),
        ];

        for (name, make_tail) in cases {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("completion-witness-{name}");
            // General Unicode escapes and exponent spellings belong to the
            // historical reader language, not necessarily the bounded
            // writer's exact encoding. Keep this compatibility fixture
            // explicitly unclaimed rather than silently using today's writer.
            write_legacy_session_started(
                &store,
                &session_id,
                serde_json::to_value(header(temp.path())).unwrap(),
            );
            let path = store.layout().journal_path(&session_id).unwrap();
            let tail = make_tail(&session_id);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&tail)
                .unwrap();

            let reopened = store
                .open(&session_id)
                .unwrap_or_else(|error| panic!("{name} witness was rejected: {error}"));
            assert_eq!(
                reopened
                    .recovery_info()
                    .truncated_tail
                    .as_ref()
                    .unwrap()
                    .byte_count,
                tail.len() as u64,
                "{name} tail was not recorded as truncated"
            );
            assert_eq!(reopened.recovery_info().marker_seq, Some(2));
            assert_eq!(reopened.read_events().unwrap()[1].kind, RECOVERY_KIND);
        }
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
    fn reopen_rechecks_in_doubt_headroom_when_no_recovery_event_is_appended() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("pending-empty-reservation", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-pending"),
                json!({
                    "call_id":"call-pending",
                    "tool":"read",
                    "arguments":{"path":"a"},
                    "error_code":"in_doubt",
                }),
            )
            .unwrap();
        drop(journal);

        let recovered = store.open("pending-empty-reservation").unwrap();
        let debt = recovered.recovery_headroom_bytes;
        assert!(debt > 0);
        let current_size = recovered.file.metadata().unwrap().len();
        drop(recovered);

        let insufficient_limit = current_size + debt - 1;
        let error =
            match store.open_with_byte_limit("pending-empty-reservation", insufficient_limit) {
                Ok(_) => panic!("an empty recovery batch must still prove its retained headroom"),
                Err(error) => error.to_string(),
            };
        assert!(error.contains("transaction would exceed"), "{error}");
    }

    #[test]
    fn sequential_tool_lifecycle_does_not_charge_a_fixed_margin_per_call() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("bounded-tool-lifecycle-debt", header(temp.path()))
            .unwrap();
        let mut turn = admit_test_turn(&mut journal, "turn-lifecycle-debt");
        let mut response = journal
            .append_provider_response_started_v1(
                &turn,
                "turn-lifecycle-debt",
                json!({
                    "response_attempt_id":"attempt-lifecycle-debt",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();
        let call_count = 64usize;
        let output_items = (0..call_count)
            .map(|index| {
                json!({
                    "type":"function_call",
                    "call_id":format!("call-{index}"),
                    "name":"read",
                    "arguments":"{}",
                })
            })
            .collect::<Vec<_>>();
        journal
            .append_provider_response_completed_v1(
                &mut response,
                json!({
                    "response_attempt_id":"attempt-lifecycle-debt",
                    "output_items":output_items,
                }),
            )
            .unwrap();

        let baseline_headroom = journal
            .active_turn
            .as_ref()
            .expect("active turn reserve")
            .headroom_bytes;
        let current_size = journal.file.metadata().unwrap().len();
        // The old fixed 64 KiB per lifecycle margin rejects this sequence
        // after only a handful of calls.  The versioned multiplier remains
        // conservative, but its debt scales with the actual encoded payload.
        let byte_limit = current_size + baseline_headroom + 512 * 1024;
        journal.set_byte_limit_for_tests(byte_limit);

        for index in 0..call_count {
            let call_id = format!("call-{index}");
            journal
                .append_and_sync(
                    "tool.started",
                    Some("turn-lifecycle-debt"),
                    json!({"call_id":call_id,"tool":"read","arguments":{}}),
                )
                .unwrap();
            journal
                .append_and_sync(
                    "tool.completed",
                    Some("turn-lifecycle-debt"),
                    json!({"call_id":call_id,"output":{"ok":true}}),
                )
                .unwrap();
        }

        assert!(journal.file.metadata().unwrap().len() <= byte_limit);
        journal
            .finish_turn_transaction_v1(&mut turn, Some("test lifecycle completion"))
            .unwrap();
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

        recovered.resolve_all_in_doubt_v1(&pending).unwrap();
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
    fn live_in_doubt_resolution_also_finalizes_parent_turn() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("live-in-doubt-finalization", header(temp.path()))
            .unwrap();
        let mut turn_admission = admit_test_turn(&mut journal, "turn-live-in-doubt");
        let mut response_admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-live-in-doubt",
                json!({
                    "response_attempt_id":"attempt-live-in-doubt",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();
        journal
            .append_provider_response_completed_v1(
                &mut response_admission,
                json!({
                    "response_attempt_id":"attempt-live-in-doubt",
                    "output_items":[
                        {"type":"function_call","call_id":"call-live","name":"shell","arguments":{"command":"true"}}
                    ],
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.started",
                Some("turn-live-in-doubt"),
                json!({"call_id":"call-live","tool":"shell","arguments":{"command":"true"}}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-live-in-doubt"),
                json!({
                    "started_seq": journal.next_seq() - 1,
                    "call_id":"call-live",
                    "tool":"shell",
                    "output":{"error":{"code":"in_doubt","message":"unknown"}},
                    "is_error":true,
                    "error_code":"in_doubt",
                }),
            )
            .unwrap();
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("tool side effect unknown"))
            .unwrap();
        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        journal.resolve_all_in_doubt_v1(&pending).unwrap();
        let events = journal.read_events().unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "tool.in_doubt_resolved")
        );
        assert!(events.iter().any(|event| event.kind == "turn.cancelled"));
        assert!(journal.in_doubt().unwrap().is_empty());
        drop(journal);
        let reopened = store.open("live-in-doubt-finalization").unwrap();
        assert!(reopened.in_doubt().unwrap().is_empty());
    }

    #[test]
    fn turn_cancellation_settles_interleaved_mcp_and_builtin_calls_before_terminal() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mixed-mcp-builtin-cancellation", header(temp.path()))
            .unwrap();
        let epoch = "0190f5e6-7b00-7abc-8000-000000000102";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        journal
            .append_mcp_event_and_sync_v1(
                "mcp.registry.activated",
                None,
                json!({
                    "coordinator_version":1,
                    "call_chain_validator_version":1,
                    "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000101",
                    "registry_epoch_id":epoch,
                    "registry_version":1,
                    "stdio_kernel_version":1,
                    "schema_profile_version":1,
                    "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "registry_digest":digest,
                    "provider_names":["mcp_fixture_echo_deadbeef"],
                }),
            )
            .unwrap();
        let mut turn = admit_test_turn(&mut journal, "turn-mixed-cancellation");
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mixed-cancellation"),
                json!({
                    "response_attempt_id":"attempt-mixed-cancellation",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mixed-cancellation"),
                json!({
                    "response_attempt_id":"attempt-mixed-cancellation",
                    "output_items":[
                        {
                            "type":"function_call",
                            "call_id":"call-mcp",
                            "name":"mcp_fixture_echo_deadbeef",
                            "arguments":"{\"text\":\"hello\"}",
                        },
                        {
                            "type":"function_call",
                            "call_id":"call-builtin",
                            "name":"read",
                            "arguments":"{\"path\":\"README.md\"}",
                        },
                    ],
                }),
            )
            .unwrap();

        journal
            .finish_turn_transaction_v1(&mut turn, Some("observer failed before dispatch"))
            .unwrap();

        let events = journal.read_events().unwrap();
        let lifecycle = events
            .iter()
            .filter(|event| {
                matches!(
                    event.kind.as_str(),
                    "journal.recovered"
                        | "tool.skipped_due_to_recovery"
                        | "tool.skipped_due_to_cancel"
                        | "turn.cancelled"
                )
            })
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            lifecycle,
            vec![
                "journal.recovered",
                "tool.skipped_due_to_recovery",
                "tool.skipped_due_to_cancel",
                "turn.cancelled",
            ]
        );
        crate::mcp::validate_mcp_call_chain(&events).unwrap();
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                "turn-mixed-cancellation",
            )
            .unwrap(),
            ProviderRequestSlotState::Terminal
        );
        drop(journal);
        store
            .open("mixed-mcp-builtin-cancellation")
            .expect("the mixed cancellation transaction must reopen cleanly");
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
        crate::turn::validate_turn_recovery_dynamic(&events)
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
    fn provider_context_limit_recovery_cannot_cross_a_later_durable_event() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-gap", header(temp.path()))
            .unwrap();
        append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-context-limit-gap",
            "attempt-context-limit-gap",
        );
        journal
            .append_and_sync(
                "custom.after_context_limit_gap",
                None,
                json!({"after":true}),
            )
            .unwrap();
        let path = journal.journal_path().to_owned();
        let before = fs::read(&path).unwrap();
        drop(journal);

        let error = store
            .open("provider-context-limit-gap")
            .err()
            .expect("an old transaction gap must not be repaired retroactively")
            .to_string();
        assert!(error.contains("durable journal tail"), "{error}");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "recovery rejection must precede every journal mutation"
        );
    }

    #[test]
    fn provider_context_limit_terminal_must_directly_follow_its_intent() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-nonadjacent", header(temp.path()))
            .unwrap();
        let (_started, failed, context) = append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-context-limit-nonadjacent",
            "attempt-context-limit-nonadjacent",
        );
        journal
            .append_and_sync(
                "custom.between_context_limit_events",
                None,
                json!({"between":true}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "context.limit_reached",
                Some("turn-context-limit-nonadjacent"),
                provider_context_limit_event_data_v1(
                    "attempt-context-limit-nonadjacent",
                    failed.seq,
                    "context_length_exceeded",
                    context,
                ),
            )
            .unwrap();
        let path = journal.journal_path().to_owned();
        let before = fs::read(&path).unwrap();
        drop(journal);

        let error = store
            .open("provider-context-limit-nonadjacent")
            .err()
            .expect("a non-adjacent terminal must fail closed")
            .to_string();
        assert!(error.contains("direct successor"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn provider_context_limit_recovery_does_not_upgrade_legacy_turn_language() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id(
                "provider-context-limit-mixed-turn-versions",
                header(temp.path()),
            )
            .unwrap();
        let legacy_user = journal
            .append_and_sync(
                "user.message",
                Some("turn-legacy-v2"),
                json!({
                    "item":{"role":"user","content":"legacy prompt"},
                    "turn_boundary_version":2,
                }),
            )
            .unwrap();
        let legacy_limit = journal
            .append_and_sync(
                "context.limit_reached",
                Some("turn-legacy-v2"),
                json!({"source":"provider"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "turn.retry_started",
                Some("turn-legacy-v2"),
                json!({
                    "retry_version":1,
                    "retry_id":"legacy-v2-retry",
                    "user_message_seq":legacy_user.seq,
                    "context_limit_seq":legacy_limit.seq,
                }),
            )
            .unwrap();
        let legacy_prefix = journal.read_events().unwrap();
        crate::turn::validate_turn_recovery_v2(&legacy_prefix)
            .expect("the legacy turn must remain valid recovery v2");
        assert!(
            crate::turn::validate_turn_recovery_v3(&legacy_prefix).is_err(),
            "the mixed-version regression must contain a v2-only recovery prefix"
        );
        append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-current-v8",
            "attempt-current-v8",
        );
        drop(journal);

        let recovered = store
            .open("provider-context-limit-mixed-turn-versions")
            .expect("current recovery must not apply v3 rules to the legacy v2 turn");
        assert_eq!(
            recovered.recovery_info().recovered_provider_context_limits,
            1
        );
        let events = recovered.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "context.limit_reached")
                .count(),
            2
        );
        assert!(crate::turn::validate_turn_recovery_v3(&events).is_err());
        crate::turn::validate_turn_recovery_dynamic(&events)
            .expect("each turn must retain its selected recovery language");
    }

    #[test]
    fn reopens_provider_context_limit_after_truncating_partial_audit_event() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-partial", header(temp.path()))
            .unwrap();
        let (_started, failed, context) = append_provider_context_limit_intent_prefix(
            &mut journal,
            "turn-context-limit",
            "attempt-context-limit",
        );
        let mut planned_seq = journal.next_seq();
        let audit = planned_recovery_event(
            journal.session_id(),
            &mut planned_seq,
            "context.limit_reached",
            Some("turn-context-limit"),
            provider_context_limit_event_data_v1(
                "attempt-context-limit",
                failed.seq,
                "context_length_exceeded",
                context.clone(),
            ),
        )
        .unwrap();
        let encoded = encode_journal_event_v2(&audit).unwrap();
        let cut = encoded
            .windows(b",\"session_id\"".len())
            .position(|window| window == b",\"session_id\"")
            .expect("canonical event contains session_id after kind");
        journal.file.write_all(&encoded[..cut]).unwrap();
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
        let limit = recovered
            .read_events()
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "context.limit_reached")
            .expect("the partial audit tail must be completed as the canonical event");
        assert_eq!(limit.turn_id.as_deref(), Some("turn-context-limit"));
        assert_eq!(
            limit.data,
            provider_context_limit_event_data_v1(
                "attempt-context-limit",
                failed.seq,
                "context_length_exceeded",
                context,
            )
        );
    }

    #[test]
    fn orphan_response_completion_tail_is_not_repaired_or_deleted() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("orphan-response-tail", header(temp.path()))
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("turn-orphan-response"),
                json!({
                    "item": {"role": "user", "content": "hello"},
                    "turn_boundary_version": crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let tail = br#"{"schema":1,"seq":3,"kind":"response.completed","session_id":"orphan-response-tail","turn_id":"turn-orphan-response","data":{"response_attempt_id":"attempt-orphan""#;
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(tail)
            .unwrap();
        let before = fs::read(&path).unwrap();

        let error = store
            .open("orphan-response-tail")
            .err()
            .expect("an orphan response completion must not acquire repair authority")
            .to_string();
        assert!(
            error.contains("turn") || error.contains("response"),
            "unexpected orphan response error: {error}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);

        let archive = temp.path().join(format!(
            "orphan-response-tail.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"
        ));
        store
            .export_read_only_snapshot("orphan-response-tail", &archive)
            .unwrap();
        let archive_bytes = fs::read(archive).unwrap();
        let manifest_end = archive_bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
        assert_eq!(&archive_bytes[manifest_end + 1..], before);
    }

    #[test]
    fn complete_provider_context_limit_transaction_is_not_duplicated() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-context-limit-complete", header(temp.path()))
            .unwrap();
        let mut turn_admission = admit_test_turn(&mut journal, "turn-context-limit");
        let context = json!({"measurement":{"request_digest":"context-digest"}});
        let mut admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
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
        journal
            .finish_turn_transaction_v1(&mut turn_admission, None)
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
    fn standalone_mcp_dispatch_denies_start_without_complete_outcome_headroom() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("standalone-mcp-capacity", header(temp.path()))
            .unwrap();
        let current_size = journal.file.metadata().unwrap().len();
        journal.set_byte_limit_for_tests(current_size + MCP_TOOL_OUTCOME_HEADROOM_BYTES_V1);

        let error = journal
            .append_mcp_tool_started_v1(
                "standalone-turn",
                json!({"call_id":"standalone-call","tool":"read","arguments":{}}),
            )
            .expect_err("tool.started must not commit without full outcome/recovery headroom");
        assert!(matches!(
            error,
            DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(_)
        ));
        assert!(
            journal
                .read_events()
                .unwrap()
                .iter()
                .all(|event| event.kind != "tool.started")
        );
    }

    #[test]
    fn standalone_mcp_in_doubt_transfers_reserve_to_resolution() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("standalone-mcp-in-doubt", header(temp.path()))
            .unwrap();
        let mut admission = journal
            .append_mcp_tool_started_v1(
                "standalone-turn",
                json!({"call_id":"standalone-call","tool":"read","arguments":{}}),
            )
            .unwrap();
        let started_seq = admission.started_seq();
        journal
            .commit_mcp_tool_terminal_v1(
                &mut admission,
                "tool.in_doubt",
                json!({
                    "started_seq":started_seq,
                    "call_id":"standalone-call",
                    "tool":"read",
                    "output":{"error":{"code":"in_doubt","message":"side effect is unknown"}},
                    "is_error":true,
                    "error_code":"in_doubt",
                }),
            )
            .unwrap();

        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(journal.recovery_headroom_bytes > 0);
        journal
            .resolve_all_in_doubt_v1(&pending)
            .expect("the live standalone reserve must authorize exact resolution");
        assert_eq!(journal.recovery_headroom_bytes, 0);
        assert!(journal.in_doubt().unwrap().is_empty());
    }

    #[test]
    fn active_turn_mcp_in_doubt_consumes_its_predispatch_reserve_at_exact_limit() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("active-turn-mcp-in-doubt", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-active-mcp-in-doubt");
        let arguments = json!({});
        let provenance = test_mcp_provenance_v2(epoch, digest, &arguments);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-active-mcp-in-doubt"),
                json!({
                    "response_attempt_id":"attempt-active-mcp-in-doubt",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-active-mcp-in-doubt"),
                json!({
                    "response_attempt_id":"attempt-active-mcp-in-doubt",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-active-mcp-in-doubt",
                        "name":provider_name,
                        "arguments":"{}",
                    }],
                }),
            )
            .unwrap();

        let mut tool_admission = journal
            .append_mcp_tool_started_v1(
                "turn-active-mcp-in-doubt",
                json!({
                    "call_id":"call-active-mcp-in-doubt",
                    "tool":provider_name,
                    "arguments":arguments,
                    "mcp":provenance.clone(),
                }),
            )
            .unwrap();
        let started_seq = tool_admission.started_seq();
        let reserved = journal
            .active_mcp_tool
            .as_ref()
            .expect("active MCP reserve")
            .headroom_bytes;
        let current_size = journal.file.metadata().unwrap().len();
        let exact_limit = current_size + reserved;
        journal.set_byte_limit_for_tests(exact_limit);

        journal
            .commit_mcp_tool_terminal_v1(
                &mut tool_admission,
                "tool.in_doubt",
                json!({
                    "started_seq":started_seq,
                    "call_id":"call-active-mcp-in-doubt",
                    "tool":provider_name,
                    "output":{"error":{"code":"in_doubt","message":"side effect is unknown"}},
                    "is_error":true,
                    "error_code":"in_doubt",
                    "before_dispatch":false,
                    "mcp":provenance,
                }),
            )
            .expect("the pre-dispatch reserve must cover the bounded in-doubt terminal");
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("tool side effect unknown"))
            .unwrap();
        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        journal.resolve_all_in_doubt_v1(&pending).unwrap();
        assert_eq!(journal.recovery_headroom_bytes, 0);
        drop(journal);
        store
            .open_with_byte_limit("active-turn-mcp-in-doubt", exact_limit)
            .expect("the exact-limit transaction must reopen cleanly");
    }

    #[test]
    fn live_in_doubt_suspension_keeps_builtin_siblings_out_of_mcp_authority() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mixed-in-doubt-sibling", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-mixed-in-doubt");
        let arguments = json!({});
        let provenance = test_mcp_provenance_v2(epoch, digest, &arguments);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mixed-in-doubt"),
                json!({
                    "response_attempt_id":"attempt-mixed-in-doubt",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mixed-in-doubt"),
                json!({
                    "response_attempt_id":"attempt-mixed-in-doubt",
                    "output_items":[
                        {
                            "type":"function_call",
                            "call_id":"call-mixed-in-doubt-mcp",
                            "name":provider_name,
                            "arguments":"{}",
                        },
                        {
                            "type":"function_call",
                            "call_id":"call-mixed-in-doubt-builtin",
                            "name":"read",
                            "arguments":"{\"path\":\"README.md\"}",
                        },
                    ],
                }),
            )
            .unwrap();
        let mut tool_admission = journal
            .append_mcp_tool_started_v1(
                "turn-mixed-in-doubt",
                json!({
                    "call_id":"call-mixed-in-doubt-mcp",
                    "tool":provider_name,
                    "arguments":arguments,
                    "mcp":provenance.clone(),
                }),
            )
            .unwrap();
        let started_seq = tool_admission.started_seq();
        journal
            .commit_mcp_tool_terminal_v1(
                &mut tool_admission,
                "tool.in_doubt",
                json!({
                    "started_seq":started_seq,
                    "call_id":"call-mixed-in-doubt-mcp",
                    "tool":provider_name,
                    "output":{"error":{"code":"in_doubt","message":"unknown"}},
                    "is_error":true,
                    "error_code":"in_doubt",
                    "before_dispatch":false,
                    "mcp":provenance,
                }),
            )
            .unwrap();
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("tool side effect unknown"))
            .expect("live suspension must settle the builtin sibling generically");

        let events = journal.read_events().unwrap();
        assert!(
            !events
                .iter()
                .any(|event| event.kind == "tool.skipped_due_to_recovery")
        );
        assert!(events.iter().any(|event| {
            event.kind == "tool.skipped_due_to_in_doubt"
                && event.data["call_id"] == "call-mixed-in-doubt-builtin"
                && event.data.get("generic_recovery_skip_version").is_none()
        }));
        let marker = events
            .iter()
            .find(|event| event.kind == RECOVERY_KIND)
            .expect("in-doubt lineage still requires its generic marker");
        assert_eq!(marker.data["skipped_before_start"], 0);
        assert!(marker.data.get("unstarted_tool_calls").is_none());
        assert!(
            !serde_json::to_string(&marker.data)
                .unwrap()
                .contains("README.md")
        );
        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 1);
        journal.resolve_all_in_doubt_v1(&pending).unwrap();
        drop(journal);
        store
            .open("mixed-in-doubt-sibling")
            .expect("resolved split lifecycle must reopen cleanly");
    }

    #[test]
    fn live_in_doubt_suspension_reopen_does_not_duplicate_marker_or_drift_skip_count() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mixed-in-doubt-reopen", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-mixed-in-doubt-reopen");
        let arguments = json!({});
        let provenance = test_mcp_provenance_v2(epoch, digest, &arguments);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mixed-in-doubt-reopen"),
                json!({
                    "response_attempt_id":"attempt-mixed-in-doubt-reopen",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mixed-in-doubt-reopen"),
                json!({
                    "response_attempt_id":"attempt-mixed-in-doubt-reopen",
                    "output_items":[
                        {"type":"function_call","call_id":"call-mixed-reopen-mcp","name":provider_name,"arguments":"{}"},
                        {"type":"function_call","call_id":"call-mixed-reopen-builtin","name":"read","arguments":"{\"path\":\"README.md\"}"},
                    ],
                }),
            )
            .unwrap();
        let mut tool_admission = journal
            .append_mcp_tool_started_v1(
                "turn-mixed-in-doubt-reopen",
                json!({
                    "call_id":"call-mixed-reopen-mcp",
                    "tool":provider_name,
                    "arguments":arguments,
                    "mcp":provenance.clone(),
                }),
            )
            .unwrap();
        let started_seq = tool_admission.started_seq();
        journal
            .commit_mcp_tool_terminal_v1(
                &mut tool_admission,
                "tool.in_doubt",
                json!({
                    "started_seq":started_seq,
                    "call_id":"call-mixed-reopen-mcp",
                    "tool":provider_name,
                    "output":{"error":{"code":"in_doubt","message":"unknown"}},
                    "is_error":true,
                    "error_code":"in_doubt",
                    "before_dispatch":false,
                    "mcp":provenance,
                }),
            )
            .unwrap();
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("tool side effect unknown"))
            .unwrap();
        drop(journal);

        let first = store
            .open("mixed-in-doubt-reopen")
            .expect("first reopen must preserve suspended transaction");
        let first_events = first.read_events().unwrap();
        let first_markers = first_events
            .iter()
            .filter(|e| e.kind == RECOVERY_KIND)
            .count();
        assert_eq!(first_markers, 1);
        let first_skip_count = first_events
            .iter()
            .filter(|e| e.kind == "tool.skipped_due_to_in_doubt")
            .count();
        assert_eq!(first_skip_count, 1);
        drop(first);

        let second = store
            .open("mixed-in-doubt-reopen")
            .expect("second reopen must not append another marker");
        let second_events = second.read_events().unwrap();
        assert_eq!(
            second_events
                .iter()
                .filter(|e| e.kind == RECOVERY_KIND)
                .count(),
            first_markers,
            "reopen must reuse the existing in-doubt marker"
        );
        assert_eq!(
            second_events
                .iter()
                .filter(|e| e.kind == "tool.skipped_due_to_in_doubt")
                .count(),
            first_skip_count
        );
    }

    #[test]
    fn active_turn_mcp_completed_call_preserves_sibling_recovery_debt() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("active-turn-mcp-sibling-debt", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-active-mcp-sibling");
        let arguments = json!({});
        let first_provenance = test_mcp_provenance_v2(epoch, digest, &arguments);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-active-mcp-sibling"),
                json!({
                    "response_attempt_id":"attempt-active-mcp-sibling",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-active-mcp-sibling"),
                json!({
                    "response_attempt_id":"attempt-active-mcp-sibling",
                    "output_items":[
                        {
                            "type":"function_call",
                            "call_id":"call-active-mcp-first",
                            "name":provider_name,
                            "arguments":"{}",
                        },
                        {
                            "type":"function_call",
                            "call_id":"call-active-mcp-second",
                            "name":provider_name,
                            "arguments":"{}",
                        },
                    ],
                }),
            )
            .unwrap();

        let mut tool_admission = journal
            .append_mcp_tool_started_v1(
                "turn-active-mcp-sibling",
                json!({
                    "call_id":"call-active-mcp-first",
                    "tool":provider_name,
                    "arguments":arguments,
                    "mcp":first_provenance.clone(),
                }),
            )
            .unwrap();
        let started_seq = tool_admission.started_seq();
        let reserved = journal
            .active_mcp_tool
            .as_ref()
            .expect("active MCP reserve")
            .headroom_bytes;
        let exact_limit = journal.file.metadata().unwrap().len() + reserved;
        journal.set_byte_limit_for_tests(exact_limit);
        journal
            .commit_mcp_tool_terminal_v1(
                &mut tool_admission,
                "tool.completed",
                json!({
                    "started_seq":started_seq,
                    "call_id":"call-active-mcp-first",
                    "tool":provider_name,
                    "output":{"structuredContent":{"blob":"x".repeat(50 * 1024)}},
                    "is_error":false,
                    "error_code":null,
                    "before_dispatch":false,
                    "mcp":first_provenance,
                }),
            )
            .expect("the bounded complete result must fit beside sibling recovery debt");
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("second call not dispatched"))
            .unwrap();
        assert!(journal.in_doubt().unwrap().is_empty());
        assert_eq!(
            journal
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "tool.skipped_due_to_recovery")
                .count(),
            1
        );
        drop(journal);
        store
            .open_with_byte_limit("active-turn-mcp-sibling-debt", exact_limit)
            .expect("sibling recovery must fit the same dispatch reservation");
    }

    #[test]
    fn mixed_mcp_builtin_recovery_reserve_matches_the_split_transaction() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mixed-mcp-builtin-recovery-debt", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let turn_admission = admit_test_turn(&mut journal, "turn-mixed-recovery-debt");
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mixed-recovery-debt"),
                json!({
                    "response_attempt_id":"attempt-mixed-recovery-debt",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mixed-recovery-debt"),
                json!({
                    "response_attempt_id":"attempt-mixed-recovery-debt",
                    "output_items":[
                        {
                            "type":"function_call",
                            "call_id":"call-mixed-mcp",
                            "name":provider_name,
                            "arguments":"{}",
                        },
                        {
                            "type":"function_call",
                            "call_id":"call-mixed-builtin",
                            "name":"read",
                            "arguments":"{\"path\":\"README.md\"}",
                        },
                    ],
                }),
            )
            .expect("mixed response must reserve its split recovery transaction");
        let reserved = journal
            .active_turn
            .as_ref()
            .expect("active turn recovery reserve")
            .headroom_bytes;
        let exact_limit = journal.file.metadata().unwrap().len() + reserved;
        drop(turn_admission);
        drop(journal);

        let recovered = store
            .open_with_byte_limit("mixed-mcp-builtin-recovery-debt", exact_limit)
            .expect("split recovery must fit the admission-time reserve");
        let events = recovered.read_events().unwrap();
        let marker = events
            .iter()
            .find(|event| event.kind == RECOVERY_KIND)
            .expect("mixed recovery has one audit/authority marker");
        let authorizations = marker.data["unstarted_tool_calls"].as_array().unwrap();
        assert_eq!(authorizations.len(), 1);
        assert_eq!(authorizations[0]["call_id"], "call-mixed-mcp");
        assert!(
            !serde_json::to_string(&marker.data)
                .unwrap()
                .contains("README.md")
        );
        assert!(events.iter().any(|event| {
            event.kind == "tool.skipped_due_to_recovery"
                && event.data["call_id"] == "call-mixed-mcp"
        }));
        assert!(events.iter().any(|event| {
            event.kind == "tool.skipped_due_to_cancel"
                && event.data["call_id"] == "call-mixed-builtin"
                && event.data["generic_recovery_skip_version"] == GENERIC_RECOVERY_SKIP_VERSION_V1
        }));
        drop(recovered);
        let reopened = store
            .open_with_byte_limit("mixed-mcp-builtin-recovery-debt", exact_limit)
            .expect("repeat reopen must not invent another recovery transaction");
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
    fn provider_dispatch_admission_is_exclusive_and_single_use() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-dispatch-capability", header(temp.path()))
            .unwrap();
        let mut turn_admission = admit_test_turn(&mut journal, "turn-provider");
        let mut admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
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
        journal
            .finish_turn_transaction_v1(&mut turn_admission, None)
            .unwrap();
    }

    #[test]
    fn provider_dispatch_without_active_turn_is_rejected_without_writing() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-dispatch-no-active-turn", header(temp.path()))
            .unwrap();
        let mut turn_admission = admit_test_turn(&mut journal, "turn-provider");
        // A stale caller may retain the capability after the journal-side
        // reservation has disappeared.  The real dispatch primitive must
        // fail before constructing or appending response.started.
        journal.active_turn = None;
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        let error = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-provider",
                json!({
                    "response_attempt_id":"attempt-provider",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect_err("dispatch without an active turn must fail closed");
        assert!(error.to_string().contains("turn transaction"), "{error}");
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);

        // Do not let the intentionally stale capability poison subsequent
        // assertions if this test is extended later.
        turn_admission.consumed = true;
    }

    #[test]
    fn provider_dispatch_headroom_survives_crash_recovery_at_the_same_limit() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-dispatch-recovery-headroom", header(temp.path()))
            .unwrap();
        let turn_admission = admit_test_turn(&mut journal, "turn-provider");
        let current_size = journal.file.metadata().unwrap().len();
        let byte_limit = current_size
            + TURN_OUTCOME_HEADROOM_BYTES_V1
            + PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1
            + 16 * 1024;
        journal.set_byte_limit_for_tests(byte_limit);
        let admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-provider",
                json!({
                    "response_attempt_id":"attempt-provider",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect("the exact dispatch reserve must fit");
        drop(admission);
        drop(turn_admission);
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
        let mut turn_admission = admit_test_turn(&mut journal, "turn-provider");
        let current_size = journal.file.metadata().unwrap().len();
        let byte_limit = current_size
            + TURN_OUTCOME_HEADROOM_BYTES_V1
            + PROVIDER_RESPONSE_OUTCOME_HEADROOM_BYTES_V1
            + 16 * 1024;
        journal.set_byte_limit_for_tests(byte_limit);
        let mut admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
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
        journal
            .finish_turn_transaction_v1(&mut turn_admission, None)
            .unwrap();
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
                &turn_admission,
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
                &turn_admission,
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
    fn partial_mcp_registry_claim_is_rejected_before_provider_start_is_written() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-partial-mcp-claim", header(temp.path()))
            .unwrap();
        let (epoch, _, _) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-partial-mcp-claim");
        let before = journal.read_events().unwrap();

        let error = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-partial-mcp-claim",
                json!({
                    "response_attempt_id":"attempt-partial-mcp-claim",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                }),
            )
            .expect_err("a partial registry claim must fail before Provider dispatch");
        assert!(matches!(error, DispatchAdmissionErrorV1::Fatal(_)));
        assert_eq!(journal.read_events().unwrap(), before);

        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("invalid MCP registry claim"))
            .unwrap();
    }

    #[test]
    fn generic_provider_admission_rejects_complete_mcp_claim_before_fsync() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-complete-mcp-claim", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-complete-mcp-claim");
        let before = journal.read_events().unwrap();

        let error = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-complete-mcp-claim",
                json!({
                    "response_attempt_id":"attempt-complete-mcp-claim",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .expect_err("generic Provider admission must not acquire MCP response authority");
        assert!(matches!(error, DispatchAdmissionErrorV1::Fatal(_)));
        assert!(
            error.to_string().contains("typed MCP Provider writer"),
            "{error}"
        );
        assert_eq!(journal.read_events().unwrap(), before);

        journal
            .finish_turn_transaction_v1(
                &mut turn_admission,
                Some("MCP response requires typed ownership"),
            )
            .unwrap();
    }

    #[test]
    fn mcp_context_tools_reference_is_rejected_before_provider_start_is_written() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-mcp-context-tools-reference", header(temp.path()))
            .unwrap();
        append_test_mcp_activation_v2(&mut journal);
        let surface = journal
            .append_mcp_event_and_sync_v1(
                "context.tools",
                None,
                json!({
                    "version":1,
                    "digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "tools":[],
                    "mcp":{},
                }),
            )
            .unwrap();
        let mut turn_admission = admit_test_turn(&mut journal, "turn-mcp-context-tools");
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        let error = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-mcp-context-tools",
                json!({
                    "response_attempt_id":"attempt-mcp-context-tools",
                    "response_index":1,
                    "context":{
                        "measurement":{"request_digest":"digest"},
                        "tools_event_seq":surface.seq,
                    },
                }),
            )
            .expect_err("an MCP context.tools relation requires the typed Provider writer");
        assert!(matches!(error, DispatchAdmissionErrorV1::Fatal(_)));
        assert!(
            error.to_string().contains("typed MCP Provider writer"),
            "{error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);

        journal
            .finish_turn_transaction_v1(
                &mut turn_admission,
                Some("MCP surface requires typed Provider authority"),
            )
            .unwrap();
    }

    #[test]
    fn generic_builtin_provider_response_remains_valid_after_mcp_activation() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-builtin-after-mcp-activation", header(temp.path()))
            .unwrap();
        append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-builtin-after-activation");
        let mut response_admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-builtin-after-activation",
                json!({
                    "response_attempt_id":"attempt-builtin-after-activation",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .expect("a generic Provider start remains valid after MCP activation");
        journal
            .append_provider_response_completed_v1(
                &mut response_admission,
                json!({
                    "response_attempt_id":"attempt-builtin-after-activation",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-builtin-after-activation",
                        "name":"read",
                        "arguments":"{}",
                    }],
                }),
            )
            .expect("a builtin-only completion remains on the generic Provider path");
        journal
            .append_and_sync(
                "tool.started",
                Some("turn-builtin-after-activation"),
                json!({
                    "call_id":"call-builtin-after-activation",
                    "tool":"read",
                    "arguments":{},
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.completed",
                Some("turn-builtin-after-activation"),
                json!({
                    "call_id":"call-builtin-after-activation",
                    "tool":"read",
                    "output":{"ok":true},
                    "is_error":false,
                    "error_code":null,
                }),
            )
            .unwrap();
        journal
            .finish_turn_transaction_v1(
                &mut turn_admission,
                Some("generic builtin admission regression complete"),
            )
            .unwrap();
        drop(journal);

        let reopened = store
            .open("provider-builtin-after-mcp-activation")
            .expect("the generic builtin response must reopen under the MCP reader");
        crate::mcp::validate_mcp_call_chain(&reopened.read_events().unwrap()).unwrap();
    }

    #[test]
    fn activated_mcp_alias_completion_is_rejected_before_fsync_and_can_fallback() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("provider-activated-mcp-alias", header(temp.path()))
            .unwrap();
        let (_, _, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let mut turn_admission = admit_test_turn(&mut journal, "turn-activated-mcp-alias");
        let mut response_admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-activated-mcp-alias",
                json!({
                    "response_attempt_id":"attempt-activated-mcp-alias",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();
        let before = journal.read_events().unwrap();

        let error = journal
            .append_provider_response_completed_v1(
                &mut response_admission,
                json!({
                    "response_attempt_id":"attempt-activated-mcp-alias",
                    "raw_response":{"output":[{
                        "type":"function_call",
                        "call_id":"call-activated-mcp-alias",
                        "name":provider_name,
                        "arguments":"{}",
                    }]},
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-activated-mcp-alias",
                        "name":provider_name,
                        "arguments":"{}",
                    }],
                    "text":"",
                    "usage":{},
                }),
            )
            .expect_err("generic Provider admission cannot author an activated MCP alias");
        assert!(
            error.to_string().contains("typed MCP Provider writer"),
            "{error}"
        );
        assert_eq!(journal.read_events().unwrap(), before);

        journal
            .append_provider_response_failed_v1(
                &mut response_admission,
                "activated MCP alias requires typed ownership",
            )
            .expect("the still-live admission must authorize a bounded failure fallback");
        journal
            .finish_turn_transaction_v1(&mut turn_admission, None)
            .unwrap();
        drop(journal);

        let reopened = store.open("provider-activated-mcp-alias").unwrap();
        let events = reopened.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.completed")
                .count(),
            0
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.failed")
                .count(),
            1
        );
        crate::mcp::validate_mcp_call_chain(&events).unwrap();
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
        let turn_admission = admit_test_turn(&mut journal, "turn-response-drop");
        let admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
                "turn-response-drop",
                json!({
                    "response_attempt_id":"attempt-response-drop",
                    "response_index":1,
                    "context":{"measurement":{"request_digest":"digest"}},
                }),
            )
            .unwrap();
        drop(admission);
        drop(turn_admission);
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
        let turn_admission = admit_test_turn(&mut journal, "turn-context-limit");
        let context = json!({"measurement":{"request_digest":"context-digest"}});
        let mut admission = journal
            .append_provider_response_started_v1(
                &turn_admission,
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
    fn recovers_builtin_function_call_without_mcp_authority() {
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
            .find(|event| event.kind == "tool.skipped_due_to_cancel")
            .unwrap();
        assert_eq!(skipped.data["call_id"], "call-from-id");
        assert_eq!(skipped.data["error_code"], "cancelled");
        assert_eq!(
            skipped.data["generic_recovery_skip_version"],
            GENERIC_RECOVERY_SKIP_VERSION_V1
        );
        assert_eq!(skipped.data["recovered"], true);
        assert_eq!(skipped.data["arguments"], "{\"path\":\"calc.py\"}");
        assert!(skipped.data.get("recovery_marker_seq").is_none());
        let marker = events
            .iter()
            .find(|event| event.kind == RECOVERY_KIND)
            .expect("recovery marker exists");
        assert!(marker.seq < skipped.seq);
        assert!(marker.data.get("tool_skip_authorization_version").is_none());
        assert!(marker.data.get("unstarted_tool_calls").is_none());
        assert!(
            !serde_json::to_string(&marker.data)
                .unwrap()
                .contains("calc.py")
        );
        drop(recovered);

        let reopened = store.open("unstarted-tool").unwrap();
        assert_eq!(reopened.recovery_info().skipped_before_start, 1);
        let reopened_events = reopened.read_events().unwrap();
        assert_eq!(
            reopened_events
                .iter()
                .filter(|event| event.kind == "tool.skipped_due_to_cancel")
                .count(),
            1
        );
        assert_eq!(
            reopened_events
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1,
            "repeat reopen must reuse the aggregate recovery marker"
        );
    }

    #[test]
    fn generic_recovery_skip_profile_is_versioned_and_fail_closed() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-recovery-profile", header(temp.path()))
            .unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "tool.skipped_due_to_cancel",
                Some("turn-generic-recovery"),
                json!({
                    "call_id":"call-generic-recovery",
                    "tool":"read",
                    "arguments":"{}",
                    "response_seq":1,
                    "reason":GENERIC_RECOVERY_SKIP_REASON_V1,
                    "output":{"error":{"code":"cancelled","message":GENERIC_RECOVERY_SKIP_MESSAGE_V1}},
                    "is_error":true,
                    "error_code":"cancelled",
                    "generic_recovery_skip_version":2,
                    "recovered":true,
                }),
            )
            .expect_err("unknown generic recovery terminal versions must fail before fsync")
            .to_string();
        assert!(error.contains("invalid generic recovery skip profile"));
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_recovery_skip_profile_freezes_exact_shape_and_output() {
        let valid = generic_recovery_skip_event(
            "generic-profile-shape",
            2,
            1,
            "turn-profile",
            "call-profile",
            "read",
            json!({"path":"README.md"}),
        );
        validate_generic_recovery_skip_profile_v1(&valid).unwrap();

        let mut missing_version = valid.clone();
        missing_version
            .data
            .as_object_mut()
            .unwrap()
            .remove("generic_recovery_skip_version");
        assert!(validate_generic_recovery_skip_profile_v1(&missing_version).is_err());

        let mut forged_output = valid.clone();
        forged_output.data["output"]["error"]["message"] = Value::String("forged".to_owned());
        assert!(validate_generic_recovery_skip_profile_v1(&forged_output).is_err());

        let mut unknown_field = valid.clone();
        unknown_field.data["mcp"] = json!({"forged":true});
        assert!(validate_generic_recovery_skip_profile_v1(&unknown_field).is_err());

        let mut missing_arguments = valid;
        missing_arguments
            .data
            .as_object_mut()
            .unwrap()
            .remove("arguments");
        assert!(validate_generic_recovery_skip_profile_v1(&missing_arguments).is_err());
    }

    #[test]
    fn generic_recovery_skip_rejects_non_integer_response_seq_without_panicking() {
        let valid = generic_recovery_skip_event(
            "generic-response-seq-type",
            2,
            1,
            "turn-profile",
            "call-profile",
            "read",
            json!({"path":"README.md"}),
        );
        for malformed in [Value::Null, Value::String("1".to_owned()), json!(1.5)] {
            let mut event = valid.clone();
            event.data["response_seq"] = malformed;
            assert!(
                validate_generic_recovery_skip_profile_v1(&event).is_err(),
                "non-integer response_seq must fail closed"
            );
            assert!(
                validate_generic_recovery_skips_v1(&[
                    generic_function_call_event(
                        "generic-response-seq-type",
                        1,
                        "turn-profile",
                        "call-profile",
                        "read",
                        json!({"path":"README.md"}),
                    ),
                    event,
                ])
                .is_err(),
                "binding validation must return an error rather than panic"
            );
        }
    }

    #[test]
    fn generic_recovery_skip_binds_one_exact_unstarted_occurrence() {
        let response = generic_function_call_event(
            "generic-binding",
            1,
            "turn-a",
            "shared",
            "read",
            json!({"path":"a"}),
        );
        let valid = generic_recovery_skip_event(
            "generic-binding",
            2,
            1,
            "turn-a",
            "shared",
            "read",
            json!({"path":"a"}),
        );
        validate_generic_recovery_skips_v1(&[response.clone(), valid.clone()]).unwrap();

        let mut wrong_arguments = valid.clone();
        wrong_arguments.data["arguments"] = json!({"path":"b"});
        assert!(validate_generic_recovery_skips_v1(&[response.clone(), wrong_arguments]).is_err());

        let mut wrong_tool = valid.clone();
        wrong_tool.data["tool"] = Value::String("write".to_owned());
        assert!(validate_generic_recovery_skips_v1(&[response.clone(), wrong_tool]).is_err());

        let mut cross_turn = valid.clone();
        cross_turn.turn_id = Some("turn-b".to_owned());
        assert!(validate_generic_recovery_skips_v1(&[response.clone(), cross_turn]).is_err());

        assert!(validate_generic_recovery_skips_v1(std::slice::from_ref(&valid)).is_err());
        let mut duplicate = valid.clone();
        duplicate.seq = 3;
        assert!(validate_generic_recovery_skips_v1(&[response.clone(), valid, duplicate]).is_err());

        let newer = generic_function_call_event(
            "generic-binding",
            2,
            "turn-a",
            "shared",
            "write",
            json!({"path":"new"}),
        );
        let stale = generic_recovery_skip_event(
            "generic-binding",
            3,
            1,
            "turn-a",
            "shared",
            "read",
            json!({"path":"a"}),
        );
        assert!(validate_generic_recovery_skips_v1(&[response, newer, stale]).is_err());
    }

    #[test]
    fn forged_generic_recovery_skip_fails_reopen_without_writing() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "forged-generic-recovery";
        let mut journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let response = journal
            .append_and_sync(
                "response.completed",
                Some("turn-forged-generic"),
                json!({"output_items":[{
                    "type":"function_call",
                    "call_id":"call-forged-generic",
                    "name":"read",
                    "arguments":{"path":"a"},
                }]}),
            )
            .unwrap();
        let path = journal.journal_path().to_owned();
        let seq = journal.next_seq();
        drop(journal);

        let mut forged = generic_recovery_skip_event(
            session_id,
            seq,
            response.seq,
            "turn-forged-generic",
            "call-forged-generic",
            "read",
            json!({"path":"different"}),
        );
        forged.ts = Utc::now();
        let mut encoded = serde_json::to_vec(&forged).unwrap();
        encoded.push(b'\n');
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&encoded)
            .unwrap();
        let before = fs::read(&path).unwrap();

        let error = store
            .open(session_id)
            .err()
            .expect("forged generic recovery authority must fail closed")
            .to_string();
        assert!(error.contains("exact durable Provider call"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn recovery_authorization_index_reuses_only_valid_v1_markers() {
        let tool = UnstartedTool {
            response_seq: 2,
            turn_id: Some("turn-marker".to_owned()),
            call_id: "call-marker".to_owned(),
            tool_name: Some("read".to_owned()),
            arguments: Some(json!({"path":"calc.py"})),
        };
        let recovery = RecoveryInfo {
            skipped_before_start: 1,
            ..RecoveryInfo::default()
        };
        let data = recovery_marker_data(&recovery, std::slice::from_ref(&tool)).unwrap();
        let authorization = data["unstarted_tool_calls"][0].clone();
        let authorization_key = serde_json::to_string(&authorization).unwrap();
        let event = |seq, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: RECOVERY_KIND.to_owned(),
            session_id: "marker-index".to_owned(),
            turn_id: None,
            data,
        };

        let valid = event(7, data.clone());
        let index = recovery_authorization_index(std::slice::from_ref(&valid)).unwrap();
        assert_eq!(index.get(&authorization_key), Some(&7));

        let marker_before_response = event(2, data.clone());
        assert!(
            recovery_authorization_index(std::slice::from_ref(&marker_before_response))
                .unwrap()
                .is_empty()
        );

        let mut wrong_version = data.clone();
        wrong_version["tool_skip_authorization_version"] = Value::from(2);
        assert!(
            recovery_authorization_index(&[event(8, wrong_version)])
                .unwrap()
                .is_empty()
        );

        let mut duplicate = data;
        duplicate["unstarted_tool_calls"] =
            Value::Array(vec![authorization.clone(), authorization]);
        assert!(
            recovery_authorization_index(&[event(9, duplicate)])
                .unwrap()
                .is_empty()
        );

        let mut malformed = valid.data.clone();
        malformed["unstarted_tool_calls"][0]["arguments_sha256"] = Value::String("bad".to_owned());
        assert!(
            recovery_authorization_index(&[event(10, malformed)])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn in_doubt_marker_lineage_requires_versioned_exact_durable_prefix() {
        let base = Utc::now();
        let event = |seq, kind: &str, data| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: base,
            kind: kind.to_owned(),
            session_id: "in-doubt-lineage-profile".to_owned(),
            turn_id: Some("turn-lineage".to_owned()),
            data,
        };
        let mut events = vec![
            event(
                1,
                "tool.started",
                json!({"call_id":"call-lineage","tool":"read","arguments":{"path":"a"}}),
            ),
            event(
                2,
                "tool.in_doubt",
                json!({
                    "started_seq":1,
                    "call_id":"call-lineage",
                    "tool":"read",
                    "arguments":{"path":"a"},
                    "error_code":"in_doubt",
                }),
            ),
        ];
        let pending = pending_tools(&events);
        let marker = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 3,
            ts: base,
            kind: RECOVERY_KIND.to_owned(),
            session_id: "in-doubt-lineage-profile".to_owned(),
            turn_id: None,
            data: recovery_marker_data(
                &RecoveryInfo {
                    in_doubt: pending.clone(),
                    ..RecoveryInfo::default()
                },
                &[],
            )
            .unwrap(),
        };
        events.push(marker);
        assert!(recovery_marker_covers_in_doubt_v1(&events, 2, &pending));

        let mut unversioned = events.clone();
        unversioned[2]
            .data
            .as_object_mut()
            .unwrap()
            .remove("in_doubt_resolution_authorization_version");
        assert!(!recovery_marker_covers_in_doubt_v1(
            &unversioned,
            2,
            &pending
        ));
        assert!(
            in_doubt_future_marker_headroom_v1(
                "in-doubt-lineage-profile",
                &unversioned,
                &pending,
                &[],
            )
            .unwrap()
                > 0
        );

        let mut forged_payload = events.clone();
        forged_payload[2].data["in_doubt"][0]["arguments"] = json!({"path":"different"});
        assert!(!recovery_marker_covers_in_doubt_v1(
            &forged_payload,
            2,
            &pending
        ));
    }

    #[test]
    fn recovery_marker_scan_rejects_short_snapshots_without_rescanning_wide_pending_state() {
        let base = Utc::now();
        let mut events = (0..128u64)
            .map(|index| JournalEvent {
                schema: JOURNAL_SCHEMA,
                seq: index + 1,
                ts: base,
                kind: "tool.started".to_owned(),
                session_id: "wide-marker-lineage".to_owned(),
                turn_id: Some("turn-wide".to_owned()),
                data: json!({
                    "call_id": format!("call-{index}"),
                    "tool": "read",
                    "arguments": {"index": index},
                }),
            })
            .collect::<Vec<_>>();
        let pending = pending_tools(&events);
        let short = vec![pending[0].clone()];
        for index in 0..256u64 {
            events.push(JournalEvent {
                schema: JOURNAL_SCHEMA,
                seq: 129 + index,
                ts: base,
                kind: RECOVERY_KIND.to_owned(),
                session_id: "wide-marker-lineage".to_owned(),
                turn_id: None,
                data: recovery_marker_data(
                    &RecoveryInfo {
                        in_doubt: short.clone(),
                        ..RecoveryInfo::default()
                    },
                    &[],
                )
                .unwrap(),
            });
        }
        let expected_seq = 385;
        events.push(JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: expected_seq,
            ts: base,
            kind: RECOVERY_KIND.to_owned(),
            session_id: "wide-marker-lineage".to_owned(),
            turn_id: None,
            data: recovery_marker_data(
                &RecoveryInfo {
                    in_doubt: pending.clone(),
                    ..RecoveryInfo::default()
                },
                &[],
            )
            .unwrap(),
        });
        let recovery = RecoveryInfo {
            in_doubt: pending.clone(),
            ..RecoveryInfo::default()
        };

        assert_eq!(
            matching_recovery_marker(&events, &recovery),
            Some(expected_seq)
        );
        assert!(recovery_marker_covers_current_in_doubt_v1(
            &events, &pending
        ));
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
                None,
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
    fn generic_unstarted_arguments_remain_raw_during_recovery_classification() {
        let raw_arguments = format!("{{\"blob\":\"{}\"}}", "x".repeat(1024 * 1024));
        let events = vec![JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 1,
            ts: Utc::now(),
            kind: "response.completed".to_owned(),
            session_id: "generic-raw-arguments".to_owned(),
            turn_id: Some("turn-generic-raw".to_owned()),
            data: json!({
                "output_items":[{
                    "type":"function_call",
                    "call_id":"call-generic-raw",
                    "name":"read",
                    "arguments":raw_arguments,
                }]
            }),
        }];
        let unstarted = unstarted_tool_calls(&events);
        assert_eq!(unstarted.len(), 1);
        assert_eq!(
            unstarted[0].arguments.as_ref().and_then(Value::as_str),
            Some(raw_arguments.as_str())
        );
        let (mcp, generic) = partition_unstarted_tools_v1(&events, &unstarted).unwrap();
        assert!(mcp.is_empty());
        assert_eq!(
            generic[0].arguments.as_ref().and_then(Value::as_str),
            Some(raw_arguments.as_str())
        );
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
    fn generic_writer_rejects_invalid_mcp_response_before_fsync() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("invalid-mcp-response", header(temp.path()))
            .unwrap();
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        journal
            .append_mcp_event_and_sync_v1(
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
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp"),
                json!({
                    "response_attempt_id":"attempt-1",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mcp"),
                json!({
                    "response_attempt_id":"attempt-1",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-1",
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":"{}"
                    }]
                }),
            )
            .unwrap();
        let original_events = journal.read_events().unwrap();
        let original_size = journal.file.metadata().unwrap().len();
        let original_seq = journal.next_seq();

        let error = journal
            .append_and_sync(
                "response.completed",
                Some("turn-mcp"),
                json!({
                    "response_attempt_id":"attempt-1",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-2",
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":"{}"
                    }]
                }),
            )
            .expect_err("generic writer must reject a second MCP response terminal")
            .to_string();
        assert!(
            error.contains("has 2 terminals"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), original_events);
        assert_eq!(journal.file.metadata().unwrap().len(), original_size);
        assert_eq!(journal.next_seq(), original_seq);
    }

    #[test]
    fn generic_writer_rejects_fresh_mcp_activation_without_mutating_journal() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-fresh-mcp-activation", header(temp.path()))
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "mcp.registry.activated",
                None,
                json!({
                    "coordinator_version":2,
                    "call_chain_validator_version":2,
                    "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000201",
                    "registry_epoch_id":"0190f5e6-7b00-7abc-8000-000000000202",
                    "registry_version":1,
                    "stdio_kernel_version":1,
                    "schema_profile_version":1,
                    "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "registry_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "bindings":[{
                        "provider_name":"mcp_fixture_echo_deadbeef",
                        "server_name":"fixture",
                        "raw_tool_name":"echo",
                        "protocol_version":"2026-07-28"
                    }]
                }),
            )
            .expect_err("generic writers cannot create MCP activation authority")
            .to_string();
        assert!(
            error.contains("typed MCP authority"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn mcp_capability_cannot_author_unrelated_journal_events() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mcp-capability-scope", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        let activation_seq = journal.next_seq() - 1;
        let capability = McpJournalWriteCapabilityV1::for_test(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            activation_seq,
            "0190f5e6-7b00-7abc-8000-000000000201".to_owned(),
            epoch.to_owned(),
            digest.to_owned(),
            Arc::new(AtomicBool::new(true)),
        );
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        let error = journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "note",
                None,
                json!({"message":"must use the generic writer"}),
            )
            .expect_err("MCP capability must not bypass unrelated writer authority")
            .to_string();

        assert!(
            error.contains("not an MCP-reserved event") || error.contains("cannot author"),
            "{error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn public_mcp_capability_cannot_author_tool_lifecycle_without_dispatch_admission() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mcp-capability-tool-scope", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let capability = McpJournalWriteCapabilityV1::for_test(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            journal.next_seq() - 1,
            "0190f5e6-7b00-7abc-8000-000000000201".to_owned(),
            epoch.to_owned(),
            digest.to_owned(),
            Arc::new(AtomicBool::new(true)),
        );
        let turn_id = "mcp-capability-tool-turn";
        let call_id = "mcp-capability-tool-call";
        let call_item = json!({
            "type":"function_call",
            "call_id":call_id,
            "name":provider_name,
            "arguments":"{}",
        });
        journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "response.started",
                Some(turn_id),
                json!({
                    "response_attempt_id":"mcp-capability-tool-response",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "response.completed",
                Some(turn_id),
                json!({
                    "response_attempt_id":"mcp-capability-tool-response",
                    "raw_response":{"output":[call_item.clone()]},
                    "output_items":[call_item],
                    "text":"",
                    "usage":{},
                }),
            )
            .unwrap();

        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "tool.completed",
                Some(turn_id),
                json!({
                    "call_id":call_id,
                    "tool":provider_name,
                    "output":{"ok":true},
                    "is_error":false,
                    "error_code":null,
                    "mcp_execution_coordinator_version":2,
                    "registry_epoch_id":epoch,
                    "registry_digest":digest,
                }),
            )
            .expect_err("public epoch capability must not replace a dispatch admission")
            .to_string();
        assert!(error.contains("cannot author"), "unexpected error: {error}");
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn activated_alias_completion_requires_exact_mcp_owned_response_start() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mcp-alias-owned-response", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let capability = McpJournalWriteCapabilityV1::for_test(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            journal.next_seq() - 1,
            "0190f5e6-7b00-7abc-8000-000000000201".to_owned(),
            epoch.to_owned(),
            digest.to_owned(),
            Arc::new(AtomicBool::new(true)),
        );
        journal
            .append_and_sync(
                "response.started",
                Some("generic-start-turn"),
                json!({"response_attempt_id":"generic-start-attempt"}),
            )
            .unwrap();
        let call_item = json!({
            "type":"function_call",
            "call_id":"generic-start-mcp-alias-call",
            "name":provider_name,
            "arguments":"{}",
        });
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        let error = journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "response.completed",
                Some("generic-start-turn"),
                json!({
                    "response_attempt_id":"generic-start-attempt",
                    "raw_response":{"output":[call_item.clone()]},
                    "output_items":[call_item],
                    "text":"",
                    "usage":{},
                }),
            )
            .expect_err("an activated alias cannot upgrade a generic response terminal")
            .to_string();
        assert!(
            error.contains("without an exact MCP-owned response.started"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_tool_lifecycle_rejects_wrong_turn_and_legacy_mcp_identity() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-tool-identity-boundary", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let response_turn = "durable-mcp-turn";
        let call_id = "durable-mcp-call";
        let call_item = json!({
            "type":"function_call",
            "call_id":call_id,
            "name":provider_name,
            "arguments":"{}",
        });
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some(response_turn),
                json!({
                    "response_attempt_id":"durable-mcp-response",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some(response_turn),
                json!({
                    "response_attempt_id":"durable-mcp-response",
                    "raw_response":{"output":[call_item.clone()]},
                    "output_items":[call_item],
                    "text":"",
                    "usage":{},
                }),
            )
            .unwrap();

        for data in [
            json!({
                "call_id":call_id,
                "tool":provider_name,
                "output":{"ok":true},
            }),
            json!({
                "id":call_id,
                "tool":provider_name,
                "output":{"ok":true},
            }),
        ] {
            let before_events = journal.read_events().unwrap();
            let before_size = journal.file.metadata().unwrap().len();
            let before_seq = journal.next_seq();
            let error = journal
                .append_and_sync("tool.completed", Some("wrong-turn"), data)
                .expect_err("generic tool identity mutation must fail before fsync")
                .to_string();
            assert!(
                error.contains("does not reference a durable MCP Provider call")
                    || error.contains("canonical call_id"),
                "unexpected error: {error}"
            );
            assert_eq!(journal.read_events().unwrap(), before_events);
            assert_eq!(journal.file.metadata().unwrap().len(), before_size);
            assert_eq!(journal.next_seq(), before_seq);
        }
    }

    #[test]
    fn mixed_mcp_response_keeps_builtin_tool_lifecycle_on_generic_writer() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mixed-mcp-builtin-batch", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        let turn_id = "mixed-mcp-builtin-turn";
        journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({"turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION}),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some(turn_id),
                json!({
                    "response_attempt_id":"mixed-mcp-builtin-response",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        let mcp_call = json!({
            "type":"function_call",
            "call_id":"mixed-mcp-call",
            "name":provider_name,
            "arguments":"{}",
        });
        let builtin_call = json!({
            "type":"function_call",
            "call_id":"mixed-builtin-call",
            "name":"read",
            "arguments":"{\"path\":\"fixture.txt\"}",
        });
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some(turn_id),
                json!({
                    "response_attempt_id":"mixed-mcp-builtin-response",
                    "raw_response":{"output":[mcp_call.clone(), builtin_call.clone()]},
                    "output_items":[mcp_call, builtin_call],
                    "text":"",
                    "usage":{},
                }),
            )
            .unwrap();

        journal
            .append_and_sync(
                "tool.started",
                Some(turn_id),
                json!({
                    "call_id":"mixed-builtin-call",
                    "tool":"read",
                    "arguments":{"path":"fixture.txt"},
                }),
            )
            .expect("a proven builtin call remains on the generic writer");
        journal
            .append_and_sync(
                "tool.completed",
                Some(turn_id),
                json!({
                    "call_id":"mixed-builtin-call",
                    "tool":"read",
                    "output":{"text":"fixture"},
                }),
            )
            .expect("builtin terminal remains writable in an MCP-owned response batch");
        crate::mcp::validate_mcp_call_chain(&journal.read_events().unwrap())
            .expect("mixed batch remains valid for the MCP reader");
    }

    #[test]
    fn revoked_mcp_capability_cannot_author_after_coordinator_shutdown() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("mcp-capability-revoked", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        let authority_active = Arc::new(AtomicBool::new(true));
        let capability = McpJournalWriteCapabilityV1::for_test(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            journal.next_seq() - 1,
            "0190f5e6-7b00-7abc-8000-000000000201".to_owned(),
            epoch.to_owned(),
            digest.to_owned(),
            Arc::clone(&authority_active),
        );
        authority_active.store(false, Ordering::Release);

        let before_events = journal.read_events().unwrap();
        let error = journal
            .append_mcp_event_with_capability_v1(
                &capability,
                "response.started",
                Some("turn-revoked-capability"),
                json!({
                    "response_attempt_id":"attempt-revoked-capability",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .expect_err("revoked coordinator authority must fail closed")
            .to_string();
        assert!(error.contains("revoked"), "{error}");
        assert_eq!(journal.read_events().unwrap(), before_events);
    }

    #[test]
    fn v3_surface_reference_requires_mcp_writer_authority_without_flat_claims() {
        let make_event = |seq: u64, kind: &str, turn_id: Option<&str>, data: Value| JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: kind.to_owned(),
            session_id: "v3-surface-authority".to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            data,
        };
        let activation = make_event(
            1,
            "mcp.registry.activated",
            None,
            json!({"call_chain_validator_version":3}),
        );
        let surface = make_event(
            2,
            "context.tools",
            None,
            json!({"digest":"a", "tools":[], "mcp":{}}),
        );
        let start = make_event(
            3,
            "response.started",
            Some("turn-v3-surface-authority"),
            json!({
                "response_attempt_id":"attempt-v3-surface-authority",
                "context":{"tools_event_seq":2},
            }),
        );
        let terminal = make_event(
            4,
            "response.failed",
            Some("turn-v3-surface-authority"),
            json!({"response_attempt_id":"attempt-v3-surface-authority"}),
        );
        let prefix = vec![activation, surface, start];
        assert!(response_started_references_mcp_surface_v1(
            &prefix, &prefix[2]
        ));
        assert!(response_terminal_may_belong_to_claimed_mcp_attempt_v1(
            &prefix, &terminal
        ));

        let malformed_start = make_event(
            5,
            "response.started",
            Some("turn-v3-surface-authority-2"),
            json!({
                "response_attempt_id":"attempt-v3-surface-authority-2",
                "context":{"tools_event_seq":999},
            }),
        );
        assert!(response_started_references_mcp_surface_v1(
            &prefix,
            &malformed_start
        ));
    }

    #[test]
    fn generic_writer_rejects_mcp_terminal_identity_mutations() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id(
                "generic-mcp-terminal-identity-mutations",
                header(temp.path()),
            )
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp-terminal-identity"),
                json!({
                    "response_attempt_id":"attempt-mcp-terminal-identity",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();

        for (turn_id, attempt_id) in [
            (
                Some("turn-mcp-terminal-identity"),
                Some("different-attempt"),
            ),
            (None, Some("attempt-mcp-terminal-identity")),
            (
                Some("different-turn"),
                Some("attempt-mcp-terminal-identity"),
            ),
            (Some("different-turn"), Some("different-attempt")),
        ] {
            let before_events = journal.read_events().unwrap();
            let before_size = journal.file.metadata().unwrap().len();
            let before_seq = journal.next_seq();
            let mut data = json!({"error":"provider failed"});
            if let Some(attempt_id) = attempt_id {
                data["response_attempt_id"] = Value::String(attempt_id.to_owned());
            }
            let error = journal
                .append_and_sync("response.failed", turn_id, data)
                .expect_err("mutated MCP terminal must stay on the typed writer path")
                .to_string();
            assert!(
                error.contains("MCP authority")
                    || error.contains("typed MCP authority")
                    || error.contains("response"),
                "unexpected error: {error}"
            );
            assert_eq!(journal.read_events().unwrap(), before_events);
            assert_eq!(journal.file.metadata().unwrap().len(), before_size);
            assert_eq!(journal.next_seq(), before_seq);
        }
    }

    #[test]
    fn generic_writer_rejects_mcp_aborted_terminal_identity_mutation() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-mcp-aborted-identity-mutation", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp-aborted-identity"),
                json!({
                    "response_attempt_id":"attempt-mcp-aborted-identity",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "response.aborted",
                Some("different-turn"),
                json!({
                    "response_attempt_id":"different-attempt",
                    "reason":"provider cancelled",
                }),
            )
            .expect_err("mutated MCP aborted terminal must be rejected before fsync")
            .to_string();
        assert!(
            error.contains("MCP authority")
                || error.contains("typed MCP authority")
                || error.contains("response"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_preserves_valid_non_mcp_response_after_activation() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-response-after-mcp-activation", header(temp.path()))
            .unwrap();
        append_test_mcp_activation_v2(&mut journal);
        journal
            .append_and_sync(
                "user.message",
                Some("turn-generic-after-activation"),
                json!({"turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("turn-generic-after-activation"),
                json!({"response_attempt_id":"attempt-generic-after-activation"}),
            )
            .expect("valid generic response start remains outside MCP authority");
        journal
            .append_and_sync(
                "response.failed",
                Some("turn-generic-after-activation"),
                json!({
                    "response_attempt_id":"attempt-generic-after-activation",
                    "error":"provider failed",
                }),
            )
            .expect("exact generic response terminal remains outside MCP authority");
        crate::mcp::validate_mcp_call_chain(&journal.read_events().unwrap())
            .expect("generic response remains valid under the post-activation reader");
    }

    #[test]
    fn generic_writer_rejects_mcp_lifecycle_without_turn_identity() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-mcp-lifecycle-without-turn", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp-no-turn"),
                json!({
                    "response_attempt_id":"attempt-mcp-no-turn",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mcp-no-turn"),
                json!({
                    "response_attempt_id":"attempt-mcp-no-turn",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-mcp-no-turn",
                        "name":provider_name,
                        "arguments":"{}"
                    }]
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "tool.completed",
                None,
                json!({
                    "call_id":"call-mcp-no-turn",
                    "tool":provider_name,
                    "output":{"ok":true},
                }),
            )
            .expect_err("MCP lifecycle without turn_id must not use generic authority")
            .to_string();
        assert!(
            error.contains("MCP authority")
                || error.contains("typed MCP authority")
                || error.contains("turn_id"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_rejects_claimed_response_start_without_mutating_journal() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-claimed-response-start", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "response.started",
                Some("turn-claimed-response"),
                json!({
                    "response_attempt_id":"attempt-claimed-response",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .expect_err("generic writers cannot create an MCP response claim")
            .to_string();
        assert!(
            error.contains("typed MCP authority"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_rejects_markerless_mcp_lifecycle_without_mutating_journal() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-markerless-mcp-lifecycle", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_and_sync(
                "user.message",
                Some("turn-markerless-mcp"),
                json!({"turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION}),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-markerless-mcp"),
                json!({
                    "response_attempt_id":"attempt-markerless-mcp",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-markerless-mcp"),
                json!({
                    "response_attempt_id":"attempt-markerless-mcp",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-markerless-mcp",
                        "name":provider_name,
                        "arguments":"{}"
                    }]
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "tool.completed",
                Some("turn-markerless-mcp"),
                json!({
                    "call_id":"call-markerless-mcp",
                    "tool":provider_name,
                    "output":{"ok":true},
                }),
            )
            .expect_err("markerless MCP lifecycle must use typed authority")
            .to_string();
        assert!(
            error.contains("typed MCP authority")
                || error.contains("MCP provenance")
                || error.contains("pre-start MCP authority"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_rejects_activated_alias_response_without_mutating_journal() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-activated-alias-response", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-activated-alias"),
                json!({
                    "response_attempt_id":"attempt-activated-alias",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();
        let error = journal
            .append_and_sync(
                "response.completed",
                Some("turn-activated-alias"),
                json!({
                    "response_attempt_id":"attempt-activated-alias",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-activated-alias",
                        "name":provider_name,
                        "arguments":"{}"
                    }]
                }),
            )
            .expect_err("activated MCP aliases cannot be authored generically")
            .to_string();
        assert!(
            error.contains("typed MCP authority") || error.contains("owned"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_rejects_orphan_mcp_surface_markers_before_fsync() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("orphan-mcp-surface", header(temp.path()))
            .unwrap();
        let original_events = journal.read_events().unwrap();
        let original_size = journal.file.metadata().unwrap().len();
        let original_seq = journal.next_seq();

        for (kind, turn_id, data) in [
            (
                "context.tools",
                None,
                json!({
                    "version":1,
                    "digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "tools":[],
                    "mcp":{},
                }),
            ),
            (
                "response.started",
                Some("turn-orphan-surface"),
                json!({
                    "response_attempt_id":"attempt-orphan-surface",
                    "mcp_surface":{
                        "version":1,
                        "event_seq":2,
                        "digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    },
                }),
            ),
        ] {
            let error = journal
                .append_and_sync(kind, turn_id, data)
                .expect_err("orphan MCP surface authority must fail before fsync")
                .to_string();
            assert!(
                error.contains("without a registry activation"),
                "unexpected error: {error}"
            );
            assert_eq!(journal.read_events().unwrap(), original_events);
            assert_eq!(journal.file.metadata().unwrap().len(), original_size);
            assert_eq!(journal.next_seq(), original_seq);
        }
    }

    #[test]
    fn generic_writer_rejects_mcp_terminal_that_strips_authority_before_fsync() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-mcp-terminal-boundary", header(temp.path()))
            .unwrap();
        let (epoch, digest, provider_name) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_and_sync(
                "user.message",
                Some("turn-mcp-terminal-boundary"),
                json!({"turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION}),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp-terminal-boundary"),
                json!({
                    "response_attempt_id":"attempt-mcp-terminal-boundary",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.completed",
                Some("turn-mcp-terminal-boundary"),
                json!({
                    "response_attempt_id":"attempt-mcp-terminal-boundary",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-mcp-terminal-boundary",
                        "name":provider_name,
                        "arguments":"{}"
                    }]
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        // A generic caller can still name the MCP call, but it must not be
        // able to settle it while omitting the exact coordinator authority.
        let error = journal
            .append_and_sync(
                "tool.completed",
                Some("turn-mcp-terminal-boundary"),
                json!({
                    "call_id":"call-mcp-terminal-boundary",
                    "tool":provider_name,
                    "output":{"ok":true},
                }),
            )
            .expect_err("MCP terminal provenance must be checked before fsync")
            .to_string();
        assert!(error.contains("MCP authority"), "unexpected error: {error}");
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
    }

    #[test]
    fn generic_writer_rejects_mcp_terminal_with_missing_response_identity() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("generic-mcp-missing-response-id", header(temp.path()))
            .unwrap();
        let (epoch, digest, _) = append_test_mcp_activation_v2(&mut journal);
        journal
            .append_and_sync(
                "user.message",
                Some("turn-mcp-missing-response-id"),
                json!({"turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION}),
            )
            .unwrap();
        journal
            .append_mcp_event_and_sync_v1(
                "response.started",
                Some("turn-mcp-missing-response-id"),
                json!({
                    "response_attempt_id":"attempt-missing-response-id",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            )
            .unwrap();
        let before_events = journal.read_events().unwrap();
        let before_size = journal.file.metadata().unwrap().len();
        let before_seq = journal.next_seq();

        let error = journal
            .append_and_sync(
                "response.failed",
                Some("turn-mcp-missing-response-id"),
                json!({"error":"missing attempt identity"}),
            )
            .expect_err("claimed MCP response terminal must bind an exact attempt")
            .to_string();
        assert!(
            error.contains("response_attempt_id"),
            "unexpected error: {error}"
        );
        assert_eq!(journal.read_events().unwrap(), before_events);
        assert_eq!(journal.file.metadata().unwrap().len(), before_size);
        assert_eq!(journal.next_seq(), before_seq);
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
    fn partial_in_doubt_resolution_reuses_one_marker_lineage_at_the_reserved_limit() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("partial-resolution-marker-lineage", header(temp.path()))
            .unwrap();
        let mut turn = admit_test_turn(&mut journal, "turn-resolution");
        let context = json!({
            "measurement":{"request_digest":"context-digest"},
            "tools_event_seq":1,
        });
        let large_arguments = json!({"blob":"x".repeat(300_000)});
        let large_wire = serde_json::to_string(&large_arguments).unwrap();
        let mut response = journal
            .append_provider_response_started_v1(
                &turn,
                "turn-resolution",
                json!({
                    "response_attempt_id":"attempt-resolution",
                    "response_index":1,
                    "context":context,
                }),
            )
            .unwrap();
        journal
            .append_provider_response_completed_v1(
                &mut response,
                json!({
                    "response_attempt_id":"attempt-resolution",
                    "output_items":[
                        {
                            "type":"function_call",
                            "call_id":"small-call",
                            "name":"read",
                            "arguments":"{}",
                        },
                        {
                            "type":"function_call",
                            "call_id":"large-call",
                            "name":"read",
                            "arguments":large_wire,
                        },
                    ],
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.started",
                Some("turn-resolution"),
                json!({"call_id":"small-call","tool":"read","arguments":{}}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-resolution"),
                json!({
                    "call_id":"small-call",
                    "tool":"read",
                    "arguments":{},
                    "error_code":"in_doubt",
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.started",
                Some("turn-resolution"),
                json!({
                    "call_id":"large-call",
                    "tool":"read",
                    "arguments":large_arguments,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.in_doubt",
                Some("turn-resolution"),
                json!({
                    "call_id":"large-call",
                    "tool":"read",
                    "arguments":large_arguments,
                    "error_code":"in_doubt",
                }),
            )
            .unwrap();
        journal
            .finish_turn_transaction_v1(&mut turn, Some("test interruption"))
            .unwrap();

        let pending = journal.in_doubt().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].call_id.as_deref(), Some("small-call"));
        let current_size = journal.file.metadata().unwrap().len();
        let byte_limit = current_size + journal.recovery_headroom_bytes;
        journal.set_byte_limit_for_tests(byte_limit);

        // Model a crash after the first complete resolution line but before
        // the second call or its parent turn terminal is written.
        let mut planned_seq = journal.next_seq();
        let first_resolution = planned_recovery_event(
            journal.session_id(),
            &mut planned_seq,
            "tool.in_doubt_resolved",
            pending[0].turn_id.as_deref(),
            in_doubt_resolution_data_v1(&pending[0]).unwrap(),
        )
        .unwrap();
        journal
            .append_prebuilt_batch_with_limit(std::slice::from_ref(&first_resolution), byte_limit)
            .unwrap();
        drop(journal);

        let mut recovered = store
            .open_with_byte_limit("partial-resolution-marker-lineage", byte_limit)
            .expect("the original debt must cover one marker and the remaining resolution");
        let remaining = recovered.in_doubt().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].call_id.as_deref(), Some("large-call"));
        assert_eq!(
            recovered
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1
        );
        recovered.resolve_all_in_doubt_v1(&remaining).unwrap();
        drop(recovered);

        let reopened = store
            .open_with_byte_limit("partial-resolution-marker-lineage", byte_limit)
            .unwrap();
        assert!(reopened.in_doubt().unwrap().is_empty());
        let events = reopened.read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == RECOVERY_KIND)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "tool.in_doubt_resolved")
                .count(),
            2
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
    fn empty_kind_without_newline_is_rejected_without_normalization() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "empty-kind-no-newline";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let mut bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        let event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 2,
            ts: Utc::now(),
            kind: String::new(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data: json!({}),
        };
        bytes.push(b'\n');
        bytes.extend_from_slice(&serde_json::to_vec(&event).unwrap());
        fs::write(&path, &bytes).unwrap();

        let before = fs::read(&path).unwrap();
        let error = store
            .open(session_id)
            .err()
            .expect("empty event kind must fail closed before newline normalization");
        assert!(
            error.to_string().contains("event kind cannot be empty"),
            "{error}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn every_partial_first_header_is_rejected_without_repair_or_mutation() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "partial-first-header";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let complete = fs::read(&path).unwrap();
        assert_eq!(complete.last(), Some(&b'\n'));
        let json_len = complete.len() - 1;
        for cut in 0..json_len {
            let prefix = &complete[..cut];
            fs::write(&path, prefix).unwrap();

            let error = store
                .open(session_id)
                .err()
                .unwrap_or_else(|| panic!("header prefix of {cut} bytes was accepted"));
            assert!(
                error.to_string().contains("header") || error.to_string().contains("invalid"),
                "unexpected error for {cut}-byte prefix: {error}"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                prefix,
                "open mutated the {cut}-byte creation prefix"
            );
        }

        // The exact complete JSON record without only its final newline is a
        // different crash prefix: its creation commit is intact, so ordinary
        // newline normalization remains safe.
        fs::write(&path, &complete[..json_len]).unwrap();
        let reopened = store.open(session_id).unwrap();
        assert_eq!(reopened.next_seq(), 2);
        assert!(reopened.header().unwrap().is_some());
        assert!(reopened.recovery_info().normalized_missing_newline);
        assert!(reopened.recovery_info().truncated_tail.is_none());
        assert_eq!(fs::read(&path).unwrap(), complete);
    }

    #[test]
    fn reopen_requires_session_started_at_sequence_one_before_any_repair() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        for (session_id, kind, seq) in [
            ("missing-first-header", "custom.fixture", 1),
            ("misnumbered-first-header", SESSION_STARTED_KIND, 2),
        ] {
            let event = JournalEvent {
                schema: JOURNAL_SCHEMA,
                seq,
                ts: Utc::now(),
                kind: kind.to_owned(),
                session_id: session_id.to_owned(),
                turn_id: None,
                data: serde_json::to_value(header(temp.path())).unwrap(),
            };
            // Deliberately model a legacy schema-1 fixture with no bounded-v2
            // activation claim so structural validation is the decisive gate.
            let mut bytes = serde_json::to_vec(&event).unwrap();
            bytes.push(b'\n');
            let path = store.layout().journal_path(session_id).unwrap();
            fs::write(&path, &bytes).unwrap();

            let error = store
                .open(session_id)
                .err()
                .expect("invalid first event must be rejected")
                .to_string();
            assert!(error.contains("session.started at seq 1"), "{error}");
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn failed_atomic_header_write_leaves_no_discoverable_empty_session() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "failed-header-publish";
        let destination = store.layout().journal_path(session_id).unwrap();

        let error = write_new_file_atomically(&destination, |output| {
            output.write_all(br#"{"schema":1,"seq":1"#)?;
            Err(std::io::Error::other(
                "injected session header write failure",
            ))
        })
        .unwrap_err();

        assert!(matches!(error, AtomicNewFileError::BeforePublish(_)));
        assert!(!destination.exists());
        let error = store
            .open(session_id)
            .err()
            .expect("a failed atomic header write must not publish a session")
            .to_string();
        assert!(error.contains("session not found"), "{error}");
    }

    #[test]
    fn tail_syntax_classifier_distinguishes_valid_prefixes_from_invalid_open_json() {
        let complete = serde_json::to_vec(&json!({
            "text":"braces { } brackets [ ] quote \" slash \\",
            "array":[true,false,null,-12.5e3],
        }))
        .unwrap();
        assert_eq!(
            journal_tail_syntax_v1(&complete),
            JournalTailSyntaxV1::Complete
        );
        assert_eq!(
            journal_tail_syntax_v1(&complete[..complete.len() - 1]),
            JournalTailSyntaxV1::Incomplete,
            "a closed string containing structural characters must not close the root object"
        );
        assert_eq!(
            journal_tail_syntax_v1(br#"{"data":"\u12"#),
            JournalTailSyntaxV1::Incomplete
        );
        assert_eq!(
            journal_tail_syntax_v1(br#"{"data":!"#),
            JournalTailSyntaxV1::Invalid
        );
        assert_eq!(
            journal_tail_syntax_v1(br#"{"data":]}"#),
            JournalTailSyntaxV1::Invalid
        );
        assert_eq!(
            journal_tail_syntax_v1(br#"[]"#),
            JournalTailSyntaxV1::Invalid,
            "a journal record must have an object root"
        );
    }

    #[test]
    fn deep_incomplete_tail_outside_frozen_profile_is_not_truncated() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("deep-incomplete-tail", header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);
        let mut tail = format!(
            "{{\"schema\":{JOURNAL_SCHEMA},\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.deep_tail\",\"session_id\":\"deep-incomplete-tail\",\"turn_id\":null,\"data\":"
        )
        .into_bytes();
        for _ in 0..(MAX_JOURNAL_EVENT_DEPTH_V2 + 10) {
            tail.extend_from_slice(b"{\"child\":");
        }
        tail.extend_from_slice(b"null");
        assert_eq!(
            journal_tail_syntax_v1(&tail),
            JournalTailSyntaxV1::Incomplete
        );
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&tail)
            .unwrap();

        let before = fs::read(&path).unwrap();
        let error = store
            .open("deep-incomplete-tail")
            .err()
            .expect("a completion outside the frozen profile must fail closed")
            .to_string();
        assert!(
            error.contains("depth") || error.contains("recursion"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "an unrepairable deep tail must remain byte-for-byte intact"
        );

        let archive = temp.path().join(format!(
            "deep-incomplete-tail.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"
        ));
        store
            .export_read_only_snapshot("deep-incomplete-tail", &archive)
            .unwrap();
        let archive_bytes = fs::read(archive).unwrap();
        let manifest_end = archive_bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
        assert_eq!(&archive_bytes[manifest_end + 1..], before);
    }

    #[test]
    fn invalid_open_tail_is_not_silently_truncated() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("invalid-open-tail", header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);
        let invalid_tail = br#"{"data":!"#;
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(invalid_tail)
            .unwrap();
        let before = fs::read(&path).unwrap();

        let error = store
            .open("invalid-open-tail")
            .err()
            .expect("invalid JSON is not recoverable crash debris")
            .to_string();
        assert!(error.contains("invalid"), "unexpected error: {error}");
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn incomplete_tail_requires_a_frozen_reader_completion_witness() {
        let cases = [
            ("overlong-utf8", b"{\"data\":\"\xe0\x80".as_slice()),
            ("lone-low-surrogate", br#"{"data":"\uDC00"#),
            ("broken-high-surrogate", br#"{"data":"\uD800x"#),
            ("out-of-range-number", br#"{"data":1e9999"#),
            ("unsupported-schema", br#"{"schema":999"#),
        ];

        for (name, tail) in cases {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("unrecoverable-{name}");
            let journal = store
                .create_with_id(&session_id, header(temp.path()))
                .unwrap();
            let path = journal.journal_path().to_owned();
            drop(journal);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(tail)
                .unwrap();
            let before = fs::read(&path).unwrap();

            store
                .open(&session_id)
                .err()
                .unwrap_or_else(|| panic!("{name} tail must fail closed"));
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "{name} tail must remain byte-for-byte intact"
            );

            let archive = temp
                .path()
                .join(format!("{name}.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"));
            store
                .export_read_only_snapshot(&session_id, &archive)
                .unwrap();
            let archive_bytes = fs::read(archive).unwrap();
            let manifest_end = archive_bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap();
            assert_eq!(&archive_bytes[manifest_end + 1..], before);
        }
    }

    #[test]
    fn bounded_tail_repairs_real_writer_timestamp_and_sequence_prefixes() {
        for (name, prior_events, needle, prefix_len) in [
            ("timestamp", 0usize, b"\"ts\":\"" as &[u8], 4usize),
            ("sequence", 10usize, b"\"seq\":" as &[u8], 1usize),
        ] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("canonical-tail-{name}");
            let mut journal = store
                .create_with_id(&session_id, header(temp.path()))
                .unwrap();
            for n in 0..prior_events {
                journal
                    .append_custom_and_sync("custom.prior", None, json!({"n": n}))
                    .unwrap();
            }
            let path = journal.journal_path().to_owned();
            let target_start = fs::read(&path).unwrap().len();
            journal
                .append_custom_and_sync("custom.writer_prefix", None, json!({"text": "ok"}))
                .unwrap();
            drop(journal);

            let complete = fs::read(&path).unwrap();
            let record = &complete[target_start..];
            let marker = record
                .windows(needle.len())
                .position(|bytes| bytes == needle)
                .unwrap();
            let cut = marker + needle.len() + prefix_len;
            let prefix = &complete[..target_start + cut];
            fs::write(&path, prefix).unwrap();

            let reopened = store
                .open(&session_id)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(reopened.recovery_info().truncated_tail.is_some());
            assert_eq!(
                reopened.recovery_info().marker_seq,
                Some((prior_events + 2) as u64)
            );
        }
    }

    const WRITER_TIMESTAMP_FIXTURES: &[&str] = &[
        "2026-09-08T12:34:56Z",
        "2026-09-08T12:34:56.001Z",
        "2026-09-08T12:34:56.100Z",
        "2026-09-08T12:34:56.000001Z",
        "2026-09-08T12:34:56.123001Z",
        "2026-09-08T12:34:56.123100Z",
        "2026-09-08T12:34:56.000000001Z",
        "2026-09-08T12:34:56.000001001Z",
        "2026-09-08T12:34:56.123000001Z",
        "2026-09-08T12:34:56.123456001Z",
        "2026-09-08T12:34:56.123456100Z",
        "2024-02-29T23:59:59.123456789Z",
    ];

    #[test]
    fn timestamp_completion_preserves_every_fixed_writer_prefix() {
        for timestamp in WRITER_TIMESTAMP_FIXTURES {
            let value = DateTime::parse_from_rfc3339(timestamp)
                .unwrap()
                .with_timezone(&Utc);
            let encoded = serde_json::to_vec(&value).unwrap();
            assert_eq!(encoded, format!("\"{timestamp}\"").as_bytes());
            for cut in 1..encoded.len() {
                let prefix = &encoded[..cut];
                let suffix = journal_timestamp_completion_suffix_v1(prefix, 0)
                    .unwrap_or_else(|| panic!("{timestamp}: cannot complete timestamp cut {cut}"));
                let mut completed = prefix.to_vec();
                completed.extend_from_slice(&suffix);
                let parsed: DateTime<Utc> = serde_json::from_slice(&completed).unwrap();
                assert_eq!(serde_json::to_vec(&parsed).unwrap(), completed);
                assert!(completed.starts_with(prefix));
            }
        }
    }

    #[test]
    fn bounded_tail_rejects_impossible_timestamp_prefixes_without_modifying_evidence() {
        for timestamp in [
            "2026-09-08T12:34:56.1230Z",
            "2026-09-08T12:34:56.123000Z",
            "2026-09-08T12:34:56.123456000Z",
            "2026-09-08T12:34:56.000Z",
            "2026-09-08T12:34:56.Z",
            "2026-09-08T12:34:56.1234567890",
            "2026-09-08T12:34:56+00:00",
            "2026-09-08T12:34:56z",
            "2026-02-30T12:34:56",
            "2026-09-08T25",
        ] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = "impossible-timestamp-tail";
            let journal = store
                .create_with_id(session_id, header(temp.path()))
                .unwrap();
            let path = journal.journal_path().to_owned();
            drop(journal);
            let mut before = fs::read(&path).unwrap();
            before.extend_from_slice(
                format!("{{\"schema\":{JOURNAL_SCHEMA},\"seq\":2,\"ts\":\"{timestamp}").as_bytes(),
            );
            fs::write(&path, &before).unwrap();
            assert!(store.open(session_id).is_err(), "must reject {timestamp}");
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "must preserve {timestamp}"
            );
        }
    }

    #[test]
    fn bounded_tail_repairs_every_real_writer_record_prefix() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "canonical-prefix";
        let mut journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        for n in 0..10 {
            journal
                .append_custom_and_sync("custom.prior", None, json!({"n": n}))
                .unwrap();
        }
        let path = journal.journal_path().to_owned();
        let target_start = fs::read(&path).unwrap().len();
        let mut event = journal
            .append_custom_and_sync(
                "custom.writer_prefix",
                None,
                json!({"text": "prefix €\u{0001}"}),
            )
            .unwrap();
        drop(journal);
        let baseline = fs::read(&path).unwrap()[..target_start].to_vec();

        // Use the production encoder with fixed timestamps, not Utc::now():
        // AutoSi's precision depends on the actual fractional-second digits.
        for timestamp in WRITER_TIMESTAMP_FIXTURES {
            event.ts = DateTime::parse_from_rfc3339(timestamp)
                .unwrap()
                .with_timezone(&Utc);
            let record = encode_journal_event_v2(&event).unwrap();
            for cut in 1..=record.len() {
                let mut prefix = baseline.clone();
                prefix.extend_from_slice(&record[..cut]);
                fs::write(&path, prefix).unwrap();
                let reopened = store.open(session_id).unwrap_or_else(|error| {
                    panic!(
                        "{timestamp}: writer prefix cut {cut}/{} must reopen: {error}",
                        record.len()
                    )
                });
                if cut < record.len() {
                    let recovery = reopened.recovery_info();
                    assert_eq!(
                        recovery.truncated_tail.as_ref().unwrap().byte_count,
                        cut as u64
                    );
                    assert_eq!(recovery.marker_seq, Some(event.seq));
                } else {
                    assert!(reopened.recovery_info().normalized_missing_newline);
                }
                drop(reopened);
                assert!(fs::read(&path).unwrap().starts_with(&baseline));
                // Opening a recovered journal again must not repair it twice.
                let repaired = fs::read(&path).unwrap();
                drop(store.open(session_id).unwrap());
                assert_eq!(fs::read(&path).unwrap(), repaired);
            }
        }
    }

    #[test]
    fn bounded_tail_repairs_real_writer_utf8_and_control_escape_prefixes() {
        for (name, text, needle) in [
            ("utf8", "€", &[0xe2, 0x82][..]),
            ("control-escape", "\u{0001}", br#"\u000"#.as_slice()),
        ] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("canonical-tail-{name}");
            let mut journal = store
                .create_with_id(&session_id, header(temp.path()))
                .unwrap();
            let path = journal.journal_path().to_owned();
            let header_bytes = fs::read(&path).unwrap().len();
            journal
                .append_custom_and_sync("custom.writer_prefix", None, json!({"text":text}))
                .unwrap();
            drop(journal);
            let complete = fs::read(&path).unwrap();
            let tail = &complete[header_bytes..];
            let cut = tail
                .windows(needle.len())
                .position(|bytes| bytes == needle)
                .unwrap()
                + needle.len();
            fs::write(&path, &complete[..header_bytes + cut]).unwrap();
            let reopened = store
                .open(&session_id)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                reopened
                    .recovery_info()
                    .truncated_tail
                    .as_ref()
                    .unwrap()
                    .byte_count,
                cut as u64
            );
            assert_eq!(reopened.recovery_info().marker_seq, Some(2));
        }
    }

    #[test]
    fn bounded_tail_rejects_noncanonical_unicode_reader_completions() {
        for suffix in [br#""\u12"#.as_slice(), br#""\uD800"#.as_slice()] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = "noncanonical-unicode-tail";
            let journal = store
                .create_with_id(session_id, header(temp.path()))
                .unwrap();
            let path = journal.journal_path().to_owned();
            drop(journal);
            let mut tail = format!(
                "{{\"schema\":1,\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.partial\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":"
            ).into_bytes();
            tail.extend_from_slice(suffix);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&tail)
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(store.open(session_id).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn bounded_tail_must_be_a_prefix_of_the_exact_writer_encoding() {
        for (name, tail) in [
            ("unknown-root-field", br#"{"x":"#.as_slice()),
            ("reordered-envelope", br#"{"seq":2,"#.as_slice()),
        ] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = format!("noncanonical-{name}");
            let journal = store
                .create_with_id(&session_id, header(temp.path()))
                .unwrap();
            let path = journal.journal_path().to_owned();
            drop(journal);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(tail)
                .unwrap();
            let before = fs::read(&path).unwrap();

            store
                .open(&session_id)
                .err()
                .unwrap_or_else(|| panic!("{name} must not borrow a synthetic reader completion"));
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "{name} must remain byte-for-byte export evidence"
            );
        }
    }

    #[test]
    fn orphan_partial_compaction_checkpoint_has_no_repair_authority() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "orphan-partial-checkpoint";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let tail = format!(
            "{{\"schema\":{JOURNAL_SCHEMA},\"seq\":2,\"ts\":\"2026-08-22T00:00:00Z\",\"kind\":\"{COMPACTION_CHECKPOINT_KIND}\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":{{\"attempt_id\":\"orphan-attempt\""
        );
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(tail.as_bytes())
            .unwrap();
        let before = fs::read(&path).unwrap();

        store
            .open(session_id)
            .err()
            .expect("an orphan checkpoint tail must fail closed");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "an orphan checkpoint tail must remain exact export evidence"
        );

        let archive = temp.path().join(format!(
            "orphan-partial-checkpoint.{READ_ONLY_SESSION_EXPORT_EXTENSION_V1}"
        ));
        store
            .export_read_only_snapshot(session_id, &archive)
            .unwrap();
        let archive_bytes = fs::read(archive).unwrap();
        let manifest_end = archive_bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
        assert_eq!(&archive_bytes[manifest_end + 1..], before);
    }

    #[test]
    fn partial_compaction_checkpoint_with_matching_attempt_still_needs_recovery_witness() {
        for raw_response_tail in ["{", "null"] {
            let temp = TempDir::new().unwrap();
            let store = SessionStore::new(temp.path()).unwrap();
            let session_id = "forged-partial-checkpoint";
            let mut journal = store
                .create_with_id(session_id, header(temp.path()))
                .unwrap();
            let user = journal
                .append_and_sync(
                    "user.message",
                    Some("compact-turn"),
                    json!({
                        "item": {"role": "user", "content": "compact me"},
                        "turn_boundary_version": crate::turn::TURN_BOUNDARY_VERSION,
                    }),
                )
                .unwrap();
            let response_seq = journal.next_seq();
            let response = journal
                .append_and_sync(
                    "response.completed",
                    Some("compact-turn"),
                    json!({
                        "response_attempt_id": "compact-response",
                        "raw_response": {
                            "id": "compact-response",
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
                            "turn_boundary_version": crate::turn::TURN_BOUNDARY_VERSION,
                            "covers_from_seq": user.seq,
                            "final_response_seq": response_seq,
                            "covers_through_seq": response_seq,
                        },
                    }),
                )
                .unwrap();
            let marker_seq = journal.next_seq();
            journal
                .append_and_sync(
                    "turn.completed",
                    Some("compact-turn"),
                    json!({
                        "turn_boundary_version": crate::turn::TURN_BOUNDARY_VERSION,
                        "covers_from_seq": user.seq,
                        "final_response_seq": response.seq,
                        "covers_through_seq": marker_seq,
                    }),
                )
                .unwrap();
            let prefix_events = journal.read_events().unwrap();
            let source =
                crate::compaction::build_compaction_source(&prefix_events, None, marker_seq)
                    .unwrap();
            let source_digest = source.digest().unwrap();
            journal
            .append_and_sync(
                COMPACTION_STARTED_KIND,
                None,
                json!({
                    "attempt_id": "compact-1",
                    "parent_checkpoint_id": null,
                    "covers_through_seq": marker_seq,
                    "source": source,
                    "source_digest": source_digest,
                    "instructions": crate::compaction::compaction_instructions(
                        crate::compaction::COMPACTION_PROMPT_VERSION
                    )
                    .unwrap(),
                    "prompt_version": crate::compaction::COMPACTION_PROMPT_VERSION,
                    "summary_envelope_version": crate::compaction::SUMMARY_ENVELOPE_VERSION,
                    "source_projection_version": crate::projection::SOURCE_PROJECTION_VERSION,
                    "turn_boundary_validator_version": crate::turn::TURN_BOUNDARY_VALIDATOR_VERSION,
                    "source_digest_version": crate::compaction::SOURCE_DIGEST_VERSION,
                    "usage_contract_version": crate::compaction::USAGE_CONTRACT_VERSION,
                    "model": "test-model",
                }),
            )
            .unwrap();
            let checkpoint_seq = journal.next_seq();
            let path = journal.journal_path().to_owned();
            drop(journal);

            let prompt_version = crate::compaction::COMPACTION_PROMPT_VERSION;
            let tail = format!(
                "{{\"schema\":{JOURNAL_SCHEMA},\"seq\":{checkpoint_seq},\"ts\":\"2026-08-22T00:00:00Z\",\"kind\":\"{COMPACTION_CHECKPOINT_KIND}\",\"session_id\":\"{session_id}\",\"turn_id\":null,\"data\":{{\"attempt_id\":\"compact-1\",\"checkpoint_id\":\"forged\",\"covers_through_seq\":{marker_seq},\"duration_ms\":0,\"prompt_version\":{prompt_version},\"raw_response\":{raw_response_tail}"
            );
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(tail.as_bytes())
                .unwrap();
            let before = fs::read(&path).unwrap();

            let opened = store.open(session_id);
            let after = fs::read(&path).unwrap();
            if raw_response_tail == "null" {
                assert!(
                    opened.is_err(),
                    "a complete raw_response value must not receive partial repair authority"
                );
                assert_eq!(
                    after, before,
                    "a complete invalid raw_response value must remain exact evidence"
                );
            } else {
                assert!(
                    opened.is_ok(),
                    "a genuinely torn raw_response value remains recoverable"
                );
                assert_ne!(
                    after, before,
                    "a torn raw_response value should be settled by recovery"
                );
            }
        }
    }

    #[test]
    fn raw_tail_key_witness_is_top_level_and_escape_aware() {
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":null}"#, b"raw_response"),
            RawTailKeyWitnessV1::Complete
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":{}}"#, b"raw_response"),
            RawTailKeyWitnessV1::Complete
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":[]}"#, b"raw_response"),
            RawTailKeyWitnessV1::Complete
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":"done"}"#, b"raw_response"),
            RawTailKeyWitnessV1::Complete
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":{"#, b"raw_response"),
            RawTailKeyWitnessV1::Torn
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"raw_response":!"#, b"raw_response"),
            RawTailKeyWitnessV1::Invalid
        );
        assert_eq!(
            raw_tail_key_witness_v1(br#"{"data":{"other":1}"#, b"raw_response"),
            RawTailKeyWitnessV1::Absent
        );
        assert!(!raw_tail_contains_top_level_key_v1(
            br#"{"raw_response":{"output":1}}"#,
            b"raw_response"
        ));
        assert!(!raw_tail_contains_top_level_key_v1(
            br#"{"data":{"nested":{"raw_response":1}}}"#,
            b"raw_response"
        ));
        assert!(!raw_tail_contains_top_level_key_v1(
            b"{\"data\":{\"note\":\"\\\"raw_response\\\":\"}}",
            b"raw_response"
        ));
        assert!(raw_tail_contains_top_level_key_v1(
            br#"{"data":{"raw_\u0072esponse":{"output":1}}}"#,
            b"raw_response"
        ));
        assert!(raw_tail_contains_top_level_key_v1(
            br#"{"data":{"raw_response":{"output":"#,
            b"raw_response"
        ));
        assert_eq!(
            raw_tail_key_witness_v1(
                br#"{"data":{"raw_response":null,"later":{"#,
                b"raw_response"
            ),
            RawTailKeyWitnessV1::Complete,
            "a later torn value must not downgrade an already-complete target"
        );
        assert_eq!(
            raw_tail_key_witness_v1(
                br#"{"data":{"raw_response":null,"later":!"#,
                b"raw_response"
            ),
            RawTailKeyWitnessV1::Invalid,
            "an invalid outer value must never look like a complete target witness"
        );
    }

    #[test]
    fn invalid_complete_missing_newline_is_rejected_without_normalization() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "invalid-complete-no-newline";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let invalid = serde_json::to_vec(&json!({
            "schema": JOURNAL_SCHEMA,
            "seq": 2,
            "ts": "2026-08-22T00:00:00Z",
            "kind": "tool.started",
            "session_id": session_id,
            "turn_id": null,
            "data": {},
        }))
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&invalid)
            .unwrap();
        let before = fs::read(&path).unwrap();

        store
            .open(session_id)
            .err()
            .expect("a semantically invalid complete line must fail closed");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "newline normalization must wait for semantic validation"
        );
    }

    #[test]
    fn malformed_user_message_without_newline_is_rejected_without_normalization() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "invalid-user-message-no-newline";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let invalid = serde_json::to_vec(&JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 2,
            ts: Utc::now(),
            kind: "user.message".to_owned(),
            session_id: session_id.to_owned(),
            turn_id: Some("turn-1".to_owned()),
            data: json!({}),
        })
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&invalid)
            .unwrap();
        let before = fs::read(&path).unwrap();

        store
            .open(session_id)
            .err()
            .expect("a malformed user.message must fail closed");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "newline normalization must not mutate a malformed user.message"
        );
    }

    #[test]
    fn invalid_compaction_line_without_newline_is_not_normalized() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let session_id = "invalid-compaction-no-newline";
        let journal = store
            .create_with_id(session_id, header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let invalid = serde_json::to_vec(&JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: 2,
            ts: Utc::now(),
            kind: COMPACTION_STARTED_KIND.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: None,
            data: json!({}),
        })
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&invalid)
            .unwrap();
        let before = fs::read(&path).unwrap();

        store
            .open(session_id)
            .err()
            .expect("an invalid complete compaction line must fail closed");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "semantic validation must precede missing-newline normalization"
        );
    }

    #[test]
    fn complete_profile_rejected_tail_is_not_truncated_as_crash_debris() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let journal = store
            .create_with_id("deep-complete-tail", header(temp.path()))
            .unwrap();
        let path = journal.journal_path().to_owned();
        drop(journal);

        let mut bytes = fs::read(&path).unwrap();
        let prefix = format!(
            "{{\"schema\":{JOURNAL_SCHEMA},\"seq\":2,\"ts\":\"2026-08-21T00:00:00Z\",\"kind\":\"custom.deep_tail\",\"session_id\":\"deep-complete-tail\",\"turn_id\":null,\"data\":"
        );
        bytes.extend_from_slice(prefix.as_bytes());
        for _ in 0..(MAX_JOURNAL_EVENT_DEPTH_V2 + 8) {
            bytes.extend_from_slice(b"{\"child\":");
        }
        bytes.extend_from_slice(b"null");
        bytes.resize(bytes.len() + MAX_JOURNAL_EVENT_DEPTH_V2 + 8, b'}');
        bytes.push(b'}');
        fs::write(&path, &bytes).unwrap();

        let error = store
            .open("deep-complete-tail")
            .err()
            .expect("complete out-of-profile JSON must fail closed")
            .to_string();
        assert!(
            error.contains("depth") || error.contains("recursion limit"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "a complete invalid record must not be mistaken for an incomplete crash tail"
        );
    }

    #[test]
    fn prebuilt_batch_rejects_deep_payload_without_partial_write() {
        let temp = TempDir::new().unwrap();
        let store = SessionStore::new(temp.path()).unwrap();
        let mut journal = store
            .create_with_id("deep-prebuilt", header(temp.path()))
            .unwrap();
        let original = fs::read(journal.journal_path()).unwrap();
        let original_seq = journal.next_seq();
        let event = JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: original_seq,
            ts: Utc::now(),
            kind: "custom.deep_prebuilt".to_owned(),
            session_id: journal.session_id().to_owned(),
            turn_id: None,
            data: nested_object_value(20_000),
        };

        let error = journal
            .append_prebuilt_batch_with_limit(&[event], MAX_SESSION_BYTES)
            .expect_err("prebuilt writer must reject before writing")
            .to_string();
        assert!(error.contains("depth profile"), "unexpected error: {error}");
        assert_eq!(fs::read(journal.journal_path()).unwrap(), original);
        assert_eq!(journal.next_seq(), original_seq);
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
