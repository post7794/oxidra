//! Frozen validation for the durable MCP call lifecycle.
//!
//! Journal payloads are untrusted.  A provider alias that belongs to an MCP
//! registry only receives tool lifecycle semantics after this reducer proves
//! the activation, durable Provider call and every started/terminal edge.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::schema;
use crate::error::{OxidraError, Result};
use crate::event_kind::{is_response_terminal, is_tool_lifecycle, is_tool_terminal};
use crate::session::JournalEvent;

pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V1: u32 = 1;
pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V2: u32 = 2;
pub const MCP_CALL_CHAIN_VALIDATOR_VERSION: u32 = MCP_CALL_CHAIN_VALIDATOR_VERSION_V2;
const MAX_MCP_CALLS_PER_RESPONSE_V1: usize = 4_096;
pub const MAX_MCP_CALLS_PER_RESPONSE: usize = MAX_MCP_CALLS_PER_RESPONSE_V1;
const MCP_EXECUTION_COORDINATOR_VERSION_V1: u64 = 1;
const MCP_EXECUTION_COORDINATOR_VERSION_V2: u64 = 2;
const MCP_DISPATCH_PERMIT_VERSION_V1: u64 = 1;
const MCP_ARGUMENT_DIGEST_VERSION_V1: u64 = 1;
const MCP_TOOL_REGISTRY_VERSION_V1: u64 = 1;
const MCP_STDIO_KERNEL_VERSION_V1: u64 = 1;
const MCP_SCHEMA_PROFILE_VERSION_V1: u64 = 1;
const MCP_REGISTRY_ACTIVATED_KIND: &str = "mcp.registry.activated";

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct McpCallKey {
    turn_id: String,
    call_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RecoveryAuthorizationKey {
    response_seq: u64,
    turn_id: String,
    call_id: String,
    provider_name: String,
    arguments_sha256: String,
}

#[derive(Clone, Debug)]
struct RecoveryMarkerAuthority {
    skipped_before_start: u64,
    authorization_version: Option<u64>,
    authorization_count: Option<usize>,
    authorization_matches: HashMap<RecoveryAuthorizationKey, u8>,
}

#[derive(Clone, Debug)]
struct Activation {
    seq: u64,
    coordinator_version: u32,
    call_chain_validator_version: u32,
    schema_profile_version: u32,
    registry_epoch_id: String,
    registry_digest: String,
    execution_plan_digest: String,
    provider_names: BTreeSet<String>,
    bindings: Option<BTreeMap<String, BindingIdentity>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BindingIdentity {
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
}

#[derive(Clone, Debug)]
struct DurableMcpCall {
    key: McpCallKey,
    provider_name: String,
    arguments: Value,
    arguments_sha256: String,
    registry_epoch_id: String,
    registry_digest: String,
    response_started_seq: u64,
    response_seq: u64,
}

/// A Provider MCP call extracted by the validator selected by the durable
/// registry activation. Coordinator code consumes this snapshot instead of
/// independently reinterpreting `response.completed` payloads.
#[derive(Clone, Debug)]
pub(crate) struct ValidatedDurableMcpCall {
    pub(crate) provider_name: String,
    pub(crate) arguments: Value,
    pub(crate) arguments_sha256: String,
    pub(crate) registry_epoch_id: String,
    pub(crate) registry_digest: String,
    pub(crate) response_started_seq: u64,
    pub(crate) response_completed_seq: u64,
}

#[derive(Clone, Debug)]
enum CallState {
    Unstarted,
    Started { seq: u64, provenance: Value },
    InDoubt { started_seq: u64 },
    Terminal,
}

/// Validate the current MCP journal protocol.  With no activation this is a
/// no-op for historical non-MCP journals, except that orphan MCP provenance is
/// rejected instead of being interpreted by generic tool reducers.
pub(crate) fn validate_mcp_call_chain_v1(events: &[JournalEvent]) -> Result<()> {
    let activation = activation_v1(events)?;
    let Some(activation) = activation else {
        reject_orphan_mcp_markers(events)?;
        return Ok(());
    };
    if activation.call_chain_validator_version != MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 {
        return session_error("unsupported MCP call-chain validator version");
    }

    validate_mcp_call_chain_with_activation(events, &activation)
}

pub(crate) fn validate_mcp_call_chain_v2(events: &[JournalEvent]) -> Result<()> {
    let activation = activation_v2(events)?;
    let Some(activation) = activation else {
        reject_orphan_mcp_markers(events)?;
        return Ok(());
    };
    if activation.call_chain_validator_version != MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 {
        return session_error("unsupported MCP call-chain validator version");
    }

    validate_mcp_call_chain_with_activation(events, &activation)
}

fn validate_mcp_call_chain_with_activation(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<()> {
    validate_response_registry_claims(events, activation)?;
    let durable_calls = durable_mcp_calls(events, activation)?;
    let mcp_call_response_seqs = durable_calls
        .values()
        .map(|call| (call.key.call_id.as_str(), call.response_seq))
        .collect::<HashMap<_, _>>();
    let mut states = durable_calls
        .keys()
        .cloned()
        .map(|key| (key, CallState::Unstarted))
        .collect::<HashMap<_, _>>();
    // Recovery skips may be numerous in a legacy v1 batch. Build the durable
    // marker/authorization authority once so each lifecycle edge remains an
    // O(1) lookup instead of rescanning the journal and up to 4096 entries.
    let recovery_authorities = recovery_marker_authorities(events);
    for event in events {
        if !is_tool_lifecycle(&event.kind) {
            continue;
        }
        let turn_id = event.turn_id.as_deref();
        // The generic turn reducer accepts `id` as a legacy alias for
        // `call_id`, but the MCP v1 journal contract deliberately does not:
        // the durable Provider function-call identity and every lifecycle
        // edge must use the canonical field.  Otherwise a generic terminal
        // carrying `{id: ...}` could settle an MCP call in the slot reducer
        // while bypassing this validator's provenance checks.
        let call_id = event.data.get("call_id").and_then(Value::as_str);
        let legacy_id = event.data.get("id").and_then(Value::as_str);
        let key = turn_id.zip(call_id).map(|(turn_id, call_id)| McpCallKey {
            turn_id: turn_id.to_owned(),
            call_id: call_id.to_owned(),
        });
        let claims_call_id = |candidate: &str| {
            mcp_call_response_seqs
                .get(candidate)
                .is_some_and(|response_seq| event.seq > *response_seq)
        };
        let legacy_id_claims_mcp = call_id.is_none() && legacy_id.is_some_and(claims_call_id);
        let claims_mcp =
            event_claims_mcp(event) || call_id.is_some_and(claims_call_id) || legacy_id_claims_mcp;
        if legacy_id_claims_mcp {
            return session_error(format!(
                "{} at seq {} must use canonical call_id for an MCP lifecycle edge",
                event.kind, event.seq
            ));
        }
        let Some(key) = key else {
            if claims_mcp {
                return session_error(format!(
                    "{} at seq {} claims MCP lifecycle semantics without turn_id/call_id",
                    event.kind, event.seq
                ));
            }
            continue;
        };
        let Some(call) = durable_calls.get(&key) else {
            if claims_mcp {
                return session_error(format!(
                    "{} at seq {} does not reference a durable MCP Provider call",
                    event.kind, event.seq
                ));
            }
            continue;
        };
        validate_lifecycle_identity(event, call)?;
        let state = states.get_mut(&key).expect("durable MCP call state");
        validate_lifecycle_event_v1(event, call, activation, state, &recovery_authorities)?;
    }

    Ok(())
}

const MAX_RESPONSE_STATUS_TEXT_BYTES_V2: usize = 16 * 1024;

/// Validate the complete v2 response transaction before projecting any MCP
/// calls.  The response start, not a discovered function call, owns the
/// lifecycle.  Generic and MCP-claimed attempts share one per-turn active
/// slot, so a second start cannot hide behind a later MCP projection.
fn response_attempts_v2<'a>(
    events: &'a [JournalEvent],
    activation: &Activation,
) -> Result<BTreeMap<(String, String), OwnedResponseAttemptV2<'a>>> {
    let mut starts = HashMap::<(String, String), Vec<u64>>::new();
    let mut active = HashMap::<String, (String, u64)>::new();
    let mut terminal_counts = HashMap::<(String, String), u8>::new();
    let mut owned = BTreeMap::new();
    for event in events {
        match event.kind.as_str() {
            "response.started" => {
                let Some(turn_id) = event.turn_id.as_deref() else {
                    if event.seq > activation.seq {
                        return Err(session_message(
                            event,
                            "response.started has no valid turn_id",
                        ));
                    }
                    continue;
                };
                let Some(attempt_id) = event
                    .data
                    .get("response_attempt_id")
                    .and_then(Value::as_str)
                    .filter(|value| valid_identity(value))
                else {
                    if event.seq > activation.seq {
                        return Err(session_message(
                            event,
                            "response.started has no valid response_attempt_id",
                        ));
                    }
                    continue;
                };
                let key = (turn_id.to_owned(), attempt_id.to_owned());
                let matching_starts = starts.entry(key.clone()).or_default();
                if event.seq > activation.seq && !matching_starts.is_empty() {
                    return session_error(format!(
                        "duplicate response.started for attempt {attempt_id} in turn {turn_id}"
                    ));
                }
                matching_starts.push(event.seq);
                if event.seq > activation.seq {
                    if let Some((prior_attempt, prior_seq)) = active.get(turn_id) {
                        return session_error(format!(
                            "response.started at seq {} overlaps active attempt {prior_attempt} at seq {prior_seq} for turn {turn_id}",
                            event.seq
                        ));
                    }
                    active.insert(turn_id.to_owned(), (attempt_id.to_owned(), event.seq));
                    let claims_mcp = event.data.get("mcp_registry_epoch_id").is_some()
                        || event.data.get("mcp_registry_digest").is_some();
                    if claims_mcp {
                        validate_response_registry(event, activation)?;
                        if owned
                            .insert(
                                key,
                                OwnedResponseAttemptV2 {
                                    start: event,
                                    turn_id: turn_id.to_owned(),
                                    response_attempt_id: attempt_id.to_owned(),
                                    terminal: None,
                                },
                            )
                            .is_some()
                        {
                            return session_error(format!(
                                "MCP response attempt {attempt_id} for turn {turn_id} has duplicate registry claims"
                            ));
                        }
                    }
                } else if !active.contains_key(turn_id) {
                    active.insert(turn_id.to_owned(), (attempt_id.to_owned(), event.seq));
                }
            }
            kind if is_response_terminal(kind) => {
                if event.seq <= activation.seq {
                    if let (Some(turn_id), Some(attempt_id)) = (
                        event.turn_id.as_deref(),
                        event
                            .data
                            .get("response_attempt_id")
                            .and_then(Value::as_str),
                    ) {
                        if active
                            .get(turn_id)
                            .is_some_and(|(active_attempt, _)| active_attempt == attempt_id)
                        {
                            active.remove(turn_id);
                        }
                    }
                    continue;
                }
                let turn_id = event
                    .turn_id
                    .as_deref()
                    .filter(|value| valid_identity(value))
                    .ok_or_else(|| {
                        session_message(event, "response terminal has no valid turn_id")
                    })?;
                let attempt_id = event
                    .data
                    .get("response_attempt_id")
                    .and_then(Value::as_str)
                    .filter(|value| valid_identity(value))
                    .ok_or_else(|| {
                        session_message(event, "response terminal has no valid response_attempt_id")
                    })?;
                let matching_starts = starts
                    .get(&(turn_id.to_owned(), attempt_id.to_owned()))
                    .ok_or_else(|| {
                        session_message(event, "response terminal has no matching response.started")
                    })?;
                if matching_starts.len() != 1 {
                    return session_error(format!(
                        "{} at seq {} does not bind one unique response.started",
                        event.kind, event.seq
                    ));
                }
                let started_seq = matching_starts[0];
                if started_seq >= event.seq {
                    return session_error(format!(
                        "{} at seq {} does not follow response.started seq {}",
                        event.kind, event.seq, started_seq
                    ));
                }
                let terminal_count = terminal_counts
                    .entry((turn_id.to_owned(), attempt_id.to_owned()))
                    .or_insert(0);
                if *terminal_count >= 1 {
                    return session_error(format!(
                        "{} at seq {} leaves response attempt {attempt_id} in turn {turn_id} has 2 terminals",
                        event.kind, event.seq
                    ));
                }
                *terminal_count = 1;
                match active.get(turn_id) {
                    Some((active_attempt, _)) if active_attempt == attempt_id => {}
                    _ => {
                        return session_error(format!(
                            "{} at seq {} does not terminate the active response attempt for turn {turn_id}",
                            event.kind, event.seq
                        ));
                    }
                }
                let start_after_activation = started_seq > activation.seq;
                validate_response_terminal_profile_v2(event, started_seq, start_after_activation)?;
                if let Some(attempt) = owned.get_mut(&(turn_id.to_owned(), attempt_id.to_owned())) {
                    if attempt.terminal.replace(event).is_some() {
                        return session_error(format!(
                            "MCP response attempt {attempt_id} for turn {turn_id} has more than one terminal"
                        ));
                    }
                    validate_owned_completed_response_v2(attempt)?;
                }
                active.remove(turn_id);
            }
            _ => {}
        }
    }
    Ok(owned)
}

fn validate_response_terminal_profile_v2(
    event: &JournalEvent,
    started_seq: u64,
    enforce_status: bool,
) -> Result<()> {
    let data = object_data(event)?;
    let has_recovered = data.contains_key("recovered");
    let has_started_seq = data.contains_key("started_seq");
    if event.kind == "response.aborted" && (has_recovered || has_started_seq) {
        require_exact_keys(
            data,
            &["response_attempt_id", "started_seq", "reason", "recovered"],
            event,
        )?;
        if data.get("recovered").and_then(Value::as_bool) != Some(true)
            || data.get("started_seq").and_then(Value::as_u64) != Some(started_seq)
            || data.get("reason").and_then(Value::as_str)
                != Some(RECOVERED_RESPONSE_ABORT_REASON_V1)
        {
            return session_error(format!(
                "recovered response.aborted at seq {} does not match its exact response.started seq {}",
                event.seq, started_seq
            ));
        }
    } else if has_recovered || has_started_seq {
        return session_error(format!(
            "non-recovery {} at seq {} carries response recovery provenance",
            event.kind, event.seq
        ));
    }
    if enforce_status {
        match event.kind.as_str() {
            "response.failed" => validate_response_status_text(data, "error", event),
            "response.aborted" if !has_recovered && !has_started_seq => {
                validate_response_status_text(data, "reason", event)
            }
            _ => Ok(()),
        }
    } else {
        Ok(())
    }
}

fn validate_owned_completed_response_v2(attempt: &OwnedResponseAttemptV2<'_>) -> Result<()> {
    let Some(terminal) = attempt.terminal else {
        return Ok(());
    };
    if terminal
        .data
        .get("response_attempt_id")
        .and_then(Value::as_str)
        != Some(attempt.response_attempt_id.as_str())
    {
        return session_error(format!(
            "{} at seq {} is not bound to owned response attempt {}",
            terminal.kind, terminal.seq, attempt.response_attempt_id
        ));
    }
    if terminal.kind != "response.completed" {
        return Ok(());
    }
    let items = terminal
        .data
        .get("output_items")
        .ok_or_else(|| {
            session_message(
                terminal,
                "MCP-owned response.completed has no canonical output_items",
            )
        })?
        .as_array()
        .ok_or_else(|| {
            session_message(
                terminal,
                "MCP-owned response.completed has non-array canonical output_items",
            )
        })?;
    let count = items
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .count();
    if count > MAX_MCP_CALLS_PER_RESPONSE_V1 {
        return session_error(format!(
            "MCP response.completed at seq {} exceeds the {MAX_MCP_CALLS_PER_RESPONSE_V1}-call limit",
            terminal.seq
        ));
    }
    Ok(())
}

fn validate_response_status_text(
    data: &Map<String, Value>,
    field: &str,
    event: &JournalEvent,
) -> Result<()> {
    if !data
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty() && value.len() <= MAX_RESPONSE_STATUS_TEXT_BYTES_V2)
    {
        return session_error(format!(
            "{} at seq {} has no bounded non-empty {field}",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn recovery_marker_authorities(events: &[JournalEvent]) -> HashMap<u64, RecoveryMarkerAuthority> {
    events
        .iter()
        .filter(|event| event.kind == crate::session::RECOVERY_KIND && event.turn_id.is_none())
        .map(|event| {
            let authorizations = event
                .data
                .get("unstarted_tool_calls")
                .and_then(Value::as_array);
            let authorization_count = authorizations.map(Vec::len);
            let mut authorization_matches = HashMap::new();
            // Do not allocate an attacker-sized index for a marker the frozen
            // protocol will reject. The referenced skip receives the same
            // limit error below from the recorded count.
            if let Some(authorizations) =
                authorizations.filter(|items| items.len() <= MAX_MCP_CALLS_PER_RESPONSE_V1)
            {
                for authorization in authorizations {
                    let Some(response_seq) =
                        authorization.get("response_seq").and_then(Value::as_u64)
                    else {
                        continue;
                    };
                    let Some(turn_id) = authorization.get("turn_id").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(call_id) = authorization.get("call_id").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(provider_name) = authorization.get("tool").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Some(arguments_sha256) = authorization
                        .get("arguments_sha256")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let key = RecoveryAuthorizationKey {
                        response_seq,
                        turn_id: turn_id.to_owned(),
                        call_id: call_id.to_owned(),
                        provider_name: provider_name.to_owned(),
                        arguments_sha256: arguments_sha256.to_owned(),
                    };
                    let matches = authorization_matches.entry(key).or_insert(0u8);
                    *matches = matches.saturating_add(1).min(2);
                }
            }
            (
                event.seq,
                RecoveryMarkerAuthority {
                    skipped_before_start: event
                        .data
                        .get("skipped_before_start")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    authorization_version: event
                        .data
                        .get("tool_skip_authorization_version")
                        .and_then(Value::as_u64),
                    authorization_count,
                    authorization_matches,
                },
            )
        })
        .collect()
}

pub(crate) fn validate_mcp_call_chain_for_version(
    version: u32,
    events: &[JournalEvent],
) -> Result<()> {
    match version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => validate_mcp_call_chain_v1(events),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => validate_mcp_call_chain_v2(events),
        _ => session_error(format!(
            "unsupported MCP call-chain validator version {version}"
        )),
    }
}

/// Validate the durable MCP activation with the exact reducer selected by the
/// journal, while freezing the newest activation version this caller can
/// interpret. This lets a new projection/reducer continue to read v1 and v2
/// journals without silently opting into a future v3 validator.
pub(crate) fn validate_mcp_call_chain_through_version(
    ceiling: u32,
    events: &[JournalEvent],
) -> Result<()> {
    match call_chain_validator_version(events)? {
        Some(version) if version <= ceiling => validate_mcp_call_chain_for_version(version, events),
        Some(version) => session_error(format!(
            "MCP call-chain validator version {version} exceeds compatibility ceiling {ceiling}"
        )),
        None => {
            reject_orphan_mcp_markers(events)?;
            Ok(())
        }
    }
}

pub(crate) fn call_chain_validator_version(events: &[JournalEvent]) -> Result<Option<u32>> {
    let mut activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND);
    let Some(activation) = activations.next() else {
        return Ok(None);
    };
    if activations.next().is_some() {
        return session_error("MCP journal contains more than one registry activation");
    }
    let version = activation
        .data
        .get("call_chain_validator_version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            session_message(activation, "has no supported call_chain_validator_version")
        })?;
    Ok(Some(version))
}

pub(crate) fn validate_mcp_call_chain(events: &[JournalEvent]) -> Result<()> {
    validate_mcp_call_chain_through_version(MCP_CALL_CHAIN_VALIDATOR_VERSION, events)
}

/// Return the unique durable MCP call selected by the activation's frozen
/// call-chain validator. This first validates the complete lifecycle, then
/// exposes the same canonical call projection used by that validator.
pub(crate) fn validated_durable_mcp_call(
    events: &[JournalEvent],
    turn_id: &str,
    call_id: &str,
) -> Result<ValidatedDurableMcpCall> {
    let version = call_chain_validator_version(events)?.ok_or_else(|| {
        OxidraError::Session("MCP call lookup requires a durable registry activation".to_owned())
    })?;
    let activation = match version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => activation_v1(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => activation_v2(events)?,
        version => {
            return session_error(format!(
                "unsupported MCP call-chain validator version {version}"
            ));
        }
    }
    .expect("call-chain version implies an activation");
    validate_mcp_call_chain_with_activation(events, &activation)?;
    let key = McpCallKey {
        turn_id: turn_id.to_owned(),
        call_id: call_id.to_owned(),
    };
    let call = durable_mcp_calls(events, &activation)?
        .remove(&key)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "MCP call {call_id} is not present in turn {turn_id}"
            ))
        })?;
    Ok(ValidatedDurableMcpCall {
        provider_name: call.provider_name,
        arguments: call.arguments,
        arguments_sha256: call.arguments_sha256,
        registry_epoch_id: call.registry_epoch_id,
        registry_digest: call.registry_digest,
        response_started_seq: call.response_started_seq,
        response_completed_seq: call.response_seq,
    })
}

pub(crate) fn mcp_turn_ids(events: &[JournalEvent]) -> Result<Vec<String>> {
    let version = call_chain_validator_version(events)?;
    let activation = match version {
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V1) => activation_v1(events)?,
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) => activation_v2(events)?,
        Some(version) => {
            return session_error(format!(
                "unsupported MCP call-chain validator version {version}"
            ));
        }
        None => return Ok(Vec::new()),
    };
    let Some(activation) = activation else {
        return Ok(Vec::new());
    };
    let mut turn_ids = if version == Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) {
        owned_response_attempts_v2(events, &activation)?
            .values()
            .map(|attempt| attempt.turn_id.clone())
            .collect::<Vec<_>>()
    } else {
        durable_mcp_calls(events, &activation)?
            .keys()
            .map(|key| key.turn_id.clone())
            .collect::<Vec<_>>()
    };
    turn_ids.sort();
    turn_ids.dedup();
    Ok(turn_ids)
}

pub(crate) fn ensure_no_unstarted_mcp_calls_v1(events: &[JournalEvent]) -> Result<()> {
    validate_mcp_call_chain_v1(events)?;
    let Some(activation) = activation_v1(events)? else {
        return Ok(());
    };
    ensure_no_unstarted_mcp_calls_with_activation(events, &activation)
}

pub(crate) fn ensure_no_unstarted_mcp_calls_v2(events: &[JournalEvent]) -> Result<()> {
    validate_mcp_call_chain_v2(events)?;
    let Some(activation) = activation_v2(events)? else {
        return Ok(());
    };
    ensure_no_unstarted_mcp_calls_with_activation(events, &activation)
}

pub(crate) fn ensure_no_unstarted_mcp_calls(events: &[JournalEvent]) -> Result<()> {
    match call_chain_validator_version(events)? {
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V1) => ensure_no_unstarted_mcp_calls_v1(events),
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) => ensure_no_unstarted_mcp_calls_v2(events),
        Some(version) => session_error(format!(
            "unsupported MCP call-chain validator version {version}"
        )),
        None => Ok(()),
    }
}

fn ensure_no_unstarted_mcp_calls_with_activation(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<()> {
    let calls = durable_mcp_calls(events, activation)?;
    let lifecycle_calls = events
        .iter()
        .filter(|event| is_tool_lifecycle(&event.kind))
        .filter_map(|event| {
            let key = McpCallKey {
                turn_id: event.turn_id.as_deref()?.to_owned(),
                call_id: event.data.get("call_id")?.as_str()?.to_owned(),
            };
            let call = calls.get(&key)?;
            (event.seq > call.response_seq).then_some(key)
        })
        .collect::<HashSet<_>>();
    for call in calls.values() {
        if !lifecycle_calls.contains(&call.key) {
            return session_error(format!(
                "MCP call {} in turn {} must be recovered before the live registry resumes",
                call.key.call_id, call.key.turn_id
            ));
        }
    }
    Ok(())
}

pub(crate) fn argument_digest_v1(arguments: &Value) -> Result<String> {
    let payload = json!({
        "argument_digest_version": MCP_ARGUMENT_DIGEST_VERSION_V1,
        "arguments": arguments,
    });
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&payload)?)))
}

fn activation_v1(events: &[JournalEvent]) -> Result<Option<Activation>> {
    let activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
        .collect::<Vec<_>>();
    if activations.is_empty() {
        return Ok(None);
    }
    if activations.len() != 1 {
        return session_error(
            "MCP call-chain validator v1 requires exactly one registry activation",
        );
    }
    let event = activations[0];
    if event.turn_id.is_some() {
        return session_error(format!(
            "mcp.registry.activated at seq {} must be a global event",
            event.seq
        ));
    }
    let data = object_data(event)?;
    require_exact_keys(
        data,
        &[
            "config_sha256",
            "call_chain_validator_version",
            "coordinator_id",
            "coordinator_version",
            "execution_plan_digest",
            "provider_names",
            "registry_digest",
            "registry_epoch_id",
            "registry_version",
            "schema_profile_version",
            "stdio_kernel_version",
        ],
        event,
    )?;
    require_version(
        data,
        "coordinator_version",
        MCP_EXECUTION_COORDINATOR_VERSION_V1,
        event,
    )?;
    require_version(
        data,
        "call_chain_validator_version",
        u64::from(MCP_CALL_CHAIN_VALIDATOR_VERSION_V1),
        event,
    )?;
    require_version(
        data,
        "registry_version",
        MCP_TOOL_REGISTRY_VERSION_V1,
        event,
    )?;
    require_version(
        data,
        "stdio_kernel_version",
        MCP_STDIO_KERNEL_VERSION_V1,
        event,
    )?;
    require_version(
        data,
        "schema_profile_version",
        MCP_SCHEMA_PROFILE_VERSION_V1,
        event,
    )?;
    required_uuid_v7(data, "coordinator_id", event)?;
    let registry_epoch_id = required_uuid_v7(data, "registry_epoch_id", event)?;
    let registry_digest = required_sha256(data, "registry_digest", event)?;
    let execution_plan_digest = required_sha256(data, "execution_plan_digest", event)?;
    required_sha256(data, "config_sha256", event)?;
    let names = data
        .get("provider_names")
        .and_then(Value::as_array)
        .ok_or_else(|| session_message(event, "provider_names must be an array"))?;
    if names.len() > 512 {
        return session_error(format!(
            "mcp.registry.activated at seq {} exceeds the provider-name limit",
            event.seq
        ));
    }
    let mut provider_names = BTreeSet::new();
    let mut previous = None::<&str>;
    for name in names {
        let name = name
            .as_str()
            .filter(|name| valid_provider_name(name))
            .ok_or_else(|| session_message(event, "provider_names contains an invalid name"))?;
        if previous.is_some_and(|candidate| candidate >= name) {
            return session_error(format!(
                "mcp.registry.activated at seq {} provider_names are not strictly sorted and unique",
                event.seq
            ));
        }
        previous = Some(name);
        provider_names.insert(name.to_owned());
    }
    Ok(Some(Activation {
        seq: event.seq,
        coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V1 as u32,
        call_chain_validator_version: MCP_CALL_CHAIN_VALIDATOR_VERSION_V1,
        schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1 as u32,
        registry_epoch_id,
        registry_digest,
        execution_plan_digest,
        provider_names,
        bindings: None,
    }))
}

fn activation_v2(events: &[JournalEvent]) -> Result<Option<Activation>> {
    let activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
        .collect::<Vec<_>>();
    if activations.is_empty() {
        return Ok(None);
    }
    if activations.len() != 1 {
        return session_error(
            "MCP call-chain validator v2 requires exactly one registry activation",
        );
    }
    let event = activations[0];
    if event.turn_id.is_some() {
        return session_error(format!(
            "mcp.registry.activated at seq {} must be a global event",
            event.seq
        ));
    }
    let data = object_data(event)?;
    require_exact_keys(
        data,
        &[
            "bindings",
            "config_sha256",
            "call_chain_validator_version",
            "coordinator_id",
            "coordinator_version",
            "execution_plan_digest",
            "registry_digest",
            "registry_epoch_id",
            "registry_version",
            "schema_profile_version",
            "stdio_kernel_version",
        ],
        event,
    )?;
    require_version(
        data,
        "coordinator_version",
        MCP_EXECUTION_COORDINATOR_VERSION_V2,
        event,
    )?;
    require_version(
        data,
        "call_chain_validator_version",
        u64::from(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2),
        event,
    )?;
    require_version(
        data,
        "registry_version",
        MCP_TOOL_REGISTRY_VERSION_V1,
        event,
    )?;
    require_version(
        data,
        "stdio_kernel_version",
        MCP_STDIO_KERNEL_VERSION_V1,
        event,
    )?;
    require_version(
        data,
        "schema_profile_version",
        MCP_SCHEMA_PROFILE_VERSION_V1,
        event,
    )?;
    required_uuid_v7(data, "coordinator_id", event)?;
    let registry_epoch_id = required_uuid_v7(data, "registry_epoch_id", event)?;
    let registry_digest = required_sha256(data, "registry_digest", event)?;
    let execution_plan_digest = required_sha256(data, "execution_plan_digest", event)?;
    required_sha256(data, "config_sha256", event)?;

    let snapshot = data
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| session_message(event, "bindings must be an array"))?;
    if snapshot.len() > 512 {
        return session_error(format!(
            "mcp.registry.activated at seq {} exceeds the binding limit",
            event.seq
        ));
    }
    let mut provider_names = BTreeSet::new();
    let mut bindings = BTreeMap::new();
    let mut previous = None::<&str>;
    for value in snapshot {
        let binding = value
            .as_object()
            .ok_or_else(|| session_message(event, "bindings contains a non-object entry"))?;
        require_exact_keys(
            binding,
            &[
                "protocol_version",
                "provider_name",
                "raw_tool_name",
                "server_name",
            ],
            event,
        )?;
        let provider_name = binding
            .get("provider_name")
            .and_then(Value::as_str)
            .filter(|name| valid_provider_name(name))
            .ok_or_else(|| session_message(event, "bindings contains an invalid provider_name"))?;
        if previous.is_some_and(|candidate| candidate >= provider_name) {
            return session_error(format!(
                "mcp.registry.activated at seq {} bindings are not strictly sorted and unique",
                event.seq
            ));
        }
        previous = Some(provider_name);
        let required_identity = |field: &str| -> Result<String> {
            binding
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| valid_identity(value))
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    session_message(event, format!("bindings contains an invalid {field}"))
                })
        };
        provider_names.insert(provider_name.to_owned());
        bindings.insert(
            provider_name.to_owned(),
            BindingIdentity {
                server_name: required_identity("server_name")?,
                raw_tool_name: required_identity("raw_tool_name")?,
                protocol_version: required_identity("protocol_version")?,
            },
        );
    }

    Ok(Some(Activation {
        seq: event.seq,
        coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V2 as u32,
        call_chain_validator_version: MCP_CALL_CHAIN_VALIDATOR_VERSION_V2,
        schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1 as u32,
        registry_epoch_id,
        registry_digest,
        execution_plan_digest,
        provider_names,
        bindings: Some(bindings),
    }))
}

fn durable_mcp_calls(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<McpCallKey, DurableMcpCall>> {
    match activation.call_chain_validator_version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => durable_mcp_calls_v1(events, activation),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => durable_mcp_calls_v2(events, activation),
        version => session_error(format!(
            "unsupported MCP call-chain validator version {version}"
        )),
    }
}

fn durable_mcp_calls_v1(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<McpCallKey, DurableMcpCall>> {
    let starts = response_starts(events)?;
    let terminals = response_terminals(events);
    let mut calls = HashMap::new();
    let mut call_ids = HashMap::<String, McpCallKey>::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "response.completed")
    {
        // Registry activation is a prefix boundary.  Calls completed before
        // it retain their generic Provider meaning even when a later MCP
        // registry happens to use the same provider alias.
        if event.seq <= activation.seq {
            continue;
        }
        let Some(items) = event.data.get("output_items").and_then(Value::as_array) else {
            continue;
        };
        let response_function_call_count = items
            .iter()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .count();
        let mut response_limit_checked = false;
        for item in items {
            if item.get("type").and_then(Value::as_str) != Some("function_call") {
                continue;
            }
            let Some(provider_name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !activation.provider_names.contains(provider_name) {
                continue;
            }
            let turn_id = event
                .turn_id
                .as_deref()
                .ok_or_else(|| session_message(event, "MCP response.completed has no turn_id"))?;
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .filter(|value| valid_identity(value))
                .ok_or_else(|| session_message(event, "MCP function_call has no valid call_id"))?;
            let attempt_id = event
                .data
                .get("response_attempt_id")
                .and_then(Value::as_str)
                .filter(|value| valid_identity(value))
                .ok_or_else(|| {
                    session_message(event, "MCP response.completed has no response_attempt_id")
                })?;
            let matching_starts = starts
                .get(&(turn_id.to_owned(), attempt_id.to_owned()))
                .ok_or_else(|| {
                    session_message(
                        event,
                        "MCP response has no unique matching response.started",
                    )
                })?;
            if matching_starts.len() != 1 {
                return session_error(format!(
                    "MCP response attempt {attempt_id} for turn {turn_id} has {} matching starts",
                    matching_starts.len()
                ));
            }
            let start = matching_starts[0];
            if start.seq <= activation.seq {
                // A response that began before MCP activation is still a
                // generic request.  It must not be retroactively reinterpreted
                // merely because its completion appears after activation.
                continue;
            }
            // Coordinator/call-chain v1 predates the durable response-batch
            // bound and remains byte-compatible. v2 freezes the bound across
            // the complete Provider response (including non-MCP calls in a
            // mixed batch), because recovery authorizes the whole batch.
            if activation.call_chain_validator_version >= MCP_CALL_CHAIN_VALIDATOR_VERSION_V2
                && !response_limit_checked
                && response_function_call_count > MAX_MCP_CALLS_PER_RESPONSE_V1
            {
                return session_error(format!(
                    "MCP response.completed at seq {} exceeds the {MAX_MCP_CALLS_PER_RESPONSE_V1}-call limit",
                    event.seq
                ));
            }
            response_limit_checked = true;
            if start.seq >= event.seq {
                return session_error(format!(
                    "MCP Provider call {call_id} is not ordered after its response.started"
                ));
            }
            let start_has_registry_claim = start.data.get("mcp_registry_epoch_id").is_some()
                || start.data.get("mcp_registry_digest").is_some();
            if !start_has_registry_claim {
                return session_error(format!(
                    "MCP Provider call {call_id} after activation has no registry claim"
                ));
            }
            validate_response_registry(start, activation)?;
            let terminal_key = (turn_id.to_owned(), attempt_id.to_owned());
            let matching_terminals = terminals.get(&terminal_key).ok_or_else(|| {
                session_message(event, "MCP response has no matching response terminal")
            })?;
            if matching_terminals.len() != 1 || matching_terminals[0].seq != event.seq {
                return session_error(format!(
                    "MCP response attempt {attempt_id} for turn {turn_id} has {} terminals",
                    matching_terminals.len()
                ));
            }
            let arguments = durable_arguments(item, event, call_id)?;
            let key = McpCallKey {
                turn_id: turn_id.to_owned(),
                call_id: call_id.to_owned(),
            };
            let call = DurableMcpCall {
                key: key.clone(),
                provider_name: provider_name.to_owned(),
                arguments_sha256: argument_digest_v1(&arguments)?,
                arguments,
                registry_epoch_id: activation.registry_epoch_id.clone(),
                registry_digest: activation.registry_digest.clone(),
                response_started_seq: start.seq,
                response_seq: event.seq,
            };
            if let Some(previous) = call_ids.insert(call_id.to_owned(), key.clone()) {
                return session_error(format!(
                    "MCP call_id {call_id} is reused by turns {} and {turn_id}",
                    previous.turn_id
                ));
            }
            if calls.insert(key, call).is_some() {
                return session_error(format!(
                    "MCP call_id {call_id} appears more than once in turn {turn_id}"
                ));
            }
        }
    }
    Ok(calls)
}

/// A response attempt whose ownership was established by its durable
/// `response.started` registry claim. The attempt remains an MCP-owned
/// transaction even when it has no terminal yet, has failed/aborted, or
/// completed without any MCP function calls.
#[derive(Clone, Debug)]
struct OwnedResponseAttemptV2<'a> {
    start: &'a JournalEvent,
    turn_id: String,
    response_attempt_id: String,
    terminal: Option<&'a JournalEvent>,
}

fn owned_response_attempts_v2<'a>(
    events: &'a [JournalEvent],
    activation: &Activation,
) -> Result<BTreeMap<(String, String), OwnedResponseAttemptV2<'a>>> {
    response_attempts_v2(events, activation)
}

const RECOVERED_RESPONSE_ABORT_REASON_V1: &str =
    "process stopped before a terminal response event was committed";

/// Bind an MCP-owned response terminal to the exact durable start that owns
/// the attempt. Recovery provenance is deliberately a closed profile: it is
/// only valid on the recovery writer's `response.aborted` event, references
/// the exact start sequence, and cannot be copied onto a live terminal.
/// Extract durable MCP calls under the frozen v2 response-ownership rules.
/// Ownership is derived from claimed starts first; calls are only a projection
/// of completed owned attempts.
fn durable_mcp_calls_v2(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<McpCallKey, DurableMcpCall>> {
    let owned = owned_response_attempts_v2(events, activation)?;
    let mut calls = HashMap::new();
    let mut call_ids = HashMap::<String, McpCallKey>::new();
    for attempt in owned.values() {
        let Some(event) = attempt.terminal else {
            continue;
        };
        if event.kind != "response.completed" {
            continue;
        }
        let items = event
            .data
            .get("output_items")
            .and_then(Value::as_array)
            .expect("owned completed response was validated");
        for item in items {
            if item.get("type").and_then(Value::as_str) != Some("function_call") {
                continue;
            }
            let Some(provider_name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !activation.provider_names.contains(provider_name) {
                continue;
            }
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .filter(|value| valid_identity(value))
                .ok_or_else(|| session_message(event, "MCP function_call has no valid call_id"))?;
            let arguments = durable_arguments(item, event, call_id)?;
            let key = McpCallKey {
                turn_id: attempt.turn_id.clone(),
                call_id: call_id.to_owned(),
            };
            let call = DurableMcpCall {
                key: key.clone(),
                provider_name: provider_name.to_owned(),
                arguments_sha256: argument_digest_v1(&arguments)?,
                arguments,
                registry_epoch_id: activation.registry_epoch_id.clone(),
                registry_digest: activation.registry_digest.clone(),
                response_started_seq: attempt.start.seq,
                response_seq: event.seq,
            };
            if let Some(previous) = call_ids.insert(call_id.to_owned(), key.clone()) {
                return session_error(format!(
                    "MCP call_id {call_id} is reused by turns {} and {}",
                    previous.turn_id, attempt.turn_id
                ));
            }
            if calls.insert(key, call).is_some() {
                return session_error(format!(
                    "MCP call_id {call_id} appears more than once in turn {}",
                    attempt.turn_id
                ));
            }
        }
    }
    Ok(calls)
}

fn response_starts(
    events: &[JournalEvent],
) -> Result<HashMap<(String, String), Vec<&JournalEvent>>> {
    let mut starts = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "response.started")
    {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        let Some(attempt_id) = event
            .data
            .get("response_attempt_id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let key = (turn_id.to_owned(), attempt_id.to_owned());
        starts.entry(key).or_insert_with(Vec::new).push(event);
    }
    Ok(starts)
}

fn response_terminals(events: &[JournalEvent]) -> HashMap<(String, String), Vec<&JournalEvent>> {
    let mut terminals = HashMap::new();
    for event in events
        .iter()
        .filter(|event| is_response_terminal(&event.kind))
    {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        let Some(attempt_id) = event
            .data
            .get("response_attempt_id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        terminals
            .entry((turn_id.to_owned(), attempt_id.to_owned()))
            .or_insert_with(Vec::new)
            .push(event);
    }
    terminals
}

fn validate_response_registry_claims(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<()> {
    for event in events
        .iter()
        .filter(|event| event.kind == "response.started")
    {
        let has_epoch = event.data.get("mcp_registry_epoch_id").is_some();
        let has_digest = event.data.get("mcp_registry_digest").is_some();
        if !has_epoch && !has_digest {
            continue;
        }
        if event.seq <= activation.seq {
            return session_error(format!(
                "response.started at seq {} claims MCP registry state before activation",
                event.seq
            ));
        }
        validate_response_registry(event, activation)?;
    }
    Ok(())
}

fn durable_arguments(item: &Value, event: &JournalEvent, call_id: &str) -> Result<Value> {
    match item.get("arguments") {
        Some(Value::String(arguments)) => serde_json::from_str(arguments).map_err(|error| {
            OxidraError::Session(format!(
                "MCP call {call_id} at seq {} has invalid durable arguments: {error}",
                event.seq
            ))
        }),
        Some(arguments) => Ok(arguments.clone()),
        None => session_error(format!(
            "MCP call {call_id} at seq {} has no durable arguments",
            event.seq
        )),
    }
}

fn validate_response_registry(event: &JournalEvent, activation: &Activation) -> Result<()> {
    if event
        .data
        .get("mcp_registry_epoch_id")
        .and_then(Value::as_str)
        != Some(&activation.registry_epoch_id)
        || event
            .data
            .get("mcp_registry_digest")
            .and_then(Value::as_str)
            != Some(&activation.registry_digest)
    {
        return session_error(format!(
            "response.started at seq {} does not use the activated MCP registry epoch",
            event.seq
        ));
    }
    Ok(())
}

fn validate_lifecycle_identity(event: &JournalEvent, call: &DurableMcpCall) -> Result<()> {
    if event.turn_id.as_deref() != Some(&call.key.turn_id)
        || event.data.get("call_id").and_then(Value::as_str) != Some(&call.key.call_id)
        || event
            .data
            .get("id")
            .is_some_and(|id| id.as_str() != Some(&call.key.call_id))
        || event.data.get("tool").and_then(Value::as_str) != Some(&call.provider_name)
        || event.seq <= call.response_seq
    {
        return session_error(format!(
            "{} at seq {} does not match its durable MCP Provider call",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn validate_lifecycle_event_v1(
    event: &JournalEvent,
    call: &DurableMcpCall,
    activation: &Activation,
    state: &mut CallState,
    recovery_authorities: &HashMap<u64, RecoveryMarkerAuthority>,
) -> Result<()> {
    match event.kind.as_str() {
        "tool.started" => {
            if !matches!(state, CallState::Unstarted) {
                return invalid_transition(event, state);
            }
            schema::preflight_instance_for_profile(
                activation.schema_profile_version,
                &call.arguments,
            )
            .map_err(|error| {
                OxidraError::Session(format!(
                    "tool.started at seq {} references unsupported MCP arguments: {error}",
                    event.seq
                ))
            })?;
            if event.data.get("arguments") != Some(&call.arguments) {
                return session_error(format!(
                    "tool.started at seq {} arguments differ from the durable Provider call",
                    event.seq
                ));
            }
            let provenance = validate_full_provenance(event, call, activation)?;
            *state = CallState::Started {
                seq: event.seq,
                provenance: provenance.clone(),
            };
        }
        "tool.in_doubt" => {
            let CallState::Started { seq, provenance } = state else {
                return invalid_transition(event, state);
            };
            validate_started_terminal(event, *seq, provenance, call, activation)?;
            validate_error_result(event, "in_doubt")?;
            *state = CallState::InDoubt { started_seq: *seq };
        }
        "tool.in_doubt_resolved" => {
            let CallState::InDoubt { started_seq } = state else {
                return invalid_transition(event, state);
            };
            require_started_seq(event, *started_seq)?;
            validate_error_result(event, "in_doubt")?;
            if event.data.get("resolution").and_then(Value::as_str)
                != Some("user_treated_as_failed")
            {
                return session_error(format!(
                    "tool.in_doubt_resolved at seq {} has no registered resolution",
                    event.seq
                ));
            }
            *state = CallState::Terminal;
        }
        "tool.completed" => match state {
            CallState::Unstarted => {
                validate_pre_start_terminal(event, call, activation, false)?;
                *state = CallState::Terminal;
            }
            CallState::Started { seq, provenance } => {
                validate_started_terminal(event, *seq, provenance, call, activation)?;
                validate_completed_result(event)?;
                *state = CallState::Terminal;
            }
            _ => return invalid_transition(event, state),
        },
        "tool.cancelled" => match state {
            CallState::Unstarted => {
                validate_pre_start_terminal(event, call, activation, true)?;
                *state = CallState::Terminal;
            }
            CallState::Started { seq, provenance } => {
                validate_started_terminal(event, *seq, provenance, call, activation)?;
                if event.data.get("before_dispatch").and_then(Value::as_bool) != Some(true) {
                    return session_error(format!(
                        "tool.cancelled at seq {} is not marked before_dispatch",
                        event.seq
                    ));
                }
                validate_error_result(event, "cancelled")?;
                *state = CallState::Terminal;
            }
            _ => return invalid_transition(event, state),
        },
        kind if kind.starts_with("tool.skipped_due_to_") => {
            if !matches!(state, CallState::Unstarted) {
                return invalid_transition(event, state);
            }
            validate_safe_skip(event, call, activation, recovery_authorities)?;
            *state = CallState::Terminal;
        }
        _ if is_tool_terminal(&event.kind) => return invalid_transition(event, state),
        _ => {}
    }
    Ok(())
}

fn validate_full_provenance<'a>(
    event: &'a JournalEvent,
    call: &DurableMcpCall,
    activation: &Activation,
) -> Result<&'a Value> {
    let provenance = event
        .data
        .get("mcp")
        .ok_or_else(|| session_message(event, "MCP lifecycle event has no mcp provenance"))?;
    let data = provenance
        .as_object()
        .ok_or_else(|| session_message(event, "MCP lifecycle provenance must be an object"))?;
    require_version_map(
        data,
        "execution_coordinator_version",
        u64::from(activation.coordinator_version),
        event,
    )?;
    require_version_map(
        data,
        "dispatch_permit_version",
        MCP_DISPATCH_PERMIT_VERSION_V1,
        event,
    )?;
    require_version_map(
        data,
        "argument_digest_version",
        MCP_ARGUMENT_DIGEST_VERSION_V1,
        event,
    )?;
    require_version_map(
        data,
        "registry_version",
        MCP_TOOL_REGISTRY_VERSION_V1,
        event,
    )?;
    if data.get("registry_epoch_id").and_then(Value::as_str) != Some(&activation.registry_epoch_id)
        || data.get("registry_digest").and_then(Value::as_str) != Some(&activation.registry_digest)
        || data.get("execution_plan_digest").and_then(Value::as_str)
            != Some(&activation.execution_plan_digest)
        || data.get("arguments_sha256").and_then(Value::as_str) != Some(&call.arguments_sha256)
    {
        return session_error(format!(
            "{} at seq {} MCP provenance does not match activation/call",
            event.kind, event.seq
        ));
    }
    for field in [
        "server_name",
        "raw_tool_name",
        "protocol_version",
        "server_attempt_id",
    ] {
        if !data
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_identity)
        {
            return session_error(format!(
                "{} at seq {} has invalid MCP provenance field {field}",
                event.kind, event.seq
            ));
        }
    }
    if let Some(bindings) = &activation.bindings {
        let binding = bindings.get(&call.provider_name).ok_or_else(|| {
            session_message(
                event,
                "MCP lifecycle provider alias has no activated binding",
            )
        })?;
        if data.get("server_name").and_then(Value::as_str) != Some(&binding.server_name)
            || data.get("raw_tool_name").and_then(Value::as_str) != Some(&binding.raw_tool_name)
            || data.get("protocol_version").and_then(Value::as_str)
                != Some(&binding.protocol_version)
        {
            return session_error(format!(
                "{} at seq {} MCP provenance does not match the activated provider binding",
                event.kind, event.seq
            ));
        }
    }
    Ok(provenance)
}

fn validate_started_terminal(
    event: &JournalEvent,
    started_seq: u64,
    provenance: &Value,
    call: &DurableMcpCall,
    activation: &Activation,
) -> Result<()> {
    require_started_seq(event, started_seq)?;
    let terminal_provenance = validate_full_provenance(event, call, activation)?;
    if terminal_provenance != provenance {
        return session_error(format!(
            "{} at seq {} changed MCP provenance after tool.started",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn validate_pre_start_terminal(
    event: &JournalEvent,
    call: &DurableMcpCall,
    activation: &Activation,
    cancelled: bool,
) -> Result<()> {
    if event.data.get("started_seq").is_some() {
        return session_error(format!(
            "{} at seq {} references a nonexistent MCP tool.started",
            event.kind, event.seq
        ));
    }
    if event
        .data
        .get("mcp_execution_coordinator_version")
        .and_then(Value::as_u64)
        != Some(u64::from(activation.coordinator_version))
        || event.data.get("registry_epoch_id").and_then(Value::as_str)
            != Some(&activation.registry_epoch_id)
        || event.data.get("registry_digest").and_then(Value::as_str)
            != Some(&activation.registry_digest)
    {
        return session_error(format!(
            "{} at seq {} has no valid pre-start MCP authority",
            event.kind, event.seq
        ));
    }
    if event.data.get("mcp").is_some() {
        validate_full_provenance(event, call, activation)?;
    }
    if cancelled {
        if event.data.get("before_start").and_then(Value::as_bool) != Some(true) {
            return session_error(format!(
                "tool.cancelled at seq {} is not marked before_start",
                event.seq
            ));
        }
        validate_error_result(event, "cancelled")?;
    } else {
        let code = event
            .data
            .get("error_code")
            .and_then(Value::as_str)
            .ok_or_else(|| session_message(event, "pre-start MCP failure has no error_code"))?;
        if !matches!(
            code,
            "validation_error" | "not_found" | "transport_closed" | "approval_required"
        ) {
            return session_error(format!(
                "tool.completed at seq {} has unregistered pre-start error code {code}",
                event.seq
            ));
        }
        validate_error_result(event, code)?;
    }
    Ok(())
}

fn validate_safe_skip(
    event: &JournalEvent,
    call: &DurableMcpCall,
    _activation: &Activation,
    recovery_authorities: &HashMap<u64, RecoveryMarkerAuthority>,
) -> Result<()> {
    let code = event
        .data
        .get("error_code")
        .and_then(Value::as_str)
        .ok_or_else(|| session_message(event, "MCP skip has no error_code"))?;
    let expected = match event.kind.as_str() {
        "tool.skipped_due_to_recovery" => "interrupted_before_start",
        "tool.skipped_due_to_cancel" => "cancelled",
        "tool.skipped_due_to_in_doubt" => "in_doubt",
        "tool.skipped_due_to_limit" => "limit_reached",
        "tool.skipped_due_to_stalled" => "stalled",
        _ => {
            return session_error(format!(
                "{} at seq {} is not a registered MCP skip",
                event.kind, event.seq
            ));
        }
    };
    if code != expected {
        return session_error(format!(
            "{} at seq {} has inconsistent error code",
            event.kind, event.seq
        ));
    }
    if event.kind != "tool.skipped_due_to_recovery" {
        return session_error(format!(
            "{} at seq {} has no registered MCP recovery authority",
            event.kind, event.seq
        ));
    }
    if event.kind == "tool.skipped_due_to_recovery" {
        if event.data.get("response_seq").and_then(Value::as_u64) != Some(call.response_seq)
            || event.data.get("arguments") != Some(&call.arguments)
        {
            return session_error(format!(
                "tool.skipped_due_to_recovery at seq {} does not match the durable MCP call",
                event.seq
            ));
        }
        let marker_seq = event
            .data
            .get("recovery_marker_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                session_message(
                    event,
                    "tool.skipped_due_to_recovery has no recovery_marker_seq",
                )
            })?;
        let marker = recovery_authorities.get(&marker_seq);
        if marker.is_none()
            || marker_seq <= call.response_seq
            || marker_seq >= event.seq
            || marker.is_some_and(|marker| marker.skipped_before_start == 0)
        {
            return session_error(format!(
                "tool.skipped_due_to_recovery at seq {} has no preceding recovery authority",
                event.seq
            ));
        }
        let marker = marker.expect("checked recovery marker");
        if marker.authorization_version != Some(1) {
            return session_error(format!(
                "tool.skipped_due_to_recovery at seq {} has an unsupported recovery authorization",
                event.seq
            ));
        }
        let authorization_count = marker
            .authorization_count
            .ok_or_else(|| session_message(event, "recovery marker has no unstarted_tool_calls"))?;
        if authorization_count > MAX_MCP_CALLS_PER_RESPONSE_V1 {
            return session_error(format!(
                "recovery marker at seq {marker_seq} exceeds the unstarted-call limit"
            ));
        }
        let authorization_key = RecoveryAuthorizationKey {
            response_seq: call.response_seq,
            turn_id: call.key.turn_id.clone(),
            call_id: call.key.call_id.clone(),
            provider_name: call.provider_name.clone(),
            arguments_sha256: call.arguments_sha256.clone(),
        };
        let matching_authorizations = marker
            .authorization_matches
            .get(&authorization_key)
            .copied()
            .unwrap_or_default();
        if matching_authorizations != 1 {
            return session_error(format!(
                "tool.skipped_due_to_recovery at seq {} is not uniquely authorized by marker {marker_seq}",
                event.seq
            ));
        }
    }
    validate_error_result(event, expected)
}

fn validate_completed_result(event: &JournalEvent) -> Result<()> {
    let is_error = event
        .data
        .get("is_error")
        .and_then(Value::as_bool)
        .ok_or_else(|| session_message(event, "tool.completed has no is_error boolean"))?;
    let error_code = event.data.get("error_code");
    if is_error {
        if !error_code
            .and_then(Value::as_str)
            .is_some_and(valid_identity)
        {
            return session_error(format!(
                "tool.completed at seq {} has no valid error_code",
                event.seq
            ));
        }
    } else if error_code.is_some_and(|value| !value.is_null()) {
        return session_error(format!(
            "successful tool.completed at seq {} has an error_code",
            event.seq
        ));
    }
    if event.data.get("output").is_none() {
        return session_error(format!("tool.completed at seq {} has no output", event.seq));
    }
    Ok(())
}

fn validate_error_result(event: &JournalEvent, code: &str) -> Result<()> {
    if event.data.get("is_error").and_then(Value::as_bool) != Some(true)
        || event.data.get("error_code").and_then(Value::as_str) != Some(code)
        || event
            .data
            .get("output")
            .and_then(|output| output.get("error"))
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            != Some(code)
        || event
            .data
            .get("output")
            .and_then(|output| output.get("error"))
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .is_none_or(|message| message.is_empty())
    {
        return session_error(format!(
            "{} at seq {} has an inconsistent MCP error result",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn require_started_seq(event: &JournalEvent, started_seq: u64) -> Result<()> {
    if event.data.get("started_seq").and_then(Value::as_u64) != Some(started_seq) {
        return session_error(format!(
            "{} at seq {} does not reference MCP tool.started seq {started_seq}",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn event_claims_mcp(event: &JournalEvent) -> bool {
    event.data.get("mcp").is_some()
        || event
            .data
            .get("mcp_execution_coordinator_version")
            .is_some()
}

fn reject_orphan_mcp_markers(events: &[JournalEvent]) -> Result<()> {
    for event in events {
        let orphan_lifecycle = is_tool_lifecycle(&event.kind)
            && (event.data.get("mcp").is_some()
                || event
                    .data
                    .get("mcp_execution_coordinator_version")
                    .is_some());
        let orphan_response = event.kind == "response.started"
            && (event.data.get("mcp_registry_epoch_id").is_some()
                || event.data.get("mcp_registry_digest").is_some());
        if orphan_lifecycle || orphan_response {
            return session_error(format!(
                "{} at seq {} claims MCP semantics without a registry activation",
                event.kind, event.seq
            ));
        }
    }
    Ok(())
}

fn object_data(event: &JournalEvent) -> Result<&Map<String, Value>> {
    event
        .data
        .as_object()
        .ok_or_else(|| session_message(event, "data must be an object"))
}

fn require_exact_keys(
    data: &Map<String, Value>,
    expected: &[&str],
    event: &JournalEvent,
) -> Result<()> {
    let actual = data.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return session_error(format!(
            "{} at seq {} does not match the required exact key profile",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn require_version(
    data: &Map<String, Value>,
    field: &str,
    expected: u64,
    event: &JournalEvent,
) -> Result<()> {
    require_version_map(data, field, expected, event)
}

fn require_version_map(
    data: &Map<String, Value>,
    field: &str,
    expected: u64,
    event: &JournalEvent,
) -> Result<()> {
    if data.get(field).and_then(Value::as_u64) != Some(expected) {
        return session_error(format!(
            "{} at seq {} has unsupported {field}",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn required_uuid_v7(
    data: &Map<String, Value>,
    field: &str,
    event: &JournalEvent,
) -> Result<String> {
    let value = data
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| session_message(event, format!("{field} must be a UUIDv7")))?;
    let uuid = Uuid::parse_str(value)
        .map_err(|_| session_message(event, format!("{field} must be a UUIDv7")))?;
    if uuid.get_version_num() != 7 {
        return Err(session_message(event, format!("{field} must be a UUIDv7")));
    }
    Ok(value.to_owned())
}

fn required_sha256(data: &Map<String, Value>, field: &str, event: &JournalEvent) -> Result<String> {
    let value = data
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| session_message(event, format!("{field} must be a lowercase SHA-256")))?;
    Ok(value.to_owned())
}

fn valid_provider_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_identity(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn invalid_transition(event: &JournalEvent, state: &CallState) -> Result<()> {
    session_error(format!(
        "{} at seq {} cannot transition MCP call from state {state:?}",
        event.kind, event.seq
    ))
}

fn session_message(event: &JournalEvent, message: impl AsRef<str>) -> OxidraError {
    OxidraError::Session(format!(
        "{} at seq {} {}",
        event.kind,
        event.seq,
        message.as_ref()
    ))
}

fn session_error<T>(message: impl Into<String>) -> Result<T> {
    Err(OxidraError::Session(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn event(seq: u64, turn_id: Option<&str>, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: DateTime::<Utc>::from_timestamp(seq as i64, 0).expect("valid test timestamp"),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            data,
        }
    }

    fn activation(epoch: &str, digest: &str) -> JournalEvent {
        event(
            1,
            None,
            MCP_REGISTRY_ACTIVATED_KIND,
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
    }

    fn mcp_events() -> Vec<JournalEvent> {
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let arguments = json!({"text":"hello"});
        let arguments_sha256 = argument_digest_v1(&arguments).expect("digest arguments");
        let provenance = json!({
            "execution_coordinator_version":1,
            "dispatch_permit_version":1,
            "argument_digest_version":1,
            "registry_version":1,
            "registry_epoch_id":epoch,
            "registry_digest":digest,
            "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "server_name":"fixture",
            "raw_tool_name":"echo",
            "protocol_version":"2026-07-28",
            "server_attempt_id":"0190f5e6-7b00-7abc-8000-000000000003",
            "arguments_sha256":arguments_sha256,
        });
        vec![
            activation(epoch, digest),
            event(
                2,
                Some("turn-1"),
                "user.message",
                json!({"turn_boundary_version":6}),
            ),
            event(
                3,
                Some("turn-1"),
                "response.started",
                json!({
                    "response_attempt_id":"attempt-1",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            ),
            event(
                4,
                Some("turn-1"),
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-1",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-1",
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":serde_json::to_string(&arguments).expect("encode arguments"),
                    }]
                }),
            ),
            event(
                5,
                Some("turn-1"),
                "tool.started",
                json!({
                    "call_id":"call-1",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "arguments":arguments,
                    "mcp":provenance,
                }),
            ),
            event(
                6,
                Some("turn-1"),
                "tool.completed",
                json!({
                    "started_seq":5,
                    "call_id":"call-1",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "output":{"content":[{"type":"text","text":"hello"}]},
                    "is_error":false,
                    "error_code":Value::Null,
                    "before_dispatch":false,
                    "mcp":provenance,
                }),
            ),
        ]
    }

    fn mcp_events_v2() -> Vec<JournalEvent> {
        let mut events = mcp_events();
        let activation = events[0].data.as_object_mut().expect("activation data");
        activation.insert("coordinator_version".to_owned(), Value::from(2));
        activation.insert("call_chain_validator_version".to_owned(), Value::from(2));
        activation.remove("provider_names");
        activation.insert(
            "bindings".to_owned(),
            json!([{
                "provider_name":"mcp_fixture_echo_deadbeef",
                "server_name":"fixture",
                "raw_tool_name":"echo",
                "protocol_version":"2026-07-28",
            }]),
        );
        for event in &mut events {
            if let Some(provenance) = event.data.get_mut("mcp") {
                provenance["execution_coordinator_version"] = Value::from(2);
            }
        }
        events
    }

    #[test]
    fn valid_mcp_call_chain_v1_is_accepted() {
        validate_mcp_call_chain_v1(&mcp_events()).expect("valid MCP chain");
    }

    #[test]
    fn valid_mcp_call_chain_v2_binds_offline_provider_identity() {
        validate_mcp_call_chain_v2(&mcp_events_v2()).expect("valid MCP v2 chain");
    }

    #[test]
    fn validated_call_reader_ignores_earlier_generic_raw_only_completion() {
        let mut events = mcp_events_v2();
        for event in &mut events[2..] {
            event.seq += 2;
        }
        events[5].data["started_seq"] = Value::from(7);
        events.insert(
            2,
            event(
                3,
                Some("turn-1"),
                "response.started",
                json!({"response_attempt_id":"generic-attempt"}),
            ),
        );
        events.insert(
            3,
            event(
                4,
                Some("turn-1"),
                "response.completed",
                json!({
                    "response_attempt_id":"generic-attempt",
                    "raw_response":{"output":[{"type":"message","text":"generic"}]},
                    "text":"generic",
                    "usage":{},
                }),
            ),
        );

        validate_mcp_call_chain_v2(&events).expect("canonical v2 chain remains valid");
        let call = validated_durable_mcp_call(&events, "turn-1", "call-1")
            .expect("coordinator reader selects the later owned MCP response");
        assert_eq!(call.provider_name, "mcp_fixture_echo_deadbeef");
        assert_eq!(call.arguments, json!({"text":"hello"}));
        assert_eq!(call.response_started_seq, 5);
        assert_eq!(call.response_completed_seq, 6);
    }

    #[test]
    fn v2_claimed_response_owns_failed_and_unfinished_attempts() {
        let mut unfinished = mcp_events_v2();
        unfinished.truncate(3);
        validate_mcp_call_chain_v2(&unfinished)
            .expect("a claimed response may be unfinished in a crash prefix");
        assert_eq!(
            mcp_turn_ids(&unfinished).expect("owned turn"),
            vec!["turn-1"]
        );

        let mut failed = unfinished.clone();
        failed.push(event(
            4,
            Some("turn-1"),
            "response.failed",
            json!({"response_attempt_id":"attempt-1","error":"provider failed"}),
        ));
        validate_mcp_call_chain_v2(&failed)
            .expect("failed claimed response remains an owned transaction");
        assert_eq!(mcp_turn_ids(&failed).expect("owned turn"), vec!["turn-1"]);

        failed.push(event(
            5,
            Some("turn-1"),
            "response.failed",
            json!({"response_attempt_id":"attempt-1","error":"duplicate"}),
        ));
        let error = validate_mcp_call_chain_v2(&failed)
            .expect_err("a claimed response may have at most one terminal")
            .to_string();
        assert!(
            error.contains("has 2 terminals"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn v2_recovered_response_terminal_binds_exact_start_and_frozen_profile() {
        fn recovered_aborted() -> Vec<JournalEvent> {
            let mut events = mcp_events_v2();
            events.truncate(3);
            events.push(event(
                4,
                Some("turn-1"),
                "response.aborted",
                json!({
                    "response_attempt_id":"attempt-1",
                    "started_seq":3,
                    "reason":RECOVERED_RESPONSE_ABORT_REASON_V1,
                    "recovered":true,
                }),
            ));
            events
        }

        validate_mcp_call_chain_v2(&recovered_aborted())
            .expect("literal recovery writer profile must be accepted");

        let mut wrong_start = recovered_aborted();
        wrong_start[3].data["started_seq"] = Value::from(103);
        let error = validate_mcp_call_chain_v2(&wrong_start)
            .expect_err("recovery terminal must reference the exact owned start")
            .to_string();
        assert!(error.contains("exact response.started seq 3"), "{error}");

        type TerminalMutation = (&'static str, fn(&mut Map<String, Value>));
        let mutations: [TerminalMutation; 3] = [
            ("false recovered flag", |data| {
                data.insert("recovered".to_owned(), Value::Bool(false));
            }),
            ("missing reason", |data| {
                data.remove("reason");
            }),
            ("extra field", |data| {
                data.insert("extra".to_owned(), Value::Bool(true));
            }),
        ];
        for (name, mutate) in mutations {
            let mut events = recovered_aborted();
            let data = events[3].data.as_object_mut().expect("terminal data");
            mutate(data);
            assert!(
                validate_mcp_call_chain_v2(&events).is_err(),
                "{name} must fail closed"
            );
        }

        for kind in ["response.completed", "response.failed"] {
            let mut events = mcp_events_v2();
            events.truncate(4);
            events[3].kind = kind.to_owned();
            events[3].data["started_seq"] = Value::from(3);
            events[3].data["recovered"] = Value::Bool(true);
            assert!(
                validate_mcp_call_chain_v2(&events).is_err(),
                "non-recovery {kind} must reject recovery provenance"
            );
        }

        let mut live_aborted = recovered_aborted();
        live_aborted[3].data = json!({
            "response_attempt_id":"attempt-1",
            "reason":"cancelled",
        });
        validate_mcp_call_chain_v2(&live_aborted)
            .expect("ordinary response.aborted remains a non-recovery terminal");
    }

    #[test]
    fn v2_owned_response_rejects_unbound_terminal_identity() {
        for replacement in [None, Some(""), Some("attempt-other")] {
            let mut events = mcp_events_v2();
            events.truncate(3);
            let mut data = json!({"error":"provider failed"});
            if let Some(attempt_id) = replacement {
                data["response_attempt_id"] = Value::String(attempt_id.to_owned());
            }
            events.push(event(4, Some("turn-1"), "response.failed", data));
            let error = validate_mcp_call_chain_v2(&events)
                .expect_err("owned response terminal must bind the active exact attempt")
                .to_string();
            assert!(
                error.contains("active MCP response attempt")
                    || error.contains("no valid response_attempt_id")
                    || error.contains("no matching response.started"),
                "{error}"
            );
        }

        let mut events = mcp_events_v2();
        events.truncate(3);
        events.push(event(
            4,
            Some("turn-1"),
            "response.failed",
            json!({"response_attempt_id":"attempt-1","error":"first"}),
        ));
        events.push(event(
            5,
            Some("turn-1"),
            "response.started",
            json!({
                "response_attempt_id":"attempt-2",
                "mcp_registry_epoch_id":events[0].data["registry_epoch_id"],
                "mcp_registry_digest":events[0].data["registry_digest"],
            }),
        ));
        events.push(event(
            6,
            Some("turn-1"),
            "response.failed",
            json!({"response_attempt_id":"attempt-2","error":"second"}),
        ));
        validate_mcp_call_chain_v2(&events)
            .expect("sequential exact owned attempts on the same turn remain valid");
    }

    #[test]
    fn v2_response_envelope_rejects_generic_recovery_and_overlapping_attempts() {
        let mut generic_recovery = mcp_events_v2();
        generic_recovery.truncate(1);
        generic_recovery.push(event(
            2,
            Some("turn-generic"),
            "response.started",
            json!({"response_attempt_id":"generic-attempt"}),
        ));
        generic_recovery.push(event(
            3,
            Some("turn-generic"),
            "response.aborted",
            json!({
                "response_attempt_id":"generic-attempt",
                "started_seq":103,
                "reason":RECOVERED_RESPONSE_ABORT_REASON_V1,
                "recovered":true,
            }),
        ));
        validate_mcp_call_chain_v2(&generic_recovery)
            .expect_err("generic recovery provenance must bind its exact start");

        for generic_first in [false, true] {
            let mut events = mcp_events_v2();
            events.truncate(1);
            let epoch = events[0].data["registry_epoch_id"].clone();
            let digest = events[0].data["registry_digest"].clone();
            let generic = event(
                2 + u64::from(!generic_first),
                Some("turn-overlap"),
                "response.started",
                json!({"response_attempt_id":"generic-attempt"}),
            );
            let owned = event(
                2 + u64::from(generic_first),
                Some("turn-overlap"),
                "response.started",
                json!({
                    "response_attempt_id":"owned-attempt",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":digest,
                }),
            );
            if generic_first {
                events.extend([generic, owned]);
            } else {
                events.extend([owned, generic]);
            }
            validate_mcp_call_chain_v2(&events)
                .expect_err("generic and owned attempts cannot overlap on one turn");
        }
    }

    #[test]
    fn v2_response_envelope_requires_status_payloads() {
        for (kind, field) in [("response.failed", "error"), ("response.aborted", "reason")] {
            for value in [
                None,
                Some(Value::String(String::new())),
                Some(Value::Bool(true)),
            ] {
                let mut events = mcp_events_v2();
                events.truncate(3);
                let mut data = json!({"response_attempt_id":"attempt-1"});
                if let Some(value) = value {
                    data[field] = value;
                }
                events.push(event(4, Some("turn-1"), kind, data));
                validate_mcp_call_chain_v2(&events)
                    .expect_err("owned status terminal requires a bounded non-empty payload");
            }
        }
    }

    #[test]
    fn v2_claimed_builtin_only_response_is_still_owned() {
        let mut events = mcp_events_v2();
        events.truncate(4);
        events[3].data["output_items"] = json!([{
            "type":"function_call",
            "call_id":"builtin-call",
            "name":"read",
            "arguments":"{}"
        }]);
        validate_mcp_call_chain_v2(&events)
            .expect("MCP-owned responses with only built-in calls remain valid");
        assert_eq!(mcp_turn_ids(&events).expect("owned turn"), vec!["turn-1"]);
    }

    #[test]
    fn v2_claimed_start_requires_turn_and_attempt_identity() {
        let mut missing_turn = mcp_events_v2();
        missing_turn[2].turn_id = None;
        let error = validate_mcp_call_chain_v2(&missing_turn)
            .expect_err("claimed response.started must carry turn_id")
            .to_string();
        assert!(
            error.contains("no valid turn_id"),
            "unexpected error: {error}"
        );

        let mut missing_attempt = mcp_events_v2();
        missing_attempt[2]
            .data
            .as_object_mut()
            .unwrap()
            .remove("response_attempt_id");
        let error = validate_mcp_call_chain_v2(&missing_attempt)
            .expect_err("claimed response.started must carry response_attempt_id")
            .to_string();
        assert!(
            error.contains("no valid response_attempt_id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn frozen_v1_and_v2_have_explicit_binding_semantics() {
        let mut v1 = mcp_events();
        for event in &mut v1[4..=5] {
            event.data["mcp"]["server_name"] = Value::String("other-server".to_owned());
            event.data["mcp"]["raw_tool_name"] = Value::String("other-tool".to_owned());
            event.data["mcp"]["protocol_version"] = Value::String("other-protocol".to_owned());
        }
        validate_mcp_call_chain_v1(&v1).expect("frozen v1 did not persist a binding snapshot");

        let mut v2 = mcp_events_v2();
        for event in &mut v2[4..=5] {
            event.data["mcp"]["server_name"] = Value::String("other-server".to_owned());
            event.data["mcp"]["raw_tool_name"] = Value::String("other-tool".to_owned());
            event.data["mcp"]["protocol_version"] = Value::String("other-protocol".to_owned());
        }
        let error = validate_mcp_call_chain_v2(&v2)
            .expect_err("v2 must prove provider alias provenance from the activation snapshot")
            .to_string();
        assert!(
            error.contains("does not match the activated provider binding"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mcp_response_call_limit_is_frozen_in_validator_v2_without_rewriting_v1() {
        let mut events = mcp_events();
        events.truncate(4);
        events[3].data["output_items"] = Value::Array(
            (0..=MAX_MCP_CALLS_PER_RESPONSE_V1)
                .map(|index| {
                    json!({
                        "type":"function_call",
                        "call_id":format!("call-{index}"),
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":"{}"
                    })
                })
                .collect(),
        );

        validate_mcp_call_chain_v1(&events)
            .expect("frozen validator v1 accepted oversized batches before v2 added the bound");

        let mut events = mcp_events_v2();
        events.truncate(4);
        events[3].data["output_items"] = Value::Array(
            (0..=MAX_MCP_CALLS_PER_RESPONSE_V1)
                .map(|index| {
                    json!({
                        "type":"function_call",
                        "call_id":format!("call-{index}"),
                        "name": if index == 0 { "mcp_fixture_echo_deadbeef" } else { "read" },
                        "arguments":"{}"
                    })
                })
                .collect(),
        );
        let error = validate_mcp_call_chain_v2(&events)
            .expect_err("validator v2 must reject an oversized mixed response batch")
            .to_string();
        assert!(
            error.contains("exceeds the 4096-call limit"),
            "unexpected error: {error}"
        );

        let mut all_generic = mcp_events_v2();
        all_generic.truncate(4);
        all_generic[3].data["output_items"] = Value::Array(
            (0..=MAX_MCP_CALLS_PER_RESPONSE_V1)
                .map(|index| {
                    json!({
                        "type":"function_call",
                        "call_id":format!("generic-call-{index}"),
                        "name":"read",
                        "arguments":"{}"
                    })
                })
                .collect(),
        );
        let error = validate_mcp_call_chain_v2(&all_generic)
            .expect_err("an MCP-owned response must bound the complete Provider call batch")
            .to_string();
        assert!(
            error.contains("exceeds the 4096-call limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn v2_response_ownership_requires_canonical_output_items() {
        fn hide_call_in_raw_response_and_make_terminal_generic(events: &mut Vec<JournalEvent>) {
            let output_items = events[3]
                .data
                .as_object_mut()
                .expect("response data")
                .remove("output_items")
                .expect("output items");
            events[3].data["raw_response"] = json!({"output":output_items});
            events.remove(4);
            events[4].seq = 5;
            let terminal = events[4].data.as_object_mut().expect("terminal data");
            terminal.remove("mcp");
            terminal.remove("started_seq");
            terminal.remove("before_dispatch");
        }

        let mut v1 = mcp_events();
        hide_call_in_raw_response_and_make_terminal_generic(&mut v1);
        validate_mcp_call_chain_v1(&v1)
            .expect("frozen v1 identified ownership from output_items rather than the start claim");

        let mut v2 = mcp_events_v2();
        hide_call_in_raw_response_and_make_terminal_generic(&mut v2);
        let error = validate_mcp_call_chain_v2(&v2)
            .expect_err("v2 must not let a claimed raw-only MCP call use a generic terminal")
            .to_string();
        assert!(
            error.contains("no canonical output_items"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validator_ceiling_accepts_registered_history_but_not_future_versions() {
        validate_mcp_call_chain_through_version(2, &mcp_events())
            .expect("v2 compatibility view must retain v1 journals");
        validate_mcp_call_chain_through_version(2, &mcp_events_v2())
            .expect("v2 compatibility view must accept v2 journals");

        let mut future = mcp_events_v2();
        future[0].data["call_chain_validator_version"] = Value::from(3);
        let error = validate_mcp_call_chain_through_version(2, &future)
            .expect_err("v2 compatibility view must not inherit future validators")
            .to_string();
        assert!(error.contains("exceeds compatibility ceiling 2"));
    }

    #[test]
    fn generic_terminal_cannot_settle_an_mcp_call() {
        let mut events = mcp_events();
        events[5]
            .data
            .as_object_mut()
            .expect("terminal object")
            .remove("mcp");
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("generic terminal must not settle MCP call")
            .to_string();
        assert!(
            error.contains("MCP lifecycle event has no mcp provenance"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn reused_mcp_call_id_cannot_be_settled_from_another_turn() {
        let mut events = mcp_events();
        events[5].turn_id = Some("turn-2".to_owned());
        events[5].data["tool"] = Value::String("local_tool".to_owned());
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("global pending-tool matching must not bypass MCP turn identity")
            .to_string();
        assert!(error.contains("does not reference a durable MCP Provider call"));
    }

    #[test]
    fn wrong_mcp_argument_digest_is_rejected() {
        let mut events = mcp_events();
        events[4].data["mcp"]["arguments_sha256"] = Value::String("d".repeat(64));
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("MCP started provenance must bind arguments")
            .to_string();
        assert!(error.contains("provenance does not match"));
    }

    #[test]
    fn id_alias_cannot_settle_an_mcp_call() {
        let mut events = mcp_events();
        let terminal = events[5].data.as_object_mut().expect("terminal object");
        terminal.remove("call_id");
        terminal.insert("id".to_owned(), Value::String("call-1".to_owned()));
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("MCP lifecycle must use canonical call_id")
            .to_string();
        assert!(
            error.contains("canonical call_id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn orphan_mcp_provenance_is_rejected_without_activation() {
        let events = vec![event(
            1,
            Some("turn-1"),
            "tool.completed",
            json!({
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "mcp_execution_coordinator_version":1,
            }),
        )];
        assert!(validate_mcp_call_chain_v1(&events).is_err());
    }

    #[test]
    fn response_registry_claim_must_match_activation_even_without_a_call() {
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let events = vec![
            activation(epoch, digest),
            event(
                2,
                Some("turn-1"),
                "response.started",
                json!({
                    "response_attempt_id":"attempt-1",
                    "mcp_registry_epoch_id":epoch,
                    "mcp_registry_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                }),
            ),
        ];
        assert!(validate_mcp_call_chain_v1(&events).is_err());
    }

    #[test]
    fn activation_does_not_reinterpret_pre_activation_provider_calls() {
        let mut registry_activation = activation(
            "0190f5e6-7b00-7abc-8000-000000000002",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
        registry_activation.seq = 4;
        let events = vec![
            event(
                1,
                Some("turn-legacy"),
                "response.started",
                json!({"response_attempt_id":"attempt-legacy"}),
            ),
            event(
                2,
                Some("turn-legacy"),
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-legacy",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"legacy-call",
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":"{}"
                    }]
                }),
            ),
            event(
                3,
                Some("turn-legacy"),
                "tool.completed",
                json!({
                    "call_id":"legacy-call",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "output":{"ok":true},
                    "is_error":false
                }),
            ),
            registry_activation,
        ];
        validate_mcp_call_chain_v1(&events)
            .expect("historical generic call remains outside the activated MCP prefix");
    }

    #[test]
    fn recovery_skip_requires_a_preceding_recovery_marker() {
        let mut events = mcp_events();
        let arguments = json!({"text":"hello"});
        events.truncate(4);
        let error = ensure_no_unstarted_mcp_calls_v1(&events)
            .expect_err("live registry resume must wait for recovery")
            .to_string();
        assert!(error.contains("must be recovered"));
        events.push(event(
            6,
            None,
            crate::session::RECOVERY_KIND,
            json!({
                "skipped_before_start":1,
                "tool_skip_authorization_version":1,
                "unstarted_tool_calls":[{
                    "response_seq":4,
                    "turn_id":"turn-1",
                    "call_id":"call-1",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "arguments_sha256":argument_digest_v1(&arguments).expect("argument digest")
                }]
            }),
        ));
        events.push(event(
            7,
            Some("turn-1"),
            "tool.skipped_due_to_recovery",
            json!({
                "response_seq":4,
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "arguments":arguments,
                "output":{"error":{"code":"interrupted_before_start","message":"not dispatched"}},
                "is_error":true,
                "error_code":"interrupted_before_start",
                "recovery_marker_seq":6
            }),
        ));
        validate_mcp_call_chain_v1(&events).expect("recovery-authorized skip");
        ensure_no_unstarted_mcp_calls_v1(&events)
            .expect("recovery terminal makes the durable epoch resumable");

        let mut forged = events;
        forged[5].data["recovery_marker_seq"] = Value::from(5);
        assert!(validate_mcp_call_chain_v1(&forged).is_err());
    }

    #[test]
    fn generic_skip_cannot_terminalize_an_mcp_call() {
        let mut events = mcp_events();
        events.truncate(4);
        events.push(event(
            5,
            Some("turn-1"),
            "tool.skipped_due_to_limit",
            json!({
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "output":{"error":{"code":"limit_reached","message":"not dispatched"}},
                "is_error":true,
                "error_code":"limit_reached"
            }),
        ));
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("generic skip has no MCP recovery authority")
            .to_string();
        assert!(error.contains("no registered MCP recovery authority"));
    }

    #[test]
    fn response_attempt_cannot_have_two_mcp_terminals() {
        let mut events = mcp_events();
        events.truncate(4);
        let mut duplicate = events[3].clone();
        duplicate.seq = 5;
        duplicate.data["output_items"][0]["call_id"] = Value::String("call-2".to_owned());
        events.push(duplicate);
        let error = validate_mcp_call_chain_v1(&events)
            .expect_err("one response attempt must have one terminal")
            .to_string();
        assert!(
            error.contains("has 2 terminals"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn generic_response_started_before_activation_may_finish_after_it() {
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let mut registry_activation = activation(epoch, digest);
        registry_activation.seq = 3;
        let events = vec![
            event(
                1,
                Some("turn-legacy"),
                "response.started",
                json!({"response_attempt_id":"attempt-legacy"}),
            ),
            event(2, Some("turn-legacy"), "display.note", json!({})),
            registry_activation,
            event(
                4,
                Some("turn-legacy"),
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-legacy",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"legacy-call",
                        "name":"mcp_fixture_echo_deadbeef",
                        "arguments":"{}"
                    }]
                }),
            ),
            event(
                5,
                Some("turn-legacy"),
                "tool.completed",
                json!({
                    "call_id":"legacy-call",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "output":{"ok":true},
                    "is_error":false
                }),
            ),
        ];
        validate_mcp_call_chain_v1(&events)
            .expect("response ownership is fixed by its pre-activation start");
    }
}
