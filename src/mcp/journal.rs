//! Frozen validation for the durable MCP call lifecycle.
//!
//! Journal payloads are untrusted.  A provider alias that belongs to an MCP
//! registry only receives tool lifecycle semantics after this reducer proves
//! the activation, durable Provider call and every started/terminal edge.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, Write};
use std::sync::Arc;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{McpModelOutputV1, schema};
use crate::context::{
    MCP_SURFACE_CLAIM_VERSION_V1, PROVIDER_PROTOCOL_OPENAI_RESPONSES, ToolSurfaceSnapshotV1,
    measure_exact_prepared_request,
};
use crate::error::{OxidraError, Result};
use crate::event_kind::{is_response_terminal, is_tool_lifecycle, is_tool_terminal};
use crate::projection::project_provider_request_after_mcp_validation;
use crate::session::JournalEvent;

pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V1: u32 = 1;
pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V2: u32 = 2;
pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V3: u32 = 3;
pub(crate) const MCP_CALL_CHAIN_VALIDATOR_VERSION_V4: u32 = 4;
pub const MCP_CALL_CHAIN_VALIDATOR_VERSION: u32 = MCP_CALL_CHAIN_VALIDATOR_VERSION_V4;
const MAX_MCP_CALLS_PER_RESPONSE_V1: usize = 4_096;
pub const MAX_MCP_CALLS_PER_RESPONSE: usize = MAX_MCP_CALLS_PER_RESPONSE_V1;
const MCP_EXECUTION_COORDINATOR_VERSION_V1: u64 = 1;
const MCP_EXECUTION_COORDINATOR_VERSION_V2: u64 = 2;
const MCP_EXECUTION_COORDINATOR_VERSION_V3: u64 = 3;
const MCP_EXECUTION_COORDINATOR_VERSION_V4: u64 = 4;
const MCP_RESPONSE_SURFACE_REFERENCE_VERSION_V1: u64 = 1;
const MCP_PREPARED_REQUEST_REFERENCE_VERSION_V1: u64 = 1;
const MAX_MCP_PREPARED_REQUEST_BODY_BYTES_V1: usize = 8 * 1024 * 1024;
/// v4 replays a historical projection for every owned Provider start. Until a
/// streaming projection reader replaces that algorithm, freeze cumulative
/// work so a valid journal cannot make reopen perform unbounded quadratic
/// scans. Production admission runs the same prospective validator before the
/// next `response.started` is fsynced.
const MAX_MCP_V4_PROJECTION_PREFIX_EVENT_VISITS: usize = 8 * 1024 * 1024;
const MAX_MCP_V4_PROJECTION_PREFIX_BYTES: usize = 1024 * 1024 * 1024;
const MAX_MCP_V4_OWNED_RESPONSE_STARTS: usize = 4_096;
const MCP_DISPATCH_PERMIT_VERSION_V1: u64 = 1;
const MCP_ARGUMENT_DIGEST_VERSION_V1: u64 = 1;
const MCP_TOOL_REGISTRY_VERSION_V1: u64 = 1;
const MCP_STDIO_KERNEL_VERSION_V1: u64 = 1;
const MCP_SCHEMA_PROFILE_VERSION_V1: u64 = 1;
const MCP_REGISTRY_ACTIVATED_KIND: &str = "mcp.registry.activated";
const MAX_MCP_RAWLESS_ERROR_MESSAGE_BYTES_V3: usize = 16 * 1024;
const MCP_RAWLESS_COMPLETION_CODES_V3: &[&str] =
    &["dispatch_permit_invalid", "not_found", "transport_closed"];

thread_local! {
    /// Projection v4 depends on the compaction/turn reducers, whose frozen
    /// policies in turn re-check the MCP prefix. Nested checks validate the
    /// complete v4 core but must not recursively rebuild the same prepared
    /// request projection. This scope is thread-local and panic-safe; callers
    /// cannot construct it outside this module.
    static MCP_V4_PROJECTION_SCOPE: Cell<bool> = const { Cell::new(false) };
}

struct McpV4ProjectionScope;

#[derive(Default)]
struct McpV4ProjectionBudget {
    response_starts: usize,
    prefix_event_visits: usize,
    prefix_bytes: usize,
}

impl McpV4ProjectionBudget {
    fn charge(&mut self, prefix_event_visits: usize, prefix_bytes: usize) -> Result<()> {
        self.response_starts = self.response_starts.checked_add(1).ok_or_else(|| {
            OxidraError::Session("MCP v4 prepared-request projection budget overflow".to_owned())
        })?;
        self.prefix_event_visits = self
            .prefix_event_visits
            .checked_add(prefix_event_visits)
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP v4 prepared-request event-visit budget overflow".to_owned(),
                )
            })?;
        self.prefix_bytes = self.prefix_bytes.checked_add(prefix_bytes).ok_or_else(|| {
            OxidraError::Session("MCP v4 prepared-request prefix-byte budget overflow".to_owned())
        })?;
        if self.response_starts > MAX_MCP_V4_OWNED_RESPONSE_STARTS
            || self.prefix_event_visits > MAX_MCP_V4_PROJECTION_PREFIX_EVENT_VISITS
            || self.prefix_bytes > MAX_MCP_V4_PROJECTION_PREFIX_BYTES
        {
            return session_error(
                "MCP v4 prepared-request projection exceeds its frozen validation-work budget",
            );
        }
        Ok(())
    }
}

impl McpV4ProjectionScope {
    fn enter() -> Option<Self> {
        MCP_V4_PROJECTION_SCOPE.with(|scope| {
            if scope.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
    }
}

impl Drop for McpV4ProjectionScope {
    fn drop(&mut self) {
        MCP_V4_PROJECTION_SCOPE.with(|scope| scope.set(false));
    }
}

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
    surface_claim_version: Option<u32>,
    surface_bindings: Option<Vec<SurfaceBindingIdentity>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BindingIdentity {
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SurfaceBindingIdentity {
    provider_name: String,
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
    definition_digest: String,
    output_schema_digest: Option<String>,
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
    response_attempt_id: Option<String>,
    surface: Option<SurfaceProvenanceV3>,
}

/// The exact Provider-visible surface relation carried by a v3 MCP call.
/// Keeping this on the validated call projection prevents lifecycle readers
/// from re-deriving alias identity from a live registry or a second event
/// scan.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SurfaceProvenanceV3 {
    surface_event_seq: u64,
    surface_digest: String,
    definition_digest: String,
    output_schema_digest: Option<String>,
}

impl From<SurfaceProvenanceV3> for ValidatedMcpSurfaceProvenanceV3 {
    fn from(surface: SurfaceProvenanceV3) -> Self {
        Self {
            surface_event_seq: surface.surface_event_seq,
            surface_digest: surface.surface_digest,
            definition_digest: surface.definition_digest,
            output_schema_digest: surface.output_schema_digest,
        }
    }
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
    // The v3 offline reader is intentionally registered before the v3
    // coordinator/Agent consumers. Retain the proof now without forcing the
    // current v2 coordinator to interpret future protocol fields.
    #[allow(dead_code)]
    pub(crate) response_attempt_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) surface: Option<ValidatedMcpSurfaceProvenanceV3>,
}

/// Exact v3 surface identity retained by the canonical durable-call reader.
/// v1/v2 projections use `None`; consumers must not reconstruct these fields
/// from a live registry after validation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ValidatedMcpSurfaceProvenanceV3 {
    pub(crate) surface_event_seq: u64,
    pub(crate) surface_digest: String,
    pub(crate) definition_digest: String,
    pub(crate) output_schema_digest: Option<String>,
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

/// Validate the first MCP protocol that binds an owned Provider response to
/// one exact, durable `context.tools` surface.  This reader is registered now
/// but is not the current writer default: turn/slot/projection/compaction
/// protocols still freeze their compatibility ceiling at call-chain v2.
pub(crate) fn validate_mcp_call_chain_v3(events: &[JournalEvent]) -> Result<()> {
    let activation = activation_v3(events)?;
    let Some(activation) = activation else {
        reject_orphan_mcp_markers(events)?;
        return Ok(());
    };
    if activation.call_chain_validator_version != MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 {
        return session_error("unsupported MCP call-chain validator version");
    }

    validate_mcp_call_chain_with_activation(events, &activation)
}

/// Validate the first MCP protocol that binds the exact prepared Provider
/// request digest as well as the v3 Provider-visible tool surface.  v1-v3
/// remain frozen compatibility readers; v4 is registered as an offline
/// reader before it becomes the current writer protocol.
pub(crate) fn validate_mcp_call_chain_v4(events: &[JournalEvent]) -> Result<()> {
    let activation = activation_v4(events)?;
    let Some(activation) = activation else {
        reject_orphan_mcp_markers(events)?;
        return Ok(());
    };
    if activation.call_chain_validator_version != MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 {
        return session_error("unsupported MCP call-chain validator version");
    }

    validate_mcp_call_chain_with_activation(events, &activation)?;
    let Some(_scope) = McpV4ProjectionScope::enter() else {
        // A projection-level dependency is validating a prefix of the exact
        // chain already being proved. The core activation/response/lifecycle
        // state above remains mandatory; only the cyclic projection edge is
        // suppressed for this nested call.
        return Ok(());
    };
    validate_prepared_request_projection_v4(events, &activation)
}

fn validate_mcp_call_chain_with_activation(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<()> {
    if activation.call_chain_validator_version < MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 {
        validate_response_registry_claims(events, activation)?;
    }
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
        match activation.call_chain_validator_version {
            MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 | MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => {
                validate_lifecycle_event_v1(event, call, activation, state, &recovery_authorities)?;
            }
            MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 | MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => {
                validate_lifecycle_event_v3(event, call, activation, state, &recovery_authorities)?;
            }
            version => {
                return session_error(format!(
                    "unsupported MCP lifecycle validator version {version}"
                ));
            }
        }
    }

    Ok(())
}

/// Maximum durable response failure/abort status size.  Production writers
/// use `response_status_text_for_journal` before fsync so the frozen reader
/// and writer accept exactly the same profile.
pub(crate) const MAX_RESPONSE_STATUS_TEXT_BYTES_V2: usize = 16 * 1024;

pub(crate) fn response_status_text_for_journal(input: &str) -> String {
    let input = if input.is_empty() {
        "unspecified response status"
    } else {
        input
    };
    crate::untrusted_display::truncate_utf8(input, MAX_RESPONSE_STATUS_TEXT_BYTES_V2)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedResponseSurfaceV3 {
    surface_event_seq: u64,
    surface_digest: String,
    registry_epoch_id: String,
    registry_digest: String,
    bindings: Vec<SurfaceBindingIdentity>,
    provider_tools: Value,
}

/// Establish v3 response ownership from the exact tool surface referenced by
/// the Provider request.  The explicit `mcp_surface` row closes that relation;
/// it is not the sole authority, so deleting the row cannot downgrade a
/// response that actually used an MCP-capable `context.tools` snapshot.
fn owned_response_start_seqs_v3(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<u64, Arc<OwnedResponseSurfaceV3>>> {
    let mut events_by_seq = HashMap::<u64, &JournalEvent>::new();
    for event in events {
        if events_by_seq.insert(event.seq, event).is_some() {
            return session_error(format!(
                "MCP call-chain validator v3 found duplicate journal seq {}",
                event.seq
            ));
        }
    }

    let mut start_context_seqs = HashMap::<u64, u64>::new();
    let mut referenced_tools_seqs = BTreeSet::new();
    for start in events
        .iter()
        .filter(|event| event.kind == "response.started")
    {
        let has_registry_epoch = start.data.get("mcp_registry_epoch_id").is_some();
        let has_registry_digest = start.data.get("mcp_registry_digest").is_some();
        let has_surface_reference = start.data.get("mcp_surface").is_some();
        if start.seq <= activation.seq {
            if has_registry_epoch || has_registry_digest || has_surface_reference {
                return session_error(format!(
                    "response.started at seq {} claims MCP surface state before activation",
                    start.seq
                ));
            }
            continue;
        }
        let tools_event_seq = start
            .data
            .get("context")
            .and_then(Value::as_object)
            .and_then(|context| context.get("tools_event_seq"))
            .and_then(Value::as_u64)
            .filter(|seq| *seq != 0)
            .ok_or_else(|| {
                session_message(
                    start,
                    "has no valid context.tools_event_seq for surface validation v3",
                )
            })?;
        if tools_event_seq >= start.seq {
            return session_error(format!(
                "response.started at seq {} does not follow context.tools seq {tools_event_seq}",
                start.seq
            ));
        }
        start_context_seqs.insert(start.seq, tools_event_seq);
        referenced_tools_seqs.insert(tools_event_seq);
    }

    let mut surfaces = HashMap::<u64, Arc<OwnedResponseSurfaceV3>>::new();
    for tools_event_seq in referenced_tools_seqs {
        let event = events_by_seq
            .get(&tools_event_seq)
            .copied()
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "MCP surface reference points to missing context.tools seq {tools_event_seq}"
                ))
            })?;
        if event.kind != "context.tools" || event.turn_id.is_some() {
            return session_error(format!(
                "MCP surface reference seq {tools_event_seq} does not identify one global context.tools event"
            ));
        }
        let has_mcp_claim = event
            .data
            .as_object()
            .is_some_and(|data| data.contains_key("mcp"));
        if !has_mcp_claim {
            return Err(session_message(
                event,
                "is referenced after activation v3 but has no MCP surface claim",
            ));
        }
        let snapshot = ToolSurfaceSnapshotV1::from_exact_journal_value(&event.data)?;
        let claim = snapshot.mcp().ok_or_else(|| {
            session_message(event, "has an empty or non-canonical MCP surface claim")
        })?;
        let bindings = claim
            .bindings()
            .iter()
            .map(|binding| SurfaceBindingIdentity {
                provider_name: binding.provider_name().to_owned(),
                server_name: binding.server_name().to_owned(),
                raw_tool_name: binding.raw_tool_name().to_owned(),
                protocol_version: binding.protocol_version().to_owned(),
                definition_digest: binding.definition_digest().to_owned(),
                output_schema_digest: binding.output_schema_digest().map(ToOwned::to_owned),
            })
            .collect::<Vec<_>>();
        let provider_tools = Value::Array(
            snapshot
                .tools()
                .iter()
                .map(|tool| {
                    json!({
                        "type":"function",
                        "name":tool.name,
                        "description":tool.description,
                        "parameters":tool.input_schema,
                        "strict":false,
                    })
                })
                .collect(),
        );
        let surface = Arc::new(OwnedResponseSurfaceV3 {
            surface_event_seq: tools_event_seq,
            surface_digest: snapshot.digest().to_owned(),
            registry_epoch_id: claim.registry_epoch_id().to_owned(),
            registry_digest: claim.registry_digest().to_owned(),
            bindings,
            provider_tools,
        });
        surfaces.insert(tools_event_seq, surface);
    }

    let expected_bindings = activation.surface_bindings.as_deref().ok_or_else(|| {
        OxidraError::Session("MCP activation v3 has no surface binding snapshot".to_owned())
    })?;
    if activation.surface_claim_version != Some(MCP_SURFACE_CLAIM_VERSION_V1) {
        return session_error("MCP activation v3 has no supported surface claim version");
    }
    let mut owned = HashMap::<u64, Arc<OwnedResponseSurfaceV3>>::new();
    let mut starts_by_key = HashMap::<(String, String), Vec<u64>>::new();
    for start in events
        .iter()
        .filter(|event| event.kind == "response.started" && event.seq > activation.seq)
    {
        let tools_event_seq = *start_context_seqs
            .get(&start.seq)
            .expect("post-activation start context was indexed");
        let surface = surfaces
            .get(&tools_event_seq)
            .expect("referenced context.tools surface was decoded");
        let has_registry_epoch = start.data.get("mcp_registry_epoch_id").is_some();
        let has_registry_digest = start.data.get("mcp_registry_digest").is_some();
        let has_surface_reference = start.data.get("mcp_surface").is_some();
        if tools_event_seq <= activation.seq {
            return session_error(format!(
                "MCP context.tools seq {tools_event_seq} does not follow activation seq {}",
                activation.seq
            ));
        }
        if surface.registry_epoch_id != activation.registry_epoch_id
            || surface.registry_digest != activation.registry_digest
            || surface.bindings.as_slice() != expected_bindings
        {
            return Err(session_message(
                start,
                "references a tool surface that does not match activation v3",
            ));
        }
        if !(has_registry_epoch && has_registry_digest && has_surface_reference) {
            return Err(session_message(
                start,
                "must carry the complete MCP registry and surface reference",
            ));
        }
        validate_response_registry(start, activation)?;
        let reference = start
            .data
            .get("mcp_surface")
            .and_then(Value::as_object)
            .ok_or_else(|| session_message(start, "mcp_surface must be an object"))?;
        require_exact_keys(reference, &["digest", "event_seq", "version"], start)?;
        require_version(
            reference,
            "version",
            MCP_RESPONSE_SURFACE_REFERENCE_VERSION_V1,
            start,
        )?;
        if reference.get("event_seq").and_then(Value::as_u64) != Some(tools_event_seq) {
            return Err(session_message(
                start,
                "mcp_surface.event_seq does not match context.tools_event_seq",
            ));
        }
        if required_sha256(reference, "digest", start)? != surface.surface_digest {
            return Err(session_message(
                start,
                "mcp_surface.digest does not match the referenced context.tools snapshot",
            ));
        }
        owned.insert(start.seq, Arc::clone(surface));
        if let (Some(turn_id), Some(attempt_id)) = (
            start.turn_id.as_deref(),
            start
                .data
                .get("response_attempt_id")
                .and_then(Value::as_str),
        ) {
            starts_by_key
                .entry((turn_id.to_owned(), attempt_id.to_owned()))
                .or_default()
                .push(start.seq);
        }
    }

    // A durable activated alias cannot be smuggled through a generic response
    // by deleting its registry/surface claim.  Canonical output owns the call;
    // raw-response audit fields do not.
    for completed in events
        .iter()
        .filter(|event| event.kind == "response.completed" && event.seq > activation.seq)
    {
        let uses_activated_alias = completed
            .data
            .get("output_items")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item.get("type").and_then(Value::as_str) == Some("function_call")
                        && item
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| activation.provider_names.contains(name))
                })
            });
        if !uses_activated_alias {
            continue;
        }
        let key = completed
            .turn_id
            .as_deref()
            .zip(
                completed
                    .data
                    .get("response_attempt_id")
                    .and_then(Value::as_str),
            )
            .map(|(turn_id, attempt_id)| (turn_id.to_owned(), attempt_id.to_owned()));
        let start_seq = key
            .as_ref()
            .and_then(|key| starts_by_key.get(key))
            .filter(|starts| starts.len() == 1)
            .map(|starts| starts[0]);
        if start_seq.is_none_or(|seq| !owned.contains_key(&seq)) {
            return Err(session_message(
                completed,
                "uses an activated MCP provider alias without an owned v3 response surface",
            ));
        }
    }

    Ok(owned)
}

/// Extend the frozen v3 surface relation with one exact prepared-request
/// identity. The request reference is a separate closed profile so later
/// request hashing rules need not change the v3 surface snapshot contract.
fn owned_response_start_seqs_v4(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<u64, Arc<OwnedResponseSurfaceV3>>> {
    let owned = owned_response_start_seqs_v3(events, activation)?;
    let starts_by_seq = events
        .iter()
        .filter(|event| event.kind == "response.started")
        .map(|event| (event.seq, event))
        .collect::<HashMap<_, _>>();
    for start_seq in owned.keys() {
        let start = starts_by_seq
            .get(start_seq)
            .copied()
            .expect("owned response start was indexed from the same journal");
        let reference = start
            .data
            .get("mcp_prepared_request")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                session_message(start, "mcp_prepared_request must be an object for v4")
            })?;
        require_exact_keys(reference, &["body", "digest", "version"], start)?;
        require_version(
            reference,
            "version",
            MCP_PREPARED_REQUEST_REFERENCE_VERSION_V1,
            start,
        )?;
        let reference_digest = required_sha256(reference, "digest", start)?;
        let body = reference.get("body").ok_or_else(|| {
            session_message(start, "mcp_prepared_request has no canonical body for v4")
        })?;
        super::preflight_mcp_provider_event_tree_v1(
            body,
            MAX_MCP_PREPARED_REQUEST_BODY_BYTES_V1,
        )
        .map_err(|error| {
            OxidraError::Session(format!(
                "response.started at seq {} prepared Provider request exceeds the bounded v1 JSON profile: {error}",
                start.seq
            ))
        })?;
        let canonical_body_bytes = serde_json::to_vec(body)?;
        let recomputed_measurement = measure_exact_prepared_request(body, &canonical_body_bytes)?;
        let recomputed_digest = recomputed_measurement.request_digest.as_str();
        if reference_digest != recomputed_digest {
            return Err(session_message(
                start,
                "mcp_prepared_request.digest does not match its canonical body",
            ));
        }
        let surface = owned
            .get(start_seq)
            .expect("v4 request start has the v3 surface indexed above");
        validate_prepared_request_body_v1(body, start, surface)?;
        let measurement = start
            .data
            .get("context")
            .and_then(Value::as_object)
            .and_then(|context| context.get("measurement"))
            .ok_or_else(|| {
                session_message(
                    start,
                    "has no context.measurement for prepared-request validation v4",
                )
            })?;
        let expected_measurement = serde_json::to_value(&recomputed_measurement)?;
        if measurement != &expected_measurement {
            return Err(session_message(
                start,
                "context.measurement does not match the canonical prepared Provider request",
            ));
        }
    }
    Ok(owned)
}

/// Bind every v4 prepared body to the journal state that existed before its
/// exact `response.started`. Digest and measurement fields live in the same
/// mutable journal record as the body, so they are integrity checks, not an
/// independent provenance anchor. The canonical input/instructions/runtime
/// events are the authority that prevents a self-consistent forged request
/// from becoming valid history.
fn validate_prepared_request_projection_v4(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<()> {
    let owned = owned_response_start_seqs_v4(events, activation)?;
    let events_by_seq = events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<HashMap<_, _>>();
    let event_indexes = events
        .iter()
        .enumerate()
        .map(|(index, event)| (event.seq, index))
        .collect::<HashMap<_, _>>();
    let mut cumulative_encoded_bytes = Vec::with_capacity(events.len());
    let mut encoded_bytes = 0usize;
    for event in events {
        let event_bytes = crate::session::encode_journal_event_v2(event)?
            .len()
            .checked_add(1)
            .ok_or_else(|| OxidraError::Session("MCP v4 journal event size overflow".to_owned()))?;
        encoded_bytes = encoded_bytes.checked_add(event_bytes).ok_or_else(|| {
            OxidraError::Session("MCP v4 journal prefix size overflow".to_owned())
        })?;
        cumulative_encoded_bytes.push(encoded_bytes);
    }
    let mut budget = McpV4ProjectionBudget::default();
    let mut start_seqs = owned.keys().copied().collect::<Vec<_>>();
    start_seqs.sort_unstable();

    for start_seq in start_seqs {
        let start = events_by_seq
            .get(&start_seq)
            .copied()
            .expect("owned v4 response start was indexed from the same journal");
        let start_index = *event_indexes
            .get(&start_seq)
            .expect("owned v4 response start index");
        let context = start
            .data
            .get("context")
            .and_then(Value::as_object)
            .ok_or_else(|| session_message(start, "has no request context object for v4"))?;
        let through_seq = context
            .get("request_journal_through_seq")
            .and_then(Value::as_u64)
            .filter(|seq| *seq != 0 && *seq < start.seq)
            .ok_or_else(|| {
                session_message(
                    start,
                    "has no valid request_journal_through_seq for prepared-request validation v4",
                )
            })?;
        let Some(&through_index) = event_indexes.get(&through_seq) else {
            return Err(session_message(
                start,
                "references a missing request_journal_through_seq event",
            ));
        };
        if start_index == 0 || through_index + 1 != start_index {
            return Err(session_message(
                start,
                "request_journal_through_seq is not the exact durable predecessor of response.started",
            ));
        }
        budget.charge(through_index + 1, cumulative_encoded_bytes[through_index])?;
        let prefix = &events[..=through_index];
        let tools_event_seq = context
            .get("tools_event_seq")
            .and_then(Value::as_u64)
            .filter(|seq| *seq != 0 && *seq <= through_seq)
            .ok_or_else(|| {
                session_message(
                    start,
                    "has no valid tools_event_seq for prepared-request validation v4",
                )
            })?;
        if latest_global_context_event_seq_v4(prefix, "context.tools") != Some(tools_event_seq) {
            return Err(session_message(
                start,
                "tools_event_seq is not the effective context.tools at the request cutoff",
            ));
        }
        let projected = project_provider_request_after_mcp_validation(prefix)?;
        let body = start
            .data
            .get("mcp_prepared_request")
            .and_then(Value::as_object)
            .and_then(|reference| reference.get("body"))
            .and_then(Value::as_object)
            .expect("owned v4 request body was validated above");
        if body.get("input") != Some(&Value::Array(projected)) {
            return Err(session_message(
                start,
                "mcp_prepared_request.body.input does not match the canonical journal projection",
            ));
        }

        let configured_seq = context
            .get("configured_event_seq")
            .and_then(Value::as_u64)
            .filter(|seq| *seq != 0 && *seq <= through_seq)
            .ok_or_else(|| {
                session_message(
                    start,
                    "has no valid configured_event_seq for prepared-request validation v4",
                )
            })?;
        if latest_global_context_event_seq_v4(prefix, "context.configured") != Some(configured_seq)
        {
            return Err(session_message(
                start,
                "configured_event_seq is not the effective context.configured at the request cutoff",
            ));
        }
        let configured = exact_global_context_event_v4(
            &events_by_seq,
            configured_seq,
            "context.configured",
            start,
        )?;
        let configured_model = configured
            .data
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| session_message(configured, "has no non-empty model"))?;
        if body.get("model").and_then(Value::as_str) != Some(configured_model) {
            return Err(session_message(
                start,
                "mcp_prepared_request.body.model does not match context.configured",
            ));
        }
        if configured
            .data
            .get("provider_protocol")
            .and_then(Value::as_str)
            != Some(PROVIDER_PROTOCOL_OPENAI_RESPONSES)
        {
            return Err(session_message(
                configured,
                "does not select the frozen OpenAI Responses Provider protocol",
            ));
        }
        let configured_domain = configured
            .data
            .get("provider_usage_domain")
            .and_then(Value::as_str)
            .filter(|value| valid_sha256(value))
            .ok_or_else(|| {
                session_message(configured, "has no valid Provider usage-domain digest")
            })?;
        if context.get("provider_usage_domain").and_then(Value::as_str) != Some(configured_domain) {
            return Err(session_message(
                start,
                "request context Provider usage domain does not match context.configured",
            ));
        }

        let instructions_seq = match context.get("instructions_event_seq") {
            Some(Value::Null) | None => None,
            Some(value) => {
                let instructions_seq = value
                    .as_u64()
                    .filter(|seq| *seq != 0 && *seq <= through_seq)
                    .ok_or_else(|| {
                        session_message(
                            start,
                            "has an invalid instructions_event_seq for prepared-request validation v4",
                        )
                    })?;
                Some(instructions_seq)
            }
        };
        if latest_global_context_event_seq_v4(prefix, "context.instructions") != instructions_seq {
            return Err(session_message(
                start,
                "instructions_event_seq is not the effective context.instructions at the request cutoff",
            ));
        }
        let expected_instructions = match instructions_seq {
            Some(instructions_seq) => {
                let instructions = exact_global_context_event_v4(
                    &events_by_seq,
                    instructions_seq,
                    "context.instructions",
                    start,
                )?
                .data
                .get("instructions")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    session_message(start, "referenced context.instructions is not a string")
                })?;
                (!instructions.is_empty()).then_some(instructions)
            }
            None => None,
        };
        if body.get("instructions").and_then(Value::as_str) != expected_instructions {
            return Err(session_message(
                start,
                "mcp_prepared_request.body.instructions does not match context.instructions",
            ));
        }
        // v4 has no independent durable policy field for a per-request output
        // override. Accepting one would make the body its own authority.
        if body.contains_key("max_output_tokens") {
            return Err(session_message(
                start,
                "mcp_prepared_request.body.max_output_tokens has no durable v4 policy anchor",
            ));
        }
    }
    Ok(())
}

fn latest_global_context_event_seq_v4(events: &[JournalEvent], kind: &str) -> Option<u64> {
    events
        .iter()
        .rev()
        .find(|event| event.kind == kind && event.turn_id.is_none())
        .map(|event| event.seq)
}

fn exact_global_context_event_v4<'a>(
    events_by_seq: &'a HashMap<u64, &'a JournalEvent>,
    seq: u64,
    expected_kind: &str,
    start: &JournalEvent,
) -> Result<&'a JournalEvent> {
    let event = events_by_seq.get(&seq).copied().ok_or_else(|| {
        session_message(
            start,
            format!("references missing {expected_kind} seq {seq}"),
        )
    })?;
    if event.kind != expected_kind || event.turn_id.is_some() || event.seq >= start.seq {
        return Err(session_message(
            start,
            format!("does not reference one earlier global {expected_kind} event"),
        ));
    }
    Ok(event)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_prepared_request_body_v1(
    body: &Value,
    start: &JournalEvent,
    surface: &OwnedResponseSurfaceV3,
) -> Result<()> {
    let object = body.as_object().ok_or_else(|| {
        session_message(
            start,
            "mcp_prepared_request.body must be a canonical Provider request object",
        )
    })?;
    let mut expected = BTreeSet::from(["include", "input", "model", "store", "stream", "tools"]);
    if object.contains_key("instructions") {
        expected.insert("instructions");
    }
    if object.contains_key("max_output_tokens") {
        expected.insert("max_output_tokens");
    }
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(session_message(
            start,
            "mcp_prepared_request.body is not in the frozen Provider request v1 shape",
        ));
    }
    if object
        .get("model")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || !object.get("input").is_some_and(Value::is_array)
        || object.get("tools") != Some(&surface.provider_tools)
        || object.get("stream").and_then(Value::as_bool) != Some(true)
        || object.get("store").and_then(Value::as_bool) != Some(false)
        || object.get("include") != Some(&json!(["reasoning.encrypted_content"]))
        || object
            .get("instructions")
            .is_some_and(|value| !value.is_string())
        || object
            .get("max_output_tokens")
            .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(session_message(
            start,
            "mcp_prepared_request.body does not match its exact Provider surface/profile",
        ));
    }
    Ok(())
}

/// Validate the complete v2 response transaction before projecting any MCP
/// calls.  The response start, not a discovered function call, owns the
/// lifecycle.  Generic and MCP-claimed attempts share one per-turn active
/// slot, so a second start cannot hide behind a later MCP projection.
fn response_attempts_v2<'a>(
    events: &'a [JournalEvent],
    activation: &Activation,
) -> Result<BTreeMap<(String, String), OwnedResponseAttemptV2<'a>>> {
    let owned_surface = match activation.call_chain_validator_version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 => {
            Some(owned_response_start_seqs_v3(events, activation)?)
        }
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => {
            Some(owned_response_start_seqs_v4(events, activation)?)
        }
        _ => None,
    };
    let mut starts = HashMap::<(String, String), Vec<u64>>::new();
    let mut active = HashMap::<String, (String, u64)>::new();
    let mut terminal_counts = HashMap::<(String, String), u8>::new();
    let mut owned = BTreeMap::new();
    for event in events {
        match event.kind.as_str() {
            "response.started" => {
                let Some(turn_id) = event
                    .turn_id
                    .as_deref()
                    .filter(|value| valid_identity(value))
                else {
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
                    let claims_mcp = owned_surface.as_ref().map_or_else(
                        || {
                            event.data.get("mcp_registry_epoch_id").is_some()
                                || event.data.get("mcp_registry_digest").is_some()
                        },
                        |owned| owned.contains_key(&event.seq),
                    );
                    if claims_mcp {
                        validate_response_registry(event, activation)?;
                        let surface = owned_surface
                            .as_ref()
                            .and_then(|owned| owned.get(&event.seq))
                            .cloned();
                        if owned
                            .insert(
                                key,
                                OwnedResponseAttemptV2 {
                                    start: event,
                                    turn_id: turn_id.to_owned(),
                                    response_attempt_id: attempt_id.to_owned(),
                                    terminal: None,
                                    surface,
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
    // Public turn/projection reducers can reach this dispatcher with events
    // constructed directly in safe Rust. A historical wire reader could not
    // materialize trees beyond serde_json's depth ceiling; reject those
    // fixtures before activation/call/result readers clone or serialize them.
    for event in events {
        crate::session::validate_borrowed_json_depth_v1(
            &event.data,
            128,
            "MCP reducer",
            "journal event data",
        )?;
    }
    match version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => validate_mcp_call_chain_v1(events),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => validate_mcp_call_chain_v2(events),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 => validate_mcp_call_chain_v3(events),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => validate_mcp_call_chain_v4(events),
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
    validated_durable_mcp_call_if_present(events, turn_id, call_id)?.ok_or_else(|| {
        OxidraError::Session(format!(
            "MCP call {call_id} is not present in turn {turn_id}"
        ))
    })
}

/// Return a validated MCP call when the exact Provider call is owned by the
/// durable activation, or `None` for a built-in/non-MCP call.  The complete
/// chain is still validated before classification so callers cannot downgrade
/// a malformed MCP prefix to a generic lifecycle event.
pub(crate) fn validated_durable_mcp_call_if_present(
    events: &[JournalEvent],
    turn_id: &str,
    call_id: &str,
) -> Result<Option<ValidatedDurableMcpCall>> {
    let Some(version) = call_chain_validator_version(events)? else {
        return Ok(None);
    };
    let activation = match version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => activation_v1(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => activation_v2(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 => activation_v3(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => activation_v4(events)?,
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
    let Some(call) = durable_mcp_calls(events, &activation)?.remove(&key) else {
        return Ok(None);
    };
    Ok(Some(ValidatedDurableMcpCall {
        provider_name: call.provider_name,
        arguments: call.arguments,
        arguments_sha256: call.arguments_sha256,
        registry_epoch_id: call.registry_epoch_id,
        registry_digest: call.registry_digest,
        response_started_seq: call.response_started_seq,
        response_completed_seq: call.response_seq,
        response_attempt_id: call.response_attempt_id,
        surface: call.surface.map(Into::into),
    }))
}

/// Validate once and return all canonical MCP calls belonging to one turn.
/// Agent skip/recovery paths use this batch projection so classifying a wide
/// response does not re-run the complete reducer for every sibling call.
pub(crate) fn validated_durable_mcp_calls_for_turn(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<HashMap<String, ValidatedDurableMcpCall>> {
    Ok(validated_durable_mcp_calls_index(events)?
        .into_iter()
        .filter(|((call_turn_id, _), _)| call_turn_id == turn_id)
        .map(|((_, call_id), call)| (call_id, call))
        .collect())
}

/// Validate the selected durable MCP language once and return an exact
/// `(turn_id, call_id)` index for every owned Provider call.  Recovery uses
/// this whole-journal form so classifying unstarted calls across many turns is
/// O(events + calls), rather than re-running the complete MCP reducer once per
/// turn.
pub(crate) fn validated_durable_mcp_calls_index(
    events: &[JournalEvent],
) -> Result<HashMap<(String, String), ValidatedDurableMcpCall>> {
    let Some(version) = call_chain_validator_version(events)? else {
        return Ok(HashMap::new());
    };
    let activation = match version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => activation_v1(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => activation_v2(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 => activation_v3(events)?,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => activation_v4(events)?,
        version => {
            return session_error(format!(
                "unsupported MCP call-chain validator version {version}"
            ));
        }
    }
    .expect("call-chain version implies an activation");
    validate_mcp_call_chain_with_activation(events, &activation)?;
    Ok(durable_mcp_calls(events, &activation)?
        .into_iter()
        .map(|(key, call)| {
            (
                (key.turn_id, key.call_id),
                ValidatedDurableMcpCall {
                    provider_name: call.provider_name,
                    arguments: call.arguments,
                    arguments_sha256: call.arguments_sha256,
                    registry_epoch_id: call.registry_epoch_id,
                    registry_digest: call.registry_digest,
                    response_started_seq: call.response_started_seq,
                    response_completed_seq: call.response_seq,
                    response_attempt_id: call.response_attempt_id,
                    surface: call.surface.map(Into::into),
                },
            )
        })
        .collect())
}

pub(crate) fn mcp_turn_ids(events: &[JournalEvent]) -> Result<Vec<String>> {
    let version = call_chain_validator_version(events)?;
    let activation = match version {
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V1) => activation_v1(events)?,
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) => activation_v2(events)?,
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V3) => activation_v3(events)?,
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V4) => activation_v4(events)?,
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
    let mut turn_ids =
        if version.is_some_and(|version| version >= MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) {
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

pub(crate) fn ensure_no_unstarted_mcp_calls_v3(events: &[JournalEvent]) -> Result<()> {
    validate_mcp_call_chain_v3(events)?;
    let Some(activation) = activation_v3(events)? else {
        return Ok(());
    };
    ensure_no_unstarted_mcp_calls_with_activation(events, &activation)
}

pub(crate) fn ensure_no_unstarted_mcp_calls_v4(events: &[JournalEvent]) -> Result<()> {
    validate_mcp_call_chain_v4(events)?;
    let Some(activation) = activation_v4(events)? else {
        return Ok(());
    };
    ensure_no_unstarted_mcp_calls_with_activation(events, &activation)
}

pub(crate) fn ensure_no_unstarted_mcp_calls(events: &[JournalEvent]) -> Result<()> {
    match call_chain_validator_version(events)? {
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V1) => ensure_no_unstarted_mcp_calls_v1(events),
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V2) => ensure_no_unstarted_mcp_calls_v2(events),
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V3) => ensure_no_unstarted_mcp_calls_v3(events),
        Some(MCP_CALL_CHAIN_VALIDATOR_VERSION_V4) => ensure_no_unstarted_mcp_calls_v4(events),
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
        surface_claim_version: None,
        surface_bindings: None,
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
        surface_claim_version: None,
        surface_bindings: None,
    }))
}

fn activation_v3(events: &[JournalEvent]) -> Result<Option<Activation>> {
    activation_surface_v3_or_v4(
        events,
        MCP_EXECUTION_COORDINATOR_VERSION_V3,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3,
    )
}

fn activation_v4(events: &[JournalEvent]) -> Result<Option<Activation>> {
    activation_surface_v3_or_v4(
        events,
        MCP_EXECUTION_COORDINATOR_VERSION_V4,
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4,
    )
}

fn activation_surface_v3_or_v4(
    events: &[JournalEvent],
    coordinator_version: u64,
    call_chain_validator_version: u32,
) -> Result<Option<Activation>> {
    let activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
        .collect::<Vec<_>>();
    if activations.is_empty() {
        return Ok(None);
    }
    if activations.len() != 1 {
        return session_error(format!(
            "MCP call-chain validator v{call_chain_validator_version} requires exactly one registry activation"
        ));
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
            "surface_claim_version",
        ],
        event,
    )?;
    require_version(data, "coordinator_version", coordinator_version, event)?;
    require_version(
        data,
        "call_chain_validator_version",
        u64::from(call_chain_validator_version),
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
    require_version(
        data,
        "surface_claim_version",
        u64::from(MCP_SURFACE_CLAIM_VERSION_V1),
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
    let mut surface_bindings = Vec::with_capacity(snapshot.len());
    let mut previous = None::<&str>;
    for value in snapshot {
        let binding = value
            .as_object()
            .ok_or_else(|| session_message(event, "bindings contains a non-object entry"))?;
        require_exact_keys(
            binding,
            &[
                "definition_digest",
                "output_schema_digest",
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
                .filter(|value| valid_surface_identity_v1(value))
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    session_message(event, format!("bindings contains an invalid {field}"))
                })
        };
        let definition_digest = required_sha256(binding, "definition_digest", event)?;
        let output_schema_digest = match binding.get("output_schema_digest") {
            Some(Value::Null) => None,
            Some(Value::String(_)) => {
                Some(required_sha256(binding, "output_schema_digest", event)?)
            }
            _ => {
                return Err(session_message(
                    event,
                    "bindings contains an invalid output_schema_digest",
                ));
            }
        };
        let server_name = required_identity("server_name")?;
        let raw_tool_name = required_identity("raw_tool_name")?;
        let protocol_version = required_identity("protocol_version")?;
        provider_names.insert(provider_name.to_owned());
        bindings.insert(
            provider_name.to_owned(),
            BindingIdentity {
                server_name: server_name.clone(),
                raw_tool_name: raw_tool_name.clone(),
                protocol_version: protocol_version.clone(),
            },
        );
        surface_bindings.push(SurfaceBindingIdentity {
            provider_name: provider_name.to_owned(),
            server_name,
            raw_tool_name,
            protocol_version,
            definition_digest,
            output_schema_digest,
        });
    }

    Ok(Some(Activation {
        seq: event.seq,
        coordinator_version: coordinator_version as u32,
        call_chain_validator_version,
        schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1 as u32,
        registry_epoch_id,
        registry_digest,
        execution_plan_digest,
        provider_names,
        bindings: Some(bindings),
        surface_claim_version: Some(MCP_SURFACE_CLAIM_VERSION_V1),
        surface_bindings: Some(surface_bindings),
    }))
}

fn durable_mcp_calls(
    events: &[JournalEvent],
    activation: &Activation,
) -> Result<HashMap<McpCallKey, DurableMcpCall>> {
    match activation.call_chain_validator_version {
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V1 => durable_mcp_calls_v1(events, activation),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V2 => durable_mcp_calls_v2(events, activation),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V3 => durable_mcp_calls_v2(events, activation),
        MCP_CALL_CHAIN_VALIDATOR_VERSION_V4 => durable_mcp_calls_v2(events, activation),
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
                response_attempt_id: None,
                surface: None,
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
    surface: Option<Arc<OwnedResponseSurfaceV3>>,
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
            let surface = match attempt.surface.as_ref() {
                Some(surface) => {
                    let binding = surface
                        .bindings
                        .iter()
                        .find(|binding| binding.provider_name == provider_name)
                        .ok_or_else(|| {
                            session_message(
                                event,
                                "MCP function_call provider alias is absent from its owned v3 surface",
                            )
                        })?;
                    Some(SurfaceProvenanceV3 {
                        surface_event_seq: surface.surface_event_seq,
                        surface_digest: surface.surface_digest.clone(),
                        definition_digest: binding.definition_digest.clone(),
                        output_schema_digest: binding.output_schema_digest.clone(),
                    })
                }
                None => None,
            };
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
                response_attempt_id: Some(attempt.response_attempt_id.clone()),
                surface,
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

/// Validate lifecycle edges for the first protocol that binds dispatch to the
/// exact Provider-visible surface.  v1/v2 provenance remains byte-compatible;
/// v3 deliberately freezes a new closed provenance profile instead of
/// silently inheriting the older alias-only checks.
fn validate_lifecycle_event_v3(
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
            validate_started_outer_profile_v3(event)?;
            let provenance = validate_full_provenance_v3(event, call, activation)?;
            *state = CallState::Started {
                seq: event.seq,
                provenance: provenance.clone(),
            };
        }
        "tool.in_doubt" => {
            let CallState::Started { seq, provenance } = state else {
                return invalid_transition(event, state);
            };
            validate_post_start_terminal_outer_profile_v3(event, false)?;
            validate_started_terminal_v3(event, *seq, provenance, call, activation)?;
            validate_error_result(event, "in_doubt")?;
            *state = CallState::InDoubt { started_seq: *seq };
        }
        "tool.in_doubt_resolved" => {
            let CallState::InDoubt { started_seq } = state else {
                return invalid_transition(event, state);
            };
            require_exact_keys(
                object_data(event)?,
                &[
                    "call_id",
                    "error_code",
                    "is_error",
                    "output",
                    "resolution",
                    "started_seq",
                    "tool",
                ],
                event,
            )?;
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
                validate_pre_start_terminal_outer_profile_v3(event, false)?;
                validate_pre_start_terminal_v3(event, call, activation, false)?;
                *state = CallState::Terminal;
            }
            CallState::Started { seq, provenance } => {
                validate_started_terminal_v3(event, *seq, provenance, call, activation)?;
                if event.data.get("mcp_raw_result").is_some() {
                    validate_post_start_completed_outer_profile_v3(event)?;
                    validate_completed_result_v3(event)?;
                } else {
                    // A post-dispatch transport/coordination failure may have
                    // no protocol result to audit.  It is still a completed
                    // lifecycle edge, but only the bounded, self-consistent
                    // error profile is allowed; a raw-less success must not
                    // be mistaken for a validated MCP result.
                    validate_post_start_terminal_outer_profile_v3(event, false)?;
                    validate_known_error_result_v3(event)?;
                }
                *state = CallState::Terminal;
            }
            _ => return invalid_transition(event, state),
        },
        "tool.cancelled" => match state {
            CallState::Unstarted => {
                validate_pre_start_terminal_outer_profile_v3(event, true)?;
                validate_pre_start_terminal_v3(event, call, activation, true)?;
                *state = CallState::Terminal;
            }
            CallState::Started { seq, provenance } => {
                validate_post_start_terminal_outer_profile_v3(event, true)?;
                validate_started_terminal_v3(event, *seq, provenance, call, activation)?;
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
            require_exact_keys(
                object_data(event)?,
                &[
                    "arguments",
                    "call_id",
                    "error_code",
                    "is_error",
                    "output",
                    "reason",
                    "recovery_marker_seq",
                    "response_seq",
                    "tool",
                ],
                event,
            )?;
            // Recovery authorization binds the exact durable response seq,
            // call identity and arguments digest.  Since the durable v3 call
            // already owns one exact surface, the recovery edge does not need
            // a second caller-supplied surface claim.
            validate_safe_skip(event, call, activation, recovery_authorities)?;
            *state = CallState::Terminal;
        }
        _ if is_tool_terminal(&event.kind) => return invalid_transition(event, state),
        _ => {}
    }
    Ok(())
}

fn validate_started_outer_profile_v3(event: &JournalEvent) -> Result<()> {
    require_exact_keys(
        object_data(event)?,
        &["arguments", "call_id", "mcp", "tool"],
        event,
    )
}

fn validate_post_start_terminal_outer_profile_v3(
    event: &JournalEvent,
    before_dispatch: bool,
) -> Result<()> {
    require_exact_keys(
        object_data(event)?,
        &[
            "before_dispatch",
            "call_id",
            "error_code",
            "is_error",
            "mcp",
            "output",
            "started_seq",
            "tool",
        ],
        event,
    )?;
    if event.data.get("before_dispatch").and_then(Value::as_bool) != Some(before_dispatch) {
        return session_error(format!(
            "{} at seq {} has inconsistent before_dispatch authority",
            event.kind, event.seq
        ));
    }
    Ok(())
}

fn validate_post_start_completed_outer_profile_v3(event: &JournalEvent) -> Result<()> {
    require_exact_keys(
        object_data(event)?,
        &[
            "before_dispatch",
            "call_id",
            "error_code",
            "is_error",
            "mcp",
            "mcp_raw_result",
            "output",
            "started_seq",
            "tool",
        ],
        event,
    )?;
    if event.data.get("before_dispatch").and_then(Value::as_bool) != Some(false) {
        return session_error(format!(
            "tool.completed at seq {} is not marked as post-dispatch",
            event.seq
        ));
    }
    Ok(())
}

fn validate_pre_start_terminal_outer_profile_v3(
    event: &JournalEvent,
    cancelled: bool,
) -> Result<()> {
    let data = object_data(event)?;
    if cancelled {
        require_exact_keys(
            data,
            &[
                "before_start",
                "call_id",
                "error_code",
                "is_error",
                "mcp",
                "mcp_execution_coordinator_version",
                "output",
                "registry_digest",
                "registry_epoch_id",
                "tool",
            ],
            event,
        )
    } else {
        require_exact_keys(
            data,
            &[
                "call_id",
                "error_code",
                "is_error",
                "mcp",
                "mcp_execution_coordinator_version",
                "output",
                "registry_digest",
                "registry_epoch_id",
                "tool",
            ],
            event,
        )
    }
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

fn validate_full_provenance_v3<'a>(
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
    require_exact_keys(
        data,
        &[
            "argument_digest_version",
            "arguments_sha256",
            "definition_digest",
            "dispatch_permit_version",
            "execution_coordinator_version",
            "execution_plan_digest",
            "output_schema_digest",
            "protocol_version",
            "raw_tool_name",
            "registry_digest",
            "registry_epoch_id",
            "registry_version",
            "response_attempt_id",
            "response_completed_seq",
            "response_started_seq",
            "server_attempt_id",
            "server_name",
            "surface_claim_version",
            "surface_digest",
            "surface_event_seq",
        ],
        event,
    )?;
    require_version_map(
        data,
        "dispatch_permit_version",
        MCP_DISPATCH_PERMIT_VERSION_V1,
        event,
    )?;
    validate_surface_bound_provenance_v3(data, event, call, activation)?;
    required_uuid_v7(data, "server_attempt_id", event)?;
    Ok(provenance)
}

fn validate_pre_start_provenance_v3(
    event: &JournalEvent,
    call: &DurableMcpCall,
    activation: &Activation,
) -> Result<()> {
    let provenance = event
        .data
        .get("mcp")
        .ok_or_else(|| session_message(event, "pre-start MCP lifecycle has no mcp provenance"))?;
    let data = provenance.as_object().ok_or_else(|| {
        session_message(
            event,
            "pre-start MCP lifecycle provenance must be an object",
        )
    })?;
    require_exact_keys(
        data,
        &[
            "argument_digest_version",
            "arguments_sha256",
            "definition_digest",
            "execution_coordinator_version",
            "execution_plan_digest",
            "output_schema_digest",
            "protocol_version",
            "raw_tool_name",
            "registry_digest",
            "registry_epoch_id",
            "registry_version",
            "response_attempt_id",
            "response_completed_seq",
            "response_started_seq",
            "server_name",
            "surface_claim_version",
            "surface_digest",
            "surface_event_seq",
        ],
        event,
    )?;
    validate_surface_bound_provenance_v3(data, event, call, activation)
}

fn validate_surface_bound_provenance_v3(
    data: &Map<String, Value>,
    event: &JournalEvent,
    call: &DurableMcpCall,
    activation: &Activation,
) -> Result<()> {
    require_version_map(
        data,
        "execution_coordinator_version",
        u64::from(activation.coordinator_version),
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
    require_version_map(
        data,
        "surface_claim_version",
        u64::from(MCP_SURFACE_CLAIM_VERSION_V1),
        event,
    )?;

    let surface = call.surface.as_ref().ok_or_else(|| {
        session_message(
            event,
            "MCP lifecycle call has no owned v3 surface provenance",
        )
    })?;
    let response_attempt_id = call.response_attempt_id.as_deref().ok_or_else(|| {
        session_message(event, "MCP lifecycle call has no owned response attempt")
    })?;
    if data.get("registry_epoch_id").and_then(Value::as_str)
        != Some(activation.registry_epoch_id.as_str())
        || data.get("registry_digest").and_then(Value::as_str)
            != Some(activation.registry_digest.as_str())
        || data.get("execution_plan_digest").and_then(Value::as_str)
            != Some(activation.execution_plan_digest.as_str())
        || data.get("arguments_sha256").and_then(Value::as_str)
            != Some(call.arguments_sha256.as_str())
        || data.get("response_attempt_id").and_then(Value::as_str) != Some(response_attempt_id)
        || data.get("response_started_seq").and_then(Value::as_u64)
            != Some(call.response_started_seq)
        || data.get("response_completed_seq").and_then(Value::as_u64) != Some(call.response_seq)
        || data.get("surface_event_seq").and_then(Value::as_u64) != Some(surface.surface_event_seq)
        || data.get("surface_digest").and_then(Value::as_str)
            != Some(surface.surface_digest.as_str())
        || data.get("definition_digest").and_then(Value::as_str)
            != Some(surface.definition_digest.as_str())
    {
        return session_error(format!(
            "{} at seq {} MCP v3 provenance does not match its exact response/call/surface",
            event.kind, event.seq
        ));
    }
    match (
        &surface.output_schema_digest,
        data.get("output_schema_digest"),
    ) {
        (None, Some(Value::Null)) => {}
        (Some(expected), Some(Value::String(actual))) if actual == expected => {}
        _ => {
            return session_error(format!(
                "{} at seq {} MCP v3 provenance has a mismatched output schema digest",
                event.kind, event.seq
            ));
        }
    }
    for field in [
        "registry_digest",
        "execution_plan_digest",
        "arguments_sha256",
        "surface_digest",
        "definition_digest",
    ] {
        required_sha256(data, field, event)?;
    }
    if surface.output_schema_digest.is_some() {
        required_sha256(data, "output_schema_digest", event)?;
    }

    let binding = activation
        .surface_bindings
        .as_deref()
        .and_then(|bindings| {
            bindings
                .iter()
                .find(|binding| binding.provider_name == call.provider_name)
        })
        .ok_or_else(|| {
            session_message(
                event,
                "MCP lifecycle provider alias has no activated v3 surface binding",
            )
        })?;
    for (field, expected) in [
        ("server_name", binding.server_name.as_str()),
        ("raw_tool_name", binding.raw_tool_name.as_str()),
        ("protocol_version", binding.protocol_version.as_str()),
    ] {
        let actual = data
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| valid_surface_identity_v1(value));
        if actual != Some(expected) {
            return session_error(format!(
                "{} at seq {} MCP v3 provenance does not match surface field {field}",
                event.kind, event.seq
            ));
        }
    }
    Ok(())
}

fn validate_started_terminal_v3(
    event: &JournalEvent,
    started_seq: u64,
    provenance: &Value,
    call: &DurableMcpCall,
    activation: &Activation,
) -> Result<()> {
    require_started_seq(event, started_seq)?;
    let terminal_provenance = validate_full_provenance_v3(event, call, activation)?;
    if terminal_provenance != provenance {
        return session_error(format!(
            "{} at seq {} changed MCP v3 provenance after tool.started",
            event.kind, event.seq
        ));
    }
    Ok(())
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

fn validate_pre_start_terminal_v3(
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
            != Some(activation.registry_epoch_id.as_str())
        || event.data.get("registry_digest").and_then(Value::as_str)
            != Some(activation.registry_digest.as_str())
    {
        return session_error(format!(
            "{} at seq {} has no valid pre-start MCP v3 authority",
            event.kind, event.seq
        ));
    }
    validate_pre_start_provenance_v3(event, call, activation)?;
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

/// v3 post-dispatch completions carry two deliberately separate views:
/// `mcp_raw_result` is the bounded parsed protocol audit value and `output` is
/// the canonical text-only model projection.  Re-derive the latter from the
/// former while reading the journal so a writer cannot smuggle metadata,
/// structured content, a trusted label, or a different error polarity into
/// the model-facing surface.
fn validate_completed_result_v3(event: &JournalEvent) -> Result<()> {
    validate_completed_result(event)?;
    let raw = event.data.get("mcp_raw_result").ok_or_else(|| {
        session_message(
            event,
            "post-dispatch v3 tool.completed has no mcp_raw_result audit value",
        )
    })?;
    super::preflight_mcp_result_tree_v1(raw).map_err(|error| {
        OxidraError::Session(format!(
            "tool.completed at seq {} raw MCP result exceeds the v1 tree profile: {error}",
            event.seq
        ))
    })?;
    validate_bounded_json_v3(
        raw,
        super::MAX_MCP_RAW_RESULT_BYTES_V1,
        event,
        "raw MCP result",
    )?;
    let expected = McpModelOutputV1::from_raw_result_v1(raw).map_err(|error| {
        OxidraError::Session(format!(
            "tool.completed at seq {} has invalid MCP raw result profile: {error}",
            event.seq
        ))
    })?;
    let output = event
        .data
        .get("output")
        .ok_or_else(|| session_message(event, "tool.completed has no model output"))?;
    super::preflight_mcp_result_tree_v1(output).map_err(|error| {
        OxidraError::Session(format!(
            "tool.completed at seq {} model output exceeds the v1 tree profile: {error}",
            event.seq
        ))
    })?;
    validate_bounded_json_v3(
        output,
        super::MAX_MCP_MODEL_OUTPUT_BYTES_V1,
        event,
        "model output",
    )?;
    let actual = McpModelOutputV1::from_value_v1(output).map_err(|error| {
        OxidraError::Session(format!(
            "tool.completed at seq {} has invalid MCP model output profile: {error}",
            event.seq
        ))
    })?;
    if actual != expected {
        return session_error(format!(
            "tool.completed at seq {} model output does not match mcp_raw_result",
            event.seq
        ));
    }
    if event.data.get("is_error").and_then(Value::as_bool) != Some(expected.is_error()) {
        return session_error(format!(
            "tool.completed at seq {} error polarity does not match mcp_raw_result",
            event.seq
        ));
    }
    let expected_error_code = expected.is_error().then_some("mcp_tool_error");
    let actual_error_code = event.data.get("error_code").and_then(Value::as_str);
    if actual_error_code != expected_error_code {
        return session_error(format!(
            "tool.completed at seq {} error_code does not match the v3 MCP result profile",
            event.seq
        ));
    }
    Ok(())
}

/// Serialize only into a bounded sink.  The journal reader must reject an
/// oversized untrusted JSON value before any `to_vec`/clone-style operation
/// can allocate its complete canonical representation.
fn validate_bounded_json_v3(
    value: &Value,
    maximum_bytes: usize,
    event: &JournalEvent,
    label: &str,
) -> Result<()> {
    let mut sink = BoundedJsonSizeSink::new(maximum_bytes);
    match serde_json::to_writer(&mut sink, value) {
        Ok(()) => Ok(()),
        Err(_error) if sink.exceeded => session_error(format!(
            "{} at seq {} exceeds its {}-byte bound",
            label, event.seq, maximum_bytes
        )),
        Err(error) => Err(OxidraError::Session(format!(
            "{} at seq {} cannot be encoded: {error}",
            label, event.seq
        ))),
    }
}

struct BoundedJsonSizeSink {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl BoundedJsonSizeSink {
    fn new(maximum: usize) -> Self {
        Self {
            written: 0,
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonSizeSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded JSON sink limit exceeded",
            ));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_known_error_result_v3(event: &JournalEvent) -> Result<()> {
    validate_completed_result(event)?;
    let code = event
        .data
        .get("error_code")
        .and_then(Value::as_str)
        .ok_or_else(|| session_message(event, "raw-less MCP completion has no error code"))?;
    if !MCP_RAWLESS_COMPLETION_CODES_V3.contains(&code) {
        return session_error(format!(
            "tool.completed at seq {} uses unregistered raw-less MCP error code {code}",
            event.seq
        ));
    }
    let output = event
        .data
        .get("output")
        .and_then(Value::as_object)
        .ok_or_else(|| session_message(event, "raw-less MCP error output must be an object"))?;
    require_exact_nested_keys(output, &["error"], event, "output")?;
    let error = output
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| session_message(event, "raw-less MCP error must be an object"))?;
    require_exact_nested_keys(error, &["code", "message"], event, "output.error")?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| {
            !message.is_empty()
                && message.len() <= MAX_MCP_RAWLESS_ERROR_MESSAGE_BYTES_V3
                && crate::untrusted_display::sanitize_single_line(message) == *message
        })
        .ok_or_else(|| {
            session_message(
                event,
                "raw-less MCP error message is empty, unsafe, or exceeds its v3 byte limit",
            )
        })?;
    let _ = message;
    validate_error_result(event, code)
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
                || event.data.get("mcp_registry_digest").is_some()
                || event.data.get("mcp_surface").is_some()
                || event.data.get("mcp_prepared_request").is_some());
        let orphan_context_surface = event.kind == "context.tools"
            && event
                .data
                .as_object()
                .is_some_and(|data| data.contains_key("mcp"));
        if orphan_lifecycle || orphan_response || orphan_context_surface {
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

fn require_exact_nested_keys(
    data: &Map<String, Value>,
    expected: &[&str],
    event: &JournalEvent,
    path: &str,
) -> Result<()> {
    let actual = data.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return session_error(format!(
            "{} at seq {} {path} does not match the required exact key profile",
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

fn valid_surface_identity_v1(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
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

    use crate::compaction::{
        COMPACTION_BOUNDARY_STARTED_KIND, CompactionBoundary, CompactionBoundaryStarted,
    };
    use crate::context::{McpSurfaceBindingV1, McpSurfaceClaimV1, snapshot_tool_surface_v1};
    use crate::types::ToolDefinition;

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
                    "output":{
                        "profile_version":1,
                        "trust":"untrusted_mcp_tool_output",
                        "is_error":false,
                        "content":["hello"]
                    },
                    "mcp_raw_result":{
                        "content":[{"type":"text","text":"hello"}],
                        "isError":false
                    },
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

    fn mcp_events_v3() -> Vec<JournalEvent> {
        let mut events = mcp_events_v2();
        let epoch = events[0].data["registry_epoch_id"]
            .as_str()
            .expect("activation epoch")
            .to_owned();
        let registry_digest = events[0].data["registry_digest"]
            .as_str()
            .expect("activation digest")
            .to_owned();
        let definition = ToolDefinition {
            name: "mcp_fixture_echo_deadbeef".to_owned(),
            description: "MCP tool fixture/echo: echo text".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{"text":{"type":"string"}},
                "required":["text"],
                "additionalProperties":false,
            }),
        };
        let binding = McpSurfaceBindingV1::from_parts(
            definition.name.clone(),
            "fixture",
            "echo",
            "2026-07-28",
            &definition,
            None,
        )
        .expect("surface binding");
        let claim = McpSurfaceClaimV1::new(
            epoch.clone(),
            registry_digest.clone(),
            vec![binding.clone()],
        )
        .expect("surface claim");
        let surface =
            snapshot_tool_surface_v1(&[definition], Some(claim)).expect("tool surface snapshot");
        let surface_digest = surface.digest().to_owned();
        let definition_digest = binding.definition_digest().to_owned();

        let activation = events[0].data.as_object_mut().expect("activation data");
        activation.insert("coordinator_version".to_owned(), Value::from(3));
        activation.insert("call_chain_validator_version".to_owned(), Value::from(3));
        activation.insert("surface_claim_version".to_owned(), Value::from(1));
        activation.insert(
            "bindings".to_owned(),
            json!([{
                "provider_name":binding.provider_name(),
                "server_name":binding.server_name(),
                "raw_tool_name":binding.raw_tool_name(),
                "protocol_version":binding.protocol_version(),
                "definition_digest":binding.definition_digest(),
                "output_schema_digest":Value::Null,
            }]),
        );
        for event in &mut events[1..] {
            event.seq += 1;
            if let Some(provenance) = event.data.get_mut("mcp") {
                provenance["execution_coordinator_version"] = Value::from(3);
                provenance["surface_claim_version"] = Value::from(1);
                provenance["response_attempt_id"] = Value::String("attempt-1".to_owned());
                provenance["response_started_seq"] = Value::from(4);
                provenance["response_completed_seq"] = Value::from(5);
                provenance["surface_event_seq"] = Value::from(2);
                provenance["surface_digest"] = Value::String(surface_digest.clone());
                provenance["definition_digest"] = Value::String(definition_digest.clone());
                provenance["output_schema_digest"] = Value::Null;
            }
        }
        events[5].data["started_seq"] = Value::from(6);
        events[2].data["context"] = json!({"tools_event_seq":2});
        events[2].data["mcp_surface"] = json!({
            "version":MCP_RESPONSE_SURFACE_REFERENCE_VERSION_V1,
            "event_seq":2,
            "digest":surface_digest,
        });
        events.insert(
            1,
            event(
                2,
                None,
                "context.tools",
                serde_json::to_value(&surface).expect("encode surface"),
            ),
        );
        events
    }

    fn mcp_events_v4() -> Vec<JournalEvent> {
        let mut events = mcp_events_v3();
        events[0].data["coordinator_version"] = Value::from(4);
        events[0].data["call_chain_validator_version"] = Value::from(4);
        for event in &mut events[2..] {
            event.seq += 1;
        }
        events.insert(
            2,
            event(
                3,
                None,
                "context.configured",
                json!({
                    "measurement_version":crate::context::CONTEXT_MEASUREMENT_VERSION,
                    "estimator_version":crate::context::CONTEXT_ESTIMATOR_VERSION,
                    "request_shape_version":crate::context::REQUEST_SHAPE_VERSION,
                    "model":"fixture-model",
                    "provider_protocol":PROVIDER_PROTOCOL_OPENAI_RESPONSES,
                    "provider_usage_domain":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "context_window":Value::Null,
                    "reserve_tokens":0,
                    "usable_tokens":Value::Null,
                    "trigger_tokens":Value::Null,
                    "target_tokens":Value::Null,
                    "context_window_source":"fixture",
                    "reserve_tokens_source":"fixture",
                }),
            ),
        );
        events[3].data["item"] = json!({"role":"user","content":"fixture"});
        for event in &mut events[1..] {
            if is_tool_lifecycle(&event.kind) {
                if let Some(provenance) = event.data.get_mut("mcp") {
                    provenance["execution_coordinator_version"] = Value::from(4);
                    provenance["response_started_seq"] = Value::from(5);
                    provenance["response_completed_seq"] = Value::from(6);
                }
            }
        }
        events[7].data["started_seq"] = Value::from(7);
        let surface = ToolSurfaceSnapshotV1::from_exact_journal_value(&events[1].data)
            .expect("parse v4 fixture surface");
        let provider_tools = surface
            .tools()
            .iter()
            .map(|tool| {
                json!({
                    "type":"function",
                    "name":tool.name,
                    "description":tool.description,
                    "parameters":tool.input_schema,
                    "strict":false,
                })
            })
            .collect::<Vec<_>>();
        let request_body = json!({
            "model":"fixture-model",
            "input":[{"role":"user","content":"fixture"}],
            "tools":provider_tools,
            "stream":true,
            "store":false,
            "include":["reasoning.encrypted_content"],
        });
        let request_body_bytes =
            serde_json::to_vec(&request_body).expect("encode v4 fixture request");
        let measurement = measure_exact_prepared_request(&request_body, &request_body_bytes)
            .expect("measure v4 fixture request");
        let request_digest = measurement.request_digest.clone();
        let start = events
            .iter_mut()
            .find(|event| event.kind == "response.started")
            .expect("v4 fixture response start");
        start.data["context"]["request_journal_through_seq"] = Value::from(4);
        start.data["context"]["configured_event_seq"] = Value::from(3);
        start.data["context"]["instructions_event_seq"] = Value::Null;
        start.data["context"]["provider_usage_domain"] = Value::String(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        );
        start.data["context"]["measurement"] =
            serde_json::to_value(measurement).expect("encode v4 fixture measurement");
        start.data["mcp_prepared_request"] = json!({
            "version":MCP_PREPARED_REQUEST_REFERENCE_VERSION_V1,
            "digest":request_digest,
            "body":request_body,
        });
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
    fn valid_mcp_call_chain_v3_binds_exact_provider_surface() {
        let events = mcp_events_v3();
        validate_mcp_call_chain_v3(&events).expect("valid MCP v3 chain");
        let call = validated_durable_mcp_call(&events, "turn-1", "call-1")
            .expect("validated v3 durable call");
        assert_eq!(call.response_attempt_id.as_deref(), Some("attempt-1"));
        let surface = call.surface.expect("validated v3 surface provenance");
        assert_eq!(surface.surface_event_seq, 2);
        assert_eq!(
            surface.surface_digest,
            events[1].data["digest"].as_str().expect("surface digest")
        );
        assert_eq!(
            surface.definition_digest,
            events[0].data["bindings"][0]["definition_digest"]
                .as_str()
                .expect("definition digest")
        );
        assert_eq!(surface.output_schema_digest, None);
        validate_mcp_call_chain_through_version(3, &events)
            .expect("v3 ceiling accepts exact surface reader");
        let error = validate_mcp_call_chain_through_version(2, &events)
            .expect_err("v2 compatibility ceiling must reject v3")
            .to_string();
        assert!(error.contains("exceeds compatibility ceiling 2"), "{error}");
    }

    #[test]
    fn valid_mcp_call_chain_v4_binds_prepared_request_digest() {
        let events = mcp_events_v4();
        validate_mcp_call_chain_v4(&events).expect("valid MCP v4 chain");
        validate_mcp_call_chain_through_version(4, &events)
            .expect("v4 ceiling accepts prepared-request reader");
        let error = validate_mcp_call_chain_through_version(3, &events)
            .expect_err("v3 compatibility ceiling must reject v4")
            .to_string();
        assert!(error.contains("exceeds compatibility ceiling 3"), "{error}");

        let call = validated_durable_mcp_call(&events, "turn-1", "call-1")
            .expect("validated v4 durable call");
        assert_eq!(call.response_attempt_id.as_deref(), Some("attempt-1"));
        let surface = call.surface.expect("validated v4 surface provenance");
        assert_eq!(surface.surface_event_seq, 2);
        assert_eq!(
            surface.surface_digest,
            events[1].data["digest"].as_str().expect("surface digest")
        );
    }

    #[test]
    fn v4_projection_reentry_through_current_compaction_boundary_is_bounded() {
        let mut events = mcp_events_v4();
        for event in events.iter_mut().filter(|event| event.seq >= 5) {
            event.seq += 1;
            if let Some(provenance) = event.data.get_mut("mcp") {
                provenance["response_started_seq"] = Value::from(6);
                provenance["response_completed_seq"] = Value::from(7);
            }
        }
        let terminal = events
            .iter_mut()
            .find(|event| event.kind == "tool.completed")
            .expect("fixture terminal");
        terminal.data["started_seq"] = Value::from(8);
        let start = events
            .iter_mut()
            .find(|event| event.kind == "response.started")
            .expect("fixture start");
        start.data["context"]["request_journal_through_seq"] = Value::from(5);
        events.insert(
            4,
            event(
                5,
                None,
                COMPACTION_BOUNDARY_STARTED_KIND,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: CompactionBoundary::new("boundary-v4", "turn-1", 4),
                    trigger: "context_trigger".to_owned(),
                    extra: Map::new(),
                })
                .expect("encode v4 compaction boundary"),
            ),
        );

        let error = validate_mcp_call_chain_v4(&events)
            .expect_err("pending compaction boundary must reject ordinary Provider dispatch");
        assert!(
            error.to_string().contains("compaction") || error.to_string().contains("boundary"),
            "projection recursion must terminate at the deterministic boundary error: {error}"
        );
    }

    #[test]
    fn nested_v4_projection_scope_still_validates_core_provenance() {
        let _scope = McpV4ProjectionScope::enter().expect("enter outer projection scope");
        let mut events = mcp_events_v4();
        let lifecycle = events
            .iter_mut()
            .find(|event| event.kind == "tool.started")
            .expect("fixture lifecycle");
        lifecycle.data["mcp"]["registry_digest"] = Value::String("f".repeat(64));
        validate_mcp_call_chain_v4(&events)
            .expect_err("nested projection scope may not suppress MCP core validation");
    }

    #[test]
    fn v4_projection_budget_fails_before_counter_overflow_or_unbounded_work() {
        let mut budget = McpV4ProjectionBudget::default();
        budget
            .charge(
                MAX_MCP_V4_PROJECTION_PREFIX_EVENT_VISITS,
                MAX_MCP_V4_PROJECTION_PREFIX_BYTES,
            )
            .expect("exact frozen projection budget");
        budget
            .charge(1, 0)
            .expect_err("projection event work above the frozen budget must fail closed");
    }

    #[test]
    fn v4_activation_profile_is_exact_and_does_not_change_the_current_writer() {
        assert_eq!(MCP_CALL_CHAIN_VALIDATOR_VERSION, 4);

        let mut wrong_coordinator = mcp_events_v4();
        wrong_coordinator[0].data["coordinator_version"] = Value::from(3);
        validate_mcp_call_chain_v4(&wrong_coordinator)
            .expect_err("v4 activation requires coordinator v4");

        let mut wrong_call_chain = mcp_events_v4();
        wrong_call_chain[0].data["call_chain_validator_version"] = Value::from(3);
        validate_mcp_call_chain_v4(&wrong_call_chain)
            .expect_err("v4 activation requires call-chain v4");

        let mut missing_surface_profile = mcp_events_v4();
        missing_surface_profile[0]
            .data
            .as_object_mut()
            .expect("activation data")
            .remove("surface_claim_version");
        validate_mcp_call_chain_v4(&missing_surface_profile)
            .expect_err("v4 activation requires the surface claim profile");

        let mut unknown_activation_field = mcp_events_v4();
        unknown_activation_field[0].data["unexpected"] = Value::Bool(true);
        validate_mcp_call_chain_v4(&unknown_activation_field)
            .expect_err("v4 activation rejects unknown fields");
    }

    #[test]
    fn v4_prepared_request_reference_mutations_fail_closed() {
        let assert_rejected = |name: &str, events: Vec<JournalEvent>| {
            assert!(
                validate_mcp_call_chain_v4(&events).is_err(),
                "{name} must fail closed"
            );
        };
        let start_index = |events: &[JournalEvent]| {
            events
                .iter()
                .position(|event| event.kind == "response.started")
                .expect("fixture response start")
        };

        let mut missing = mcp_events_v4();
        let index = start_index(&missing);
        missing[index]
            .data
            .as_object_mut()
            .expect("start data")
            .remove("mcp_prepared_request");
        assert_rejected("missing prepared request reference", missing);

        let mut wrong_version = mcp_events_v4();
        let index = start_index(&wrong_version);
        wrong_version[index].data["mcp_prepared_request"]["version"] = Value::from(2);
        assert_rejected("wrong prepared request reference version", wrong_version);

        let mut unknown_field = mcp_events_v4();
        let index = start_index(&unknown_field);
        unknown_field[index].data["mcp_prepared_request"]["unexpected"] = Value::Bool(true);
        assert_rejected("unknown prepared request reference field", unknown_field);

        let mut invalid_digest = mcp_events_v4();
        let index = start_index(&invalid_digest);
        invalid_digest[index].data["mcp_prepared_request"]["digest"] =
            Value::String("not-a-sha256".to_owned());
        assert_rejected("invalid prepared request reference digest", invalid_digest);

        let mut missing_body = mcp_events_v4();
        let index = start_index(&missing_body);
        missing_body[index].data["mcp_prepared_request"]
            .as_object_mut()
            .expect("prepared request reference")
            .remove("body");
        assert_rejected("missing canonical prepared request body", missing_body);

        let mut mutated_body = mcp_events_v4();
        let index = start_index(&mutated_body);
        mutated_body[index].data["mcp_prepared_request"]["body"]["model"] =
            Value::String("mutated-model".to_owned());
        assert_rejected("prepared request body mutation", mutated_body);

        let mut self_certifying_digests = mcp_events_v4();
        let index = start_index(&self_certifying_digests);
        self_certifying_digests[index].data["mcp_prepared_request"]["body"]["model"] =
            Value::String("mutated-model".to_owned());
        self_certifying_digests[index].data["mcp_prepared_request"]["digest"] =
            Value::String("b".repeat(64));
        self_certifying_digests[index].data["context"]["measurement"]["request_digest"] =
            Value::String("b".repeat(64));
        assert_rejected(
            "matching attacker-controlled digests without the canonical body hash",
            self_certifying_digests,
        );

        let mut self_consistent_forgery = mcp_events_v4();
        let index = start_index(&self_consistent_forgery);
        self_consistent_forgery[index].data["mcp_prepared_request"]["body"]["input"] =
            json!([{"role":"user","content":"forged input"}]);
        let forged_body =
            self_consistent_forgery[index].data["mcp_prepared_request"]["body"].clone();
        let forged_bytes = serde_json::to_vec(&forged_body).expect("encode forged request body");
        let forged_measurement = measure_exact_prepared_request(&forged_body, &forged_bytes)
            .expect("measure forged request body");
        self_consistent_forgery[index].data["mcp_prepared_request"]["digest"] =
            Value::String(forged_measurement.request_digest.clone());
        self_consistent_forgery[index].data["context"]["measurement"] =
            serde_json::to_value(forged_measurement).expect("encode forged measurement");
        assert_rejected(
            "self-consistent request body not anchored in the journal projection",
            self_consistent_forgery,
        );

        let mut stale_cutoff = mcp_events_v4();
        let index = start_index(&stale_cutoff);
        stale_cutoff[index].data["context"]["request_journal_through_seq"] = Value::from(3);
        stale_cutoff[index].data["mcp_prepared_request"]["body"]["input"] = json!([]);
        let stale_body = stale_cutoff[index].data["mcp_prepared_request"]["body"].clone();
        let stale_bytes = serde_json::to_vec(&stale_body).expect("encode stale-cutoff body");
        let stale_measurement = measure_exact_prepared_request(&stale_body, &stale_bytes)
            .expect("measure stale-cutoff body");
        stale_cutoff[index].data["mcp_prepared_request"]["digest"] =
            Value::String(stale_measurement.request_digest.clone());
        stale_cutoff[index].data["context"]["measurement"] =
            serde_json::to_value(stale_measurement).expect("encode stale-cutoff measurement");
        assert_rejected(
            "self-consistent request may not omit durable events before response.started",
            stale_cutoff,
        );

        let mut mismatched_digest = mcp_events_v4();
        let index = start_index(&mismatched_digest);
        mismatched_digest[index].data["mcp_prepared_request"]["digest"] =
            Value::String("b".repeat(64));
        assert_rejected("mismatched prepared request digest", mismatched_digest);

        let mut missing_measurement = mcp_events_v4();
        let index = start_index(&missing_measurement);
        missing_measurement[index].data["context"]
            .as_object_mut()
            .expect("context")
            .remove("measurement");
        assert_rejected("missing context measurement", missing_measurement);

        let mut invalid_measurement_digest = mcp_events_v4();
        let index = start_index(&invalid_measurement_digest);
        invalid_measurement_digest[index].data["context"]["measurement"]["request_digest"] =
            Value::String("invalid".to_owned());
        assert_rejected(
            "invalid context measurement request digest",
            invalid_measurement_digest,
        );

        for field in [
            "measurement_version",
            "estimator_version",
            "request_shape_version",
            "estimated_input_tokens",
            "serialized_request_bytes",
        ] {
            let mut mismatched_measurement = mcp_events_v4();
            let index = start_index(&mismatched_measurement);
            let value = mismatched_measurement[index].data["context"]["measurement"][field]
                .as_u64()
                .expect("numeric prepared-request measurement field");
            mismatched_measurement[index].data["context"]["measurement"][field] =
                Value::from(value + 1);
            assert_rejected(
                &format!("mismatched context measurement field {field}"),
                mismatched_measurement,
            );
        }

        let mut unknown_measurement_field = mcp_events_v4();
        let index = start_index(&unknown_measurement_field);
        unknown_measurement_field[index].data["context"]["measurement"]["unexpected"] =
            Value::Bool(true);
        assert_rejected(
            "unknown context measurement field",
            unknown_measurement_field,
        );
    }

    #[test]
    fn v3_surface_relation_mutations_fail_closed() {
        let assert_rejected = |name: &str, events: Vec<JournalEvent>| {
            assert!(
                validate_mcp_call_chain_v3(&events).is_err(),
                "{name} must fail closed"
            );
        };

        let mut missing_reference = mcp_events_v3();
        missing_reference[3]
            .data
            .as_object_mut()
            .unwrap()
            .remove("mcp_surface");
        assert_rejected("missing surface reference", missing_reference);

        let mut partial_registry = mcp_events_v3();
        partial_registry[3]
            .data
            .as_object_mut()
            .unwrap()
            .remove("mcp_registry_digest");
        assert_rejected("partial registry claim", partial_registry);

        let mut wrong_digest = mcp_events_v3();
        wrong_digest[3].data["mcp_surface"]["digest"] = Value::String("d".repeat(64));
        assert_rejected("wrong surface digest", wrong_digest);

        let mut wrong_kind = mcp_events_v3();
        wrong_kind[1].kind = "context.instructions".to_owned();
        assert_rejected("wrong referenced event kind", wrong_kind);

        let mut turn_scoped = mcp_events_v3();
        turn_scoped[1].turn_id = Some("turn-1".to_owned());
        assert_rejected("turn-scoped surface event", turn_scoped);

        let mut unknown_surface_field = mcp_events_v3();
        unknown_surface_field[1].data["unexpected"] = Value::Bool(true);
        assert_rejected("unknown surface field", unknown_surface_field);

        let mut definition_drift = mcp_events_v3();
        definition_drift[0].data["bindings"][0]["definition_digest"] =
            Value::String("d".repeat(64));
        assert_rejected("definition digest drift", definition_drift);

        let mut output_schema_drift = mcp_events_v3();
        output_schema_drift[0].data["bindings"][0]["output_schema_digest"] =
            Value::String("d".repeat(64));
        assert_rejected("output schema digest drift", output_schema_drift);

        let mut duplicate_seq = mcp_events_v3();
        duplicate_seq.insert(2, duplicate_seq[1].clone());
        assert_rejected("duplicate referenced seq", duplicate_seq);

        let mut split_reference = mcp_events_v3();
        for event in &mut split_reference[2..] {
            event.seq += 1;
        }
        split_reference[6].data["started_seq"] = Value::from(7);
        let mut second_surface = split_reference[1].clone();
        second_surface.seq = 3;
        split_reference.insert(2, second_surface);
        split_reference[4].data["context"]["tools_event_seq"] = Value::from(3);
        assert_rejected(
            "surface reference split from request context",
            split_reference,
        );
    }

    #[test]
    fn v3_lifecycle_provenance_binds_exact_response_and_surface() {
        let assert_mutation_rejected = |name: &str, field: &str, value: Value| {
            let mut events = mcp_events_v3();
            for event in events
                .iter_mut()
                .filter(|event| matches!(event.kind.as_str(), "tool.started" | "tool.completed"))
            {
                event.data["mcp"][field] = value.clone();
            }
            assert!(
                validate_mcp_call_chain_v3(&events).is_err(),
                "{name} must fail closed"
            );
        };

        for (name, field, value) in [
            (
                "response attempt drift",
                "response_attempt_id",
                Value::String("attempt-other".to_owned()),
            ),
            (
                "response start drift",
                "response_started_seq",
                Value::from(3),
            ),
            (
                "response completion drift",
                "response_completed_seq",
                Value::from(4),
            ),
            ("surface event drift", "surface_event_seq", Value::from(3)),
            (
                "surface digest drift",
                "surface_digest",
                Value::String("d".repeat(64)),
            ),
            (
                "definition digest drift",
                "definition_digest",
                Value::String("d".repeat(64)),
            ),
            (
                "output schema digest drift",
                "output_schema_digest",
                Value::String("d".repeat(64)),
            ),
            (
                "surface claim version drift",
                "surface_claim_version",
                Value::from(2),
            ),
        ] {
            assert_mutation_rejected(name, field, value);
        }

        let mut missing_field = mcp_events_v3();
        for event in missing_field
            .iter_mut()
            .filter(|event| matches!(event.kind.as_str(), "tool.started" | "tool.completed"))
        {
            event.data["mcp"]
                .as_object_mut()
                .expect("provenance object")
                .remove("definition_digest");
        }
        validate_mcp_call_chain_v3(&missing_field)
            .expect_err("v3 lifecycle provenance has an exact required key profile");

        let mut unknown_field = mcp_events_v3();
        for event in unknown_field
            .iter_mut()
            .filter(|event| matches!(event.kind.as_str(), "tool.started" | "tool.completed"))
        {
            event.data["mcp"]["unexpected"] = Value::Bool(true);
        }
        validate_mcp_call_chain_v3(&unknown_field)
            .expect_err("v3 lifecycle provenance rejects unknown fields");

        let mut outer_authority = mcp_events_v3();
        outer_authority[5].data["surface_digest"] = Value::String("d".repeat(64));
        validate_mcp_call_chain_v3(&outer_authority)
            .expect_err("tool.started rejects a second outer surface authority");

        let mut contradictory_terminal = mcp_events_v3();
        contradictory_terminal[6].data["before_dispatch"] = Value::Bool(true);
        validate_mcp_call_chain_v3(&contradictory_terminal)
            .expect_err("completed result cannot claim it was before dispatch");
    }

    #[test]
    fn v3_completed_result_rederives_the_model_envelope_from_raw() {
        let assert_rejected = |name: &str, mutate: &mut dyn FnMut(&mut Value)| {
            let mut events = mcp_events_v3();
            mutate(&mut events[6].data);
            assert!(
                validate_mcp_call_chain_v3(&events).is_err(),
                "{name} must fail closed"
            );
        };

        let mut raw_content = |data: &mut Value| {
            data["mcp_raw_result"]["content"][0]["text"] = Value::String("drift".to_owned());
        };
        assert_rejected("raw content drift", &mut raw_content);

        let mut model_content = |data: &mut Value| {
            data["output"]["content"][0] = Value::String("drift".to_owned());
        };
        assert_rejected("model content drift", &mut model_content);

        let mut trusted = |data: &mut Value| {
            data["output"]["trust"] = Value::String("trusted".to_owned());
        };
        assert_rejected("trusted output label", &mut trusted);

        let mut profile = |data: &mut Value| {
            data["output"]["profile_version"] = Value::from(2);
        };
        assert_rejected("future output profile", &mut profile);

        let mut polarity = |data: &mut Value| {
            data["mcp_raw_result"]["isError"] = Value::Bool(true);
        };
        assert_rejected("raw error polarity drift", &mut polarity);

        let mut code = |data: &mut Value| {
            data["error_code"] = Value::String("other_error".to_owned());
        };
        assert_rejected("error code drift", &mut code);

        let mut unknown_output = |data: &mut Value| {
            data["output"]["unexpected"] = Value::Bool(true);
        };
        assert_rejected("unknown model output field", &mut unknown_output);
    }

    #[test]
    fn v3_completed_result_checks_tree_and_bytes_before_owned_projection() {
        let mut oversized_raw = mcp_events_v3();
        oversized_raw[6].data["mcp_raw_result"]["_meta"] = json!({
            "padding":"x".repeat(crate::mcp::MAX_MCP_RAW_RESULT_BYTES_V1)
        });
        let error = validate_mcp_call_chain_v3(&oversized_raw)
            .expect_err("oversized raw result must fail before projection")
            .to_string();
        assert!(
            error.contains("raw MCP result"),
            "unexpected error: {error}"
        );
        assert!(error.contains("byte bound"), "unexpected error: {error}");

        let mut oversized_model = mcp_events_v3();
        oversized_model[6].data["output"]["content"] =
            json!(["x".repeat(crate::mcp::MAX_MCP_MODEL_OUTPUT_BYTES_V1)]);
        let error = validate_mcp_call_chain_v3(&oversized_model)
            .expect_err("oversized model output must fail before typed clone")
            .to_string();
        assert!(error.contains("model output"), "unexpected error: {error}");
        assert!(error.contains("byte bound"), "unexpected error: {error}");

        let mut too_wide = mcp_events_v3();
        too_wide[6].data["mcp_raw_result"]["_meta"] =
            Value::Array((0..16_384).map(|_| Value::Array(Vec::new())).collect());
        let error = validate_mcp_call_chain_v3(&too_wide)
            .expect_err("raw result must share the frozen v1 tree profile")
            .to_string();
        assert!(error.contains("node budget"), "unexpected error: {error}");
    }

    #[test]
    fn v3_post_start_rawless_completion_is_only_a_known_error() {
        let mut known_error = mcp_events_v3();
        let data = known_error[6]
            .data
            .as_object_mut()
            .expect("terminal object");
        data.remove("mcp_raw_result");
        data["output"] = json!({
            "error":{"code":"transport_closed","message":"server stream is closed"}
        });
        data["is_error"] = Value::Bool(true);
        data["error_code"] = Value::String("transport_closed".to_owned());
        validate_mcp_call_chain_v3(&known_error)
            .expect("bounded post-dispatch coordination errors remain readable");

        let mut rawless_success = mcp_events_v3();
        let data = rawless_success[6]
            .data
            .as_object_mut()
            .expect("terminal object");
        data.remove("mcp_raw_result");
        validate_mcp_call_chain_v3(&rawless_success)
            .expect_err("raw-less success cannot claim a validated MCP result");

        for forbidden_code in [
            "in_doubt",
            "mcp_tool_error",
            "cancelled",
            "approval_required",
            "future_error",
        ] {
            let mut forged = mcp_events_v3();
            let data = forged[6].data.as_object_mut().expect("terminal object");
            data.remove("mcp_raw_result");
            data["output"] = json!({
                "error":{"code":forbidden_code,"message":"bounded"}
            });
            data["is_error"] = Value::Bool(true);
            data["error_code"] = Value::String(forbidden_code.to_owned());
            validate_mcp_call_chain_v3(&forged)
                .expect_err("raw-less terminal code must be closed-world validated");
        }

        for unsafe_message in [
            "unsafe\u{202e}bidi",
            "unsafe\u{200b}zero-width",
            "unsafe\u{2028}line-separator",
            "unsafe\u{2029}paragraph-separator",
            "unsafe\nnewline",
        ] {
            let mut forged = mcp_events_v3();
            let data = forged[6].data.as_object_mut().expect("terminal object");
            data.remove("mcp_raw_result");
            data["output"] = json!({
                "error":{"code":"transport_closed","message":unsafe_message}
            });
            data["is_error"] = Value::Bool(true);
            data["error_code"] = Value::String("transport_closed".to_owned());
            validate_mcp_call_chain_v3(&forged)
                .expect_err("raw-less terminal message must use the safe single-line profile");
        }
    }

    #[test]
    fn v3_pre_start_terminal_carries_surface_bound_authority() {
        let mut events = mcp_events_v3();
        let mut provenance = events[5].data["mcp"].clone();
        let provenance = provenance.as_object_mut().expect("provenance object");
        provenance.remove("dispatch_permit_version");
        provenance.remove("server_attempt_id");
        let provenance = Value::Object(provenance.clone());
        let registry_epoch_id = events[0].data["registry_epoch_id"].clone();
        let registry_digest = events[0].data["registry_digest"].clone();
        events.truncate(5);
        events.push(event(
            6,
            Some("turn-1"),
            "tool.completed",
            json!({
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "output":{"error":{"code":"approval_required","message":"not approved"}},
                "is_error":true,
                "error_code":"approval_required",
                "mcp_execution_coordinator_version":3,
                "registry_epoch_id":registry_epoch_id,
                "registry_digest":registry_digest,
                "mcp":provenance,
            }),
        ));
        validate_mcp_call_chain_v3(&events)
            .expect("pre-start v3 authority binds the exact durable call and surface");

        events[5].data["mcp"]["surface_digest"] = Value::String("d".repeat(64));
        validate_mcp_call_chain_v3(&events)
            .expect_err("pre-start lifecycle cannot drift from its owned surface");
    }

    #[test]
    fn v3_resolution_and_recovery_edges_reject_injected_surface_authority() {
        let mut resolved = mcp_events_v3();
        resolved[6].kind = "tool.in_doubt".to_owned();
        resolved[6].data["output"] =
            json!({"error":{"code":"in_doubt","message":"result was not validated"}});
        resolved[6]
            .data
            .as_object_mut()
            .expect("terminal object")
            .remove("mcp_raw_result");
        resolved[6].data["is_error"] = Value::Bool(true);
        resolved[6].data["error_code"] = Value::String("in_doubt".to_owned());
        resolved.push(event(
            8,
            Some("turn-1"),
            "tool.in_doubt_resolved",
            json!({
                "started_seq":6,
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "output":{"error":{"code":"in_doubt","message":"user treated as failed"}},
                "is_error":true,
                "error_code":"in_doubt",
                "resolution":"user_treated_as_failed",
            }),
        ));
        validate_mcp_call_chain_v3(&resolved).expect("canonical v3 resolution edge");
        resolved[7].data["mcp"] = resolved[5].data["mcp"].clone();
        validate_mcp_call_chain_v3(&resolved)
            .expect_err("resolution cannot introduce a second surface authority");

        let mut recovered = mcp_events_v3();
        recovered.truncate(5);
        let arguments = json!({"text":"hello"});
        recovered.push(event(
            6,
            None,
            crate::session::RECOVERY_KIND,
            json!({
                "skipped_before_start":1,
                "tool_skip_authorization_version":1,
                "unstarted_tool_calls":[{
                    "response_seq":5,
                    "turn_id":"turn-1",
                    "call_id":"call-1",
                    "tool":"mcp_fixture_echo_deadbeef",
                    "arguments_sha256":argument_digest_v1(&arguments).expect("argument digest"),
                }],
            }),
        ));
        recovered.push(event(
            7,
            Some("turn-1"),
            "tool.skipped_due_to_recovery",
            json!({
                "response_seq":5,
                "call_id":"call-1",
                "tool":"mcp_fixture_echo_deadbeef",
                "arguments":arguments,
                "reason":"process stopped before tool.started was committed",
                "output":{"error":{"code":"interrupted_before_start","message":"not dispatched"}},
                "is_error":true,
                "error_code":"interrupted_before_start",
                "recovery_marker_seq":6,
            }),
        ));
        validate_mcp_call_chain_v3(&recovered).expect("canonical v3 recovery skip");
        recovered[6].data["mcp"] = mcp_events_v3()[5].data["mcp"].clone();
        validate_mcp_call_chain_v3(&recovered)
            .expect_err("recovery skip cannot introduce a second surface authority");
    }

    #[test]
    fn v3_surface_ownership_cannot_be_downgraded_by_deleting_claims() {
        let mut claimed_surface = mcp_events_v3();
        for field in [
            "mcp_registry_epoch_id",
            "mcp_registry_digest",
            "mcp_surface",
        ] {
            claimed_surface[3]
                .data
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        validate_mcp_call_chain_v3(&claimed_surface)
            .expect_err("an MCP context.tools snapshot owns the response even without flat claims");

        let mut alias_only = mcp_events_v3();
        let generic_definition = ToolDefinition {
            name: "read".to_owned(),
            description: "builtin read".to_owned(),
            input_schema: json!({"type":"object"}),
        };
        alias_only[1].data = serde_json::to_value(
            crate::context::snapshot_tools(&[generic_definition]).expect("generic snapshot"),
        )
        .expect("encode generic snapshot");
        for field in [
            "mcp_registry_epoch_id",
            "mcp_registry_digest",
            "mcp_surface",
        ] {
            alias_only[3].data.as_object_mut().unwrap().remove(field);
        }
        let error = validate_mcp_call_chain_v3(&alias_only)
            .expect_err("an activated alias cannot be projected from a generic surface")
            .to_string();
        assert!(error.contains("has no MCP surface claim"), "{error}");

        let mut failed = mcp_events_v3();
        failed.truncate(4);
        failed[1].data = alias_only[1].data.clone();
        for field in [
            "mcp_registry_epoch_id",
            "mcp_registry_digest",
            "mcp_surface",
        ] {
            failed[3].data.as_object_mut().unwrap().remove(field);
        }
        failed.push(event(
            5,
            Some("turn-1"),
            "response.failed",
            json!({"response_attempt_id":"attempt-1","error":"provider failed"}),
        ));
        validate_mcp_call_chain_v3(&failed)
            .expect_err("failed responses cannot downgrade by deleting all surface evidence");
    }

    #[test]
    fn v3_multiple_attempts_can_share_one_validated_surface_event() {
        let mut events = mcp_events_v3();
        let mut second_start = events[3].clone();
        second_start.seq = 8;
        second_start.turn_id = Some("turn-2".to_owned());
        second_start.data["response_attempt_id"] = Value::String("attempt-2".to_owned());
        events.push(second_start);
        events.push(event(
            9,
            Some("turn-2"),
            "response.failed",
            json!({"response_attempt_id":"attempt-2","error":"provider failed"}),
        ));

        validate_mcp_call_chain_v3(&events).expect("shared surface reference remains valid");
        assert_eq!(
            mcp_turn_ids(&events).expect("owned v3 turns"),
            vec!["turn-1", "turn-2"]
        );
    }

    #[test]
    fn v3_orphan_surface_markers_are_rejected_without_activation() {
        let mut events = mcp_events_v3();
        events.remove(0);
        validate_mcp_call_chain_v3(&events)
            .expect_err("surface claims without activation must fail closed");
        validate_mcp_call_chain_through_version(3, &events)
            .expect_err("ceiling-based v3 readers must reject orphan surface claims too");
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
    fn response_status_writer_matches_the_frozen_validator_limit() {
        let exact =
            response_status_text_for_journal(&"x".repeat(MAX_RESPONSE_STATUS_TEXT_BYTES_V2));
        assert_eq!(exact.len(), MAX_RESPONSE_STATUS_TEXT_BYTES_V2);
        let oversized =
            response_status_text_for_journal(&"x".repeat(MAX_RESPONSE_STATUS_TEXT_BYTES_V2 + 1));
        assert!(oversized.len() <= MAX_RESPONSE_STATUS_TEXT_BYTES_V2);
        assert!(oversized.ends_with("<truncated>"));

        let mut events = mcp_events_v2();
        events.truncate(3);
        events.push(event(
            4,
            Some("turn-1"),
            "response.failed",
            json!({
                "response_attempt_id":"attempt-1",
                "error":oversized,
            }),
        ));
        validate_mcp_call_chain_v2(&events)
            .expect("the shared writer projection must be accepted by the frozen validator");
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

        for invalid_turn_id in [String::new(), "turn\u{0001}".to_owned(), "x".repeat(129)] {
            let mut events = mcp_events_v2();
            events[2].turn_id = Some(invalid_turn_id);
            let error = validate_mcp_call_chain_v2(&events)
                .expect_err("claimed response.started must carry a valid turn_id")
                .to_string();
            assert!(
                error.contains("no valid turn_id"),
                "unexpected error: {error}"
            );
        }
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
