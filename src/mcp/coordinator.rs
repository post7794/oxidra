use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::journal::{
    MAX_MCP_CALLS_PER_RESPONSE, MCP_CALL_CHAIN_VALIDATOR_VERSION_V1,
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V2, MCP_CALL_CHAIN_VALIDATOR_VERSION_V4,
    ValidatedDurableMcpCall, argument_digest_v1, ensure_no_unstarted_mcp_calls,
    validate_mcp_call_chain, validated_durable_mcp_call,
};
use super::registry::{
    ApprovedMcpRegistry, ApprovedMcpResumeRegistry, McpRegistry, PreparedMcpRegistryCall,
};
use super::{
    MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1, MAX_MCP_PROVIDER_START_EVENT_BYTES_V1, McpCallError,
    McpModelOutputV1, PreflightedJsonValue, TransportAbortHandle, drop_json_value_iteratively,
    preflight_mcp_provider_event_tree_v1,
};
use crate::compaction::validate_compaction_boundary_chain;
use crate::context::{
    MCP_SURFACE_CLAIM_VERSION_V1, McpSurfaceClaimV1, PROVIDER_PROTOCOL_OPENAI_RESPONSES,
    TOOL_SURFACE_MAX_TOOLS_V1, ToolSurfaceSnapshotV1, measure_provider_prepared_request,
    snapshot_tool_surface_v1,
};
use crate::error::{OxidraError, Result};
use crate::projection::validate_response_output_items;
use crate::provider::{
    MAX_PROVIDER_RESPONSE_ARGUMENT_BYTES_V1, MAX_RESPONSE_RETAINED_NODES_V1, McpExactWireProvider,
    OwnedAssistantTurnV1, PreparedResponseRequest, ProviderEvent, ResponseRequest, StreamObserver,
    prepared_request_body,
};
use crate::session::{
    DispatchAdmissionErrorV1, DurableOutcomeCommitErrorV1, JOURNAL_SCHEMA, JournalEvent,
    McpToolDispatchAdmissionV1, ProviderResponseDispatchAdmissionV1, SessionExecutionLeaseV1,
    SessionJournal, TurnTransactionAdmissionV1,
};
use crate::turn::{ProviderRequestSlotState, provider_request_slot_state_for_version};
use crate::types::{AssistantTurn, ToolCall, ToolDefinition, ToolResult, Usage};

const MCP_EXECUTION_COORDINATOR_VERSION_V1: u32 = 1;
const MCP_EXECUTION_COORDINATOR_VERSION_V2: u32 = 2;
const MCP_EXECUTION_COORDINATOR_VERSION_V4: u32 = 4;
const MCP_DISPATCH_PERMIT_VERSION_V1: u32 = 1;
const MCP_ARGUMENT_DIGEST_VERSION_V1: u32 = 1;
const MCP_TOOL_REGISTRY_VERSION_V1: u32 = 1;
const MCP_STDIO_KERNEL_VERSION_V1: u32 = 1;
const MCP_SCHEMA_PROFILE_VERSION_V1: u32 = 1;
const MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1: u32 = 2;
const MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V4: u32 = 5;
const MAX_MCP_PREPARED_PROVIDER_INPUT_ITEMS_V1: usize = 16_384;
const MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1: usize = 8 * 1024 * 1024;

pub const MCP_EXECUTION_COORDINATOR_VERSION: u32 = MCP_EXECUTION_COORDINATOR_VERSION_V4;
pub const MCP_DISPATCH_PERMIT_VERSION: u32 = MCP_DISPATCH_PERMIT_VERSION_V1;
pub const MCP_ARGUMENT_DIGEST_VERSION: u32 = MCP_ARGUMENT_DIGEST_VERSION_V1;

const MCP_REGISTRY_ACTIVATED_KIND: &str = "mcp.registry.activated";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct McpCoordinatorPolicy {
    coordinator_version: u32,
    call_chain_validator_version: u32,
    dispatch_permit_version: u32,
    argument_digest_version: u32,
    registry_version: u32,
    stdio_kernel_version: u32,
    schema_profile_version: u32,
    provider_slot_version: u32,
}

const MCP_COORDINATOR_POLICY_V1: McpCoordinatorPolicy = McpCoordinatorPolicy {
    coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V1,
    call_chain_validator_version: MCP_CALL_CHAIN_VALIDATOR_VERSION_V1,
    dispatch_permit_version: MCP_DISPATCH_PERMIT_VERSION_V1,
    argument_digest_version: MCP_ARGUMENT_DIGEST_VERSION_V1,
    registry_version: MCP_TOOL_REGISTRY_VERSION_V1,
    stdio_kernel_version: MCP_STDIO_KERNEL_VERSION_V1,
    schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1,
    provider_slot_version: MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1,
};

const MCP_COORDINATOR_POLICY_V2: McpCoordinatorPolicy = McpCoordinatorPolicy {
    coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V2,
    call_chain_validator_version: MCP_CALL_CHAIN_VALIDATOR_VERSION_V2,
    dispatch_permit_version: MCP_DISPATCH_PERMIT_VERSION_V1,
    argument_digest_version: MCP_ARGUMENT_DIGEST_VERSION_V1,
    registry_version: MCP_TOOL_REGISTRY_VERSION_V1,
    stdio_kernel_version: MCP_STDIO_KERNEL_VERSION_V1,
    schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1,
    provider_slot_version: MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1,
};

const MCP_COORDINATOR_POLICY_V4: McpCoordinatorPolicy = McpCoordinatorPolicy {
    coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V4,
    call_chain_validator_version: MCP_CALL_CHAIN_VALIDATOR_VERSION_V4,
    dispatch_permit_version: MCP_DISPATCH_PERMIT_VERSION_V1,
    argument_digest_version: MCP_ARGUMENT_DIGEST_VERSION_V1,
    registry_version: MCP_TOOL_REGISTRY_VERSION_V1,
    stdio_kernel_version: MCP_STDIO_KERNEL_VERSION_V1,
    schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1,
    provider_slot_version: MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V4,
};

/// Pre-start approval view of one durable MCP call.
///
/// The subject is generated by the coordinator and is intentionally opaque.
/// Provider-controlled identities, binding names, and deterministic argument
/// digests are absent because each can otherwise become a covert pre-start
/// argument channel.
///
/// ```compile_fail
/// fn copy_provider_call_id(request: &oxidra::mcp::McpCallApprovalRequest) {
///     let _call_id = request.call_id.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn copy_argument_digest(request: &oxidra::mcp::McpCallApprovalRequest) {
///     let _digest = request.arguments_sha256.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn copy_wire_arguments(request: &oxidra::mcp::McpCallApprovalRequest) {
///     let _wire = request.arguments_json.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn copy_display_arguments(request: &oxidra::mcp::McpCallApprovalRequest) {
///     let _display = request.arguments_display.clone();
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpCallApprovalRequest {
    /// Random, single-call display/policy subject minted by the live
    /// coordinator. It does not encode any Provider-controlled bytes and is
    /// not accepted as execution authority by any public API.
    pub approval_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct McpCallApprovalContext {
    request: McpCallApprovalRequest,
    execution_coordinator_version: u32,
    turn_id: String,
    call_id: String,
    provider_name: String,
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
    registry_epoch_id: String,
    registry_digest: String,
    execution_plan_digest: String,
    server_attempt_id: String,
    arguments_sha256: String,
    durable_provenance_v4: Option<McpDurableCallProvenanceV4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct McpDurableCallProvenanceV4 {
    response_attempt_id: String,
    response_started_seq: u64,
    response_completed_seq: u64,
    surface_event_seq: u64,
    surface_digest: String,
    definition_digest: String,
    output_schema_digest: Option<String>,
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
    arguments_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpCallIdentity<'a> {
    pub turn_id: &'a str,
    pub call_id: &'a str,
    pub provider_name: &'a str,
}

impl<'a> McpCallIdentity<'a> {
    pub fn new(turn_id: &'a str, call_id: &'a str, provider_name: &'a str) -> Self {
        Self {
            turn_id,
            call_id,
            provider_name,
        }
    }
}

pub(crate) mod mcp_call_approval_handler_sealed {
    pub trait Sealed {}
}

#[allow(private_bounds)]
#[async_trait]
/// Fixed-policy approval boundary for one exact durable MCP call.
///
/// This trait is sealed: external code cannot install a pre-`tool.started`
/// callback, even one that attempts to recover arguments from the journal or
/// captured state. Public callers select [`AllowMcpCallApproval`] or
/// [`DenyMcpCallApproval`]. Argument-aware or interactive approval requires a
/// separately durable approval-attempt protocol owned by the coordinator.
///
/// ```compile_fail
/// use async_trait::async_trait;
/// use oxidra::Result;
/// use oxidra::mcp::{McpCallApprovalHandler, McpCallApprovalRequest};
/// use tokio_util::sync::CancellationToken;
///
/// struct ExternalApproval;
///
/// #[async_trait]
/// impl McpCallApprovalHandler for ExternalApproval {
///     async fn approve_mcp_call(
///         &mut self,
///         _request: &McpCallApprovalRequest,
///         _cancellation: &CancellationToken,
///     ) -> Result<bool> {
///         Ok(true)
///     }
/// }
/// ```
pub trait McpCallApprovalHandler: mcp_call_approval_handler_sealed::Sealed + Send {
    /// Approve one exact durable MCP call before `tool.started` is committed.
    ///
    /// `request` intentionally contains only a coordinator-generated opaque
    /// subject. Provider-controlled identities and deterministic argument
    /// digests are kept in a private context that remains bound to the exact
    /// durable call. Only crate-owned fixed policies implement this method.
    async fn approve_mcp_call(
        &mut self,
        request: &McpCallApprovalRequest,
        cancellation: &CancellationToken,
    ) -> Result<bool>;
}

/// Fixed policy that denies every already validated MCP call.
///
/// This type has no callback and cannot retain or correlate Provider payload.
#[derive(Default)]
pub struct DenyMcpCallApproval;

impl mcp_call_approval_handler_sealed::Sealed for DenyMcpCallApproval {}

#[async_trait]
impl McpCallApprovalHandler for DenyMcpCallApproval {
    async fn approve_mcp_call(
        &mut self,
        _request: &McpCallApprovalRequest,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        Ok(false)
    }
}

/// Fixed policy that approves every already validated MCP call.
///
/// This type has no callback and cannot retain or correlate Provider payload.
/// Interactive or argument-aware approval must use a future durable approval
/// lifecycle implemented inside the coordinator crate, not an external
/// pre-`tool.started` callback.
#[derive(Default)]
pub struct AllowMcpCallApproval;

impl mcp_call_approval_handler_sealed::Sealed for AllowMcpCallApproval {}

#[async_trait]
impl McpCallApprovalHandler for AllowMcpCallApproval {
    async fn approve_mcp_call(
        &mut self,
        _request: &McpCallApprovalRequest,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// Opaque authority to append the bounded Provider response/context portion
/// of the MCP journal for one exact live coordinator/registry epoch and one
/// exact runtime journal handle.
///
/// Construction stays private to this module.  Copying the durable activation
/// strings, or being another module in this crate, is therefore insufficient
/// to manufacture writer authority. The handle identity is deliberately not
/// durable: reopening the same session produces a new identity, so a surviving
/// coordinator or capability from the old handle cannot cross the recovery
/// boundary. The Session layer can only validate and consume a capability that
/// a live coordinator actually minted for its current handle. Tool lifecycle
/// and recovery events use narrower coordinator/session admissions and are
/// deliberately outside this capability's public vocabulary.
pub(crate) struct McpJournalWriteCapabilityV1 {
    session_id: String,
    journal_handle_id: String,
    activation_seq: u64,
    coordinator_id: String,
    registry_epoch_id: String,
    registry_digest: String,
    authority: Arc<McpJournalAuthorityState>,
}

/// Typed failure from the pre-dispatch MCP Provider response gate.
///
/// `RejectedBeforeStart` is a caller-controlled event/profile rejection that
/// is proven zero-write and leaves the journal reusable. Only
/// `CapacityDeniedBeforeStart` permits the bounded capacity cancellation
/// fallback. `Fatal` covers journal/protocol/I/O failures or authority lost
/// after acquisition; the journal is marked reopen-required before that
/// variant is returned. A stale or already-revoked coordinator rejected
/// before capability acquisition is also zero-write `RejectedBeforeStart`.
#[derive(Debug)]
pub enum McpProviderResponseAdmissionErrorV1 {
    RejectedBeforeStart(OxidraError),
    CapacityDeniedBeforeStart(OxidraError),
    Fatal(OxidraError),
}

/// Typed failure from an admitted MCP Provider response terminal.
///
/// `FallbackPermittedBeforeWrite` proves that the completed candidate was
/// rejected before any terminal byte was written and the same one-shot guard
/// may still be consumed by a bounded `response.failed`. `Fatal` means the
/// durable prefix, authority, serialization, I/O or fsync outcome is no
/// longer safely classifiable; callers must close/reopen instead of trying a
/// second write.
#[derive(Debug)]
pub enum McpProviderResponseCommitErrorV1 {
    FallbackPermittedBeforeWrite(OxidraError),
    Fatal(OxidraError),
}

impl McpProviderResponseCommitErrorV1 {
    pub fn into_error(self) -> OxidraError {
        match self {
            Self::FallbackPermittedBeforeWrite(error) | Self::Fatal(error) => error,
        }
    }
}

impl std::fmt::Display for McpProviderResponseCommitErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FallbackPermittedBeforeWrite(error) | Self::Fatal(error) => {
                std::fmt::Display::fmt(error, formatter)
            }
        }
    }
}

impl std::error::Error for McpProviderResponseCommitErrorV1 {}

impl From<DurableOutcomeCommitErrorV1> for McpProviderResponseCommitErrorV1 {
    fn from(error: DurableOutcomeCommitErrorV1) -> Self {
        match error {
            DurableOutcomeCommitErrorV1::FallbackPermittedBeforeWrite(error) => {
                Self::FallbackPermittedBeforeWrite(error)
            }
            DurableOutcomeCommitErrorV1::Fatal(error) => Self::Fatal(error),
        }
    }
}

impl McpProviderResponseAdmissionErrorV1 {
    pub fn into_error(self) -> OxidraError {
        match self {
            Self::RejectedBeforeStart(error)
            | Self::CapacityDeniedBeforeStart(error)
            | Self::Fatal(error) => error,
        }
    }
}

impl std::fmt::Display for McpProviderResponseAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RejectedBeforeStart(error)
            | Self::CapacityDeniedBeforeStart(error)
            | Self::Fatal(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for McpProviderResponseAdmissionErrorV1 {}

struct OwnedMcpProviderEventV1 {
    value: Option<Value>,
}

impl OwnedMcpProviderEventV1 {
    fn take(value: Value) -> Self {
        Self { value: Some(value) }
    }

    fn new(value: Value, maximum_bytes: usize) -> std::result::Result<Self, OxidraError> {
        let owned = Self::take(value);
        owned.validate(maximum_bytes)?;
        Ok(owned)
    }

    fn validate(&self, maximum_bytes: usize) -> std::result::Result<(), OxidraError> {
        preflight_mcp_provider_event_tree_v1(self.as_value(), maximum_bytes).map_err(|error| {
            OxidraError::Session(format!(
                "MCP Provider event exceeds the bounded v1 JSON profile: {error}"
            ))
        })
    }

    fn as_value(&self) -> &Value {
        self.value.as_ref().expect("owned MCP Provider event")
    }

    fn as_value_mut(&mut self) -> &mut Value {
        self.value.as_mut().expect("owned MCP Provider event")
    }

    fn into_value(mut self) -> Value {
        self.value.take().expect("owned MCP Provider event")
    }
}

struct BoundedCountingWriterV1 {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl Write for BoundedCountingWriterV1 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other(
                "prepared Provider request size overflowed",
            ));
        };
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other(
                "prepared Provider request exceeds its byte budget",
            ));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_mcp_provider_request_v1(
    request: &ResponseRequest,
) -> std::result::Result<(), OxidraError> {
    if request.input.len() > MAX_MCP_PREPARED_PROVIDER_INPUT_ITEMS_V1 {
        return Err(OxidraError::Session(format!(
            "MCP prepared Provider request exposes more than {MAX_MCP_PREPARED_PROVIDER_INPUT_ITEMS_V1} input items"
        )));
    }
    if request.tools.len() > TOOL_SURFACE_MAX_TOOLS_V1 {
        return Err(OxidraError::Session(format!(
            "MCP prepared Provider request exposes more than {TOOL_SURFACE_MAX_TOOLS_V1} tools"
        )));
    }
    for (index, input) in request.input.iter().enumerate() {
        preflight_mcp_provider_event_tree_v1(
                input,
                MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1,
            )
            .map_err(|error| {
                OxidraError::Session(format!(
                    "MCP prepared Provider request input[{index}] exceeds the bounded v1 JSON profile: {error}"
                ))
            })?;
    }
    for (index, tool) in request.tools.iter().enumerate() {
        preflight_mcp_provider_event_tree_v1(
                &tool.input_schema,
                MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1,
            )
            .map_err(|error| {
                OxidraError::Session(format!(
                    "MCP prepared Provider request tools[{index}].parameters exceeds the bounded v1 JSON profile: {error}"
                ))
            })?;
    }
    // Bound the complete logical request before durable admission. Per-subtree
    // limits alone still allow thousands of individually valid inputs to be
    // cloned into an attacker-sized prepared body. Every Value above has
    // already passed the depth/node scan, so this aggregate serialization
    // cannot reintroduce an unbounded recursive walk and the writer stops at
    // the first byte over the budget.
    let mut writer = BoundedCountingWriterV1 {
        written: 0,
        maximum: MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(
        &mut writer,
        &(
            &request.instructions,
            &request.input,
            &request.tools,
            &request.model,
            request.max_output_tokens,
        ),
    ) {
        if writer.exceeded {
            return Err(OxidraError::Session(format!(
                "MCP prepared Provider request exceeds {MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1} aggregate bytes"
            )));
        }
        return Err(error.into());
    }
    Ok(())
}

/// Own a Provider result without exposing recursive `serde_json::Value` drop
/// through an abandoned outcome capability. The public Provider trait is
/// substitutable, so the coordinator cannot rely only on the wire parser's
/// recursion limits.
struct OwnedMcpAssistantTurnV1 {
    turn: OwnedAssistantTurnV1,
}

impl OwnedMcpAssistantTurnV1 {
    fn take(turn: OwnedAssistantTurnV1) -> Self {
        Self { turn }
    }

    fn as_turn(&self) -> &AssistantTurn {
        self.turn.as_turn()
    }

    fn validate(&self) -> Result<()> {
        self.turn.preflight_bounded_v1()?;
        let turn = self.as_turn();
        preflight_mcp_provider_event_tree_v1(
            &turn.raw_response,
            MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1,
        )
        .map_err(|error| {
            OxidraError::Provider(format!(
                "MCP Provider raw response exceeds the bounded v1 JSON profile: {error}"
            ))
        })?;
        for (index, item) in turn.output_items.iter().enumerate() {
            preflight_mcp_provider_event_tree_v1(
                item,
                MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1,
            )
            .map_err(|error| {
                OxidraError::Provider(format!(
                    "MCP Provider output_items[{index}] exceeds the bounded v1 JSON profile: {error}"
                ))
            })?;
        }
        for (index, call) in turn.tool_calls.iter().enumerate() {
            preflight_mcp_provider_event_tree_v1(
                &call.arguments,
                MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1,
            )
            .map_err(|error| {
                OxidraError::Provider(format!(
                    "MCP Provider tool_calls[{index}].arguments exceeds the bounded v1 JSON profile: {error}"
                ))
            })?;
        }
        for (index, event) in turn.unknown_stream_events.iter().enumerate() {
            preflight_mcp_provider_event_tree_v1(
                event,
                MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1,
            )
            .map_err(|error| {
                OxidraError::Provider(format!(
                    "MCP Provider unknown_stream_events[{index}] exceeds the bounded v1 JSON profile: {error}"
                ))
            })?;
        }
        let mut writer = BoundedCountingWriterV1 {
            written: 0,
            maximum: MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1,
            exceeded: false,
        };
        if let Err(error) = serde_json::to_writer(&mut writer, turn) {
            if writer.exceeded {
                return Err(OxidraError::Provider(format!(
                    "MCP Provider response exceeds {MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1} encoded bytes"
                )));
            }
            return Err(error.into());
        }
        Ok(())
    }

    fn into_turn(self) -> AssistantTurn {
        self.turn.into_turn()
    }
}

impl Drop for OwnedMcpProviderEventV1 {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop_json_value_iteratively(value);
        }
    }
}

/// One-shot durable ownership of an MCP-owned Provider response attempt.
///
/// Construction atomically validates and binds the active turn's capacity
/// boundary, acquires live coordinator authority, syncs the exact
/// `response.started`, and creates its bounded one-shot outcome/recovery
/// reservation. The parent turn admission remains live across sequential
/// Provider attempts. The guard can commit only one terminal and poisons the
/// journal handle if it is abandoned.
struct McpProviderResponseDispatchAdmissionV1<'turn> {
    capability: McpJournalWriteCapabilityV1,
    inner: ProviderResponseDispatchAdmissionV1,
    response_attempt_id: String,
    // Keep the exact parent turn capability borrowed for the complete
    // Provider-dispatch lifetime. Safe callers therefore cannot drop or
    // finalize the turn after response.started but before this response owns
    // one durable terminal.
    _turn_admission: &'turn TurnTransactionAdmissionV1,
}

/// Exact Provider request plus the already-durable one-shot response outcome
/// admission that authorizes dispatching it. The request is never returned to
/// the caller after this capability has been minted.
pub struct McpPreparedProviderRequestV1<'coordinator, 'turn, 'provider> {
    request: Option<PreparedResponseRequest>,
    provider: &'provider dyn McpExactWireProvider,
    admission: Option<McpProviderResponseDispatchAdmissionV1<'turn>>,
    // Keep the live coordinator itself borrowed until the admitted Provider
    // attempt has produced (or abandoned) its durable outcome. Without this
    // lifetime edge a caller could drop/shutdown the coordinator after
    // `response.started` and still dispatch the already-prepared request.
    _coordinator: PhantomData<&'coordinator McpExecutionCoordinator>,
}

/// Provider result that still owns the unique durable response terminal
/// capability. Dropping this value without terminalizing poisons the journal
/// through the underlying admission guard. The uncommitted Provider payload is
/// deliberately not observable: callers can obtain executable tool calls only
/// from the durable projection returned by [`Self::commit_v1`].
pub struct McpProviderDispatchOutcomeV1<'coordinator, 'turn> {
    uncommitted_result: Option<std::result::Result<OwnedMcpAssistantTurnV1, OxidraError>>,
    admission: McpProviderResponseDispatchAdmissionV1<'turn>,
    // Preserve the same borrow through terminal commit. This prevents a safe
    // caller from revoking the execution epoch between Provider completion
    // and consumption of its one-shot durable outcome capability.
    _coordinator: PhantomData<&'coordinator McpExecutionCoordinator>,
}

/// Drops the entire pre-commit stream. Even a seemingly bounded retry variant
/// is transport-controlled for custom Providers and can encode payload through
/// its values, count, or timing. Provider data becomes observable only after a
/// durable terminal.
struct McpPrecommitDisplayObserverV1;

impl crate::provider::stream_observer_sealed::Sealed for McpPrecommitDisplayObserverV1 {}

impl StreamObserver for McpPrecommitDisplayObserverV1 {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
        match event {
            ProviderEvent::Retry { .. } => Ok(()),
            ProviderEvent::TextDelta(_) => Ok(()),
            ProviderEvent::FunctionArgumentsDelta { .. } => Ok(()),
            ProviderEvent::Unknown { payload, .. } => {
                drop_json_value_iteratively(payload);
                Ok(())
            }
        }
    }
}

/// Durable projection of the exact successful Provider result consumed by
/// [`McpProviderDispatchOutcomeV1::commit_v1`]. Raw response/audit JSON is no
/// longer returned after commit; callers execute calls from this validated
/// projection while the journal remains the canonical response source.
pub struct McpCommittedProviderResponseV1 {
    event: JournalEvent,
    tool_calls: Vec<ToolCall>,
    usage: Usage,
}

impl McpCommittedProviderResponseV1 {
    pub fn event(&self) -> &JournalEvent {
        &self.event
    }

    pub fn text(&self) -> &str {
        self.event
            .data
            .get("text")
            .and_then(Value::as_str)
            .expect("committed MCP Provider response has canonical text")
    }

    /// Returns the validated projection of the already-synced
    /// `response.completed`. This is durable input for the later call/batch
    /// state machine, not by itself a reusable execution permit.
    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.tool_calls
    }

    pub fn usage(&self) -> &Usage {
        &self.usage
    }
}

impl McpProviderDispatchOutcomeV1<'_, '_> {
    /// Consume the actual Provider outcome and its unique journal admission.
    /// No caller-provided response JSON is accepted at this boundary.
    pub fn commit_v1(
        mut self,
        journal: &mut SessionJournal,
    ) -> Result<McpCommittedProviderResponseV1> {
        let result = self
            .uncommitted_result
            .take()
            .expect("MCP Provider outcome was already committed");
        match result {
            Ok(turn) => commit_actual_provider_turn_v1(journal, &mut self.admission, turn),
            Err(error) => {
                commit_actual_provider_error_v1(journal, &mut self.admission, &error)?;
                Err(error)
            }
        }
    }
}

impl<'coordinator, 'turn, 'provider> McpPreparedProviderRequestV1<'coordinator, 'turn, 'provider> {
    pub fn respond<'a>(
        mut self,
        _observer: &'a mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> impl std::future::Future<Output = McpProviderDispatchOutcomeV1<'coordinator, 'turn>> + 'a
    where
        'coordinator: 'a,
        'turn: 'a,
        'provider: 'a,
    {
        let request = self
            .request
            .take()
            .expect("prepared MCP Provider request was already dispatched");
        let admission = self
            .admission
            .take()
            .expect("prepared MCP Provider admission was already consumed");
        let provider = self.provider;
        let coordinator = self._coordinator;
        async move {
            let mut display_observer = McpPrecommitDisplayObserverV1;
            let result = provider
                .respond_exact_mcp_v1(request, &mut display_observer, cancellation)
                .await
                .into_result_v1()
                .map(OwnedMcpAssistantTurnV1::take);
            McpProviderDispatchOutcomeV1 {
                uncommitted_result: Some(result),
                admission,
                _coordinator: coordinator,
            }
        }
    }
}

impl McpProviderResponseDispatchAdmissionV1<'_> {
    /// Commit the unique successful terminal for this admitted response.
    /// The exact response identity is inserted by the guard and cannot be
    /// redirected by caller-provided JSON.
    pub fn commit_completed_v1(
        &mut self,
        journal: &mut SessionJournal,
        data: Value,
    ) -> std::result::Result<JournalEvent, McpProviderResponseCommitErrorV1> {
        let mut data =
            OwnedMcpProviderEventV1::new(data, MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1)
                .map_err(McpProviderResponseCommitErrorV1::FallbackPermittedBeforeWrite)?;
        bind_exact_response_attempt_v1(data.as_value_mut(), &self.response_attempt_id)
            .map_err(McpProviderResponseCommitErrorV1::FallbackPermittedBeforeWrite)?;
        data.validate(MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1)
            .map_err(McpProviderResponseCommitErrorV1::FallbackPermittedBeforeWrite)?;
        let proof = self.capability.acquire_live_proof().map_err(|error| {
            self.inner.mark_reopen_required_v1();
            McpProviderResponseCommitErrorV1::Fatal(error)
        })?;
        journal
            .append_mcp_provider_response_completed_with_live_proof_v1(
                &proof,
                &mut self.inner,
                data.into_value(),
            )
            .map_err(|error| {
                if matches!(error, DurableOutcomeCommitErrorV1::Fatal(_)) {
                    self.inner.mark_reopen_required_v1();
                }
                McpProviderResponseCommitErrorV1::from(error)
            })
    }

    /// Commit the unique bounded failure terminal for this admitted response.
    pub fn commit_failed_v1(
        &mut self,
        journal: &mut SessionJournal,
        error: &str,
    ) -> std::result::Result<JournalEvent, McpProviderResponseCommitErrorV1> {
        let proof = self.capability.acquire_live_proof().map_err(|error| {
            self.inner.mark_reopen_required_v1();
            McpProviderResponseCommitErrorV1::Fatal(error)
        })?;
        journal
            .append_mcp_provider_response_failed_with_live_proof_v1(&proof, &mut self.inner, error)
            .map_err(|error| {
                self.inner.mark_reopen_required_v1();
                McpProviderResponseCommitErrorV1::Fatal(error)
            })
    }

    /// Commit the unique bounded cancellation terminal for this response.
    pub fn commit_aborted_v1(
        &mut self,
        journal: &mut SessionJournal,
        reason: &str,
    ) -> std::result::Result<JournalEvent, McpProviderResponseCommitErrorV1> {
        let proof = self.capability.acquire_live_proof().map_err(|error| {
            self.inner.mark_reopen_required_v1();
            McpProviderResponseCommitErrorV1::Fatal(error)
        })?;
        journal
            .append_mcp_provider_response_aborted_with_live_proof_v1(
                &proof,
                &mut self.inner,
                reason,
            )
            .map_err(|error| {
                self.inner.mark_reopen_required_v1();
                McpProviderResponseCommitErrorV1::Fatal(error)
            })
    }

    /// Commit the crash-recoverable Provider context-limit intent/audit pair
    /// while retaining the same live MCP and outcome authority.
    pub fn commit_context_limit_v1(
        &mut self,
        journal: &mut SessionJournal,
        reason: &str,
    ) -> std::result::Result<(JournalEvent, JournalEvent), McpProviderResponseCommitErrorV1> {
        let proof = self.capability.acquire_live_proof().map_err(|error| {
            self.inner.mark_reopen_required_v1();
            McpProviderResponseCommitErrorV1::Fatal(error)
        })?;
        journal
            .append_mcp_provider_context_limit_with_live_proof_v1(&proof, &mut self.inner, reason)
            .map_err(|error| {
                self.inner.mark_reopen_required_v1();
                McpProviderResponseCommitErrorV1::Fatal(error)
            })
    }
}

fn commit_actual_provider_turn_v1(
    journal: &mut SessionJournal,
    admission: &mut McpProviderResponseDispatchAdmissionV1<'_>,
    turn: OwnedMcpAssistantTurnV1,
) -> Result<McpCommittedProviderResponseV1> {
    if let Err(error) = turn.validate().and_then(|()| {
        validate_response_output_items(&turn.as_turn().output_items)?;
        validate_actual_provider_turn_v1(turn.as_turn())
    }) {
        admission
            .commit_failed_v1(journal, &error.to_string())
            .map_err(McpProviderResponseCommitErrorV1::into_error)?;
        return Err(error);
    }

    let AssistantTurn {
        raw_response,
        output_items,
        text,
        tool_calls,
        usage,
        unknown_stream_events,
    } = turn.into_turn();
    // Build the durable event by moving every recursive Provider tree into its
    // sole journal owner. `json!` serializes expressions by reference and
    // would deep-clone raw_response/output_items/unknown events while the
    // original AssistantTurn was still alive, briefly retaining another full
    // response budget at the commit boundary.
    let mut data = Map::new();
    data.insert("raw_response".to_owned(), raw_response);
    data.insert("output_items".to_owned(), Value::Array(output_items));
    data.insert("text".to_owned(), Value::String(text));
    data.insert(
        "usage".to_owned(),
        json!({
            "input_tokens": usage.input_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
            "output_tokens": usage.output_tokens,
            "reasoning_output_tokens": usage.reasoning_output_tokens,
            "total_tokens": usage.total_tokens,
        }),
    );
    data.insert(
        "unknown_stream_events".to_owned(),
        Value::Array(unknown_stream_events),
    );
    let data = Value::Object(data);
    let event = match admission.commit_completed_v1(journal, data) {
        Ok(event) => event,
        Err(McpProviderResponseCommitErrorV1::FallbackPermittedBeforeWrite(error)) => {
            admission
                .commit_failed_v1(
                    journal,
                    &format!("Provider response completed but could not be committed: {error}"),
                )
                .map_err(McpProviderResponseCommitErrorV1::into_error)?;
            return Err(error);
        }
        Err(McpProviderResponseCommitErrorV1::Fatal(error)) => return Err(error),
    };
    Ok(McpCommittedProviderResponseV1 {
        event,
        tool_calls,
        usage,
    })
}

fn validate_actual_provider_turn_v1(turn: &AssistantTurn) -> Result<()> {
    if turn
        .raw_response
        .get("output")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        != Some(turn.output_items.as_slice())
    {
        return Err(OxidraError::Provider(
            "MCP Provider raw_response.output does not match canonical output_items".to_owned(),
        ));
    }
    let mut call_index = 0usize;
    let mut projected_argument_nodes = 0usize;
    for item in &turn.output_items {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            continue;
        }
        if call_index == MAX_MCP_CALLS_PER_RESPONSE {
            return Err(OxidraError::Limit(format!(
                "a Provider response may contain at most {MAX_MCP_CALLS_PER_RESPONSE} function calls"
            )));
        }
        let expected = turn.tool_calls.get(call_index).ok_or_else(|| {
            OxidraError::Provider(
                "MCP Provider tool_calls do not match canonical output_items".to_owned(),
            )
        })?;
        let id = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| OxidraError::Provider("function_call is missing call_id".to_owned()))?
            .to_owned();
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| OxidraError::Provider("function_call is missing name".to_owned()))?
            .to_owned();
        let arguments = match item.get("arguments") {
            Some(Value::String(arguments)) => {
                let nodes = super::count_mcp_provider_json_text_nodes_v1(
                    arguments,
                    MAX_PROVIDER_RESPONSE_ARGUMENT_BYTES_V1,
                )
                .map_err(|error| {
                    OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                })?;
                projected_argument_nodes =
                    projected_argument_nodes.checked_add(nodes).ok_or_else(|| {
                        OxidraError::Provider(
                            "MCP Provider projected argument node count overflowed".to_owned(),
                        )
                    })?;
                if projected_argument_nodes > MAX_RESPONSE_RETAINED_NODES_V1 {
                    return Err(OxidraError::Provider(format!(
                        "MCP Provider projected arguments exceed the {MAX_RESPONSE_RETAINED_NODES_V1}-node limit"
                    )));
                }
                serde_json::from_str(arguments).map_err(|error| {
                    OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                })?
            }
            Some(arguments) => {
                let metrics = super::measure_mcp_provider_event_tree_v1(
                    arguments,
                    MAX_PROVIDER_RESPONSE_ARGUMENT_BYTES_V1,
                )
                .map_err(|error| {
                    OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                })?;
                projected_argument_nodes = projected_argument_nodes
                    .checked_add(metrics.nodes)
                    .ok_or_else(|| {
                        OxidraError::Provider(
                            "MCP Provider projected argument node count overflowed".to_owned(),
                        )
                    })?;
                if projected_argument_nodes > MAX_RESPONSE_RETAINED_NODES_V1 {
                    return Err(OxidraError::Provider(format!(
                        "MCP Provider projected arguments exceed the {MAX_RESPONSE_RETAINED_NODES_V1}-node limit"
                    )));
                }
                arguments.clone()
            }
            None => {
                return Err(OxidraError::Provider(format!(
                    "function_call {name} is missing arguments"
                )));
            }
        };
        if expected.id != id || expected.name != name || expected.arguments != arguments {
            return Err(OxidraError::Provider(
                "MCP Provider tool_calls do not match canonical output_items".to_owned(),
            ));
        }
        call_index += 1;
    }
    if call_index != turn.tool_calls.len() {
        return Err(OxidraError::Provider(
            "MCP Provider tool_calls do not match canonical output_items".to_owned(),
        ));
    }
    Ok(())
}

fn commit_actual_provider_error_v1(
    journal: &mut SessionJournal,
    admission: &mut McpProviderResponseDispatchAdmissionV1<'_>,
    error: &OxidraError,
) -> Result<()> {
    match error {
        OxidraError::Interrupted => admission
            .commit_aborted_v1(journal, "cancelled")
            .map(|_| ())
            .map_err(McpProviderResponseCommitErrorV1::into_error),
        OxidraError::ResponseAborted(reason) => admission
            .commit_aborted_v1(journal, reason)
            .map(|_| ())
            .map_err(McpProviderResponseCommitErrorV1::into_error),
        OxidraError::Observer(_) => admission
            .commit_aborted_v1(journal, &error.to_string())
            .map(|_| ())
            .map_err(McpProviderResponseCommitErrorV1::into_error),
        OxidraError::ProviderContextLimit(reason) => admission
            .commit_context_limit_v1(journal, reason)
            .map(|_| ())
            .map_err(McpProviderResponseCommitErrorV1::into_error),
        _ => admission
            .commit_failed_v1(journal, &error.to_string())
            .map(|_| ())
            .map_err(McpProviderResponseCommitErrorV1::into_error),
    }
}

fn bind_exact_response_attempt_v1(data: &mut Value, response_attempt_id: &str) -> Result<()> {
    let object = data.as_object_mut().ok_or_else(|| {
        OxidraError::Session("MCP Provider response.completed data must be an object".to_owned())
    })?;
    if object
        .get("response_attempt_id")
        .and_then(Value::as_str)
        .is_some_and(|value| value != response_attempt_id)
    {
        return Err(OxidraError::Session(
            "MCP Provider response.completed attempts to change its admitted response identity"
                .to_owned(),
        ));
    }
    object.insert(
        "response_attempt_id".to_owned(),
        Value::String(response_attempt_id.to_owned()),
    );
    Ok(())
}

/// Proof that one fixed synchronous journal append acquired the live
/// coordinator authority before revocation.
///
/// The proof is intentionally not constructible outside this module.  In
/// particular, callers cannot run an arbitrary closure while the authority
/// mutex is held and then re-enter coordinator shutdown from that closure.
pub(crate) struct LiveMcpJournalWriteProofV1<'a> {
    capability: &'a McpJournalWriteCapabilityV1,
    _guard: MutexGuard<'a, ()>,
}

impl LiveMcpJournalWriteProofV1<'_> {
    pub(crate) fn capability(&self) -> &McpJournalWriteCapabilityV1 {
        self.capability
    }
}

struct McpJournalAuthorityState {
    active: Arc<AtomicBool>,
    gate: Mutex<()>,
}

impl McpJournalAuthorityState {
    fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(true)),
            gate: Mutex::new(()),
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn begin_revoke(&self) {
        // Publish revocation before waiting for an in-flight append. Writers
        // that have not already acquired the gate must fail even if they win
        // the mutex race against the draining thread.
        self.active.store(false, Ordering::Release);
    }

    fn wait_for_writers(&self) {
        match self.gate.lock() {
            Ok(_guard) => {}
            Err(_poisoned) => {}
        }
    }

    #[cfg(test)]
    fn revoke(&self) {
        self.begin_revoke();
        self.wait_for_writers();
    }
}

impl McpJournalWriteCapabilityV1 {
    fn new(
        session_id: String,
        journal_handle_id: String,
        activation_seq: u64,
        coordinator_id: String,
        registry_epoch_id: String,
        registry_digest: String,
        authority: Arc<McpJournalAuthorityState>,
    ) -> Self {
        Self {
            session_id,
            journal_handle_id,
            activation_seq,
            coordinator_id,
            registry_epoch_id,
            registry_digest,
            authority,
        }
    }

    fn acquire_live_proof(&self) -> Result<LiveMcpJournalWriteProofV1<'_>> {
        let guard = self.authority.gate.lock().map_err(|_| {
            OxidraError::Session("MCP journal authority lock is poisoned".to_owned())
        })?;
        if !self.authority.is_active() {
            return Err(OxidraError::Session(
                "MCP journal write capability has been revoked with its coordinator".to_owned(),
            ));
        }
        Ok(LiveMcpJournalWriteProofV1 {
            capability: self,
            _guard: guard,
        })
    }

    #[cfg(test)]
    pub(crate) fn append_event_to_journal_for_test(
        &self,
        journal: &mut SessionJournal,
        kind: String,
        turn_id: Option<&str>,
        data: Value,
    ) -> Result<JournalEvent> {
        if !matches!(
            kind.as_str(),
            "context.tools"
                | "response.started"
                | "response.completed"
                | "response.failed"
                | "response.aborted"
        ) {
            return Err(OxidraError::Session(format!(
                "MCP journal capability v1 cannot author {kind}; use the typed dispatch or recovery writer"
            )));
        }
        let proof = self.acquire_live_proof()?;
        journal.append_mcp_event_with_live_proof_for_test_v1(&proof, kind, turn_id, data)
    }

    fn append_tool_cancelled_before_start_to_journal(
        &self,
        journal: &mut SessionJournal,
        turn_id: &str,
        data: Value,
    ) -> Result<JournalEvent> {
        let proof = self.acquire_live_proof()?;
        journal.append_mcp_tool_cancelled_before_start_with_live_proof_v1(&proof, turn_id, data)
    }

    fn append_tool_completed_before_start_to_journal(
        &self,
        journal: &mut SessionJournal,
        turn_id: &str,
        data: Value,
    ) -> Result<JournalEvent> {
        let proof = self.acquire_live_proof()?;
        journal.append_mcp_tool_completed_before_start_with_live_proof_v1(&proof, turn_id, data)
    }

    pub(crate) fn validate_for_journal_unlocked(
        &self,
        session_id: &str,
        journal_handle_id: &str,
        events: &[JournalEvent],
    ) -> Result<()> {
        if self.session_id != session_id || self.journal_handle_id != journal_handle_id {
            return Err(OxidraError::Session(
                "MCP journal write capability belongs to a different session journal handle"
                    .to_owned(),
            ));
        }
        validate_mcp_call_chain(events)?;
        let mut matching = events.iter().filter(|event| {
            event.kind == MCP_REGISTRY_ACTIVATED_KIND
                && event.seq == self.activation_seq
                && event.turn_id.is_none()
                && event.data.get("coordinator_id").and_then(Value::as_str)
                    == Some(self.coordinator_id.as_str())
                && event.data.get("registry_epoch_id").and_then(Value::as_str)
                    == Some(self.registry_epoch_id.as_str())
                && event.data.get("registry_digest").and_then(Value::as_str)
                    == Some(self.registry_digest.as_str())
        });
        if matching.next().is_none() || matching.next().is_some() {
            return Err(OxidraError::Session(
                "MCP journal write capability no longer matches one exact registry activation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        session_id: String,
        journal_handle_id: String,
        activation_seq: u64,
        coordinator_id: String,
        registry_epoch_id: String,
        registry_digest: String,
        authority_active: Arc<AtomicBool>,
    ) -> Self {
        Self::new(
            session_id,
            journal_handle_id,
            activation_seq,
            coordinator_id,
            registry_epoch_id,
            registry_digest,
            Arc::new(McpJournalAuthorityState {
                active: authority_active,
                gate: Mutex::new(()),
            }),
        )
    }
}

/// One-shot bootstrap authority for the first durable MCP activation.
///
/// The activation itself necessarily precedes the ordinary epoch capability,
/// so it uses a separate token that owns the exact prevalidated payload and
/// expected journal position.  No generic/raw append primitive is exposed to
/// the rest of the crate.
pub(crate) struct McpRegistryActivationAdmissionV1 {
    session_id: String,
    expected_seq: u64,
    data: Value,
}

impl McpRegistryActivationAdmissionV1 {
    fn new(session_id: String, expected_seq: u64, data: Value) -> Self {
        Self {
            session_id,
            expected_seq,
            data,
        }
    }

    pub(crate) fn into_data_for_journal(self, session_id: &str, next_seq: u64) -> Result<Value> {
        if self.session_id != session_id || self.expected_seq != next_seq {
            return Err(OxidraError::Session(
                "MCP activation admission no longer matches the target journal prefix".to_owned(),
            ));
        }
        Ok(self.data)
    }
}

/// Sole owner of a surface-approved registry and its dispatch authority.
///
/// The coordinator binds one runtime registry epoch to one durable session
/// and to the exact journal handle that activated or resumed it. It retains
/// that handle's exclusive writer-lock lease until `shutdown` completes or the
/// coordinator is dropped, so a second open generation cannot coexist with
/// live MCP transports. Callers can request approval and execution, but cannot
/// construct the private `DispatchPermit` consumed by the registry.
pub struct McpExecutionCoordinator {
    policy: McpCoordinatorPolicy,
    coordinator_id: String,
    registry_epoch_id: String,
    session_id: String,
    journal_handle_id: String,
    /// Keeps the exact session writer lock alive for the full execution
    /// authority lifetime. Dropping the journal alone must not allow another
    /// open generation to start MCP processes alongside this coordinator.
    journal_execution_lease: Option<SessionExecutionLeaseV1>,
    activation_seq: u64,
    registry: McpRegistry,
    dispatch_poisoned: Arc<AtomicBool>,
    journal_authority_active: Arc<McpJournalAuthorityState>,
}

/// Opaque runtime proof of the exact MCP definitions and registry claim for
/// one activated coordinator epoch.
///
/// The fields are private so Agent request construction cannot assemble an
/// MCP claim from arbitrary strings.  This is only a writer-side primitive:
/// coordinator/call-chain v2 activation rows do not yet bind definition or
/// output-schema digests, so the future MCP-capable journal protocol must bump
/// its activation/reader version before treating this snapshot as durable
/// offline proof.
pub struct McpProviderSurfaceV1 {
    definitions: Vec<ToolDefinition>,
    claim: McpSurfaceClaimV1,
}

impl McpProviderSurfaceV1 {
    /// Merge the live MCP surface into builtin/history definitions and bind
    /// the exact Provider-visible ordering in one versioned snapshot.  Name
    /// collisions fail before any `context.tools` row can be written.
    pub fn merge_with(
        self,
        mut base_definitions: Vec<ToolDefinition>,
    ) -> Result<ToolSurfaceSnapshotV1> {
        base_definitions.extend(self.definitions);
        snapshot_tool_surface_v1(&base_definitions, Some(self.claim))
    }
}

/// Opaque proof that a durable session was opened, recovered and reduced
/// before any MCP process is started for resume.
///
/// The private fields make the proof unforgeable outside this crate.  Its
/// lifetime also keeps the recovered [`SessionJournal`] borrowed until
/// `connect_for_resume` has consumed the proof.
pub struct McpResumeEligibility<'journal> {
    policy: McpCoordinatorPolicy,
    session_id: String,
    journal_open_id: String,
    activation_seq: u64,
    coordinator_id: String,
    registry_epoch_id: String,
    config_sha256: String,
    execution_plan_digest: String,
    registry_digest: String,
    execution_lease: Option<SessionExecutionLeaseV1>,
    _journal: PhantomData<&'journal mut SessionJournal>,
}

pub(super) struct McpResumePermit {
    policy: McpCoordinatorPolicy,
    session_id: String,
    journal_open_id: String,
    activation_seq: u64,
    coordinator_id: String,
    registry_epoch_id: String,
    config_sha256: String,
    execution_plan_digest: String,
    registry_digest: String,
}

impl<'journal> McpResumeEligibility<'journal> {
    pub(crate) fn from_recovered_journal(journal: &'journal mut SessionJournal) -> Result<Self> {
        let events = journal.read_events()?;
        validate_mcp_call_chain(&events)?;
        ensure_no_unstarted_mcp_calls(&events)?;
        ensure_no_unresolved_in_doubt_tools(journal)?;
        let activation = durable_activation(&events)?;
        let policy = activation_policy(activation)?;
        let activation_seq = activation.seq;
        let coordinator_id = required_activation_string(activation, "coordinator_id")?.to_owned();
        let registry_epoch_id =
            required_activation_string(activation, "registry_epoch_id")?.to_owned();
        let config_sha256 = required_activation_string(activation, "config_sha256")?.to_owned();
        let execution_plan_digest =
            required_activation_string(activation, "execution_plan_digest")?.to_owned();
        let registry_digest = required_activation_string(activation, "registry_digest")?.to_owned();
        let journal_open_id = journal.claim_mcp_resume_open_id()?;

        Ok(Self {
            policy,
            session_id: journal.session_id().to_owned(),
            journal_open_id,
            activation_seq,
            coordinator_id,
            registry_epoch_id,
            config_sha256,
            execution_plan_digest,
            registry_digest,
            execution_lease: Some(journal.retain_guarded_execution_lease_v1()?),
            _journal: PhantomData,
        })
    }

    pub(super) fn validate_config(
        &self,
        config_sha256: &str,
        execution_plan_digest: &str,
    ) -> Result<()> {
        if self.config_sha256 != config_sha256
            || self.execution_plan_digest != execution_plan_digest
        {
            return Err(OxidraError::Mcp(
                "MCP resume config does not match the durable registry activation".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn into_permit(self) -> McpResumePermit {
        McpResumePermit {
            policy: self.policy,
            session_id: self.session_id,
            journal_open_id: self.journal_open_id,
            activation_seq: self.activation_seq,
            coordinator_id: self.coordinator_id,
            registry_epoch_id: self.registry_epoch_id,
            config_sha256: self.config_sha256,
            execution_plan_digest: self.execution_plan_digest,
            registry_digest: self.registry_digest,
        }
    }

    pub(super) fn execution_lease(&self) -> SessionExecutionLeaseV1 {
        // The eligibility is only minted from the exact locked journal handle;
        // cloning the Arc-backed lease here transfers that ownership into the
        // registry before startup. The eligibility itself remains consumed by
        // `connect_for_resume` and cannot be reused.
        self.execution_lease
            .as_ref()
            .expect("MCP resume eligibility execution lease missing")
            .clone_v1()
    }
}

impl McpResumePermit {
    fn validate_journal(&self, journal: &SessionJournal) -> Result<()> {
        if journal.session_id() != self.session_id
            || journal.mcp_resume_open_id() != Some(self.journal_open_id.as_str())
        {
            return Err(OxidraError::Session(
                "MCP resume permit does not belong to this recovered journal handle".to_owned(),
            ));
        }
        Ok(())
    }
}

impl McpExecutionCoordinator {
    pub fn activate(
        approved_registry: ApprovedMcpRegistry,
        journal: &mut SessionJournal,
    ) -> Result<Self> {
        let mut events = journal.read_events()?;
        validate_new_activation(&events)?;
        let (mut registry, journal_execution_lease) = approved_registry.into_parts();
        let journal_execution_lease = journal_execution_lease.ok_or_else(|| {
            OxidraError::Session(
                "MCP activation registry was not bound to the locked session journal before startup"
                    .to_owned(),
            )
        })?;
        if !journal_execution_lease.matches_journal(journal) {
            return Err(OxidraError::Session(
                "MCP activation registry belongs to a different session journal handle".to_owned(),
            ));
        }
        let policy = MCP_COORDINATOR_POLICY_V4;
        let bindings = registry.surface_binding_snapshot_v1()?;
        let coordinator_id = Uuid::now_v7().to_string();
        let registry_epoch_id = Uuid::now_v7().to_string();
        let activation_data = json!({
            "coordinator_version": policy.coordinator_version,
            "call_chain_validator_version": policy.call_chain_validator_version,
            "coordinator_id": coordinator_id,
            "registry_epoch_id": registry_epoch_id,
            "registry_version": policy.registry_version,
            "stdio_kernel_version": policy.stdio_kernel_version,
            "schema_profile_version": policy.schema_profile_version,
            "surface_claim_version": MCP_SURFACE_CLAIM_VERSION_V1,
            "config_sha256": registry.config_sha256(),
            "execution_plan_digest": registry.execution_plan_digest(),
            "registry_digest": registry.digest(),
            "bindings": bindings,
        });
        events.push(JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq: journal.next_seq(),
            ts: Utc::now(),
            kind: MCP_REGISTRY_ACTIVATED_KIND.to_owned(),
            session_id: journal.session_id().to_owned(),
            turn_id: None,
            data: activation_data.clone(),
        });
        validate_mcp_call_chain(&events)?;
        validate_compaction_boundary_chain(&events)?;

        let activation_admission = McpRegistryActivationAdmissionV1::new(
            journal.session_id().to_owned(),
            journal.next_seq(),
            activation_data,
        );
        registry.bind_dispatch_authority(&coordinator_id, &registry_epoch_id)?;
        let event = journal.append_mcp_registry_activation_v1(activation_admission)?;
        Ok(Self {
            policy,
            coordinator_id,
            registry_epoch_id,
            session_id: journal.session_id().to_owned(),
            journal_handle_id: journal.handle_id().to_owned(),
            journal_execution_lease: Some(journal_execution_lease),
            activation_seq: event.seq,
            registry,
            dispatch_poisoned: Arc::new(AtomicBool::new(false)),
            journal_authority_active: Arc::new(McpJournalAuthorityState::new()),
        })
    }

    /// Rebind a newly discovered, explicitly approved live registry to the
    /// immutable registry epoch already recorded in a recovered session.
    ///
    /// This does not create a second activation.  The live registry must
    /// reproduce the exact config, execution-plan, provider surface and
    /// registry digest recorded by the activation policy. Callers must open the
    /// session through [`crate::session::SessionStore`] first so interrupted
    /// pre-start calls have already received their durable recovery outcome.
    pub fn resume(
        approved_registry: ApprovedMcpResumeRegistry,
        journal: &SessionJournal,
    ) -> Result<Self> {
        let (mut registry, resume_permit, journal_execution_lease) = approved_registry.into_parts();
        let journal_execution_lease = journal_execution_lease.ok_or_else(|| {
            OxidraError::Session(
                "MCP resume registry lost its locked session execution lease".to_owned(),
            )
        })?;
        if !journal_execution_lease.matches_journal(journal) {
            return Err(OxidraError::Session(
                "MCP resume registry belongs to a different session journal handle".to_owned(),
            ));
        }
        resume_permit.validate_journal(journal)?;
        let events = journal.read_events()?;
        validate_mcp_call_chain(&events)?;
        ensure_no_unstarted_mcp_calls(&events)?;
        ensure_no_unresolved_in_doubt_tools(journal)?;
        let activation = durable_activation(&events)?;
        if activation_policy(activation)? != resume_permit.policy
            || activation.seq != resume_permit.activation_seq
            || required_activation_string(activation, "coordinator_id")?
                != resume_permit.coordinator_id
            || required_activation_string(activation, "registry_epoch_id")?
                != resume_permit.registry_epoch_id
            || required_activation_string(activation, "config_sha256")?
                != resume_permit.config_sha256
            || required_activation_string(activation, "execution_plan_digest")?
                != resume_permit.execution_plan_digest
            || required_activation_string(activation, "registry_digest")?
                != resume_permit.registry_digest
        {
            return Err(OxidraError::Session(
                "MCP resume permit no longer matches the durable registry activation".to_owned(),
            ));
        }

        registry.bind_dispatch_authority(
            &resume_permit.coordinator_id,
            &resume_permit.registry_epoch_id,
        )?;
        let coordinator = Self {
            policy: resume_permit.policy,
            coordinator_id: resume_permit.coordinator_id,
            registry_epoch_id: resume_permit.registry_epoch_id,
            session_id: journal.session_id().to_owned(),
            journal_handle_id: journal.handle_id().to_owned(),
            journal_execution_lease: Some(journal_execution_lease),
            activation_seq: activation.seq,
            registry,
            dispatch_poisoned: Arc::new(AtomicBool::new(false)),
            journal_authority_active: Arc::new(McpJournalAuthorityState::new()),
        };
        validate_activation(&events, &coordinator)?;
        Ok(coordinator)
    }

    pub fn registry_epoch_id(&self) -> &str {
        &self.registry_epoch_id
    }

    pub fn registry_digest(&self) -> &str {
        self.registry.digest()
    }

    /// Mint the opaque journal capability used by Provider/context writers.
    /// Tool lifecycle and recovery events remain on narrower typed paths. The
    /// exact activation and runtime journal handle are revalidated before the
    /// capability is issued, so copying public digest strings is not
    /// sufficient to obtain this authority and a capability cannot be reused
    /// after the session is reopened.
    fn journal_write_capability_v1(
        &self,
        journal: &SessionJournal,
    ) -> Result<McpJournalWriteCapabilityV1> {
        if !self.journal_authority_active.is_active() {
            return Err(OxidraError::Session(
                "MCP coordinator journal authority has been revoked".to_owned(),
            ));
        }
        self.require_bound_journal(journal)?;
        let events = journal.read_events()?;
        let activation_seq = validate_activation(&events, self)?;
        Ok(McpJournalWriteCapabilityV1::new(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            activation_seq,
            self.coordinator_id.clone(),
            self.registry_epoch_id.clone(),
            self.registry.digest().to_owned(),
            Arc::clone(&self.journal_authority_active),
        ))
    }

    /// Bind one exact prepared request to its durable MCP surface and response
    /// outcome admission before Provider code can run. The returned capability
    /// owns the request and is the only API that can pass it to a Provider.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_prepared_provider_request_v1<'coordinator, 'turn, 'provider>(
        &'coordinator self,
        journal: &mut SessionJournal,
        turn_admission: &'turn TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
        request: PreparedResponseRequest,
        provider: &'provider dyn McpExactWireProvider,
    ) -> std::result::Result<
        McpPreparedProviderRequestV1<'coordinator, 'turn, 'provider>,
        McpProviderResponseAdmissionErrorV1,
    > {
        // Take iterative-drop ownership of both caller-controlled trees before
        // the first fallible operation. A rejection of either side must not
        // recursively destroy the other still-bare argument.
        let mut data = OwnedMcpProviderEventV1::take(data);
        data.validate(MAX_MCP_PROVIDER_START_EVENT_BYTES_V1)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        validate_mcp_provider_request_v1(request.request())
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        preflight_mcp_provider_event_tree_v1(
            request.body(),
            MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1,
        )
        .map_err(|error| {
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(format!(
                "exact MCP Provider request body exceeds the bounded v1 JSON profile: {error}"
            )))
        })?;
        if request.body_bytes().len() > MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1 {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(format!(
                    "exact MCP Provider request body exceeds {MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1} encoded bytes"
                )),
            ));
        }
        let effective_model = request
            .body()
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                    "exact MCP Provider request body has no string model".to_owned(),
                ))
            })?;
        let transport_model = provider
            .mcp_provider_model_v1()
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        if effective_model != transport_model {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "sealed MCP Provider request model does not match the transport configuration"
                        .to_owned(),
                ),
            ));
        }
        if request.body() != &prepared_request_body(request.request(), effective_model) {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "Provider prepared body does not match the frozen Responses request profile"
                        .to_owned(),
                ),
            ));
        }
        let measurement = measure_provider_prepared_request(&request)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        let object = data.as_value_mut().as_object_mut().ok_or_else(|| {
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                "MCP response.started data must be an object".to_owned(),
            ))
        })?;
        let context = object
            .get("context")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                    "MCP response.started has no context object".to_owned(),
                ))
            })?;
        if request.provider_protocol() != PROVIDER_PROTOCOL_OPENAI_RESPONSES {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "exact MCP Provider request uses an unsupported Provider protocol".to_owned(),
                ),
            ));
        }
        let transport_usage_domain = provider
            .mcp_provider_usage_domain_v1()
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        if request.provider_usage_domain() != transport_usage_domain {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "sealed MCP Provider request belongs to a different transport endpoint/model domain"
                        .to_owned(),
                ),
            ));
        }
        if context.get("provider_usage_domain").and_then(Value::as_str)
            != Some(request.provider_usage_domain())
        {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "exact MCP Provider endpoint identity does not match response.started context"
                        .to_owned(),
                ),
            ));
        }
        let expected_measurement = serde_json::to_value(&measurement).map_err(|error| {
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(error.into())
        })?;
        if context.get("measurement") != Some(&expected_measurement) {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "MCP Provider request does not match response.started context measurement"
                        .to_owned(),
                ),
            ));
        }
        let tools_event_seq = context
            .get("tools_event_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                    "MCP response.started context has no tools_event_seq".to_owned(),
                ))
            })?;
        let events = journal.read_events().map_err(|error| {
            journal.mark_reopen_required();
            McpProviderResponseAdmissionErrorV1::Fatal(error)
        })?;
        let tools_event = events
            .iter()
            .find(|event| event.seq == tools_event_seq)
            .filter(|event| event.kind == "context.tools" && event.turn_id.is_none())
            .ok_or_else(|| {
                McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                    "MCP Provider request references no exact global context.tools snapshot"
                        .to_owned(),
                ))
            })?;
        let snapshot = ToolSurfaceSnapshotV1::from_exact_journal_value(&tools_event.data)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        self.validate_live_surface_snapshot_v1(&snapshot)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        if request.request().tools.as_slice() != snapshot.tools() {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "MCP Provider request tools do not match the referenced context.tools snapshot"
                        .to_owned(),
                ),
            ));
        }
        object.insert(
            "mcp_surface".to_owned(),
            json!({
                "version": MCP_SURFACE_CLAIM_VERSION_V1,
                "event_seq": tools_event_seq,
                "digest": snapshot.digest(),
            }),
        );
        object.insert(
            "mcp_prepared_request".to_owned(),
            json!({
                "version": 1,
                "digest": measurement.request_digest,
                "body": request.body(),
            }),
        );
        let admission =
            self.admit_provider_response_v1(journal, turn_admission, turn_id, data.into_value())?;
        Ok(McpPreparedProviderRequestV1 {
            request: Some(request),
            provider,
            admission: Some(admission),
            _coordinator: PhantomData,
        })
    }

    /// Admit one MCP-owned Provider response against the exact active turn.
    /// This is the sole production path for MCP `response.started`: it holds
    /// live coordinator authority across the synchronous append and returns a
    /// one-shot guard backed by the ordinary Provider outcome reservation.
    fn admit_provider_response_v1<'turn>(
        &self,
        journal: &mut SessionJournal,
        turn_admission: &'turn TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<
        McpProviderResponseDispatchAdmissionV1<'turn>,
        McpProviderResponseAdmissionErrorV1,
    > {
        // Take iterative-drop ownership before any fallible journal/authority
        // check. A stale coordinator must not turn rejection of a deep caller-
        // constructed Value into recursive stack overflow.
        let mut data = OwnedMcpProviderEventV1::new(data, MAX_MCP_PROVIDER_START_EVENT_BYTES_V1)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        if !self.journal_authority_active.is_active() {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                OxidraError::Session(
                    "MCP coordinator journal authority has been revoked".to_owned(),
                ),
            ));
        }
        if let Err(error) = self.require_bound_journal(journal) {
            return Err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(
                error,
            ));
        }
        let capability = match self.journal_write_capability_v1(journal) {
            Ok(capability) => capability,
            Err(error) => {
                journal.mark_reopen_required();
                return Err(McpProviderResponseAdmissionErrorV1::Fatal(error));
            }
        };
        let object = data.as_value_mut().as_object_mut().ok_or_else(|| {
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                "MCP response.started data must be an object".to_owned(),
            ))
        })?;
        let response_attempt_id = object
            .get("response_attempt_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(OxidraError::Session(
                    "MCP response.started has no response_attempt_id for dispatch admission"
                        .to_owned(),
                ))
            })?
            .to_owned();
        object.insert(
            "mcp_registry_epoch_id".to_owned(),
            Value::String(self.registry_epoch_id.clone()),
        );
        object.insert(
            "mcp_registry_digest".to_owned(),
            Value::String(self.registry.digest().to_owned()),
        );
        data.validate(MAX_MCP_PROVIDER_START_EVENT_BYTES_V1)
            .map_err(McpProviderResponseAdmissionErrorV1::RejectedBeforeStart)?;
        let proof = match capability.acquire_live_proof() {
            Ok(proof) => proof,
            Err(error) => {
                journal.mark_reopen_required();
                return Err(McpProviderResponseAdmissionErrorV1::Fatal(error));
            }
        };
        let inner = match journal.append_mcp_provider_response_started_with_live_proof_v1(
            &proof,
            turn_admission,
            turn_id,
            data.into_value(),
        ) {
            Ok(inner) => inner,
            Err(DispatchAdmissionErrorV1::CapacityDeniedBeforeStart(error)) => {
                return Err(McpProviderResponseAdmissionErrorV1::CapacityDeniedBeforeStart(error));
            }
            Err(DispatchAdmissionErrorV1::Fatal(error)) => {
                journal.mark_reopen_required();
                return Err(McpProviderResponseAdmissionErrorV1::Fatal(error));
            }
        };
        drop(proof);
        Ok(McpProviderResponseDispatchAdmissionV1 {
            capability,
            inner,
            response_attempt_id,
            _turn_admission: turn_admission,
        })
    }

    /// Persist one canonical Provider-visible MCP tool surface.  Callers pass
    /// the typed snapshot rather than a raw journal event, and the coordinator
    /// proves that its embedded registry claim belongs to this live epoch.
    pub fn append_context_tools_v1(
        &self,
        journal: &mut SessionJournal,
        snapshot: &ToolSurfaceSnapshotV1,
    ) -> Result<JournalEvent> {
        self.validate_live_surface_snapshot_v1(snapshot)?;
        let capability = self.journal_write_capability_v1(journal)?;
        let proof = capability.acquire_live_proof()?;
        journal.append_mcp_context_tools_with_live_proof_v1(&proof, serde_json::to_value(snapshot)?)
    }

    fn validate_live_surface_snapshot_v1(&self, snapshot: &ToolSurfaceSnapshotV1) -> Result<()> {
        snapshot.validate()?;
        let claim = snapshot.mcp().ok_or_else(|| {
            OxidraError::Session(
                "MCP context.tools snapshot has no live registry surface claim".to_owned(),
            )
        })?;
        if claim.registry_epoch_id() != self.registry_epoch_id
            || claim.registry_digest() != self.registry.digest()
        {
            return Err(OxidraError::Session(
                "MCP context.tools snapshot belongs to a different live registry epoch".to_owned(),
            ));
        }
        let live_bindings = self.registry.surface_binding_snapshot_v1()?;
        if claim.bindings() != live_bindings.as_slice() {
            return Err(OxidraError::Session(
                "MCP context.tools snapshot bindings do not match the live registry surface"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.registry.definitions()
    }

    /// Produce the writer-side claim for the exact Provider-visible MCP
    /// surface of this activated epoch. Agent request construction should
    /// combine this claim with builtin/history definitions through
    /// [`McpProviderSurfaceV1::merge_with`], not copy only the registry digest.
    /// The current v2 activation reader does not yet persist the definition
    /// and output-schema digests, so this is a prerequisite for (not a
    /// substitute for) the future v3 offline proof.
    pub fn surface_claim_v1(&self) -> Result<McpProviderSurfaceV1> {
        let definitions = self.registry.definitions();
        let bindings = self.registry.surface_binding_snapshot_v1()?;
        let claim = McpSurfaceClaimV1::new(
            self.registry_epoch_id.clone(),
            self.registry.digest().to_owned(),
            bindings,
        )?;
        Ok(McpProviderSurfaceV1 { definitions, claim })
    }

    /// Authorize and dispatch the unique durable Provider call identified by
    /// `turn_id`/`call_id`. Arguments are read from the journal; callers do
    /// not supply a second Value that could diverge from the Provider output.
    pub fn execute_call<'a>(
        &'a mut self,
        journal: &'a mut SessionJournal,
        call: McpCallIdentity<'a>,
        cancellation: &'a CancellationToken,
        approval: &'a mut dyn McpCallApprovalHandler,
    ) -> impl std::future::Future<Output = Result<ToolResult>> + 'a {
        let prepared = self.prepare_durable_call(journal, call);
        async move {
            self.execute_prepared_call(journal, call, prepared, cancellation, approval)
                .await
        }
    }

    async fn execute_prepared_call(
        &mut self,
        journal: &mut SessionJournal,
        call: McpCallIdentity<'_>,
        prepared: Result<PreparedCoordinatorCall>,
        cancellation: &CancellationToken,
        approval: &mut dyn McpCallApprovalHandler,
    ) -> Result<ToolResult> {
        // Bind the exact live journal handle before consulting coordinator
        // health.  A coordinator from a pre-reopen prefix must fail closed
        // on the ownership boundary, even if its old transport was also
        // poisoned by an abandoned dispatch.
        self.require_bound_journal(journal)?;
        self.ensure_dispatch_healthy()?;
        validate_call_identity(call.turn_id, call.call_id, call.provider_name)?;

        let (arguments_sha256, durable_provenance_v4, prepared) = match prepared? {
            PreparedCoordinatorCall::Ready {
                arguments_sha256,
                durable_provenance_v4,
                prepared,
            } => (arguments_sha256, durable_provenance_v4, prepared),
            PreparedCoordinatorCall::Rejected {
                error,
                durable_provenance_v4,
            } => {
                validate_pre_start_terminal_candidate(
                    journal.read_events()?,
                    journal,
                    self,
                    call,
                    durable_provenance_v4.as_ref(),
                )?;
                return self.commit_known_failure(
                    journal,
                    call,
                    error.code,
                    error.message,
                    None,
                    None,
                    durable_provenance_v4.as_ref(),
                );
            }
        };
        let approval_context = McpCallApprovalContext {
            request: McpCallApprovalRequest {
                approval_subject: Uuid::new_v4().to_string(),
            },
            execution_coordinator_version: self.policy.coordinator_version,
            turn_id: call.turn_id.to_owned(),
            call_id: call.call_id.to_owned(),
            provider_name: call.provider_name.to_owned(),
            server_name: prepared.binding().server_name.clone(),
            raw_tool_name: prepared.binding().raw_tool_name.clone(),
            protocol_version: prepared.binding().protocol_version.clone(),
            registry_epoch_id: self.registry_epoch_id.clone(),
            registry_digest: self.registry.digest().to_owned(),
            execution_plan_digest: self.registry.execution_plan_digest().to_owned(),
            server_attempt_id: prepared.server_attempt_id().to_owned(),
            arguments_sha256: arguments_sha256.clone(),
            durable_provenance_v4,
        };

        let snapshot = journal.read_events()?;
        validate_dispatch_candidate(
            snapshot,
            journal,
            self,
            &approval_context,
            prepared.arguments(),
        )?;

        if cancellation.is_cancelled() {
            return self.commit_cancelled_before_start(
                journal,
                call,
                "MCP call was cancelled before approval",
                &approval_context,
            );
        }
        let approved = match approval
            .approve_mcp_call(&approval_context.request, cancellation)
            .await
        {
            Ok(approved) => approved,
            Err(OxidraError::Interrupted) => {
                return self.commit_cancelled_before_start(
                    journal,
                    call,
                    "MCP call approval was cancelled",
                    &approval_context,
                );
            }
            Err(error) => return Err(error),
        };
        if !approved {
            return self.commit_known_failure(
                journal,
                call,
                "approval_required",
                "MCP tool call requires user confirmation".to_owned(),
                Some(&approval_context),
                None,
                approval_context.durable_provenance_v4.as_ref(),
            );
        }
        let approved_call = ApprovedMcpCall {
            approval: approval_context,
            prepared,
        };

        // The mutable journal borrow spans approval, so no in-process writer
        // can change the prefix. Re-read anyway and bind the durable permit to
        // the exact post-approval snapshot that authorizes dispatch.
        let snapshot = journal.read_events()?;
        validate_dispatch_candidate(
            snapshot,
            journal,
            self,
            &approved_call.approval,
            approved_call.prepared.arguments(),
        )?;

        let admission = journal
            .append_mcp_tool_started_v1(
                call.turn_id,
                started_data(&approved_call.approval, approved_call.prepared.arguments()),
            )
            .map_err(|error| error.into_error())?;
        let started_seq = admission.started_seq();
        let mut started_guard = McpStartedCallGuard::new(
            journal,
            admission,
            Arc::clone(&self.dispatch_poisoned),
            approved_call.prepared.transport_abort_handle(),
        );
        let permit = DispatchPermit {
            permit_version: self.policy.dispatch_permit_version,
            coordinator_id: self.coordinator_id.clone(),
            registry_epoch_id: self.registry_epoch_id.clone(),
            registry_digest: self.registry.digest().to_owned(),
            turn_id: call.turn_id.to_owned(),
            call_id: call.call_id.to_owned(),
            provider_name: call.provider_name.to_owned(),
            server_name: approved_call.prepared.binding().server_name.clone(),
            raw_tool_name: approved_call.prepared.binding().raw_tool_name.clone(),
            protocol_version: approved_call.prepared.binding().protocol_version.clone(),
            server_attempt_id: approved_call.prepared.server_attempt_id().to_owned(),
            arguments_sha256,
            started_seq,
        };

        if cancellation.is_cancelled() {
            let result = ToolResult::error(
                call.call_id,
                "cancelled",
                "MCP call was cancelled before dispatch",
            );
            started_guard.terminalize(|journal, admission| {
                journal.commit_mcp_tool_terminal_v1(
                    admission,
                    "tool.cancelled",
                    terminal_data(&approved_call.approval, started_seq, &result, true, None),
                )?;
                Ok(())
            })?;
            return Ok(result);
        }

        let ApprovedMcpCall { approval, prepared } = approved_call;
        let dispatched = self.registry.dispatch(permit, prepared, cancellation).await;
        match dispatched {
            Ok(raw_result) => {
                if self.policy.coordinator_version == MCP_EXECUTION_COORDINATOR_VERSION_V4 {
                    let raw_value = raw_result.into_value();
                    match McpModelOutputV1::from_raw_result_v1(&raw_value) {
                        Ok(model_output) => {
                            let result = ToolResult {
                                call_id: call.call_id.to_owned(),
                                output: model_output.as_value(),
                                is_error: model_output.is_error(),
                                error_code: model_output
                                    .is_error()
                                    .then(|| "mcp_tool_error".to_owned()),
                            };
                            started_guard.terminalize(|journal, admission| {
                                journal.commit_mcp_tool_terminal_v1(
                                    admission,
                                    "tool.completed",
                                    terminal_data(
                                        &approval,
                                        started_seq,
                                        &result,
                                        false,
                                        Some(raw_value),
                                    ),
                                )?;
                                Ok(())
                            })?;
                            Ok(result)
                        }
                        Err(error) => {
                            started_guard.abort_transport();
                            let result = ToolResult::error(
                                call.call_id,
                                "in_doubt",
                                format!(
                                    "MCP result cannot be projected into the frozen model output profile: {error}"
                                ),
                            );
                            started_guard.terminalize(|journal, admission| {
                                journal.commit_mcp_tool_terminal_v1(
                                    admission,
                                    "tool.in_doubt",
                                    terminal_data(&approval, started_seq, &result, false, None),
                                )?;
                                Ok(())
                            })?;
                            Ok(result)
                        }
                    }
                } else {
                    // The historical coordinator/call-chain v1/v2 contract
                    // returns the complete bounded raw result unchanged.
                    let raw_value = raw_result.as_value();
                    let is_error = raw_value.get("isError").and_then(Value::as_bool) == Some(true);
                    let result = ToolResult {
                        call_id: call.call_id.to_owned(),
                        output: raw_value.clone(),
                        is_error,
                        error_code: is_error.then(|| "mcp_tool_error".to_owned()),
                    };
                    started_guard.terminalize(|journal, admission| {
                        journal.commit_mcp_tool_terminal_v1(
                            admission,
                            "tool.completed",
                            terminal_data(&approval, started_seq, &result, false, None),
                        )?;
                        Ok(())
                    })?;
                    Ok(result)
                }
            }
            Err(error) if error.in_doubt || error.interrupted => {
                let result = ToolResult::error(call.call_id, "in_doubt", error.message);
                started_guard.terminalize(|journal, admission| {
                    journal.commit_mcp_tool_terminal_v1(
                        admission,
                        "tool.in_doubt",
                        terminal_data(&approval, started_seq, &result, false, None),
                    )?;
                    Ok(())
                })?;
                Ok(result)
            }
            Err(error) => started_guard.terminalize(|journal, admission| {
                let result = ToolResult::error(call.call_id, error.code, error.message);
                journal.commit_mcp_tool_terminal_v1(
                    admission,
                    "tool.completed",
                    terminal_data(&approval, started_seq, &result, false, None),
                )?;
                Ok(result)
            }),
        }
    }

    fn require_bound_journal(&self, journal: &SessionJournal) -> Result<()> {
        if journal.session_id() != self.session_id || journal.handle_id() != self.journal_handle_id
        {
            return Err(OxidraError::Session(
                "MCP coordinator cannot dispatch into a different session journal handle"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_dispatch_healthy(&self) -> Result<()> {
        if !self.journal_authority_active.is_active() {
            return Err(OxidraError::Session(
                "MCP coordinator is shut down and cannot dispatch another call".to_owned(),
            ));
        }
        if self.dispatch_poisoned.load(Ordering::Acquire) {
            return Err(OxidraError::Session(
                "MCP coordinator dispatch was abandoned after tool.started; shut it down and reconnect before dispatching another call"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn durable_call_provenance_v4(
        &self,
        durable_call: &ValidatedDurableMcpCall,
    ) -> Result<Option<McpDurableCallProvenanceV4>> {
        if self.policy.coordinator_version != MCP_EXECUTION_COORDINATOR_VERSION_V4 {
            return Ok(None);
        }
        let response_attempt_id = durable_call.response_attempt_id.clone().ok_or_else(|| {
            OxidraError::Session(
                "MCP coordinator v4 call has no validated response attempt identity".to_owned(),
            )
        })?;
        let surface = durable_call.surface.as_ref().ok_or_else(|| {
            OxidraError::Session(
                "MCP coordinator v4 call has no validated Provider surface provenance".to_owned(),
            )
        })?;
        let binding = self
            .registry
            .bindings()
            .find(|binding| binding.provider_name == durable_call.provider_name)
            .ok_or_else(|| {
                OxidraError::Session(
                    "MCP coordinator v4 call has no matching live registry binding".to_owned(),
                )
            })?;
        Ok(Some(McpDurableCallProvenanceV4 {
            response_attempt_id,
            response_started_seq: durable_call.response_started_seq,
            response_completed_seq: durable_call.response_completed_seq,
            surface_event_seq: surface.surface_event_seq,
            surface_digest: surface.surface_digest.clone(),
            definition_digest: surface.definition_digest.clone(),
            output_schema_digest: surface.output_schema_digest.clone(),
            server_name: binding.server_name.clone(),
            raw_tool_name: binding.raw_tool_name.clone(),
            protocol_version: binding.protocol_version.clone(),
            arguments_sha256: durable_call.arguments_sha256.clone(),
        }))
    }

    fn prepare_durable_call(
        &self,
        journal: &SessionJournal,
        call: McpCallIdentity<'_>,
    ) -> Result<PreparedCoordinatorCall> {
        self.require_bound_journal(journal)?;
        self.ensure_dispatch_healthy()?;
        validate_call_identity(call.turn_id, call.call_id, call.provider_name)?;
        if !journal.in_doubt()?.is_empty() {
            return Err(OxidraError::Session(
                "MCP dispatch is blocked until every in-doubt tool is explicitly resolved"
                    .to_owned(),
            ));
        }
        let events = journal.read_events()?;
        validate_mcp_call_chain(&events)?;
        let activation_seq = validate_activation(&events, self)?;
        let durable_call = validated_durable_mcp_call(&events, call.turn_id, call.call_id)?;
        validate_call_after_activation(&durable_call, activation_seq, self)?;
        if durable_call.provider_name != call.provider_name {
            return Err(OxidraError::Session(
                "MCP call identity does not match the durable Provider call".to_owned(),
            ));
        }
        let durable_provenance_v4 = self.durable_call_provenance_v4(&durable_call)?;

        let arguments = match PreflightedJsonValue::new(durable_call.arguments).into_validated() {
            Ok(arguments) => arguments,
            Err(error) => {
                return Ok(PreparedCoordinatorCall::Rejected {
                    error,
                    durable_provenance_v4,
                });
            }
        };
        let arguments_sha256 = argument_digest_v1(arguments.as_value())?;
        if arguments_sha256 != durable_call.arguments_sha256 {
            return Err(OxidraError::Session(
                "validated MCP arguments no longer match their durable digest".to_owned(),
            ));
        }
        match self.registry.prepare_call(call.provider_name, arguments) {
            Ok(prepared) => Ok(PreparedCoordinatorCall::Ready {
                arguments_sha256,
                durable_provenance_v4,
                prepared,
            }),
            Err(error) => Ok(PreparedCoordinatorCall::Rejected {
                error,
                durable_provenance_v4,
            }),
        }
    }

    fn commit_cancelled_before_start(
        &self,
        journal: &mut SessionJournal,
        call: McpCallIdentity<'_>,
        message: &str,
        approval: &McpCallApprovalContext,
    ) -> Result<ToolResult> {
        let result = ToolResult::error(call.call_id, "cancelled", message);
        let policy = self.policy;
        let capability = self.journal_write_capability_v1(journal)?;
        let mut data = json!({
            "call_id": call.call_id,
            "tool": call.provider_name,
            "output": result.output,
            "is_error": true,
            "error_code": "cancelled",
            "before_start": true,
            "mcp_execution_coordinator_version": policy.coordinator_version,
            "registry_epoch_id": self.registry_epoch_id,
            "registry_digest": self.registry.digest(),
        });
        if policy.coordinator_version == MCP_EXECUTION_COORDINATOR_VERSION_V4 {
            data["mcp"] = pre_start_provenance_data_v4(
                approval.durable_provenance_v4.as_ref().ok_or_else(|| {
                    OxidraError::Session(
                        "MCP coordinator v4 cancellation has no durable call provenance".to_owned(),
                    )
                })?,
                self,
            );
        }
        capability.append_tool_cancelled_before_start_to_journal(journal, call.turn_id, data)?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_known_failure(
        &self,
        journal: &mut SessionJournal,
        call: McpCallIdentity<'_>,
        code: &str,
        message: String,
        approval: Option<&McpCallApprovalContext>,
        started_seq: Option<u64>,
        durable_provenance_v4: Option<&McpDurableCallProvenanceV4>,
    ) -> Result<ToolResult> {
        let result = ToolResult::error(call.call_id, code, message);
        let policy = self.policy;
        let mut data = json!({
            "call_id": call.call_id,
            "tool": call.provider_name,
            "output": result.output,
            "is_error": true,
            "error_code": result.error_code,
            "mcp_execution_coordinator_version": policy.coordinator_version,
            "registry_epoch_id": self.registry_epoch_id,
            "registry_digest": self.registry.digest(),
        });
        if policy.coordinator_version == MCP_EXECUTION_COORDINATOR_VERSION_V4 {
            data["mcp"] = pre_start_provenance_data_v4(
                durable_provenance_v4.ok_or_else(|| {
                    OxidraError::Session(
                        "MCP coordinator v4 pre-start terminal has no durable call provenance"
                            .to_owned(),
                    )
                })?,
                self,
            );
        } else if let Some(approval) = approval {
            data["mcp"] = provenance_data(approval);
        }
        if let Some(started_seq) = started_seq {
            data["started_seq"] = Value::from(started_seq);
        }
        let capability = self.journal_write_capability_v1(journal)?;
        capability.append_tool_completed_before_start_to_journal(journal, call.turn_id, data)?;
        Ok(result)
    }

    pub async fn shutdown(&mut self) {
        self.journal_authority_active.begin_revoke();
        // Native transport abort must happen before waiting for a possibly
        // blocking journal fsync. Otherwise coordinator shutdown/drop could
        // strand a live MCP server behind the authority drain.
        self.registry.abort_transports();
        self.journal_authority_active.wait_for_writers();
        self.registry.shutdown().await;
        self.journal_execution_lease.take();
    }
}

impl Drop for McpExecutionCoordinator {
    fn drop(&mut self) {
        // A journal capability is live authority, not a detached copy of the
        // activation strings. Revoking it before the registry is dropped
        // prevents late callers from authoring MCP lifecycle events after the
        // coordinator that owns the dispatch epoch has gone away.
        self.journal_authority_active.begin_revoke();
        self.registry.abort_transports();
        self.journal_authority_active.wait_for_writers();
        self.journal_execution_lease.take();
    }
}

struct McpStartedCallGuard<'journal> {
    journal: &'journal mut SessionJournal,
    admission: McpToolDispatchAdmissionV1,
    dispatch_poisoned: Arc<AtomicBool>,
    transport_abort: TransportAbortHandle,
    terminalized: bool,
}

impl<'journal> McpStartedCallGuard<'journal> {
    fn new(
        journal: &'journal mut SessionJournal,
        admission: McpToolDispatchAdmissionV1,
        dispatch_poisoned: Arc<AtomicBool>,
        transport_abort: TransportAbortHandle,
    ) -> Self {
        // `tool.started` is already durable when this guard is created.  Arm
        // the coordinator poison before returning so leaking/forgetting the
        // future cannot make the old transport reusable without a terminal.
        dispatch_poisoned.store(true, Ordering::Release);
        Self {
            journal,
            admission,
            dispatch_poisoned,
            transport_abort,
            terminalized: false,
        }
    }

    fn abort_transport(&self) {
        self.transport_abort.abort();
    }

    fn terminalize<T>(
        &mut self,
        commit: impl FnOnce(&mut SessionJournal, &mut McpToolDispatchAdmissionV1) -> Result<T>,
    ) -> Result<T> {
        let result = commit(self.journal, &mut self.admission)?;
        self.terminalized = true;
        self.dispatch_poisoned.store(false, Ordering::Release);
        Ok(result)
    }
}

impl Drop for McpStartedCallGuard<'_> {
    fn drop(&mut self) {
        if !self.terminalized {
            // A dropped future cannot await `Transport::terminate`.  Publish
            // a synchronous abort request before poisoning the journal; the
            // independent native reaper can then terminate and reap the exact
            // process tree without depending on this borrowed guard or Tokio.
            self.transport_abort.abort();
            self.journal.mark_reopen_required();
        }
    }
}

struct ApprovedMcpCall {
    approval: McpCallApprovalContext,
    prepared: PreparedMcpRegistryCall,
}

enum PreparedCoordinatorCall {
    Ready {
        arguments_sha256: String,
        durable_provenance_v4: Option<McpDurableCallProvenanceV4>,
        prepared: PreparedMcpRegistryCall,
    },
    Rejected {
        error: McpCallError,
        durable_provenance_v4: Option<McpDurableCallProvenanceV4>,
    },
}

pub(super) struct DispatchPermit {
    permit_version: u32,
    coordinator_id: String,
    registry_epoch_id: String,
    registry_digest: String,
    turn_id: String,
    call_id: String,
    provider_name: String,
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
    server_attempt_id: String,
    arguments_sha256: String,
    started_seq: u64,
}

impl DispatchPermit {
    pub(super) fn validate(
        &self,
        coordinator_id: &str,
        registry_epoch_id: &str,
        registry_digest: &str,
        prepared: &PreparedMcpRegistryCall,
    ) -> std::result::Result<(), McpCallError> {
        let prepared_arguments_sha256 =
            argument_digest_v1(prepared.arguments()).map_err(|error| McpCallError {
                code: "dispatch_permit_invalid",
                message: format!("cannot verify MCP dispatch arguments: {error}"),
                in_doubt: false,
                interrupted: false,
            })?;
        let valid = self.permit_version == MCP_COORDINATOR_POLICY_V1.dispatch_permit_version
            && self.coordinator_id == coordinator_id
            && self.registry_epoch_id == registry_epoch_id
            && self.registry_digest == registry_digest
            && self.provider_name == prepared.binding().provider_name
            && self.server_name == prepared.binding().server_name
            && self.raw_tool_name == prepared.binding().raw_tool_name
            && self.protocol_version == prepared.binding().protocol_version
            && self.server_attempt_id == prepared.server_attempt_id()
            && self.arguments_sha256 == prepared_arguments_sha256
            && !self.turn_id.is_empty()
            && !self.call_id.is_empty()
            && self.started_seq > 0;
        if !valid {
            return Err(McpCallError {
                code: "dispatch_permit_invalid",
                message: "MCP dispatch permit does not match the prepared call".to_owned(),
                in_doubt: false,
                interrupted: false,
            });
        }
        Ok(())
    }
}

fn validate_call_identity(turn_id: &str, call_id: &str, provider_name: &str) -> Result<()> {
    for (label, value) in [
        ("turn_id", turn_id),
        ("call_id", call_id),
        ("provider_name", provider_name),
    ] {
        if value.trim().is_empty() || value.len() > 128 {
            return Err(OxidraError::Mcp(format!(
                "MCP {label} must contain 1-128 bytes"
            )));
        }
    }
    Ok(())
}

fn ensure_no_unresolved_in_doubt_tools(journal: &SessionJournal) -> Result<()> {
    let pending = journal.in_doubt()?;
    if pending.is_empty() {
        return Ok(());
    }
    Err(OxidraError::Session(format!(
        "MCP resume is blocked until every in-doubt tool is explicitly resolved ({} unresolved)",
        pending.len()
    )))
}

fn validate_dispatch_candidate(
    mut events: Vec<JournalEvent>,
    journal: &SessionJournal,
    coordinator: &McpExecutionCoordinator,
    approval: &McpCallApprovalContext,
    arguments: &Value,
) -> Result<()> {
    validate_mcp_call_chain(&events)?;
    let activation_seq = validate_activation(&events, coordinator)?;

    let durable_call = validated_durable_mcp_call(&events, &approval.turn_id, &approval.call_id)?;
    validate_call_after_activation(&durable_call, activation_seq, coordinator)?;
    if durable_call.provider_name != approval.provider_name
        || durable_call.arguments_sha256 != approval.arguments_sha256
        || argument_digest_v1(arguments)? != approval.arguments_sha256
    {
        return Err(OxidraError::Session(
            "MCP dispatch candidate does not match the durable Provider call".to_owned(),
        ));
    }

    events.push(JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq: journal.next_seq(),
        ts: Utc::now(),
        kind: "tool.started".to_owned(),
        session_id: journal.session_id().to_owned(),
        turn_id: Some(approval.turn_id.clone()),
        data: started_data(approval, arguments),
    });
    validate_mcp_call_chain(&events)?;
    let state = provider_request_slot_state_for_version(
        coordinator.policy.provider_slot_version,
        &events,
        &approval.turn_id,
    )?;
    if state != ProviderRequestSlotState::AwaitingTools {
        return Err(OxidraError::Session(format!(
            "MCP dispatch cannot acquire the Provider tool slot from state {state:?}"
        )));
    }
    Ok(())
}

fn validate_pre_start_terminal_candidate(
    mut events: Vec<JournalEvent>,
    journal: &SessionJournal,
    coordinator: &McpExecutionCoordinator,
    call: McpCallIdentity<'_>,
    durable_provenance_v4: Option<&McpDurableCallProvenanceV4>,
) -> Result<()> {
    validate_mcp_call_chain(&events)?;
    let activation_seq = validate_activation(&events, coordinator)?;
    let durable_call = validated_durable_mcp_call(&events, call.turn_id, call.call_id)?;
    validate_call_after_activation(&durable_call, activation_seq, coordinator)?;
    if durable_call.provider_name != call.provider_name {
        return Err(OxidraError::Session(
            "MCP rejected call does not match the durable Provider call".to_owned(),
        ));
    }
    let mut data = json!({
        "call_id": call.call_id,
        "tool": call.provider_name,
        "output":{"error":{"code":"validation_error","message":"rejected before dispatch"}},
        "is_error":true,
        "error_code":"validation_error",
        "mcp_execution_coordinator_version": coordinator.policy.coordinator_version,
        "registry_epoch_id": coordinator.registry_epoch_id,
        "registry_digest": coordinator.registry.digest(),
    });
    if coordinator.policy.coordinator_version == MCP_EXECUTION_COORDINATOR_VERSION_V4 {
        data["mcp"] = pre_start_provenance_data_v4(
            durable_provenance_v4.ok_or_else(|| {
                OxidraError::Session(
                    "MCP coordinator v4 rejected call has no durable provenance".to_owned(),
                )
            })?,
            coordinator,
        );
    }
    events.push(JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq: journal.next_seq(),
        ts: Utc::now(),
        kind: "tool.completed".to_owned(),
        session_id: journal.session_id().to_owned(),
        turn_id: Some(call.turn_id.to_owned()),
        data,
    });
    validate_mcp_call_chain(&events)?;
    provider_request_slot_state_for_version(
        coordinator.policy.provider_slot_version,
        &events,
        call.turn_id,
    )?;
    Ok(())
}

fn durable_activation(events: &[JournalEvent]) -> Result<&JournalEvent> {
    let mut activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND);
    let activation = activations.next().ok_or_else(|| {
        OxidraError::Session(
            "MCP coordinator resume requires a durable registry activation".to_owned(),
        )
    })?;
    if activations.next().is_some() {
        return Err(OxidraError::Session(
            "MCP coordinator requires exactly one registry activation per session".to_owned(),
        ));
    }
    activation_policy(activation)?;
    Ok(activation)
}

fn required_activation_string<'a>(activation: &'a JournalEvent, field: &str) -> Result<&'a str> {
    activation
        .data
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "mcp.registry.activated at seq {} has no valid {field}",
                activation.seq
            ))
        })
}

fn validate_activation(
    events: &[JournalEvent],
    coordinator: &McpExecutionCoordinator,
) -> Result<u64> {
    let activation = durable_activation(events)?;
    let policy = activation_policy(activation)?;
    if policy != coordinator.policy {
        return Err(OxidraError::Session(
            "MCP registry activation policy does not match the live coordinator".to_owned(),
        ));
    }
    match policy.coordinator_version {
        MCP_EXECUTION_COORDINATOR_VERSION_V1 => {
            let expected_provider_names = coordinator
                .registry
                .bindings()
                .map(|binding| binding.provider_name.clone())
                .collect::<BTreeSet<_>>();
            let recorded_provider_names = activation
                .data
                .get("provider_names")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "mcp.registry.activated at seq {} has no provider_names",
                        activation.seq
                    ))
                })?
                .iter()
                .map(|value| {
                    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                        OxidraError::Session(format!(
                            "mcp.registry.activated at seq {} has a non-string provider name",
                            activation.seq
                        ))
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            if recorded_provider_names != expected_provider_names {
                return Err(OxidraError::Session(
                    "MCP registry activation provider_names do not match the live registry"
                        .to_owned(),
                ));
            }
        }
        MCP_EXECUTION_COORDINATOR_VERSION_V2 => {
            let expected_bindings =
                serde_json::to_value(coordinator.registry.binding_identity_snapshot())?;
            if activation.data.get("bindings") != Some(&expected_bindings) {
                return Err(OxidraError::Session(
                    "MCP registry activation bindings do not match the live registry".to_owned(),
                ));
            }
        }
        MCP_EXECUTION_COORDINATOR_VERSION_V4 => {
            let expected_bindings =
                serde_json::to_value(coordinator.registry.surface_binding_snapshot_v1()?)?;
            if activation.data.get("bindings") != Some(&expected_bindings)
                || activation
                    .data
                    .get("surface_claim_version")
                    .and_then(Value::as_u64)
                    != Some(u64::from(MCP_SURFACE_CLAIM_VERSION_V1))
            {
                return Err(OxidraError::Session(
                    "MCP registry activation surface bindings do not match the live registry"
                        .to_owned(),
                ));
            }
        }
        _ => unreachable!("activation_policy rejected an unknown coordinator version"),
    }
    let activation_matches = activation.seq == coordinator.activation_seq && {
        activation.kind == MCP_REGISTRY_ACTIVATED_KIND
            && activation.turn_id.is_none()
            && activation
                .data
                .get("coordinator_id")
                .and_then(Value::as_str)
                == Some(&coordinator.coordinator_id)
            && activation
                .data
                .get("registry_epoch_id")
                .and_then(Value::as_str)
                == Some(&coordinator.registry_epoch_id)
            && activation
                .data
                .get("registry_digest")
                .and_then(Value::as_str)
                == Some(coordinator.registry.digest())
            && activation
                .data
                .get("coordinator_version")
                .and_then(Value::as_u64)
                == Some(u64::from(policy.coordinator_version))
            && activation
                .data
                .get("call_chain_validator_version")
                .and_then(Value::as_u64)
                == Some(u64::from(policy.call_chain_validator_version))
            && activation
                .data
                .get("registry_version")
                .and_then(Value::as_u64)
                == Some(u64::from(policy.registry_version))
            && activation
                .data
                .get("stdio_kernel_version")
                .and_then(Value::as_u64)
                == Some(u64::from(policy.stdio_kernel_version))
            && activation
                .data
                .get("schema_profile_version")
                .and_then(Value::as_u64)
                == Some(u64::from(policy.schema_profile_version))
            && activation.data.get("config_sha256").and_then(Value::as_str)
                == Some(coordinator.registry.config_sha256())
            && activation
                .data
                .get("execution_plan_digest")
                .and_then(Value::as_str)
                == Some(coordinator.registry.execution_plan_digest())
    };
    if !activation_matches {
        return Err(OxidraError::Session(
            "MCP registry activation does not match the live coordinator".to_owned(),
        ));
    }

    Ok(activation.seq)
}

fn validate_new_activation(events: &[JournalEvent]) -> Result<()> {
    if events
        .iter()
        .any(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
    {
        return Err(OxidraError::Session(
            "MCP coordinator does not replace an existing registry activation".to_owned(),
        ));
    }
    if let Some(pending) = validate_compaction_boundary_chain(events)?.latest_pending() {
        return Err(OxidraError::Session(format!(
            "MCP registry activation cannot cross pending compaction boundary {}",
            pending.boundary.boundary_id
        )));
    }
    Ok(())
}

fn activation_policy(event: &JournalEvent) -> Result<McpCoordinatorPolicy> {
    match event
        .data
        .get("coordinator_version")
        .and_then(Value::as_u64)
    {
        Some(version) if version == u64::from(MCP_EXECUTION_COORDINATOR_VERSION_V1) => {
            Ok(MCP_COORDINATOR_POLICY_V1)
        }
        Some(version) if version == u64::from(MCP_EXECUTION_COORDINATOR_VERSION_V2) => {
            Ok(MCP_COORDINATOR_POLICY_V2)
        }
        Some(version) if version == u64::from(MCP_EXECUTION_COORDINATOR_VERSION_V4) => {
            Ok(MCP_COORDINATOR_POLICY_V4)
        }
        Some(version) => Err(OxidraError::Session(format!(
            "unsupported MCP execution coordinator version {version} at seq {}",
            event.seq
        ))),
        None => Err(OxidraError::Session(format!(
            "mcp.registry.activated at seq {} has no coordinator_version",
            event.seq
        ))),
    }
}

fn validate_call_after_activation(
    durable_call: &ValidatedDurableMcpCall,
    activation_seq: u64,
    coordinator: &McpExecutionCoordinator,
) -> Result<()> {
    if durable_call.response_started_seq <= activation_seq
        || durable_call.response_completed_seq <= activation_seq
    {
        return Err(OxidraError::Session(
            "MCP Provider call was created before the active registry epoch".to_owned(),
        ));
    }
    if durable_call.registry_epoch_id != coordinator.registry_epoch_id
        || durable_call.registry_digest != coordinator.registry.digest()
    {
        return Err(OxidraError::Session(
            "MCP Provider call does not use the active registry epoch".to_owned(),
        ));
    }
    Ok(())
}

fn started_data(approval: &McpCallApprovalContext, arguments: &Value) -> Value {
    json!({
        "call_id": approval.call_id,
        "tool": approval.provider_name,
        "arguments": arguments,
        "mcp": provenance_data(approval),
    })
}

fn terminal_data(
    approval: &McpCallApprovalContext,
    started_seq: u64,
    result: &ToolResult,
    before_dispatch: bool,
    raw_result: Option<Value>,
) -> Value {
    let mut data = json!({
        "started_seq": started_seq,
        "call_id": result.call_id,
        "tool": approval.provider_name,
        "output": result.output,
        "is_error": result.is_error,
        "error_code": result.error_code,
        "before_dispatch": before_dispatch,
        "mcp": provenance_data(approval),
    });
    if let Some(raw_result) = raw_result {
        data["mcp_raw_result"] = raw_result;
    }
    data
}

fn provenance_data(approval: &McpCallApprovalContext) -> Value {
    let mut data = json!({
        "execution_coordinator_version": approval.execution_coordinator_version,
        "dispatch_permit_version": MCP_DISPATCH_PERMIT_VERSION_V1,
        "argument_digest_version": MCP_ARGUMENT_DIGEST_VERSION_V1,
        "registry_version": MCP_TOOL_REGISTRY_VERSION_V1,
        "registry_epoch_id": approval.registry_epoch_id,
        "registry_digest": approval.registry_digest,
        "execution_plan_digest": approval.execution_plan_digest,
        "server_name": approval.server_name,
        "raw_tool_name": approval.raw_tool_name,
        "protocol_version": approval.protocol_version,
        "server_attempt_id": approval.server_attempt_id,
        "arguments_sha256": approval.arguments_sha256,
    });
    if approval.execution_coordinator_version == MCP_EXECUTION_COORDINATOR_VERSION_V4 {
        let provenance = approval
            .durable_provenance_v4
            .as_ref()
            .expect("coordinator v4 approval has durable provenance");
        data["surface_claim_version"] = Value::from(MCP_SURFACE_CLAIM_VERSION_V1);
        data["response_attempt_id"] = Value::String(provenance.response_attempt_id.clone());
        data["response_started_seq"] = Value::from(provenance.response_started_seq);
        data["response_completed_seq"] = Value::from(provenance.response_completed_seq);
        data["surface_event_seq"] = Value::from(provenance.surface_event_seq);
        data["surface_digest"] = Value::String(provenance.surface_digest.clone());
        data["definition_digest"] = Value::String(provenance.definition_digest.clone());
        data["output_schema_digest"] = provenance
            .output_schema_digest
            .as_ref()
            .map_or(Value::Null, |digest| Value::String(digest.clone()));
    }
    data
}

fn pre_start_provenance_data_v4(
    provenance: &McpDurableCallProvenanceV4,
    coordinator: &McpExecutionCoordinator,
) -> Value {
    json!({
        "execution_coordinator_version": MCP_EXECUTION_COORDINATOR_VERSION_V4,
        "argument_digest_version": MCP_ARGUMENT_DIGEST_VERSION_V1,
        "registry_version": MCP_TOOL_REGISTRY_VERSION_V1,
        "surface_claim_version": MCP_SURFACE_CLAIM_VERSION_V1,
        "registry_epoch_id": coordinator.registry_epoch_id,
        "registry_digest": coordinator.registry.digest(),
        "execution_plan_digest": coordinator.registry.execution_plan_digest(),
        "server_name": provenance.server_name,
        "raw_tool_name": provenance.raw_tool_name,
        "protocol_version": provenance.protocol_version,
        "arguments_sha256": provenance.arguments_sha256,
        "response_attempt_id": provenance.response_attempt_id,
        "response_started_seq": provenance.response_started_seq,
        "response_completed_seq": provenance.response_completed_seq,
        "surface_event_seq": provenance.surface_event_seq,
        "surface_digest": provenance.surface_digest,
        "definition_digest": provenance.definition_digest,
        "output_schema_digest": provenance.output_schema_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContextLimits;
    use crate::context::{ContextRuntime, measure_prepared_request};
    use crate::provider::{
        ProviderEvent, ResponseProvider, UncommittedProviderOutcomeV1, prepared_request_body,
    };
    use crate::session::{SessionHeader, SessionStore};
    use crate::types::Usage;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, mpsc};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn event(seq: u64, turn_id: Option<&str>, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            data,
        }
    }

    struct NoopStreamObserver;

    impl crate::provider::stream_observer_sealed::Sealed for NoopStreamObserver {}

    impl StreamObserver for NoopStreamObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CapturingStreamObserver {
        retries: usize,
        provider_controlled_events: usize,
    }

    impl crate::provider::stream_observer_sealed::Sealed for CapturingStreamObserver {}

    impl StreamObserver for CapturingStreamObserver {
        fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
            match event {
                ProviderEvent::TextDelta(_)
                | ProviderEvent::FunctionArgumentsDelta { .. }
                | ProviderEvent::Unknown { .. } => {
                    self.provider_controlled_events += 1;
                }
                ProviderEvent::Retry { .. } => self.retries += 1,
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingProvider {
        calls: AtomicUsize,
        request_body: Mutex<Option<Value>>,
        provider_usage_domain: Option<String>,
        provider_model: Option<String>,
        emit_precommit_events: bool,
    }

    #[async_trait::async_trait]
    impl ResponseProvider for RecordingProvider {
        async fn respond(
            &self,
            request: ResponseRequest,
            observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> UncommittedProviderOutcomeV1 {
            self.calls.fetch_add(1, Ordering::SeqCst);
            macro_rules! emit {
                ($event:expr) => {
                    if let Err(error) = observer.on_event($event) {
                        return UncommittedProviderOutcomeV1::failure(error);
                    }
                };
            }
            if self.emit_precommit_events {
                emit!(ProviderEvent::TextDelta(
                    "provider-controlled text".to_owned()
                ));
                emit!(ProviderEvent::FunctionArgumentsDelta {
                    item_id: Some("fixture-item".to_owned()),
                    call_id: Some("fixture-call".to_owned()),
                    delta: "{\"command\":\"side effect\"}".to_owned(),
                });
                emit!(ProviderEvent::Unknown {
                    event_type: "future.function_call.ready".to_owned(),
                    payload: json!({
                        "call_id":"fixture-call",
                        "name":"shell",
                        "arguments":{"command":"side effect"},
                    }),
                });
                let mut deep_unknown_payload = Value::Null;
                for _ in 0..50_000 {
                    deep_unknown_payload = Value::Array(vec![deep_unknown_payload]);
                }
                emit!(ProviderEvent::Unknown {
                    event_type: "future.deep_payload".to_owned(),
                    payload: deep_unknown_payload,
                });
                emit!(ProviderEvent::Retry {
                    attempt: 1,
                    classification: crate::provider::ProviderRetryClassV1::TransportBeforeResponse,
                });
            }
            let provider_name = request
                .tools
                .first()
                .expect("prepared Provider request has an MCP tool")
                .name
                .clone();
            *self.request_body.lock().expect("record Provider request") =
                Some(prepared_request_body(&request, "fixture-model"));
            let output_item = json!({
                "type":"function_call",
                "call_id":"fixture-call",
                "name":provider_name,
                "arguments":"{}",
            });
            UncommittedProviderOutcomeV1::success(AssistantTurn {
                raw_response: json!({"output":[output_item.clone()]}),
                output_items: vec![output_item],
                text: "fixture response".to_owned(),
                tool_calls: vec![ToolCall {
                    id: "fixture-call".to_owned(),
                    name: provider_name,
                    arguments: json!({}),
                }],
                usage: Usage::default(),
                unknown_stream_events: Vec::new(),
            })
        }
    }

    impl RecordingProvider {
        fn prepare_request(&self, request: ResponseRequest) -> Result<PreparedResponseRequest> {
            PreparedResponseRequest::from_responses_request(
                request,
                "fixture-model",
                self.provider_usage_domain.clone().unwrap_or_else(|| {
                    ContextRuntime::for_tests("fixture-model", ContextLimits::default())
                        .provider_usage_domain
                }),
            )
        }
    }

    impl crate::provider::mcp_exact_wire_sealed::Sealed for RecordingProvider {}

    #[async_trait::async_trait]
    impl McpExactWireProvider for RecordingProvider {
        fn mcp_provider_usage_domain_v1(&self) -> Result<String> {
            Ok(self.provider_usage_domain.clone().unwrap_or_else(|| {
                ContextRuntime::for_tests("fixture-model", ContextLimits::default())
                    .provider_usage_domain
            }))
        }

        fn mcp_provider_model_v1(&self) -> Result<String> {
            Ok(self
                .provider_model
                .clone()
                .unwrap_or_else(|| "fixture-model".to_owned()))
        }

        async fn respond_exact_mcp_v1(
            &self,
            request: PreparedResponseRequest,
            observer: &mut dyn StreamObserver,
            cancellation: CancellationToken,
        ) -> UncommittedProviderOutcomeV1 {
            let exact_body = request.body().clone();
            let logical_request = request.request().clone();
            let result = self.respond(logical_request, observer, cancellation).await;
            *self
                .request_body
                .lock()
                .expect("record exact Provider body") = Some(exact_body);
            result
        }
    }

    fn provider_request_fixture() -> ResponseRequest {
        ResponseRequest {
            instructions: Some("exact instructions".to_owned()),
            input: vec![json!({"role":"user","content":"exact input"})],
            tools: vec![ToolDefinition {
                name: "fixture_tool".to_owned(),
                description: "fixture definition".to_owned(),
                input_schema: json!({
                    "type":"object",
                    "properties":{"text":{"type":"string"}},
                    "required":["text"],
                    "additionalProperties":false,
                }),
            }],
            model: None,
            max_output_tokens: Some(123),
        }
    }

    fn prepared_request_drop_fixture() -> (
        TempDir,
        SessionJournal,
        TurnTransactionAdmissionV1,
        McpJournalWriteCapabilityV1,
        ProviderResponseDispatchAdmissionV1,
        String,
    ) {
        let directory = TempDir::new().expect("create prepared request fixture directory");
        let store = SessionStore::new(directory.path()).expect("create prepared request store");
        let mut journal = store
            .create_with_id(
                "prepared-request-drop",
                SessionHeader::new(Path::new("."), "prepared-request-test"),
            )
            .expect("create prepared request journal");
        let turn_id = "prepared-request-turn";
        let turn_admission = journal
            .begin_turn_transaction_v1(
                turn_id,
                json!({
                    "text":"prepared request",
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .expect("begin prepared request turn");
        let response_attempt_id = "prepared-request-attempt";
        let inner = journal
            .append_provider_response_started_v1(
                &turn_admission,
                turn_id,
                json!({
                    "response_attempt_id":response_attempt_id,
                    "context":{},
                }),
            )
            .expect("admit prepared request Provider response");
        let capability = McpJournalWriteCapabilityV1::new(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            0,
            "test-coordinator".to_owned(),
            "test-epoch".to_owned(),
            "d".repeat(64),
            Arc::new(McpJournalAuthorityState::new()),
        );
        (
            directory,
            journal,
            turn_admission,
            capability,
            inner,
            response_attempt_id.to_owned(),
        )
    }

    fn prepared_request_from_parts<'turn, 'provider>(
        turn_admission: &'turn TurnTransactionAdmissionV1,
        provider: &'provider RecordingProvider,
        capability: McpJournalWriteCapabilityV1,
        inner: ProviderResponseDispatchAdmissionV1,
        response_attempt_id: String,
    ) -> McpPreparedProviderRequestV1<'turn, 'turn, 'provider> {
        let request = provider
            .prepare_request(provider_request_fixture())
            .expect("prepare exact Provider request fixture");
        McpPreparedProviderRequestV1 {
            request: Some(request),
            provider,
            admission: Some(McpProviderResponseDispatchAdmissionV1 {
                capability,
                inner,
                response_attempt_id,
                _turn_admission: turn_admission,
            }),
            _coordinator: PhantomData,
        }
    }

    fn assert_journal_requires_reopen(journal: &SessionJournal) {
        let error = journal
            .read_events()
            .expect_err("abandoned Provider admission must poison the journal handle")
            .to_string();
        assert!(
            error.contains("capability was dropped") && error.contains("reopen"),
            "unexpected journal poison error: {error}"
        );
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn find_test_python() -> Option<PathBuf> {
        #[cfg(all(windows, debug_assertions))]
        {
            static GUARDIAN_JOB_TEST_SETUP: std::sync::Once = std::sync::Once::new();
            GUARDIAN_JOB_TEST_SETUP.call_once(|| {
                // Cargo can place the test host in a non-breakaway Job. This
                // debug-only fixture hook preserves the production fail-closed
                // behavior while allowing the guardian path to run in tests.
                unsafe {
                    std::env::set_var("OXIDRA_INTERNAL_GUARDIAN_ALLOW_SAME_JOB_V1", "1");
                }
            });
        }
        ["python", "python3", "py"].into_iter().find_map(|name| {
            let output = Command::new(name)
                .args(["-c", "import sys; print(sys.executable)"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let executable = String::from_utf8(output.stdout).ok()?;
            Path::new(executable.trim()).canonicalize().ok()
        })
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn test_path_literal(path: &Path) -> String {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn provider_request_project_config(python: &Path, script: &Path) -> String {
        let inherited = ["SYSTEMROOT", "WINDIR", "HOME", "TMP", "TEMP"]
            .into_iter()
            .filter(|name| std::env::var_os(name).is_some())
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\nargs = [\"{}\"]\ncwd = \".\"\ninherit_env = [{inherited}]\n",
            test_path_literal(python),
            test_path_literal(script),
        )
    }

    #[cfg(any(windows, target_os = "linux"))]
    const PROVIDER_REQUEST_MCP_FIXTURE: &str = r#"
import json
import sys

def reply(message, result):
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message.get("method", "")
    if method == "server/discover":
        reply(message, {
            "resultType": "complete",
            "ttlMs": 1000,
            "cacheScope": "private",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {"listChanged": False}},
        })
    elif method == "tools/list":
        reply(message, {
            "resultType": "complete",
            "ttlMs": 1000,
            "cacheScope": "private",
            "tools": [{
                "name": "echo.v1",
                "description": "Echo text",
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
            }],
        })
    else:
        reply(message, {"resultType": "complete"})
"#;

    #[test]
    fn coordinator_versions_and_argument_digest_v1_are_frozen() {
        assert_eq!(MCP_EXECUTION_COORDINATOR_VERSION, 4);
        assert_eq!(MCP_DISPATCH_PERMIT_VERSION, 1);
        assert_eq!(MCP_ARGUMENT_DIGEST_VERSION, 1);
        assert_eq!(MAX_MCP_PREPARED_PROVIDER_INPUT_ITEMS_V1, 16_384);
        assert_eq!(MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1, 8 * 1024 * 1024);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.coordinator_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.call_chain_validator_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.dispatch_permit_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.argument_digest_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.registry_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.stdio_kernel_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.schema_profile_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.provider_slot_version, 2);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.coordinator_version, 2);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.call_chain_validator_version, 2);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.dispatch_permit_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.argument_digest_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.registry_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.stdio_kernel_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.schema_profile_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V2.provider_slot_version, 2);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.coordinator_version, 4);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.call_chain_validator_version, 4);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.dispatch_permit_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.argument_digest_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.registry_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.stdio_kernel_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.schema_profile_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V4.provider_slot_version, 5);
        assert_eq!(
            argument_digest_v1(&json!({
                "count": 7,
                "items": ["alpha", true, null],
                "name": "fixture",
            }))
            .expect("compute frozen MCP argument digest"),
            "490f03fe740f99e35c2ed88df2cdc00017e89d463b891dd2e0c16ff866fe1b31"
        );
    }

    #[test]
    fn actual_provider_turn_accepts_final_message_and_rejects_call_projection_drift() {
        let message = json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":"done"}],
        });
        let final_turn = AssistantTurn {
            raw_response: json!({"output":[message.clone()]}),
            output_items: vec![message],
            text: "done".to_owned(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        };
        validate_actual_provider_turn_v1(&final_turn)
            .expect("a final Provider message is a valid exact MCP-owned response");

        let call_item = json!({
            "type":"function_call",
            "call_id":"call-1",
            "name":"fixture_tool",
            "arguments":"{}",
        });
        let drifted = AssistantTurn {
            raw_response: json!({"output":[call_item.clone()]}),
            output_items: vec![call_item],
            text: String::new(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        };
        let error = validate_actual_provider_turn_v1(&drifted)
            .expect_err("execution projection must match the durable output_items")
            .to_string();
        assert!(error.contains("tool_calls do not match"));
    }

    #[test]
    fn dropping_prepared_provider_request_poisons_outcome_admission() {
        let (_directory, journal, turn_admission, capability, inner, response_attempt_id) =
            prepared_request_drop_fixture();
        let provider = RecordingProvider::default();
        let prepared = prepared_request_from_parts(
            &turn_admission,
            &provider,
            capability,
            inner,
            response_attempt_id,
        );

        drop(prepared);

        assert_journal_requires_reopen(&journal);
    }

    #[test]
    fn unpolled_prepared_response_never_calls_provider_and_poisons_admission() {
        let (_directory, journal, turn_admission, capability, inner, response_attempt_id) =
            prepared_request_drop_fixture();
        let provider = RecordingProvider::default();
        let prepared = prepared_request_from_parts(
            &turn_admission,
            &provider,
            capability,
            inner,
            response_attempt_id,
        );
        let mut observer = NoopStreamObserver;

        let response = prepared.respond(&mut observer, CancellationToken::new());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        drop(response);

        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            0,
            "creating and dropping an unpolled response future must not enter Provider code"
        );
        assert_journal_requires_reopen(&journal);
    }

    #[tokio::test]
    async fn dropping_provider_outcome_preserves_exact_request_and_poisons_admission() {
        let (_directory, journal, turn_admission, capability, inner, response_attempt_id) =
            prepared_request_drop_fixture();
        let provider = RecordingProvider::default();
        let prepared = prepared_request_from_parts(
            &turn_admission,
            &provider,
            capability,
            inner,
            response_attempt_id,
        );
        let expected = prepared_request_body(
            prepared
                .request
                .as_ref()
                .expect("prepared request fixture owns an exact request")
                .request(),
            "fixture-model",
        );
        let mut observer = NoopStreamObserver;

        let outcome = prepared
            .respond(&mut observer, CancellationToken::new())
            .await;

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *provider
                .request_body
                .lock()
                .expect("read recorded Provider request"),
            Some(expected),
            "Provider must receive the exact request owned by the prepared capability"
        );
        drop(outcome);
        assert_journal_requires_reopen(&journal);
    }

    #[tokio::test]
    async fn precommit_provider_stream_does_not_expose_provider_controlled_payload() {
        let (_directory, journal, turn_admission, capability, inner, response_attempt_id) =
            prepared_request_drop_fixture();
        let provider = RecordingProvider {
            emit_precommit_events: true,
            ..RecordingProvider::default()
        };
        let prepared = prepared_request_from_parts(
            &turn_admission,
            &provider,
            capability,
            inner,
            response_attempt_id,
        );
        let mut observer = CapturingStreamObserver::default();

        let outcome = prepared
            .respond(&mut observer, CancellationToken::new())
            .await;

        assert_eq!(observer.retries, 0);
        assert_eq!(observer.provider_controlled_events, 0);
        drop(outcome);
        assert_journal_requires_reopen(&journal);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[tokio::test]
    async fn prepared_provider_request_admission_binds_exact_request_surface_and_measurement() {
        let Some(python) = find_test_python() else {
            eprintln!("skipping prepared Provider request test: Python is unavailable");
            return;
        };
        let directory = TempDir::new().expect("create prepared Provider request directory");
        let root = directory.path().join("project");
        fs::create_dir_all(&root).expect("create prepared Provider request project");
        let script = root.join("server.py");
        fs::write(&script, PROVIDER_REQUEST_MCP_FIXTURE)
            .expect("write prepared Provider request MCP fixture");
        let config_path = root.join("mcp.toml");
        fs::write(
            &config_path,
            provider_request_project_config(&python, &script),
        )
        .expect("write prepared Provider request config");
        let config = crate::mcp::McpProjectConfig::load(
            &root,
            &config_path
                .canonicalize()
                .expect("canonicalize prepared Provider request config"),
        )
        .expect("load prepared Provider request config");
        let approved = config
            .approve_execution(config.execution_plan_digest())
            .expect("approve prepared Provider request execution plan");
        let store = SessionStore::new(directory.path().join("data"))
            .expect("create prepared Provider request store");
        let mut journal = store
            .create(SessionHeader::new(&root, "prepared-provider-request"))
            .expect("create prepared Provider request journal");
        let registry = McpRegistry::connect_for_activation(
            &approved,
            std::iter::empty(),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .expect("connect prepared Provider request registry");
        let registry_digest = registry.digest().to_owned();
        let approved_registry = registry
            .approve_surface(&registry_digest)
            .expect("approve prepared Provider request surface");
        let mut coordinator = McpExecutionCoordinator::activate(approved_registry, &mut journal)
            .expect("activate prepared Provider request coordinator");
        let runtime = ContextRuntime::for_tests("fixture-model", ContextLimits::default());
        let configured_event = journal
            .append_and_sync("context.configured", None, runtime.configured_event_data())
            .expect("append prepared Provider request context.configured");
        let instructions_event = journal
            .append_and_sync(
                "context.instructions",
                None,
                json!({"instructions":"exact instructions"}),
            )
            .expect("append prepared Provider request context.instructions");
        let surface = coordinator
            .surface_claim_v1()
            .expect("derive prepared Provider request surface")
            .merge_with(Vec::new())
            .expect("build prepared Provider request snapshot");
        let tools_event = coordinator
            .append_context_tools_v1(&mut journal, &surface)
            .expect("append prepared Provider request context.tools");
        let turn_id = "prepared-provider-request-turn";
        let request = ResponseRequest {
            instructions: Some("exact instructions".to_owned()),
            input: vec![json!({"role":"user","content":"use the exact MCP surface"})],
            tools: surface.tools().to_vec(),
            model: None,
            max_output_tokens: None,
        };
        let mut turn_admission = journal
            .begin_turn_transaction_v1(
                turn_id,
                json!({
                    "item":request.input[0],
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VERSION,
                }),
            )
            .expect("begin prepared Provider request turn");
        let provider = RecordingProvider::default();

        let response_data = |journal: &SessionJournal,
                             request: &ResponseRequest,
                             response_attempt_id: &str|
         -> Value {
            let events = journal
                .read_events()
                .expect("read prepared Provider request context");
            let measurement = measure_prepared_request(request, &runtime)
                .expect("measure prepared Provider request");
            let context = crate::context::decide_context(
                &events,
                &runtime,
                measurement,
                events.last().map(|event| event.seq),
                None,
                None,
                Some(instructions_event.seq),
                Some(configured_event.seq),
                tools_event.seq,
            )
            .expect("decide prepared Provider request context");
            json!({
                "response_attempt_id":response_attempt_id,
                "response_index":1,
                "context":context.audit_value().expect("encode Provider request context"),
            })
        };

        let mut mismatched_tools_request = request.clone();
        mismatched_tools_request.tools[0]
            .description
            .push_str(" (mutated)");
        let mismatched_tools_data = response_data(
            &journal,
            &mismatched_tools_request,
            "mismatched-tools-attempt",
        );
        let before_tools_mismatch = journal
            .read_events()
            .expect("read journal before tools mismatch");
        let tools_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                mismatched_tools_data,
                provider
                    .prepare_request(mismatched_tools_request)
                    .expect("seal mismatched-tools Provider request"),
                &provider,
            )
            .err()
            .expect("mutated Provider tools must be rejected");
        assert!(matches!(
            tools_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after tools mismatch"),
            before_tools_mismatch,
            "request.tools mismatch must be rejected before response.started is written"
        );

        let mut measurement_mismatch_data =
            response_data(&journal, &request, "measurement-mismatch-attempt");
        measurement_mismatch_data["context"]["measurement"]["request_digest"] =
            Value::String("0".repeat(64));
        let before_measurement_mismatch = journal
            .read_events()
            .expect("read journal before measurement mismatch");
        let measurement_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                measurement_mismatch_data,
                provider
                    .prepare_request(request.clone())
                    .expect("seal measurement-mismatch Provider request"),
                &provider,
            )
            .err()
            .expect("mutated request measurement must be rejected");
        assert!(matches!(
            measurement_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after measurement mismatch"),
            before_measurement_mismatch,
            "measurement mismatch must be rejected before response.started is written"
        );

        let bounded_data = response_data(&journal, &request, "wide-request-attempt");
        let mut wide_input_request = request.clone();
        wide_input_request.input = vec![Value::Null; MAX_MCP_PREPARED_PROVIDER_INPUT_ITEMS_V1 + 1];
        let before_wide_input = journal
            .read_events()
            .expect("read journal before wide prepared request input");
        let wide_input_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                bounded_data.clone(),
                provider
                    .prepare_request(wide_input_request)
                    .expect("seal wide-input Provider request"),
                &provider,
            )
            .err()
            .expect("wide prepared request input must fail closed");
        assert!(matches!(
            wide_input_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after wide prepared request input"),
            before_wide_input,
            "wide prepared request input rejection must be zero-write"
        );

        let mut wide_tools_request = request.clone();
        wide_tools_request.tools = vec![request.tools[0].clone(); TOOL_SURFACE_MAX_TOOLS_V1 + 1];
        let before_wide_tools = journal
            .read_events()
            .expect("read journal before wide prepared request tools");
        let wide_tools_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                bounded_data.clone(),
                provider
                    .prepare_request(wide_tools_request)
                    .expect("seal wide-tools Provider request"),
                &provider,
            )
            .err()
            .expect("wide prepared request tools must fail closed");
        assert!(matches!(
            wide_tools_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after wide prepared request tools"),
            before_wide_tools,
            "wide prepared request tools rejection must be zero-write"
        );

        let mut oversized_request = request.clone();
        oversized_request.instructions =
            Some("x".repeat(MAX_MCP_PREPARED_PROVIDER_REQUEST_BYTES_V1 + 1));
        let before_oversized_request = journal
            .read_events()
            .expect("read journal before oversized prepared request");
        let oversized_request_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                bounded_data.clone(),
                provider
                    .prepare_request(oversized_request)
                    .expect("seal oversized Provider request within transport ceiling"),
                &provider,
            )
            .err()
            .expect("oversized prepared request must fail closed");
        assert!(matches!(
            oversized_request_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after oversized prepared request"),
            before_oversized_request,
            "aggregate prepared request budget rejection must be zero-write"
        );

        let mut deep_input = Value::Null;
        for _ in 0..50_000 {
            deep_input = Value::Array(vec![deep_input]);
        }
        let mut deep_input_request = request.clone();
        deep_input_request.input = vec![deep_input];
        let before_deep_request = journal
            .read_events()
            .expect("read journal before deep prepared request input");
        let deep_request_error = provider
            .prepare_request(deep_input_request)
            .expect_err("deep prepared request input must fail during pure sealing");
        assert!(deep_request_error.to_string().contains("not bounded"));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after deep prepared request input"),
            before_deep_request,
            "deep prepared request input rejection must be zero-write"
        );

        let mut deep_schema = Value::Null;
        for _ in 0..50_000 {
            deep_schema = Value::Array(vec![deep_schema]);
        }
        let mut deep_schema_request = request.clone();
        deep_schema_request.tools[0].input_schema = deep_schema;
        let before_deep_schema = journal
            .read_events()
            .expect("read journal before deep prepared request schema");
        let deep_schema_error = provider
            .prepare_request(deep_schema_request)
            .expect_err("deep prepared request schema must fail during pure sealing");
        assert!(deep_schema_error.to_string().contains("not bounded"));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after deep prepared request schema"),
            before_deep_schema,
            "deep prepared request schema rejection must be zero-write"
        );

        let mut deep = Value::Null;
        for _ in 0..50_000 {
            deep = Value::Array(vec![deep]);
        }
        let before_deep_data = journal
            .read_events()
            .expect("read journal before deep response.started data");
        let deep_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                Value::Object(serde_json::Map::from_iter([
                    (
                        "response_attempt_id".to_owned(),
                        Value::String("deep-data-attempt".to_owned()),
                    ),
                    ("context".to_owned(), deep),
                ])),
                provider
                    .prepare_request(request.clone())
                    .expect("seal deep-data Provider request"),
                &provider,
            )
            .err()
            .expect("deep response.started data must fail closed");
        assert!(matches!(
            deep_error,
            McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
        ));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after deep response.started data"),
            before_deep_data,
            "deep response.started data rejection must be zero-write"
        );

        let mismatched_endpoint_data =
            response_data(&journal, &request, "mismatched-endpoint-attempt");
        let mismatched_endpoint_provider = RecordingProvider {
            provider_usage_domain: Some("different-provider-usage-domain".to_owned()),
            ..RecordingProvider::default()
        };
        let before_endpoint_mismatch = journal
            .read_events()
            .expect("read journal before Provider endpoint mismatch");
        let endpoint_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                mismatched_endpoint_data,
                mismatched_endpoint_provider
                    .prepare_request(request.clone())
                    .expect("seal mismatched-endpoint Provider request"),
                &mismatched_endpoint_provider,
            )
            .err()
            .expect("prepared request from another Provider domain must fail closed");
        assert!(endpoint_error.to_string().contains("endpoint identity"));
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after Provider endpoint mismatch"),
            before_endpoint_mismatch,
            "Provider endpoint mismatch must be zero-write"
        );

        let mismatched_model_data = response_data(&journal, &request, "mismatched-model-attempt");
        let mismatched_model_provider = RecordingProvider {
            provider_model: Some("different-model".to_owned()),
            ..RecordingProvider::default()
        };
        let before_model_mismatch = journal
            .read_events()
            .expect("read journal before Provider model mismatch");
        let model_error = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                mismatched_model_data,
                mismatched_model_provider
                    .prepare_request(request.clone())
                    .expect("seal mismatched-model Provider request"),
                &mismatched_model_provider,
            )
            .err()
            .expect("Provider model mismatch must fail closed before response.started");
        assert!(
            model_error
                .to_string()
                .contains("model does not match the transport configuration")
        );
        assert_eq!(
            journal
                .read_events()
                .expect("read journal after Provider model mismatch"),
            before_model_mismatch,
            "Provider model mismatch must be zero-write"
        );

        let exact_data = response_data(&journal, &request, "exact-request-attempt");
        let prepared = coordinator
            .admit_prepared_provider_request_v1(
                &mut journal,
                &turn_admission,
                turn_id,
                exact_data,
                provider
                    .prepare_request(request.clone())
                    .expect("seal exact Provider request"),
                &provider,
            )
            .expect("admit exact prepared Provider request");
        let expected_body = prepared_request_body(&request, "fixture-model");
        let mut observer = NoopStreamObserver;
        let outcome = prepared
            .respond(&mut observer, CancellationToken::new())
            .await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *provider
                .request_body
                .lock()
                .expect("read exact Provider request"),
            Some(expected_body),
            "typed dispatch must pass the exact admitted request to the Provider"
        );
        let committed = outcome
            .commit_v1(&mut journal)
            .expect("commit the exact Provider result");
        assert_eq!(committed.tool_calls().len(), 1);
        assert_eq!(committed.tool_calls()[0].id, "fixture-call");
        journal
            .finish_turn_transaction_v1(&mut turn_admission, Some("fixture finished"))
            .expect("finish prepared Provider request turn");
        coordinator.shutdown().await;
    }

    #[test]
    fn journal_authority_revoke_waits_for_inflight_writer() {
        let authority = Arc::new(McpJournalAuthorityState::new());
        let capability = McpJournalWriteCapabilityV1::new(
            "session".to_owned(),
            "journal-handle".to_owned(),
            1,
            "coordinator".to_owned(),
            "epoch".to_owned(),
            "digest".to_owned(),
            Arc::clone(&authority),
        );
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let proof = capability
                .acquire_live_proof()
                .expect("in-flight writer acquires live authority");
            entered_tx.send(()).expect("announce live authority");
            release_rx.recv().expect("release live authority");
            drop(proof);
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer acquired authority gate");

        let (revoked_tx, revoked_rx) = mpsc::channel();
        let revoking_authority = Arc::clone(&authority);
        let revoker = thread::spawn(move || {
            revoking_authority.revoke();
            revoked_tx.send(()).expect("announce authority revocation");
        });
        assert!(
            revoked_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "revocation must not overtake a writer that already holds the authority gate"
        );
        release_tx.send(()).expect("release in-flight writer");
        writer.join().expect("join authority writer");
        revoked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("revocation completes after the writer exits");
        revoker.join().expect("join authority revoker");
        assert!(!authority.is_active());
    }

    #[test]
    fn journal_kind_conversion_runs_before_authority_gate_is_acquired() {
        struct GateCheckingKind {
            authority: Arc<McpJournalAuthorityState>,
        }

        impl From<GateCheckingKind> for String {
            fn from(value: GateCheckingKind) -> Self {
                let _guard = value
                    .authority
                    .gate
                    .try_lock()
                    .expect("kind conversion must run before the authority gate is acquired");
                "response.started".to_owned()
            }
        }

        let directory = TempDir::new().expect("create authority fixture directory");
        let store = SessionStore::new(directory.path()).expect("create authority fixture store");
        let mut journal = store
            .create_with_id(
                "authority-kind-conversion",
                SessionHeader::new(Path::new("."), "authority-test"),
            )
            .expect("create authority fixture journal");
        let authority = Arc::new(McpJournalAuthorityState::new());
        let capability = McpJournalWriteCapabilityV1::new(
            journal.session_id().to_owned(),
            journal.handle_id().to_owned(),
            1,
            "coordinator".to_owned(),
            "epoch".to_owned(),
            "digest".to_owned(),
            Arc::clone(&authority),
        );

        let error = journal
            .append_mcp_event_with_capability_v1(
                &capability,
                GateCheckingKind { authority },
                Some("turn"),
                json!({"response_attempt_id":"attempt"}),
            )
            .expect_err("fixture capability has no matching activation")
            .to_string();
        assert!(
            error.contains("exact registry activation"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn activation_cannot_cross_a_pending_compaction_boundary() {
        let events = vec![
            event(
                1,
                Some("turn-1"),
                "user.message",
                json!({
                    "turn_boundary_version":crate::turn::TURN_BOUNDARY_VALIDATOR_VERSION,
                    "item":{"role":"user","content":"prompt"},
                }),
            ),
            event(
                2,
                None,
                "compaction.boundary.started",
                json!({
                    "boundary":{
                        "version":crate::compaction::COMPACTION_BOUNDARY_VERSION,
                        "boundary_id":"boundary-1",
                        "turn_id":"turn-1",
                        "user_message_seq":1,
                    },
                    "trigger":"context_trigger",
                }),
            ),
        ];
        let error = validate_new_activation(&events)
            .expect_err("activation must not cross a pending compaction boundary")
            .to_string();
        assert!(error.contains("cannot cross pending compaction boundary boundary-1"));
    }
}
