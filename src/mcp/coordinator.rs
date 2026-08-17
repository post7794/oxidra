use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::journal::{
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1, MCP_CALL_CHAIN_VALIDATOR_VERSION_V2,
    ValidatedDurableMcpCall, argument_digest_v1, ensure_no_unstarted_mcp_calls,
    validate_mcp_call_chain, validated_durable_mcp_call,
};
use super::registry::{
    ApprovedMcpRegistry, ApprovedMcpResumeRegistry, McpRegistry, PreparedMcpRegistryCall,
};
use super::{
    MAX_MCP_PROVIDER_COMPLETED_EVENT_BYTES_V1, MAX_MCP_PROVIDER_START_EVENT_BYTES_V1, McpCallError,
    PreflightedJsonValue, TransportAbortHandle, drop_json_value_iteratively,
    preflight_mcp_provider_event_tree_v1,
};
use crate::compaction::validate_compaction_boundary_chain;
use crate::context::{McpSurfaceClaimV1, ToolSurfaceSnapshotV1, snapshot_tool_surface_v1};
use crate::error::{OxidraError, Result};
use crate::session::{
    DispatchAdmissionErrorV1, DurableOutcomeCommitErrorV1, JOURNAL_SCHEMA, JournalEvent,
    McpToolDispatchAdmissionV1, ProviderResponseDispatchAdmissionV1, SessionExecutionLeaseV1,
    SessionJournal, TurnTransactionAdmissionV1,
};
use crate::turn::{ProviderRequestSlotState, provider_request_slot_state_for_version};
use crate::types::{ToolDefinition, ToolResult};
use crate::untrusted_display;

const MCP_EXECUTION_COORDINATOR_VERSION_V1: u32 = 1;
const MCP_EXECUTION_COORDINATOR_VERSION_V2: u32 = 2;
const MCP_DISPATCH_PERMIT_VERSION_V1: u32 = 1;
const MCP_ARGUMENT_DIGEST_VERSION_V1: u32 = 1;
const MCP_TOOL_REGISTRY_VERSION_V1: u32 = 1;
const MCP_STDIO_KERNEL_VERSION_V1: u32 = 1;
const MCP_SCHEMA_PROFILE_VERSION_V1: u32 = 1;
const MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1: u32 = 2;

pub const MCP_EXECUTION_COORDINATOR_VERSION: u32 = MCP_EXECUTION_COORDINATOR_VERSION_V2;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpCallApprovalRequest {
    pub execution_coordinator_version: u32,
    pub turn_id: String,
    pub call_id: String,
    pub provider_name: String,
    pub server_name: String,
    pub raw_tool_name: String,
    pub protocol_version: String,
    pub registry_epoch_id: String,
    pub registry_digest: String,
    pub execution_plan_digest: String,
    pub server_attempt_id: String,
    pub arguments_sha256: String,
    pub arguments_display: String,
    pub arguments_json: String,
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

#[async_trait]
pub trait McpCallApprovalHandler: Send {
    async fn approve_mcp_call(
        &mut self,
        request: &McpCallApprovalRequest,
        cancellation: &CancellationToken,
    ) -> Result<bool>;
}

#[derive(Default)]
pub struct DenyMcpCallApproval;

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
    fn new(value: Value, maximum_bytes: usize) -> std::result::Result<Self, OxidraError> {
        let owned = Self { value: Some(value) };
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
pub struct McpProviderResponseDispatchAdmissionV1 {
    capability: McpJournalWriteCapabilityV1,
    inner: ProviderResponseDispatchAdmissionV1,
    turn_id: String,
    response_attempt_id: String,
}

impl McpProviderResponseDispatchAdmissionV1 {
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn response_attempt_id(&self) -> &str {
        &self.response_attempt_id
    }

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
            execution_lease: Some(journal.retain_execution_lease_v1()),
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
        let policy = MCP_COORDINATOR_POLICY_V2;
        let bindings = registry.binding_identity_snapshot();
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

    /// Admit one MCP-owned Provider response against the exact active turn.
    /// This is the sole production path for MCP `response.started`: it holds
    /// live coordinator authority across the synchronous append and returns a
    /// one-shot guard backed by the ordinary Provider outcome reservation.
    pub fn admit_provider_response_v1(
        &self,
        journal: &mut SessionJournal,
        turn_admission: &TurnTransactionAdmissionV1,
        turn_id: &str,
        data: Value,
    ) -> std::result::Result<
        McpProviderResponseDispatchAdmissionV1,
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
            turn_id: turn_id.to_owned(),
            response_attempt_id,
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
        let capability = self.journal_write_capability_v1(journal)?;
        let proof = capability.acquire_live_proof()?;
        journal.append_mcp_context_tools_with_live_proof_v1(&proof, serde_json::to_value(snapshot)?)
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

        let (arguments_sha256, prepared) = match prepared? {
            PreparedCoordinatorCall::Ready {
                arguments_sha256,
                prepared,
            } => (arguments_sha256, prepared),
            PreparedCoordinatorCall::Rejected(error) => {
                validate_pre_start_terminal_candidate(journal.read_events()?, journal, self, call)?;
                return self.commit_known_failure(
                    journal,
                    call,
                    error.code,
                    error.message,
                    None,
                    None,
                );
            }
        };
        let arguments_json = serde_json::to_string(prepared.arguments())?;
        let approval_request = McpCallApprovalRequest {
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
            arguments_display: untrusted_display::json_for_display(prepared.arguments()),
            arguments_json,
        };

        let snapshot = journal.read_events()?;
        validate_dispatch_candidate(
            snapshot,
            journal,
            self,
            &approval_request,
            prepared.arguments(),
        )?;

        if cancellation.is_cancelled() {
            return self.commit_cancelled_before_start(
                journal,
                call,
                "MCP call was cancelled before approval",
            );
        }
        let approved = match approval
            .approve_mcp_call(&approval_request, cancellation)
            .await
        {
            Ok(approved) => approved,
            Err(OxidraError::Interrupted) => {
                return self.commit_cancelled_before_start(
                    journal,
                    call,
                    "MCP call approval was cancelled",
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
                Some(&approval_request),
                None,
            );
        }
        let approved_call = ApprovedMcpCall {
            request: approval_request,
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
            &approved_call.request,
            approved_call.prepared.arguments(),
        )?;

        let admission = journal
            .append_mcp_tool_started_v1(
                call.turn_id,
                started_data(&approved_call.request, approved_call.prepared.arguments()),
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
                    terminal_data(&approved_call.request, started_seq, &result, true),
                )?;
                Ok(())
            })?;
            return Ok(result);
        }

        let ApprovedMcpCall { request, prepared } = approved_call;
        let dispatched = self.registry.dispatch(permit, prepared, cancellation).await;
        match dispatched {
            Ok(raw_result) => {
                // Coordinator/call-chain v2 has a frozen raw-result output
                // contract.  The v3 model projection is an offline profile
                // for the next typed writer epoch and is not applied to this
                // current dispatch path.
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
                        terminal_data(&request, started_seq, &result, false),
                    )?;
                    Ok(())
                })?;
                Ok(result)
            }
            Err(error) if error.in_doubt || error.interrupted => {
                let result = ToolResult::error(call.call_id, "in_doubt", error.message);
                started_guard.terminalize(|journal, admission| {
                    journal.commit_mcp_tool_terminal_v1(
                        admission,
                        "tool.in_doubt",
                        terminal_data(&request, started_seq, &result, false),
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
                    terminal_data(&request, started_seq, &result, false),
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

        let arguments = match PreflightedJsonValue::new(durable_call.arguments).into_validated() {
            Ok(arguments) => arguments,
            Err(error) => return Ok(PreparedCoordinatorCall::Rejected(error)),
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
                prepared,
            }),
            Err(error) => Ok(PreparedCoordinatorCall::Rejected(error)),
        }
    }

    fn commit_cancelled_before_start(
        &self,
        journal: &mut SessionJournal,
        call: McpCallIdentity<'_>,
        message: &str,
    ) -> Result<ToolResult> {
        let result = ToolResult::error(call.call_id, "cancelled", message);
        let policy = self.policy;
        let capability = self.journal_write_capability_v1(journal)?;
        capability.append_tool_cancelled_before_start_to_journal(
            journal,
            call.turn_id,
            json!({
                "call_id": call.call_id,
                "tool": call.provider_name,
                "output": result.output,
                "is_error": true,
                "error_code": "cancelled",
                "before_start": true,
                "mcp_execution_coordinator_version": policy.coordinator_version,
                "registry_epoch_id": self.registry_epoch_id,
                "registry_digest": self.registry.digest(),
            }),
        )?;
        Ok(result)
    }

    fn commit_known_failure(
        &self,
        journal: &mut SessionJournal,
        call: McpCallIdentity<'_>,
        code: &str,
        message: String,
        approval: Option<&McpCallApprovalRequest>,
        started_seq: Option<u64>,
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
        if let Some(approval) = approval {
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
    request: McpCallApprovalRequest,
    prepared: PreparedMcpRegistryCall,
}

enum PreparedCoordinatorCall {
    Ready {
        arguments_sha256: String,
        prepared: PreparedMcpRegistryCall,
    },
    Rejected(McpCallError),
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
    approval: &McpCallApprovalRequest,
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
    events.push(JournalEvent {
        schema: JOURNAL_SCHEMA,
        seq: journal.next_seq(),
        ts: Utc::now(),
        kind: "tool.completed".to_owned(),
        session_id: journal.session_id().to_owned(),
        turn_id: Some(call.turn_id.to_owned()),
        data: json!({
            "call_id": call.call_id,
            "tool": call.provider_name,
            "output":{"error":{"code":"validation_error","message":"rejected before dispatch"}},
            "is_error":true,
            "error_code":"validation_error",
            "mcp_execution_coordinator_version": coordinator.policy.coordinator_version,
            "registry_epoch_id": coordinator.registry_epoch_id,
            "registry_digest": coordinator.registry.digest(),
        }),
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

fn started_data(approval: &McpCallApprovalRequest, arguments: &Value) -> Value {
    json!({
        "call_id": approval.call_id,
        "tool": approval.provider_name,
        "arguments": arguments,
        "mcp": provenance_data(approval),
    })
}

fn terminal_data(
    approval: &McpCallApprovalRequest,
    started_seq: u64,
    result: &ToolResult,
    before_dispatch: bool,
) -> Value {
    json!({
        "started_seq": started_seq,
        "call_id": result.call_id,
        "tool": approval.provider_name,
        "output": result.output,
        "is_error": result.is_error,
        "error_code": result.error_code,
        "before_dispatch": before_dispatch,
        "mcp": provenance_data(approval),
    })
}

fn provenance_data(approval: &McpCallApprovalRequest) -> Value {
    json!({
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionHeader, SessionStore};
    use std::path::Path;
    use std::sync::mpsc;
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

    #[test]
    fn coordinator_versions_and_argument_digest_v1_are_frozen() {
        assert_eq!(MCP_EXECUTION_COORDINATOR_VERSION, 2);
        assert_eq!(MCP_DISPATCH_PERMIT_VERSION, 1);
        assert_eq!(MCP_ARGUMENT_DIGEST_VERSION, 1);
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
