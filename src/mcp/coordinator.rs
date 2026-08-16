use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::{
    Arc,
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
use super::{McpCallError, PreflightedJsonValue};
use crate::compaction::validate_compaction_boundary_chain;
use crate::context::{
    McpSurfaceBindingV1, McpSurfaceClaimV1, ToolSurfaceSnapshotV1, snapshot_tool_surface_v1,
};
use crate::error::{OxidraError, Result};
use crate::session::{JOURNAL_SCHEMA, JournalEvent, McpToolDispatchAdmissionV1, SessionJournal};
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

/// Sole owner of a surface-approved registry and its dispatch authority.
///
/// The coordinator binds one runtime registry epoch to one durable session.
/// Callers can request approval and execution, but cannot construct the
/// private `DispatchPermit` consumed by the registry.
pub struct McpExecutionCoordinator {
    policy: McpCoordinatorPolicy,
    coordinator_id: String,
    registry_epoch_id: String,
    session_id: String,
    activation_seq: u64,
    registry: McpRegistry,
    dispatch_poisoned: Arc<AtomicBool>,
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
        let mut registry = approved_registry.into_registry();
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

        registry.bind_dispatch_authority(&coordinator_id, &registry_epoch_id)?;
        let event = journal.append_and_sync(MCP_REGISTRY_ACTIVATED_KIND, None, activation_data)?;
        Ok(Self {
            policy,
            coordinator_id,
            registry_epoch_id,
            session_id: journal.session_id().to_owned(),
            activation_seq: event.seq,
            registry,
            dispatch_poisoned: Arc::new(AtomicBool::new(false)),
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
        let (mut registry, resume_permit) = approved_registry.into_parts();
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
            activation_seq: activation.seq,
            registry,
            dispatch_poisoned: Arc::new(AtomicBool::new(false)),
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
        let bindings = self
            .registry
            .bindings()
            .map(|binding| {
                McpSurfaceBindingV1::from_parts(
                    binding.provider_name.clone(),
                    binding.server_name.clone(),
                    binding.raw_tool_name.clone(),
                    binding.protocol_version.clone(),
                    &binding.definition,
                    binding.output_schema.as_ref(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
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
        self.ensure_dispatch_healthy()?;
        self.require_bound_journal(journal)?;
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
        let mut started_guard =
            McpStartedCallGuard::new(journal, admission, Arc::clone(&self.dispatch_poisoned));
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
            Ok(output) => {
                let is_error = output.get("isError").and_then(Value::as_bool) == Some(true);
                let result = ToolResult {
                    call_id: call.call_id.to_owned(),
                    output,
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
        if journal.session_id() != self.session_id {
            return Err(OxidraError::Session(
                "MCP coordinator cannot dispatch into a different session journal".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_dispatch_healthy(&self) -> Result<()> {
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
        self.ensure_dispatch_healthy()?;
        self.require_bound_journal(journal)?;
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
        journal.append_and_sync(
            "tool.cancelled",
            Some(call.turn_id),
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
        journal.append_and_sync("tool.completed", Some(call.turn_id), data)?;
        Ok(result)
    }

    pub async fn shutdown(&mut self) {
        self.registry.shutdown().await;
    }
}

struct McpStartedCallGuard<'journal> {
    journal: &'journal mut SessionJournal,
    admission: McpToolDispatchAdmissionV1,
    dispatch_poisoned: Arc<AtomicBool>,
    terminalized: bool,
}

impl<'journal> McpStartedCallGuard<'journal> {
    fn new(
        journal: &'journal mut SessionJournal,
        admission: McpToolDispatchAdmissionV1,
        dispatch_poisoned: Arc<AtomicBool>,
    ) -> Self {
        // `tool.started` is already durable when this guard is created.  Arm
        // the coordinator poison before returning so leaking/forgetting the
        // future cannot make the old transport reusable without a terminal.
        dispatch_poisoned.store(true, Ordering::Release);
        Self {
            journal,
            admission,
            dispatch_poisoned,
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
