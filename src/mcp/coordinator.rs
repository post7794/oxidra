use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::registry::{ApprovedMcpRegistry, McpRegistry, PreparedMcpRegistryCall};
use super::{McpCallError, PreflightedJsonValue};
use crate::error::{OxidraError, Result};
use crate::session::{JOURNAL_SCHEMA, JournalEvent, SessionJournal};
use crate::turn::{ProviderRequestSlotState, provider_request_slot_state_for_version};
use crate::types::{ToolDefinition, ToolResult};
use crate::untrusted_display;

const MCP_EXECUTION_COORDINATOR_VERSION_V1: u32 = 1;
const MCP_DISPATCH_PERMIT_VERSION_V1: u32 = 1;
const MCP_ARGUMENT_DIGEST_VERSION_V1: u32 = 1;
const MCP_TOOL_REGISTRY_VERSION_V1: u32 = 1;
const MCP_STDIO_KERNEL_VERSION_V1: u32 = 1;
const MCP_SCHEMA_PROFILE_VERSION_V1: u32 = 1;
const MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1: u32 = 2;

pub const MCP_EXECUTION_COORDINATOR_VERSION: u32 = MCP_EXECUTION_COORDINATOR_VERSION_V1;
pub const MCP_DISPATCH_PERMIT_VERSION: u32 = MCP_DISPATCH_PERMIT_VERSION_V1;
pub const MCP_ARGUMENT_DIGEST_VERSION: u32 = MCP_ARGUMENT_DIGEST_VERSION_V1;

const MCP_REGISTRY_ACTIVATED_KIND: &str = "mcp.registry.activated";

#[derive(Clone, Copy)]
struct McpCoordinatorPolicy {
    coordinator_version: u32,
    dispatch_permit_version: u32,
    argument_digest_version: u32,
    registry_version: u32,
    stdio_kernel_version: u32,
    schema_profile_version: u32,
    provider_slot_version: u32,
}

const MCP_COORDINATOR_POLICY_V1: McpCoordinatorPolicy = McpCoordinatorPolicy {
    coordinator_version: MCP_EXECUTION_COORDINATOR_VERSION_V1,
    dispatch_permit_version: MCP_DISPATCH_PERMIT_VERSION_V1,
    argument_digest_version: MCP_ARGUMENT_DIGEST_VERSION_V1,
    registry_version: MCP_TOOL_REGISTRY_VERSION_V1,
    stdio_kernel_version: MCP_STDIO_KERNEL_VERSION_V1,
    schema_profile_version: MCP_SCHEMA_PROFILE_VERSION_V1,
    provider_slot_version: MCP_COORDINATOR_PROVIDER_SLOT_VERSION_V1,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpCallApprovalRequest {
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
    coordinator_id: String,
    registry_epoch_id: String,
    session_id: String,
    activation_seq: u64,
    registry: McpRegistry,
}

impl McpExecutionCoordinator {
    pub fn activate(
        approved_registry: ApprovedMcpRegistry,
        journal: &mut SessionJournal,
    ) -> Result<Self> {
        validate_new_activation_v1(&journal.read_events()?)?;
        let mut registry = approved_registry.into_registry();
        let policy = MCP_COORDINATOR_POLICY_V1;
        let provider_names = registry
            .bindings()
            .map(|binding| binding.provider_name.clone())
            .collect::<Vec<_>>();
        let coordinator_id = Uuid::now_v7().to_string();
        let registry_epoch_id = Uuid::now_v7().to_string();
        registry.bind_dispatch_authority(&coordinator_id, &registry_epoch_id)?;
        let event = journal.append_and_sync(
            MCP_REGISTRY_ACTIVATED_KIND,
            None,
            json!({
                "coordinator_version": policy.coordinator_version,
                "coordinator_id": coordinator_id,
                "registry_epoch_id": registry_epoch_id,
                "registry_version": policy.registry_version,
                "stdio_kernel_version": policy.stdio_kernel_version,
                "schema_profile_version": policy.schema_profile_version,
                "config_sha256": registry.config_sha256(),
                "execution_plan_digest": registry.execution_plan_digest(),
                "registry_digest": registry.digest(),
                "provider_names": provider_names,
            }),
        )?;
        Ok(Self {
            coordinator_id,
            registry_epoch_id,
            session_id: journal.session_id().to_owned(),
            activation_seq: event.seq,
            registry,
        })
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
        self.require_bound_journal(journal)?;
        validate_call_identity(call.turn_id, call.call_id, call.provider_name)?;

        let (arguments_sha256, prepared) = match prepared? {
            PreparedCoordinatorCall::Ready {
                arguments_sha256,
                prepared,
            } => (arguments_sha256, prepared),
            PreparedCoordinatorCall::Rejected(error) => {
                validate_pre_start_terminal_candidate_v1(
                    journal.read_events()?,
                    journal,
                    self,
                    call,
                )?;
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
        validate_dispatch_candidate_v1(
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
        validate_dispatch_candidate_v1(
            snapshot,
            journal,
            self,
            &approved_call.request,
            approved_call.prepared.arguments(),
        )?;

        let started = journal.append_and_sync(
            "tool.started",
            Some(call.turn_id),
            started_data(&approved_call.request, approved_call.prepared.arguments()),
        )?;
        let permit = DispatchPermit {
            permit_version: MCP_COORDINATOR_POLICY_V1.dispatch_permit_version,
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
            started_seq: started.seq,
        };

        if cancellation.is_cancelled() {
            let result = ToolResult::error(
                call.call_id,
                "cancelled",
                "MCP call was cancelled before dispatch",
            );
            journal.append_and_sync(
                "tool.cancelled",
                Some(call.turn_id),
                terminal_data(&approved_call.request, started.seq, &result, true),
            )?;
            return Ok(result);
        }

        let started_seq = started.seq;
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
                journal.append_and_sync(
                    "tool.completed",
                    Some(call.turn_id),
                    terminal_data(&request, started_seq, &result, false),
                )?;
                Ok(result)
            }
            Err(error) if error.in_doubt || error.interrupted => {
                let result = ToolResult::error(call.call_id, "in_doubt", error.message);
                journal.append_and_sync(
                    "tool.in_doubt",
                    Some(call.turn_id),
                    terminal_data(&request, started_seq, &result, false),
                )?;
                Ok(result)
            }
            Err(error) => self.commit_known_failure(
                journal,
                call,
                error.code,
                error.message,
                Some(&request),
                Some(started_seq),
            ),
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

    fn prepare_durable_call(
        &self,
        journal: &SessionJournal,
        call: McpCallIdentity<'_>,
    ) -> Result<PreparedCoordinatorCall> {
        self.require_bound_journal(journal)?;
        validate_call_identity(call.turn_id, call.call_id, call.provider_name)?;
        if !journal.in_doubt()?.is_empty() {
            return Err(OxidraError::Session(
                "MCP dispatch is blocked until every in-doubt tool is explicitly resolved"
                    .to_owned(),
            ));
        }
        let events = journal.read_events()?;
        let activation_seq = validate_activation_v1(&events, self)?;
        let durable_call = provider_call_v1(&events, call.turn_id, call.call_id)?;
        validate_call_after_activation_v1(&durable_call, activation_seq, self)?;
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
        let policy = MCP_COORDINATOR_POLICY_V1;
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
        let policy = MCP_COORDINATOR_POLICY_V1;
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

pub(super) fn argument_digest_v1(arguments: &Value) -> Result<String> {
    let payload = json!({
        "argument_digest_version": MCP_COORDINATOR_POLICY_V1.argument_digest_version,
        "arguments": arguments,
    });
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&payload)?)))
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

fn validate_dispatch_candidate_v1(
    mut events: Vec<JournalEvent>,
    journal: &SessionJournal,
    coordinator: &McpExecutionCoordinator,
    approval: &McpCallApprovalRequest,
    arguments: &Value,
) -> Result<()> {
    let activation_seq = validate_activation_v1(&events, coordinator)?;

    let durable_call = provider_call_v1(&events, &approval.turn_id, &approval.call_id)?;
    validate_call_after_activation_v1(&durable_call, activation_seq, coordinator)?;
    if durable_call.provider_name != approval.provider_name
        || argument_digest_v1(&durable_call.arguments)? != approval.arguments_sha256
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
    let state = provider_request_slot_state_for_version(
        MCP_COORDINATOR_POLICY_V1.provider_slot_version,
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

fn validate_pre_start_terminal_candidate_v1(
    mut events: Vec<JournalEvent>,
    journal: &SessionJournal,
    coordinator: &McpExecutionCoordinator,
    call: McpCallIdentity<'_>,
) -> Result<()> {
    let activation_seq = validate_activation_v1(&events, coordinator)?;
    let durable_call = provider_call_v1(&events, call.turn_id, call.call_id)?;
    validate_call_after_activation_v1(&durable_call, activation_seq, coordinator)?;
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
        }),
    });
    provider_request_slot_state_for_version(
        MCP_COORDINATOR_POLICY_V1.provider_slot_version,
        &events,
        call.turn_id,
    )?;
    Ok(())
}

fn validate_activation_v1(
    events: &[JournalEvent],
    coordinator: &McpExecutionCoordinator,
) -> Result<u64> {
    let activations = events
        .iter()
        .filter(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
        .collect::<Vec<_>>();
    if activations.len() != 1 {
        return Err(OxidraError::Session(
            "MCP coordinator v1 requires exactly one registry activation per session".to_owned(),
        ));
    }
    let activation = activations[0];
    let policy = activation_policy_v1(activation)?;
    let expected_provider_names = coordinator
        .registry
        .bindings()
        .map(|binding| binding.provider_name.clone())
        .collect::<Vec<_>>();
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
        .collect::<Result<Vec<_>>>()?;
    if recorded_provider_names.len() != expected_provider_names.len()
        || recorded_provider_names.iter().collect::<BTreeSet<_>>()
            != expected_provider_names.iter().collect::<BTreeSet<_>>()
    {
        return Err(OxidraError::Session(
            "MCP registry activation provider_names do not match the live registry".to_owned(),
        ));
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

fn validate_new_activation_v1(events: &[JournalEvent]) -> Result<()> {
    if events
        .iter()
        .any(|event| event.kind == MCP_REGISTRY_ACTIVATED_KIND)
    {
        return Err(OxidraError::Session(
            "MCP coordinator v1 does not replace an existing registry activation".to_owned(),
        ));
    }
    Ok(())
}

fn activation_policy_v1(event: &JournalEvent) -> Result<McpCoordinatorPolicy> {
    match event
        .data
        .get("coordinator_version")
        .and_then(Value::as_u64)
    {
        Some(version) if version == u64::from(MCP_EXECUTION_COORDINATOR_VERSION_V1) => {
            Ok(MCP_COORDINATOR_POLICY_V1)
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

struct DurableProviderCall {
    provider_name: String,
    arguments: Value,
    registry_epoch_id: String,
    registry_digest: String,
    response_started_seq: u64,
    response_completed_seq: u64,
}

fn validate_call_after_activation_v1(
    durable_call: &DurableProviderCall,
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

fn provider_call_v1(
    events: &[JournalEvent],
    turn_id: &str,
    call_id: &str,
) -> Result<DurableProviderCall> {
    let mut found = None;
    for event in events.iter().filter(|event| {
        event.turn_id.as_deref() == Some(turn_id) && event.kind == "response.completed"
    }) {
        let items = event
            .data
            .get("output_items")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "response.completed at seq {} has no output_items",
                    event.seq
                ))
            })?;
        for item in items {
            if item.get("type").and_then(Value::as_str) != Some("function_call")
                || item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    != Some(call_id)
            {
                continue;
            }
            if found.is_some() {
                return Err(OxidraError::Session(format!(
                    "MCP call_id {call_id} appears more than once in turn {turn_id}"
                )));
            }
            let provider_name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    OxidraError::Session(format!("MCP call {call_id} has no Provider tool name"))
                })?;
            let arguments = match item.get("arguments") {
                Some(Value::String(arguments)) => {
                    serde_json::from_str(arguments).map_err(|error| {
                        OxidraError::Session(format!(
                            "MCP call {call_id} has invalid durable arguments: {error}"
                        ))
                    })?
                }
                Some(arguments) => arguments.clone(),
                None => {
                    return Err(OxidraError::Session(format!(
                        "MCP call {call_id} has no durable arguments"
                    )));
                }
            };
            let response_attempt_id = event
                .data
                .get("response_attempt_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "response.completed at seq {} has no response_attempt_id",
                        event.seq
                    ))
                })?;
            let response_started = events
                .iter()
                .find(|candidate| {
                    candidate.kind == "response.started"
                        && candidate.turn_id.as_deref() == Some(turn_id)
                        && candidate.seq < event.seq
                        && candidate
                            .data
                            .get("response_attempt_id")
                            .and_then(Value::as_str)
                            == Some(response_attempt_id)
                })
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "MCP call {call_id} has no matching response.started"
                    ))
                })?;
            let registry_epoch_id = response_started
                .data
                .get("mcp_registry_epoch_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "response.started at seq {} has no MCP registry epoch",
                        response_started.seq
                    ))
                })?;
            let registry_digest = response_started
                .data
                .get("mcp_registry_digest")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "response.started at seq {} has no MCP registry digest",
                        response_started.seq
                    ))
                })?;
            found = Some(DurableProviderCall {
                provider_name: provider_name.to_owned(),
                arguments,
                registry_epoch_id: registry_epoch_id.to_owned(),
                registry_digest: registry_digest.to_owned(),
                response_started_seq: response_started.seq,
                response_completed_seq: event.seq,
            });
        }
    }
    found.ok_or_else(|| {
        OxidraError::Session(format!(
            "MCP call {call_id} is not present in turn {turn_id}"
        ))
    })
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
    let policy = MCP_COORDINATOR_POLICY_V1;
    json!({
        "execution_coordinator_version": policy.coordinator_version,
        "dispatch_permit_version": policy.dispatch_permit_version,
        "argument_digest_version": policy.argument_digest_version,
        "registry_version": policy.registry_version,
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

    #[test]
    fn coordinator_versions_and_argument_digest_v1_are_frozen() {
        assert_eq!(MCP_EXECUTION_COORDINATOR_VERSION, 1);
        assert_eq!(MCP_DISPATCH_PERMIT_VERSION, 1);
        assert_eq!(MCP_ARGUMENT_DIGEST_VERSION, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.coordinator_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.dispatch_permit_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.argument_digest_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.registry_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.stdio_kernel_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.schema_profile_version, 1);
        assert_eq!(MCP_COORDINATOR_POLICY_V1.provider_slot_version, 2);
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
}
