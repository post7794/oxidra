//! The provider/tool/session orchestration layer.
//!
//! `Agent` is intentionally small: it owns one session journal and runs one
//! user turn at a time.  UI, approval prompts, and provider implementations
//! are supplied through traits so the core remains usable from tests and a
//! future TUI.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::compaction::{
    COMPACTION_BOUNDARY_ABANDONED_KIND, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
    COMPACTION_BOUNDARY_FAILED_KIND, COMPACTION_BOUNDARY_RETRY_STARTED_KIND,
    COMPACTION_BOUNDARY_STARTED_KIND, COMPACTION_STARTED_KIND, CandidateEstimate,
    CompactionBoundary, CompactionBoundaryAbandoned, CompactionBoundaryBudgetRetryStarted,
    CompactionBoundaryChain, CompactionBoundaryFailed, CompactionBoundaryRetryStarted,
    CompactionBoundaryStarted, CompactionBoundaryState, CompactionCandidate, CompactionContext,
    CompactionSelection, CompactionStarted, MAX_COMPACTION_OUTPUT_TOKENS,
    MIN_RECENT_COMPLETE_TURNS, SUMMARY_ENVELOPE_VERSION, ValidatedCompactionBoundary,
    attempt_boundary, compact_once_for_boundary, compact_replay_once_for_boundary,
    ensure_checkpointed_boundary_request_ready, ensure_compaction_boundary_turn_request_ready,
    rebuild_failed_boundary_candidate, select_compaction_candidate, validate_checkpoint_chain,
    validate_compaction_boundary_chain, validate_replay_compaction_candidate,
};
use crate::config::ContextLimits;
use crate::context::{
    AUTOMATIC_COMPACTION_PLANNING_VERSION, AUTOMATIC_COMPACTION_PLANNING_VERSION_V1,
    ContextDecision, ContextRuntime, decide_context, measure_prepared_request, snapshot_tools,
};
use crate::error::{OxidraError, Result};
use crate::history::{
    HISTORY_ARTIFACT_TOOL, HISTORY_CONTROL_OUTPUT_RESERVE_BYTES, HISTORY_SEARCH_TOOL,
    HISTORY_TURN_TOOL, HistoryQuota, HistorySearchRequest, HistorySnapshot, HistoryTurnRequest,
    MAX_HISTORY_CALLS_PER_RESPONSE, MAX_HISTORY_TOOL_OUTPUT_BYTES, MAX_HISTORY_TURN_OUTPUT_BYTES,
    history_tool_definitions, is_history_tool_name, rebuild_history_quota_for_compaction_preview,
    rebuild_history_quota_with_boundary_chain, serialized_history_tool_output_bytes,
    validate_history_snapshot_after_compaction,
};
use crate::history_artifact::{HistoryArtifactReader, HistoryArtifactRequest};
pub use crate::projection::project_events;
use crate::projection::{
    project_checkpoint_and_tail_for_recovery_planning,
    project_checkpoint_and_tail_with_boundary_chain, project_compaction_summary_and_tail,
    project_events_for_recovery_planning, project_events_with_boundary_chain,
    validate_response_output_items,
};
use crate::provider::{ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver};
use crate::session::{JournalEvent, SessionJournal};
use crate::tools::{BuiltinTools, ToolContext};
use crate::turn::{
    PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION, ProviderRequestSlotState,
    TURN_BOUNDARY_VALIDATOR_VERSION, TURN_BOUNDARY_VERSION, TurnState,
    complete_prefix_candidates_for_version, provider_request_slot_state_for_version, segment_turns,
    validate_turn_recovery,
};
use crate::types::{ToolCall, ToolDefinition, ToolResult, Usage};

const MAX_PROJECT_INSTRUCTIONS: usize = 32 * 1024;
const AUTOMATIC_COMPACTION_PLANNING_CONTEXT_MEASUREMENT_VERSION_V1: u32 = 2;
const AUTOMATIC_COMPACTION_PLANNING_CONTEXT_ESTIMATOR_VERSION_V1: u32 = 1;
const AUTOMATIC_COMPACTION_PLANNING_CONTEXT_REQUEST_SHAPE_VERSION_V1: u32 = 1;
const PROVIDER_CALL_BUDGET_VERSION_V1: u32 = 1;

/// Events emitted to the UI.  Streaming provider events are forwarded through
/// [`AgentObserver::on_provider_event`]; tool lifecycle events are committed before/after the
/// actual operation and therefore remain visible even when a process crashes.
pub trait AgentObserver: Send {
    fn on_response_started(&mut self) -> Result<()> {
        Ok(())
    }
    fn on_provider_event(&mut self, event: ProviderEvent) -> Result<()>;
    fn on_tool_started(&mut self, call: &ToolCall) -> Result<()>;
    fn on_tool_completed(&mut self, call: &ToolCall, result: &ToolResult) -> Result<()>;
    fn on_message(&mut self, message: &str) -> Result<()>;
    fn on_compaction(&mut self, message: &str) -> Result<()> {
        self.on_message(message)
    }

    /// Observability hook after a replacement compaction boundary is durable
    /// but before its candidate is planned. The default remains silent; process
    /// fault-injection tests block here and kill the writer.
    fn on_compaction_recovery_intent_synced(&mut self) -> Result<()> {
        Ok(())
    }

    /// Observability hook after the atomic legacy Provider-budget migration
    /// is durable but before the original turn starts another Provider
    /// request. Process fault-injection tests block here and kill the writer.
    fn on_compaction_budget_recovery_intent_synced(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The CLI implements this to keep shell authorization separate from project
/// instructions. Returning `false` is a normal tool result, not an agent failure.
#[async_trait]
pub trait ApprovalHandler: Send {
    async fn approve_shell(
        &mut self,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool>;

    async fn approve_memory(
        &mut self,
        content: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool>;
}

#[derive(Default)]
pub struct DenyApproval;

#[async_trait]
impl ApprovalHandler for DenyApproval {
    async fn approve_shell(
        &mut self,
        _command: &str,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        Ok(false)
    }

    async fn approve_memory(
        &mut self,
        _content: &str,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        Ok(false)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextEstimate {
    pub estimated_tokens: u64,
    pub context_window: Option<u64>,
    pub reserve_tokens: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TurnOutcome {
    pub text: String,
    pub responses: usize,
    pub tools: usize,
    pub stalled: bool,
    pub usage: Usage,
    pub context: Option<ContextEstimate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingContextTurn {
    pub turn_id: String,
    pub user_message_seq: u64,
    pub context_limit_seq: u64,
    pub prompt: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AbandonedPending {
    pub context_turns: usize,
    pub compaction_boundaries: usize,
}

#[derive(Clone)]
struct PlannedCompactionContinuationV1 {
    events: Arc<Vec<JournalEvent>>,
    boundary_chain: Arc<CompactionBoundaryChain>,
    instructions: Option<String>,
    tools: Vec<ToolDefinition>,
    context_runtime: ContextRuntime,
    covers_through_seq: u64,
    summary_envelope_version: u32,
}

impl PlannedCompactionContinuationV1 {
    fn context_for_summary(&self, summary: &str) -> Result<ContextDecision> {
        let input = project_compaction_summary_and_tail(
            self.events.as_slice(),
            self.covers_through_seq,
            self.summary_envelope_version,
            summary,
            self.boundary_chain.as_ref(),
        )?;
        let request = ResponseRequest {
            instructions: self.instructions.clone(),
            input,
            tools: self.tools.clone(),
            model: None,
            max_output_tokens: None,
        };
        let measured = measure_prepared_request(&request, &self.context_runtime)?;
        let instructions_event_seq = self
            .events
            .iter()
            .rev()
            .find(|event| event.kind == "context.instructions")
            .map(|event| event.seq);
        let configured_event_seq = self
            .events
            .iter()
            .rev()
            .find(|event| event.kind == "context.configured")
            .map(|event| event.seq);
        let tools_event_seq = self
            .events
            .iter()
            .rev()
            .find(|event| event.kind == "context.tools")
            .map_or(0, |event| event.seq);
        decide_context(
            self.events.as_slice(),
            &self.context_runtime,
            measured,
            self.events.last().map(|event| event.seq),
            Some("prospective-compaction-checkpoint".to_owned()),
            Some(self.covers_through_seq),
            instructions_event_seq,
            configured_event_seq,
            tools_event_seq,
        )
    }

    fn validate_summary(&self, summary: &str) -> Result<()> {
        let context = self.context_for_summary(summary)?;
        if let Some(target) = self.context_runtime.limits.target_tokens() {
            if context.estimated_next_input_tokens > target {
                return Err(OxidraError::Limit(format!(
                    "compaction summary leaves estimated context {} above target {target}",
                    context.estimated_next_input_tokens
                )));
            }
        }
        Ok(())
    }
}

struct AutomaticCompactionPlanV1 {
    snapshot: Vec<JournalEvent>,
    boundary: CompactionBoundary,
    current_context: ContextDecision,
    selection: CompactionSelection,
    continuations: HashMap<u64, PlannedCompactionContinuationV1>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct AutomaticCompactionPlanningMeasurementV1 {
    measurement_version: u32,
    estimator_version: u32,
    request_shape_version: u32,
    request_digest: String,
    estimated_input_tokens: u64,
}

/// Frozen reader for `planning_version = 1` metadata.
///
/// The journal currently stores the larger [`ContextDecision`] audit object,
/// but recovery only depends on this immutable subset. Future fields added to
/// `ContextDecision` therefore cannot silently change v1 replay semantics.
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct AutomaticCompactionPlanningContextV1 {
    measurement: AutomaticCompactionPlanningMeasurementV1,
    provider_usage_domain: String,
    estimated_next_input_tokens: u64,
    context_window: Option<u64>,
    reserve_tokens: u64,
    usable_tokens: Option<u64>,
    trigger_tokens: Option<u64>,
    target_tokens: Option<u64>,
    request_journal_through_seq: Option<u64>,
    checkpoint_id: Option<String>,
    checkpoint_covers_through_seq: Option<u64>,
    instructions_event_seq: Option<u64>,
    configured_event_seq: Option<u64>,
    tools_event_seq: u64,
}

struct PreparedRequestMaterials {
    request: ResponseRequest,
    definitions: Vec<ToolDefinition>,
    history: HistorySnapshot,
    history_quota: HistoryQuota,
    history_exposed: bool,
    checkpoint_id: Option<String>,
    checkpoint_covers_through_seq: Option<u64>,
}

enum RecoveryActionV1 {
    RetryContext {
        retry: PendingContextTurn,
        retry_intent: Option<Value>,
    },
    ResumeCheckpointed(ValidatedCompactionBoundary),
    ResumeBudgetLimitedCheckpoint {
        retry: CompactionBoundaryBudgetRetryStarted,
    },
    ReplayFailedBoundary {
        context_retry_intent: Option<Value>,
        retry: CompactionBoundaryRetryStarted,
        candidate: CompactionCandidate,
        continuation: PlannedCompactionContinuationV1,
    },
    ReplanFailedBoundary {
        context_retry_intent: Option<Value>,
        retry: CompactionBoundaryRetryStarted,
        current_context: Box<ContextDecision>,
    },
}

struct RecoveryPlanV1 {
    snapshot: Vec<JournalEvent>,
    action: RecoveryActionV1,
}

pub struct Agent {
    provider: Arc<dyn ResponseProvider>,
    journal: SessionJournal,
    tools: BuiltinTools,
    instructions: String,
    context_runtime: ContextRuntime,
    tools_epoch: Option<(String, u64)>,
    max_responses: Option<usize>,
    max_tools: Option<usize>,
    automatic_compaction: bool,
}

struct PreparedToolSet {
    definitions: Vec<ToolDefinition>,
    history: HistorySnapshot,
    history_quota: HistoryQuota,
    history_exposed: bool,
    context: ContextDecision,
}

struct ToolDispatchContext<'a> {
    observer: &'a mut dyn AgentObserver,
    approval: &'a mut dyn ApprovalHandler,
    prepared: &'a mut PreparedToolSet,
    remaining_history_calls: usize,
}

impl Agent {
    pub fn new(
        provider: Arc<dyn ResponseProvider>,
        journal: SessionJournal,
        tools: BuiltinTools,
        instructions: impl Into<String>,
        context_limits: ContextLimits,
        max_responses: Option<usize>,
        max_tools: Option<usize>,
    ) -> Self {
        Self::new_with_runtime(
            provider,
            journal,
            tools,
            instructions,
            ContextRuntime::for_tests("unspecified", context_limits),
            max_responses,
            max_tools,
        )
    }

    pub fn new_with_runtime(
        provider: Arc<dyn ResponseProvider>,
        journal: SessionJournal,
        tools: BuiltinTools,
        instructions: impl Into<String>,
        context_runtime: ContextRuntime,
        max_responses: Option<usize>,
        max_tools: Option<usize>,
    ) -> Self {
        Self {
            provider,
            journal,
            tools,
            instructions: instructions.into(),
            context_runtime,
            tools_epoch: None,
            max_responses,
            max_tools,
            automatic_compaction: false,
        }
    }

    pub(crate) fn set_automatic_compaction(&mut self, enabled: bool) {
        self.automatic_compaction = enabled;
    }

    pub fn session_id(&self) -> &str {
        self.journal.session_id()
    }

    pub fn journal(&self) -> &SessionJournal {
        &self.journal
    }

    pub fn journal_mut(&mut self) -> &mut SessionJournal {
        &mut self.journal
    }

    /// Run one complete user turn.  A successful return means every response
    /// and tool result that was claimed to have completed is in the journal.
    pub async fn run_turn(
        &mut self,
        prompt: &str,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        if prompt.trim().is_empty() {
            return Err(OxidraError::Config("prompt cannot be empty".to_owned()));
        }
        let in_doubt = self.journal.in_doubt()?;
        if !in_doubt.is_empty() {
            return Err(OxidraError::ApprovalRequired(format!(
                "session contains {} tool call(s) with unknown side effects",
                in_doubt.len()
            )));
        }
        let events = self.journal.read_events()?;
        let boundary_chain = validate_compaction_boundary_chain(&events)?;
        ensure_compaction_boundaries_allow_request(&events, &boundary_chain, None)?;
        let pending = pending_context_turns(&events)?;
        if !pending.is_empty() {
            return Err(OxidraError::ApprovalRequired(format!(
                "session contains {} context-limited turn(s); retry or abandon them before adding a new prompt",
                pending.len()
            )));
        }
        let turn_id = Uuid::now_v7().to_string();
        let user_item = json!({
            "role": "user",
            "content": prompt,
        });
        let user_event = self.journal.append_and_sync(
            "user.message",
            Some(&turn_id),
            json!({
                "item": user_item,
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
            }),
        )?;
        let turn_start_seq = user_event.seq;

        self.run_existing_turn(&turn_id, turn_start_seq, cancellation, observer, approval)
            .await
    }

    /// 从已同步的 user.message 继续执行；retry 恢复使用它避免重复追加 prompt。
    async fn run_existing_turn(
        &mut self,
        turn_id: &str,
        turn_start_seq: u64,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        self.run_existing_turn_with_accounting(
            turn_id,
            turn_start_seq,
            cancellation,
            observer,
            approval,
            Usage::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_existing_turn_with_accounting(
        &mut self,
        turn_id: &str,
        turn_start_seq: u64,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
        initial_usage: Usage,
    ) -> Result<TurnOutcome> {
        let mut outcome = TurnOutcome {
            usage: initial_usage,
            ..TurnOutcome::default()
        };
        let mut repeated_error: Option<(String, usize)> = None;

        loop {
            if cancellation.is_cancelled() {
                self.append_turn_cancelled(turn_id, "cancelled before response started")?;
                return Err(OxidraError::Interrupted);
            }
            let (request, mut prepared_tools) = self
                .prepare_request_with_automatic_compaction(
                    turn_id,
                    turn_start_seq,
                    cancellation.clone(),
                    observer,
                    &mut outcome.usage,
                )
                .await?;
            if cancellation.is_cancelled() {
                self.append_turn_cancelled(turn_id, "cancelled before response started")?;
                return Err(OxidraError::Interrupted);
            }
            let context = self.context_estimate(&prepared_tools.context);
            outcome.context = Some(context.clone());
            self.ensure_provider_call_budget(turn_id)?;
            let response_attempt_id = Uuid::now_v7().to_string();
            self.journal.append_and_sync(
                "response.started",
                Some(turn_id),
                json!({
                    "response_attempt_id": response_attempt_id,
                    "response_index": outcome.responses + 1,
                    "context": prepared_tools.context.audit_value()?,
                }),
            )?;
            if let Err(error) = observer.on_response_started() {
                let error = OxidraError::observer(error);
                self.append_response_aborted(turn_id, &response_attempt_id, &error.to_string())?;
                return Err(error);
            }
            let response = {
                let mut forward = ForwardObserver { observer };
                self.provider
                    .respond(request, &mut forward, cancellation.clone())
                    .await
            };

            let turn = match response {
                Ok(turn) => turn,
                Err(OxidraError::Interrupted) => {
                    self.append_response_aborted(turn_id, &response_attempt_id, "cancelled")?;
                    return Err(OxidraError::Interrupted);
                }
                Err(OxidraError::ResponseAborted(reason)) => {
                    self.append_response_aborted(turn_id, &response_attempt_id, &reason)?;
                    return Err(OxidraError::ResponseAborted(reason));
                }
                Err(error @ OxidraError::Observer(_)) => {
                    self.append_response_aborted(
                        turn_id,
                        &response_attempt_id,
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
                Err(OxidraError::ProviderContextLimit(reason)) => {
                    self.journal.append_and_sync(
                        "response.failed",
                        Some(turn_id),
                        json!({
                            "response_attempt_id": response_attempt_id,
                            "error": &reason,
                            "error_code": "provider_context_limit",
                        }),
                    )?;
                    self.journal.append_and_sync(
                        "context.limit_reached",
                        Some(turn_id),
                        json!({
                            "error": &reason,
                            "source": "provider",
                            "response_attempt_id": response_attempt_id,
                            "context": prepared_tools.context.audit_value()?,
                        }),
                    )?;
                    return Err(OxidraError::ProviderContextLimit(reason));
                }
                Err(error) => {
                    self.journal.append_and_sync(
                        "response.failed",
                        Some(turn_id),
                        json!({
                            "response_attempt_id": response_attempt_id,
                            "error": error.to_string(),
                        }),
                    )?;
                    return Err(error);
                }
            };

            if let Err(error) = validate_response_output_items(&turn.output_items) {
                self.journal.append_and_sync(
                    "response.failed",
                    Some(turn_id),
                    json!({
                        "response_attempt_id": response_attempt_id,
                        "error": error.to_string(),
                    }),
                )?;
                return Err(error);
            }
            if let Err(error) =
                validate_history_calls_for_response(&turn.tool_calls, &prepared_tools)
            {
                self.journal.append_and_sync(
                    "response.failed",
                    Some(turn_id),
                    json!({
                        "response_attempt_id": response_attempt_id,
                        "error": error.to_string(),
                    }),
                )?;
                return Err(error);
            }

            outcome.responses += 1;
            accumulate_usage(&mut outcome.usage, &turn.usage);
            let is_final_response = turn.tool_calls.is_empty();
            let response_seq = self.journal.next_seq();
            let mut response_data = json!({
                "response_attempt_id": response_attempt_id,
                "raw_response": turn.raw_response,
                "output_items": turn.output_items,
                "text": turn.text,
                "usage": turn.usage,
                "unknown_stream_events": turn.unknown_stream_events,
            });
            if is_final_response {
                response_data["turn_completion"] = json!({
                    "turn_boundary_version": TURN_BOUNDARY_VERSION,
                    "covers_from_seq": turn_start_seq,
                    "final_response_seq": response_seq,
                    "covers_through_seq": response_seq,
                });
            }
            let response_event =
                self.journal
                    .append_and_sync("response.completed", Some(turn_id), response_data)?;
            debug_assert_eq!(response_event.seq, response_seq);
            if is_final_response {
                outcome.text = turn.text;
                let marker_seq = self.journal.next_seq();
                self.journal.append_and_sync(
                    "turn.completed",
                    Some(turn_id),
                    json!({
                        "turn_boundary_version": TURN_BOUNDARY_VERSION,
                        "covers_from_seq": turn_start_seq,
                        "final_response_seq": response_event.seq,
                        "covers_through_seq": marker_seq,
                    }),
                )?;
                outcome.context = Some(self.next_context_estimate()?);
                return Ok(outcome);
            }

            for (index, call) in turn.tool_calls.iter().enumerate() {
                if self.max_tools.is_some_and(|limit| outcome.tools >= limit) {
                    self.mark_remaining_skipped(turn_id, &turn.tool_calls[index..], "tool limit")?;
                    self.journal.append_and_sync(
                        "agent.limit_reached",
                        Some(turn_id),
                        json!({ "kind": "tools", "limit": self.max_tools }),
                    )?;
                    return Err(OxidraError::Limit("max tools reached".to_owned()));
                }
                if cancellation.is_cancelled() {
                    self.mark_remaining_skipped(turn_id, &turn.tool_calls[index..], "cancelled")?;
                    self.append_turn_cancelled(turn_id, "cancelled before tool dispatch")?;
                    return Err(OxidraError::Interrupted);
                }

                let result = self
                    .execute_call(
                        turn_id,
                        call,
                        cancellation.clone(),
                        ToolDispatchContext {
                            observer,
                            approval,
                            prepared: &mut prepared_tools,
                            remaining_history_calls: turn.tool_calls[index..]
                                .iter()
                                .filter(|call| is_history_tool_name(&call.name))
                                .count(),
                        },
                    )
                    .await?;
                outcome.tools += 1;

                if result.error_code.as_deref() == Some("in_doubt") {
                    self.mark_remaining_skipped(
                        turn_id,
                        &turn.tool_calls[index + 1..],
                        "in_doubt",
                    )?;
                    return Err(OxidraError::tool(
                        "in_doubt",
                        format!(
                            "tool {} may have produced side effects; resolve it before continuing",
                            call.name
                        ),
                    ));
                }

                if result.is_error {
                    let key = error_fingerprint(call, &result);
                    let count = match &mut repeated_error {
                        Some((last_key, count)) if *last_key == key => {
                            *count += 1;
                            *count
                        }
                        _ => {
                            repeated_error = Some((key, 1));
                            1
                        }
                    };
                    if count >= 3 {
                        self.mark_remaining_skipped(
                            turn_id,
                            &turn.tool_calls[index + 1..],
                            "stalled",
                        )?;
                        observer.on_message("相同工具调用连续失败 3 次，已暂停以避免无效循环")?;
                        self.journal.append_and_sync(
                            "agent.stalled",
                            Some(turn_id),
                            json!({
                                "call_id": call.id,
                                "tool": call.name,
                                "reason": "repeated identical tool error",
                            }),
                        )?;
                        outcome.stalled = true;
                        outcome.context = Some(self.next_context_estimate()?);
                        return Ok(outcome);
                    }
                } else {
                    repeated_error = None;
                }

                if cancellation.is_cancelled() {
                    self.mark_remaining_skipped(
                        turn_id,
                        &turn.tool_calls[index + 1..],
                        "cancelled",
                    )?;
                    self.append_turn_cancelled(turn_id, "cancelled during tool execution")?;
                    return Err(OxidraError::Interrupted);
                }
            }
        }
    }

    /// 返回尚未被显式完成或放弃的 Provider context 超限回合。
    pub fn pending_context_turns(&self) -> Result<Vec<PendingContextTurn>> {
        pending_context_turns(&self.journal.read_events()?)
    }

    /// Return validated compaction boundaries that still own the original
    /// user request. Callers must resolve them before appending a new prompt.
    pub fn pending_compaction_boundaries(&self) -> Result<Vec<ValidatedCompactionBoundary>> {
        let events = self.journal.read_events()?;
        Ok(validate_compaction_boundary_chain(&events)?
            .pending()
            .into_iter()
            .cloned()
            .collect())
    }

    /// 以 append-only 事件放弃全部 pending 回合，不删除原始 journal 内容。
    pub fn abandon_pending_context_turns(&mut self, reason: &str) -> Result<usize> {
        let pending = self.pending_context_turns()?;
        for turn in &pending {
            self.journal.append_and_sync(
                "turn.abandoned",
                Some(&turn.turn_id),
                json!({
                    "user_message_seq": turn.user_message_seq,
                    "reason": reason,
                }),
            )?;
        }
        Ok(pending.len())
    }

    /// Resolve every pending recovery protocol without deleting journal data.
    ///
    /// Context-limit and compaction-boundary events are both appended because
    /// a checkpointed request can subsequently hit the Provider context limit.
    /// Each compaction abandon is dry-run through the canonical reducer before
    /// durable append so a control event can never poison the session merely
    /// because the CLI offered an invalid transition.
    pub fn abandon_pending_turns(&mut self, reason: &str) -> Result<AbandonedPending> {
        let context_turns = self.abandon_pending_context_turns(reason)?;
        let mut compaction_boundaries = 0usize;
        loop {
            let events = self.journal.read_events()?;
            let chain = validate_compaction_boundary_chain(&events)?;
            let Some(boundary) = chain.latest_pending().cloned() else {
                break;
            };
            let payload = CompactionBoundaryAbandoned {
                boundary_id: boundary.boundary.boundary_id,
                turn_id: boundary.boundary.turn_id,
                user_message_seq: boundary.boundary.user_message_seq,
                reason: reason.to_owned(),
                extra: Default::default(),
            };
            validate_next_compaction_boundary_event(
                &events,
                COMPACTION_BOUNDARY_ABANDONED_KIND,
                serde_json::to_value(&payload)?,
            )?;
            self.journal.append_and_sync(
                COMPACTION_BOUNDARY_ABANDONED_KIND,
                None,
                serde_json::to_value(payload)?,
            )?;
            compaction_boundaries = compaction_boundaries.saturating_add(1);
        }
        Ok(AbandonedPending {
            context_turns,
            compaction_boundaries,
        })
    }

    /// Derive one immutable recovery action from one durable journal snapshot.
    ///
    /// Recovery ownership is decided before any append. A failed compaction
    /// boundary outranks the context-limit state that caused it; otherwise the
    /// same prompt would repeatedly enter context-only retry and be rejected by
    /// the still-pending boundary during request preparation.
    fn build_recovery_plan_v1(&self) -> Result<RecoveryPlanV1> {
        let snapshot = self.journal.read_events()?;
        let context_pending = pending_context_turns(&snapshot)?;
        if context_pending.len() > 1 {
            return Err(OxidraError::ApprovalRequired(format!(
                "session has {} pending context-limited turns; abandon the legacy backlog before retrying",
                context_pending.len()
            )));
        }

        let boundary_chain = validate_compaction_boundary_chain(&snapshot)?;
        let boundary_pending = boundary_chain.pending();
        if boundary_pending.len() > 1 {
            return Err(OxidraError::ApprovalRequired(format!(
                "session has {} pending compaction boundaries; abandon the backlog before retrying",
                boundary_pending.len()
            )));
        }

        let context = context_pending.into_iter().next();
        let boundary = boundary_pending.into_iter().next().cloned();
        if let (Some(context), Some(boundary)) = (&context, &boundary) {
            if context.turn_id != boundary.boundary.turn_id
                || context.user_message_seq != boundary.boundary.user_message_seq
            {
                return Err(OxidraError::Session(format!(
                    "pending context turn {} at user.message seq {} conflicts with compaction boundary {} for turn {} at seq {}",
                    context.turn_id,
                    context.user_message_seq,
                    boundary.boundary.boundary_id,
                    boundary.boundary.turn_id,
                    boundary.boundary.user_message_seq
                )));
            }
        }

        let action = match boundary {
            None => {
                let retry = context.ok_or_else(|| {
                    OxidraError::Config("session has no pending turn to retry".to_owned())
                })?;
                self.plan_context_retry_v1(&snapshot, retry, None)?
            }
            Some(boundary) => match boundary.state {
                CompactionBoundaryState::Failed => {
                    match rebuild_failed_boundary_candidate(
                        &snapshot,
                        &boundary.boundary.boundary_id,
                    ) {
                        Ok(_) => self.plan_failed_boundary_replay_v1(
                            &snapshot,
                            &boundary,
                            context.as_ref(),
                        )?,
                        Err(OxidraError::ApprovalRequired(_)) => self
                            .plan_failed_boundary_replan_v1(
                                &snapshot,
                                &boundary,
                                context.as_ref(),
                            )?,
                        Err(error) => return Err(error),
                    }
                }
                CompactionBoundaryState::Checkpointed => {
                    if let Some(retry) = context {
                        self.plan_context_retry_v1(&snapshot, retry, Some(&boundary))?
                    } else {
                        self.plan_checkpointed_boundary_resume_v1(&snapshot, boundary)?
                    }
                }
                CompactionBoundaryState::Started => {
                    return Err(OxidraError::ApprovalRequired(
                        "compaction is still marked started; reopen the session to recover it before retrying"
                            .to_owned(),
                    ));
                }
                CompactionBoundaryState::Superseded
                | CompactionBoundaryState::Abandoned
                | CompactionBoundaryState::CompletedTurn => {
                    return Err(OxidraError::Session(format!(
                        "resolved compaction boundary {} was returned as pending",
                        boundary.boundary.boundary_id
                    )));
                }
            },
        };

        Ok(RecoveryPlanV1 { snapshot, action })
    }

    fn plan_checkpointed_boundary_resume_v1(
        &self,
        snapshot: &[JournalEvent],
        boundary: ValidatedCompactionBoundary,
    ) -> Result<RecoveryActionV1> {
        match ensure_checkpointed_boundary_request_ready(snapshot, &boundary) {
            Ok(()) => return Ok(RecoveryActionV1::ResumeCheckpointed(boundary)),
            Err(error) if boundary.boundary.version != 3 => return Err(error),
            Err(OxidraError::ApprovalRequired(_)) => {}
            Err(error) => return Err(error),
        }

        let limit = snapshot
            .iter()
            .rev()
            .find(|event| {
                event.seq > boundary.state_seq
                    && event.kind == "agent.limit_reached"
                    && event.turn_id.as_deref() == Some(boundary.boundary.turn_id.as_str())
                    && event.data.get("kind").and_then(Value::as_str) == Some("responses")
            })
            .ok_or_else(|| {
                OxidraError::ApprovalRequired(format!(
                    "checkpointed compaction boundary {} is terminal without a compatible Provider budget limit; abandon it",
                    boundary.boundary.boundary_id
                ))
            })?;
        let previous_limit = limit
            .data
            .get("limit")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "agent.limit_reached at seq {} has no positive response limit",
                    limit.seq
                ))
            })?;
        let consumed =
            durable_provider_call_intents_for_turn(snapshot, &boundary.boundary.turn_id)?;
        let consumed_u64 = u64::try_from(consumed).map_err(|_| {
            OxidraError::Session("Provider call intent count exceeds u64".to_owned())
        })?;
        let current_limit = self
            .max_responses
            .map(|limit| {
                u64::try_from(limit)
                    .map_err(|_| OxidraError::Config("max responses exceeds u64".to_owned()))
            })
            .transpose()?;
        if current_limit.is_some_and(|limit| limit <= consumed_u64) {
            return Err(OxidraError::Limit(format!(
                "max responses reached: {consumed_u64} durable Provider calls already consumed"
            )));
        }

        let replacement = CompactionBoundary::new(
            Uuid::now_v7().to_string(),
            boundary.boundary.turn_id.clone(),
            boundary.boundary.user_message_seq,
        );
        let retry = CompactionBoundaryBudgetRetryStarted {
            retry_version: 1,
            retry_id: Uuid::now_v7().to_string(),
            previous_boundary_id: boundary.boundary.boundary_id,
            boundary: replacement.clone(),
            checkpoint_id: boundary.checkpoint_id.ok_or_else(|| {
                OxidraError::Session(
                    "checkpointed compaction boundary has no checkpoint id".to_owned(),
                )
            })?,
            limit_seq: limit.seq,
            previous_limit,
            current_limit,
            budget_disabled: current_limit.is_none(),
            consumed_provider_call_intents: consumed_u64,
            extra: Map::new(),
        };
        let mut prospective = snapshot.to_vec();
        append_prospective_event(
            &mut prospective,
            COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
            None,
            serde_json::to_value(&retry)?,
        )?;
        let prospective_chain = validate_compaction_boundary_chain(&prospective)?;
        let replacement_record = prospective_chain
            .latest_pending()
            .filter(|record| record.boundary == replacement)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "Provider budget retry boundary {} is not the unique pending recovery owner",
                    replacement.boundary_id
                ))
            })?;
        ensure_checkpointed_boundary_request_ready(&prospective, replacement_record)?;
        Ok(RecoveryActionV1::ResumeBudgetLimitedCheckpoint { retry })
    }

    fn plan_context_retry_v1(
        &self,
        snapshot: &[JournalEvent],
        retry: PendingContextTurn,
        checkpointed_boundary: Option<&ValidatedCompactionBoundary>,
    ) -> Result<RecoveryActionV1> {
        let retry_intent = planned_context_retry_intent(snapshot, &retry)?;
        let mut prospective = snapshot.to_vec();
        if let Some(intent) = &retry_intent {
            append_prospective_event(
                &mut prospective,
                "turn.retry_started",
                Some(&retry.turn_id),
                intent.clone(),
            )?;
        }
        validate_turn_recovery(&prospective)?;
        let prospective_boundaries = validate_compaction_boundary_chain(&prospective)?;
        let slot = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &prospective,
            &retry.turn_id,
        )?;
        if slot != ProviderRequestSlotState::Ready {
            return Err(OxidraError::ApprovalRequired(format!(
                "context-limit retry for turn {} cannot dispatch from Provider request-slot state {slot:?}",
                retry.turn_id
            )));
        }
        if let Some(boundary) = checkpointed_boundary {
            let prospective_boundary = prospective_boundaries
                .boundaries()
                .iter()
                .find(|candidate| candidate.boundary.boundary_id == boundary.boundary.boundary_id)
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "checkpointed compaction boundary {} disappeared during recovery planning",
                        boundary.boundary.boundary_id
                    ))
                })?;
            ensure_checkpointed_boundary_request_ready(&prospective, prospective_boundary)?;
        }
        Ok(RecoveryActionV1::RetryContext {
            retry,
            retry_intent,
        })
    }

    fn plan_failed_boundary_replay_v1(
        &self,
        snapshot: &[JournalEvent],
        boundary: &ValidatedCompactionBoundary,
        context: Option<&PendingContextTurn>,
    ) -> Result<RecoveryActionV1> {
        let candidate =
            rebuild_failed_boundary_candidate(snapshot, &boundary.boundary.boundary_id)?;
        let context_retry_intent = context
            .map(|retry| planned_context_retry_intent(snapshot, retry))
            .transpose()?
            .flatten();
        let replacement = CompactionBoundary::new(
            Uuid::now_v7().to_string(),
            boundary.boundary.turn_id.clone(),
            boundary.boundary.user_message_seq,
        );
        let retry = CompactionBoundaryRetryStarted {
            retry_id: Uuid::now_v7().to_string(),
            previous_boundary_id: boundary.boundary.boundary_id.clone(),
            boundary: replacement.clone(),
            extra: Default::default(),
        };

        let mut prospective = snapshot.to_vec();
        if let Some(intent) = &context_retry_intent {
            append_prospective_event(
                &mut prospective,
                "turn.retry_started",
                Some(&replacement.turn_id),
                intent.clone(),
            )?;
        }
        validate_turn_recovery(&prospective)?;
        append_prospective_event(
            &mut prospective,
            COMPACTION_BOUNDARY_RETRY_STARTED_KIND,
            None,
            serde_json::to_value(&retry)?,
        )?;

        let prospective_boundaries = validate_compaction_boundary_chain(&prospective)?;
        let replacement_record = prospective_boundaries
            .latest_pending()
            .filter(|record| record.boundary == replacement)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "replacement compaction boundary {} is not the unique pending recovery owner",
                    replacement.boundary_id
                ))
            })?;
        if replacement_record.state != CompactionBoundaryState::Started {
            return Err(OxidraError::Session(format!(
                "replacement compaction boundary {} planned state is {:?}, not Started",
                replacement.boundary_id, replacement_record.state
            )));
        }
        ensure_compaction_boundary_turn_request_ready(&prospective, &replacement)?;
        validate_replay_compaction_candidate(&prospective, &candidate)?;

        let continuation = self.build_planned_compaction_continuation_v1(
            Arc::new(prospective),
            Arc::new(prospective_boundaries),
            &replacement.turn_id,
            candidate.covers_through_seq,
            candidate.summary_envelope_version,
        )?;
        // Exercise the same tail projection and request measurement before any
        // retry intent is durable. The real summary is checked again in the
        // pre-commit callback.
        continuation.validate_summary("x")?;

        Ok(RecoveryActionV1::ReplayFailedBoundary {
            context_retry_intent,
            retry,
            candidate,
            continuation,
        })
    }

    fn plan_failed_boundary_replan_v1(
        &self,
        snapshot: &[JournalEvent],
        boundary: &ValidatedCompactionBoundary,
        context: Option<&PendingContextTurn>,
    ) -> Result<RecoveryActionV1> {
        // The historical planning object proves that this lineage was created
        // by a supported automatic preflight protocol. It is audit evidence,
        // not the runtime decision used after resume.
        let _recorded_context = rebuild_automatic_compaction_planning_context_v1(
            snapshot,
            &boundary.boundary.boundary_id,
        )?;

        let context_retry_intent = context
            .map(|retry| planned_context_retry_intent(snapshot, retry))
            .transpose()?
            .flatten();
        let replacement = CompactionBoundary::new(
            Uuid::now_v7().to_string(),
            boundary.boundary.turn_id.clone(),
            boundary.boundary.user_message_seq,
        );
        let mut retry = CompactionBoundaryRetryStarted {
            retry_id: Uuid::now_v7().to_string(),
            previous_boundary_id: boundary.boundary.boundary_id.clone(),
            boundary: replacement,
            extra: Map::new(),
        };

        let mut prospective = snapshot.to_vec();
        if let Some(intent) = &context_retry_intent {
            append_prospective_event(
                &mut prospective,
                "turn.retry_started",
                Some(&retry.boundary.turn_id),
                intent.clone(),
            )?;
        }
        validate_turn_recovery(&prospective)?;
        append_prospective_event(
            &mut prospective,
            COMPACTION_BOUNDARY_RETRY_STARTED_KIND,
            None,
            serde_json::to_value(&retry)?,
        )?;
        let prospective_boundaries = validate_compaction_boundary_chain(&prospective)?;
        let replacement_record = prospective_boundaries
            .latest_pending()
            .filter(|record| record.boundary == retry.boundary)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "replacement compaction boundary {} is not the unique pending recovery owner",
                    retry.boundary.boundary_id
                ))
            })?;
        if replacement_record.state != CompactionBoundaryState::Started {
            return Err(OxidraError::Session(format!(
                "replacement compaction boundary {} planned state is {:?}, not Started",
                retry.boundary.boundary_id, replacement_record.state
            )));
        }
        ensure_compaction_boundary_turn_request_ready(&prospective, &retry.boundary)?;

        let current_context = self.measure_replan_context_v1(
            &prospective,
            &prospective_boundaries,
            &retry.boundary.turn_id,
        )?;
        let trigger = current_context.trigger_tokens.ok_or_else(|| {
            OxidraError::Config(
                "automatic compaction recovery requires a current trigger token count".to_owned(),
            )
        })?;
        current_context.target_tokens.ok_or_else(|| {
            OxidraError::Config(
                "automatic compaction recovery requires a current target token count".to_owned(),
            )
        })?;
        if current_context.estimated_next_input_tokens < trigger {
            return Err(OxidraError::ApprovalRequired(format!(
                "current request estimate {} is below the current automatic compaction trigger {trigger}; the failed boundary cannot be replayed safely without a resolved-without-checkpoint protocol, so abandon it before continuing",
                current_context.estimated_next_input_tokens
            )));
        }

        retry.extra.insert(
            "planning_version".to_owned(),
            json!(AUTOMATIC_COMPACTION_PLANNING_VERSION),
        );
        retry.extra.insert(
            "context".to_owned(),
            automatic_compaction_planning_context_value_v1(&current_context)?,
        );
        let retry_event = prospective
            .last_mut()
            .ok_or_else(|| OxidraError::Session("prospective retry journal is empty".to_owned()))?;
        retry_event.data = serde_json::to_value(&retry)?;
        validate_compaction_boundary_chain(&prospective)?;

        Ok(RecoveryActionV1::ReplanFailedBoundary {
            context_retry_intent,
            retry,
            current_context: Box::new(current_context),
        })
    }

    fn build_planned_compaction_continuation_v1(
        &self,
        events: Arc<Vec<JournalEvent>>,
        boundary_chain: Arc<CompactionBoundaryChain>,
        turn_id: &str,
        covers_through_seq: u64,
        summary_envelope_version: u32,
    ) -> Result<PlannedCompactionContinuationV1> {
        let checkpoint_chain = validate_checkpoint_chain(events.as_slice())?;
        let prospective_history = validate_history_snapshot_after_compaction(
            events.as_slice(),
            &checkpoint_chain,
            boundary_chain.as_ref(),
            covers_through_seq,
        )?;
        let history_quota = rebuild_history_quota_for_compaction_preview(
            events.as_slice(),
            turn_id,
            boundary_chain.as_ref(),
        )?;
        let history_exposed = prospective_history.is_available()
            && history_quota.remaining_bytes
                >= MAX_HISTORY_CALLS_PER_RESPONSE
                    .saturating_mul(HISTORY_CONTROL_OUTPUT_RESERVE_BYTES);
        let mut tools = self.tools.definitions();
        if history_exposed {
            tools.extend(history_tool_definitions());
        }
        Ok(PlannedCompactionContinuationV1 {
            events,
            boundary_chain,
            instructions: (!self.instructions.is_empty()).then(|| self.instructions.clone()),
            tools,
            context_runtime: self.context_runtime.clone(),
            covers_through_seq,
            summary_envelope_version,
        })
    }

    /// Retry the single pending user request, regardless of which recovery
    /// protocol owns it.
    ///
    /// A context-limit retry keeps its existing `turn.retry_started` intent.
    /// A checkpointed compaction boundary resumes the normal Provider request.
    /// A failed compaction boundary first persists a new boundary retry intent,
    /// replays the last durable candidate in its lineage, then resumes the
    /// original user turn after the replacement checkpoint is synced.
    pub async fn retry_pending_turn(
        &mut self,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        let RecoveryPlanV1 { snapshot, action } = self.build_recovery_plan_v1()?;
        if self.journal.read_events()? != snapshot {
            return Err(OxidraError::Session(
                "journal changed after recovery planning".to_owned(),
            ));
        }
        match action {
            RecoveryActionV1::RetryContext {
                retry,
                retry_intent,
            } => {
                self.ensure_provider_call_budget(&retry.turn_id)?;
                self.retry_pending_context_turn_from_snapshot(
                    &snapshot,
                    &retry,
                    retry_intent,
                    cancellation,
                    observer,
                    approval,
                )
                .await
            }
            RecoveryActionV1::ResumeCheckpointed(boundary) => {
                self.run_existing_turn(
                    &boundary.boundary.turn_id,
                    boundary.boundary.user_message_seq,
                    cancellation,
                    observer,
                    approval,
                )
                .await
            }
            RecoveryActionV1::ResumeBudgetLimitedCheckpoint { retry } => {
                let replacement = retry.boundary.clone();
                self.ensure_provider_call_budget(&replacement.turn_id)?;
                self.journal.append_and_sync(
                    COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
                    None,
                    serde_json::to_value(retry)?,
                )?;
                if let Err(error) = observer.on_compaction_budget_recovery_intent_synced() {
                    return Err(OxidraError::observer(error));
                }
                self.run_existing_turn(
                    &replacement.turn_id,
                    replacement.user_message_seq,
                    cancellation,
                    observer,
                    approval,
                )
                .await
            }
            RecoveryActionV1::ReplayFailedBoundary {
                context_retry_intent,
                retry,
                candidate,
                continuation,
            } => {
                let replacement = retry.boundary.clone();
                self.ensure_provider_call_budget(&replacement.turn_id)?;
                if let Some(intent) = context_retry_intent {
                    self.journal.append_and_sync(
                        "turn.retry_started",
                        Some(&replacement.turn_id),
                        intent,
                    )?;
                }
                self.journal.append_and_sync(
                    COMPACTION_BOUNDARY_RETRY_STARTED_KIND,
                    None,
                    serde_json::to_value(retry)?,
                )?;
                let mut compaction_observer = SilentCompactionObserver;
                let checkpoint = compact_replay_once_for_boundary(
                    self.provider.as_ref(),
                    &mut self.journal,
                    &replacement,
                    &candidate,
                    &self.context_runtime.model,
                    &mut compaction_observer,
                    cancellation.clone(),
                    move |summary| continuation.validate_summary(summary),
                )
                .await?;
                let mut usage = Usage::default();
                accumulate_usage_value(&mut usage, &checkpoint.usage)?;
                self.run_existing_turn_with_accounting(
                    &replacement.turn_id,
                    replacement.user_message_seq,
                    cancellation,
                    observer,
                    approval,
                    usage,
                )
                .await
            }
            RecoveryActionV1::ReplanFailedBoundary {
                context_retry_intent,
                retry,
                current_context,
            } => {
                let replacement = retry.boundary.clone();
                self.ensure_provider_call_budget(&replacement.turn_id)?;
                if let Some(intent) = context_retry_intent {
                    self.journal.append_and_sync(
                        "turn.retry_started",
                        Some(&replacement.turn_id),
                        intent,
                    )?;
                }
                self.journal.append_and_sync(
                    COMPACTION_BOUNDARY_RETRY_STARTED_KIND,
                    None,
                    serde_json::to_value(&retry)?,
                )?;

                if let Err(error) = observer.on_compaction_recovery_intent_synced() {
                    self.append_automatic_compaction_preflight_failure(
                        &replacement,
                        "observer_failed",
                        &error.to_string(),
                    )?;
                    return Err(error);
                }

                if cancellation.is_cancelled() {
                    self.append_automatic_compaction_preflight_failure(
                        &replacement,
                        "cancelled",
                        "automatic compaction recovery was cancelled before candidate planning",
                    )?;
                    return Err(OxidraError::Interrupted);
                }

                let plan =
                    match self.build_automatic_compaction_plan_v1(replacement, *current_context) {
                        Ok(plan) => plan,
                        Err(error) => {
                            self.append_automatic_compaction_preflight_failure(
                                &retry.boundary,
                                "preflight_failed",
                                &error.to_string(),
                            )?;
                            return Err(error);
                        }
                    };
                let AutomaticCompactionPlanV1 {
                    snapshot: plan_snapshot,
                    boundary: planned_boundary,
                    selection,
                    mut continuations,
                    ..
                } = plan;
                if self.journal.read_events()? != plan_snapshot {
                    let error = OxidraError::Session(
                        "journal changed after automatic compaction recovery planning".to_owned(),
                    );
                    self.append_automatic_compaction_preflight_failure(
                        &planned_boundary,
                        "snapshot_changed",
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
                let candidate = match selection {
                    CompactionSelection::Selected(candidate) => candidate,
                    CompactionSelection::Unavailable(reason) => {
                        let message = format!(
                            "automatic compaction recovery has no safe candidate: {reason}"
                        );
                        self.append_automatic_compaction_preflight_failure(
                            &planned_boundary,
                            "no_candidate",
                            &message,
                        )?;
                        return Err(OxidraError::Limit(message));
                    }
                };
                let Some(continuation) = continuations.remove(&candidate.covers_through_seq) else {
                    let error = OxidraError::Session(format!(
                        "selected compaction cutoff {} has no prepared continuation",
                        candidate.covers_through_seq
                    ));
                    self.append_automatic_compaction_preflight_failure(
                        &planned_boundary,
                        "invalid_plan",
                        &error.to_string(),
                    )?;
                    return Err(error);
                };

                let mut compaction_observer = SilentCompactionObserver;
                let checkpoint = compact_once_for_boundary(
                    self.provider.as_ref(),
                    &mut self.journal,
                    &planned_boundary,
                    &candidate,
                    &self.context_runtime.model,
                    &mut compaction_observer,
                    cancellation.clone(),
                    move |summary| continuation.validate_summary(summary),
                )
                .await?;
                let mut usage = Usage::default();
                accumulate_usage_value(&mut usage, &checkpoint.usage)?;
                self.run_existing_turn_with_accounting(
                    &planned_boundary.turn_id,
                    planned_boundary.user_message_seq,
                    cancellation,
                    observer,
                    approval,
                    usage,
                )
                .await
            }
        }
    }

    /// 持久化 retry intent 后在原 turn 上继续，崩溃恢复不会重复追加 prompt。
    pub async fn retry_pending_context_turn(
        &mut self,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        let RecoveryPlanV1 { snapshot, action } = self.build_recovery_plan_v1()?;
        if self.journal.read_events()? != snapshot {
            return Err(OxidraError::Session(
                "journal changed after recovery planning".to_owned(),
            ));
        }
        let RecoveryActionV1::RetryContext {
            retry,
            retry_intent,
        } = action
        else {
            return Err(OxidraError::ApprovalRequired(
                "the pending request is owned by compaction recovery; use the unified pending retry"
                    .to_owned(),
            ));
        };
        self.ensure_provider_call_budget(&retry.turn_id)?;
        self.retry_pending_context_turn_from_snapshot(
            &snapshot,
            &retry,
            retry_intent,
            cancellation,
            observer,
            approval,
        )
        .await
    }

    async fn retry_pending_context_turn_from_snapshot(
        &mut self,
        snapshot: &[JournalEvent],
        retry: &PendingContextTurn,
        retry_intent: Option<Value>,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        if self.journal.read_events()? != snapshot {
            return Err(OxidraError::Session(
                "journal changed before context retry intent was committed".to_owned(),
            ));
        }
        if let Some(intent) = retry_intent {
            self.journal
                .append_and_sync("turn.retry_started", Some(&retry.turn_id), intent)?;
        }
        self.run_existing_turn(
            &retry.turn_id,
            retry.user_message_seq,
            cancellation,
            observer,
            approval,
        )
        .await
    }

    async fn execute_call(
        &mut self,
        turn_id: &str,
        call: &ToolCall,
        cancellation: CancellationToken,
        dispatch: ToolDispatchContext<'_>,
    ) -> Result<ToolResult> {
        let ToolDispatchContext {
            observer,
            approval,
            prepared,
            remaining_history_calls,
        } = dispatch;
        if is_history_tool_name(&call.name) {
            return self
                .execute_history_call(
                    turn_id,
                    call,
                    cancellation,
                    observer,
                    prepared,
                    remaining_history_calls,
                )
                .await;
        }

        let definition = prepared
            .definitions
            .iter()
            .find(|definition| definition.name == call.name);
        let Some(definition) = definition else {
            let result = ToolResult::error(&call.id, "not_found", "tool is not registered");
            self.commit_tool_completed(turn_id, call, &result, observer)?;
            return Ok(result);
        };
        if let Err(message) = validate_json_schema(&definition.input_schema, &call.arguments) {
            let result = ToolResult::error(
                &call.id,
                "validation_error",
                format!("invalid arguments for {}: {message}", call.name),
            );
            self.commit_tool_completed(turn_id, call, &result, observer)?;
            return Ok(result);
        }

        let shell_approved = if call.name == "shell" {
            let command = call
                .arguments
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            approval.approve_shell(command, &cancellation).await?
        } else {
            false
        };
        let memory_approved = if call.name == "remember" {
            let content = call
                .arguments
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            approval.approve_memory(content, &cancellation).await?
        } else {
            false
        };

        // Authorization is a decision point, not tool execution.  Record
        // `tool.started` only after approval succeeds so a crash while the
        // prompt is waiting cannot turn an unexecuted persistent action into
        // an in-doubt side effect.
        if cancellation.is_cancelled() {
            let result =
                ToolResult::error(&call.id, "cancelled", "tool was cancelled before start");
            self.journal.append_and_sync(
                "tool.cancelled",
                Some(turn_id),
                json!({
                    "call_id": call.id,
                    "tool": call.name,
                    "output": result.output,
                    "error_code": result.error_code,
                    "before_start": true,
                }),
            )?;
            observer.on_tool_completed(call, &result)?;
            return Ok(result);
        }

        if call.name == "shell" && !shell_approved {
            let result = ToolResult::error(
                &call.id,
                "approval_required",
                "shell command requires user confirmation",
            );
            self.commit_tool_completed(turn_id, call, &result, observer)?;
            return Ok(result);
        }
        if call.name == "remember" && !memory_approved {
            let result = ToolResult::error(
                &call.id,
                "approval_required",
                "remember requires user confirmation",
            );
            self.commit_tool_completed(turn_id, call, &result, observer)?;
            return Ok(result);
        }

        observer.on_tool_started(call)?;
        self.journal.append_and_sync(
            "tool.started",
            Some(turn_id),
            json!({
                "call_id": call.id,
                "tool": call.name,
                "arguments": call.arguments,
            }),
        )?;

        let context = ToolContext::new(cancellation.clone())
            .with_shell_approval(shell_approved)
            .with_memory_approval(memory_approved);
        let result = self.tools.execute(call, &context).await;

        if result.error_code.as_deref() == Some("in_doubt") {
            self.journal.append_and_sync(
                "tool.in_doubt",
                Some(turn_id),
                json!({
                    "call_id": call.id,
                    "tool": call.name,
                    "arguments": call.arguments,
                    "output": result.output,
                    "error_code": "in_doubt",
                }),
            )?;
            observer.on_tool_completed(call, &result)?;
            return Ok(result);
        }

        if cancellation.is_cancelled() && result.error_code.as_deref() == Some("cancelled") {
            self.journal.append_and_sync(
                "tool.cancelled",
                Some(turn_id),
                json!({
                    "call_id": call.id,
                    "tool": call.name,
                    "output": result.output,
                    "error_code": result.error_code,
                }),
            )?;
            observer.on_tool_completed(call, &result)?;
            return Ok(result);
        }

        self.commit_tool_completed(turn_id, call, &result, observer)?;
        Ok(result)
    }

    async fn execute_history_call(
        &mut self,
        turn_id: &str,
        call: &ToolCall,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        prepared: &mut PreparedToolSet,
        remaining_history_calls: usize,
    ) -> Result<ToolResult> {
        let future_reserve = remaining_history_calls
            .saturating_sub(1)
            .saturating_mul(HISTORY_CONTROL_OUTPUT_RESERVE_BYTES);
        let output_budget = prepared
            .history_quota
            .remaining_bytes
            .saturating_sub(future_reserve)
            .min(MAX_HISTORY_TOOL_OUTPUT_BYTES);

        let definition = prepared
            .definitions
            .iter()
            .find(|definition| definition.name == call.name);
        let mut started = false;
        let mut result = if !prepared.history_exposed || definition.is_none() {
            if prepared.history.is_available() {
                ToolResult::error(
                    &call.id,
                    "history_quota_exhausted",
                    "history tools are unavailable because this turn's history quota is exhausted",
                )
            } else {
                ToolResult::error(
                    &call.id,
                    "history_not_available",
                    "no valid compaction checkpoint is available",
                )
            }
        } else if let Err(message) = validate_json_schema(
            &definition.expect("definition was checked").input_schema,
            &call.arguments,
        ) {
            ToolResult::error(
                &call.id,
                "validation_error",
                format!("invalid arguments for {}: {message}", call.name),
            )
        } else if cancellation.is_cancelled() {
            ToolResult::error(&call.id, "cancelled", "history lookup was cancelled")
        } else {
            observer.on_tool_started(call)?;
            self.journal.append_and_sync(
                "tool.started",
                Some(turn_id),
                json!({
                    "call_id": call.id,
                    "tool": call.name,
                    "arguments": call.arguments,
                }),
            )?;
            started = true;
            match self
                .run_history_tool(call, &prepared.history, output_budget, &cancellation)
                .await
            {
                Ok(output) => ToolResult::success(&call.id, output),
                Err(OxidraError::Tool { code, message }) => {
                    ToolResult::error(&call.id, code, message)
                }
                Err(OxidraError::Interrupted) => {
                    ToolResult::error(&call.id, "cancelled", "history lookup was cancelled")
                }
                // history_* is read-only. Once started is durable, every
                // local parsing/IO failure is a known failure rather than an
                // unknown side effect, so always close it with a terminal.
                Err(error) => ToolResult::error(&call.id, "history_error", error.to_string()),
            }
        };

        if serialized_history_tool_output_bytes(&call.id, &result.output)? > output_budget {
            result = ToolResult::error(
                &call.id,
                "history_quota_exhausted",
                "remaining history quota cannot fit this result",
            );
        }
        let output_bytes = serialized_history_tool_output_bytes(&call.id, &result.output)?;
        if output_bytes > output_budget {
            return Err(OxidraError::Session(
                "reserved history control output does not fit the remaining quota".to_owned(),
            ));
        }
        prepared.history_quota.used_bytes = prepared
            .history_quota
            .used_bytes
            .saturating_add(output_bytes);
        prepared.history_quota.remaining_bytes =
            MAX_HISTORY_TURN_OUTPUT_BYTES.saturating_sub(prepared.history_quota.used_bytes);
        prepared.history_quota.exhausted =
            prepared.history_quota.used_bytes >= MAX_HISTORY_TURN_OUTPUT_BYTES;
        if result.error_code.as_deref() == Some("cancelled") {
            self.journal.append_and_sync(
                "tool.cancelled",
                Some(turn_id),
                json!({
                    "call_id": result.call_id,
                    "tool": call.name,
                    "output": result.output,
                    "is_error": true,
                    "error_code": "cancelled",
                    "before_start": !started,
                }),
            )?;
            observer.on_tool_completed(call, &result)?;
        } else {
            self.commit_tool_completed(turn_id, call, &result, observer)?;
        }
        Ok(result)
    }

    async fn run_history_tool(
        &self,
        call: &ToolCall,
        snapshot: &HistorySnapshot,
        output_budget: usize,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        let output = match call.name.as_str() {
            HISTORY_SEARCH_TOOL => {
                let request =
                    serde_json::from_value::<HistorySearchRequest>(call.arguments.clone())
                        .map_err(|error| {
                            OxidraError::tool("validation_error", error.to_string())
                        })?;
                serde_json::to_value(snapshot.search(&request)?)?
            }
            HISTORY_TURN_TOOL => {
                let request = serde_json::from_value::<HistoryTurnRequest>(call.arguments.clone())
                    .map_err(|error| OxidraError::tool("validation_error", error.to_string()))?;
                serde_json::to_value(snapshot.turn(&request)?)?
            }
            HISTORY_ARTIFACT_TOOL => {
                let request =
                    serde_json::from_value::<HistoryArtifactRequest>(call.arguments.clone())
                        .map_err(|error| {
                            OxidraError::tool("validation_error", error.to_string())
                        })?;
                return HistoryArtifactReader::new(self.tools.artifact_dir())?
                    .read(snapshot, &request, &call.id, output_budget, cancellation)
                    .await;
            }
            _ => unreachable!("history tool name was validated"),
        };
        if serialized_history_tool_output_bytes(&call.id, &output)? > output_budget {
            return Err(OxidraError::tool(
                "history_quota_exhausted",
                "remaining history quota cannot fit this history page",
            ));
        }
        Ok(output)
    }

    fn commit_tool_completed(
        &mut self,
        turn_id: &str,
        call: &ToolCall,
        result: &ToolResult,
        observer: &mut dyn AgentObserver,
    ) -> Result<()> {
        self.journal.append_and_sync(
            "tool.completed",
            Some(turn_id),
            json!({
                "call_id": result.call_id,
                "tool": call.name,
                "output": result.output,
                "is_error": result.is_error,
                "error_code": result.error_code,
            }),
        )?;
        observer.on_tool_completed(call, result)
    }

    fn mark_remaining_skipped(
        &mut self,
        turn_id: &str,
        calls: &[ToolCall],
        reason: &str,
    ) -> Result<()> {
        let (kind, code) = match reason {
            "cancelled" => ("tool.skipped_due_to_cancel", "cancelled"),
            "in_doubt" => ("tool.skipped_due_to_in_doubt", "in_doubt"),
            "stalled" => ("tool.skipped_due_to_stalled", "stalled"),
            _ => ("tool.skipped_due_to_limit", "limit_reached"),
        };
        for call in calls {
            self.journal.append_and_sync(
                kind,
                Some(turn_id),
                json!({
                    "call_id": call.id,
                    "tool": call.name,
                    "arguments": call.arguments,
                    "reason": reason,
                    "output": {
                        "error": {
                            "code": code,
                            "message": format!("tool was not executed: {reason}"),
                        }
                    },
                    "is_error": true,
                    "error_code": code,
                }),
            )?;
        }
        Ok(())
    }

    fn append_response_aborted(
        &mut self,
        turn_id: &str,
        response_attempt_id: &str,
        reason: &str,
    ) -> Result<()> {
        self.journal.append_and_sync(
            "response.aborted",
            Some(turn_id),
            json!({
                "response_attempt_id": response_attempt_id,
                "reason": reason,
            }),
        )?;
        Ok(())
    }

    fn append_turn_cancelled(&mut self, turn_id: &str, reason: &str) -> Result<()> {
        self.journal.append_and_sync(
            "turn.cancelled",
            Some(turn_id),
            json!({ "reason": reason }),
        )?;
        Ok(())
    }

    /// Enforce the response-call insurance limit from durable dispatch intents,
    /// not process-local counters. Both normal `response.started` and bound
    /// `compaction.started` rows consume the turn's budget, including attempts
    /// that later fail, abort, or are recovered after a crash.
    fn ensure_provider_call_budget(&mut self, turn_id: &str) -> Result<()> {
        let Some(limit) = self.max_responses else {
            return Ok(());
        };
        let events = self.journal.read_events()?;
        let boundary_chain = validate_compaction_boundary_chain(&events)?;
        let boundary_owns_recovery = boundary_chain
            .pending()
            .iter()
            .any(|boundary| boundary.boundary.turn_id == turn_id);
        let consumed = durable_provider_call_intents_for_turn(&events, turn_id)?;
        let latest_retry_seq = events
            .iter()
            .filter(|event| {
                event.kind == "turn.retry_started" && event.turn_id.as_deref() == Some(turn_id)
            })
            .map(|event| event.seq)
            .max()
            .unwrap_or(0);
        let limit_u64 = u64::try_from(limit)
            .map_err(|_| OxidraError::Config("max responses exceeds u64".to_owned()))?;
        let consumed_u64 = u64::try_from(consumed).map_err(|_| {
            OxidraError::Session("provider call intent count exceeds u64".to_owned())
        })?;
        let mut already_recorded = false;
        for event in events.iter().filter(|event| {
            event.seq > latest_retry_seq
                && event.kind == "agent.limit_reached"
                && event.turn_id.as_deref() == Some(turn_id)
                && event.data.get("kind").and_then(Value::as_str) == Some("responses")
        }) {
            let recorded_version = event
                .data
                .get("provider_call_budget_version")
                .map(|version| {
                    version.as_u64().ok_or_else(|| {
                        OxidraError::Session(format!(
                            "agent.limit_reached at seq {} has a non-integer Provider call budget version",
                            event.seq
                        ))
                    })
                })
                .transpose()?;
            if recorded_version
                .is_some_and(|version| version != u64::from(PROVIDER_CALL_BUDGET_VERSION_V1))
            {
                return Err(OxidraError::Session(format!(
                    "agent.limit_reached at seq {} uses unsupported Provider call budget version {:?}",
                    event.seq, recorded_version
                )));
            }
            if event.data.get("limit").and_then(Value::as_u64) != Some(limit_u64) {
                continue;
            }
            // Pre-v1 limit events did not record the durable consumed count.
            // Treat the matching current limit as already terminal rather than
            // appending a second terminal event into the same retry epoch.
            if recorded_version.is_none()
                || event
                    .data
                    .get("consumed_provider_call_intents")
                    .and_then(Value::as_u64)
                    == Some(consumed_u64)
            {
                already_recorded = true;
            }
        }
        if consumed < limit {
            return Ok(());
        }
        // `agent.limit_reached` is a terminal turn event. A pending compaction
        // boundary is itself the durable recovery owner, so writing that turn
        // terminal here would make the boundary impossible to resume after the
        // user raises `--max-responses`. The durable dispatch intents already
        // provide the cross-process budget fact; leave the boundary pending and
        // re-evaluate the current runtime limit on the next retry.
        if !already_recorded && !boundary_owns_recovery {
            self.journal.append_and_sync(
                "agent.limit_reached",
                Some(turn_id),
                json!({
                    "kind": "responses",
                    "limit": limit,
                    "consumed_provider_call_intents": consumed,
                    "provider_call_budget_version": PROVIDER_CALL_BUDGET_VERSION_V1,
                }),
            )?;
        }
        Err(OxidraError::Limit("max responses reached".to_owned()))
    }

    async fn prepare_request_with_automatic_compaction(
        &mut self,
        turn_id: &str,
        user_message_seq: u64,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        usage: &mut Usage,
    ) -> Result<(ResponseRequest, PreparedToolSet)> {
        let (request, prepared) = self.prepare_request(Some(turn_id))?;
        if !self.automatic_compaction {
            return Ok((request, prepared));
        }

        // `prepare_request` may have synchronized a new context.tools epoch.
        // Rebuild once from the resulting durable prefix so the trigger,
        // boundary intent and all candidate projections share one snapshot.
        let (request, prepared) = self.prepare_request(Some(turn_id))?;
        let Some(trigger_tokens) = prepared.context.trigger_tokens else {
            return Ok((request, prepared));
        };
        let Some(target_tokens) = prepared.context.target_tokens else {
            return Ok((request, prepared));
        };
        if prepared.context.estimated_next_input_tokens < trigger_tokens {
            return Ok((request, prepared));
        }

        // Reserve budget before the boundary intent is durable. If no Provider
        // slot remains, terminate the turn without creating a pending boundary
        // that could never legally dispatch its compaction attempt.
        self.ensure_provider_call_budget(turn_id)?;

        let snapshot = self.journal.read_events()?;
        if snapshot.last().map(|event| event.seq) != prepared.context.request_journal_through_seq {
            return Err(OxidraError::Session(
                "journal changed after automatic compaction trigger measurement".to_owned(),
            ));
        }
        let boundary_chain = validate_compaction_boundary_chain(&snapshot)?;
        if boundary_chain.pending().iter().any(|record| {
            record.boundary.turn_id == turn_id
                && record.boundary.user_message_seq == user_message_seq
                && record.state == CompactionBoundaryState::Checkpointed
        }) {
            // A checkpointed boundary already spent this user turn's single
            // automatic compaction attempt. The Provider remains the hard
            // context boundary for this request and any later tool round-trip.
            return Ok((request, prepared));
        }

        let boundary =
            CompactionBoundary::new(Uuid::now_v7().to_string(), turn_id, user_message_seq);
        let mut extra = Map::new();
        extra.insert(
            "planning_version".to_owned(),
            json!(AUTOMATIC_COMPACTION_PLANNING_VERSION),
        );
        extra.insert(
            "context".to_owned(),
            automatic_compaction_planning_context_value_v1(&prepared.context)?,
        );
        extra.insert("trigger_tokens".to_owned(), json!(trigger_tokens));
        extra.insert("target_tokens".to_owned(), json!(target_tokens));
        extra.insert(
            "max_summary_output_tokens".to_owned(),
            json!(MAX_COMPACTION_OUTPUT_TOKENS),
        );
        extra.insert(
            "context_window_source".to_owned(),
            json!(self.context_runtime.limits.context_window_source),
        );
        extra.insert(
            "reserve_tokens_source".to_owned(),
            json!(self.context_runtime.limits.reserve_tokens_source),
        );
        let started = CompactionBoundaryStarted {
            boundary: boundary.clone(),
            trigger: "estimated_context_threshold".to_owned(),
            extra,
        };
        let started_data = serde_json::to_value(&started)?;
        validate_next_compaction_boundary_event(
            &snapshot,
            COMPACTION_BOUNDARY_STARTED_KIND,
            started_data.clone(),
        )?;
        self.journal
            .append_and_sync(COMPACTION_BOUNDARY_STARTED_KIND, None, started_data)?;

        if cancellation.is_cancelled() {
            self.append_automatic_compaction_preflight_failure(
                &boundary,
                "cancelled",
                "automatic compaction was cancelled before candidate planning",
            )?;
            return Err(OxidraError::Interrupted);
        }

        let plan = match self
            .build_automatic_compaction_plan_v1(boundary.clone(), prepared.context.clone())
        {
            Ok(plan) => plan,
            Err(error) => {
                self.append_automatic_compaction_preflight_failure(
                    &boundary,
                    "preflight_failed",
                    &error.to_string(),
                )?;
                return Err(error);
            }
        };
        if self.journal.read_events()? != plan.snapshot {
            self.append_automatic_compaction_preflight_failure(
                &boundary,
                "snapshot_changed",
                "journal changed after automatic compaction planning",
            )?;
            return Err(OxidraError::Session(
                "journal changed after automatic compaction planning".to_owned(),
            ));
        }

        let AutomaticCompactionPlanV1 {
            snapshot: _,
            boundary,
            current_context,
            selection,
            mut continuations,
        } = plan;
        let candidate = match selection {
            CompactionSelection::Selected(candidate) => candidate,
            CompactionSelection::Unavailable(reason) => {
                let message = format!("automatic compaction has no safe candidate: {reason}");
                self.append_automatic_compaction_preflight_failure(
                    &boundary,
                    "no_candidate",
                    &message,
                )?;
                return Err(OxidraError::Limit(message));
            }
        };
        let Some(continuation) = continuations.remove(&candidate.covers_through_seq) else {
            let error = OxidraError::Session(format!(
                "selected compaction cutoff {} has no prepared continuation",
                candidate.covers_through_seq
            ));
            self.append_automatic_compaction_preflight_failure(
                &boundary,
                "invalid_plan",
                &error.to_string(),
            )?;
            return Err(error);
        };
        let usable = current_context
            .usable_tokens
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        if let Err(error) = observer.on_compaction(&format!(
            "context {}/{}; window {} ({}), reserve {} ({}); compacting {} completed turns",
            current_context.estimated_next_input_tokens,
            usable,
            current_context
                .context_window
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            self.context_runtime.limits.context_window_source.as_str(),
            current_context.reserve_tokens,
            self.context_runtime.limits.reserve_tokens_source.as_str(),
            candidate.newly_compacted_complete_turns,
        )) {
            let error = OxidraError::observer(error);
            self.append_automatic_compaction_preflight_failure(
                &boundary,
                "observer_error",
                &error.to_string(),
            )?;
            return Err(error);
        }

        let mut compaction_observer = SilentCompactionObserver;
        let checkpoint = compact_once_for_boundary(
            self.provider.as_ref(),
            &mut self.journal,
            &boundary,
            &candidate,
            &self.context_runtime.model,
            &mut compaction_observer,
            cancellation.clone(),
            move |summary| continuation.validate_summary(summary),
        )
        .await?;

        if cancellation.is_cancelled() {
            return Err(OxidraError::Interrupted);
        }

        accumulate_usage_value(usage, &checkpoint.usage)?;

        let _ = self.prepare_request(Some(turn_id))?;
        let (request, prepared) = self.prepare_request(Some(turn_id))?;
        if cancellation.is_cancelled() {
            return Err(OxidraError::Interrupted);
        }
        if prepared.context.estimated_next_input_tokens > target_tokens {
            return Err(OxidraError::Session(format!(
                "checkpoint {} was committed but rebuilt context {} exceeds target {target_tokens}",
                checkpoint.checkpoint_id, prepared.context.estimated_next_input_tokens
            )));
        }
        observer
            .on_compaction(&format!(
                "checkpoint {}; context {}/{}",
                checkpoint.checkpoint_id,
                prepared.context.estimated_next_input_tokens,
                prepared
                    .context
                    .usable_tokens
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            ))
            .map_err(OxidraError::observer)?;
        Ok((request, prepared))
    }

    fn build_automatic_compaction_plan_v1(
        &self,
        boundary: CompactionBoundary,
        current_context: ContextDecision,
    ) -> Result<AutomaticCompactionPlanV1> {
        let snapshot = self.journal.read_events()?;
        let boundary_chain = validate_compaction_boundary_chain(&snapshot)?;
        let pending = boundary_chain.latest_pending().ok_or_else(|| {
            OxidraError::Session(format!(
                "automatic compaction boundary {} disappeared during planning",
                boundary.boundary_id
            ))
        })?;
        if pending.boundary != boundary || pending.state != CompactionBoundaryState::Started {
            return Err(OxidraError::Session(format!(
                "automatic compaction boundary {} is not the current Started boundary",
                boundary.boundary_id
            )));
        }
        let checkpoint_chain = validate_checkpoint_chain(&snapshot)?;
        let parent_cutoff = checkpoint_chain
            .latest()
            .map_or(0, |checkpoint| checkpoint.covers_through_seq);
        let uncompacted_events = snapshot
            .iter()
            .filter(|event| event.seq > parent_cutoff)
            .cloned()
            .collect::<Vec<_>>();
        let cutoffs = complete_prefix_candidates_for_version(
            TURN_BOUNDARY_VALIDATOR_VERSION,
            &uncompacted_events,
        )?;
        let complete_turns = segment_turns(&uncompacted_events)?
            .into_iter()
            .filter(|turn| matches!(turn.state, TurnState::Complete(_)))
            .count();
        let abandoned_barrier = boundary_chain.first_abandoned_user_seq_after(parent_cutoff);
        let events = Arc::new(snapshot.clone());
        let boundary_chain = Arc::new(boundary_chain);
        let planning_summary = automatic_compaction_summary_placeholder_v1()?;
        let mut estimates = Vec::with_capacity(cutoffs.len());
        let mut continuations = HashMap::with_capacity(cutoffs.len());
        for cutoff in cutoffs.into_iter().filter(|cutoff| {
            complete_turns.saturating_sub(cutoff.turn_count) >= MIN_RECENT_COMPLETE_TURNS
                && abandoned_barrier.is_none_or(|seq| cutoff.covers_through_seq < seq)
        }) {
            let continuation = self.build_planned_compaction_continuation_v1(
                Arc::clone(&events),
                Arc::clone(&boundary_chain),
                &boundary.turn_id,
                cutoff.covers_through_seq,
                SUMMARY_ENVELOPE_VERSION,
            )?;
            let projected = continuation.context_for_summary(&planning_summary)?;
            estimates.push(CandidateEstimate {
                covers_through_seq: cutoff.covers_through_seq,
                estimated_input_tokens_after: projected.estimated_next_input_tokens,
            });
            continuations.insert(cutoff.covers_through_seq, continuation);
        }
        let target_input_tokens = current_context.target_tokens.ok_or_else(|| {
            OxidraError::Config(
                "automatic compaction requires a configured target token count".to_owned(),
            )
        })?;
        let selection = select_compaction_candidate(
            &snapshot,
            &checkpoint_chain,
            &CompactionContext {
                current_input_tokens: current_context.estimated_next_input_tokens,
                target_input_tokens,
                min_recent_complete_turns: MIN_RECENT_COMPLETE_TURNS,
                estimates,
            },
        )?;
        Ok(AutomaticCompactionPlanV1 {
            snapshot,
            boundary,
            current_context,
            selection,
            continuations,
        })
    }

    fn append_automatic_compaction_preflight_failure(
        &mut self,
        boundary: &CompactionBoundary,
        code: &str,
        message: &str,
    ) -> Result<()> {
        let events = self.journal.read_events()?;
        let payload = CompactionBoundaryFailed {
            boundary_id: boundary.boundary_id.clone(),
            code: code.to_owned(),
            message: message.to_owned(),
            attempt_id: None,
            extra: Map::new(),
        };
        let data = serde_json::to_value(payload)?;
        validate_next_compaction_boundary_event(
            &events,
            COMPACTION_BOUNDARY_FAILED_KIND,
            data.clone(),
        )?;
        self.journal
            .append_and_sync(COMPACTION_BOUNDARY_FAILED_KIND, None, data)?;
        Ok(())
    }

    fn build_prepared_request_materials(
        &self,
        events: &[JournalEvent],
        boundary_chain: &CompactionBoundaryChain,
        turn_id: Option<&str>,
        recovery_planning: bool,
    ) -> Result<PreparedRequestMaterials> {
        let chain = validate_checkpoint_chain(events)?;
        let checkpoint_id = chain
            .latest()
            .map(|checkpoint| checkpoint.checkpoint_id.clone());
        let checkpoint_covers_through_seq = chain
            .latest()
            .map(|checkpoint| checkpoint.covers_through_seq);
        let input = if recovery_planning && chain.latest().is_some() {
            project_checkpoint_and_tail_for_recovery_planning(events, &chain, boundary_chain)?
        } else if recovery_planning {
            project_events_for_recovery_planning(events, boundary_chain)?
        } else if chain.latest().is_some() {
            project_checkpoint_and_tail_with_boundary_chain(events, &chain, boundary_chain)?
        } else {
            project_events_with_boundary_chain(events, boundary_chain)?
        };
        let history = if recovery_planning {
            HistorySnapshot::build_for_recovery_planning(events, &chain, boundary_chain)?
        } else {
            HistorySnapshot::build_with_boundary_chain(events, &chain, boundary_chain)?
        };
        let history_quota = match turn_id {
            Some(turn_id) if recovery_planning => {
                rebuild_history_quota_for_compaction_preview(events, turn_id, boundary_chain)?
            }
            Some(turn_id) => {
                rebuild_history_quota_with_boundary_chain(events, turn_id, boundary_chain)?
            }
            None => HistoryQuota {
                used_bytes: 0,
                remaining_bytes: MAX_HISTORY_TURN_OUTPUT_BYTES,
                exhausted: false,
            },
        };
        let history_exposed = history.is_available()
            && history_quota.remaining_bytes
                >= MAX_HISTORY_CALLS_PER_RESPONSE
                    .saturating_mul(HISTORY_CONTROL_OUTPUT_RESERVE_BYTES);
        let mut definitions = self.tools.definitions();
        if history_exposed {
            definitions.extend(history_tool_definitions());
        }
        let request = ResponseRequest {
            instructions: (!self.instructions.is_empty()).then(|| self.instructions.clone()),
            input,
            tools: definitions.clone(),
            model: None,
            max_output_tokens: None,
        };
        Ok(PreparedRequestMaterials {
            request,
            definitions,
            history,
            history_quota,
            history_exposed,
            checkpoint_id,
            checkpoint_covers_through_seq,
        })
    }

    fn finish_prepared_request(
        &self,
        events: &[JournalEvent],
        materials: PreparedRequestMaterials,
        tools_event_seq: u64,
    ) -> Result<(ResponseRequest, PreparedToolSet)> {
        let measurement = measure_prepared_request(&materials.request, &self.context_runtime)?;
        let instructions_event_seq = events
            .iter()
            .rev()
            .find(|event| event.kind == "context.instructions")
            .map(|event| event.seq);
        let configured_event_seq = events
            .iter()
            .rev()
            .find(|event| event.kind == "context.configured")
            .map(|event| event.seq);
        let context = decide_context(
            events,
            &self.context_runtime,
            measurement,
            events.last().map(|event| event.seq),
            materials.checkpoint_id,
            materials.checkpoint_covers_through_seq,
            instructions_event_seq,
            configured_event_seq,
            tools_event_seq,
        )?;
        Ok((
            materials.request,
            PreparedToolSet {
                definitions: materials.definitions,
                history: materials.history,
                history_quota: materials.history_quota,
                history_exposed: materials.history_exposed,
                context,
            },
        ))
    }

    fn measure_replan_context_v1(
        &self,
        events: &[JournalEvent],
        boundary_chain: &CompactionBoundaryChain,
        turn_id: &str,
    ) -> Result<ContextDecision> {
        let materials =
            self.build_prepared_request_materials(events, boundary_chain, Some(turn_id), true)?;
        let tool_snapshot = snapshot_tools(&materials.definitions)?;
        let tools_event_seq = events
            .iter()
            .rev()
            .find(|event| {
                event.kind == "context.tools"
                    && event.data.get("digest").and_then(Value::as_str)
                        == Some(tool_snapshot.digest.as_str())
            })
            .map_or(0, |event| event.seq);
        let (_, prepared) = self.finish_prepared_request(events, materials, tools_event_seq)?;
        Ok(prepared.context)
    }

    fn prepare_request(
        &mut self,
        turn_id: Option<&str>,
    ) -> Result<(ResponseRequest, PreparedToolSet)> {
        let events = self.journal.read_events()?;
        let boundary_chain = validate_compaction_boundary_chain(&events)?;
        ensure_compaction_boundaries_allow_request(&events, &boundary_chain, turn_id)?;
        let materials =
            self.build_prepared_request_materials(&events, &boundary_chain, turn_id, false)?;
        let tool_snapshot = snapshot_tools(&materials.definitions)?;
        let tools_event_seq = match &self.tools_epoch {
            Some((digest, seq)) if digest == &tool_snapshot.digest => *seq,
            _ => {
                let event = self.journal.append_and_sync(
                    "context.tools",
                    None,
                    serde_json::to_value(&tool_snapshot)?,
                )?;
                self.tools_epoch = Some((tool_snapshot.digest.clone(), event.seq));
                event.seq
            }
        };
        self.finish_prepared_request(&events, materials, tools_event_seq)
    }

    fn context_estimate(&self, decision: &ContextDecision) -> ContextEstimate {
        ContextEstimate {
            estimated_tokens: decision.estimated_next_input_tokens,
            context_window: self.context_runtime.limits.context_window,
            reserve_tokens: self.context_runtime.limits.reserve_tokens,
        }
    }

    fn next_context_estimate(&mut self) -> Result<ContextEstimate> {
        let (_, prepared) = self.prepare_request(None)?;
        Ok(self.context_estimate(&prepared.context))
    }
}

fn planned_context_retry_intent(
    events: &[JournalEvent],
    retry: &PendingContextTurn,
) -> Result<Option<Value>> {
    let recovery = validate_turn_recovery(events)?;
    let has_current_intent = recovery
        .retries
        .iter()
        .rev()
        .find(|intent| {
            intent.turn_id == retry.turn_id && intent.limit_seq == retry.context_limit_seq
        })
        .is_some_and(|intent| {
            !events.iter().any(|event| {
                event.turn_id.as_deref() == Some(retry.turn_id.as_str())
                    && event.seq > intent.retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.started"
                            | "response.completed"
                            | "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            })
        });
    Ok((!has_current_intent).then(|| {
        json!({
            "retry_version": 1,
            "retry_id": Uuid::now_v7().to_string(),
            "user_message_seq": retry.user_message_seq,
            "context_limit_seq": retry.context_limit_seq,
        })
    }))
}

fn durable_provider_call_intents_for_turn(events: &[JournalEvent], turn_id: &str) -> Result<usize> {
    // Validate the boundary/attempt graph before interpreting its bindings as
    // budget facts. Raw `extra["boundary"]` fields are not authority by
    // themselves.
    validate_compaction_boundary_chain(events)?;
    let normal = events
        .iter()
        .filter(|event| {
            event.kind == "response.started" && event.turn_id.as_deref() == Some(turn_id)
        })
        .count();
    let mut compaction = 0usize;
    for event in events
        .iter()
        .filter(|event| event.kind == COMPACTION_STARTED_KIND)
    {
        let started: CompactionStarted = serde_json::from_value(event.data.clone())?;
        if attempt_boundary(&started.extra)?
            .as_ref()
            .is_some_and(|boundary| boundary.turn_id == turn_id)
        {
            compaction = compaction.checked_add(1).ok_or_else(|| {
                OxidraError::Session("provider call intent count overflow".to_owned())
            })?;
        }
    }
    normal
        .checked_add(compaction)
        .ok_or_else(|| OxidraError::Session("provider call intent count overflow".to_owned()))
}

fn rebuild_automatic_compaction_planning_context_v1(
    events: &[JournalEvent],
    boundary_id: &str,
) -> Result<AutomaticCompactionPlanningContextV1> {
    let mut current_boundary_id = boundary_id.to_owned();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_boundary_id.clone()) {
            return Err(OxidraError::Session(format!(
                "automatic compaction planning lineage for boundary {boundary_id} contains a cycle"
            )));
        }

        if let Some(started) = events
            .iter()
            .filter(|event| event.kind == COMPACTION_BOUNDARY_STARTED_KIND)
            .map(|event| -> Result<CompactionBoundaryStarted> {
                Ok(serde_json::from_value(event.data.clone())?)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|started| started.boundary.boundary_id == current_boundary_id)
        {
            if let Some(context) =
                automatic_compaction_planning_context_v1(&started.extra, &current_boundary_id)?
            {
                return Ok(context);
            }
        }

        let retry = events
            .iter()
            .filter(|event| event.kind == COMPACTION_BOUNDARY_RETRY_STARTED_KIND)
            .map(|event| -> Result<CompactionBoundaryRetryStarted> {
                Ok(serde_json::from_value(event.data.clone())?)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|retry| retry.boundary.boundary_id == current_boundary_id);
        let Some(retry) = retry else {
            return Err(OxidraError::ApprovalRequired(format!(
                "failed compaction boundary {boundary_id} has no durable automatic planning context; abandon it"
            )));
        };
        if let Some(context) =
            automatic_compaction_planning_context_v1(&retry.extra, &current_boundary_id)?
        {
            return Ok(context);
        }
        current_boundary_id = retry.previous_boundary_id;
    }
}

fn automatic_compaction_planning_context_v1(
    extra: &Map<String, Value>,
    boundary_id: &str,
) -> Result<Option<AutomaticCompactionPlanningContextV1>> {
    let planning_version = extra.get("planning_version");
    let context = extra.get("context");
    match (planning_version, context) {
        (None, None) => Ok(None),
        (Some(version), Some(context)) => {
            let version = version.as_u64().ok_or_else(|| {
                OxidraError::Session(format!(
                    "automatic compaction boundary {boundary_id} has a non-integer planning version"
                ))
            })?;
            let parsed = match u32::try_from(version).ok() {
                Some(AUTOMATIC_COMPACTION_PLANNING_VERSION_V1) => {
                    serde_json::from_value::<AutomaticCompactionPlanningContextV1>(context.clone())?
                }
                _ => {
                    return Err(OxidraError::ApprovalRequired(format!(
                        "automatic compaction boundary {boundary_id} uses unsupported planning version {version}; abandon it"
                    )));
                }
            };
            validate_automatic_compaction_planning_context_v1(&parsed, boundary_id)?;
            Ok(Some(parsed))
        }
        _ => Err(OxidraError::Session(format!(
            "automatic compaction boundary {boundary_id} has incomplete durable planning metadata"
        ))),
    }
}

fn validate_automatic_compaction_planning_context_v1(
    context: &AutomaticCompactionPlanningContextV1,
    boundary_id: &str,
) -> Result<()> {
    let measurement = &context.measurement;
    if measurement.measurement_version
        != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_MEASUREMENT_VERSION_V1
        || measurement.estimator_version
            != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_ESTIMATOR_VERSION_V1
        || measurement.request_shape_version
            != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_REQUEST_SHAPE_VERSION_V1
    {
        return Err(OxidraError::ApprovalRequired(format!(
            "automatic compaction boundary {boundary_id} uses unsupported planning v1 context measurement versions; abandon it"
        )));
    }
    if measurement.request_digest.trim().is_empty()
        || context.provider_usage_domain.trim().is_empty()
    {
        return Err(OxidraError::Session(format!(
            "automatic compaction boundary {boundary_id} has incomplete planning v1 identity"
        )));
    }
    let expected_usable = context
        .context_window
        .map(|window| window.saturating_sub(context.reserve_tokens));
    let expected_trigger = expected_usable.map(|usable| ((u128::from(usable) * 80) / 100) as u64);
    let expected_target = expected_usable.map(|usable| usable / 2);
    if context.usable_tokens != expected_usable
        || context.trigger_tokens != expected_trigger
        || context.target_tokens != expected_target
    {
        return Err(OxidraError::Session(format!(
            "automatic compaction boundary {boundary_id} has internally inconsistent planning v1 limits"
        )));
    }
    Ok(())
}

fn automatic_compaction_planning_context_value_v1(context: &ContextDecision) -> Result<Value> {
    if context.measurement.measurement_version
        != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_MEASUREMENT_VERSION_V1
        || context.measurement.estimator_version
            != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_ESTIMATOR_VERSION_V1
        || context.measurement.request_shape_version
            != AUTOMATIC_COMPACTION_PLANNING_CONTEXT_REQUEST_SHAPE_VERSION_V1
    {
        return Err(OxidraError::Config(
            "current context measurement versions require a new automatic compaction planning protocol version"
                .to_owned(),
        ));
    }
    let value = context.audit_value()?;
    let frozen = serde_json::from_value::<AutomaticCompactionPlanningContextV1>(value.clone())
        .map_err(|error| {
            OxidraError::Config(format!(
                "current context decision cannot be written as automatic compaction planning v1: {error}"
            ))
        })?;
    validate_automatic_compaction_planning_context_v1(&frozen, "current-writer").map_err(
        |error| {
            OxidraError::Config(format!(
                "current context decision requires a new automatic compaction planning protocol version: {error}"
            ))
        },
    )?;
    Ok(value)
}

fn append_prospective_event(
    events: &mut Vec<JournalEvent>,
    kind: &str,
    turn_id: Option<&str>,
    data: Value,
) -> Result<()> {
    let mut event = events.last().cloned().ok_or_else(|| {
        OxidraError::Session("cannot plan recovery against an empty journal".to_owned())
    })?;
    event.seq = event.seq.checked_add(1).ok_or_else(|| {
        OxidraError::Session("journal sequence overflow while planning recovery".to_owned())
    })?;
    event.kind = kind.to_owned();
    event.turn_id = turn_id.map(str::to_owned);
    event.data = data;
    events.push(event);
    Ok(())
}

fn automatic_compaction_summary_placeholder_v1() -> Result<String> {
    let token_budget = usize::try_from(MAX_COMPACTION_OUTPUT_TOKENS).map_err(|_| {
        OxidraError::Config("compaction output token limit exceeds platform capacity".to_owned())
    })?;
    let ascii_characters = token_budget.checked_mul(4).ok_or_else(|| {
        OxidraError::Config("compaction planning summary size overflow".to_owned())
    })?;
    Ok("x".repeat(ascii_characters))
}

fn pending_context_turns(
    events: &[crate::session::JournalEvent],
) -> Result<Vec<PendingContextTurn>> {
    // resolution 可能在更晚的回合之后追加，因此必须按 turn_id 全局归约，
    // 不能只扫描两个 user.message 之间的物理区间。
    let limited_turns = events
        .iter()
        .filter(|event| event.kind == "context.limit_reached")
        .try_fold(
            std::collections::HashMap::<String, u64>::new(),
            |mut limits, event| {
                let turn_id = event.turn_id.clone().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "context.limit_reached at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                limits
                    .entry(turn_id)
                    .and_modify(|seq| *seq = (*seq).max(event.seq))
                    .or_insert(event.seq);
                Ok::<_, OxidraError>(limits)
            },
        )?;
    let recovery = validate_turn_recovery(events)?;
    let resolved_turns = segment_turns(events)?
        .into_iter()
        .filter(|turn| matches!(turn.state, TurnState::Complete(_)))
        .map(|turn| turn.turn_id)
        .collect::<HashSet<_>>();
    let resolved_turns = resolved_turns
        .into_iter()
        .chain(recovery.abandons.into_keys())
        .collect::<HashSet<_>>();
    let mut pending = Vec::new();
    for user in events.iter().filter(|event| event.kind == "user.message") {
        let Some(turn_id) = user.turn_id.as_deref() else {
            return Err(OxidraError::Session(format!(
                "user.message at seq {} has no turn_id",
                user.seq
            )));
        };
        let Some(context_limit_seq) = limited_turns.get(turn_id).copied() else {
            continue;
        };
        if resolved_turns.contains(turn_id) {
            continue;
        }
        let prompt = user
            .data
            .get("item")
            .and_then(|item| item.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "pending user.message at seq {} has no string content",
                    user.seq
                ))
            })?;
        pending.push(PendingContextTurn {
            turn_id: turn_id.to_owned(),
            user_message_seq: user.seq,
            context_limit_seq,
            prompt: prompt.to_owned(),
        });
    }
    Ok(pending)
}

fn ensure_compaction_boundaries_allow_request(
    events: &[crate::session::JournalEvent],
    chain: &CompactionBoundaryChain,
    current_turn_id: Option<&str>,
) -> Result<()> {
    let mut blocked = Vec::new();
    for boundary in chain.pending() {
        if boundary.state == CompactionBoundaryState::Checkpointed
            && current_turn_id == Some(boundary.boundary.turn_id.as_str())
        {
            ensure_checkpointed_boundary_request_ready(events, boundary)?;
        } else {
            blocked.push(boundary);
        }
    }
    if blocked.is_empty() {
        return Ok(());
    }

    let latest = blocked
        .iter()
        .max_by_key(|boundary| boundary.started_seq)
        .expect("non-empty pending boundary set");
    Err(OxidraError::ApprovalRequired(format!(
        "session contains {} pending compaction boundary/boundaries (latest {} is {:?}); retry or abandon before dispatching another request",
        blocked.len(),
        latest.boundary.boundary_id,
        latest.state
    )))
}

fn validate_next_compaction_boundary_event(
    events: &[crate::session::JournalEvent],
    kind: &str,
    data: Value,
) -> Result<()> {
    let mut next = events.last().cloned().ok_or_else(|| {
        OxidraError::Session(
            "cannot append a compaction boundary event to an empty journal".to_owned(),
        )
    })?;
    next.seq = next.seq.checked_add(1).ok_or_else(|| {
        OxidraError::Session("journal sequence overflow while validating boundary event".to_owned())
    })?;
    next.kind = kind.to_owned();
    next.turn_id = None;
    next.data = data;
    let mut prospective = events.to_vec();
    prospective.push(next);
    validate_compaction_boundary_chain(&prospective)?;
    Ok(())
}

fn validate_history_calls_for_response(
    calls: &[ToolCall],
    prepared: &PreparedToolSet,
) -> Result<()> {
    let history_calls = calls
        .iter()
        .filter(|call| is_history_tool_name(&call.name))
        .collect::<Vec<_>>();
    if history_calls.len() > MAX_HISTORY_CALLS_PER_RESPONSE {
        return Err(OxidraError::Limit(format!(
            "a response may contain at most {MAX_HISTORY_CALLS_PER_RESPONSE} history calls"
        )));
    }
    let required_reserve = history_calls
        .len()
        .saturating_mul(HISTORY_CONTROL_OUTPUT_RESERVE_BYTES);
    if prepared.history_quota.remaining_bytes < required_reserve {
        return Err(OxidraError::Limit(
            "remaining history quota cannot pair every history call in this response".to_owned(),
        ));
    }
    let mut call_ids = HashSet::new();
    for call in history_calls {
        if call.id.is_empty() || call.id.len() > 128 {
            return Err(OxidraError::Provider(
                "history call_id must contain between 1 and 128 UTF-8 bytes".to_owned(),
            ));
        }
        if !call_ids.insert(call.id.as_str()) {
            return Err(OxidraError::Provider(format!(
                "duplicate history call_id {:?} in one response",
                call.id
            )));
        }
    }
    Ok(())
}

fn accumulate_usage(total: &mut Usage, usage: &Usage) {
    total.input_tokens = total.input_tokens.saturating_add(usage.input_tokens);
    total.cached_input_tokens = total
        .cached_input_tokens
        .saturating_add(usage.cached_input_tokens);
    total.output_tokens = total.output_tokens.saturating_add(usage.output_tokens);
    total.reasoning_output_tokens = total
        .reasoning_output_tokens
        .saturating_add(usage.reasoning_output_tokens);
    total.total_tokens = total.total_tokens.saturating_add(usage.total_tokens);
}

fn accumulate_usage_value(total: &mut Usage, usage: &Value) -> Result<()> {
    let object = usage.as_object().ok_or_else(|| {
        OxidraError::Session("invalid persisted compaction usage: expected an object".to_owned())
    })?;
    let read = |name: &str| {
        object.get(name).and_then(Value::as_u64).ok_or_else(|| {
            OxidraError::Session(format!(
                "invalid persisted compaction usage: missing {name}"
            ))
        })
    };
    let cached_input_tokens = object
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let reasoning_output_tokens = object
        .get("output_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let usage = Usage {
        input_tokens: read("input_tokens")?,
        cached_input_tokens,
        output_tokens: read("output_tokens")?,
        reasoning_output_tokens,
        total_tokens: read("total_tokens")?,
    };
    accumulate_usage(total, &usage);
    Ok(())
}

struct ForwardObserver<'a> {
    observer: &'a mut dyn AgentObserver,
}

struct SilentCompactionObserver;

impl StreamObserver for SilentCompactionObserver {
    fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }
}

impl StreamObserver for ForwardObserver<'_> {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
        self.observer
            .on_provider_event(event)
            .map_err(OxidraError::observer)
    }
}

fn error_fingerprint(call: &ToolCall, result: &ToolResult) -> String {
    let stable_output = stable_error_output(&result.output);
    format!(
        "{}:{}:{}:{}",
        call.name,
        canonical_json(&call.arguments),
        result.error_code.as_deref().unwrap_or("unknown_error"),
        canonical_json(&stable_output)
    )
}

/// Remove observational fields that change between otherwise identical
/// failures. They remain in the journal and model-visible tool result, but
/// must not defeat the repeated-error circuit breaker.
fn stable_error_output(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(stable_error_output).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .filter(|(key, _)| key.as_str() != "duration_ms")
                .map(|(key, value)| (key.clone(), stable_error_output(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_default(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// A deliberately bounded JSON-Schema validator for tool arguments.  It
/// covers the schema vocabulary emitted by the built-ins; unknown annotation
/// keywords and `$ref` are left untouched so a
/// valid remote schema is not rejected merely for using a newer draft.
pub fn validate_json_schema(schema: &Value, value: &Value) -> std::result::Result<(), String> {
    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array) {
        if !any_of
            .iter()
            .any(|candidate| validate_json_schema(candidate, value).is_ok())
        {
            return Err("value does not match anyOf".to_owned());
        }
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|candidate| validate_json_schema(candidate, value).is_ok())
            .count();
        if matches != 1 {
            return Err("value does not match exactly one oneOf branch".to_owned());
        }
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for candidate in all_of {
            validate_json_schema(candidate, value)?;
        }
    }
    if let Some(expected) = schema.get("const") {
        if expected != value {
            return Err("value does not match const".to_owned());
        }
    }
    if let Some(enumeration) = schema.get("enum").and_then(Value::as_array) {
        if !enumeration.iter().any(|candidate| candidate == value) {
            return Err("value is not in enum".to_owned());
        }
    }
    if let Some(types) = schema.get("type") {
        let matches = match types {
            Value::String(kind) => json_type_matches(kind, value),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| json_type_matches(kind, value)),
            _ => true,
        };
        if !matches {
            return Err(format!("expected type {}, got {}", types, json_type(value)));
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    return Err(format!("missing required property {name:?}"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (name, property_schema) in properties {
                if let Some(property) = object.get(name) {
                    validate_json_schema(property_schema, property)
                        .map_err(|error| format!("property {name:?}: {error}"))?;
                }
            }
        }
        match schema.get("additionalProperties") {
            Some(Value::Bool(false)) => {
                if let Some(name) = object.keys().find(|name| {
                    !properties.is_some_and(|properties| properties.contains_key(*name))
                }) {
                    return Err(format!("unknown property {name:?}"));
                }
            }
            Some(Value::Object(additional_schema)) => {
                for (name, property) in object {
                    if !properties.is_some_and(|properties| properties.contains_key(name)) {
                        validate_json_schema(&Value::Object(additional_schema.clone()), property)
                            .map_err(|error| format!("property {name:?}: {error}"))?;
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(items_schema) = schema.get("items") {
        if let Some(items) = value.as_array() {
            for (index, item) in items.iter().enumerate() {
                validate_json_schema(items_schema, item)
                    .map_err(|error| format!("item {index}: {error}"))?;
            }
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        if value.as_f64().is_some_and(|number| number < minimum) {
            return Err(format!("number is below minimum {minimum}"));
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
        if value.as_f64().is_some_and(|number| number > maximum) {
            return Err(format!("number is above maximum {maximum}"));
        }
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
        if value
            .as_str()
            .is_some_and(|text| text.chars().count() < min_length as usize)
        {
            return Err(format!("string is shorter than {min_length}"));
        }
    }
    if let Some(max_length) = schema.get("maxLength").and_then(Value::as_u64) {
        if value
            .as_str()
            .is_some_and(|text| text.chars().count() > max_length as usize)
        {
            return Err(format!("string is longer than {max_length}"));
        }
    }
    Ok(())
}

fn json_type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        _ => true,
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Load only the project-local instruction file.  The caller decides whether
/// to include this text in a system/developer prompt.
pub fn load_project_instructions(root: &std::path::Path) -> Result<String> {
    let root = root.canonicalize()?;
    let path = root.join("AGENTS.md");
    if !path.is_file() {
        return Ok(String::new());
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err(OxidraError::Config(format!(
            "{} must not be a symbolic link",
            path.display()
        )));
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(&root) {
        return Err(OxidraError::Config(format!(
            "{} resolves outside the project root",
            path.display()
        )));
    }
    let bytes = std::fs::read(&canonical)?;
    if bytes.len() > MAX_PROJECT_INSTRUCTIONS {
        return Err(OxidraError::Config(format!(
            "{} exceeds the 32 KiB AGENTS.md limit",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| OxidraError::Config(format!("{} is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::compaction::{
        COMPACTION_BOUNDARY_CHECKPOINTED_KIND, COMPACTION_BOUNDARY_FAILED_KIND,
        COMPACTION_BOUNDARY_STARTED_KIND, COMPACTION_CHECKPOINT_KIND, COMPACTION_FAILED_KIND,
        COMPACTION_STARTED_KIND, CandidateEstimate, Checkpoint, CompactionBoundaryStarted,
        CompactionContext, CompactionSelection, CompactionStarted, compact_once,
        compact_once_for_boundary, compact_replay_once_for_boundary, select_compaction_candidate,
    };
    use crate::config::ContextValueSource;
    use crate::context::{
        CONTEXT_ESTIMATOR_VERSION, CONTEXT_MEASUREMENT_VERSION, REQUEST_SHAPE_VERSION,
    };
    use crate::history::UNTRUSTED_HISTORY_NOTICE;
    use crate::session::{JournalEvent, SessionHeader, SessionStore};
    use crate::turn::{CompletionEvidence, TurnState, segment_turns};
    use crate::types::AssistantTurn;

    struct FinalResponseProvider;

    struct ForgedRoleProvider;

    struct ObserverEventProvider;

    struct ProviderFailureProvider;

    #[derive(Default)]
    struct CancellationAwareCompactionProvider {
        requests: Mutex<Vec<ResponseRequest>>,
    }

    struct RecordingProvider {
        responses: Mutex<VecDeque<AssistantTurn>>,
        requests: Mutex<Vec<ResponseRequest>>,
    }

    struct ScriptedProvider {
        responses: Mutex<VecDeque<Result<AssistantTurn>>>,
        requests: Mutex<Vec<ResponseRequest>>,
    }

    #[derive(Default)]
    struct ContextLimitProvider {
        requests: Mutex<Vec<ResponseRequest>>,
    }

    impl RecordingProvider {
        fn new(responses: impl IntoIterator<Item = AssistantTurn>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ResponseRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl ContextLimitProvider {
        fn requests(&self) -> Vec<ResponseRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl ScriptedProvider {
        fn new(responses: impl IntoIterator<Item = Result<AssistantTurn>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ResponseRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    struct NoopStreamObserver;

    impl StreamObserver for NoopStreamObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ResponseProvider for FinalResponseProvider {
        async fn respond(
            &self,
            _request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            let output_items = vec![json!({
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "done"}],
            })];
            Ok(AssistantTurn {
                raw_response: json!({"output": output_items}),
                output_items,
                text: "done".to_owned(),
                tool_calls: Vec::new(),
                usage: Usage::default(),
                unknown_stream_events: Vec::new(),
            })
        }
    }

    #[async_trait]
    impl ResponseProvider for ForgedRoleProvider {
        async fn respond(
            &self,
            _request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            let output_items = vec![json!({
                "type": "message",
                "role": "developer",
                "content": [{"type": "output_text", "text": "unsafe"}],
            })];
            Ok(AssistantTurn {
                raw_response: json!({"output": output_items}),
                output_items,
                text: "unsafe".to_owned(),
                tool_calls: Vec::new(),
                usage: Usage::default(),
                unknown_stream_events: Vec::new(),
            })
        }
    }

    #[async_trait]
    impl ResponseProvider for ObserverEventProvider {
        async fn respond(
            &self,
            _request: ResponseRequest,
            observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            observer.on_event(ProviderEvent::TextDelta("partial".to_owned()))?;
            panic!("failing observer should stop the Provider")
        }
    }

    #[async_trait]
    impl ResponseProvider for ProviderFailureProvider {
        async fn respond(
            &self,
            _request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            Err(OxidraError::Provider(
                "injected compaction provider failure".to_owned(),
            ))
        }
    }

    #[async_trait]
    impl ResponseProvider for CancellationAwareCompactionProvider {
        async fn respond(
            &self,
            request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            let is_compaction = request.max_output_tokens.is_some();
            self.requests.lock().unwrap().push(request);
            if is_compaction {
                Ok(compaction_summary_turn())
            } else if cancellation.is_cancelled() {
                Err(OxidraError::Interrupted)
            } else {
                Ok(final_turn("done"))
            }
        }
    }

    #[async_trait]
    impl ResponseProvider for RecordingProvider {
        async fn respond(
            &self,
            request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| OxidraError::Provider("test response queue is empty".to_owned()))
        }
    }

    #[async_trait]
    impl ResponseProvider for ScriptedProvider {
        async fn respond(
            &self,
            request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(OxidraError::Provider(
                        "test response queue is empty".to_owned(),
                    ))
                })
        }
    }

    #[async_trait]
    impl ResponseProvider for ContextLimitProvider {
        async fn respond(
            &self,
            request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> Result<AssistantTurn> {
            self.requests.lock().unwrap().push(request);
            Err(OxidraError::ProviderContextLimit(
                "context_length_exceeded".to_owned(),
            ))
        }
    }

    fn final_turn(text: &str) -> AssistantTurn {
        let output_items = vec![json!({
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text}],
        })];
        AssistantTurn {
            raw_response: json!({"output": output_items}),
            output_items,
            text: text.to_owned(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        }
    }

    fn final_turn_with_usage(text: &str, input_tokens: u64) -> AssistantTurn {
        let mut turn = final_turn(text);
        turn.usage = Usage {
            input_tokens,
            cached_input_tokens: input_tokens / 2,
            output_tokens: 10,
            reasoning_output_tokens: 2,
            total_tokens: input_tokens + 10,
        };
        turn.raw_response["id"] = json!(format!("response-{text}"));
        turn.raw_response["status"] = json!("completed");
        turn.raw_response["usage"] = json!({
            "input_tokens":input_tokens,
            "input_tokens_details":{"cached_tokens":input_tokens / 2},
            "output_tokens":10,
            "output_tokens_details":{"reasoning_tokens":2},
            "total_tokens":input_tokens + 10,
        });
        turn
    }

    fn tool_turn(calls: Vec<ToolCall>) -> AssistantTurn {
        let output_items = calls
            .iter()
            .map(|call| {
                json!({
                    "type":"function_call",
                    "call_id":call.id,
                    "name":call.name,
                    "arguments":serde_json::to_string(&call.arguments).unwrap(),
                })
            })
            .collect::<Vec<_>>();
        AssistantTurn {
            raw_response: json!({"output": output_items}),
            output_items,
            text: String::new(),
            tool_calls: calls,
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        }
    }

    fn compaction_summary_turn() -> AssistantTurn {
        let output_items = vec![json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":"checkpoint summary"}],
        })];
        let usage = Usage {
            input_tokens: 100,
            cached_input_tokens: 10,
            output_tokens: 20,
            reasoning_output_tokens: 5,
            total_tokens: 120,
        };
        AssistantTurn {
            raw_response: json!({
                "id":"compaction-test-response",
                "status":"completed",
                "output":output_items,
                "usage":{
                    "input_tokens":100,
                    "input_tokens_details":{"cached_tokens":10},
                    "output_tokens":20,
                    "output_tokens_details":{"reasoning_tokens":5},
                    "total_tokens":120,
                }
            }),
            output_items,
            text: "checkpoint summary".to_owned(),
            tool_calls: Vec::new(),
            usage,
            unknown_stream_events: Vec::new(),
        }
    }

    fn compaction_summary_turn_with_text(text: String) -> AssistantTurn {
        let output_items = vec![json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":text}],
        })];
        let usage = Usage {
            input_tokens: 100,
            cached_input_tokens: 10,
            output_tokens: 8_000,
            reasoning_output_tokens: 5,
            total_tokens: 8_100,
        };
        AssistantTurn {
            raw_response: json!({
                "id":"compaction-large-summary",
                "status":"completed",
                "output":output_items,
                "usage":{
                    "input_tokens":100,
                    "input_tokens_details":{"cached_tokens":10},
                    "output_tokens":8_000,
                    "output_tokens_details":{"reasoning_tokens":5},
                    "total_tokens":8_100,
                }
            }),
            output_items,
            text,
            tool_calls: Vec::new(),
            usage,
            unknown_stream_events: Vec::new(),
        }
    }

    fn append_large_complete_turns(journal: &mut SessionJournal, count: usize, bytes: usize) {
        for index in 0..count {
            append_complete_turn(
                journal,
                &format!("large-old-turn-{index}"),
                &format!("old-question-{index}:{}", "q".repeat(bytes)),
                &format!("old-answer-{index}:{}", "a".repeat(bytes)),
            );
        }
    }

    fn automatic_compaction_context_limits() -> ContextLimits {
        ContextLimits {
            context_window: Some(130_000),
            reserve_tokens: 10_000,
            context_window_source: ContextValueSource::Cli,
            reserve_tokens_source: ContextValueSource::Cli,
        }
    }

    fn automatic_compaction_test_agent(
        session_id: &str,
        old_turns: usize,
        bytes_per_item: usize,
        responses: impl IntoIterator<Item = AssistantTurn>,
        enabled: bool,
    ) -> (tempfile::TempDir, Arc<RecordingProvider>, Agent) {
        let provider = Arc::new(RecordingProvider::new(responses));
        let (temp, agent) = automatic_compaction_test_agent_with_provider(
            session_id,
            old_turns,
            bytes_per_item,
            provider.clone(),
            enabled,
        );
        (temp, provider, agent)
    }

    fn automatic_compaction_test_agent_with_provider(
        session_id: &str,
        old_turns: usize,
        bytes_per_item: usize,
        provider: Arc<dyn ResponseProvider>,
        enabled: bool,
    ) -> (tempfile::TempDir, Agent) {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(session_id, SessionHeader::new(&project_root, "test-model"))
            .unwrap();
        append_large_complete_turns(&mut journal, old_turns, bytes_per_item);
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            automatic_compaction_context_limits(),
            None,
            None,
        );
        agent.set_automatic_compaction(enabled);
        (temp, agent)
    }

    fn append_preflight_only_automatic_compaction_failure(
        agent: &mut Agent,
        boundary_id: &str,
        turn_id: &str,
        prompt: &str,
    ) -> CompactionBoundary {
        let user = agent
            .journal_mut()
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":prompt},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let (_, prepared) = agent.prepare_request(Some(turn_id)).unwrap();
        let boundary = CompactionBoundary::new(boundary_id, turn_id, user.seq);
        let mut extra = Map::new();
        extra.insert(
            "planning_version".to_owned(),
            json!(AUTOMATIC_COMPACTION_PLANNING_VERSION),
        );
        extra.insert(
            "context".to_owned(),
            automatic_compaction_planning_context_value_v1(&prepared.context).unwrap(),
        );
        agent
            .journal_mut()
            .append_and_sync(
                COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "estimated_context_threshold".to_owned(),
                    extra,
                })
                .unwrap(),
            )
            .unwrap();
        agent
            .journal_mut()
            .append_and_sync(
                COMPACTION_BOUNDARY_FAILED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryFailed {
                    boundary_id: boundary.boundary_id.clone(),
                    code: "cancelled".to_owned(),
                    message: "automatic compaction was cancelled before candidate planning"
                        .to_owned(),
                    attempt_id: None,
                    extra: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        boundary
    }

    fn append_complete_turn(
        journal: &mut SessionJournal,
        turn_id: &str,
        question: &str,
        answer: &str,
    ) -> u64 {
        append_complete_turn_with_version(journal, turn_id, question, answer, TURN_BOUNDARY_VERSION)
    }

    fn append_complete_turn_with_version(
        journal: &mut SessionJournal,
        turn_id: &str,
        question: &str,
        answer: &str,
        turn_boundary_version: u64,
    ) -> u64 {
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":question},
                    "turn_boundary_version":turn_boundary_version,
                }),
            )
            .unwrap();
        let response_seq = journal.next_seq();
        let output_items = vec![json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":answer}],
        })];
        journal
            .append_and_sync(
                "response.completed",
                Some(turn_id),
                json!({
                    "raw_response":{"output":output_items},
                    "output_items":output_items,
                    "text":answer,
                    "usage":Usage::default(),
                    "turn_completion":{
                        "turn_boundary_version":turn_boundary_version,
                        "covers_from_seq":user.seq,
                        "final_response_seq":response_seq,
                        "covers_through_seq":response_seq,
                    }
                }),
            )
            .unwrap();
        let marker_seq = journal.next_seq();
        journal
            .append_and_sync(
                "turn.completed",
                Some(turn_id),
                json!({
                    "turn_boundary_version":turn_boundary_version,
                    "covers_from_seq":user.seq,
                    "final_response_seq":response_seq,
                    "covers_through_seq":marker_seq,
                }),
            )
            .unwrap();
        marker_seq
    }

    fn append_complete_tool_turn_without_output(
        journal: &mut SessionJournal,
        turn_id: &str,
    ) -> u64 {
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":"read the malformed record"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.completed",
                Some(turn_id),
                json!({
                    "raw_response":{"output":[{
                        "type":"function_call",
                        "call_id":"missing-output-call",
                        "name":"read",
                        "arguments":"{\"path\":\"missing.txt\"}"
                    }]},
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"missing-output-call",
                        "name":"read",
                        "arguments":"{\"path\":\"missing.txt\"}"
                    }],
                    "text":"",
                    "usage":Usage::default(),
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.completed",
                Some(turn_id),
                json!({
                    "call_id":"missing-output-call",
                    "tool":"read",
                }),
            )
            .unwrap();
        let response_seq = journal.next_seq();
        let output_items = vec![json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":"done"}],
        })];
        journal
            .append_and_sync(
                "response.completed",
                Some(turn_id),
                json!({
                    "raw_response":{"output":output_items},
                    "output_items":output_items,
                    "text":"done",
                    "usage":Usage::default(),
                    "turn_completion":{
                        "turn_boundary_version":TURN_BOUNDARY_VERSION,
                        "covers_from_seq":user.seq,
                        "final_response_seq":response_seq,
                        "covers_through_seq":response_seq,
                    }
                }),
            )
            .unwrap();
        let marker_seq = journal.next_seq();
        journal
            .append_and_sync(
                "turn.completed",
                Some(turn_id),
                json!({
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                    "covers_from_seq":user.seq,
                    "final_response_seq":response_seq,
                    "covers_through_seq":marker_seq,
                }),
            )
            .unwrap();
        marker_seq
    }

    fn append_pending_context_turn(
        journal: &mut SessionJournal,
        turn_id: &str,
        prompt: &str,
    ) -> (u64, u64) {
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":prompt},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let limit = journal
            .append_and_sync(
                "context.limit_reached",
                Some(turn_id),
                json!({"error":"context window limit reached"}),
            )
            .unwrap();
        (user.seq, limit.seq)
    }

    fn append_open_compaction_boundary(
        journal: &mut SessionJournal,
        turn_id: &str,
        prompt: &str,
    ) -> CompactionBoundary {
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":prompt},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let boundary = CompactionBoundary::new(format!("boundary-{turn_id}"), turn_id, user.seq);
        journal
            .append_and_sync(
                COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "test".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        boundary
    }

    fn boundary_candidate(
        journal: &mut SessionJournal,
        current_turn_id: &str,
        prompt: &str,
    ) -> (CompactionBoundary, crate::compaction::CompactionCandidate) {
        let cutoff = append_complete_turn(journal, "old-turn-1", "old one", "answer one");
        append_complete_turn(journal, "old-turn-2", "old two", "answer two");
        append_complete_turn(journal, "old-turn-3", "old three", "answer three");
        let boundary = append_open_compaction_boundary(journal, current_turn_id, prompt);
        let candidate = candidate_for_cutoff(journal, cutoff);
        (boundary, candidate)
    }

    fn candidate_for_cutoff(
        journal: &SessionJournal,
        cutoff: u64,
    ) -> crate::compaction::CompactionCandidate {
        let events = journal.read_events().unwrap();
        let chain = validate_checkpoint_chain(&events).unwrap();
        match select_compaction_candidate(
            &events,
            &chain,
            &CompactionContext {
                current_input_tokens: 100,
                target_input_tokens: 10,
                min_recent_complete_turns: 2,
                estimates: vec![CandidateEstimate {
                    covers_through_seq: cutoff,
                    estimated_input_tokens_after: 5,
                }],
            },
        )
        .unwrap()
        {
            CompactionSelection::Selected(candidate) => candidate,
            other => panic!("expected boundary candidate, got {other:?}"),
        }
    }

    fn count_events(events: &[JournalEvent], kind: &str) -> usize {
        events.iter().filter(|event| event.kind == kind).count()
    }

    async fn commit_checkpoint(journal: &mut SessionJournal, cutoff: u64) {
        let events = journal.read_events().unwrap();
        let chain = validate_checkpoint_chain(&events).unwrap();
        let candidate = match select_compaction_candidate(
            &events,
            &chain,
            &CompactionContext {
                current_input_tokens: 100,
                target_input_tokens: 10,
                min_recent_complete_turns: 2,
                estimates: vec![CandidateEstimate {
                    covers_through_seq: cutoff,
                    estimated_input_tokens_after: 5,
                }],
            },
        )
        .unwrap()
        {
            CompactionSelection::Selected(candidate) => candidate,
            other => panic!("expected compaction candidate, got {other:?}"),
        };
        let provider = RecordingProvider::new([compaction_summary_turn()]);
        compact_once(
            &provider,
            journal,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap();
    }

    async fn seed_checkpoint(journal: &mut SessionJournal) {
        let cutoff = append_complete_turn(
            journal,
            "old-turn-1",
            "historical needle",
            "historical answer",
        );
        append_complete_turn(journal, "old-turn-2", "second question", "second answer");
        append_complete_turn(journal, "old-turn-3", "third question", "third answer");
        commit_checkpoint(journal, cutoff).await;
    }

    async fn seed_artifact_checkpoint(journal: &mut SessionJournal) {
        let turn_id = "old-artifact-turn";
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":"produce old output"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let call_item = json!({
            "type":"function_call",
            "call_id":"old-shell-call",
            "name":"shell",
            "arguments":"{\"command\":\"echo old\"}",
        });
        journal
            .append_and_sync(
                "response.completed",
                Some(turn_id),
                json!({"raw_response":{"output":[call_item.clone()]},"output_items":[call_item]}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "tool.completed",
                Some(turn_id),
                json!({
                    "call_id":"old-shell-call",
                    "tool":"shell",
                    "output":{
                        "artifact_id":"artifact-old",
                        "artifact_sha256":"a".repeat(64),
                    },
                    "is_error":false,
                }),
            )
            .unwrap();
        let response_seq = journal.next_seq();
        let final_item = json!({
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":"saved"}],
        });
        journal
            .append_and_sync(
                "response.completed",
                Some(turn_id),
                json!({
                    "raw_response":{"output":[final_item.clone()]},
                    "output_items":[final_item],
                    "turn_completion":{
                        "turn_boundary_version":TURN_BOUNDARY_VERSION,
                        "covers_from_seq":user.seq,
                        "final_response_seq":response_seq,
                        "covers_through_seq":response_seq,
                    }
                }),
            )
            .unwrap();
        let cutoff = journal.next_seq();
        journal
            .append_and_sync(
                "turn.completed",
                Some(turn_id),
                json!({
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                    "covers_from_seq":user.seq,
                    "final_response_seq":response_seq,
                    "covers_through_seq":cutoff,
                }),
            )
            .unwrap();
        append_complete_turn(journal, "old-turn-2", "second question", "second answer");
        append_complete_turn(journal, "old-turn-3", "third question", "third answer");
        commit_checkpoint(journal, cutoff).await;
    }

    #[derive(Default)]
    struct NoopObserver;

    struct FailingProviderEventObserver;

    struct FailingStartObserver;

    struct FailingCompactionRecoveryIntentObserver;

    struct CancelAfterCheckpointObserver {
        cancellation: CancellationToken,
    }

    impl AgentObserver for NoopObserver {
        fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }

        fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
            Ok(())
        }

        fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
            Ok(())
        }

        fn on_message(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }
    }

    impl AgentObserver for FailingProviderEventObserver {
        fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Err(OxidraError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stdout closed",
            )))
        }

        fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
            Ok(())
        }

        fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
            Ok(())
        }

        fn on_message(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }
    }

    impl AgentObserver for FailingStartObserver {
        fn on_response_started(&mut self) -> Result<()> {
            Err(OxidraError::Config(
                "response renderer could not initialize".to_owned(),
            ))
        }

        fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }

        fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
            Ok(())
        }

        fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
            Ok(())
        }

        fn on_message(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }
    }

    impl AgentObserver for FailingCompactionRecoveryIntentObserver {
        fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }

        fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
            Ok(())
        }

        fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
            Ok(())
        }

        fn on_message(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }

        fn on_compaction_recovery_intent_synced(&mut self) -> Result<()> {
            Err(OxidraError::Config(
                "injected recovery observer failure".to_owned(),
            ))
        }
    }

    impl AgentObserver for CancelAfterCheckpointObserver {
        fn on_provider_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }

        fn on_tool_started(&mut self, _call: &ToolCall) -> Result<()> {
            Ok(())
        }

        fn on_tool_completed(&mut self, _call: &ToolCall, _result: &ToolResult) -> Result<()> {
            Ok(())
        }

        fn on_message(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }

        fn on_compaction(&mut self, message: &str) -> Result<()> {
            if message.starts_with("checkpoint ") {
                self.cancellation.cancel();
            }
            Ok(())
        }
    }

    #[test]
    fn automatic_compaction_planning_v1_fixture_is_frozen_and_extensible() {
        let context = serde_json::from_str::<Value>(include_str!(
            "../tests/fixtures/automatic_compaction_planning_v1.json"
        ))
        .unwrap();
        let mut extra = Map::new();
        extra.insert(
            "planning_version".to_owned(),
            json!(AUTOMATIC_COMPACTION_PLANNING_VERSION_V1),
        );
        extra.insert("context".to_owned(), context.clone());

        let parsed = automatic_compaction_planning_context_v1(&extra, "fixture-boundary")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.estimated_next_input_tokens, 100_000);
        assert_eq!(parsed.trigger_tokens, Some(96_000));
        assert_eq!(parsed.target_tokens, Some(60_000));
        assert_eq!(parsed.measurement.measurement_version, 2);
        assert_eq!(parsed.measurement.estimator_version, 1);
        assert_eq!(parsed.measurement.request_shape_version, 1);

        let mut unknown = extra.clone();
        unknown.insert("planning_version".to_owned(), json!(2));
        let error =
            automatic_compaction_planning_context_v1(&unknown, "future-boundary").unwrap_err();
        assert!(matches!(error, OxidraError::ApprovalRequired(_)));

        let mut unsupported_nested = extra;
        unsupported_nested["context"]["measurement"]["measurement_version"] = json!(3);
        let error = automatic_compaction_planning_context_v1(
            &unsupported_nested,
            "unsupported-measurement-boundary",
        )
        .unwrap_err();
        assert!(matches!(error, OxidraError::ApprovalRequired(_)));

        let current = serde_json::from_value::<ContextDecision>(context).unwrap();
        automatic_compaction_planning_context_value_v1(&current).unwrap();
        let mut changed = current;
        changed.measurement.measurement_version = 3;
        let error = automatic_compaction_planning_context_value_v1(&changed).unwrap_err();
        assert!(matches!(error, OxidraError::Config(_)));
    }

    #[test]
    fn automatic_compaction_planning_v1_writer_dependencies_are_explicit() {
        assert_eq!(AUTOMATIC_COMPACTION_PLANNING_VERSION, 1);
        assert_eq!(
            CONTEXT_MEASUREMENT_VERSION,
            AUTOMATIC_COMPACTION_PLANNING_CONTEXT_MEASUREMENT_VERSION_V1
        );
        assert_eq!(
            CONTEXT_ESTIMATOR_VERSION,
            AUTOMATIC_COMPACTION_PLANNING_CONTEXT_ESTIMATOR_VERSION_V1
        );
        assert_eq!(
            REQUEST_SHAPE_VERSION,
            AUTOMATIC_COMPACTION_PLANNING_CONTEXT_REQUEST_SHAPE_VERSION_V1
        );
    }

    #[tokio::test]
    async fn history_tools_are_hidden_without_a_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let journal = store
            .create_with_id(
                "history-hidden-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("done")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        agent
            .run_turn(
                "new session",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        let requests = provider.requests();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .tools
                .iter()
                .all(|tool| !is_history_tool_name(&tool.name))
        );
    }

    #[tokio::test]
    async fn response_started_audits_exact_request_and_uses_previous_usage_anchor() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let journal = store
            .create_with_id(
                "context-anchor-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            final_turn_with_usage("first", 2_000),
            final_turn_with_usage("second", 2_400),
        ]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        for prompt in ["first prompt", "second prompt"] {
            agent
                .run_turn(
                    prompt,
                    CancellationToken::new(),
                    &mut NoopObserver,
                    &mut DenyApproval,
                )
                .await
                .unwrap();
        }

        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "context.tools")
                .count(),
            1
        );
        let started = events
            .iter()
            .filter(|event| event.kind == "response.started")
            .collect::<Vec<_>>();
        assert_eq!(started.len(), 2);
        assert_eq!(started[0].data["context"]["method"], "full_request");
        assert_eq!(started[1].data["context"]["method"], "usage_anchor");
        assert_eq!(
            started[1].data["context"]["anchor_reported_input_tokens"],
            2_000
        );
        assert!(
            started[1].data["context"]["estimate_delta_tokens"]
                .as_i64()
                .is_some()
        );
        assert_eq!(
            started[0].data["context"]["tools_event_seq"],
            started[1].data["context"]["tools_event_seq"]
        );
        assert_eq!(
            started[1].data["context"]["measurement"]["request_digest"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }

    #[tokio::test]
    async fn automatic_compaction_remains_disabled_without_the_experiment_flag() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-disabled",
            6,
            40_000,
            [final_turn("done")],
            false,
        );

        agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        assert_eq!(provider.requests().len(), 1);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_STARTED_KIND), 0);
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 0);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 0);
    }

    #[tokio::test]
    async fn automatic_compaction_below_trigger_sends_the_normal_request() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-below-trigger",
            1,
            16,
            [final_turn("done")],
            true,
        );

        agent
            .run_turn(
                "small prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        assert_eq!(provider.requests().len(), 1);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "context.tools"), 1);
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_STARTED_KIND), 0);
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 0);
    }

    #[tokio::test]
    async fn automatic_compaction_commits_one_checkpoint_before_the_normal_request() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-success",
            6,
            40_000,
            [compaction_summary_turn(), final_turn("done")],
            true,
        );

        let outcome = agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        assert_eq!(outcome.responses, 1);
        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].max_output_tokens,
            Some(MAX_COMPACTION_OUTPUT_TOKENS)
        );
        assert!(requests[0].tools.is_empty());
        assert_eq!(requests[1].max_output_tokens, None);
        assert!(
            requests[1]
                .tools
                .iter()
                .any(|tool| is_history_tool_name(&tool.name))
        );
        let normal_input = serde_json::to_string(&requests[1].input).unwrap();
        assert!(normal_input.contains("oxidra_compacted_history"));
        assert!(!normal_input.contains("old-question-0"));
        assert!(normal_input.contains("old-question-5"));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_STARTED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_CHECKPOINTED_KIND),
            1
        );
        let boundary = events
            .iter()
            .find(|event| event.kind == COMPACTION_BOUNDARY_STARTED_KIND)
            .unwrap();
        assert_eq!(boundary.data["trigger"], "estimated_context_threshold");
        assert_eq!(
            boundary.data["planning_version"],
            AUTOMATIC_COMPACTION_PLANNING_VERSION
        );
        assert_eq!(boundary.data["context_window_source"], "cli");
        assert_eq!(boundary.data["reserve_tokens_source"], "cli");
    }

    #[tokio::test]
    async fn cancellation_after_compaction_checkpoint_does_not_start_normal_response() {
        let provider = Arc::new(CancellationAwareCompactionProvider::default());
        let (_temp, mut agent) = automatic_compaction_test_agent_with_provider(
            "automatic-compaction-cancel-after-checkpoint",
            6,
            40_000,
            provider,
            true,
        );
        let cancellation = CancellationToken::new();
        let mut observer = CancelAfterCheckpointObserver {
            cancellation: cancellation.clone(),
        };

        let error = agent
            .run_turn(
                "current prompt",
                cancellation,
                &mut observer,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Interrupted));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(count_events(&events, "response.started"), 0);
        assert_eq!(count_events(&events, "turn.cancelled"), 1);
    }

    #[tokio::test]
    async fn automatic_compaction_counts_against_max_responses() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-max-responses",
            6,
            40_000,
            [compaction_summary_turn(), final_turn("should not run")],
            true,
        );
        agent.max_responses = Some(1);
        let error = agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Limit(_)), "{error:?}");
        assert_eq!(provider.requests().len(), 1);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(count_events(&events, "response.started"), 0);
        assert_eq!(count_events(&events, "agent.limit_reached"), 0);

        agent.max_responses = Some(2);
        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "should not run");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "response.started"), 1);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkpointed_55e5b0c_budget_terminal_migrates_after_limit_increase() {
        let fixture = include_str!("../tests/fixtures/checkpointed_budget_limit_55e5b0c.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<JournalEvent>(line).expect("literal 55e5b0c JSONL"))
            .collect::<Vec<_>>();
        let fixture_chain = validate_compaction_boundary_chain(&fixture).unwrap();
        assert_eq!(fixture_chain.pending().len(), 1);
        assert_eq!(
            fixture_chain.pending()[0].state,
            CompactionBoundaryState::Checkpointed
        );
        assert_eq!(
            provider_request_slot_state_for_version(1, &fixture, "turn-2").unwrap(),
            ProviderRequestSlotState::Terminal
        );

        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "legacy-checkpoint-budget-retry",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        for event in fixture.into_iter().skip(1) {
            journal
                .append_and_sync(&event.kind, event.turn_id.as_deref(), event.data)
                .unwrap();
        }
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("resumed without loss")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            Some(1),
            None,
        );
        let before = agent.journal().read_events().unwrap();

        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Limit(_)), "{error:?}");
        assert_eq!(agent.journal().read_events().unwrap(), before);
        assert!(provider.requests().is_empty());

        agent.max_responses = Some(2);
        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "resumed without loss");
        let requests = provider.requests();
        assert_eq!(requests.len(), 1);
        let input = serde_json::to_string(&requests[0].input).unwrap();
        assert!(input.contains("summary v2"));
        assert!(input.contains("prompt"));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "user.message"), 2);
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND),
            1
        );
        let chain = validate_compaction_boundary_chain(&events).unwrap();
        assert!(chain.pending().is_empty());
        assert_eq!(
            chain.boundaries()[0].state,
            CompactionBoundaryState::Superseded
        );
        assert_eq!(
            chain.boundaries()[1].state,
            CompactionBoundaryState::CompletedTurn
        );
        assert!(matches!(
            segment_turns(&events).unwrap().last().unwrap().state,
            TurnState::Complete(_)
        ));
    }

    #[tokio::test]
    async fn synced_legacy_budget_migration_survives_session_reopen() {
        let fixture = include_str!("../tests/fixtures/checkpointed_budget_limit_55e5b0c.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<JournalEvent>(line).expect("literal 55e5b0c JSONL"))
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "legacy-budget-migration-reopen",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        for event in fixture.into_iter().skip(1) {
            journal
                .append_and_sync(&event.kind, event.turn_id.as_deref(), event.data)
                .unwrap();
        }
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut planning_agent = Agent::new(
            Arc::new(RecordingProvider::new([final_turn("must not run")])),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            Some(2),
            None,
        );
        let plan = planning_agent.build_recovery_plan_v1().unwrap();
        let retry = match plan.action {
            RecoveryActionV1::ResumeBudgetLimitedCheckpoint { retry } => retry,
            _ => panic!("unexpected recovery action"),
        };
        planning_agent
            .journal
            .append_and_sync(
                COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
                None,
                serde_json::to_value(retry).unwrap(),
            )
            .unwrap();
        drop(planning_agent);

        let journal = store.open("legacy-budget-migration-reopen").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("resumed after reopen")]));
        let mut resumed = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            Some(2),
            None,
        );
        let outcome = resumed
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "resumed after reopen");
        assert_eq!(provider.requests().len(), 1);
        let events = resumed.journal().read_events().unwrap();
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND),
            1,
            "reopen must reuse the durable migration instead of minting another"
        );
        assert!(
            validate_compaction_boundary_chain(&events)
                .unwrap()
                .pending()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn automatic_compaction_usage_is_included_in_turn_outcome() {
        let (_temp, _provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-usage-accounting",
            6,
            40_000,
            [compaction_summary_turn(), final_turn_with_usage("done", 50)],
            true,
        );
        agent.max_responses = Some(2);
        let outcome = agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.responses, 1);
        assert_eq!(outcome.usage.input_tokens, 150);
        assert_eq!(outcome.usage.cached_input_tokens, 35);
        assert_eq!(outcome.usage.output_tokens, 30);
        assert_eq!(outcome.usage.reasoning_output_tokens, 7);
        assert_eq!(outcome.usage.total_tokens, 180);
    }

    #[tokio::test]
    async fn automatic_compaction_stops_when_two_recent_turns_leave_no_safe_candidate() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-no-candidate",
            2,
            80_000,
            std::iter::empty::<AssistantTurn>(),
            true,
        );
        let prompt = "p".repeat(100_000);

        let error = agent
            .run_turn(
                &prompt,
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, OxidraError::Limit(_)));
        assert!(provider.requests().is_empty());
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_STARTED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_FAILED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 0);
        assert_eq!(count_events(&events, "response.started"), 0);
        let failure = events
            .iter()
            .find(|event| event.kind == COMPACTION_BOUNDARY_FAILED_KIND)
            .unwrap();
        assert_eq!(failure.data["code"], "no_candidate");
    }

    #[tokio::test]
    async fn retry_pending_replans_preflight_only_compaction_failure() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-replan-after-preflight-failure",
            6,
            40_000,
            [compaction_summary_turn(), final_turn("replanned answer")],
            true,
        );
        let turn_id = "replan-turn";
        let user = agent
            .journal_mut()
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":"current prompt"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let (_, prepared) = agent.prepare_request(Some(turn_id)).unwrap();
        let boundary = CompactionBoundary::new("preflight-only-boundary", turn_id, user.seq);
        let mut extra = Map::new();
        extra.insert(
            "planning_version".to_owned(),
            json!(AUTOMATIC_COMPACTION_PLANNING_VERSION),
        );
        extra.insert(
            "context".to_owned(),
            prepared.context.audit_value().unwrap(),
        );
        agent
            .journal_mut()
            .append_and_sync(
                COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "estimated_context_threshold".to_owned(),
                    extra,
                })
                .unwrap(),
            )
            .unwrap();
        agent
            .journal_mut()
            .append_and_sync(
                COMPACTION_BOUNDARY_FAILED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryFailed {
                    boundary_id: boundary.boundary_id.clone(),
                    code: "cancelled".to_owned(),
                    message: "automatic compaction was cancelled before candidate planning"
                        .to_owned(),
                    attempt_id: None,
                    extra: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        let failed_events = agent.journal().read_events().unwrap();
        assert_eq!(
            count_events(&failed_events, COMPACTION_BOUNDARY_STARTED_KIND),
            1
        );
        assert_eq!(
            count_events(&failed_events, COMPACTION_BOUNDARY_FAILED_KIND),
            1
        );
        assert_eq!(count_events(&failed_events, COMPACTION_STARTED_KIND), 0);

        // Resume configuration is runtime truth. The durable v1 context only
        // proves how the original preflight was planned.
        agent.context_runtime.limits = ContextLimits {
            context_window: Some(124_000),
            reserve_tokens: 0,
            context_window_source: ContextValueSource::Cli,
            reserve_tokens_source: ContextValueSource::Cli,
        };

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let error = agent
            .retry_pending_turn(cancelled, &mut NoopObserver, &mut DenyApproval)
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Interrupted));
        let cancelled_events = agent.journal().read_events().unwrap();
        assert_eq!(
            count_events(&cancelled_events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            1
        );
        assert_eq!(
            count_events(&cancelled_events, COMPACTION_BOUNDARY_FAILED_KIND),
            2
        );
        assert_eq!(count_events(&cancelled_events, COMPACTION_STARTED_KIND), 0);

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "replanned answer");
        assert_eq!(provider.requests().len(), 2);
        assert_eq!(provider.requests()[0].max_output_tokens, Some(8_192));
        assert_eq!(provider.requests()[1].max_output_tokens, None);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            2
        );
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 1);
        let latest_retry = events
            .iter()
            .rev()
            .find(|event| event.kind == COMPACTION_BOUNDARY_RETRY_STARTED_KIND)
            .unwrap();
        assert_eq!(latest_retry.data["planning_version"], 1);
        assert_eq!(latest_retry.data["context"]["context_window"], 124_000);
        assert_eq!(latest_retry.data["context"]["reserve_tokens"], 0);
        assert_eq!(latest_retry.data["context"]["target_tokens"], 62_000);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn replan_uses_current_config_and_refuses_unneeded_compaction_without_mutation() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-current-config-below-trigger",
            6,
            40_000,
            [compaction_summary_turn()],
            true,
        );
        append_preflight_only_automatic_compaction_failure(
            &mut agent,
            "old-config-failed-boundary",
            "current-config-turn",
            "current prompt",
        );
        let before = agent.journal().read_events().unwrap();

        agent.context_runtime.limits = ContextLimits {
            context_window: Some(10_000_000),
            reserve_tokens: 0,
            context_window_source: ContextValueSource::Cli,
            reserve_tokens_source: ContextValueSource::Cli,
        };
        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, OxidraError::ApprovalRequired(_)));
        assert!(
            error
                .to_string()
                .contains("below the current automatic compaction trigger")
        );
        assert!(provider.requests().is_empty());
        assert_eq!(agent.journal().read_events().unwrap(), before);
    }

    #[tokio::test]
    async fn recovery_observer_failure_settles_the_replacement_boundary() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-recovery-observer-failure",
            6,
            40_000,
            [compaction_summary_turn()],
            true,
        );
        append_preflight_only_automatic_compaction_failure(
            &mut agent,
            "observer-failed-boundary",
            "observer-failed-turn",
            "current prompt",
        );

        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut FailingCompactionRecoveryIntentObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Config(_)));
        assert!(provider.requests().is_empty());
        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            1
        );
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_FAILED_KIND), 2);
        let pending = agent.pending_compaction_boundaries().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, CompactionBoundaryState::Failed);
    }

    #[tokio::test]
    async fn automatic_compaction_rejects_a_summary_that_misses_the_real_target() {
        let (_temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-large-summary",
            6,
            40_000,
            [compaction_summary_turn_with_text("s".repeat(300_000))],
            true,
        );

        let error = agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();

        assert!(matches!(error, OxidraError::Limit(_)));
        assert_eq!(provider.requests().len(), 1);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_FAILED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_FAILED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 0);
        assert_eq!(count_events(&events, "response.started"), 0);
    }

    #[tokio::test]
    async fn automatic_compaction_runs_at_most_once_across_tool_round_trips() {
        let read_calls = (0..6)
            .map(|index| ToolCall {
                id: format!("read-after-compaction-{index}"),
                name: "read".to_owned(),
                arguments: json!({"path":"note.txt"}),
            })
            .collect::<Vec<_>>();
        let (temp, provider, mut agent) = automatic_compaction_test_agent(
            "automatic-compaction-tool-roundtrip",
            6,
            40_000,
            [
                compaction_summary_turn(),
                tool_turn(read_calls),
                final_turn("done"),
            ],
            true,
        );
        std::fs::write(
            temp.path().join("project").join("note.txt"),
            "n".repeat(60_000),
        )
        .unwrap();

        let outcome = agent
            .run_turn(
                "read note.txt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        assert_eq!(outcome.responses, 2);
        assert_eq!(outcome.tools, 6);
        let requests = provider.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.max_output_tokens.is_some())
                .count(),
            1
        );
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(count_events(&events, "response.started"), 2);
        let response_starts = events
            .iter()
            .filter(|event| event.kind == "response.started")
            .collect::<Vec<_>>();
        assert!(
            response_starts[1].data["context"]["estimated_next_input_tokens"]
                .as_u64()
                .unwrap()
                >= response_starts[1].data["context"]["trigger_tokens"]
                    .as_u64()
                    .unwrap()
        );
    }

    #[tokio::test]
    async fn provider_context_limit_after_checkpoint_retries_without_recompacting() {
        let provider = Arc::new(ScriptedProvider::new([
            Ok(compaction_summary_turn()),
            Err(OxidraError::ProviderContextLimit(
                "context_length_exceeded".to_owned(),
            )),
            Ok(final_turn("done after retry")),
        ]));
        let (_temp, mut agent) = automatic_compaction_test_agent_with_provider(
            "automatic-compaction-provider-limit",
            6,
            40_000,
            provider.clone(),
            true,
        );

        let error = agent
            .run_turn(
                "current prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::ProviderContextLimit(_)));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(count_events(&events, "context.limit_reached"), 1);
        assert_eq!(agent.pending_compaction_boundaries().unwrap().len(), 1);
        assert_eq!(agent.pending_context_turns().unwrap().len(), 1);

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "done after retry");

        let requests = provider.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.max_output_tokens.is_some())
                .count(),
            1
        );
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 1);
        assert_eq!(count_events(&events, COMPACTION_CHECKPOINT_KIND), 1);
        assert_eq!(count_events(&events, "turn.retry_started"), 1);
        assert_eq!(count_events(&events, "response.started"), 2);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
        assert!(agent.pending_context_turns().unwrap().is_empty());
    }

    #[tokio::test]
    async fn provider_context_limit_records_a_recoverable_pending_turn() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let journal = store
            .create_with_id(
                "context-limit-audit-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(ContextLimitProvider::default());
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits {
                context_window: Some(300),
                reserve_tokens: 100,
                context_window_source: ContextValueSource::Cli,
                reserve_tokens_source: ContextValueSource::Cli,
            },
            None,
            None,
        );

        let error = agent
            .run_turn(
                "this request cannot fit",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::ProviderContextLimit(_)));
        assert_eq!(provider.requests().len(), 1);
        let event = agent
            .journal()
            .read_events()
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "context.limit_reached")
            .unwrap();
        assert!(event.data["context"]["measurement"]["request_digest"].is_string());
        assert!(event.data["context"]["estimated_next_input_tokens"].is_u64());
        assert!(event.data["context"]["tools_event_seq"].is_u64());
        assert_eq!(event.data["source"], "provider");

        let retry_error = agent
            .run_turn(
                "small replacement prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(retry_error, OxidraError::ApprovalRequired(_)));
        assert_eq!(
            agent
                .journal()
                .read_events()
                .unwrap()
                .iter()
                .filter(|event| event.kind == "user.message")
                .count(),
            1,
            "a blocked resume must not append another user message"
        );
    }

    #[tokio::test]
    async fn pending_compaction_boundary_blocks_a_new_prompt_before_journal_append() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "compaction-pending-gate-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_open_compaction_boundary(&mut journal, "pending-turn", "original prompt");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("must not run")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "replacement before resolution",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::ApprovalRequired(_)));
        assert!(provider.requests().is_empty());
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "user.message"), 1);
        assert_eq!(agent.pending_compaction_boundaries().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn abandoning_a_compaction_boundary_removes_the_old_turn_from_the_next_request() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "compaction-abandon-projection-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_open_compaction_boundary(&mut journal, "abandoned-turn", "obsolete prompt");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("replacement answer")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let abandoned = agent
            .abandon_pending_turns("replace the original prompt")
            .unwrap();
        assert_eq!(
            abandoned,
            AbandonedPending {
                context_turns: 0,
                compaction_boundaries: 1,
            }
        );
        let outcome = agent
            .run_turn(
                "replacement prompt",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "replacement answer");

        let request = provider.requests().pop().unwrap();
        let serialized = serde_json::to_string(&request.input).unwrap();
        assert!(!serialized.contains("obsolete prompt"));
        assert!(serialized.contains("replacement prompt"));
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_ABANDONED_KIND), 1);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkpointed_compaction_boundary_resumes_the_original_turn() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "checkpointed-boundary-resume-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let (boundary, candidate) =
            boundary_candidate(&mut journal, "current-turn", "resume original prompt");
        compact_once_for_boundary(
            &RecordingProvider::new([compaction_summary_turn()]),
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap();
        drop(journal);

        let journal = store.open("checkpointed-boundary-resume-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("resumed answer")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "resumed answer");
        let requests = provider.requests();
        assert_eq!(requests.len(), 1);
        let serialized = serde_json::to_string(&requests[0].input).unwrap();
        assert!(serialized.contains("checkpoint summary"));
        assert!(serialized.contains("resume original prompt"));
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkpointed_boundary_does_not_append_a_retry_from_terminal_slot() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "checkpointed-boundary-terminal-slot-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let (boundary, candidate) =
            boundary_candidate(&mut journal, "current-turn", "resume original prompt");
        compact_once_for_boundary(
            &RecordingProvider::new([compaction_summary_turn()]),
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some(&boundary.turn_id),
                json!({"response_attempt_id":"failed-normal-attempt"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.failed",
                Some(&boundary.turn_id),
                json!({
                    "response_attempt_id":"failed-normal-attempt",
                    "error":"injected normal Provider failure",
                }),
            )
            .unwrap();
        drop(journal);

        let journal = store
            .open("checkpointed-boundary-terminal-slot-test")
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("must not run")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let before = agent.journal().read_events().unwrap();
        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::ApprovalRequired(_)));
        assert!(error.to_string().contains("request-slot state Terminal"));
        assert!(provider.requests().is_empty());
        let after = agent.journal().read_events().unwrap();
        assert_eq!(after, before, "a refused retry must not mutate the journal");
    }

    #[tokio::test]
    async fn failed_compaction_boundary_replays_its_candidate_before_resuming() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "failed-boundary-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let (boundary, candidate) =
            boundary_candidate(&mut journal, "current-turn", "retry original prompt");
        let error = compact_once_for_boundary(
            &ProviderFailureProvider,
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, OxidraError::Provider(_)));
        drop(journal);

        let journal = store.open("failed-boundary-retry-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            compaction_summary_turn(),
            final_turn("retried answer"),
        ]));
        let mut agent = Agent::new_with_runtime(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextRuntime::for_tests("test-model", ContextLimits::default()),
            None,
            None,
        );

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "retried answer");
        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].tools.is_empty());
        assert_eq!(requests[0].max_output_tokens, Some(8_192));
        let normal_input = serde_json::to_string(&requests[1].input).unwrap();
        assert!(normal_input.contains("checkpoint summary"));
        assert!(normal_input.contains("retry original prompt"));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            1
        );
        assert_eq!(count_events(&events, COMPACTION_BOUNDARY_FAILED_KIND), 1);
        assert_eq!(count_events(&events, "compaction.checkpoint"), 1);
        assert_eq!(count_events(&events, "user.message"), 4);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_compaction_attempt_consumes_the_durable_provider_call_budget() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "failed-boundary-budget-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let (boundary, candidate) =
            boundary_candidate(&mut journal, "budget-turn", "retry original prompt");
        let error = compact_once_for_boundary(
            &ProviderFailureProvider,
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, OxidraError::Provider(_)));

        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            compaction_summary_turn(),
            final_turn("must not dispatch"),
        ]));
        let mut agent = Agent::new_with_runtime(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextRuntime::for_tests("test-model", ContextLimits::default()),
            Some(1),
            None,
        );

        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Limit(_)));
        assert!(provider.requests().is_empty());
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 1);
        assert_eq!(count_events(&events, "agent.limit_reached"), 0);
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            0
        );
        agent.max_responses = Some(3);
        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "must not dispatch");
        assert_eq!(provider.requests().len(), 2);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, COMPACTION_STARTED_KIND), 2);
        assert_eq!(count_events(&events, "response.started"), 1);
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_boundary_owns_recovery_when_context_turn_is_also_pending() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "combined-context-boundary-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let cutoff = append_complete_turn(&mut journal, "old-turn-1", "old one", "answer one");
        append_complete_turn(&mut journal, "old-turn-2", "old two", "answer two");
        append_complete_turn(&mut journal, "old-turn-3", "old three", "answer three");
        let user = journal
            .append_and_sync(
                "user.message",
                Some("limited-turn"),
                json!({
                    "item":{"role":"user","content":"retry and compact this prompt"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let limit = journal
            .append_and_sync(
                "context.limit_reached",
                Some("limited-turn"),
                json!({"error":"context window limit reached"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "turn.retry_started",
                Some("limited-turn"),
                json!({
                    "retry_version":1,
                    "retry_id":"existing-context-retry",
                    "user_message_seq":user.seq,
                    "context_limit_seq":limit.seq,
                }),
            )
            .unwrap();
        let boundary = CompactionBoundary::new("failed-after-context", "limited-turn", user.seq);
        journal
            .append_and_sync(
                COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "context_retry".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        let candidate = candidate_for_cutoff(&journal, cutoff);
        let error = compact_once_for_boundary(
            &ProviderFailureProvider,
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, OxidraError::Provider(_)));
        drop(journal);

        let journal = store.open("combined-context-boundary-retry-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            compaction_summary_turn(),
            final_turn("combined recovery complete"),
        ]));
        let mut agent = Agent::new_with_runtime(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextRuntime::for_tests("test-model", ContextLimits::default()),
            None,
            None,
        );

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "combined recovery complete");
        assert_eq!(provider.requests().len(), 2);
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "turn.retry_started"), 1);
        assert_eq!(count_events(&events, "user.message"), 4);
        assert_eq!(
            count_events(&events, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            1
        );
        assert_eq!(count_events(&events, "compaction.checkpoint"), 1);
        assert!(agent.pending_context_turns().unwrap().is_empty());
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_historical_candidate_replays_with_its_recorded_versions() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "historical-candidate-replay-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let cutoff = append_complete_turn_with_version(
            &mut journal,
            "old-turn-1",
            "old one",
            "answer one",
            3,
        );
        append_complete_turn_with_version(&mut journal, "old-turn-2", "old two", "answer two", 3);
        append_complete_turn_with_version(
            &mut journal,
            "old-turn-3",
            "old three",
            "answer three",
            3,
        );
        let user = journal
            .append_and_sync(
                "user.message",
                Some("historical-turn"),
                json!({
                    "item":{"role":"user","content":"resume the historical prompt"},
                    "turn_boundary_version":3,
                }),
            )
            .unwrap();
        let boundary = CompactionBoundary {
            version: 1,
            boundary_id: "historical-boundary-v1".to_owned(),
            turn_id: "historical-turn".to_owned(),
            user_message_seq: user.seq,
        };
        journal
            .append_and_sync(
                COMPACTION_BOUNDARY_STARTED_KIND,
                None,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "historical".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            )
            .unwrap();
        let mut candidate = candidate_for_cutoff(&journal, cutoff);
        candidate.turn_boundary_validator_version = 3;
        let error = compact_replay_once_for_boundary(
            &ProviderFailureProvider,
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, OxidraError::Provider(_)));
        drop(journal);

        let journal = store.open("historical-candidate-replay-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            compaction_summary_turn(),
            final_turn("historical replay complete"),
        ]));
        let mut agent = Agent::new_with_runtime(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextRuntime::for_tests("test-model", ContextLimits::default()),
            None,
            None,
        );

        let outcome = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "historical replay complete");
        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].input.as_slice(), candidate.source.items());
        assert_eq!(requests[0].max_output_tokens, Some(8_192));

        let events = agent.journal().read_events().unwrap();
        let starts = events
            .iter()
            .filter(|event| event.kind == "compaction.started")
            .map(|event| serde_json::from_value::<CompactionStarted>(event.data.clone()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[1].source_projection_version, 3);
        assert_eq!(starts[1].turn_boundary_validator_version, 3);
        let checkpoints = events
            .iter()
            .filter(|event| event.kind == "compaction.checkpoint")
            .map(|event| serde_json::from_value::<Checkpoint>(event.data.clone()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].source_projection_version, 3);
        assert_eq!(checkpoints[0].turn_boundary_validator_version, 3);
        validate_checkpoint_chain(&events).unwrap();
        assert!(agent.pending_compaction_boundaries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_history_prefix_rejects_replay_before_any_durable_retry() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "history-precommit-validation-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let cutoff = append_complete_tool_turn_without_output(&mut journal, "malformed-old-turn");
        append_complete_turn(&mut journal, "old-turn-2", "old two", "answer two");
        append_complete_turn(&mut journal, "old-turn-3", "old three", "answer three");
        let boundary =
            append_open_compaction_boundary(&mut journal, "current-turn", "retry safely");
        let candidate = candidate_for_cutoff(&journal, cutoff);
        let error = compact_once_for_boundary(
            &ProviderFailureProvider,
            &mut journal,
            &boundary,
            &candidate,
            "test-model",
            &mut NoopStreamObserver,
            CancellationToken::new(),
            |_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, OxidraError::Provider(_)));
        drop(journal);

        let journal = store.open("history-precommit-validation-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([compaction_summary_turn()]));
        let mut agent = Agent::new_with_runtime(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextRuntime::for_tests("test-model", ContextLimits::default()),
            None,
            None,
        );
        let before = agent.journal().read_events().unwrap();

        let error = agent
            .retry_pending_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("has no output"));
        assert!(provider.requests().is_empty());
        let after = agent.journal().read_events().unwrap();
        assert_eq!(
            after, before,
            "failed planning must not append retry intent"
        );
        assert_eq!(count_events(&after, "compaction.checkpoint"), 0);
        assert_eq!(
            count_events(&after, COMPACTION_BOUNDARY_RETRY_STARTED_KIND),
            0
        );
    }

    #[tokio::test]
    async fn explicit_retry_reuses_the_original_turn_without_deleting_history() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "context-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("limited-turn"),
                json!({
                    "item":{"role":"user","content":"oversized prompt"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "context.limit_reached",
                Some("limited-turn"),
                json!({"error":"context window limit reached"}),
            )
            .unwrap();
        drop(journal);

        let journal = store.open("context-retry-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            final_turn("retried"),
            final_turn("follow-up"),
        ]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits {
                context_window: Some(1_000_000),
                reserve_tokens: 16_000,
                context_window_source: ContextValueSource::Cli,
                reserve_tokens_source: ContextValueSource::Cli,
            },
            None,
            None,
        );

        let pending = agent.pending_context_turns().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].prompt, "oversized prompt");

        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "retried");
        assert!(agent.pending_context_turns().unwrap().is_empty());

        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.retry_started")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.abandoned")
                .count(),
            0
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "user.message")
                .count(),
            1
        );
        let projected = project_events(&events).unwrap();
        let projected_user_text = projected
            .iter()
            .filter(|item| item.get("role").and_then(Value::as_str) == Some("user"))
            .filter_map(|item| item.get("content").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(projected_user_text, vec!["oversized prompt"]);
        assert_eq!(provider.requests().len(), 1);

        let follow_up = agent
            .run_turn(
                "continue after retry",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(follow_up.text, "follow-up");
        assert_eq!(provider.requests().len(), 2);
    }

    #[test]
    fn unvalidated_inline_completion_cannot_clear_a_pending_context_turn() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "forged-context-completion-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_pending_context_turn(&mut journal, "limited-turn", "oversized prompt");
        journal
            .append_and_sync("note", Some("limited-turn"), json!({"turn_completion":{}}))
            .unwrap();

        let error = pending_context_turns(&journal.read_events().unwrap())
            .expect_err("raw payload fields must not resolve a pending turn")
            .to_string();
        assert!(
            error.contains("inline completion") || error.contains("turn boundary"),
            "unexpected reducer error: {error}"
        );
    }

    #[tokio::test]
    async fn synced_retry_intent_survives_reopen_without_duplication() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "context-retry-recovery-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let user = journal
            .append_and_sync(
                "user.message",
                Some("limited-turn"),
                json!({
                    "item":{"role":"user","content":"retry me"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let limit = journal
            .append_and_sync(
                "context.limit_reached",
                Some("limited-turn"),
                json!({"error":"context window limit reached"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "turn.retry_started",
                Some("limited-turn"),
                json!({
                    "retry_version":1,
                    "retry_id":"persisted-retry",
                    "user_message_seq":user.seq,
                    "context_limit_seq":limit.seq,
                }),
            )
            .unwrap();
        drop(journal);

        let journal = store.open("context-retry-recovery-test").unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("recovered")]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "recovered");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.retry_started")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "user.message")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn recovered_retry_attempt_gets_a_new_intent_without_a_new_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "context-retry-attempt-recovery-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let user = journal
            .append_and_sync(
                "user.message",
                Some("limited-turn"),
                json!({
                    "item":{"role":"user","content":"retry after crash"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        let limit = journal
            .append_and_sync(
                "context.limit_reached",
                Some("limited-turn"),
                json!({"error":"context window limit reached"}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "turn.retry_started",
                Some("limited-turn"),
                json!({
                    "retry_version":1,
                    "retry_id":"first-retry",
                    "user_message_seq":user.seq,
                    "context_limit_seq":limit.seq,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("limited-turn"),
                json!({"response_attempt_id":"crashed-attempt","response_index":1}),
            )
            .unwrap();
        drop(journal);

        let journal = store.open("context-retry-attempt-recovery-test").unwrap();
        assert_eq!(journal.recovery_info().aborted_responses, 1);
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("recovered")]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "recovered");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "turn.retry_started")
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "user.message")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn cancelled_retry_can_be_retried_successfully() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "cancelled-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_pending_context_turn(&mut journal, "limited-turn", "retry after cancellation");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("done")]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            agent
                .retry_pending_context_turn(cancelled, &mut NoopObserver, &mut DenyApproval,)
                .await,
            Err(OxidraError::Interrupted)
        ));
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "done");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "turn.retry_started"), 2);
        assert_eq!(count_events(&events, "turn.cancelled"), 1);
        assert_eq!(count_events(&events, "turn.completed"), 1);
    }

    #[tokio::test]
    async fn stalled_retry_can_be_retried_successfully() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "stalled-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_pending_context_turn(&mut journal, "limited-turn", "retry after stall");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let failed_read = |id: &str| {
            tool_turn(vec![ToolCall {
                id: id.to_owned(),
                name: "read".to_owned(),
                arguments: json!({"path":"missing.txt"}),
            }])
        };
        let provider = Arc::new(RecordingProvider::new([
            failed_read("read-1"),
            failed_read("read-2"),
            failed_read("read-3"),
            final_turn("done"),
        ]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            None,
        );

        let stalled = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert!(stalled.stalled);
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "done");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "agent.stalled"), 1);
        assert_eq!(count_events(&events, "turn.retry_started"), 2);
        assert_eq!(count_events(&events, "turn.completed"), 1);
    }

    #[tokio::test]
    async fn response_limited_retry_requires_a_larger_current_budget() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::write(project_root.join("a.txt"), "ok").unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "limited-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_pending_context_turn(&mut journal, "limited-turn", "retry after response limit");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            tool_turn(vec![ToolCall {
                id: "read-1".to_owned(),
                name: "read".to_owned(),
                arguments: json!({"path":"a.txt"}),
            }]),
            final_turn("done"),
        ]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            Some(1),
            None,
        );

        assert!(matches!(
            agent
                .retry_pending_context_turn(
                    CancellationToken::new(),
                    &mut NoopObserver,
                    &mut DenyApproval,
                )
                .await,
            Err(OxidraError::Limit(_))
        ));
        assert!(matches!(
            agent
                .retry_pending_context_turn(
                    CancellationToken::new(),
                    &mut NoopObserver,
                    &mut DenyApproval,
                )
                .await,
            Err(OxidraError::Limit(_))
        ));
        assert_eq!(provider.requests().len(), 1);
        agent.max_responses = Some(2);
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "done");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "agent.limit_reached"), 1);
        assert_eq!(count_events(&events, "turn.retry_started"), 2);
        assert_eq!(count_events(&events, "turn.completed"), 1);
    }

    #[test]
    fn legacy_response_limit_is_not_duplicated_in_the_same_retry_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "legacy-response-budget-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        journal
            .append_and_sync(
                "user.message",
                Some("legacy-budget-turn"),
                json!({
                    "item":{"role":"user","content":"legacy budget"},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
                }),
            )
            .unwrap();
        journal
            .append_and_sync(
                "response.started",
                Some("legacy-budget-turn"),
                json!({"response_attempt_id":"legacy-attempt","response_index":1}),
            )
            .unwrap();
        journal
            .append_and_sync(
                "agent.limit_reached",
                Some("legacy-budget-turn"),
                json!({"kind":"responses","limit":1}),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(FinalResponseProvider),
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            Some(1),
            None,
        );
        let before = agent.journal().read_events().unwrap();

        let error = agent
            .ensure_provider_call_budget("legacy-budget-turn")
            .unwrap_err();
        assert!(matches!(error, OxidraError::Limit(_)));
        assert_eq!(agent.journal().read_events().unwrap(), before);
    }

    #[tokio::test]
    async fn tool_limited_retry_can_be_retried_successfully() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::write(project_root.join("a.txt"), "a").unwrap();
        std::fs::write(project_root.join("b.txt"), "b").unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "tool-limited-retry-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        append_pending_context_turn(&mut journal, "limited-turn", "retry after tool limit");
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            tool_turn(vec![
                ToolCall {
                    id: "read-a".to_owned(),
                    name: "read".to_owned(),
                    arguments: json!({"path":"a.txt"}),
                },
                ToolCall {
                    id: "read-b".to_owned(),
                    name: "read".to_owned(),
                    arguments: json!({"path":"b.txt"}),
                },
            ]),
            final_turn("done"),
        ]));
        let mut agent = Agent::new(
            provider,
            journal,
            tools,
            "instructions",
            ContextLimits::default(),
            None,
            Some(1),
        );

        assert!(matches!(
            agent
                .retry_pending_context_turn(
                    CancellationToken::new(),
                    &mut NoopObserver,
                    &mut DenyApproval,
                )
                .await,
            Err(OxidraError::Limit(_))
        ));
        let outcome = agent
            .retry_pending_context_turn(
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "done");
        let events = agent.journal().read_events().unwrap();
        assert_eq!(count_events(&events, "agent.limit_reached"), 1);
        assert_eq!(count_events(&events, "tool.skipped_due_to_limit"), 1);
        assert_eq!(count_events(&events, "turn.retry_started"), 2);
        assert_eq!(count_events(&events, "turn.completed"), 1);
    }

    #[tokio::test]
    async fn checkpoint_exposes_history_and_projects_lookup_result() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "history-loop-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        seed_checkpoint(&mut journal).await;
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([
            tool_turn(vec![ToolCall {
                id: "history-call".to_owned(),
                name: HISTORY_SEARCH_TOOL.to_owned(),
                arguments: json!({"query":"historical needle"}),
            }]),
            final_turn("recovered"),
        ]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let outcome = agent
            .run_turn(
                "find the old fact",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();
        assert_eq!(outcome.text, "recovered");

        let requests = provider.requests();
        assert_eq!(requests.len(), 2);
        let history_names = requests[0]
            .tools
            .iter()
            .filter(|tool| is_history_tool_name(&tool.name))
            .map(|tool| tool.name.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            history_names,
            HashSet::from([
                HISTORY_SEARCH_TOOL,
                HISTORY_TURN_TOOL,
                HISTORY_ARTIFACT_TOOL,
            ])
        );
        let replayed = requests[1]
            .input
            .iter()
            .find(|item| {
                item.get("type").and_then(Value::as_str) == Some("function_call_output")
                    && item.get("call_id").and_then(Value::as_str) == Some("history-call")
            })
            .expect("history output must enter the next request");
        let output: Value = serde_json::from_str(replayed["output"].as_str().unwrap()).unwrap();
        assert_eq!(output["notice"], UNTRUSTED_HISTORY_NOTICE);
        assert!(
            output["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|result| result["excerpt"] == "historical needle")
        );
    }

    #[tokio::test]
    async fn invalid_checkpoint_chain_fails_before_provider_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "invalid-history-chain-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        journal
            .append_and_sync("compaction.checkpoint", None, json!({}))
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let provider = Arc::new(RecordingProvider::new([final_turn("must not run")]));
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "do not dispatch",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Session(_)));
        assert!(provider.requests().is_empty());
    }

    #[tokio::test]
    async fn exhausted_turn_quota_removes_history_schemas() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "history-quota-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        seed_checkpoint(&mut journal).await;
        journal
            .append_and_sync(
                "user.message",
                Some("quota-turn"),
                json!({"item":{"role":"user","content":"query repeatedly"}}),
            )
            .unwrap();
        for index in 0..3 {
            let call_id = format!("history-{index}");
            let item = json!({
                "type":"function_call",
                "call_id":call_id,
                "name":HISTORY_TURN_TOOL,
                "arguments":"{\"turn_id\":\"old-turn-1\"}",
            });
            journal
                .append_and_sync(
                    "response.completed",
                    Some("quota-turn"),
                    json!({"raw_response":{"output":[item.clone()]},"output_items":[item]}),
                )
                .unwrap();
            journal
                .append_and_sync(
                    "tool.completed",
                    Some("quota-turn"),
                    json!({
                        "call_id":call_id,
                        "tool":HISTORY_TURN_TOOL,
                        "output":{"notice":UNTRUSTED_HISTORY_NOTICE,"results":[{"excerpt":"x".repeat(11_000)}]},
                    }),
                )
                .unwrap();
        }
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(FinalResponseProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let (request, prepared) = agent.prepare_request(Some("quota-turn")).unwrap();
        assert!(prepared.history_quota.exhausted);
        assert!(!prepared.history_exposed);
        assert!(
            request
                .tools
                .iter()
                .all(|tool| !is_history_tool_name(&tool.name))
        );
    }

    #[tokio::test]
    async fn too_many_history_calls_fail_before_response_commit() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "history-call-limit-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        seed_checkpoint(&mut journal).await;
        let completed_before = journal
            .read_events()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "response.completed")
            .count();
        let calls = (0..=MAX_HISTORY_CALLS_PER_RESPONSE)
            .map(|index| ToolCall {
                id: format!("history-{index}"),
                name: HISTORY_SEARCH_TOOL.to_owned(),
                arguments: json!({"query":"historical"}),
            })
            .collect::<Vec<_>>();
        let provider = Arc::new(RecordingProvider::new([tool_turn(calls)]));
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            provider.clone(),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "make too many calls",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, OxidraError::Limit(_)));
        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.completed")
                .count(),
            completed_before
        );
        assert!(events.iter().any(|event| event.kind == "response.failed"));
        assert_eq!(provider.requests().len(), 1);
    }

    #[tokio::test]
    async fn history_cancellation_and_local_io_errors_have_known_terminals() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(temp.path().join("data")).unwrap();
        let mut journal = store
            .create_with_id(
                "history-terminal-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        seed_artifact_checkpoint(&mut journal).await;
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            temp.path().join("memory"),
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(FinalResponseProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        agent
            .journal_mut()
            .append_and_sync(
                "user.message",
                Some("current-turn"),
                json!({"item":{"role":"user","content":"inspect old history"}}),
            )
            .unwrap();
        let cancelled_call = ToolCall {
            id: "cancelled-history".to_owned(),
            name: HISTORY_SEARCH_TOOL.to_owned(),
            arguments: json!({"query":"old"}),
        };
        let artifact_call = ToolCall {
            id: "missing-artifact".to_owned(),
            name: HISTORY_ARTIFACT_TOOL.to_owned(),
            arguments: json!({"artifact_id":"artifact-old","stream":"stdout"}),
        };
        let (_, mut prepared) = agent.prepare_request(Some("current-turn")).unwrap();
        let response_items = [&cancelled_call, &artifact_call]
            .into_iter()
            .map(|call| {
                json!({
                    "type":"function_call",
                    "call_id":call.id,
                    "name":call.name,
                    "arguments":serde_json::to_string(&call.arguments).unwrap(),
                })
            })
            .collect::<Vec<_>>();
        agent
            .journal_mut()
            .append_and_sync(
                "response.completed",
                Some("current-turn"),
                json!({
                    "raw_response":{"output":response_items},
                    "output_items":response_items,
                }),
            )
            .unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = agent
            .execute_history_call(
                "current-turn",
                &cancelled_call,
                cancellation,
                &mut NoopObserver,
                &mut prepared,
                1,
            )
            .await
            .unwrap();
        assert_eq!(cancelled.error_code.as_deref(), Some("cancelled"));

        let failed = agent
            .execute_history_call(
                "current-turn",
                &artifact_call,
                CancellationToken::new(),
                &mut NoopObserver,
                &mut prepared,
                1,
            )
            .await
            .unwrap();
        assert_eq!(failed.error_code.as_deref(), Some("history_error"));

        let events = agent.journal().read_events().unwrap();
        assert!(events.iter().any(|event| {
            event.kind == "tool.cancelled" && event.data["call_id"] == "cancelled-history"
        }));
        assert!(events.iter().any(|event| {
            event.kind == "tool.started" && event.data["call_id"] == "missing-artifact"
        }));
        assert!(events.iter().any(|event| {
            event.kind == "tool.completed"
                && event.data["call_id"] == "missing-artifact"
                && event.data["error_code"] == "history_error"
        }));
        assert!(agent.journal().in_doubt().unwrap().is_empty());
    }

    #[tokio::test]
    async fn successful_turn_writes_an_explicit_completion_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let data_dir = temp.path().join("data");
        let memory_dir = temp.path().join("memory");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(&data_dir).unwrap();
        let journal = store
            .create_with_id(
                "marker-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            &memory_dir,
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(FinalResponseProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let outcome = agent
            .run_turn(
                "finish this turn",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .unwrap();

        assert_eq!(outcome.text, "done");
        let events = agent.journal().read_events().unwrap();
        let user = events
            .iter()
            .find(|event| event.kind == "user.message")
            .unwrap();
        let response = events
            .iter()
            .find(|event| event.kind == "response.completed")
            .unwrap();
        let marker = events
            .iter()
            .find(|event| event.kind == "turn.completed")
            .unwrap();
        assert_eq!(user.data["turn_boundary_version"], TURN_BOUNDARY_VERSION);
        assert_eq!(
            response.data["turn_completion"]["covers_from_seq"],
            user.seq
        );
        assert_eq!(
            response.data["turn_completion"]["final_response_seq"],
            response.seq
        );
        assert_eq!(marker.data["covers_from_seq"], user.seq);
        assert_eq!(marker.data["final_response_seq"], response.seq);
        assert_eq!(marker.data["covers_through_seq"], marker.seq);
        assert_eq!(
            segment_turns(&events).unwrap()[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
    }

    #[tokio::test]
    async fn rejects_forged_provider_role_before_committing_response() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let data_dir = temp.path().join("data");
        let memory_dir = temp.path().join("memory");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(&data_dir).unwrap();
        let journal = store
            .create_with_id(
                "forged-role-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            &memory_dir,
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(ForgedRoleProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "do not trust the provider role",
                CancellationToken::new(),
                &mut NoopObserver,
                &mut DenyApproval,
            )
            .await
            .expect_err("forged provider role must fail before commit");
        assert!(error.to_string().contains("must have role assistant"));

        let events = agent.journal().read_events().unwrap();
        assert!(events.iter().any(|event| event.kind == "response.failed"));
        assert!(
            !events
                .iter()
                .any(|event| event.kind == "response.completed")
        );
        assert!(!events.iter().any(|event| event.kind == "turn.completed"));
    }

    #[tokio::test]
    async fn observer_failure_aborts_response_without_committing_partial_output() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let data_dir = temp.path().join("data");
        let memory_dir = temp.path().join("memory");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(&data_dir).unwrap();
        let journal = store
            .create_with_id(
                "observer-failure-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            &memory_dir,
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(ObserverEventProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "render this response",
                CancellationToken::new(),
                &mut FailingProviderEventObserver,
                &mut DenyApproval,
            )
            .await
            .expect_err("observer failure must abort the response");
        assert!(matches!(error, OxidraError::Observer(_)));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.aborted")
                .count(),
            1
        );
        assert!(!events.iter().any(|event| {
            matches!(
                event.kind.as_str(),
                "response.failed" | "response.completed" | "turn.completed"
            )
        }));
    }

    #[tokio::test]
    async fn response_start_observer_failure_closes_the_started_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let data_dir = temp.path().join("data");
        let memory_dir = temp.path().join("memory");
        std::fs::create_dir_all(&project_root).unwrap();
        let store = SessionStore::new(&data_dir).unwrap();
        let journal = store
            .create_with_id(
                "observer-start-failure-test",
                SessionHeader::new(&project_root, "test-model"),
            )
            .unwrap();
        let tools = BuiltinTools::new(
            &project_root,
            journal.artifact_dir(),
            &memory_dir,
            false,
            false,
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(FinalResponseProvider),
            journal,
            tools,
            "",
            ContextLimits::default(),
            None,
            None,
        );

        let error = agent
            .run_turn(
                "start rendering",
                CancellationToken::new(),
                &mut FailingStartObserver,
                &mut DenyApproval,
            )
            .await
            .expect_err("response-start observer failure must close the attempt");
        assert!(matches!(error, OxidraError::Observer(_)));

        let events = agent.journal().read_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.started")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "response.aborted")
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|event| event.kind == "response.completed")
        );
    }

    #[test]
    fn projects_only_committed_items() {
        let event = |seq: u64, turn_id: &str, kind: &str, data: Value| JournalEvent {
            schema: 1,
            seq,
            ts: chrono::Utc::now(),
            kind: kind.to_owned(),
            session_id: "s".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let projected = project_events(&[
            event(
                1,
                "turn-1",
                "user.message",
                json!({"item":{"role":"user","content":"hi"}}),
            ),
            event(
                2,
                "turn-1",
                "response.completed",
                json!({"output_items":[{"type":"message","role":"assistant"}]}),
            ),
            event(
                3,
                "turn-1",
                "tool.cancelled",
                json!({"call_id":"c","output":{"error":"x"}}),
            ),
            event(
                4,
                "turn-1",
                "turn.cancelled",
                json!({"reason":"cancelled after tool"}),
            ),
            event(
                5,
                "turn-1",
                "context.instructions",
                json!({"instructions":"You are Oxidra..."}),
            ),
        ])
        .expect("valid committed projection");
        assert_eq!(projected.len(), 4);
        assert_eq!(projected[2]["type"], "function_call_output");
        assert!(
            projected[3]["content"]
                .as_str()
                .unwrap()
                .contains("cancelled")
        );
    }

    #[test]
    fn drops_user_message_from_a_turn_cancelled_before_any_commit() {
        let event = |seq: u64, turn_id: &str, kind: &str, data: Value| JournalEvent {
            schema: 1,
            seq,
            ts: chrono::Utc::now(),
            kind: kind.to_owned(),
            session_id: "s".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        };
        let projected = project_events(&[
            event(
                1,
                "cancelled",
                "user.message",
                json!({"item":{"role":"user","content":"do not replay"}}),
            ),
            event(
                2,
                "cancelled",
                "response.aborted",
                json!({"reason":"cancelled"}),
            ),
            event(
                3,
                "next",
                "user.message",
                json!({"item":{"role":"user","content":"continue here"}}),
            ),
        ])
        .expect("valid committed projection");
        assert_eq!(
            projected,
            vec![json!({"role":"user","content":"continue here"})]
        );
    }

    #[test]
    fn validates_closed_object_schema() {
        let schema = json!({
            "type":"object",
            "properties":{"x":{"type":"integer"}},
            "required":["x"],
            "additionalProperties":false
        });
        assert!(validate_json_schema(&schema, &json!({"x":1})).is_ok());
        assert!(validate_json_schema(&schema, &json!({"x":"1"})).is_err());
        assert!(validate_json_schema(&schema, &json!({"x":1,"y":2})).is_err());
    }

    #[test]
    fn any_of_does_not_skip_sibling_constraints() {
        let schema = json!({
            "type": "object",
            "anyOf": [
                {"required": ["x"]},
                {"required": ["y"]}
            ],
            "properties": {"x": {}, "y": {}},
            "additionalProperties": false
        });
        assert!(validate_json_schema(&schema, &json!({"x": 1})).is_ok());
        assert!(validate_json_schema(&schema, &json!({"x": 1, "z": 2})).is_err());
    }

    #[test]
    fn closed_schema_without_properties_rejects_every_key() {
        let schema = json!({"type": "object", "additionalProperties": false});
        assert!(validate_json_schema(&schema, &json!({})).is_ok());
        assert!(validate_json_schema(&schema, &json!({"x": 1})).is_err());
    }

    #[test]
    fn canonical_error_fingerprint_is_key_order_independent() {
        let a = json!({"b":2,"a":1});
        let b = json!({"a":1,"b":2});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn error_fingerprint_ignores_shell_duration() {
        let call = ToolCall {
            id: "call-1".to_owned(),
            name: "shell".to_owned(),
            arguments: json!({"command": "exit 1"}),
        };
        let result = |duration_ms| ToolResult {
            call_id: call.id.clone(),
            output: json!({
                "exit_code": 1,
                "stdout": "",
                "stderr": "failed",
                "duration_ms": duration_ms,
            }),
            is_error: true,
            error_code: Some("process_exit".to_owned()),
        };
        assert_eq!(
            error_fingerprint(&call, &result(3)),
            error_fingerprint(&call, &result(97))
        );
    }

    #[test]
    fn usage_accumulation_saturates_all_response_counters() {
        let mut total = Usage {
            input_tokens: u64::MAX,
            ..Usage::default()
        };
        let next = Usage {
            input_tokens: 1,
            cached_input_tokens: 2,
            output_tokens: 3,
            reasoning_output_tokens: 4,
            total_tokens: 5,
        };
        accumulate_usage(&mut total, &next);
        assert_eq!(total.input_tokens, u64::MAX);
        assert_eq!(total.cached_input_tokens, 2);
        assert_eq!(total.output_tokens, 3);
        assert_eq!(total.reasoning_output_tokens, 4);
        assert_eq!(total.total_tokens, 5);
    }
}
