//! The provider/tool/session orchestration layer.
//!
//! `Agent` is intentionally small: it owns one session journal and runs one
//! user turn at a time.  UI, approval prompts, and provider implementations
//! are supplied through traits so the core remains usable from tests and a
//! future TUI.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::compaction::validate_checkpoint_chain;
use crate::config::ContextLimits;
use crate::context::{
    ContextDecision, ContextRuntime, decide_context, measure_prepared_request, snapshot_tools,
};
use crate::error::{OxidraError, Result};
use crate::history::{
    HISTORY_ARTIFACT_TOOL, HISTORY_CONTROL_OUTPUT_RESERVE_BYTES, HISTORY_SEARCH_TOOL,
    HISTORY_TURN_TOOL, HistoryQuota, HistorySearchRequest, HistorySnapshot, HistoryTurnRequest,
    MAX_HISTORY_CALLS_PER_RESPONSE, MAX_HISTORY_TOOL_OUTPUT_BYTES, MAX_HISTORY_TURN_OUTPUT_BYTES,
    history_tool_definitions, is_history_tool_name, rebuild_history_quota,
    serialized_history_tool_output_bytes,
};
use crate::history_artifact::{HistoryArtifactReader, HistoryArtifactRequest};
pub use crate::projection::project_events;
use crate::projection::{project_checkpoint_and_tail, validate_response_output_items};
use crate::provider::{ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver};
use crate::session::SessionJournal;
use crate::tools::{BuiltinTools, ToolContext};
use crate::turn::{TURN_BOUNDARY_VERSION, validate_turn_recovery};
use crate::types::{ToolCall, ToolDefinition, ToolResult, Usage};

const MAX_PROJECT_INSTRUCTIONS: usize = 32 * 1024;

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

pub struct Agent {
    provider: Arc<dyn ResponseProvider>,
    journal: SessionJournal,
    tools: BuiltinTools,
    instructions: String,
    context_runtime: ContextRuntime,
    tools_epoch: Option<(String, u64)>,
    max_responses: Option<usize>,
    max_tools: Option<usize>,
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
        }
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
        let pending = self.pending_context_turns()?;
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
        let mut outcome = TurnOutcome::default();
        let mut repeated_error: Option<(String, usize)> = None;

        loop {
            if cancellation.is_cancelled() {
                self.append_turn_cancelled(turn_id, "cancelled before response started")?;
                return Err(OxidraError::Interrupted);
            }
            if self
                .max_responses
                .is_some_and(|limit| outcome.responses >= limit)
            {
                self.journal.append_and_sync(
                    "agent.limit_reached",
                    Some(turn_id),
                    json!({ "kind": "responses", "limit": self.max_responses }),
                )?;
                return Err(OxidraError::Limit("max responses reached".to_owned()));
            }

            let (request, mut prepared_tools) = self.prepare_request(Some(turn_id))?;
            let context = self.context_estimate(&prepared_tools.context);
            outcome.context = Some(context.clone());
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

    /// 持久化 retry intent 后在原 turn 上继续，崩溃恢复不会重复追加 prompt。
    pub async fn retry_pending_context_turn(
        &mut self,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<TurnOutcome> {
        let events = self.journal.read_events()?;
        let pending = pending_context_turns(&events)?;
        let retry = pending.last().ok_or_else(|| {
            OxidraError::Config("session has no pending context-limited turn".to_owned())
        })?;
        if pending.len() != 1 {
            return Err(OxidraError::ApprovalRequired(format!(
                "session has {} pending context-limited turns; abandon the legacy backlog before retrying",
                pending.len()
            )));
        }
        let recovery = validate_turn_recovery(&events)?;
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
                        )
                })
            });
        if !has_current_intent {
            self.journal.append_and_sync(
                "turn.retry_started",
                Some(&retry.turn_id),
                json!({
                    "retry_version": 1,
                    "retry_id": Uuid::now_v7().to_string(),
                    "user_message_seq": retry.user_message_seq,
                    "context_limit_seq": retry.context_limit_seq,
                }),
            )?;
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

    fn prepare_request(
        &mut self,
        turn_id: Option<&str>,
    ) -> Result<(ResponseRequest, PreparedToolSet)> {
        let events = self.journal.read_events()?;
        let chain = validate_checkpoint_chain(&events)?;
        let checkpoint_id = chain
            .latest()
            .map(|checkpoint| checkpoint.checkpoint_id.clone());
        let checkpoint_covers_through_seq = chain
            .latest()
            .map(|checkpoint| checkpoint.covers_through_seq);
        let input = if chain.latest().is_some() {
            project_checkpoint_and_tail(&events, &chain)?
        } else {
            project_events(&events)?
        };
        let history = HistorySnapshot::build(&events, &chain)?;
        let history_quota = match turn_id {
            Some(turn_id) => rebuild_history_quota(&events, turn_id)?,
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
        let measurement = measure_prepared_request(&request, &self.context_runtime)?;
        let tool_snapshot = snapshot_tools(&definitions)?;
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
            &events,
            &self.context_runtime,
            measurement,
            events.last().map(|event| event.seq),
            checkpoint_id,
            checkpoint_covers_through_seq,
            instructions_event_seq,
            configured_event_seq,
            tools_event_seq,
        )?;
        Ok((
            request,
            PreparedToolSet {
                definitions,
                history,
                history_quota,
                history_exposed,
                context,
            },
        ))
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
    let resolved_turns = events
        .iter()
        .filter(|event| {
            event.kind == "turn.completed" || event.data.get("turn_completion").is_some()
        })
        .filter_map(|event| event.turn_id.clone())
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

struct ForwardObserver<'a> {
    observer: &'a mut dyn AgentObserver,
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
        CandidateEstimate, CompactionContext, CompactionSelection, compact_once,
        select_compaction_candidate,
    };
    use crate::config::ContextValueSource;
    use crate::history::UNTRUSTED_HISTORY_NOTICE;
    use crate::session::{JournalEvent, SessionHeader, SessionStore};
    use crate::turn::{CompletionEvidence, TurnState, segment_turns};
    use crate::types::AssistantTurn;

    struct FinalResponseProvider;

    struct ForgedRoleProvider;

    struct ObserverEventProvider;

    struct RecordingProvider {
        responses: Mutex<VecDeque<AssistantTurn>>,
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

    fn append_complete_turn(
        journal: &mut SessionJournal,
        turn_id: &str,
        question: &str,
        answer: &str,
    ) -> u64 {
        let user = journal
            .append_and_sync(
                "user.message",
                Some(turn_id),
                json!({
                    "item":{"role":"user","content":question},
                    "turn_boundary_version":TURN_BOUNDARY_VERSION,
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
