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

use crate::config::ContextLimits;
use crate::error::{OxidraError, Result};
use crate::provider::{ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver};
use crate::session::{JournalEvent, SessionJournal};
use crate::tools::{BuiltinTools, ToolContext};
use crate::types::{ToolCall, ToolResult, Usage};

const MAX_PROJECT_INSTRUCTIONS: usize = 32 * 1024;

/// Events emitted to the UI.  Streaming provider events are forwarded through
/// [`on_provider_event`]; tool lifecycle events are committed before/after the
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

pub struct Agent {
    provider: Arc<dyn ResponseProvider>,
    journal: SessionJournal,
    tools: BuiltinTools,
    instructions: String,
    context_limits: ContextLimits,
    max_responses: Option<usize>,
    max_tools: Option<usize>,
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
        Self {
            provider,
            journal,
            tools,
            instructions: instructions.into(),
            context_limits,
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
        let turn_id = Uuid::now_v7().to_string();
        let user_item = json!({
            "role": "user",
            "content": prompt,
        });
        self.journal.append_and_sync(
            "user.message",
            Some(&turn_id),
            json!({ "item": user_item }),
        )?;

        let mut outcome = TurnOutcome::default();
        let mut repeated_error: Option<(String, usize)> = None;

        loop {
            if cancellation.is_cancelled() {
                self.append_turn_cancelled(&turn_id, "cancelled before response started")?;
                return Err(OxidraError::Interrupted);
            }
            if self
                .max_responses
                .is_some_and(|limit| outcome.responses >= limit)
            {
                self.journal.append_and_sync(
                    "agent.limit_reached",
                    Some(&turn_id),
                    json!({ "kind": "responses", "limit": self.max_responses }),
                )?;
                return Err(OxidraError::Limit("max responses reached".to_owned()));
            }

            let input = self.project_input()?;
            let request = ResponseRequest {
                instructions: (!self.instructions.is_empty()).then(|| self.instructions.clone()),
                input,
                tools: self.tools.definitions(),
                model: None,
            };
            let context = self.estimate_context(&request)?;
            outcome.context = Some(context.clone());
            if let Err(error) = self.check_context(&context) {
                self.journal.append_and_sync(
                    "context.limit_reached",
                    Some(&turn_id),
                    json!({ "error": error.to_string() }),
                )?;
                return Err(error);
            }
            let response_attempt_id = Uuid::now_v7().to_string();
            self.journal.append_and_sync(
                "response.started",
                Some(&turn_id),
                json!({
                    "response_attempt_id": response_attempt_id,
                    "response_index": outcome.responses + 1,
                }),
            )?;
            observer.on_response_started()?;
            let response = {
                let mut forward = ForwardObserver { observer };
                self.provider
                    .respond(request, &mut forward, cancellation.clone())
                    .await
            };

            let turn = match response {
                Ok(turn) => turn,
                Err(OxidraError::Interrupted) => {
                    self.append_response_aborted(&turn_id, &response_attempt_id, "cancelled")?;
                    return Err(OxidraError::Interrupted);
                }
                Err(OxidraError::ResponseAborted(reason)) => {
                    self.append_response_aborted(&turn_id, &response_attempt_id, &reason)?;
                    return Err(OxidraError::ResponseAborted(reason));
                }
                Err(error) => {
                    self.journal.append_and_sync(
                        "response.failed",
                        Some(&turn_id),
                        json!({
                            "response_attempt_id": response_attempt_id,
                            "error": error.to_string(),
                        }),
                    )?;
                    return Err(error);
                }
            };

            outcome.responses += 1;
            accumulate_usage(&mut outcome.usage, &turn.usage);
            self.journal.append_and_sync(
                "response.completed",
                Some(&turn_id),
                json!({
                    "response_attempt_id": response_attempt_id,
                    "raw_response": turn.raw_response,
                    "output_items": turn.output_items,
                    "text": turn.text,
                    "usage": turn.usage,
                    "unknown_stream_events": turn.unknown_stream_events,
                }),
            )?;
            if turn.tool_calls.is_empty() {
                outcome.text = turn.text;
                outcome.context = Some(self.next_context_estimate()?);
                return Ok(outcome);
            }

            for (index, call) in turn.tool_calls.iter().enumerate() {
                if self.max_tools.is_some_and(|limit| outcome.tools >= limit) {
                    self.mark_remaining_skipped(&turn_id, &turn.tool_calls[index..], "tool limit")?;
                    self.journal.append_and_sync(
                        "agent.limit_reached",
                        Some(&turn_id),
                        json!({ "kind": "tools", "limit": self.max_tools }),
                    )?;
                    return Err(OxidraError::Limit("max tools reached".to_owned()));
                }
                if cancellation.is_cancelled() {
                    self.mark_remaining_skipped(&turn_id, &turn.tool_calls[index..], "cancelled")?;
                    self.append_turn_cancelled(&turn_id, "cancelled before tool dispatch")?;
                    return Err(OxidraError::Interrupted);
                }

                let result = self
                    .execute_call(&turn_id, call, cancellation.clone(), observer, approval)
                    .await?;
                outcome.tools += 1;

                if result.error_code.as_deref() == Some("in_doubt") {
                    self.mark_remaining_skipped(
                        &turn_id,
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
                            &turn_id,
                            &turn.tool_calls[index + 1..],
                            "stalled",
                        )?;
                        observer.on_message("相同工具调用连续失败 3 次，已暂停以避免无效循环")?;
                        self.journal.append_and_sync(
                            "agent.stalled",
                            Some(&turn_id),
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
                        &turn_id,
                        &turn.tool_calls[index + 1..],
                        "cancelled",
                    )?;
                    self.append_turn_cancelled(&turn_id, "cancelled during tool execution")?;
                    return Err(OxidraError::Interrupted);
                }
            }
        }
    }

    async fn execute_call(
        &mut self,
        turn_id: &str,
        call: &ToolCall,
        cancellation: CancellationToken,
        observer: &mut dyn AgentObserver,
        approval: &mut dyn ApprovalHandler,
    ) -> Result<ToolResult> {
        let definitions = self.tools.definitions();
        let definition = definitions
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

        // Authorization is a decision point, not tool execution.  Record
        // `tool.started` only after approval succeeds so a crash while the
        // prompt is waiting cannot turn an unexecuted shell command into an
        // in-doubt side effect.
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

        let context = ToolContext::new(cancellation.clone()).with_shell_approval(shell_approved);
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

    fn project_input(&self) -> Result<Vec<Value>> {
        let events = self.journal.read_events()?;
        Ok(project_events(&events))
    }

    fn estimate_context(&self, request: &ResponseRequest) -> Result<ContextEstimate> {
        let input = serde_json::to_string(&request.input)?;
        let tools = serde_json::to_string(&request.tools)?;
        let instructions = request.instructions.as_deref().unwrap_or_default();
        let estimated_tokens = estimate_tokens(&input)
            .saturating_add(estimate_tokens(&tools))
            .saturating_add(estimate_tokens(instructions))
            .saturating_add(256);
        Ok(ContextEstimate {
            estimated_tokens,
            context_window: self.context_limits.context_window,
            reserve_tokens: self.context_limits.reserve_tokens,
        })
    }

    fn check_context(&self, context: &ContextEstimate) -> Result<()> {
        let Some(window) = context.context_window else {
            return Ok(());
        };
        if context
            .estimated_tokens
            .saturating_add(context.reserve_tokens)
            >= window
        {
            return Err(OxidraError::ContextLimit);
        }
        Ok(())
    }

    fn next_context_estimate(&self) -> Result<ContextEstimate> {
        let request = ResponseRequest {
            instructions: (!self.instructions.is_empty()).then(|| self.instructions.clone()),
            input: self.project_input()?,
            tools: self.tools.definitions(),
            model: None,
        };
        self.estimate_context(&request)
    }
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

fn estimate_tokens(text: &str) -> u64 {
    let mut ascii = 0_u64;
    let mut non_ascii = 0_u64;
    for character in text.chars() {
        if character.is_ascii() {
            ascii += 1;
        } else {
            non_ascii += 1;
        }
    }
    ascii.div_ceil(4).saturating_add(non_ascii)
}

struct ForwardObserver<'a> {
    observer: &'a mut dyn AgentObserver,
}

impl StreamObserver for ForwardObserver<'_> {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
        self.observer.on_provider_event(event)
    }
}

/// Project only committed events into the stateless Responses `input` array.
/// Partial deltas and aborted responses are intentionally absent.
pub fn project_events(events: &[JournalEvent]) -> Vec<Value> {
    let completed_turns = events
        .iter()
        .filter(|event| event.kind == "response.completed")
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();
    let abandoned_turns = events
        .iter()
        .filter(|event| matches!(event.kind.as_str(), "response.aborted" | "turn.cancelled"))
        .filter_map(|event| event.turn_id.clone())
        .filter(|turn_id| !completed_turns.contains(turn_id))
        .collect::<HashSet<_>>();
    let mut projected = Vec::new();
    let mut marked_cancelled_turns = HashSet::new();
    for event in events {
        match event.kind.as_str() {
            "user.message" => {
                let abandoned = event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| abandoned_turns.contains(turn_id));
                if !abandoned {
                    if let Some(item) = event.data.get("item") {
                        projected.push(item.clone());
                    }
                }
            }
            "response.completed" => {
                if let Some(items) = event.data.get("output_items").and_then(Value::as_array) {
                    projected.extend(items.iter().cloned());
                } else if let Some(items) = event
                    .data
                    .get("raw_response")
                    .and_then(|response| response.get("output"))
                    .and_then(Value::as_array)
                {
                    projected.extend(items.iter().cloned());
                }
            }
            "tool.completed"
            | "tool.cancelled"
            | "tool.skipped_due_to_cancel"
            | "tool.skipped_due_to_in_doubt"
            | "tool.skipped_due_to_limit"
            | "tool.skipped_due_to_stalled"
            | "tool.skipped_due_to_recovery" => {
                if let Some(item) = tool_output_item(&event.data) {
                    projected.push(item);
                }
            }
            // A user may explicitly resolve an in-doubt tool as failed.  It
            // then becomes a normal function output for future replay.
            "tool.in_doubt_resolved" => {
                if let Some(item) = tool_output_item(&event.data) {
                    projected.push(item);
                }
            }
            "response.aborted" | "turn.cancelled" => {
                if let Some(turn_id) = &event.turn_id {
                    if completed_turns.contains(turn_id)
                        && marked_cancelled_turns.insert(turn_id.clone())
                    {
                        projected.push(json!({
                            "role": "user",
                            "content": "[Oxidra: the previous turn was cancelled. Do not continue unfinished work from it unless the user requests it again.]",
                        }));
                    }
                }
            }
            _ => {}
        }
    }
    projected
}

fn tool_output_item(data: &Value) -> Option<Value> {
    let call_id = data.get("call_id")?.as_str()?;
    let output = data.get("output").cloned().unwrap_or_else(|| {
        json!({
            "error": {
                "code": data.get("error_code").and_then(Value::as_str).unwrap_or("cancelled"),
                "message": "tool did not complete normally",
            }
        })
    });
    let output = match output {
        Value::String(output) => output,
        output => serde_json::to_string(&output)
            .unwrap_or_else(|_| "{\"error\":{\"code\":\"serialization_error\"}}".to_owned()),
    };
    Some(json!({
        "type": "function_call_output",
        "call_id": call_id,
        "output": output,
    }))
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
    use super::*;

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
                json!({"output_items":[{"type":"message"}]}),
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
        ]);
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
        ]);
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
