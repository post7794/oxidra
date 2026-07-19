//! OpenAI Responses API transport.
//!
//! The provider deliberately knows nothing about the agent loop.  It turns a
//! streamed response into one committed [`AssistantTurn`] and exposes only
//! display/diagnostic events while the stream is in flight.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use reqwest::{Client, StatusCode};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::config::ProviderConfig;
use crate::error::{OxidraError, Result};
use crate::types::{AssistantTurn, ToolCall, ToolDefinition, Usage};

const MAX_ATTEMPTS: usize = 3;
const MAX_ERROR_BODY: usize = 64 * 1024;
const MAX_RESPONSE_EVENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESPONSE_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;

/// A complete stateless Responses request.
#[derive(Clone, Debug)]
pub struct ResponseRequest {
    pub instructions: Option<String>,
    /// Raw Responses input items.  Keeping these as JSON values lets the
    /// journal replay unknown/future item fields without a lossy projection.
    pub input: Vec<Value>,
    pub tools: Vec<ToolDefinition>,
    pub model: Option<String>,
}

impl ResponseRequest {
    pub fn new(input: Vec<Value>, tools: Vec<ToolDefinition>) -> Self {
        Self {
            instructions: None,
            input,
            tools,
            model: None,
        }
    }
}

/// Events intended for the UI/diagnostic stream.  They are not canonical
/// session history; only the final `response.completed` payload is committed.
#[derive(Clone, Debug)]
pub enum ProviderEvent {
    TextDelta(String),
    FunctionArgumentsDelta {
        item_id: Option<String>,
        call_id: Option<String>,
        delta: String,
    },
    Retry {
        attempt: usize,
        delay: Duration,
        reason: String,
    },
    Unknown {
        event_type: String,
        payload: Value,
    },
}

/// Sink used by a CLI (or a test) to render streaming output.
pub trait StreamObserver: Send {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()>;
}

/// A provider implementation can be substituted by a fake in integration
/// tests without changing the agent loop.
#[async_trait]
pub trait ResponseProvider: Send + Sync {
    async fn respond(
        &self,
        request: ResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> Result<AssistantTurn>;
}

#[derive(Clone)]
pub struct OpenAiResponsesProvider {
    config: ProviderConfig,
    client: Client,
}

impl std::fmt::Debug for OpenAiResponsesProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesProvider")
            .field("api_base_url", &self.config.api_base_url)
            .field("model", &self.config.model)
            .finish_non_exhaustive()
    }
}

impl OpenAiResponsesProvider {
    pub fn new(config: ProviderConfig) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                OxidraError::Provider(format!("cannot create HTTP client: {error}"))
            })?;
        Ok(Self { config, client })
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    fn request_body(&self, request: &ResponseRequest) -> Value {
        let tools: Vec<Value> = request
            .tools
            .iter()
            .map(|tool| {
                json!({
                    "type": "function",
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                    // Do not force strict mode: existing project/plugin JSON
                    // schemas may contain constructs not accepted by strict
                    // structured outputs.  We validate before dispatch.
                    "strict": false,
                })
            })
            .collect();

        let mut body = Map::new();
        body.insert(
            "model".to_owned(),
            Value::String(
                request
                    .model
                    .clone()
                    .unwrap_or_else(|| self.config.model.clone()),
            ),
        );
        body.insert("input".to_owned(), Value::Array(request.input.clone()));
        body.insert("tools".to_owned(), Value::Array(tools));
        body.insert("stream".to_owned(), Value::Bool(true));
        body.insert("store".to_owned(), Value::Bool(false));
        // Required for stateless replay when reasoning output is present.
        body.insert("include".to_owned(), json!(["reasoning.encrypted_content"]));
        if let Some(instructions) = &request.instructions {
            body.insert(
                "instructions".to_owned(),
                Value::String(instructions.clone()),
            );
        }
        Value::Object(body)
    }

    async fn attempt(
        &self,
        request: &ResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: &CancellationToken,
    ) -> AttemptResult {
        let url = match self.config.responses_url() {
            Ok(url) => url,
            Err(error) => return AttemptResult::fatal(error),
        };
        let send = self
            .client
            .post(url)
            .bearer_auth(&self.config.api_key)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .json(&self.request_body(request))
            .send();
        let response = tokio::select! {
            _ = cancellation.cancelled() => return AttemptResult::cancelled(),
            result = send => match result {
                Ok(response) => response,
                Err(error) => return AttemptResult::transport(error.to_string(), false),
            },
        };

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_retry_after);
            let mut body_bytes = Vec::new();
            let mut body_truncated = false;
            let mut body_read_error = false;
            let mut body_stream = response.bytes_stream();
            loop {
                let next = tokio::select! {
                    _ = cancellation.cancelled() => return AttemptResult::cancelled(),
                    item = body_stream.next() => item,
                };
                let Some(chunk) = next else { break };
                let Ok(chunk) = chunk else {
                    body_read_error = true;
                    break;
                };
                let remaining = MAX_ERROR_BODY.saturating_sub(body_bytes.len());
                if chunk.len() > remaining {
                    body_bytes.extend_from_slice(&chunk[..remaining]);
                    body_truncated = true;
                    break;
                }
                body_bytes.extend_from_slice(&chunk);
                if body_bytes.len() == MAX_ERROR_BODY {
                    body_truncated = true;
                    break;
                }
            }
            let mut body = String::from_utf8_lossy(&body_bytes).into_owned();
            if body_truncated {
                body.push_str("...<truncated>");
            }
            if body_read_error {
                body.push_str("...<transport error while reading error body>");
            }
            let message = format_http_error(status, &body);
            return if retryable_status(status) {
                AttemptResult::retryable(message, retry_after)
            } else {
                AttemptResult::fatal(OxidraError::Provider(message))
            };
        }

        let mut stream = response.bytes_stream().eventsource();
        let mut state = StreamState::default();
        let mut saw_event = false;

        loop {
            let next = tokio::select! {
                _ = cancellation.cancelled() => return AttemptResult::cancelled(),
                item = stream.next() => item,
            };
            let Some(item) = next else {
                return if saw_event {
                    AttemptResult::transport(
                        "SSE stream ended before response.completed".to_owned(),
                        true,
                    )
                } else {
                    AttemptResult::retryable(
                        "SSE stream ended before the first event".to_owned(),
                        None,
                    )
                };
            };
            let event = match item {
                Ok(event) => event,
                Err(error) => {
                    return if saw_event {
                        AttemptResult::transport(
                            format!("SSE parse/transport error: {error}"),
                            true,
                        )
                    } else {
                        AttemptResult::retryable(
                            format!("SSE parse/transport error: {error}"),
                            None,
                        )
                    };
                }
            };
            // Keep the raw event payload available to diagnostics while using
            // the typed `event` field for routing.  Empty keep-alive frames are
            // harmless and do not count as a terminal event.
            if event.data.trim().is_empty() {
                continue;
            }
            saw_event = true;
            if event.data.len() > MAX_RESPONSE_EVENT_BYTES {
                return AttemptResult::fatal(OxidraError::Provider(format!(
                    "SSE event exceeds the {MAX_RESPONSE_EVENT_BYTES}-byte limit"
                )));
            }
            let payload: Value = match serde_json::from_str(&event.data) {
                Ok(value) => value,
                Err(error) => {
                    return AttemptResult::transport(
                        format!("invalid JSON in SSE event {}: {error}", event.event),
                        true,
                    );
                }
            };
            let event_type = payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or(event.event.as_str())
                .to_owned();

            match event_type.as_str() {
                "response.output_text.delta" => {
                    if let Some(delta) = payload.get("delta").and_then(Value::as_str) {
                        if state.text.len().saturating_add(delta.len()) > MAX_RESPONSE_TEXT_BYTES {
                            return AttemptResult::fatal(OxidraError::Provider(format!(
                                "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
                            )));
                        }
                        state.text.push_str(delta);
                        if let Err(error) =
                            observer.on_event(ProviderEvent::TextDelta(delta.to_owned()))
                        {
                            return AttemptResult::fatal(error);
                        }
                    }
                }
                "response.function_call_arguments.delta" => {
                    let delta = payload
                        .get("delta")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let item_id = string_field(&payload, "item_id");
                    let call_id = string_field(&payload, "call_id");
                    if let Some(key) = item_id.clone().or_else(|| call_id.clone()) {
                        let arguments = state.argument_deltas.entry(key).or_default();
                        if arguments.len().saturating_add(delta.len()) > MAX_RESPONSE_ARGUMENT_BYTES
                        {
                            return AttemptResult::fatal(OxidraError::Provider(format!(
                                "function-call arguments exceed the {MAX_RESPONSE_ARGUMENT_BYTES}-byte limit"
                            )));
                        }
                        arguments.push_str(&delta);
                    }
                    if let Err(error) = observer.on_event(ProviderEvent::FunctionArgumentsDelta {
                        item_id,
                        call_id,
                        delta,
                    }) {
                        return AttemptResult::fatal(error);
                    }
                }
                "response.function_call_arguments.done" => {
                    if let Some(arguments) = payload.get("arguments").and_then(Value::as_str) {
                        let key = string_field(&payload, "item_id")
                            .or_else(|| string_field(&payload, "call_id"));
                        if let Some(key) = key {
                            state
                                .argument_deltas
                                .entry(key)
                                .or_default()
                                .clone_from(&arguments.to_owned());
                        }
                    }
                }
                "response.output_item.done" => {
                    if let Some(item) = payload.get("item") {
                        state.output_items_by_index.insert(
                            payload
                                .get("output_index")
                                .and_then(Value::as_u64)
                                .unwrap_or(state.output_items_by_index.len() as u64),
                            item.clone(),
                        );
                    }
                }
                "response.output_item.added" => {
                    if let Some(item) = payload.get("item") {
                        state.output_items_by_index.insert(
                            payload
                                .get("output_index")
                                .and_then(Value::as_u64)
                                .unwrap_or(state.output_items_by_index.len() as u64),
                            item.clone(),
                        );
                    }
                }
                "response.completed" => {
                    let response = payload
                        .get("response")
                        .cloned()
                        .unwrap_or_else(|| payload.clone());
                    return match build_turn(response, &state) {
                        Ok(turn) => AttemptResult::completed(turn),
                        Err(error) => AttemptResult::fatal(error),
                    };
                }
                "response.failed" | "error" => {
                    return AttemptResult::fatal(OxidraError::Provider(extract_event_error(
                        &payload,
                    )));
                }
                // A response can finish with an explicit incomplete event in
                // newer API versions.  It is terminal but not replayable.
                "response.incomplete" => {
                    return AttemptResult::fatal(OxidraError::ResponseAborted(format!(
                        "response incomplete: {}",
                        payload
                    )));
                }
                "response.created"
                | "response.in_progress"
                | "response.content_part.added"
                | "response.content_part.done"
                | "response.output_text.done" => {}
                _ => {
                    state.unknown_events.push(payload.clone());
                    if let Err(error) = observer.on_event(ProviderEvent::Unknown {
                        event_type,
                        payload,
                    }) {
                        return AttemptResult::fatal(error);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ResponseProvider for OpenAiResponsesProvider {
    async fn respond(
        &self,
        request: ResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> Result<AssistantTurn> {
        let mut last_retry_reason = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.attempt(&request, observer, &cancellation).await {
                AttemptResult::Completed(turn) => return Ok(turn),
                AttemptResult::Cancelled => return Err(OxidraError::Interrupted),
                AttemptResult::Fatal(error) => return Err(error),
                AttemptResult::Transport { reason, saw_event } => {
                    if saw_event {
                        return Err(OxidraError::ResponseAborted(reason));
                    }
                    if attempt == MAX_ATTEMPTS {
                        return Err(OxidraError::Provider(reason));
                    }
                    last_retry_reason = Some(reason);
                    let delay = backoff(attempt);
                    observer.on_event(ProviderEvent::Retry {
                        attempt,
                        delay,
                        reason: last_retry_reason.clone().unwrap_or_default(),
                    })?;
                    tokio::select! {
                        _ = cancellation.cancelled() => return Err(OxidraError::Interrupted),
                        _ = tokio::time::sleep(delay) => {},
                    }
                }
                AttemptResult::Retryable {
                    reason,
                    retry_after,
                } => {
                    if attempt == MAX_ATTEMPTS {
                        return Err(OxidraError::Provider(reason));
                    }
                    last_retry_reason = Some(reason);
                    let delay = retry_after.unwrap_or_else(|| backoff(attempt));
                    observer.on_event(ProviderEvent::Retry {
                        attempt,
                        delay,
                        reason: last_retry_reason.clone().unwrap_or_default(),
                    })?;
                    tokio::select! {
                        _ = cancellation.cancelled() => return Err(OxidraError::Interrupted),
                        _ = tokio::time::sleep(delay) => {},
                    }
                }
            }
        }
        Err(OxidraError::Provider(
            last_retry_reason.unwrap_or_else(|| "provider failed".to_owned()),
        ))
    }
}

enum AttemptResult {
    Completed(AssistantTurn),
    Retryable {
        reason: String,
        retry_after: Option<Duration>,
    },
    Transport {
        reason: String,
        saw_event: bool,
    },
    Fatal(OxidraError),
    Cancelled,
}

impl AttemptResult {
    fn completed(turn: AssistantTurn) -> Self {
        Self::Completed(turn)
    }

    fn retryable(reason: String, retry_after: Option<Duration>) -> Self {
        Self::Retryable {
            reason,
            retry_after,
        }
    }

    fn transport(reason: String, saw_event: bool) -> Self {
        Self::Transport { reason, saw_event }
    }

    fn fatal(error: OxidraError) -> Self {
        Self::Fatal(error)
    }

    fn cancelled() -> Self {
        Self::Cancelled
    }
}

#[derive(Default)]
struct StreamState {
    text: String,
    argument_deltas: BTreeMap<String, String>,
    output_items_by_index: BTreeMap<u64, Value>,
    unknown_events: Vec<Value>,
}

fn build_turn(mut response: Value, stream_state: &StreamState) -> Result<AssistantTurn> {
    if serde_json::to_vec(&response)
        .map(|bytes| bytes.len() > MAX_RESPONSE_EVENT_BYTES)
        .unwrap_or(true)
    {
        return Err(OxidraError::Provider(format!(
            "completed response exceeds the {MAX_RESPONSE_EVENT_BYTES}-byte limit"
        )));
    }
    let mut output_items = response
        .get("output")
        .and_then(Value::as_array)
        .cloned()
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            stream_state
                .output_items_by_index
                .values()
                .cloned()
                .collect()
        });
    if output_items.is_empty() && stream_state.output_items_by_index.is_empty() {
        return Err(OxidraError::Provider(
            "response.completed has no output array".to_owned(),
        ));
    }

    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for item in &mut output_items {
        if item.get("type").and_then(Value::as_str) == Some("function_call") {
            let id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    OxidraError::Provider("function_call is missing call_id".to_owned())
                })?
                .to_owned();
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| OxidraError::Provider("function_call is missing name".to_owned()))?
                .to_owned();
            let arguments = match item.get("arguments") {
                Some(Value::String(arguments)) => {
                    serde_json::from_str(arguments).map_err(|error| {
                        OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                    })?
                }
                Some(value) => value.clone(),
                None => {
                    let key = item
                        .get("id")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("call_id").and_then(Value::as_str));
                    let Some(arguments) = key.and_then(|key| stream_state.argument_deltas.get(key))
                    else {
                        return Err(OxidraError::Provider(format!(
                            "function_call {name} is missing arguments"
                        )));
                    };
                    if let Some(object) = item.as_object_mut() {
                        object.insert("arguments".to_owned(), Value::String(arguments.clone()));
                    }
                    serde_json::from_str(arguments).map_err(|error| {
                        OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                    })?
                }
            };
            tool_calls.push(ToolCall {
                id,
                name,
                arguments,
            });
        } else if item.get("type").and_then(Value::as_str) == Some("message") {
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                for part in content {
                    if part.get("type").and_then(Value::as_str) == Some("output_text") {
                        if let Some(value) = part.get("text").and_then(Value::as_str) {
                            text.push_str(value);
                        }
                    }
                }
            }
        }
    }

    if text.is_empty() {
        text = stream_state.text.clone();
    }
    if let Some(object) = response.as_object_mut() {
        object.insert("output".to_owned(), Value::Array(output_items.clone()));
    }
    let usage = parse_usage(response.get("usage"));
    Ok(AssistantTurn {
        raw_response: response,
        output_items,
        text,
        tool_calls,
        usage,
        unknown_stream_events: stream_state.unknown_events.clone(),
    })
}

fn parse_usage(value: Option<&Value>) -> Usage {
    let Some(value) = value else {
        return Usage::default();
    };
    let input_tokens = value
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let cached_input_tokens = value
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let output_tokens = value
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let reasoning_output_tokens = value
        .get("output_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let total_tokens = value
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(input_tokens.saturating_add(output_tokens));
    Usage {
        input_tokens,
        cached_input_tokens,
        output_tokens,
        reasoning_output_tokens,
        total_tokens,
    }
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_event_error(payload: &Value) -> String {
    payload
        .get("error")
        .and_then(|error| {
            error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
        })
        .or_else(|| {
            payload
                .get("response")
                .and_then(|response| response.get("error"))
                .and_then(|error| error.get("message").and_then(Value::as_str))
        })
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| payload.to_string())
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.min(60)));
    }
    let retry_at = DateTime::parse_from_rfc2822(value)
        .ok()?
        .with_timezone(&Utc);
    let seconds = retry_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0) as u64;
    Some(Duration::from_secs(seconds.min(60)))
}

fn backoff(attempt: usize) -> Duration {
    let base_ms = 250_u64.saturating_mul(1_u64 << attempt.saturating_sub(1));
    let jitter = fastrand::u64(0..=100);
    Duration::from_millis((base_ms + jitter).min(60_000))
}

fn format_http_error(status: StatusCode, body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        format!("Responses API returned HTTP {status}")
    } else {
        format!("Responses API returned HTTP {status}: {body}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopObserver;

    impl StreamObserver for NoopObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parses_message_and_function_call_output() {
        let response = json!({
            "usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
            "output": [
                {"type":"message","content":[{"type":"output_text","text":"ok"}]},
                {"type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"a\"}"}
            ]
        });
        let turn = build_turn(response, &StreamState::default()).unwrap();
        assert_eq!(turn.text, "ok");
        assert_eq!(turn.tool_calls[0].id, "call_1");
        assert_eq!(turn.usage.total_tokens, 7);
    }

    #[test]
    fn rebuilds_empty_completed_output_from_stream_items() {
        let mut state = StreamState::default();
        state.output_items_by_index.insert(
            0,
            json!({"type":"function_call","id":"item_1","name":"read"}),
        );
        state
            .argument_deltas
            .insert("item_1".to_owned(), "{\"path\":\"calc.py\"}".to_owned());
        state
            .unknown_events
            .push(json!({"type":"future.event","x":1}));

        let turn = build_turn(json!({"output": [], "usage": {}}), &state).unwrap();
        assert_eq!(turn.tool_calls[0].arguments["path"], "calc.py");
        assert_eq!(turn.output_items[0]["arguments"], "{\"path\":\"calc.py\"}");
        assert_eq!(
            turn.raw_response["output"],
            Value::Array(turn.output_items.clone())
        );
        assert_eq!(
            turn.unknown_stream_events,
            vec![json!({"type":"future.event","x":1})]
        );
    }

    #[test]
    fn request_has_stateless_stream_flags() {
        let config = ProviderConfig {
            api_key: "x".to_owned(),
            api_base_url: url::Url::parse("https://example.test/v1/").unwrap(),
            model: "m".to_owned(),
        };
        let provider = OpenAiResponsesProvider::new(config).unwrap();
        let body = provider.request_body(&ResponseRequest::new(Vec::new(), Vec::new()));
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
        assert_eq!(body["model"], "m");
    }

    #[test]
    fn retry_after_is_bounded() {
        assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
        assert_eq!(parse_retry_after("999"), Some(Duration::from_secs(60)));
        assert_eq!(parse_retry_after("nope"), None);
    }

    #[allow(dead_code)]
    fn observer_is_send(_: &mut dyn StreamObserver) {
        let _ = NoopObserver;
    }
}
