//! OpenAI Responses API transport.
//!
//! The provider deliberately knows nothing about the agent loop.  It turns a
//! streamed response into an opaque, uncommitted transport outcome. Only
//! crate-owned durable writers may unwrap that outcome into an [`AssistantTurn`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;

use crate::config::{ProviderConfig, display_safe_url};
use crate::error::{OxidraError, Result};
use crate::mcp::{
    McpJsonTreeMetricsV1, count_mcp_provider_json_text_nodes_v1, drop_json_value_iteratively,
    measure_mcp_provider_event_tree_v1, parse_mcp_provider_json_text_v1,
    preflight_mcp_provider_event_tree_v1,
};
use crate::projection::validate_response_output_items;
use crate::provider_sse::{BoundedSseDecoder, SseDecodeError, SseEvent, SseFeedError, SseLimits};
use crate::types::{AssistantTurn, ToolCall, ToolDefinition, Usage};

const MAX_ATTEMPTS: usize = 3;
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RESPONSE_WALL_TIME_V1: Duration = Duration::from_secs(15 * 60);
const MAX_ERROR_BODY: usize = 64 * 1024;
const MAX_RESPONSE_EVENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESPONSE_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_PROVIDER_RESPONSE_ARGUMENT_BYTES_V1: usize = MAX_RESPONSE_ARGUMENT_BYTES;
const MAX_RESPONSE_STREAM_EVENTS_V1: usize = 262_144;
const MAX_RESPONSE_CUMULATIVE_EVENT_BYTES_V1: usize = 128 * 1024 * 1024;
const MAX_RESPONSE_RETAINED_ENTRIES_V1: usize = 16_384;
pub(crate) const MAX_RESPONSE_RETAINED_NODES_V1: usize = 262_144;
const MAX_RESPONSE_RETAINED_BYTES_V1: usize = 32 * 1024 * 1024;
const MAX_EXACT_PREPARED_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_EXACT_PREPARED_REQUEST_NODES_V1: usize = 262_144;

/// A complete stateless Responses request.
#[derive(Debug)]
pub struct ResponseRequest {
    pub instructions: Option<String>,
    /// Raw Responses input items.  Keeping these as JSON values lets the
    /// journal replay unknown/future item fields without a lossy projection.
    pub input: Vec<Value>,
    pub tools: Vec<ToolDefinition>,
    pub model: Option<String>,
    pub max_output_tokens: Option<u64>,
}

impl Clone for ResponseRequest {
    fn clone(&self) -> Self {
        // `serde_json::Value::clone` recursively walks attacker-controlled
        // arrays/objects.  Keep the public convenience Clone implementation,
        // but make its traversal obey the same iterative ownership rule as
        // journal fixtures; callers may clone a request before Provider
        // admission has had a chance to reject its depth.
        Self {
            instructions: self.instructions.clone(),
            input: self
                .input
                .iter()
                .map(crate::session::clone_json_value_iteratively_v1)
                .collect(),
            tools: self
                .tools
                .iter()
                .map(|tool| ToolDefinition {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    input_schema: crate::session::clone_json_value_iteratively_v1(
                        &tool.input_schema,
                    ),
                })
                .collect(),
            model: self.model.clone(),
            max_output_tokens: self.max_output_tokens,
        }
    }
}

impl ResponseRequest {
    pub fn new(input: Vec<Value>, tools: Vec<ToolDefinition>) -> Self {
        Self {
            instructions: None,
            input,
            tools,
            model: None,
            max_output_tokens: None,
        }
    }
}

impl Drop for ResponseRequest {
    fn drop(&mut self) {
        // `ResponseProvider::respond` is an async trait method. Its returned
        // future owns `request` before the first poll, so an unpolled/cancelled
        // future must not recursively destroy attacker-controlled JSON on the
        // caller's stack. Drain one top-level owner at a time and use the
        // O(depth) iterative JSON destructor for every untrusted tree.
        for input in self.input.drain(..) {
            drop_json_value_iteratively(input);
        }
        for tool in &mut self.tools {
            drop_json_value_iteratively(std::mem::replace(&mut tool.input_schema, Value::Null));
        }
        self.tools.clear();
    }
}

/// Opaque ownership of a Provider attempt before its durable terminal exists.
///
/// Direct transport callers may create or drop this value, but cannot inspect
/// either a successful payload or a failure body. Crate-owned durable writers
/// are the only consumers. This prevents a low-level safe Rust caller from
/// turning an uncommitted Provider result into execution authority.
///
/// ```compile_fail
/// use oxidra::provider::UncommittedProviderOutcomeV1;
///
/// fn inspect(outcome: UncommittedProviderOutcomeV1) {
///     let _ = outcome.result;
/// }
/// ```
///
/// ```compile_fail
/// use oxidra::provider::UncommittedProviderOutcomeV1;
///
/// fn unwrap(outcome: UncommittedProviderOutcomeV1) {
///     let _ = outcome.into_result_v1();
/// }
/// ```
pub struct UncommittedProviderOutcomeV1 {
    result: Option<Result<OwnedAssistantTurnV1>>,
}

/// Iterative-drop owner retained by durable writers until the response has
/// passed its bounded JSON preflight.
pub(crate) struct OwnedAssistantTurnV1 {
    turn: Option<AssistantTurn>,
}

impl std::fmt::Debug for OwnedAssistantTurnV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedAssistantTurnV1")
            .field("state", &"redacted")
            .finish()
    }
}

impl OwnedAssistantTurnV1 {
    fn new(turn: AssistantTurn) -> Self {
        Self { turn: Some(turn) }
    }

    pub(crate) fn as_turn(&self) -> &AssistantTurn {
        self.turn.as_ref().expect("owned Provider turn")
    }

    pub(crate) fn preflight_bounded_v1(&self) -> Result<()> {
        let turn = self.as_turn();
        preflight_provider_value_v1(&turn.raw_response, "raw_response")?;
        for (index, item) in turn.output_items.iter().enumerate() {
            preflight_provider_value_v1(item, &format!("output_items[{index}]"))?;
        }
        for (index, call) in turn.tool_calls.iter().enumerate() {
            preflight_provider_value_v1(
                &call.arguments,
                &format!("tool_calls[{index}].arguments"),
            )?;
        }
        for (index, event) in turn.unknown_stream_events.iter().enumerate() {
            preflight_provider_value_v1(event, &format!("unknown_stream_events[{index}]"))?;
        }
        Ok(())
    }

    pub(crate) fn into_turn(mut self) -> AssistantTurn {
        self.turn.take().expect("owned Provider turn")
    }
}

impl std::ops::Deref for OwnedAssistantTurnV1 {
    type Target = AssistantTurn;

    fn deref(&self) -> &Self::Target {
        self.as_turn()
    }
}

fn preflight_provider_value_v1(value: &Value, path: &str) -> Result<()> {
    preflight_provider_value_with_limit_v1(value, path, MAX_RESPONSE_EVENT_BYTES)
}

fn preflight_provider_value_with_limit_v1(
    value: &Value,
    path: &str,
    maximum_bytes: usize,
) -> Result<()> {
    preflight_mcp_provider_event_tree_v1(value, maximum_bytes).map_err(|error| {
        OxidraError::Provider(format!(
            "Provider {path} exceeds the bounded response profile: {error}"
        ))
    })
}

fn measure_provider_value_v1(value: &Value, path: &str) -> Result<McpJsonTreeMetricsV1> {
    measure_mcp_provider_event_tree_v1(value, MAX_RESPONSE_EVENT_BYTES).map_err(|error| {
        OxidraError::Provider(format!(
            "Provider {path} exceeds the bounded response profile: {error}"
        ))
    })
}

impl Drop for OwnedAssistantTurnV1 {
    fn drop(&mut self) {
        let Some(mut turn) = self.turn.take() else {
            return;
        };
        drop_json_value_iteratively(std::mem::replace(&mut turn.raw_response, Value::Null));
        for item in turn.output_items.drain(..) {
            drop_json_value_iteratively(item);
        }
        for mut call in turn.tool_calls.drain(..) {
            drop_json_value_iteratively(std::mem::replace(&mut call.arguments, Value::Null));
        }
        for event in turn.unknown_stream_events.drain(..) {
            drop_json_value_iteratively(event);
        }
    }
}

impl UncommittedProviderOutcomeV1 {
    pub fn success(turn: AssistantTurn) -> Self {
        Self {
            result: Some(Ok(OwnedAssistantTurnV1::new(turn))),
        }
    }

    pub fn failure(error: OxidraError) -> Self {
        Self {
            result: Some(Err(error)),
        }
    }

    pub fn from_result(result: Result<AssistantTurn>) -> Self {
        Self {
            result: Some(result.map(OwnedAssistantTurnV1::new)),
        }
    }

    pub(crate) fn into_result_v1(mut self) -> Result<OwnedAssistantTurnV1> {
        self.result.take().expect("uncommitted Provider outcome")
    }
}

impl std::fmt::Debug for UncommittedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UncommittedProviderOutcomeV1")
            .field("state", &"redacted")
            .finish()
    }
}

impl Drop for UncommittedProviderOutcomeV1 {
    fn drop(&mut self) {
        let Some(result) = self.result.take() else {
            return;
        };
        match result {
            Ok(turn) => drop(turn),
            Err(mut error) => loop {
                match error {
                    OxidraError::Observer(source) => error = *source,
                    terminal => {
                        drop(terminal);
                        break;
                    }
                }
            },
        }
    }
}

/// A Provider-owned preparation of one exact wire request.
///
/// The serialized body is created once and is the body a supporting transport
/// must send.  Keeping the exact bytes beside the logical request lets durable
/// admission bind what will cross the wire instead of independently rebuilding
/// a body from configuration that the transport might not use.
pub struct PreparedResponseRequest {
    request: Option<ResponseRequest>,
    body: Option<Value>,
    // `reqwest::Body` also retains `Bytes`. Keeping the sealed wire image in
    // the same reference-counted owner avoids copying the complete request for
    // every retry while the logical request and frozen JSON body are still
    // alive for durable admission.
    body_bytes: Bytes,
    provider_protocol: String,
    provider_usage_domain: String,
}

impl std::fmt::Debug for PreparedResponseRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The logical request and frozen body contain prompts, history, tool
        // schemas, and arbitrary provider payloads.  A derived Debug impl
        // would recursively dump all of them into logs.  Keep only bounded
        // shape metadata; the values themselves are intentionally opaque.
        formatter
            .debug_struct("PreparedResponseRequest")
            .field("request_present", &self.request.is_some())
            .field("body_present", &self.body.is_some())
            .field("body_bytes_len", &self.body_bytes.len())
            .field("provider_protocol", &"redacted")
            .field("provider_usage_domain", &"redacted")
            .finish()
    }
}

/// Count one canonical Responses body without first cloning its input/schema
/// trees into a second `Value`.  The ordinary serializer is deliberately used
/// here so string escaping and every optional field have exactly the same wire
/// cost as the body that will subsequently be frozen.
struct PreparedResponseBodyRefV1<'a> {
    request: &'a ResponseRequest,
    effective_model: &'a str,
}

impl Serialize for PreparedResponseBodyRefV1<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let request = self.request;
        let mut body = serializer.serialize_map(Some(
            6 + usize::from(request.instructions.is_some())
                + usize::from(request.max_output_tokens.is_some()),
        ))?;
        body.serialize_entry(
            "model",
            request.model.as_deref().unwrap_or(self.effective_model),
        )?;
        body.serialize_entry("input", &request.input)?;
        body.serialize_entry(
            "tools",
            &PreparedResponseToolsRefV1 {
                tools: &request.tools,
            },
        )?;
        body.serialize_entry("stream", &true)?;
        body.serialize_entry("store", &false)?;
        body.serialize_entry("include", &["reasoning.encrypted_content"])?;
        if let Some(instructions) = &request.instructions {
            body.serialize_entry("instructions", instructions)?;
        }
        if let Some(max_output_tokens) = request.max_output_tokens {
            body.serialize_entry("max_output_tokens", &max_output_tokens)?;
        }
        body.end()
    }
}

struct PreparedResponseToolsRefV1<'a> {
    tools: &'a [ToolDefinition],
}

impl Serialize for PreparedResponseToolsRefV1<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tools = serializer.serialize_seq(Some(self.tools.len()))?;
        for tool in self.tools {
            tools.serialize_element(&PreparedResponseToolRefV1 { tool })?;
        }
        tools.end()
    }
}

struct PreparedResponseToolRefV1<'a> {
    tool: &'a ToolDefinition,
}

impl Serialize for PreparedResponseToolRefV1<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tool = serializer.serialize_map(Some(5))?;
        tool.serialize_entry("type", "function")?;
        tool.serialize_entry("name", &self.tool.name)?;
        tool.serialize_entry("description", &self.tool.description)?;
        tool.serialize_entry("parameters", &self.tool.input_schema)?;
        tool.serialize_entry("strict", &false)?;
        tool.end()
    }
}

struct BoundedPreparedRequestWriterV1 {
    written: usize,
    exceeded: bool,
}

impl Write for BoundedPreparedRequestWriterV1 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other(
                "prepared Provider request size overflowed",
            ));
        };
        if next > MAX_EXACT_PREPARED_REQUEST_BYTES {
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

impl PreparedResponseRequest {
    /// Build the frozen body used by the OpenAI Responses profile without
    /// invoking Provider code.  This constructor is intentionally a pure
    /// value transformation: callers can complete durable admission before
    /// handing the resulting sealed request to a transport.
    pub fn from_responses_request(
        request: ResponseRequest,
        effective_model: impl Into<String>,
        provider_usage_domain: impl Into<String>,
    ) -> Result<Self> {
        let effective_model = effective_model.into();
        // Take iterative-drop ownership before inspecting or cloning any
        // caller-controlled JSON. A rejected 50k-deep in-memory request must
        // not recursively unwind through the constructor's error path.
        let mut prepared = Self {
            request: Some(request),
            body: None,
            body_bytes: Bytes::new(),
            provider_protocol: crate::context::PROVIDER_PROTOCOL_OPENAI_RESPONSES.to_owned(),
            provider_usage_domain: provider_usage_domain.into(),
        };
        prepared.validate_logical_request_tree()?;
        // Reject the complete logical request before `prepared_request_body`
        // clones every input and schema into a second tree. Per-value limits
        // are insufficient: thousands of individually valid values can make
        // that projection exceed both its byte and node budgets.
        prepared.validate_responses_body_before_clone(&effective_model)?;
        let body = prepared_request_body(prepared.request(), &effective_model);
        prepared.body = Some(body);
        prepared.validate_body_and_encode()?;
        Ok(prepared)
    }

    /// Construct an exact prepared request for a custom Provider transport.
    /// Implementors must send `body_bytes()` unchanged from
    /// [`PreparedResponseProvider::respond_prepared`]. This is a logical
    /// preparation guarantee only: custom transports are trusted TCB and are
    /// intentionally excluded from the sealed MCP exact-wire path.
    pub fn from_exact_body(
        request: ResponseRequest,
        body: Value,
        provider_protocol: impl Into<String>,
        provider_usage_domain: impl Into<String>,
    ) -> Result<Self> {
        // Take iterative-drop ownership before validation or serialization so
        // a custom Provider cannot reintroduce recursive destruction through
        // an oversized/deep prepared body.
        let mut prepared = Self {
            request: Some(request),
            body: Some(body),
            body_bytes: Bytes::new(),
            provider_protocol: provider_protocol.into(),
            provider_usage_domain: provider_usage_domain.into(),
        };
        prepared.validate_logical_request_tree()?;
        prepared.validate_body_and_encode()?;
        Ok(prepared)
    }

    fn validate_logical_request_tree(&self) -> Result<()> {
        let mut aggregate_nodes = 8usize;
        for (index, input) in self.request().input.iter().enumerate() {
            let metrics =
                measure_mcp_provider_event_tree_v1(input, MAX_EXACT_PREPARED_REQUEST_BYTES)
                    .map_err(|error| {
                        OxidraError::Provider(format!(
                            "prepared Provider request input[{index}] is not bounded: {error}"
                        ))
                    })?;
            aggregate_nodes = aggregate_nodes.checked_add(metrics.nodes).ok_or_else(|| {
                OxidraError::Provider(
                    "prepared Provider request aggregate node budget overflowed".to_owned(),
                )
            })?;
        }
        for (index, tool) in self.request().tools.iter().enumerate() {
            let metrics = measure_mcp_provider_event_tree_v1(
                &tool.input_schema,
                MAX_EXACT_PREPARED_REQUEST_BYTES,
            )
            .map_err(|error| {
                OxidraError::Provider(format!(
                    "prepared Provider request tool[{index}] schema is not bounded: {error}"
                ))
            })?;
            aggregate_nodes = aggregate_nodes
                .checked_add(metrics.nodes.saturating_add(5))
                .ok_or_else(|| {
                    OxidraError::Provider(
                        "prepared Provider request aggregate node budget overflowed".to_owned(),
                    )
                })?;
        }
        aggregate_nodes = aggregate_nodes
            .saturating_add(usize::from(self.request().instructions.is_some()))
            .saturating_add(usize::from(self.request().max_output_tokens.is_some()));
        if aggregate_nodes > MAX_EXACT_PREPARED_REQUEST_NODES_V1 {
            return Err(OxidraError::Provider(format!(
                "prepared Provider request exceeds aggregate node budget {MAX_EXACT_PREPARED_REQUEST_NODES_V1}"
            )));
        }
        // `from_exact_body` retains the logical request even though it does
        // not build the canonical Responses projection. Bound that retained
        // aggregate too; otherwise many individually valid input/schema trees
        // could still occupy an attacker-sized request before a custom
        // transport gets to consume the prepared capability.
        let mut writer = BoundedPreparedRequestWriterV1 {
            written: 0,
            exceeded: false,
        };
        if let Err(error) = serde_json::to_writer(
            &mut writer,
            &(
                &self.request().instructions,
                &self.request().input,
                &self.request().tools,
                &self.request().model,
                self.request().max_output_tokens,
            ),
        ) {
            if writer.exceeded {
                return Err(OxidraError::Provider(format!(
                    "prepared Provider request exceeds aggregate byte budget {MAX_EXACT_PREPARED_REQUEST_BYTES}"
                )));
            }
            return Err(error.into());
        }
        Ok(())
    }

    fn validate_responses_body_before_clone(&self, effective_model: &str) -> Result<()> {
        let mut writer = BoundedPreparedRequestWriterV1 {
            written: 0,
            exceeded: false,
        };
        let body = PreparedResponseBodyRefV1 {
            request: self.request(),
            effective_model,
        };
        if let Err(error) = serde_json::to_writer(&mut writer, &body) {
            if writer.exceeded {
                return Err(OxidraError::Provider(format!(
                    "prepared Provider request exceeds aggregate byte budget {MAX_EXACT_PREPARED_REQUEST_BYTES}"
                )));
            }
            return Err(error.into());
        }
        Ok(())
    }

    fn validate_body_and_encode(&mut self) -> Result<()> {
        preflight_mcp_provider_event_tree_v1(self.body(), MAX_EXACT_PREPARED_REQUEST_BYTES)
            .map_err(|error| {
                OxidraError::Provider(format!(
                    "prepared Provider request body is not bounded: {error}"
                ))
            })?;
        self.body_bytes = serde_json::to_vec(self.body())?.into();
        Ok(())
    }

    pub(crate) fn request(&self) -> &ResponseRequest {
        self.request.as_ref().expect("prepared Provider request")
    }

    pub(crate) fn body(&self) -> &Value {
        self.body.as_ref().expect("prepared Provider body")
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    fn shared_body_bytes_v1(&self) -> Bytes {
        self.body_bytes.clone()
    }

    pub fn provider_protocol(&self) -> &str {
        &self.provider_protocol
    }

    pub fn provider_usage_domain(&self) -> &str {
        &self.provider_usage_domain
    }
}

impl Drop for PreparedResponseRequest {
    fn drop(&mut self) {
        if let Some(body) = self.body.take() {
            drop_json_value_iteratively(body);
        }
        let Some(mut request) = self.request.take() else {
            return;
        };
        for input in request.input.drain(..) {
            drop_json_value_iteratively(input);
        }
        for mut tool in request.tools.drain(..) {
            drop_json_value_iteratively(std::mem::replace(&mut tool.input_schema, Value::Null));
        }
    }
}

/// Events intended for the UI/diagnostic stream.  They are not canonical
/// session history; only the final `response.completed` payload is committed.
///
/// Retry notices deliberately carry only a locally assigned classification.
/// Provider-controlled error bodies remain inside the transport result until
/// the durable response terminal is produced; they must not cross this
/// pre-commit observer boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRetryClassV1 {
    RetryableHttpStatus(u16),
    TransportBeforeResponse,
    StreamEndedBeforeFirstEvent,
    StreamErrorBeforeFirstEvent,
}

impl ProviderRetryClassV1 {
    /// Render only locally assigned retry metadata. No Provider error body,
    /// header value, or streamed payload participates in this text.
    pub fn display_text(self) -> String {
        match self {
            Self::RetryableHttpStatus(status) => {
                format!("retryable HTTP status {status}")
            }
            Self::TransportBeforeResponse => "transport failed before a response".to_owned(),
            Self::StreamEndedBeforeFirstEvent => "stream ended before its first event".to_owned(),
            Self::StreamErrorBeforeFirstEvent => "stream failed before its first event".to_owned(),
        }
    }
}

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
        classification: ProviderRetryClassV1,
    },
    Unknown {
        event_type: String,
        payload: Value,
    },
}

#[doc(hidden)]
pub(crate) mod stream_observer_sealed {
    pub trait Sealed {}
}

/// Sink used by crate-owned durable execution paths to render streaming
/// output. External callers cannot install a payload-bearing callback on the
/// built-in transport; use [`SilentStreamObserverV1`] for direct low-level
/// calls.
#[allow(private_bounds)]
pub trait StreamObserver: stream_observer_sealed::Sealed + Send {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SilentStreamObserverV1;

impl stream_observer_sealed::Sealed for SilentStreamObserverV1 {}

impl StreamObserver for SilentStreamObserverV1 {
    fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
        if let ProviderEvent::Unknown { payload, .. } = event {
            drop_json_value_iteratively(payload);
        }
        Ok(())
    }
}

fn notify_observer(observer: &mut dyn StreamObserver, event: ProviderEvent) -> Result<()> {
    observer.on_event(event).map_err(OxidraError::observer)
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
    ) -> UncommittedProviderOutcomeV1;
}

/// Provider transport that can seal and consume one exact serialized body.
/// MCP dispatch accepts this stronger trait rather than relying on the legacy
/// logical-request API to rebuild the same body by convention.
#[async_trait]
pub trait PreparedResponseProvider: ResponseProvider {
    async fn respond_prepared(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> UncommittedProviderOutcomeV1;
}

/// Sealing boundary for transports allowed to consume MCP exact-wire
/// capabilities. External/custom [`PreparedResponseProvider`] implementations
/// remain useful for non-MCP callers, but they are part of the caller's TCB and
/// cannot be used to satisfy the MCP journal's exact-wire claim.
#[doc(hidden)]
pub(crate) mod mcp_exact_wire_sealed {
    pub trait Sealed {}
}

/// Trusted transport used by the MCP exact-wire path.
///
/// This trait is deliberately sealed outside this crate. A public custom
/// `PreparedResponseProvider` can ignore `PreparedResponseRequest::body_bytes`,
/// so accepting that trait would only prove which bytes were journaled, not
/// which bytes reached the network. Implementations here are reviewed as part
/// of Oxidra's transport TCB and must send the sealed bytes unchanged.
#[allow(private_bounds)]
#[async_trait]
pub trait McpExactWireProvider: mcp_exact_wire_sealed::Sealed + Send + Sync {
    /// Identity of the exact endpoint/model domain used by this transport.
    /// Admission compares it with the sealed request before `response.started`
    /// is fsynced.
    fn mcp_provider_usage_domain_v1(&self) -> Result<String>;

    /// The model selected by the concrete transport configuration.  Exact MCP
    /// admission must compare this value with the sealed wire body's `model`;
    /// otherwise a caller could keep the configured usage-domain digest while
    /// overriding only the request model and send bytes for a different model.
    fn mcp_provider_model_v1(&self) -> Result<String>;

    async fn respond_exact_mcp_v1(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> UncommittedProviderOutcomeV1;
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
            .field("api_base_url", &display_safe_url(&self.config.api_base_url))
            .field("model", &self.config.model)
            .finish_non_exhaustive()
    }
}

impl OpenAiResponsesProvider {
    pub fn new(mut config: ProviderConfig) -> Result<Self> {
        // `ProviderConfig` has public fields for test/custom transport
        // construction, so callers can bypass `ProviderConfig::resolve`.
        // Re-apply the same URL boundary here before deriving usage-domain
        // provenance or issuing a request: credentials/query/fragment would
        // alter the actual recipient, and a missing trailing slash changes
        // `join("responses")` from `/v1/responses` to `/responses`.
        config.api_base_url = crate::config::normalize_base_url(config.api_base_url.as_str())?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            // Environment/system proxy discovery would disclose the sealed
            // request body to a recipient that is absent from the durable
            // Provider usage-domain identity. Operators that require a proxy
            // must configure that proxy as the explicit API base URL so it is
            // part of approval and journal provenance.
            .no_proxy()
            // Provider usage-domain provenance binds one exact configured
            // endpoint/model. Following an HTTP redirect would send the
            // sealed MCP body to a different endpoint after durable admission,
            // so redirects are a terminal response rather than transport
            // policy.
            .redirect(reqwest::redirect::Policy::none())
            // Idle timeout per socket read: streaming deltas and keep-alive
            // frames reset it, so long responses are unaffected while a hung
            // server surfaces as a normal transport error.
            .read_timeout(READ_IDLE_TIMEOUT)
            .build()
            .map_err(|error| {
                OxidraError::Provider(format!("cannot create HTTP client: {error}"))
            })?;
        Ok(Self { config, client })
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// Freeze the exact Responses body locally. This performs no network I/O
    /// and is deliberately separate from [`PreparedResponseProvider`], whose
    /// only responsibility is consuming an already-admitted wire request.
    pub fn prepare_request(&self, request: ResponseRequest) -> Result<PreparedResponseRequest> {
        PreparedResponseRequest::from_responses_request(
            request,
            self.config.model.clone(),
            crate::context::provider_usage_domain(&self.config)?,
        )
    }

    #[cfg(test)]
    fn request_body(&self, request: &ResponseRequest) -> Value {
        prepared_request_body(request, &self.config.model)
    }

    async fn attempt(
        &self,
        request_body: Bytes,
        observer: &mut dyn StreamObserver,
        cancellation: &CancellationToken,
        response_deadline: TokioInstant,
    ) -> AttemptResult {
        if cancellation.is_cancelled() {
            return AttemptResult::cancelled();
        }
        if TokioInstant::now() >= response_deadline {
            return AttemptResult::deadline_exceeded(false);
        }
        let url = match self.config.responses_url() {
            Ok(url) => url,
            Err(error) => return AttemptResult::fatal(error),
        };
        let send = self
            .client
            .post(url)
            .bearer_auth(&self.config.api_key)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            // `Bytes` is the same immutable allocation owned by the prepared
            // request. Each retry only clones its reference-counted handle.
            .body(request_body)
            .send();
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return AttemptResult::cancelled(),
            _ = tokio::time::sleep_until(response_deadline) => {
                return AttemptResult::deadline_exceeded(false);
            }
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
                    biased;
                    _ = cancellation.cancelled() => return AttemptResult::cancelled(),
                    _ = tokio::time::sleep_until(response_deadline) => {
                        return AttemptResult::deadline_exceeded(false);
                    }
                    item = body_stream.next() => item,
                };
                let Some(chunk) = next else { break };
                let Ok(chunk) = chunk else {
                    body_read_error = true;
                    break;
                };
                let remaining = MAX_ERROR_BODY.saturating_sub(body_bytes.len());
                if remaining == 0 {
                    // Do not infer truncation merely because the retained
                    // prefix is exactly the budget.  The next poll may be
                    // EOF, in which case a body of exactly MAX_ERROR_BODY
                    // bytes is complete and must not acquire a synthetic
                    // `...<truncated>` suffix.
                    if !chunk.is_empty() {
                        body_truncated = true;
                        break;
                    }
                    continue;
                }
                if chunk.len() > remaining {
                    body_bytes.extend_from_slice(&chunk[..remaining]);
                    body_truncated = true;
                    break;
                }
                body_bytes.extend_from_slice(&chunk);
            }
            let mut body = String::from_utf8_lossy(&body_bytes).into_owned();
            if body_truncated {
                body.push_str("...<truncated>");
            }
            if body_read_error {
                body.push_str("...<transport error while reading error body>");
            }
            let message = format_http_error(status, &body);
            return if is_context_limit_error_body(&body) {
                AttemptResult::fatal(OxidraError::ProviderContextLimit(message))
            } else if retryable_status(status) {
                AttemptResult::retryable(
                    message,
                    retry_after,
                    ProviderRetryClassV1::RetryableHttpStatus(status.as_u16()),
                )
            } else {
                AttemptResult::fatal(OxidraError::Provider(message))
            };
        }

        let mut stream = response.bytes_stream();
        let mut decoder = BoundedSseDecoder::new(SseLimits::new(
            MAX_RESPONSE_EVENT_BYTES,
            MAX_RESPONSE_EVENT_BYTES,
            MAX_RESPONSE_STREAM_EVENTS_V1,
            MAX_RESPONSE_CUMULATIVE_EVENT_BYTES_V1,
        ));
        let mut state = StreamState::default();
        let mut saw_event = false;

        loop {
            let next = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return AttemptResult::cancelled(),
                _ = tokio::time::sleep_until(response_deadline) => {
                    return AttemptResult::deadline_exceeded(saw_event);
                }
                item = stream.next() => item,
            };
            let Some(item) = next else {
                let finish_result = decoder.finish(|event| {
                    process_sse_event_with_guards_v1(
                        event,
                        &mut state,
                        &mut saw_event,
                        observer,
                        cancellation,
                        response_deadline,
                    )
                });
                // `decoder.finish` invokes the callback synchronously. A
                // terminal event may therefore finish parsing after the
                // select! deadline fired in wall-clock time; do not let that
                // result escape as a successful Provider response.
                if cancellation.is_cancelled() {
                    return AttemptResult::cancelled();
                }
                if TokioInstant::now() >= response_deadline {
                    return AttemptResult::deadline_exceeded(saw_event);
                }
                if let Err(error) = finish_result {
                    return sse_feed_failure_v1(error, saw_event);
                }
                return sse_ended_before_completed_v1(saw_event);
            };
            let chunk = match item {
                Ok(chunk) => chunk,
                Err(error) => {
                    return sse_transport_failure_v1(
                        format!("SSE transport error: {error}"),
                        saw_event,
                    );
                }
            };
            let push_result = decoder.push_chunk(&chunk, |event| {
                process_sse_event_with_guards_v1(
                    event,
                    &mut state,
                    &mut saw_event,
                    observer,
                    cancellation,
                    response_deadline,
                )
            });
            // Parsing, metrics, and observer delivery all happen inside the
            // synchronous decoder callback. Re-check both guards after it
            // returns so a final delimiter cannot commit a response after
            // the absolute deadline (or after cancellation) was reached.
            if cancellation.is_cancelled() {
                return AttemptResult::cancelled();
            }
            if TokioInstant::now() >= response_deadline {
                return AttemptResult::deadline_exceeded(saw_event);
            }
            if let Err(error) = push_result {
                return sse_feed_failure_v1(error, saw_event);
            }
        }
    }
}

impl OpenAiResponsesProvider {
    async fn respond_prepared_result_v1(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> Result<AssistantTurn> {
        self.respond_prepared_with_wall_time_v1(
            request,
            observer,
            cancellation,
            MAX_RESPONSE_WALL_TIME_V1,
        )
        .await
    }

    async fn respond_prepared_with_wall_time_v1(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
        maximum_wall_time: Duration,
    ) -> Result<AssistantTurn> {
        // One absolute deadline owns the complete logical Provider response,
        // including connection setup, retryable error bodies, retry backoff,
        // and every retry attempt. Socket activity can refresh reqwest's idle
        // read timeout, but it cannot extend this wall-clock budget.
        let response_deadline = TokioInstant::now() + maximum_wall_time;
        let mut last_retry_reason = None;
        for attempt in 1..=MAX_ATTEMPTS {
            if cancellation.is_cancelled() {
                return Err(OxidraError::Interrupted);
            }
            if TokioInstant::now() >= response_deadline {
                return Err(OxidraError::Provider(response_wall_time_error_v1(
                    maximum_wall_time,
                )));
            }
            match self
                .attempt(
                    request.shared_body_bytes_v1(),
                    observer,
                    &cancellation,
                    response_deadline,
                )
                .await
            {
                AttemptResult::Completed(turn) => {
                    if cancellation.is_cancelled() {
                        return Err(OxidraError::Interrupted);
                    }
                    if TokioInstant::now() >= response_deadline {
                        return Err(OxidraError::ResponseAborted(response_wall_time_error_v1(
                            maximum_wall_time,
                        )));
                    }
                    // Keep the iterative-drop owner alive until both guards
                    // above have passed.  A terminal event can be assembled
                    // synchronously inside the decoder callback; if
                    // cancellation/deadline wins immediately afterwards, a
                    // bare AssistantTurn would otherwise recurse while being
                    // discarded on this error path.
                    return Ok(turn.into_turn());
                }
                AttemptResult::Cancelled => return Err(OxidraError::Interrupted),
                AttemptResult::DeadlineExceeded { saw_event } => {
                    let reason = response_wall_time_error_v1(maximum_wall_time);
                    return if saw_event {
                        Err(OxidraError::ResponseAborted(reason))
                    } else {
                        Err(OxidraError::Provider(reason))
                    };
                }
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
                    if cancellation.is_cancelled() {
                        return Err(OxidraError::Interrupted);
                    }
                    if TokioInstant::now() >= response_deadline {
                        return Err(OxidraError::Provider(response_wall_time_error_v1(
                            maximum_wall_time,
                        )));
                    }
                    notify_observer(
                        observer,
                        ProviderEvent::Retry {
                            attempt,
                            classification: ProviderRetryClassV1::TransportBeforeResponse,
                        },
                    )?;
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Err(OxidraError::Interrupted),
                        _ = tokio::time::sleep_until(response_deadline) => {
                            return Err(OxidraError::Provider(response_wall_time_error_v1(
                                maximum_wall_time,
                            )));
                        }
                        _ = tokio::time::sleep(delay) => {},
                    }
                }
                AttemptResult::Retryable {
                    reason,
                    retry_after,
                    classification,
                } => {
                    if attempt == MAX_ATTEMPTS {
                        return Err(OxidraError::Provider(reason));
                    }
                    last_retry_reason = Some(reason);
                    let delay = retry_after.unwrap_or_else(|| backoff(attempt));
                    if cancellation.is_cancelled() {
                        return Err(OxidraError::Interrupted);
                    }
                    if TokioInstant::now() >= response_deadline {
                        return Err(OxidraError::Provider(response_wall_time_error_v1(
                            maximum_wall_time,
                        )));
                    }
                    notify_observer(
                        observer,
                        ProviderEvent::Retry {
                            attempt,
                            classification,
                        },
                    )?;
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Err(OxidraError::Interrupted),
                        _ = tokio::time::sleep_until(response_deadline) => {
                            return Err(OxidraError::Provider(response_wall_time_error_v1(
                                maximum_wall_time,
                            )));
                        }
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

#[async_trait]
impl PreparedResponseProvider for OpenAiResponsesProvider {
    async fn respond_prepared(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> UncommittedProviderOutcomeV1 {
        UncommittedProviderOutcomeV1::from_result(
            self.respond_prepared_result_v1(request, observer, cancellation)
                .await,
        )
    }
}

impl mcp_exact_wire_sealed::Sealed for OpenAiResponsesProvider {}

#[async_trait]
impl McpExactWireProvider for OpenAiResponsesProvider {
    fn mcp_provider_usage_domain_v1(&self) -> Result<String> {
        crate::context::provider_usage_domain(&self.config)
    }

    fn mcp_provider_model_v1(&self) -> Result<String> {
        Ok(self.config.model.clone())
    }

    async fn respond_exact_mcp_v1(
        &self,
        request: PreparedResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> UncommittedProviderOutcomeV1 {
        PreparedResponseProvider::respond_prepared(self, request, observer, cancellation).await
    }
}

#[async_trait]
impl ResponseProvider for OpenAiResponsesProvider {
    async fn respond(
        &self,
        request: ResponseRequest,
        observer: &mut dyn StreamObserver,
        cancellation: CancellationToken,
    ) -> UncommittedProviderOutcomeV1 {
        let request = match self.prepare_request(request) {
            Ok(request) => request,
            Err(error) => return UncommittedProviderOutcomeV1::failure(error),
        };
        PreparedResponseProvider::respond_prepared(self, request, observer, cancellation).await
    }
}

/// Exact secret-free JSON body sent to a Responses-compatible Provider.
/// Context measurement uses the same builder so request-shape drift cannot
/// silently invalidate usage-anchor deltas.
pub(crate) fn prepared_request_body(request: &ResponseRequest, effective_model: &str) -> Value {
    let tools = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
                "strict": false,
            })
        })
        .collect::<Vec<_>>();
    let mut body = Map::new();
    body.insert(
        "model".to_owned(),
        Value::String(
            request
                .model
                .clone()
                .unwrap_or_else(|| effective_model.to_owned()),
        ),
    );
    body.insert("input".to_owned(), Value::Array(request.input.clone()));
    body.insert("tools".to_owned(), Value::Array(tools));
    body.insert("stream".to_owned(), Value::Bool(true));
    body.insert("store".to_owned(), Value::Bool(false));
    body.insert("include".to_owned(), json!(["reasoning.encrypted_content"]));
    if let Some(instructions) = &request.instructions {
        body.insert(
            "instructions".to_owned(),
            Value::String(instructions.clone()),
        );
    }
    if let Some(max_output_tokens) = request.max_output_tokens {
        body.insert(
            "max_output_tokens".to_owned(),
            Value::Number(max_output_tokens.into()),
        );
    }
    Value::Object(body)
}

enum AttemptResult {
    Completed(OwnedAssistantTurnV1),
    Retryable {
        reason: String,
        retry_after: Option<Duration>,
        classification: ProviderRetryClassV1,
    },
    Transport {
        reason: String,
        saw_event: bool,
    },
    Fatal(OxidraError),
    DeadlineExceeded {
        saw_event: bool,
    },
    Cancelled,
}

impl AttemptResult {
    fn completed(turn: AssistantTurn) -> Self {
        Self::Completed(OwnedAssistantTurnV1::new(turn))
    }

    fn retryable(
        reason: String,
        retry_after: Option<Duration>,
        classification: ProviderRetryClassV1,
    ) -> Self {
        Self::Retryable {
            reason,
            retry_after,
            classification,
        }
    }

    fn transport(reason: String, saw_event: bool) -> Self {
        Self::Transport { reason, saw_event }
    }

    fn fatal(error: OxidraError) -> Self {
        Self::Fatal(error)
    }

    fn deadline_exceeded(saw_event: bool) -> Self {
        Self::DeadlineExceeded { saw_event }
    }

    fn cancelled() -> Self {
        Self::Cancelled
    }
}

fn response_wall_time_error_v1(maximum_wall_time: Duration) -> String {
    format!(
        "Provider response exceeded the {}-millisecond absolute wall-time limit",
        maximum_wall_time.as_millis()
    )
}

fn process_sse_event_v1(
    event: SseEvent,
    state: &mut StreamState,
    saw_event: &mut bool,
    observer: &mut dyn StreamObserver,
) -> std::result::Result<(), AttemptResult> {
    // Empty keep-alive frames are not semantic Provider events. The bounded
    // decoder has already charged their raw bytes and frame count.
    if event.data.trim().is_empty() {
        return Ok(());
    }
    let mut payload = parse_mcp_provider_json_text_v1(&event.data, MAX_RESPONSE_EVENT_BYTES)
        .map_err(|error| {
            AttemptResult::fatal(OxidraError::Provider(format!(
                "invalid or unbounded JSON in SSE event {}: {error}",
                event.event
            )))
        })?;
    let payload_metrics =
        measure_provider_value_v1(&payload, "SSE event").map_err(AttemptResult::fatal)?;
    let payload_type = payload.get("type").and_then(Value::as_str);
    if event.event != "message"
        && !event.event.is_empty()
        && payload_type.is_some_and(|payload_type| payload_type != event.event)
    {
        return Err(AttemptResult::fatal(OxidraError::Provider(format!(
            "SSE event type {:?} does not match payload type {:?}",
            event.event, payload_type
        ))));
    }
    // Do not let a syntactically valid but envelope-forged event acquire
    // response ownership.  `saw_event` is used by retry/transport recovery
    // to distinguish a real semantic Provider event from a rejected frame;
    // set it only after the envelope/type provenance check has passed.
    *saw_event = true;
    let event_type = payload_type.unwrap_or(event.event.as_str()).to_owned();

    match event_type.as_str() {
        "response.output_text.delta" => {
            if let Some(delta) = payload.get("delta").and_then(Value::as_str) {
                state.append_text(delta).map_err(AttemptResult::fatal)?;
                notify_observer(observer, ProviderEvent::TextDelta(delta.to_owned()))
                    .map_err(AttemptResult::fatal)?;
            }
        }
        "response.function_call_arguments.delta" => {
            let delta = payload
                .get("delta")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            validate_argument_string_v1(&delta).map_err(AttemptResult::fatal)?;
            let item_id = string_field(&payload, "item_id");
            let call_id = string_field(&payload, "call_id");
            if let Some(key) = item_id.clone().or_else(|| call_id.clone()) {
                state
                    .append_argument_delta(key, &delta)
                    .map_err(AttemptResult::fatal)?;
            }
            notify_observer(
                observer,
                ProviderEvent::FunctionArgumentsDelta {
                    item_id,
                    call_id,
                    delta,
                },
            )
            .map_err(AttemptResult::fatal)?;
        }
        "response.function_call_arguments.done" => {
            if let Some(arguments) = payload.get("arguments") {
                validate_argument_value_v1(arguments).map_err(AttemptResult::fatal)?;
                if let Some(arguments) = arguments.as_str() {
                    let key = string_field(&payload, "item_id")
                        .or_else(|| string_field(&payload, "call_id"));
                    if let Some(key) = key {
                        state
                            .replace_arguments(key, arguments)
                            .map_err(AttemptResult::fatal)?;
                    }
                }
            }
        }
        "response.output_item.done" | "response.output_item.added" => {
            if let Some(item) = payload
                .as_object_mut()
                .and_then(|object| object.remove("item"))
            {
                let explicit_index = match payload.get("output_index") {
                    None => None,
                    Some(value) => Some(value.as_u64().ok_or_else(|| {
                        AttemptResult::fatal(OxidraError::Provider(
                            "response output item has an invalid output_index".to_owned(),
                        ))
                    })?),
                };
                state
                    .replace_output_item_event(explicit_index, item)
                    .map_err(AttemptResult::fatal)?;
            }
        }
        "response.completed" => {
            let response = payload
                .as_object_mut()
                .and_then(|object| object.remove("response"))
                .unwrap_or(payload);
            return Err(match build_turn(response, std::mem::take(state)) {
                Ok(turn) => AttemptResult::completed(turn),
                Err(error) => AttemptResult::fatal(error),
            });
        }
        "response.failed" | "error" => {
            let message = extract_event_error(&payload);
            let error = if is_context_limit_error_payload(&payload) {
                OxidraError::ProviderContextLimit(message)
            } else {
                OxidraError::Provider(message)
            };
            return Err(AttemptResult::fatal(error));
        }
        // A response can finish with an explicit incomplete event in newer API
        // versions. It is terminal but not replayable.
        "response.incomplete" => {
            return Err(AttemptResult::fatal(OxidraError::ResponseAborted(format!(
                "response incomplete: {payload}"
            ))));
        }
        event_type if is_known_progress_event(event_type) => {
            validate_progress_event_payload_profile_v1(event_type, &payload)
                .map_err(AttemptResult::fatal)?;
        }
        _ => {
            notify_observer(
                observer,
                ProviderEvent::Unknown {
                    event_type,
                    payload: payload.clone(),
                },
            )
            .map_err(AttemptResult::fatal)?;
            state
                .retain_unknown(payload, payload_metrics)
                .map_err(AttemptResult::fatal)?;
        }
    }
    Ok(())
}

fn process_sse_event_with_guards_v1(
    event: SseEvent,
    state: &mut StreamState,
    saw_event: &mut bool,
    observer: &mut dyn StreamObserver,
    cancellation: &CancellationToken,
    response_deadline: TokioInstant,
) -> std::result::Result<(), AttemptResult> {
    // A decoder callback runs synchronously and is not polled by the
    // surrounding select!. Check the two external guards at every event
    // boundary so a large chunk containing many frames cannot continue
    // processing after the response has been cancelled or expired.
    if cancellation.is_cancelled() {
        return Err(AttemptResult::cancelled());
    }
    if TokioInstant::now() >= response_deadline {
        return Err(AttemptResult::deadline_exceeded(*saw_event));
    }
    let result = process_sse_event_v1(event, state, saw_event, observer);
    // The callback itself may spend a bounded-but-nontrivial amount of time
    // parsing JSON, building the terminal projection, or invoking an internal
    // observer. Re-check after that synchronous work as well; checking only
    // before the callback would allow a final `response.completed` to cross
    // the absolute wall-time boundary and still be returned successfully.
    if cancellation.is_cancelled() {
        return Err(AttemptResult::cancelled());
    }
    if TokioInstant::now() >= response_deadline {
        return Err(AttemptResult::deadline_exceeded(*saw_event));
    }
    result
}

fn sse_feed_failure_v1(error: SseFeedError<AttemptResult>, saw_event: bool) -> AttemptResult {
    match error {
        SseFeedError::Handler(result) => result,
        SseFeedError::Decode(
            error @ (SseDecodeError::LineTooLarge { .. }
            | SseDecodeError::EventTooLarge { .. }
            | SseDecodeError::EventIdTooLarge { .. }
            | SseDecodeError::TooManyFrames { .. }
            | SseDecodeError::StreamTooLarge { .. }),
        ) => AttemptResult::fatal(OxidraError::Provider(error.to_string())),
        SseFeedError::Decode(SseDecodeError::InvalidUtf8) => {
            sse_transport_failure_v1("SSE stream is not valid UTF-8".to_owned(), saw_event)
        }
        SseFeedError::Decode(error) => AttemptResult::fatal(OxidraError::Provider(format!(
            "SSE decoder entered an invalid state: {error}"
        ))),
    }
}

fn sse_transport_failure_v1(reason: String, saw_event: bool) -> AttemptResult {
    if saw_event {
        AttemptResult::transport(reason, true)
    } else {
        AttemptResult::retryable(
            reason,
            None,
            ProviderRetryClassV1::StreamErrorBeforeFirstEvent,
        )
    }
}

fn sse_ended_before_completed_v1(saw_event: bool) -> AttemptResult {
    if saw_event {
        AttemptResult::transport(
            "SSE stream ended before response.completed".to_owned(),
            true,
        )
    } else {
        AttemptResult::retryable(
            "SSE stream ended before the first event".to_owned(),
            None,
            ProviderRetryClassV1::StreamEndedBeforeFirstEvent,
        )
    }
}

#[derive(Default)]
struct ResponseRetainedBudgetV1 {
    entries: usize,
    nodes: usize,
    bytes: usize,
}

impl ResponseRetainedBudgetV1 {
    fn replace(
        &mut self,
        removed_entries: usize,
        removed_nodes: usize,
        removed_bytes: usize,
        added_entries: usize,
        added_nodes: usize,
        added_bytes: usize,
    ) -> Result<()> {
        let entries = self
            .entries
            .checked_sub(removed_entries)
            .and_then(|value| value.checked_add(added_entries))
            .ok_or_else(|| {
                OxidraError::Provider("response retained entry budget overflowed".to_owned())
            })?;
        let nodes = self
            .nodes
            .checked_sub(removed_nodes)
            .and_then(|value| value.checked_add(added_nodes))
            .ok_or_else(|| {
                OxidraError::Provider("response retained node budget overflowed".to_owned())
            })?;
        let bytes = self
            .bytes
            .checked_sub(removed_bytes)
            .and_then(|value| value.checked_add(added_bytes))
            .ok_or_else(|| {
                OxidraError::Provider("response retained byte budget overflowed".to_owned())
            })?;
        if entries > MAX_RESPONSE_RETAINED_ENTRIES_V1 {
            return Err(OxidraError::Provider(format!(
                "response retained state exceeds the {MAX_RESPONSE_RETAINED_ENTRIES_V1}-entry limit"
            )));
        }
        if nodes > MAX_RESPONSE_RETAINED_NODES_V1 {
            return Err(OxidraError::Provider(format!(
                "response retained state exceeds the {MAX_RESPONSE_RETAINED_NODES_V1}-node limit"
            )));
        }
        if bytes > MAX_RESPONSE_RETAINED_BYTES_V1 {
            return Err(OxidraError::Provider(format!(
                "response retained state exceeds the {MAX_RESPONSE_RETAINED_BYTES_V1}-byte limit"
            )));
        }
        self.entries = entries;
        self.nodes = nodes;
        self.bytes = bytes;
        Ok(())
    }
}

struct RetainedJsonValueV1 {
    value: Option<Value>,
    metrics: McpJsonTreeMetricsV1,
}

impl RetainedJsonValueV1 {
    fn new(value: Value, metrics: McpJsonTreeMetricsV1) -> Self {
        Self {
            value: Some(value),
            metrics,
        }
    }

    fn into_value(mut self) -> Value {
        self.value.take().expect("retained Provider JSON value")
    }
}

impl Drop for RetainedJsonValueV1 {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop_json_value_iteratively(value);
        }
    }
}

#[derive(Default)]
struct StreamState {
    text: String,
    argument_deltas: BTreeMap<String, String>,
    output_items_by_index: BTreeMap<u64, RetainedJsonValueV1>,
    output_item_index_by_identity: BTreeMap<[u8; 32], u64>,
    unknown_events: Vec<RetainedJsonValueV1>,
    retained: ResponseRetainedBudgetV1,
    // Some compatible endpoints omit `output_index` on output-item events.
    // Keep a monotonic implicit cursor instead of deriving it from map
    // length: sparse/out-of-order explicit indexes must never cause an
    // unindexed event to overwrite an existing item.
    next_implicit_output_index: u64,
    implicit_output_index_exhausted: bool,
}

impl StreamState {
    fn claim_output_index(&mut self, explicit: Option<u64>) -> Result<u64> {
        if let Some(index) = explicit {
            if !self.implicit_output_index_exhausted && index >= self.next_implicit_output_index {
                self.next_implicit_output_index = match index.checked_add(1) {
                    Some(next) => next,
                    None => {
                        self.implicit_output_index_exhausted = true;
                        index
                    }
                };
            }
            return Ok(index);
        }

        if self.implicit_output_index_exhausted {
            return Err(OxidraError::Provider(
                "response output item has no available implicit output_index".to_owned(),
            ));
        }
        let mut index = self.next_implicit_output_index;
        while self.output_items_by_index.contains_key(&index) {
            index = index.checked_add(1).ok_or_else(|| {
                OxidraError::Provider(
                    "response output item implicit output_index overflowed".to_owned(),
                )
            })?;
        }
        self.next_implicit_output_index = match index.checked_add(1) {
            Some(next) => next,
            None => {
                self.implicit_output_index_exhausted = true;
                index
            }
        };
        Ok(index)
    }

    fn append_text(&mut self, delta: &str) -> Result<()> {
        if self.text.len().saturating_add(delta.len()) > MAX_RESPONSE_TEXT_BYTES {
            return Err(OxidraError::Provider(format!(
                "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
            )));
        }
        self.retained.replace(0, 0, 0, 0, 0, delta.len())?;
        self.text.push_str(delta);
        Ok(())
    }

    fn append_argument_delta(&mut self, key: String, delta: &str) -> Result<()> {
        let old_len = self.argument_deltas.get(&key).map_or(0, String::len);
        if old_len.saturating_add(delta.len()) > MAX_RESPONSE_ARGUMENT_BYTES {
            return Err(OxidraError::Provider(format!(
                "function-call arguments exceed the {MAX_RESPONSE_ARGUMENT_BYTES}-byte limit"
            )));
        }
        let is_new = !self.argument_deltas.contains_key(&key);
        self.retained.replace(
            0,
            0,
            0,
            usize::from(is_new),
            0,
            delta
                .len()
                .saturating_add(if is_new { key.len() } else { 0 }),
        )?;
        self.argument_deltas.entry(key).or_default().push_str(delta);
        Ok(())
    }

    fn replace_arguments(&mut self, key: String, arguments: &str) -> Result<()> {
        if arguments.len() > MAX_RESPONSE_ARGUMENT_BYTES {
            return Err(OxidraError::Provider(format!(
                "function-call arguments exceed the {MAX_RESPONSE_ARGUMENT_BYTES}-byte limit"
            )));
        }
        let previous = self.argument_deltas.get(&key);
        let removed_bytes = previous.map_or(0, String::len);
        let is_new = previous.is_none();
        self.retained.replace(
            0,
            0,
            removed_bytes,
            usize::from(is_new),
            0,
            arguments
                .len()
                .saturating_add(if is_new { key.len() } else { 0 }),
        )?;
        self.argument_deltas.insert(key, arguments.to_owned());
        Ok(())
    }

    fn replace_output_item(&mut self, index: u64, item: Value) -> Result<()> {
        validate_output_item_payload_profile_v1(&item)?;
        let metrics = measure_provider_value_v1(&item, "stream output item")?;
        let previous = self.output_items_by_index.get(&index);
        let (removed_entries, removed_nodes, removed_bytes) = previous
            .map_or((0, 0, 0), |previous| {
                (1, previous.metrics.nodes, previous.metrics.encoded_bytes)
            });
        self.retained.replace(
            removed_entries,
            removed_nodes,
            removed_bytes,
            1,
            metrics.nodes,
            metrics.encoded_bytes,
        )?;
        self.output_items_by_index
            .insert(index, RetainedJsonValueV1::new(item, metrics));
        Ok(())
    }

    fn replace_output_item_event(
        &mut self,
        explicit_index: Option<u64>,
        item: Value,
    ) -> Result<()> {
        let identity = item.get("id").and_then(Value::as_str);
        let identity_digest = identity.map(output_item_identity_digest_v1);
        let previously_bound_index = identity_digest
            .as_ref()
            .and_then(|digest| self.output_item_index_by_identity.get(digest))
            .copied();

        if let (Some(index), Some(bound_index)) = (explicit_index, previously_bound_index) {
            if index != bound_index {
                return Err(OxidraError::Provider(format!(
                    "response output item identity is already bound to output_index {bound_index}, not {index}"
                )));
            }
        }

        let index = if let Some(bound_index) = previously_bound_index {
            bound_index
        } else {
            self.claim_output_index(explicit_index)?
        };

        if let Some(identity) = identity {
            if let Some(previous_identity) = self
                .output_items_by_index
                .get(&index)
                .and_then(|previous| previous.value.as_ref())
                .and_then(|previous| previous.get("id"))
                .and_then(Value::as_str)
            {
                if previous_identity != identity {
                    return Err(OxidraError::Provider(format!(
                        "response output_index {index} is already bound to another item identity"
                    )));
                }
            }
        }

        self.replace_output_item(index, item)?;
        if let Some(digest) = identity_digest {
            self.output_item_index_by_identity.insert(digest, index);
        }
        Ok(())
    }

    fn retain_unknown(&mut self, payload: Value, metrics: McpJsonTreeMetricsV1) -> Result<()> {
        self.retained
            .replace(0, 0, 0, 1, metrics.nodes, metrics.encoded_bytes)?;
        self.unknown_events
            .push(RetainedJsonValueV1::new(payload, metrics));
        Ok(())
    }

    fn current_output_metrics(&self) -> (usize, usize, usize) {
        self.output_items_by_index.values().fold(
            (0usize, 0usize, 0usize),
            |(entries, nodes, bytes), item| {
                (
                    entries + 1,
                    nodes.saturating_add(item.metrics.nodes),
                    bytes.saturating_add(item.metrics.encoded_bytes),
                )
            },
        )
    }

    /// Replace the streamed output-item projection with the canonical output
    /// array carried by `response.completed`. Both ingress paths consume the
    /// same aggregate retained budget. `previous` is captured before a
    /// fallback output map is moved out, so argument completion can be
    /// included in the prospective accounting before any final item is
    /// accepted.
    fn replace_final_output_budget(
        &mut self,
        items: &[Value],
        previous: (usize, usize, usize),
        response_metadata: McpJsonTreeMetricsV1,
    ) -> Result<()> {
        // `response.completed.response` remains retained as
        // `AssistantTurn::raw_response`, not just as a temporary envelope.
        // Charge every non-output field in that object to the same aggregate
        // budget as output items and prior stream state. Otherwise a Provider
        // could retain one full budget in unknown events and another full
        // budget in response metadata while every individual SSE frame still
        // satisfies the per-event ceiling.
        let mut new_nodes = response_metadata.nodes;
        let mut new_bytes = response_metadata.encoded_bytes;
        for item in items {
            let metrics = measure_provider_value_v1(item, "completed output item")?;
            new_nodes = new_nodes.checked_add(metrics.nodes).ok_or_else(|| {
                OxidraError::Provider("completed output node count overflowed".to_owned())
            })?;
            new_bytes = new_bytes
                .checked_add(metrics.encoded_bytes)
                .ok_or_else(|| {
                    OxidraError::Provider("completed output byte count overflowed".to_owned())
                })?;
        }

        self.retained.replace(
            previous.0,
            previous.1,
            previous.2,
            items.len(),
            new_nodes,
            new_bytes,
        )?;

        // The completed output is now the canonical owner. Drop the streamed
        // projection after the budget transition, using its iterative owner
        // rather than recursively destroying attacker-controlled trees.
        let superseded = std::mem::take(&mut self.output_items_by_index);
        drop(superseded);
        Ok(())
    }
}

fn output_item_identity_digest_v1(identity: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"oxidra-provider-output-item-identity-v1\0");
    digest.update(identity.as_bytes());
    digest.finalize().into()
}

fn validate_argument_string_v1(arguments: &str) -> Result<()> {
    if arguments.len() > MAX_RESPONSE_ARGUMENT_BYTES {
        return Err(OxidraError::Provider(format!(
            "function-call arguments exceed the {MAX_RESPONSE_ARGUMENT_BYTES}-byte limit"
        )));
    }
    Ok(())
}

fn validate_argument_value_v1(arguments: &Value) -> Result<()> {
    match arguments {
        Value::String(arguments) => validate_argument_string_v1(arguments),
        value => preflight_provider_value_with_limit_v1(
            value,
            "function-call arguments",
            MAX_RESPONSE_ARGUMENT_BYTES,
        ),
    }
}

fn parse_argument_json_with_response_budget_v1(
    arguments: &str,
    retained_nodes: usize,
    parsed_argument_nodes: &mut usize,
) -> Result<Value> {
    let nodes = count_mcp_provider_json_text_nodes_v1(arguments, MAX_RESPONSE_ARGUMENT_BYTES)
        .map_err(|error| {
            OxidraError::Provider(format!(
                "invalid or unbounded function-call arguments: {error}"
            ))
        })?;
    let parsed_nodes = parsed_argument_nodes
        .checked_add(nodes)
        .ok_or_else(|| OxidraError::Provider("parsed argument node count overflowed".to_owned()))?;
    if retained_nodes
        .checked_add(parsed_nodes)
        .is_none_or(|total| total > MAX_RESPONSE_RETAINED_NODES_V1)
    {
        return Err(OxidraError::Provider(format!(
            "response retained state exceeds the {MAX_RESPONSE_RETAINED_NODES_V1}-node limit after parsing function-call arguments"
        )));
    }
    let value = parse_mcp_provider_json_text_v1(arguments, MAX_RESPONSE_ARGUMENT_BYTES)
        .map_err(|error| OxidraError::Provider(format!("invalid arguments JSON: {error}")))?;
    *parsed_argument_nodes = parsed_nodes;
    Ok(value)
}

fn clone_argument_value_with_response_budget_v1(
    value: &Value,
    retained_nodes: usize,
    parsed_argument_nodes: &mut usize,
) -> Result<Value> {
    let metrics = measure_provider_value_v1(value, "function-call arguments")?;
    let projected = parsed_argument_nodes
        .checked_add(metrics.nodes)
        .ok_or_else(|| OxidraError::Provider("parsed argument node count overflowed".to_owned()))?;
    if retained_nodes
        .checked_add(projected)
        .is_none_or(|total| total > MAX_RESPONSE_RETAINED_NODES_V1)
    {
        return Err(OxidraError::Provider(format!(
            "response retained state exceeds the {MAX_RESPONSE_RETAINED_NODES_V1}-node limit after cloning function-call arguments"
        )));
    }
    *parsed_argument_nodes = projected;
    Ok(value.clone())
}

fn fill_missing_function_call_arguments_v1(
    items: &mut [Value],
    argument_deltas: &BTreeMap<String, String>,
) {
    for item in items {
        if item.get("type").and_then(Value::as_str) != Some("function_call")
            || item.get("arguments").is_some()
        {
            continue;
        }
        let key = item
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| item.get("call_id").and_then(Value::as_str));
        let Some(arguments) = key.and_then(|key| argument_deltas.get(key)) else {
            continue;
        };
        if let Some(object) = item.as_object_mut() {
            object.insert("arguments".to_owned(), Value::String(arguments.clone()));
        }
    }
}

fn preflight_missing_argument_fanout_v1(
    items: &[Value],
    argument_deltas: &BTreeMap<String, String>,
) -> Result<()> {
    let mut total_bytes = 0usize;
    let mut call_ids = BTreeSet::new();
    for item in items {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            continue;
        }
        if let Some(call_id) = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
        {
            if !call_ids.insert(call_id) {
                return Err(OxidraError::Provider(format!(
                    "duplicate function_call id {call_id:?} in one response"
                )));
            }
        }
        if item.get("arguments").is_some() {
            continue;
        }
        let key = item
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| item.get("call_id").and_then(Value::as_str));
        let Some(arguments) = key.and_then(|key| argument_deltas.get(key)) else {
            continue;
        };
        total_bytes = total_bytes.checked_add(arguments.len()).ok_or_else(|| {
            OxidraError::Provider("function-call argument fan-out overflowed".to_owned())
        })?;
        if total_bytes > MAX_RESPONSE_RETAINED_BYTES_V1 {
            return Err(OxidraError::Provider(format!(
                "response retained state exceeds the {MAX_RESPONSE_RETAINED_BYTES_V1}-byte limit during function-call argument fan-out"
            )));
        }
    }
    Ok(())
}

fn validate_output_item_payload_profile_v1(item: &Value) -> Result<()> {
    match item.get("type").and_then(Value::as_str) {
        Some("function_call") => {
            if let Some(arguments) = item.get("arguments") {
                validate_argument_value_v1(arguments)?;
            }
        }
        Some("message") => {
            let mut text_bytes = 0usize;
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                for part in content {
                    if part.get("type").and_then(Value::as_str) != Some("output_text") {
                        continue;
                    }
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        text_bytes = text_bytes.checked_add(text.len()).ok_or_else(|| {
                            OxidraError::Provider("response text byte count overflowed".to_owned())
                        })?;
                        if text_bytes > MAX_RESPONSE_TEXT_BYTES {
                            return Err(OxidraError::Provider(format!(
                                "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
                            )));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_completed_output_profile_v1(items: &[Value]) -> Result<()> {
    let mut text_bytes = 0usize;
    for item in items {
        if item.get("type").and_then(Value::as_str) == Some("function_call") {
            if let Some(arguments) = item.get("arguments") {
                validate_argument_value_v1(arguments)?;
            }
        } else if item.get("type").and_then(Value::as_str) == Some("message") {
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                for part in content {
                    if part.get("type").and_then(Value::as_str) != Some("output_text") {
                        continue;
                    }
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        text_bytes = text_bytes.checked_add(text.len()).ok_or_else(|| {
                            OxidraError::Provider("response text byte count overflowed".to_owned())
                        })?;
                        if text_bytes > MAX_RESPONSE_TEXT_BYTES {
                            return Err(OxidraError::Provider(format!(
                                "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn build_turn(mut response: Value, mut stream_state: StreamState) -> Result<AssistantTurn> {
    measure_provider_value_v1(&response, "completed response")?;
    let response_output = match response
        .as_object_mut()
        .ok_or_else(|| {
            OxidraError::Provider("response.completed data must be an object".to_owned())
        })?
        .remove("output")
    {
        Some(Value::Array(items)) if !items.is_empty() => Some(items),
        Some(Value::Array(_)) => {
            return Err(OxidraError::Provider(
                "response.completed output array is empty".to_owned(),
            ));
        }
        Some(output) => {
            drop_json_value_iteratively(output);
            return Err(OxidraError::Provider(
                "response.completed output must be an array".to_owned(),
            ));
        }
        // Some compatible endpoints omit the final output field and provide
        // the complete projection through `response.output_item.*` events.
        // Only absence permits that fallback. An explicit empty or malformed
        // terminal output is canonical and must not revive earlier calls that
        // the terminal removed.
        None => None,
    };
    let response_metadata = measure_provider_value_v1(&response, "completed response metadata")?;
    let previous_output_metrics = stream_state.current_output_metrics();
    let mut output_items = if let Some(items) = response_output {
        items
    } else {
        std::mem::take(&mut stream_state.output_items_by_index)
            .into_values()
            .map(RetainedJsonValueV1::into_value)
            .collect()
    };
    // Complete streamed function-call argument deltas before measuring the
    // final output. Otherwise the later fallback insertion would add large
    // JSON strings after the retained budget had already been approved.
    preflight_missing_argument_fanout_v1(&output_items, &stream_state.argument_deltas)?;
    fill_missing_function_call_arguments_v1(&mut output_items, &stream_state.argument_deltas);
    stream_state.replace_final_output_budget(
        &output_items,
        previous_output_metrics,
        response_metadata,
    )?;
    if output_items.is_empty() {
        return Err(OxidraError::Provider(
            "response.completed has no output array".to_owned(),
        ));
    }
    validate_completed_output_profile_v1(&output_items)?;

    let mut text = String::new();
    let mut tool_calls = Vec::new();
    let mut parsed_argument_nodes = 0usize;
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
                    validate_argument_string_v1(arguments)?;
                    let arguments = parse_argument_json_with_response_budget_v1(
                        arguments,
                        stream_state.retained.nodes,
                        &mut parsed_argument_nodes,
                    )
                    .map_err(|error| {
                        OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                    })?;
                    preflight_provider_value_with_limit_v1(
                        &arguments,
                        "function-call arguments",
                        MAX_RESPONSE_ARGUMENT_BYTES,
                    )?;
                    arguments
                }
                Some(value) => {
                    preflight_provider_value_with_limit_v1(
                        value,
                        "function-call arguments",
                        MAX_RESPONSE_ARGUMENT_BYTES,
                    )?;
                    clone_argument_value_with_response_budget_v1(
                        value,
                        stream_state.retained.nodes,
                        &mut parsed_argument_nodes,
                    )?
                }
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
                    validate_argument_string_v1(arguments)?;
                    let arguments = parse_argument_json_with_response_budget_v1(
                        arguments,
                        stream_state.retained.nodes,
                        &mut parsed_argument_nodes,
                    )
                    .map_err(|error| {
                        OxidraError::Provider(format!("invalid arguments for {name}: {error}"))
                    })?;
                    preflight_provider_value_with_limit_v1(
                        &arguments,
                        "function-call arguments",
                        MAX_RESPONSE_ARGUMENT_BYTES,
                    )?;
                    arguments
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
                            if text.len().saturating_add(value.len()) > MAX_RESPONSE_TEXT_BYTES {
                                return Err(OxidraError::Provider(format!(
                                    "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
                                )));
                            }
                            text.push_str(value);
                        }
                    }
                }
            }
        }
    }
    validate_response_output_items(&output_items)?;

    // Displayed text must come only from the selected canonical output items,
    // including when they contain no text. The output-item fallback for an
    // absent terminal output was already selected above; standalone deltas must
    // not revive text removed by either terminal representation. Release their
    // spare capacity before cloning the output into `raw_response` below.
    drop(std::mem::take(&mut stream_state.text));
    // Argument deltas have now been copied into canonical output items and
    // parsed into the execution projection. They can otherwise occupy another
    // full response budget while `output_items.clone()` materializes the raw
    // audit response.
    drop(std::mem::take(&mut stream_state.argument_deltas));
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
        unknown_stream_events: std::mem::take(&mut stream_state.unknown_events)
            .into_iter()
            .map(RetainedJsonValueV1::into_value)
            .collect(),
    })
}

pub(crate) fn parse_usage(value: Option<&Value>) -> Usage {
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

fn validate_progress_event_payload_profile_v1(event_type: &str, payload: &Value) -> Result<()> {
    let text = match event_type {
        "response.output_text.done" => payload.get("text").and_then(Value::as_str),
        "response.content_part.added" | "response.content_part.done" => payload
            .get("part")
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("output_text"))
            .and_then(|part| part.get("text"))
            .and_then(Value::as_str),
        _ => None,
    };
    if text.is_some_and(|text| text.len() > MAX_RESPONSE_TEXT_BYTES) {
        return Err(OxidraError::Provider(format!(
            "response text exceeds the {MAX_RESPONSE_TEXT_BYTES}-byte limit"
        )));
    }
    Ok(())
}

fn is_known_progress_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "response.created"
            | "response.in_progress"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_summary_text.done"
            | "response.output_text.done"
    )
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

fn is_context_limit_error_body(body: &str) -> bool {
    // 只接受结构化错误码，避免把普通错误消息中的关键词误判为 context 超限。
    parse_mcp_provider_json_text_v1(body, MAX_ERROR_BODY)
        .ok()
        .is_some_and(|payload| is_context_limit_error_payload(&payload))
}

fn is_context_limit_error_payload(payload: &Value) -> bool {
    const CONTEXT_LIMIT_CODES: &[&str] = &[
        "context_length_exceeded",
        "context_window_exceeded",
        "input_too_long",
        "max_context_length_exceeded",
        "prompt_too_long",
    ];
    [
        payload.pointer("/error/code"),
        payload.pointer("/error/type"),
        payload.pointer("/response/error/code"),
        payload.pointer("/response/error/type"),
        payload.get("code"),
        payload.get("type"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(|code| CONTEXT_LIMIT_CODES.contains(&code))
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    struct NoopObserver;

    struct NeverPolledProvider;

    struct FailingObserver {
        error: Option<OxidraError>,
    }

    struct SleepingObserver {
        duration: Duration,
    }

    #[derive(Default)]
    struct RecordingObserver {
        events: Vec<ProviderEvent>,
    }

    fn json_object_with_encoded_len(encoded_len: usize) -> Value {
        const OBJECT_OVERHEAD: usize = br#"{"x":""}"#.len();
        assert!(encoded_len >= OBJECT_OVERHEAD);
        let value = json!({"x": "x".repeat(encoded_len - OBJECT_OVERHEAD)});
        assert_eq!(serde_json::to_vec(&value).unwrap().len(), encoded_len);
        value
    }

    fn argument_string_with_len(encoded_len: usize) -> String {
        const OBJECT_OVERHEAD: usize = br#"{"x":""}"#.len();
        assert!(encoded_len >= OBJECT_OVERHEAD);
        let value = format!(
            "{{\"x\":\"{}\"}}",
            "x".repeat(encoded_len - OBJECT_OVERHEAD)
        );
        assert_eq!(value.len(), encoded_len);
        value
    }

    fn wide_null_array(elements: usize) -> String {
        let mut value = String::with_capacity(elements.saturating_mul(5).saturating_add(2));
        value.push('[');
        for index in 0..elements {
            if index != 0 {
                value.push(',');
            }
            value.push_str("null");
        }
        value.push(']');
        value
    }

    impl stream_observer_sealed::Sealed for NoopObserver {}

    impl StreamObserver for NoopObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ResponseProvider for NeverPolledProvider {
        async fn respond(
            &self,
            _request: ResponseRequest,
            _observer: &mut dyn StreamObserver,
            _cancellation: CancellationToken,
        ) -> UncommittedProviderOutcomeV1 {
            panic!("unpolled Provider future executed")
        }
    }

    impl stream_observer_sealed::Sealed for FailingObserver {}

    impl StreamObserver for FailingObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            Err(self.error.take().expect("observer is called once"))
        }
    }

    impl stream_observer_sealed::Sealed for SleepingObserver {}

    impl StreamObserver for SleepingObserver {
        fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
            thread::sleep(self.duration);
            Ok(())
        }
    }

    impl stream_observer_sealed::Sealed for RecordingObserver {}

    impl StreamObserver for RecordingObserver {
        fn on_event(&mut self, event: ProviderEvent) -> Result<()> {
            self.events.push(event);
            Ok(())
        }
    }

    #[test]
    fn provider_debug_never_echoes_secret_bearing_url_components() {
        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "api-secret".to_owned(),
            api_base_url: url::Url::parse("https://example.test/v1/").unwrap(),
            model: "model".to_owned(),
        })
        .unwrap();
        let rendered = format!("{provider:?}");
        for secret in [
            "api-secret",
            "secret-user",
            "secret-password",
            "signature",
            "fragment",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn provider_constructor_rejects_secret_bearing_or_ambiguous_endpoint_urls() {
        for raw in [
            "https://secret-user:secret-password@example.test/v1/",
            "https://example.test/v1/?signature=secret",
            "https://example.test/v1/#fragment",
            "file:///tmp/provider",
        ] {
            let error = OpenAiResponsesProvider::new(ProviderConfig {
                api_key: "secret".to_owned(),
                api_base_url: url::Url::parse(raw).unwrap(),
                model: "model".to_owned(),
            })
            .expect_err("public ProviderConfig construction must use the same URL boundary");
            assert!(
                error.to_string().contains("API base URL"),
                "unexpected error for {raw}: {error}"
            );
        }
    }

    #[test]
    fn provider_constructor_canonicalizes_base_path_before_response_join() {
        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "secret".to_owned(),
            api_base_url: url::Url::parse("https://example.test/v1").unwrap(),
            model: "model".to_owned(),
        })
        .unwrap();
        assert_eq!(
            provider.config().api_base_url.as_str(),
            "https://example.test/v1/"
        );
        assert_eq!(
            provider.config().responses_url().unwrap().as_str(),
            "https://example.test/v1/responses"
        );
    }

    #[test]
    fn provider_constructor_accepts_loopback_http_for_sandbox_transports() {
        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse("http://127.0.0.1:43123/v1").unwrap(),
            model: "fixture-model".to_owned(),
        })
        .expect("loopback HTTP must remain available for sandbox fixtures");
        assert_eq!(
            provider.config().api_base_url.as_str(),
            "http://127.0.0.1:43123/v1/"
        );
    }

    #[test]
    fn prepared_request_debug_never_echoes_logical_or_wire_payload() {
        let prepared = PreparedResponseRequest::from_exact_body(
            ResponseRequest {
                instructions: Some("secret-instructions".to_owned()),
                input: vec![json!({"secret-input": "secret-input-value"})],
                tools: vec![ToolDefinition {
                    name: "secret-tool".to_owned(),
                    description: "secret-description".to_owned(),
                    input_schema: json!({"secret-schema": "secret-schema-value"}),
                }],
                model: Some("secret-model".to_owned()),
                max_output_tokens: Some(7),
            },
            json!({"secret-wire": "secret-wire-value"}),
            "secret-protocol",
            "secret-usage-domain",
        )
        .expect("bounded prepared request");

        let rendered = format!("{prepared:?}");
        for secret in [
            "secret-instructions",
            "secret-input",
            "secret-input-value",
            "secret-tool",
            "secret-description",
            "secret-schema",
            "secret-schema-value",
            "secret-model",
            "secret-wire",
            "secret-wire-value",
            "secret-protocol",
            "secret-usage-domain",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked {secret}: {rendered}"
            );
        }
        assert!(rendered.contains("body_bytes_len"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn exact_prepared_request_rejects_deep_body_with_iterative_drop() {
        let mut body = Value::Null;
        for _ in 0..50_000 {
            body = Value::Array(vec![body]);
        }
        let error = PreparedResponseRequest::from_exact_body(
            ResponseRequest::new(Vec::new(), Vec::new()),
            body,
            "openai_responses",
            "fixture-domain",
        )
        .expect_err("deep exact Provider body must fail before serialization");
        assert!(error.to_string().contains("not bounded"));
    }

    #[test]
    fn responses_request_rejects_aggregate_bytes_before_body_cloning() {
        let input = vec![
            json_object_with_encoded_len(MAX_EXACT_PREPARED_REQUEST_BYTES / 2 + 1024),
            json_object_with_encoded_len(MAX_EXACT_PREPARED_REQUEST_BYTES / 2 + 1024),
        ];
        let error = PreparedResponseRequest::from_responses_request(
            ResponseRequest::new(input, Vec::new()),
            "fixture-model",
            "fixture-domain",
        )
        .expect_err("individually valid inputs must share one prepared-body byte budget");
        assert!(
            error.to_string().contains("aggregate byte budget"),
            "unexpected aggregate request error: {error}"
        );
    }

    #[test]
    fn responses_request_rejects_aggregate_nodes_before_body_cloning() {
        let wide = || Value::Array(vec![Value::Null; MAX_EXACT_PREPARED_REQUEST_NODES_V1 / 2]);
        let error = PreparedResponseRequest::from_responses_request(
            ResponseRequest::new(vec![wide(), wide()], Vec::new()),
            "fixture-model",
            "fixture-domain",
        )
        .expect_err("individually valid inputs must share one prepared-body node budget");
        assert!(
            error.to_string().contains("aggregate node budget"),
            "unexpected aggregate request error: {error}"
        );
    }

    #[test]
    fn unpolled_response_future_drops_deep_request_iteratively() {
        let deeply_nested_value = || {
            let mut value = Value::Null;
            for _ in 0..50_000 {
                value = Value::Array(vec![value]);
            }
            value
        };
        let request = ResponseRequest::new(
            vec![deeply_nested_value()],
            vec![ToolDefinition {
                name: "deep-schema".to_owned(),
                description: "untrusted schema".to_owned(),
                input_schema: deeply_nested_value(),
            }],
        );
        let provider = NeverPolledProvider;
        let mut observer = NoopObserver;

        let future = provider.respond(request, &mut observer, CancellationToken::new());
        drop(future);
    }

    #[test]
    fn response_request_clone_handles_deep_input_and_schema_iteratively() {
        let deeply_nested_value = || {
            let mut value = Value::Null;
            for _ in 0..50_000 {
                value = Value::Array(vec![value]);
            }
            value
        };
        let request = ResponseRequest {
            instructions: Some("clone without recursive traversal".to_owned()),
            input: vec![deeply_nested_value()],
            tools: vec![ToolDefinition {
                name: "deep-schema".to_owned(),
                description: "schema clone regression".to_owned(),
                input_schema: deeply_nested_value(),
            }],
            model: Some("fixture-model".to_owned()),
            max_output_tokens: Some(1),
        };
        let cloned = request.clone();
        drop(cloned);
        drop(request);
    }

    #[test]
    fn uncommitted_outcome_drops_deep_success_and_failure_iteratively() {
        let mut deep_value = Value::Null;
        for _ in 0..50_000 {
            deep_value = Value::Array(vec![deep_value]);
        }
        drop(UncommittedProviderOutcomeV1::success(AssistantTurn {
            raw_response: deep_value,
            output_items: Vec::new(),
            text: String::new(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        }));

        let mut deep_error = OxidraError::Provider("terminal".to_owned());
        for _ in 0..50_000 {
            deep_error = OxidraError::Observer(Box::new(deep_error));
        }
        drop(UncommittedProviderOutcomeV1::failure(deep_error));
    }

    #[test]
    fn owned_turn_rejects_deep_payload_and_drops_it_iteratively() {
        let mut deep_value = Value::Null;
        for _ in 0..50_000 {
            deep_value = Value::Array(vec![deep_value]);
        }
        let owner = UncommittedProviderOutcomeV1::success(AssistantTurn {
            raw_response: deep_value,
            output_items: Vec::new(),
            text: String::new(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        })
        .into_result_v1()
        .expect("success owner");
        assert!(owner.preflight_bounded_v1().is_err());
        drop(owner);
    }

    #[test]
    fn uncommitted_outcome_debug_is_state_independent() {
        let success = UncommittedProviderOutcomeV1::success(AssistantTurn {
            raw_response: json!({"secret":"success"}),
            output_items: Vec::new(),
            text: "secret success".to_owned(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            unknown_stream_events: Vec::new(),
        });
        let failure = UncommittedProviderOutcomeV1::failure(OxidraError::Provider(
            "secret failure".to_owned(),
        ));
        let mut consumed = UncommittedProviderOutcomeV1::failure(OxidraError::Interrupted);
        let _ = consumed.result.take();

        let success_debug = format!("{success:?}");
        assert_eq!(success_debug, format!("{failure:?}"));
        assert_eq!(success_debug, format!("{consumed:?}"));
        assert!(!success_debug.contains("secret"));
    }

    #[tokio::test]
    async fn exact_wire_transport_does_not_follow_endpoint_redirects() {
        let redirect_listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("bind redirecting Provider");
        let redirect_address = redirect_listener.local_addr().expect("redirect address");
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind redirect target");
        let target_address = target_listener
            .local_addr()
            .expect("redirect target address");
        target_listener
            .set_nonblocking(true)
            .expect("make redirect target nonblocking");
        let redirect_server = thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().expect("accept Provider request");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).expect("read Provider request");
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/v1/responses\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write Provider redirect");
            stream.flush().expect("flush Provider redirect");
        });
        let (followed_tx, followed_rx) = mpsc::channel();
        let target_server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(750);
            loop {
                match target_listener.accept() {
                    Ok((mut stream, _)) => {
                        followed_tx.send(true).expect("report followed redirect");
                        let payload = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"redirected\"}]}]}}\n\n";
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            payload.len(),
                            payload
                        )
                        .expect("write redirect target response");
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            followed_tx.send(false).expect("report no redirect");
                            return;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept redirect target: {error}"),
                }
            }
        });
        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{redirect_address}/v1/"))
                .expect("parse redirecting Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create redirecting Provider");
        let request = provider
            .prepare_request(ResponseRequest::new(
                vec![json!({"role":"user","content":"do not redirect"})],
                Vec::new(),
            ))
            .expect("prepare redirect probe request");
        let error = provider
            .respond_prepared(request, &mut NoopObserver, CancellationToken::new())
            .await
            .into_result_v1()
            .expect_err("redirect must be terminal at the configured Provider endpoint");
        assert!(error.to_string().contains("307"), "{error}");
        redirect_server.join().expect("join redirecting Provider");
        assert!(
            !followed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("redirect follow result"),
            "sealed Provider body reached a non-admitted redirect endpoint"
        );
        target_server.join().expect("join redirect target");
    }

    #[tokio::test]
    async fn retry_observer_never_receives_provider_error_body_or_retry_after_value() {
        const SECRET_BODY: &str = r#"{"command":"calc.exe","path":"known-low-entropy"}"#;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind retry Provider");
        let address = listener.local_addr().expect("retry Provider address");
        let server = thread::spawn(move || {
            for _ in 0..MAX_ATTEMPTS {
                let (mut stream, _) = listener.accept().expect("accept retry Provider request");
                let mut request = [0u8; 8192];
                let _ = stream
                    .read(&mut request)
                    .expect("read retry Provider request");
                write!(
                    stream,
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    SECRET_BODY.len(),
                    SECRET_BODY,
                )
                .expect("write retry Provider response");
                stream.flush().expect("flush retry Provider response");
            }
        });

        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
                .expect("parse retry Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create retrying Provider");
        let request = provider
            .prepare_request(ResponseRequest::new(
                vec![json!({"role":"user","content":"retry safely"})],
                Vec::new(),
            ))
            .expect("prepare retry probe request");
        let mut observer = RecordingObserver::default();
        let error = provider
            .respond_prepared(request, &mut observer, CancellationToken::new())
            .await
            .into_result_v1()
            .expect_err("three retryable responses must fail");

        server.join().expect("join retry Provider");
        assert!(
            error.to_string().contains(SECRET_BODY),
            "the internal terminal error must retain the bounded Provider body: {error}"
        );
        assert_eq!(observer.events.len(), MAX_ATTEMPTS - 1);
        assert!(observer.events.iter().all(|event| matches!(
            event,
            ProviderEvent::Retry {
                classification: ProviderRetryClassV1::RetryableHttpStatus(429),
                ..
            }
        )));
        assert!(
            !format!("{:?}", observer.events).contains(SECRET_BODY),
            "Provider-controlled error body escaped through the retry observer"
        );
    }

    #[tokio::test]
    async fn exact_error_body_budget_is_not_marked_truncated() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind exact error Provider");
        let address = listener.local_addr().expect("exact error Provider address");
        let body = "x".repeat(MAX_ERROR_BODY);
        let server_body = body.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept exact error request");
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).expect("read exact error request");
            write!(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                server_body.len(),
                server_body,
            )
            .expect("write exact error response");
        });

        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
                .expect("parse exact error Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create exact error Provider");
        let result = provider
            .attempt(
                Bytes::from_static(b"{}"),
                &mut NoopObserver,
                &CancellationToken::new(),
                TokioInstant::now() + Duration::from_secs(30),
            )
            .await;
        server.join().expect("join exact error Provider");
        let reason = match result {
            AttemptResult::Retryable { reason, .. } => reason,
            _ => panic!("exact-size retryable error body did not remain retryable"),
        };
        assert!(reason.contains(&"x".repeat(64)));
        assert!(
            !reason.contains("<truncated>"),
            "an EOF-terminated body exactly at the budget was marked truncated"
        );
    }

    #[tokio::test]
    async fn unterminated_sse_event_is_rejected_at_the_raw_byte_boundary() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind oversized SSE Provider");
        let address = listener
            .local_addr()
            .expect("oversized SSE Provider address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept oversized SSE request");
            let mut request = [0u8; 8192];
            let _ = stream
                .read(&mut request)
                .expect("read oversized SSE request");
            let body_bytes = MAX_RESPONSE_EVENT_BYTES + 1;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {body_bytes}\r\nConnection: close\r\n\r\n"
            )
            .expect("write oversized SSE headers");

            // Never terminate the line or event. The client must reject while
            // bytes are still arriving rather than waiting for an SSE frame.
            if stream.write_all(b"data: ").is_ok() {
                let chunk = vec![b'x'; 64 * 1024];
                let mut remaining = body_bytes - b"data: ".len();
                while remaining != 0 {
                    let count = remaining.min(chunk.len());
                    if stream.write_all(&chunk[..count]).is_err() {
                        break;
                    }
                    remaining -= count;
                }
            }
        });

        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
                .expect("parse oversized SSE Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create oversized SSE Provider");
        let result = provider
            .attempt(
                Bytes::from_static(b"{}"),
                &mut NoopObserver,
                &CancellationToken::new(),
                TokioInstant::now() + Duration::from_secs(30),
            )
            .await;
        let AttemptResult::Fatal(error) = result else {
            panic!("unterminated oversized SSE event was not a fatal bounded failure")
        };
        assert!(
            error
                .to_string()
                .contains("SSE event exceeds the 33554432-byte limit"),
            "unexpected bounded SSE error: {error}"
        );
        server.join().expect("join oversized SSE Provider");
    }

    #[tokio::test]
    async fn absolute_response_deadline_is_not_refreshed_by_sse_keepalives() {
        const TEST_WALL_TIME: Duration = Duration::from_millis(250);

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind keepalive Provider");
        let address = listener.local_addr().expect("keepalive Provider address");
        let (stop_tx, stop_rx) = mpsc::channel();
        let (frames_tx, frames_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept keepalive request");
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).expect("read keepalive request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            )
            .expect("write keepalive headers");
            stream.flush().expect("flush keepalive headers");

            let mut frames = 0usize;
            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                if stream.write_all(b": keepalive\n\n").is_err() || stream.flush().is_err() {
                    break;
                }
                frames += 1;
                thread::sleep(Duration::from_millis(10));
            }
            frames_tx.send(frames).expect("report keepalive count");
        });

        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
                .expect("parse keepalive Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create keepalive Provider");
        let request = provider
            .prepare_request(ResponseRequest::new(
                vec![json!({"role":"user","content":"finish within the wall budget"})],
                Vec::new(),
            ))
            .expect("prepare keepalive request");
        let started = Instant::now();
        let error = provider
            .respond_prepared_with_wall_time_v1(
                request,
                &mut NoopObserver,
                CancellationToken::new(),
                TEST_WALL_TIME,
            )
            .await
            .expect_err("keepalive frames must not refresh the absolute response deadline");
        let elapsed = started.elapsed();

        stop_tx.send(()).expect("stop keepalive Provider");
        server.join().expect("join keepalive Provider");
        assert!(
            matches!(error, OxidraError::Provider(ref reason) if reason.contains("absolute wall-time limit")),
            "unexpected wall-time error: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "absolute response deadline was refreshed by keepalives: {elapsed:?}"
        );
        assert!(
            frames_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("keepalive frame count")
                >= 2,
            "test Provider did not send enough keepalives to exercise refresh resistance"
        );
    }

    #[tokio::test]
    async fn eof_does_not_commit_an_unterminated_completed_frame() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind truncated SSE Provider");
        let address = listener
            .local_addr()
            .expect("truncated SSE Provider address");
        let body = concat!(
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"must not commit\"}]}]}}\n"
        );
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept truncated SSE request");
            let mut request = [0u8; 8192];
            let _ = stream
                .read(&mut request)
                .expect("read truncated SSE request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .expect("write truncated completed frame");
        });

        let provider = OpenAiResponsesProvider::new(ProviderConfig {
            api_key: "fixture-key".to_owned(),
            api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
                .expect("parse truncated SSE Provider URL"),
            model: "fixture-model".to_owned(),
        })
        .expect("create truncated SSE Provider");
        let result = provider
            .attempt(
                Bytes::from_static(b"{}"),
                &mut NoopObserver,
                &CancellationToken::new(),
                TokioInstant::now() + Duration::from_secs(30),
            )
            .await;
        assert!(matches!(
            result,
            AttemptResult::Retryable {
                classification: ProviderRetryClassV1::StreamEndedBeforeFirstEvent,
                ..
            }
        ));
        server.join().expect("join truncated SSE Provider");
    }

    #[test]
    fn context_limit_classification_requires_a_known_structured_code() {
        for code in [
            "context_length_exceeded",
            "context_window_exceeded",
            "input_too_long",
            "max_context_length_exceeded",
            "prompt_too_long",
        ] {
            assert!(is_context_limit_error_payload(&json!({
                "error":{"code":code,"message":"too large"}
            })));
            assert!(is_context_limit_error_payload(&json!({
                "error":{"type":code,"message":"too large"}
            })));
        }
        assert!(!is_context_limit_error_payload(&json!({
            "error":{
                "code":"invalid_request_error",
                "message":"the words context length appear only in prose"
            }
        })));
        assert!(!is_context_limit_error_body(
            "not json: context_length_exceeded"
        ));
    }

    #[test]
    fn observer_callback_errors_are_wrapped_at_the_provider_boundary() {
        for original in [
            OxidraError::Config("render configuration failed".to_owned()),
            OxidraError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stdout closed",
            )),
        ] {
            let mut observer = FailingObserver {
                error: Some(original),
            };
            let error = notify_observer(
                &mut observer,
                ProviderEvent::TextDelta("partial".to_owned()),
            )
            .expect_err("observer failure must cross an explicit provenance boundary");
            assert!(matches!(error, OxidraError::Observer(_)));
        }

        let mut observer = FailingObserver {
            error: Some(OxidraError::observer(OxidraError::Config(
                "already wrapped".to_owned(),
            ))),
        };
        let error = notify_observer(
            &mut observer,
            ProviderEvent::TextDelta("partial".to_owned()),
        )
        .expect_err("an already wrapped observer error remains an observer error");
        let OxidraError::Observer(source) = error else {
            panic!("observer provenance was lost")
        };
        assert!(matches!(*source, OxidraError::Config(_)));
    }

    #[test]
    fn synchronous_event_processing_cannot_cross_the_absolute_deadline() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        let deadline = TokioInstant::now() + Duration::from_millis(10);
        let result = process_sse_event_with_guards_v1(
            SseEvent {
                event: "response.output_text.delta".to_owned(),
                data: r#"{"type":"response.output_text.delta","delta":"x"}"#.to_owned(),
                ..SseEvent::default()
            },
            &mut state,
            &mut saw_event,
            &mut SleepingObserver {
                duration: Duration::from_millis(30),
            },
            &CancellationToken::new(),
            deadline,
        );
        assert!(matches!(
            result,
            Err(AttemptResult::DeadlineExceeded { saw_event: true })
        ));
    }

    #[test]
    fn sse_envelope_and_payload_event_types_must_agree() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        let error = process_sse_event_v1(
            SseEvent {
                event: "response.completed".to_owned(),
                data: r#"{"type":"response.output_text.delta","delta":"forged"}"#.to_owned(),
                ..SseEvent::default()
            },
            &mut state,
            &mut saw_event,
            &mut NoopObserver,
        )
        .expect_err("mismatched SSE envelope/payload types must fail closed");
        let AttemptResult::Fatal(error) = error else {
            panic!("mismatched SSE event types were not fatal");
        };
        assert!(error.to_string().contains("does not match payload type"));
        assert!(
            !saw_event,
            "a mismatched event must not enter response state"
        );
    }

    #[test]
    fn parses_message_and_function_call_output() {
        let response = json!({
            "usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
            "output": [
                {"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]},
                {"type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"a\"}"}
            ]
        });
        let turn = build_turn(response, StreamState::default()).unwrap();
        assert_eq!(turn.text, "ok");
        assert_eq!(turn.tool_calls[0].id, "call_1");
        assert_eq!(turn.usage.total_tokens, 7);
    }

    #[test]
    fn completed_output_without_text_discards_streamed_text() {
        for item in [
            json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":""}]}),
            json!({"type":"message","role":"assistant","content":[]}),
            json!({"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"declined"}]}),
            json!({"type":"reasoning","summary":[]}),
        ] {
            let mut state = StreamState::default();
            state.append_text("discarded progress text").unwrap();
            let output = json!([item]);
            let turn = build_turn(json!({"output": output}), state).unwrap();
            assert!(turn.text.is_empty());
            assert_eq!(turn.raw_response["output"], output);
            assert_eq!(Value::Array(turn.output_items), output);
        }
    }

    #[test]
    fn absent_terminal_output_uses_only_text_from_stream_output_items() {
        for text in ["", "canonical final text"] {
            let mut state = StreamState::default();
            state.append_text("discarded progress text").unwrap();
            let item = json!({
                "type":"message","role":"assistant",
                "content":[{"type":"output_text","text":text}],
            });
            state.replace_output_item(0, item.clone()).unwrap();
            let turn = build_turn(json!({"usage": {}}), state).unwrap();
            assert_eq!(turn.text, text);
            assert_eq!(turn.raw_response["output"], json!([item]));
            assert_eq!(turn.output_items, vec![item]);
        }
    }

    #[test]
    fn rejects_provider_messages_with_non_assistant_roles() {
        for role in [None, Some("user"), Some("developer"), Some("system")] {
            let mut message = json!({
                "type": "message",
                "content": [{"type": "output_text", "text": "unsafe"}],
            });
            if let Some(role) = role {
                message["role"] = json!(role);
            }
            let error = build_turn(
                json!({"output": [message], "usage": {}}),
                StreamState::default(),
            )
            .expect_err("non-assistant output role must be rejected")
            .to_string();
            assert!(error.contains("must have role assistant"), "{error}");
        }
    }

    #[test]
    fn rebuilds_missing_completed_output_from_stream_items() {
        let mut state = StreamState::default();
        state
            .replace_output_item(
                0,
                json!({"type":"function_call","id":"item_1","name":"read"}),
            )
            .unwrap();
        state
            .replace_arguments("item_1".to_owned(), "{\"path\":\"calc.py\"}")
            .unwrap();
        let unknown = json!({"type":"future.event","x":1});
        let unknown_metrics = measure_provider_value_v1(&unknown, "test unknown event").unwrap();
        state.retain_unknown(unknown, unknown_metrics).unwrap();

        let turn = build_turn(json!({"usage": {}}), state).unwrap();
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
    fn missing_output_index_never_overwrites_sparse_stream_item() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        assert!(
            process_sse_event_v1(
                SseEvent {
                    event: "response.output_item.added".to_owned(),
                    data: json!({
                        "type": "response.output_item.added",
                        "output_index": 1,
                        "item": {"type": "message", "role": "assistant"}
                    })
                    .to_string(),
                    ..SseEvent::default()
                },
                &mut state,
                &mut saw_event,
                &mut NoopObserver,
            )
            .is_ok(),
            "the sparse indexed output item is valid"
        );
        assert!(
            process_sse_event_v1(
                SseEvent {
                    event: "response.output_item.added".to_owned(),
                    data: json!({
                        "type": "response.output_item.added",
                        "item": {"type": "message", "role": "assistant"}
                    })
                    .to_string(),
                    ..SseEvent::default()
                },
                &mut state,
                &mut saw_event,
                &mut NoopObserver,
            )
            .is_ok(),
            "an omitted output index receives a fresh monotonic index"
        );

        assert_eq!(state.output_items_by_index.len(), 2);
        assert!(state.output_items_by_index.contains_key(&1));
        assert!(state.output_items_by_index.contains_key(&2));
    }

    #[test]
    fn repeated_output_item_identity_reuses_its_implicit_index() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        for (event, text) in [
            ("response.output_item.added", "partial"),
            ("response.output_item.done", "final"),
        ] {
            assert!(
                process_sse_event_v1(
                    SseEvent {
                        event: event.to_owned(),
                        data: json!({
                            "type": event,
                            "item": {
                                "id": "item_1",
                                "type": "message",
                                "role": "assistant",
                                "content": [{"type": "output_text", "text": text}]
                            }
                        })
                        .to_string(),
                        ..SseEvent::default()
                    },
                    &mut state,
                    &mut saw_event,
                    &mut NoopObserver,
                )
                .is_ok(),
                "the same item lifecycle may omit output_index consistently"
            );
        }

        assert_eq!(state.output_items_by_index.len(), 1);
        let turn = build_turn(json!({"usage": {}}), state).expect("stream fallback is valid");
        assert_eq!(turn.output_items.len(), 1);
        assert_eq!(turn.text, "final");
    }

    #[test]
    fn output_item_identity_cannot_move_to_another_explicit_index() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        assert!(
            process_sse_event_v1(
                SseEvent {
                    event: "response.output_item.added".to_owned(),
                    data: json!({
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": {"id": "item_1", "type": "message", "role": "assistant"}
                    })
                    .to_string(),
                    ..SseEvent::default()
                },
                &mut state,
                &mut saw_event,
                &mut NoopObserver,
            )
            .is_ok()
        );

        let result = process_sse_event_v1(
            SseEvent {
                event: "response.output_item.done".to_owned(),
                data: json!({
                    "type": "response.output_item.done",
                    "output_index": 1,
                    "item": {"id": "item_1", "type": "message", "role": "assistant"}
                })
                .to_string(),
                ..SseEvent::default()
            },
            &mut state,
            &mut saw_event,
            &mut NoopObserver,
        )
        .expect_err("one item identity cannot move between output indexes");
        let AttemptResult::Fatal(error) = result else {
            panic!("identity/index conflict was not fatal");
        };
        assert!(
            error
                .to_string()
                .contains("already bound to output_index 0")
        );
        assert_eq!(state.output_items_by_index.len(), 1);
        assert!(state.output_items_by_index.contains_key(&0));
    }

    #[test]
    fn invalid_output_index_does_not_fall_back_to_an_implicit_index() {
        let mut state = StreamState::default();
        let mut saw_event = false;
        let result = process_sse_event_v1(
            SseEvent {
                event: "response.output_item.added".to_owned(),
                data: json!({
                    "type": "response.output_item.added",
                    "output_index": "not-a-number",
                    "item": {"type": "message", "role": "assistant"}
                })
                .to_string(),
                ..SseEvent::default()
            },
            &mut state,
            &mut saw_event,
            &mut NoopObserver,
        )
        .expect_err("a non-numeric output index must fail closed");
        let AttemptResult::Fatal(error) = result else {
            panic!("invalid output index was not fatal");
        };
        assert!(error.to_string().contains("invalid output_index"));
        assert!(state.output_items_by_index.is_empty());
    }

    #[test]
    fn explicit_completed_output_cannot_revive_streamed_function_calls() {
        for output in [Value::Array(Vec::new()), Value::Null, json!({"items": []})] {
            let mut state = StreamState::default();
            state
                .replace_output_item(
                    0,
                    json!({
                        "type":"function_call",
                        "id":"item_1",
                        "call_id":"call_1",
                        "name":"write",
                        "arguments":"{\"path\":\"must-not-run\"}"
                    }),
                )
                .expect("retain streamed function call");

            let error = build_turn(json!({"output": output, "usage": {}}), state)
                .expect_err("an explicit terminal output must be canonical");
            assert!(
                error.to_string().contains("response.completed output"),
                "unexpected rejection: {error}"
            );
        }
    }

    #[test]
    fn arguments_done_profile_accepts_exact_limit_and_rejects_plus_one_without_mutation() {
        let exact = argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES);
        let mut state = StreamState::default();
        state
            .replace_arguments("item-1".to_owned(), &exact)
            .expect("the exact argument limit is accepted");
        let retained_before = (
            state.retained.entries,
            state.retained.nodes,
            state.retained.bytes,
        );

        let error = state
            .replace_arguments(
                "item-1".to_owned(),
                &argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES + 1),
            )
            .expect_err("arguments.done must reject one byte above the frozen limit");
        assert!(error.to_string().contains("function-call arguments exceed"));
        assert_eq!(state.argument_deltas["item-1"], exact);
        assert_eq!(
            (
                state.retained.entries,
                state.retained.nodes,
                state.retained.bytes,
            ),
            retained_before,
            "a rejected replacement must not consume budget"
        );
    }

    #[test]
    fn output_item_arguments_share_done_profile_and_failed_replacement_is_atomic() {
        let exact = argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES);
        let original = json!({
            "type":"function_call",
            "id":"item-1",
            "call_id":"call-1",
            "name":"read",
            "arguments": exact,
        });
        let mut state = StreamState::default();
        state
            .replace_output_item(7, original.clone())
            .expect("the exact argument limit is accepted in an output item");
        let retained_before = (
            state.retained.entries,
            state.retained.nodes,
            state.retained.bytes,
        );

        let oversized = json!({
            "type":"function_call",
            "id":"item-1",
            "call_id":"call-1",
            "name":"read",
            "arguments": argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES + 1),
        });
        let error = state
            .replace_output_item(7, oversized)
            .expect_err("output item arguments must reject one byte above the frozen limit");
        assert!(error.to_string().contains("function-call arguments exceed"));
        assert_eq!(
            state.output_items_by_index[&7]
                .value
                .as_ref()
                .expect("retained output item"),
            &original
        );
        assert_eq!(
            (
                state.retained.entries,
                state.retained.nodes,
                state.retained.bytes,
            ),
            retained_before,
            "a rejected output replacement must preserve its old owner and budget"
        );
    }

    #[test]
    fn completed_arguments_share_the_same_string_and_json_limits() {
        let exact_string = argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES);
        let turn = build_turn(
            json!({
                "output":[{
                    "type":"function_call",
                    "call_id":"call-string",
                    "name":"read",
                    "arguments": exact_string,
                }]
            }),
            StreamState::default(),
        )
        .expect("completed string arguments at the exact limit are accepted");
        assert_eq!(
            turn.tool_calls[0].arguments["x"].as_str().unwrap().len(),
            MAX_RESPONSE_ARGUMENT_BYTES - br#"{"x":""}"#.len()
        );

        let error = build_turn(
            json!({
                "output":[{
                    "type":"function_call",
                    "call_id":"call-string",
                    "name":"read",
                    "arguments": argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES + 1),
                }]
            }),
            StreamState::default(),
        )
        .expect_err("completed string arguments above the limit must be rejected");
        assert!(error.to_string().contains("function-call arguments exceed"));

        let exact_json = json_object_with_encoded_len(MAX_RESPONSE_ARGUMENT_BYTES);
        build_turn(
            json!({
                "output":[{
                    "type":"function_call",
                    "call_id":"call-json",
                    "name":"read",
                    "arguments": exact_json,
                }]
            }),
            StreamState::default(),
        )
        .expect("completed JSON arguments at the exact encoded limit are accepted");

        let error = build_turn(
            json!({
                "output":[{
                    "type":"function_call",
                    "call_id":"call-json",
                    "name":"read",
                    "arguments": json_object_with_encoded_len(MAX_RESPONSE_ARGUMENT_BYTES + 1),
                }]
            }),
            StreamState::default(),
        )
        .expect_err("completed JSON arguments above the encoded limit must be rejected");
        assert!(error.to_string().contains("function-call arguments"));
    }

    #[test]
    fn sse_json_preflight_rejects_a_wide_array_before_value_allocation() {
        let mut data = String::from(r#"{"type":"future.wide","values":"#);
        data.push_str(&wide_null_array(MAX_RESPONSE_RETAINED_NODES_V1));
        data.push('}');
        assert!(data.len() < MAX_RESPONSE_EVENT_BYTES);

        let mut state = StreamState::default();
        let mut saw_event = false;
        let result = process_sse_event_v1(
            SseEvent {
                event: "future.wide".to_owned(),
                data,
                ..SseEvent::default()
            },
            &mut state,
            &mut saw_event,
            &mut NoopObserver,
        )
        .expect_err("a compact but over-wide SSE JSON tree must fail before Value parsing");
        let AttemptResult::Fatal(error) = result else {
            panic!("wide SSE JSON did not produce a bounded fatal failure")
        };
        assert!(
            error.to_string().contains("validation node budget"),
            "{error}"
        );
        assert!(state.unknown_events.is_empty());
    }

    #[test]
    fn function_argument_json_preflight_rejects_a_wide_array_before_value_allocation() {
        let arguments = wide_null_array(MAX_RESPONSE_RETAINED_NODES_V1);
        assert!(arguments.len() < MAX_RESPONSE_ARGUMENT_BYTES);
        let error = build_turn(
            json!({
                "output":[{
                    "type":"function_call",
                    "call_id":"call-wide",
                    "name":"read",
                    "arguments": arguments,
                }]
            }),
            StreamState::default(),
        )
        .expect_err("a compact but over-wide argument JSON tree must fail before Value parsing");
        assert!(
            error.to_string().contains("validation node budget"),
            "{error}"
        );
    }

    #[test]
    fn completed_text_limit_is_cumulative_across_output_items_and_parts() {
        let half = MAX_RESPONSE_TEXT_BYTES / 2;
        let exact = build_turn(
            json!({
                "output":[
                    {"type":"message","role":"assistant","content":[
                        {"type":"output_text","text":"a".repeat(half)},
                        {"type":"output_text","text":"b".repeat(half - 1)},
                    ]},
                    {"type":"message","role":"assistant","content":[
                        {"type":"output_text","text":"c"},
                    ]},
                ]
            }),
            StreamState::default(),
        )
        .expect("completed text at the exact aggregate limit is accepted");
        assert_eq!(exact.text.len(), MAX_RESPONSE_TEXT_BYTES);

        let error = build_turn(
            json!({
                "output":[
                    {"type":"message","role":"assistant","content":[
                        {"type":"output_text","text":"a".repeat(half)},
                        {"type":"output_text","text":"b".repeat(half)},
                    ]},
                    {"type":"message","role":"assistant","content":[
                        {"type":"output_text","text":"c"},
                    ]},
                ]
            }),
            StreamState::default(),
        )
        .expect_err("completed text one byte above the aggregate limit must be rejected");
        assert!(error.to_string().contains("response text exceeds"));
    }

    #[test]
    fn done_text_events_share_the_terminal_text_profile() {
        for (event_type, payload) in [
            (
                "response.output_text.done",
                json!({"text": "x".repeat(MAX_RESPONSE_TEXT_BYTES)}),
            ),
            (
                "response.content_part.done",
                json!({"part": {"type":"output_text", "text": "x".repeat(MAX_RESPONSE_TEXT_BYTES)}}),
            ),
        ] {
            validate_progress_event_payload_profile_v1(event_type, &payload)
                .expect("done text at the exact frozen limit is accepted");
        }

        for (event_type, payload) in [
            (
                "response.output_text.done",
                json!({"text": "x".repeat(MAX_RESPONSE_TEXT_BYTES + 1)}),
            ),
            (
                "response.content_part.done",
                json!({"part": {"type":"output_text", "text": "x".repeat(MAX_RESPONSE_TEXT_BYTES + 1)}}),
            ),
        ] {
            let error = validate_progress_event_payload_profile_v1(event_type, &payload)
                .expect_err("done text above the frozen limit must be rejected");
            assert!(error.to_string().contains("response text exceeds"));
        }
    }

    #[test]
    fn retained_argument_entry_limit_is_prospective() {
        let mut state = StreamState::default();
        for index in 0..MAX_RESPONSE_RETAINED_ENTRIES_V1 {
            state
                .append_argument_delta(format!("item-{index}"), "")
                .expect("entries through the frozen limit are accepted");
        }
        let retained_before = (
            state.retained.entries,
            state.retained.nodes,
            state.retained.bytes,
        );

        let error = state
            .append_argument_delta("one-too-many".to_owned(), "")
            .expect_err("a new retained entry above the limit must be rejected");
        assert!(error.to_string().contains("retained state exceeds"));
        assert!(!state.argument_deltas.contains_key("one-too-many"));
        assert_eq!(
            (
                state.retained.entries,
                state.retained.nodes,
                state.retained.bytes,
            ),
            retained_before
        );

        state
            .append_argument_delta("item-0".to_owned(), "x")
            .expect("updating an existing entry does not consume another entry slot");
        assert_eq!(state.retained.entries, MAX_RESPONSE_RETAINED_ENTRIES_V1);
    }

    #[test]
    fn retained_argument_bytes_are_budgeted_across_distinct_calls() {
        let delta = "x".repeat(MAX_RESPONSE_ARGUMENT_BYTES);
        let mut state = StreamState::default();
        for index in 0..7 {
            state
                .append_argument_delta(index.to_string(), &delta)
                .expect("seven maximum-sized argument buffers fit the response budget");
        }
        let retained_before = state.retained.bytes;
        let error = state
            .append_argument_delta("7".to_owned(), &delta)
            .expect_err("the aggregate response byte budget must reject the eighth buffer");
        assert!(error.to_string().contains("retained state exceeds"));
        assert_eq!(state.retained.bytes, retained_before);
        assert!(!state.argument_deltas.contains_key("7"));
    }

    #[test]
    fn retained_json_nodes_are_budgeted_across_output_items() {
        let item = || json!({"type":"future_item","nodes": vec![Value::Null; 131_100]});
        let mut state = StreamState::default();
        state
            .replace_output_item(0, item())
            .expect("one large output item fits the response node budget");
        let retained_before = state.retained.nodes;
        let error = state
            .replace_output_item(1, item())
            .expect_err("aggregate output-item nodes must be bounded");
        assert!(error.to_string().contains("retained state exceeds"));
        assert_eq!(state.retained.nodes, retained_before);
        assert!(!state.output_items_by_index.contains_key(&1));
    }

    #[test]
    fn completed_output_uses_the_same_aggregate_retained_budget() {
        let too_many_items = (0..=MAX_RESPONSE_RETAINED_ENTRIES_V1)
            .map(|_| json!({"type":"future_item","value":0}))
            .collect::<Vec<_>>();
        let error = build_turn(json!({"output": too_many_items}), StreamState::default())
            .expect_err("completed output must not bypass the retained entry limit");
        assert!(
            error.to_string().contains("retained state exceeds"),
            "{error}"
        );

        let half = MAX_RESPONSE_RETAINED_BYTES_V1 / 2;
        let retained_value = json!({"type":"future","blob":"x".repeat(half)});
        let retained_metrics = measure_provider_value_v1(&retained_value, "test retained")
            .expect("retained test value is within the per-event profile");
        let mut state = StreamState::default();
        state
            .retain_unknown(retained_value, retained_metrics)
            .expect("the first retained value fits");
        let completed_value = json!({"type":"future","blob":"y".repeat(half)});
        let error = build_turn(json!({"output": [completed_value]}), state)
            .expect_err("completed output must share bytes with earlier retained state");
        assert!(
            error.to_string().contains("retained state exceeds"),
            "{error}"
        );
    }

    #[test]
    fn completed_response_metadata_uses_the_aggregate_retained_budget() {
        let unknown = json!({
            "type":"future",
            "nodes":vec![Value::Null; 131_100],
        });
        let unknown_metrics = measure_provider_value_v1(&unknown, "test unknown event").unwrap();
        let mut state = StreamState::default();
        state
            .retain_unknown(unknown, unknown_metrics)
            .expect("one large unknown event fits the aggregate budget");

        let error = build_turn(
            json!({
                "metadata":vec![Value::Null; 131_100],
                "output":[{
                    "type":"message",
                    "role":"assistant",
                    "content":[{"type":"output_text","text":"ok"}],
                }],
            }),
            state,
        )
        .expect_err(
            "non-output raw response fields must share the retained node budget with stream state",
        );
        assert!(
            error.to_string().contains("retained state exceeds"),
            "{error}"
        );
    }

    #[test]
    fn parsed_argument_trees_share_the_response_node_budget() {
        let mut state = StreamState::default();
        let argument = wide_null_array(100_000);
        for index in 0..3 {
            state
                .replace_arguments(format!("item-{index}"), &argument)
                .expect("each argument string is within its individual profile");
        }
        let output = (0..3)
            .map(|index| {
                json!({
                    "type":"function_call",
                    "id":format!("item-{index}"),
                    "call_id":format!("call-{index}"),
                    "name":"read"
                })
            })
            .collect::<Vec<_>>();
        let error = build_turn(json!({"output": output}), state).expect_err(
            "individually valid argument trees must not multiply past the response node budget",
        );
        assert!(
            error.to_string().contains("retained state exceeds"),
            "{error}"
        );
    }

    #[test]
    fn missing_argument_fanout_is_bounded_before_string_cloning() {
        let mut state = StreamState::default();
        state
            .replace_arguments(
                "same".to_owned(),
                &argument_string_with_len(MAX_RESPONSE_ARGUMENT_BYTES),
            )
            .expect("the source argument fits its individual limit");
        let output = (0..9)
            .map(|index| {
                json!({
                    "type":"function_call",
                    "id":"same",
                    "call_id":format!("call-{index}"),
                    "name":"read"
                })
            })
            .collect::<Vec<_>>();
        let error = build_turn(json!({"output": output}), state)
            .expect_err("argument fan-out must be bounded before cloning large strings");
        assert!(
            error.to_string().contains("retained state exceeds"),
            "{error}"
        );

        let mut duplicate_state = StreamState::default();
        duplicate_state
            .replace_arguments("same".to_owned(), "{}")
            .expect("duplicate-id source argument fits");
        let duplicate_output = vec![
            json!({"type":"function_call","id":"same","name":"read"}),
            json!({"type":"function_call","id":"same","name":"read"}),
        ];
        let error = build_turn(json!({"output": duplicate_output}), duplicate_state)
            .expect_err("duplicate function-call identities must fail before fan-out");
        assert!(
            error.to_string().contains("duplicate function_call id"),
            "{error}"
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
        assert!(body.get("max_output_tokens").is_none());
    }

    #[test]
    fn request_can_limit_compaction_output_without_tools() {
        let config = ProviderConfig {
            api_key: "x".to_owned(),
            api_base_url: url::Url::parse("https://example.test/v1/").unwrap(),
            model: "m".to_owned(),
        };
        let provider = OpenAiResponsesProvider::new(config).unwrap();
        let mut request =
            ResponseRequest::new(vec![json!({"role": "user", "content": "x"})], Vec::new());
        request.max_output_tokens = Some(8192);
        let body = provider.request_body(&request);
        assert_eq!(body["max_output_tokens"], 8192);
        assert_eq!(body["tools"], json!([]));
    }

    #[test]
    fn recognizes_reasoning_summary_progress_events() {
        for event_type in [
            "response.reasoning_summary_part.added",
            "response.reasoning_summary_part.done",
            "response.reasoning_summary_text.delta",
            "response.reasoning_summary_text.done",
        ] {
            assert!(is_known_progress_event(event_type));
        }
        assert!(!is_known_progress_event("response.future.event"));
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
