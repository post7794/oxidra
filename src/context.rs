//! Deterministic context measurement and auditable Provider usage anchors.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::{ContextLimits, ProviderConfig};
use crate::error::{OxidraError, Result};
use crate::provider::{PreparedResponseRequest, ResponseRequest, prepared_request_body};
use crate::session::JournalEvent;
use crate::types::ToolDefinition;

pub const CONTEXT_MEASUREMENT_VERSION: u32 = 2;
pub const CONTEXT_ESTIMATOR_VERSION: u32 = 1;
pub const REQUEST_SHAPE_VERSION: u32 = 1;
pub const TOOL_SNAPSHOT_VERSION: u32 = 1;
/// Version of the Provider-visible tool surface envelope used by the first
/// MCP-capable request path.  This is deliberately separate from
/// [`TOOL_SNAPSHOT_VERSION`]: the latter is already persisted by existing
/// sessions and must remain byte-for-byte compatible.
pub const TOOL_SURFACE_SNAPSHOT_VERSION_V1: u32 = 1;
pub const MCP_SURFACE_CLAIM_VERSION_V1: u32 = 1;
pub const TOOL_SURFACE_MAX_TOOLS_V1: usize = 512;
pub const TOOL_SURFACE_MAX_BYTES_V1: usize = 512 * 1024;
pub const PROVIDER_PROTOCOL_OPENAI_RESPONSES: &str = "openai_responses";
pub const AUTOMATIC_COMPACTION_PLANNING_VERSION_V1: u32 = 1;
pub const AUTOMATIC_COMPACTION_PLANNING_VERSION: u32 = AUTOMATIC_COMPACTION_PLANNING_VERSION_V1;

#[derive(Clone, Debug)]
pub struct ContextRuntime {
    pub model: String,
    pub provider_protocol: String,
    pub provider_usage_domain: String,
    pub limits: ContextLimits,
}

impl ContextRuntime {
    pub fn from_provider(provider: &ProviderConfig, limits: ContextLimits) -> Result<Self> {
        Ok(Self {
            model: provider.model.clone(),
            provider_protocol: PROVIDER_PROTOCOL_OPENAI_RESPONSES.to_owned(),
            provider_usage_domain: provider_usage_domain(provider)?,
            limits,
        })
    }

    pub fn for_tests(model: impl Into<String>, limits: ContextLimits) -> Self {
        let model = model.into();
        Self {
            provider_usage_domain: digest_bytes(
                b"oxidra.provider-usage-domain.test.v1\0",
                model.as_bytes(),
            ),
            model,
            provider_protocol: PROVIDER_PROTOCOL_OPENAI_RESPONSES.to_owned(),
            limits,
        }
    }

    pub fn configured_event_data(&self) -> Value {
        json!({
            "measurement_version": CONTEXT_MEASUREMENT_VERSION,
            "estimator_version": CONTEXT_ESTIMATOR_VERSION,
            "request_shape_version": REQUEST_SHAPE_VERSION,
            "model": self.model,
            "provider_protocol": self.provider_protocol,
            "provider_usage_domain": self.provider_usage_domain,
            "context_window": self.limits.context_window,
            "reserve_tokens": self.limits.reserve_tokens,
            "usable_tokens": self.limits.usable_tokens(),
            "trigger_tokens": self.limits.trigger_tokens(),
            "target_tokens": self.limits.target_tokens(),
            "context_window_source": self.limits.context_window_source,
            "reserve_tokens_source": self.limits.reserve_tokens_source,
        })
    }

    pub fn configured_event_data_with_compaction(&self, automatic_compaction: bool) -> Value {
        let mut data = self.configured_event_data();
        data["automatic_compaction"] = json!({
            "enabled": automatic_compaction,
            "source": if automatic_compaction { "experimental_cli" } else { "default_off" },
            "planning_version": AUTOMATIC_COMPACTION_PLANNING_VERSION,
        });
        data
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedRequestMeasurement {
    pub measurement_version: u32,
    pub estimator_version: u32,
    pub request_shape_version: u32,
    pub request_digest: String,
    pub estimated_input_tokens: u64,
    /// 完整 Provider JSON 的 UTF-8 字节数，仅用于审计估算密度，不作为 token 上限。
    #[serde(default)]
    pub serialized_request_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ToolSnapshot {
    pub version: u32,
    pub digest: String,
    pub tools: Vec<ToolDefinition>,
}

/// Exact identity of one MCP alias in a Provider-visible tool surface.
///
/// The registry digest is not invertible: by itself it cannot prove which
/// server/raw tool a Provider alias denotes.  A surface snapshot therefore
/// carries this bounded binding table as well as the registry epoch/digest.
/// `definition_digest` binds the alias to the exact definition sent to the
/// Provider; `output_schema_digest` is retained for the model-facing result
/// profile even though output schemas are not part of a Responses request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSurfaceBindingV1 {
    provider_name: String,
    server_name: String,
    raw_tool_name: String,
    protocol_version: String,
    definition_digest: String,
    output_schema_digest: Option<String>,
}

impl McpSurfaceBindingV1 {
    /// Build a binding identity from the discovered registry entry without
    /// copying the untrusted output schema into the Provider-facing event.
    pub(crate) fn from_parts(
        provider_name: impl Into<String>,
        server_name: impl Into<String>,
        raw_tool_name: impl Into<String>,
        protocol_version: impl Into<String>,
        definition: &ToolDefinition,
        output_schema: Option<&Value>,
    ) -> Result<Self> {
        let provider_name = provider_name.into();
        let server_name = server_name.into();
        let raw_tool_name = raw_tool_name.into();
        let protocol_version = protocol_version.into();
        for (label, value) in [
            ("provider_name", provider_name.as_str()),
            ("server_name", server_name.as_str()),
            ("raw_tool_name", raw_tool_name.as_str()),
            ("protocol_version", protocol_version.as_str()),
        ] {
            validate_surface_identity(label, value)?;
        }
        let definition_digest = digest_json_value(
            b"oxidra.mcp-surface-definition.v1\0",
            &serde_json::to_value(definition)?,
        )?;
        let output_schema_digest = output_schema
            .map(|schema| digest_json_value(b"oxidra.mcp-output-schema.v1\0", schema))
            .transpose()?;
        Ok(Self {
            provider_name,
            server_name,
            raw_tool_name,
            protocol_version,
            definition_digest,
            output_schema_digest,
        })
    }

    fn validate(&self) -> Result<()> {
        for (label, value) in [
            ("provider_name", self.provider_name.as_str()),
            ("server_name", self.server_name.as_str()),
            ("raw_tool_name", self.raw_tool_name.as_str()),
            ("protocol_version", self.protocol_version.as_str()),
        ] {
            validate_surface_identity(label, value)?;
        }
        validate_surface_digest("definition_digest", &self.definition_digest)?;
        if let Some(digest) = &self.output_schema_digest {
            validate_surface_digest("output_schema_digest", digest)?;
        }
        Ok(())
    }

    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn raw_tool_name(&self) -> &str {
        &self.raw_tool_name
    }

    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    pub fn output_schema_digest(&self) -> Option<&str> {
        self.output_schema_digest.as_deref()
    }
}

/// Writer-side claim tying one Provider-visible tool surface to an activated
/// MCP registry epoch.
///
/// Its shape supplies the binding material required by a future v3 activation
/// reader. Current coordinator/call-chain v2 activation rows do not bind the
/// definition/output-schema digests, so this value is not yet standalone
/// offline proof of the live registry surface.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpSurfaceClaimV1 {
    version: u32,
    registry_epoch_id: String,
    registry_digest: String,
    bindings: Vec<McpSurfaceBindingV1>,
}

impl McpSurfaceClaimV1 {
    pub(crate) fn new(
        registry_epoch_id: impl Into<String>,
        registry_digest: impl Into<String>,
        mut bindings: Vec<McpSurfaceBindingV1>,
    ) -> Result<Self> {
        bindings.sort_by(|left, right| left.provider_name.cmp(&right.provider_name));
        let claim = Self {
            version: MCP_SURFACE_CLAIM_VERSION_V1,
            registry_epoch_id: registry_epoch_id.into(),
            registry_digest: registry_digest.into(),
            bindings,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MCP_SURFACE_CLAIM_VERSION_V1 {
            return Err(OxidraError::Session(format!(
                "unsupported MCP surface claim version {}",
                self.version
            )));
        }
        validate_surface_uuid_v7("registry_epoch_id", &self.registry_epoch_id)?;
        validate_surface_digest("registry_digest", &self.registry_digest)?;
        if self.bindings.len() > TOOL_SURFACE_MAX_TOOLS_V1 {
            return Err(OxidraError::Session(format!(
                "MCP surface exposes more than {TOOL_SURFACE_MAX_TOOLS_V1} bindings"
            )));
        }
        let mut previous = None;
        for binding in &self.bindings {
            binding.validate()?;
            if let Some(previous) = previous {
                if previous >= binding.provider_name.as_str() {
                    return Err(OxidraError::Session(
                        "MCP surface bindings must be strictly sorted and unique".to_owned(),
                    ));
                }
            }
            previous = Some(binding.provider_name.as_str());
        }
        Ok(())
    }

    pub fn registry_epoch_id(&self) -> &str {
        &self.registry_epoch_id
    }

    pub fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    pub fn bindings(&self) -> &[McpSurfaceBindingV1] {
        &self.bindings
    }
}

/// Versioned, exact Provider-visible tool surface.
///
/// Existing sessions continue to use [`ToolSnapshot`] v1.  New MCP-capable
/// request code should use this envelope instead of bolting registry fields
/// onto the old event: the `mcp` claim is part of the digest, and the binding
/// table provides the material a v3 validator will need to prove
/// alias-to-definition identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ToolSurfaceSnapshotV1 {
    version: u32,
    digest: String,
    tools: Vec<ToolDefinition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpSurfaceClaimV1>,
}

impl ToolSurfaceSnapshotV1 {
    /// Decode the exact parsed-JSON `context.tools` representation for
    /// surface protocol v1.
    ///
    /// Serde structs intentionally remain usable by ordinary callers and do
    /// not globally opt into `deny_unknown_fields`.  The durable reader must
    /// nevertheless reject presentation fields that Serde would otherwise
    /// discard: Provider tool objects and MCP binding rows are part of the
    /// authority being proved.  Round-tripping the decoded value therefore
    /// freezes the complete semantic JSON shape without changing the
    /// historical `ToolSnapshot` reader.  The journal parser has already
    /// discarded object-key order and number lexemes; this method does not
    /// claim byte-for-byte wire identity.
    pub(crate) fn from_exact_journal_value(value: &Value) -> Result<Self> {
        let snapshot: Self = serde_json::from_value(value.clone()).map_err(|error| {
            OxidraError::Session(format!(
                "context.tools does not contain a valid tool surface snapshot v1: {error}"
            ))
        })?;
        snapshot.validate()?;
        if serde_json::to_value(&snapshot)? != *value {
            return Err(OxidraError::Session(
                "context.tools tool surface snapshot v1 is not in its exact canonical shape"
                    .to_owned(),
            ));
        }
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != TOOL_SURFACE_SNAPSHOT_VERSION_V1 {
            return Err(OxidraError::Session(format!(
                "unsupported tool surface snapshot version {}",
                self.version
            )));
        }
        validate_tool_definitions(&self.tools)?;
        if let Some(claim) = &self.mcp {
            claim.validate()?;
            let definition_digests = self
                .tools
                .iter()
                .map(|definition| {
                    digest_json_value(
                        b"oxidra.mcp-surface-definition.v1\0",
                        &serde_json::to_value(definition)?,
                    )
                    .map(|digest| (definition.name.as_str(), (definition, digest)))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            for binding in &claim.bindings {
                let Some((definition, actual)) =
                    definition_digests.get(binding.provider_name.as_str())
                else {
                    return Err(OxidraError::Session(format!(
                        "MCP surface binding {} is absent from tool definitions",
                        binding.provider_name
                    )));
                };
                crate::mcp::schema::validate_tool_schema(
                    &definition.input_schema,
                    "MCP surface inputSchema",
                )
                .map_err(|error| {
                    OxidraError::Session(format!(
                        "MCP surface definition {} has an invalid input schema: {error}",
                        binding.provider_name
                    ))
                })?;
                if actual != &binding.definition_digest {
                    return Err(OxidraError::Session(format!(
                        "MCP surface definition digest mismatch for {}",
                        binding.provider_name
                    )));
                }
            }
        }
        let expected = surface_snapshot_digest(&self.tools, self.mcp.as_ref())?;
        if expected != self.digest {
            return Err(OxidraError::Session(
                "tool surface snapshot digest mismatch".to_owned(),
            ));
        }
        let encoded = serde_json::to_vec(self)?;
        if encoded.len() > TOOL_SURFACE_MAX_BYTES_V1 {
            return Err(OxidraError::Session(format!(
                "tool surface snapshot exceeds {TOOL_SURFACE_MAX_BYTES_V1} bytes"
            )));
        }
        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    pub fn mcp(&self) -> Option<&McpSurfaceClaimV1> {
        self.mcp.as_ref()
    }
}

/// Build a canonical MCP-capable tool surface.  The input order is retained
/// because it is the order sent to the Provider; only the claim binding table
/// is sorted for deterministic writer-side validation.
pub(crate) fn snapshot_tool_surface_v1(
    tools: &[ToolDefinition],
    mcp: Option<McpSurfaceClaimV1>,
) -> Result<ToolSurfaceSnapshotV1> {
    validate_tool_definitions(tools)?;
    if let Some(claim) = &mcp {
        claim.validate()?;
    }
    let snapshot = ToolSurfaceSnapshotV1 {
        version: TOOL_SURFACE_SNAPSHOT_VERSION_V1,
        digest: surface_snapshot_digest(tools, mcp.as_ref())?,
        tools: tools.to_vec(),
        mcp,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextEstimateMethod {
    FullRequest,
    UsageAnchor,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextDecision {
    pub measurement: PreparedRequestMeasurement,
    pub provider_usage_domain: String,
    pub method: ContextEstimateMethod,
    pub anchor_response_seq: Option<u64>,
    pub anchor_response_attempt_id: Option<String>,
    pub anchor_reported_input_tokens: Option<u64>,
    pub anchor_estimated_input_tokens: Option<u64>,
    pub estimate_delta_tokens: Option<i64>,
    pub anchor_rejection_reason: Option<String>,
    pub estimated_next_input_tokens: u64,
    pub context_window: Option<u64>,
    pub reserve_tokens: u64,
    pub usable_tokens: Option<u64>,
    pub trigger_tokens: Option<u64>,
    pub target_tokens: Option<u64>,
    pub request_journal_through_seq: Option<u64>,
    pub checkpoint_id: Option<String>,
    pub checkpoint_covers_through_seq: Option<u64>,
    pub instructions_event_seq: Option<u64>,
    pub configured_event_seq: Option<u64>,
    pub tools_event_seq: u64,
}

impl ContextDecision {
    pub fn audit_value(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }
}

#[derive(Clone, Debug)]
struct UsageAnchor {
    response_seq: u64,
    response_attempt_id: String,
    reported_input_tokens: u64,
    estimated_input_tokens: u64,
}

#[derive(Deserialize)]
struct StoredRequestContext {
    measurement: PreparedRequestMeasurement,
    provider_usage_domain: String,
}

pub fn measure_prepared_request(
    request: &ResponseRequest,
    runtime: &ContextRuntime,
) -> Result<PreparedRequestMeasurement> {
    let body = prepared_request_body(request, &runtime.model);
    let bytes = serde_json::to_vec(&body)?;
    measure_exact_prepared_request(&body, &bytes)
}

/// Measure the exact serialized Provider body that a prepared dispatch token
/// owns. Unlike [`measure_prepared_request`], this cannot drift from a
/// Provider-specific effective model or request-shape transformation.
pub fn measure_provider_prepared_request(
    request: &PreparedResponseRequest,
) -> Result<PreparedRequestMeasurement> {
    measure_exact_prepared_request(request.body(), request.body_bytes())
}

pub(crate) fn measure_exact_prepared_request(
    body: &Value,
    bytes: &[u8],
) -> Result<PreparedRequestMeasurement> {
    Ok(PreparedRequestMeasurement {
        measurement_version: CONTEXT_MEASUREMENT_VERSION,
        estimator_version: CONTEXT_ESTIMATOR_VERSION,
        request_shape_version: REQUEST_SHAPE_VERSION,
        request_digest: digest_bytes(b"oxidra.prepared-request.v1\0", bytes),
        estimated_input_tokens: estimate_json_tokens(body)?,
        serialized_request_bytes: bytes.len() as u64,
    })
}

pub fn snapshot_tools(tools: &[ToolDefinition]) -> Result<ToolSnapshot> {
    let bytes = serde_json::to_vec(tools)?;
    Ok(ToolSnapshot {
        version: TOOL_SNAPSHOT_VERSION,
        digest: digest_bytes(b"oxidra.context-tools.v1\0", &bytes),
        tools: tools.to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn decide_context(
    events: &[JournalEvent],
    runtime: &ContextRuntime,
    measurement: PreparedRequestMeasurement,
    request_journal_through_seq: Option<u64>,
    checkpoint_id: Option<String>,
    checkpoint_covers_through_seq: Option<u64>,
    instructions_event_seq: Option<u64>,
    configured_event_seq: Option<u64>,
    tools_event_seq: u64,
) -> Result<ContextDecision> {
    let anchor = latest_comparable_anchor(events, runtime)?;
    let (
        method,
        anchor_response_seq,
        anchor_response_attempt_id,
        anchor_reported_input_tokens,
        anchor_estimated_input_tokens,
        estimate_delta_tokens,
        anchor_rejection_reason,
        estimated_next_input_tokens,
    ) = match anchor {
        Some(anchor) => {
            let delta = i128::from(measurement.estimated_input_tokens)
                - i128::from(anchor.estimated_input_tokens);
            let delta_i64 = i64::try_from(delta).map_err(|_| {
                OxidraError::Session("prepared request estimate delta exceeds i64".to_owned())
            })?;
            let anchor_error = anchor
                .reported_input_tokens
                .abs_diff(anchor.estimated_input_tokens);
            let allowed_error = anchor.estimated_input_tokens.max(1_024).saturating_mul(4);
            let candidate = i128::from(anchor.reported_input_tokens) + delta;
            let rejection = if anchor_error > allowed_error {
                Some(format!(
                    "anchor estimator error {anchor_error} exceeds tolerance {allowed_error}"
                ))
            } else if candidate <= 0 {
                Some("anchor delta produced a non-positive estimate".to_owned())
            } else {
                None
            };
            if let Some(reason) = rejection {
                (
                    ContextEstimateMethod::FullRequest,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(reason),
                    measurement.estimated_input_tokens,
                )
            } else {
                let next = u64::try_from(candidate).unwrap_or(u64::MAX);
                (
                    ContextEstimateMethod::UsageAnchor,
                    Some(anchor.response_seq),
                    Some(anchor.response_attempt_id),
                    Some(anchor.reported_input_tokens),
                    Some(anchor.estimated_input_tokens),
                    Some(delta_i64),
                    None,
                    next,
                )
            }
        }
        None => (
            ContextEstimateMethod::FullRequest,
            None,
            None,
            None,
            None,
            None,
            None,
            measurement.estimated_input_tokens,
        ),
    };
    Ok(ContextDecision {
        measurement,
        provider_usage_domain: runtime.provider_usage_domain.clone(),
        method,
        anchor_response_seq,
        anchor_response_attempt_id,
        anchor_reported_input_tokens,
        anchor_estimated_input_tokens,
        estimate_delta_tokens,
        anchor_rejection_reason,
        estimated_next_input_tokens,
        context_window: runtime.limits.context_window,
        reserve_tokens: runtime.limits.reserve_tokens,
        usable_tokens: runtime.limits.usable_tokens(),
        trigger_tokens: runtime.limits.trigger_tokens(),
        target_tokens: runtime.limits.target_tokens(),
        request_journal_through_seq,
        checkpoint_id,
        checkpoint_covers_through_seq,
        instructions_event_seq,
        configured_event_seq,
        tools_event_seq,
    })
}

fn latest_comparable_anchor(
    events: &[JournalEvent],
    runtime: &ContextRuntime,
) -> Result<Option<UsageAnchor>> {
    for completed in events
        .iter()
        .rev()
        .filter(|event| event.kind == "response.completed")
    {
        let Some(response_attempt_id) = completed
            .data
            .get("response_attempt_id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(reported_input_tokens) = completed
            .data
            .get("raw_response")
            .and_then(|response| response.get("usage"))
            .and_then(|usage| usage.get("input_tokens"))
            .and_then(Value::as_u64)
        else {
            continue;
        };
        let Some(started) = events.iter().rev().find(|event| {
            event.seq < completed.seq
                && event.kind == "response.started"
                && event.turn_id == completed.turn_id
                && event
                    .data
                    .get("response_attempt_id")
                    .and_then(Value::as_str)
                    == Some(response_attempt_id)
        }) else {
            continue;
        };
        let Some(context) = started.data.get("context") else {
            continue;
        };
        let stored: StoredRequestContext =
            serde_json::from_value(context.clone()).map_err(|error| {
                OxidraError::Session(format!(
                    "response.started at seq {} has invalid context measurement: {error}",
                    started.seq
                ))
            })?;
        if stored.provider_usage_domain != runtime.provider_usage_domain
            || stored.measurement.measurement_version != CONTEXT_MEASUREMENT_VERSION
            || stored.measurement.estimator_version != CONTEXT_ESTIMATOR_VERSION
            || stored.measurement.request_shape_version != REQUEST_SHAPE_VERSION
        {
            continue;
        }
        return Ok(Some(UsageAnchor {
            response_seq: completed.seq,
            response_attempt_id: response_attempt_id.to_owned(),
            reported_input_tokens,
            estimated_input_tokens: stored.measurement.estimated_input_tokens,
        }));
    }
    Ok(None)
}

pub(crate) fn provider_usage_domain(provider: &ProviderConfig) -> Result<String> {
    let mut endpoint = provider.api_base_url.clone();
    endpoint
        .set_username("")
        .map_err(|_| OxidraError::Config("API base URL has invalid user information".to_owned()))?;
    endpoint.set_password(None).map_err(|_| {
        OxidraError::Config("API base URL has invalid password information".to_owned())
    })?;
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let payload = serde_json::to_vec(&json!({
        "protocol": PROVIDER_PROTOCOL_OPENAI_RESPONSES,
        "endpoint": endpoint.as_str(),
        "model": provider.model,
    }))?;
    Ok(digest_bytes(b"oxidra.provider-usage-domain.v1\0", &payload))
}

fn estimate_json_tokens(value: &Value) -> Result<u64> {
    let text = serde_json::to_string(value)?;
    let mut ascii = 0u64;
    let mut non_ascii = 0u64;
    for character in text.chars() {
        if character.is_ascii() {
            ascii = ascii.saturating_add(1);
        } else {
            non_ascii = non_ascii.saturating_add(1);
        }
    }
    Ok(ascii
        .div_ceil(4)
        .saturating_add(non_ascii)
        .saturating_add(256))
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Serialize)]
struct ToolSurfaceDigestPayload<'a> {
    version: u32,
    tools: &'a [ToolDefinition],
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<&'a McpSurfaceClaimV1>,
}

fn surface_snapshot_digest(
    tools: &[ToolDefinition],
    mcp: Option<&McpSurfaceClaimV1>,
) -> Result<String> {
    let payload = ToolSurfaceDigestPayload {
        version: TOOL_SURFACE_SNAPSHOT_VERSION_V1,
        tools,
        mcp,
    };
    Ok(digest_bytes(
        b"oxidra.context-tool-surface.v1\0",
        &serde_json::to_vec(&payload)?,
    ))
}

fn digest_json_value(domain: &[u8], value: &Value) -> Result<String> {
    Ok(digest_bytes(domain, &serde_json::to_vec(value)?))
}

fn validate_tool_definitions(tools: &[ToolDefinition]) -> Result<()> {
    if tools.len() > TOOL_SURFACE_MAX_TOOLS_V1 {
        return Err(OxidraError::Session(format!(
            "tool surface exposes more than {TOOL_SURFACE_MAX_TOOLS_V1} tools"
        )));
    }
    let mut names = BTreeSet::new();
    let mut encoded_bytes = 2usize; // JSON array brackets.
    for tool in tools {
        if tool.name.is_empty()
            || tool.name.len() > 64
            || !tool
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(OxidraError::Session(format!(
                "tool definition name is invalid or exceeds 64 bytes: {:?}",
                tool.name
            )));
        }
        if !names.insert(tool.name.as_str()) {
            return Err(OxidraError::Session(format!(
                "duplicate tool definition name {:?}",
                tool.name
            )));
        }
        let tool_bytes = serde_json::to_vec(tool)?.len();
        encoded_bytes = encoded_bytes
            .checked_add(tool_bytes)
            .and_then(|bytes| bytes.checked_add(1)) // comma or closing bracket.
            .ok_or_else(|| OxidraError::Session("tool surface size overflowed".to_owned()))?;
        if encoded_bytes > TOOL_SURFACE_MAX_BYTES_V1 {
            return Err(OxidraError::Session(format!(
                "tool surface exceeds {TOOL_SURFACE_MAX_BYTES_V1} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_surface_identity(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(OxidraError::Session(format!(
            "MCP surface {label} has invalid identity"
        )));
    }
    Ok(())
}

fn validate_surface_uuid_v7(label: &str, value: &str) -> Result<()> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| OxidraError::Session(format!("MCP surface {label} must be a UUIDv7")))?;
    if uuid.get_version_num() != 7 {
        return Err(OxidraError::Session(format!(
            "MCP surface {label} must be a UUIDv7"
        )));
    }
    Ok(())
}

fn validate_surface_digest(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OxidraError::Session(format!(
            "MCP surface {label} is not a SHA-256 digest"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use url::Url;

    use super::*;
    use crate::config::ContextValueSource;
    use crate::session::JOURNAL_SCHEMA;

    fn event(seq: u64, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: JOURNAL_SCHEMA,
            seq,
            ts: Utc::now(),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: Some("turn".to_owned()),
            data,
        }
    }

    fn runtime(domain: &str) -> ContextRuntime {
        ContextRuntime {
            model: "model".to_owned(),
            provider_protocol: PROVIDER_PROTOCOL_OPENAI_RESPONSES.to_owned(),
            provider_usage_domain: domain.to_owned(),
            limits: ContextLimits {
                context_window: Some(128_000),
                reserve_tokens: 16_000,
                context_window_source: ContextValueSource::BuiltinDefault,
                reserve_tokens_source: ContextValueSource::BuiltinDefault,
            },
        }
    }

    fn tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_owned(),
            description: format!("definition for {name}"),
            input_schema: json!({
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "additionalProperties": false
            }),
        }
    }

    fn mcp_binding(provider_name: &str, definition: &ToolDefinition) -> McpSurfaceBindingV1 {
        McpSurfaceBindingV1::from_parts(
            provider_name,
            "server",
            provider_name,
            "2026-07-28",
            definition,
            Some(&json!({"type":"object"})),
        )
        .unwrap()
    }

    fn registry_epoch_id() -> &'static str {
        "0190f5e6-7b00-7abc-8000-000000000301"
    }

    #[test]
    fn mcp_surface_snapshot_binds_aliases_and_is_canonical() {
        let first = tool("mcp_first");
        let second = tool("mcp_second");
        let claim = McpSurfaceClaimV1::new(
            registry_epoch_id(),
            "a".repeat(64),
            vec![
                mcp_binding("mcp_second", &second),
                mcp_binding("mcp_first", &first),
            ],
        )
        .unwrap();
        assert_eq!(
            claim
                .bindings
                .iter()
                .map(|binding| binding.provider_name.as_str())
                .collect::<Vec<_>>(),
            vec!["mcp_first", "mcp_second"]
        );

        let snapshot = snapshot_tool_surface_v1(
            &[tool("builtin"), first.clone(), second.clone()],
            Some(claim.clone()),
        )
        .unwrap();
        snapshot.validate().unwrap();
        let encoded = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(encoded["version"], TOOL_SURFACE_SNAPSHOT_VERSION_V1);
        assert_eq!(encoded["mcp"]["version"], MCP_SURFACE_CLAIM_VERSION_V1);
        assert_eq!(
            snapshot.digest(),
            "ce17e452cb3495b1fc35d4424a36ee18acdc1c5fc3c3bf906d7726a8304cdff5"
        );

        // Reversing only the claim input cannot change the canonical digest.
        let reversed = McpSurfaceClaimV1::new(
            registry_epoch_id(),
            "a".repeat(64),
            vec![
                mcp_binding("mcp_first", &first),
                mcp_binding("mcp_second", &second),
            ],
        )
        .unwrap();
        let reversed_snapshot =
            snapshot_tool_surface_v1(&[tool("builtin"), first, second], Some(reversed)).unwrap();
        assert_eq!(snapshot.digest, reversed_snapshot.digest);
    }

    #[test]
    fn exact_surface_reader_rejects_fields_serde_would_discard() {
        let definition = tool("mcp_echo");
        let claim = McpSurfaceClaimV1::new(
            registry_epoch_id(),
            "b".repeat(64),
            vec![mcp_binding("mcp_echo", &definition)],
        )
        .unwrap();
        let snapshot = snapshot_tool_surface_v1(&[definition], Some(claim)).unwrap();
        let encoded = serde_json::to_value(&snapshot).unwrap();
        ToolSurfaceSnapshotV1::from_exact_journal_value(&encoded)
            .expect("canonical surface snapshot must decode");

        let mut top_level = encoded;
        top_level["unexpected"] = Value::Bool(true);
        let error = ToolSurfaceSnapshotV1::from_exact_journal_value(&top_level)
            .expect_err("unknown snapshot fields must fail closed")
            .to_string();
        assert!(error.contains("exact canonical shape"), "{error}");

        let mut nested = serde_json::to_value(&snapshot).unwrap();
        nested["tools"][0]["unexpected"] = Value::Bool(true);
        assert!(ToolSurfaceSnapshotV1::from_exact_journal_value(&nested).is_err());

        let mut binding = serde_json::to_value(&snapshot).unwrap();
        binding["mcp"]["bindings"][0]["unexpected"] = Value::Bool(true);
        assert!(ToolSurfaceSnapshotV1::from_exact_journal_value(&binding).is_err());
    }

    #[test]
    fn exact_surface_reader_revalidates_bound_mcp_input_schema() {
        let definition = ToolDefinition {
            name: "mcp_invalid_schema".to_owned(),
            description: "self-consistent but unsupported MCP schema".to_owned(),
            input_schema: json!({
                "type":"object",
                "$ref":"#/$defs/forbidden",
            }),
        };
        let binding = McpSurfaceBindingV1::from_parts(
            definition.name.clone(),
            "server",
            "invalid_schema",
            "2026-07-28",
            &definition,
            None,
        )
        .unwrap();
        let claim =
            McpSurfaceClaimV1::new(registry_epoch_id(), "c".repeat(64), vec![binding]).unwrap();
        let tools = vec![definition];
        let snapshot = ToolSurfaceSnapshotV1 {
            version: TOOL_SURFACE_SNAPSHOT_VERSION_V1,
            digest: surface_snapshot_digest(&tools, Some(&claim)).unwrap(),
            tools,
            mcp: Some(claim),
        };
        let encoded = serde_json::to_value(snapshot).unwrap();
        let error = ToolSurfaceSnapshotV1::from_exact_journal_value(&encoded)
            .expect_err("self-consistent unsupported MCP schemas must fail closed")
            .to_string();
        assert!(error.contains("invalid input schema"), "{error}");
    }

    #[test]
    fn mcp_surface_snapshot_rejects_alias_or_definition_mutation() {
        let definition = tool("mcp_echo");
        let claim = McpSurfaceClaimV1::new(
            registry_epoch_id(),
            "b".repeat(64),
            vec![mcp_binding("mcp_echo", &definition)],
        )
        .unwrap();
        let mut snapshot = snapshot_tool_surface_v1(&[definition.clone()], Some(claim)).unwrap();

        snapshot.tools[0].description.push_str(" mutated");
        assert!(snapshot.validate().is_err());

        let unknown = tool("mcp_other");
        let unknown_claim = McpSurfaceClaimV1::new(
            registry_epoch_id(),
            "b".repeat(64),
            vec![mcp_binding("mcp_other", &unknown)],
        )
        .unwrap();
        assert!(snapshot_tool_surface_v1(&[definition], Some(unknown_claim)).is_err());
    }

    #[test]
    fn mcp_surface_snapshot_rejects_duplicate_tool_names_and_invalid_claim_ids() {
        let duplicate = tool("same");
        assert!(snapshot_tool_surface_v1(&[duplicate.clone(), duplicate], None).is_err());

        let error = McpSurfaceClaimV1::new("", "c".repeat(64), Vec::new()).unwrap_err();
        assert!(error.to_string().contains("registry_epoch_id"));

        let error = McpSurfaceClaimV1::new(
            "0190f5e6-7b00-4abc-8000-000000000301",
            "c".repeat(64),
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("registry_epoch_id"));
    }

    #[test]
    fn mcp_surface_snapshot_enforces_frozen_count_and_name_limits() {
        let too_many = (0..=TOOL_SURFACE_MAX_TOOLS_V1)
            .map(|index| tool(&format!("tool_{index}")))
            .collect::<Vec<_>>();
        let error = snapshot_tool_surface_v1(&too_many, None).unwrap_err();
        assert!(error.to_string().contains("more than"), "{error}");

        let invalid = tool(&"x".repeat(65));
        let error = snapshot_tool_surface_v1(&[invalid], None).unwrap_err();
        assert!(error.to_string().contains("64 bytes"), "{error}");
    }

    #[test]
    fn measurement_uses_the_exact_provider_body() {
        let request = ResponseRequest {
            instructions: Some("instructions".to_owned()),
            input: vec![json!({"role":"user","content":"hello"})],
            tools: vec![],
            model: None,
            max_output_tokens: None,
        };
        let measurement = measure_prepared_request(&request, &runtime("domain")).unwrap();
        let body = prepared_request_body(&request, "model");
        assert_eq!(
            measurement.request_digest,
            digest_bytes(
                b"oxidra.prepared-request.v1\0",
                &serde_json::to_vec(&body).unwrap()
            )
        );
        assert_eq!(
            measurement.serialized_request_bytes,
            serde_json::to_vec(&body).unwrap().len() as u64
        );
        assert!(body["include"].as_array().is_some());
    }

    #[test]
    fn configured_event_audits_the_explicit_compaction_switch() {
        let enabled = runtime("domain").configured_event_data_with_compaction(true);
        assert_eq!(enabled["automatic_compaction"]["enabled"], true);
        assert_eq!(
            enabled["automatic_compaction"]["source"],
            "experimental_cli"
        );
        assert_eq!(enabled["automatic_compaction"]["planning_version"], 1);

        let disabled = runtime("domain").configured_event_data_with_compaction(false);
        assert_eq!(disabled["automatic_compaction"]["enabled"], false);
        assert_eq!(disabled["automatic_compaction"]["source"], "default_off");
    }

    #[test]
    fn usage_anchor_applies_a_signed_request_delta_without_deducting_cache() {
        let anchor_measurement = PreparedRequestMeasurement {
            measurement_version: CONTEXT_MEASUREMENT_VERSION,
            estimator_version: CONTEXT_ESTIMATOR_VERSION,
            request_shape_version: REQUEST_SHAPE_VERSION,
            request_digest: "anchor".to_owned(),
            estimated_input_tokens: 1_000,
            serialized_request_bytes: 5_000,
        };
        let events = vec![
            event(
                1,
                "response.started",
                json!({
                    "response_attempt_id":"attempt",
                    "context":{
                        "measurement":anchor_measurement,
                        "provider_usage_domain":"domain"
                    }
                }),
            ),
            event(
                2,
                "response.completed",
                json!({
                    "response_attempt_id":"attempt",
                    "raw_response":{"usage":{"input_tokens":1_500,"input_tokens_details":{"cached_tokens":1_400}}}
                }),
            ),
        ];
        let current = PreparedRequestMeasurement {
            measurement_version: CONTEXT_MEASUREMENT_VERSION,
            estimator_version: CONTEXT_ESTIMATOR_VERSION,
            request_shape_version: REQUEST_SHAPE_VERSION,
            request_digest: "current".to_owned(),
            estimated_input_tokens: 900,
            serialized_request_bytes: 5_000,
        };
        let decision = decide_context(
            &events,
            &runtime("domain"),
            current,
            Some(2),
            None,
            None,
            None,
            None,
            3,
        )
        .unwrap();
        assert_eq!(decision.method, ContextEstimateMethod::UsageAnchor);
        assert_eq!(decision.estimate_delta_tokens, Some(-100));
        assert_eq!(decision.estimated_next_input_tokens, 1_400);
        assert!(decision.anchor_rejection_reason.is_none());
    }

    #[test]
    fn non_positive_or_wild_anchor_delta_falls_back_instead_of_clamping_to_zero() {
        let anchor_measurement = PreparedRequestMeasurement {
            measurement_version: CONTEXT_MEASUREMENT_VERSION,
            estimator_version: CONTEXT_ESTIMATOR_VERSION,
            request_shape_version: REQUEST_SHAPE_VERSION,
            request_digest: "anchor".to_owned(),
            estimated_input_tokens: 10_000,
            serialized_request_bytes: 20_000,
        };
        let events = vec![
            event(
                1,
                "response.started",
                json!({
                    "response_attempt_id":"attempt",
                    "context":{
                        "measurement":anchor_measurement,
                        "provider_usage_domain":"domain"
                    }
                }),
            ),
            event(
                2,
                "response.completed",
                json!({
                    "response_attempt_id":"attempt",
                    "raw_response":{"usage":{"input_tokens":1}}
                }),
            ),
        ];
        let current = PreparedRequestMeasurement {
            measurement_version: CONTEXT_MEASUREMENT_VERSION,
            estimator_version: CONTEXT_ESTIMATOR_VERSION,
            request_shape_version: REQUEST_SHAPE_VERSION,
            request_digest: "current".to_owned(),
            estimated_input_tokens: 1,
            serialized_request_bytes: 4_200,
        };
        let decision = decide_context(
            &events,
            &runtime("domain"),
            current,
            Some(2),
            None,
            None,
            None,
            None,
            3,
        )
        .unwrap();
        assert_eq!(decision.method, ContextEstimateMethod::FullRequest);
        assert_eq!(decision.estimated_next_input_tokens, 1);
        assert!(decision.anchor_rejection_reason.is_some());
    }

    #[test]
    fn missing_usage_or_changed_domain_falls_back_to_full_measurement() {
        let events = vec![
            event(
                1,
                "response.started",
                json!({
                    "response_attempt_id":"attempt",
                    "context":{
                        "measurement":{
                            "measurement_version":2,
                            "estimator_version":1,
                            "request_shape_version":1,
                            "request_digest":"anchor",
                            "estimated_input_tokens":1000
                        },
                        "provider_usage_domain":"other"
                    }
                }),
            ),
            event(
                2,
                "response.completed",
                json!({"response_attempt_id":"attempt","raw_response":{"usage":{"input_tokens":1500}}}),
            ),
        ];
        let current = PreparedRequestMeasurement {
            measurement_version: 2,
            estimator_version: 1,
            request_shape_version: 1,
            request_digest: "current".to_owned(),
            estimated_input_tokens: 900,
            serialized_request_bytes: 5_000,
        };
        let decision = decide_context(
            &events,
            &runtime("domain"),
            current,
            Some(2),
            None,
            None,
            None,
            None,
            3,
        )
        .unwrap();
        assert_eq!(decision.method, ContextEstimateMethod::FullRequest);
        assert_eq!(decision.estimated_next_input_tokens, 900);
    }

    #[test]
    fn provider_domain_drops_credentials_query_and_fragment() {
        let first = ProviderConfig {
            api_key: "secret".to_owned(),
            api_base_url: Url::parse("https://user:pass@example.test/v1/?token=one#x").unwrap(),
            model: "model".to_owned(),
        };
        let second = ProviderConfig {
            api_key: "different".to_owned(),
            api_base_url: Url::parse("https://example.test/v1/").unwrap(),
            model: "model".to_owned(),
        };
        assert_eq!(
            provider_usage_domain(&first).unwrap(),
            provider_usage_domain(&second).unwrap()
        );
    }
}
