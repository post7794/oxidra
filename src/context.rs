//! Deterministic context measurement and auditable Provider usage anchors.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{ContextLimits, ProviderConfig};
use crate::error::{OxidraError, Result};
use crate::provider::{ResponseRequest, prepared_request_body};
use crate::session::JournalEvent;
use crate::types::ToolDefinition;

pub const CONTEXT_MEASUREMENT_VERSION: u32 = 2;
pub const CONTEXT_ESTIMATOR_VERSION: u32 = 1;
pub const REQUEST_SHAPE_VERSION: u32 = 1;
pub const TOOL_SNAPSHOT_VERSION: u32 = 1;
pub const PROVIDER_PROTOCOL_OPENAI_RESPONSES: &str = "openai_responses";

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
    Ok(PreparedRequestMeasurement {
        measurement_version: CONTEXT_MEASUREMENT_VERSION,
        estimator_version: CONTEXT_ESTIMATOR_VERSION,
        request_shape_version: REQUEST_SHAPE_VERSION,
        request_digest: digest_bytes(b"oxidra.prepared-request.v1\0", &bytes),
        estimated_input_tokens: estimate_json_tokens(&body)?,
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

fn provider_usage_domain(provider: &ProviderConfig) -> Result<String> {
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
