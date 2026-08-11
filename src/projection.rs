//! Pure projections from canonical journal events into provider input items.
//!
//! Rendering options deliberately do not enter this module. Compact or full
//! terminal output must never change the bytes replayed to the provider.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::compaction::{
    COMPACTION_CHECKPOINT_KIND, CheckpointChain, CompactionBoundaryChain, compacted_history_item,
    validate_compaction_boundary_chain,
};
use crate::error::{OxidraError, Result};
use crate::mcp::{
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1, MCP_CALL_CHAIN_VALIDATOR_VERSION_V2,
    validate_mcp_call_chain_for_version, validate_mcp_call_chain_through_version,
};
use crate::session::JournalEvent;
use crate::turn::{
    ValidatedTurnRecovery, complete_prefix_candidates, validate_turn_recovery_v2,
    validate_turn_recovery_v3,
};

/// Current immutable event-to-item format used when building compaction input.
pub const SOURCE_PROJECTION_VERSION: u32 = 6;
const SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V5: u32 =
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1;
const SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6: u32 =
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V2;

/// Whether a persisted source projection version can prove that a validated
/// compaction-boundary abandon was excluded from the opaque summary source.
///
/// Keep every match arm immutable. This capability is consumed by checkpoint
/// safety checks so advancing the current writer cannot reinterpret old
/// source bytes.
pub(crate) fn source_projection_supports_boundary_exclusions(version: u32) -> Result<bool> {
    match version {
        1..=3 => Ok(false),
        4..=6 => Ok(true),
        _ => Err(OxidraError::Session(format!(
            "unsupported compaction source projection version {version}"
        ))),
    }
}

/// Project only committed events into the stateless Responses `input` array.
/// Partial deltas and aborted responses are intentionally absent.
pub fn project_events(events: &[JournalEvent]) -> Result<Vec<Value>> {
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    project_events_with_boundary_chain(events, &boundary_chain)
}

pub(crate) fn project_events_with_boundary_chain(
    events: &[JournalEvent],
    boundary_chain: &CompactionBoundaryChain,
) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    project_events_current(events, &excluded_turn_ids)
}

/// Rebuild the current input shape while a validated recovery boundary is
/// intentionally still pending.
///
/// This is measurement-only: normal Provider dispatch must continue to use
/// [`project_events_with_boundary_chain`] so a pending boundary remains a hard
/// gate. Compaction management events are projection-neutral, while validated
/// abandoned boundary turns still have to stay excluded.
pub(crate) fn project_events_for_recovery_planning(
    events: &[JournalEvent],
    boundary_chain: &CompactionBoundaryChain,
) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    project_events_current(events, &boundary_chain.abandoned_turn_ids())
}

/// Rebuild the exact event projection recorded by a compaction attempt.
/// Published match arms are immutable; new formats must add a new version.
pub fn project_events_for_compaction(version: u32, events: &[JournalEvent]) -> Result<Vec<Value>> {
    match version {
        1 => project_events_v1(events),
        2 => project_events_v2(events),
        3 => project_events_v3(events),
        4 => project_events_v4(events),
        5 => project_events_v5(events),
        6 => project_events_v6(events),
        _ => Err(OxidraError::Session(format!(
            "unsupported compaction source projection version {version}"
        ))),
    }
}

fn project_events_v1(events: &[JournalEvent]) -> Result<Vec<Value>> {
    project_events_impl(events, None, false, None)
}

fn project_events_v2(events: &[JournalEvent]) -> Result<Vec<Value>> {
    // v2 新增显式 abandon 语义；v1 必须保持历史 checkpoint 的原始字节行为。
    let recovery = validate_turn_recovery_v2(events)?;
    project_events_impl(events, Some(&recovery), false, None)
}

fn project_events_v3(events: &[JournalEvent]) -> Result<Vec<Value>> {
    // v3 将较早 retry attempt 的取消终态从当前 projection 中移除。
    let recovery = validate_turn_recovery_v3(events)?;
    project_events_impl(events, Some(&recovery), true, None)
}

fn project_events_v4(events: &[JournalEvent]) -> Result<Vec<Value>> {
    // v4 is the first compaction source format that consumes the independently
    // versioned boundary reducer and removes every item from a validated
    // abandoned boundary turn. v1-v3 intentionally remain unaware of it.
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    let recovery = validate_turn_recovery_v3(events)?;
    project_events_impl(events, Some(&recovery), true, Some(&excluded_turn_ids))
}

fn project_events_v5(events: &[JournalEvent]) -> Result<Vec<Value>> {
    validate_mcp_call_chain_for_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V5,
        events,
    )?;
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    let recovery = validate_turn_recovery_v3(events)?;
    project_events_impl(events, Some(&recovery), true, Some(&excluded_turn_ids))
}

fn project_events_v6(events: &[JournalEvent]) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    let recovery = validate_turn_recovery_v3(events)?;
    project_events_impl(events, Some(&recovery), true, Some(&excluded_turn_ids))
}

/// Build the current runtime projection after applying the separately
/// versioned compaction-boundary state machine. Historical source projection
/// versions intentionally bypass this wrapper and remain byte-frozen.
fn project_events_current(
    events: &[JournalEvent],
    excluded_turn_ids: &HashSet<String>,
) -> Result<Vec<Value>> {
    let recovery = validate_turn_recovery_v3(events)?;
    project_events_impl(events, Some(&recovery), true, Some(excluded_turn_ids))
}

fn project_events_impl(
    events: &[JournalEvent],
    recovery: Option<&ValidatedTurnRecovery>,
    supports_retry_supersession: bool,
    boundary_excluded_turn_ids: Option<&HashSet<String>>,
) -> Result<Vec<Value>> {
    let latest_retry_by_turn = if supports_retry_supersession {
        recovery
            .expect("retry-aware projection has recovery state")
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            })
    } else {
        HashMap::new()
    };
    let superseded_by_retry = |event: &JournalEvent| {
        event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| event.seq < *retry_seq)
    };
    let completed_turns = events
        .iter()
        .filter(|event| event.kind == "response.completed")
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();
    let abandoned_turns = events
        .iter()
        .filter(|event| matches!(event.kind.as_str(), "response.aborted" | "turn.cancelled"))
        .filter(|event| !superseded_by_retry(event))
        .filter_map(|event| event.turn_id.clone())
        .filter(|turn_id| !completed_turns.contains(turn_id))
        .collect::<HashSet<_>>();
    let mut explicitly_abandoned_turns = if let Some(recovery) = recovery {
        recovery.abandons.keys().cloned().collect::<HashSet<_>>()
    } else {
        HashSet::new()
    };
    if let Some(boundary_excluded_turn_ids) = boundary_excluded_turn_ids {
        explicitly_abandoned_turns.extend(boundary_excluded_turn_ids.iter().cloned());
    }
    let mut projected = Vec::new();
    let mut marked_cancelled_turns = HashSet::new();
    for event in events {
        match event.kind.as_str() {
            "user.message" => {
                let item = event.data.get("item").ok_or_else(|| {
                    OxidraError::Session(format!(
                        "user.message at seq {} has no input item",
                        event.seq
                    ))
                })?;
                validate_user_input_item(item, event.seq)?;
                let abandoned = event.turn_id.as_ref().is_some_and(|turn_id| {
                    abandoned_turns.contains(turn_id)
                        || explicitly_abandoned_turns.contains(turn_id)
                });
                if !abandoned {
                    projected.push(item.clone());
                }
            }
            "response.completed" => {
                if event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| explicitly_abandoned_turns.contains(turn_id))
                {
                    continue;
                }
                let items = response_output_items(event)?;
                validate_response_output_items(items)?;
                projected.extend(items.iter().cloned());
            }
            kind if is_tool_terminal_v1(kind) => {
                if event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| explicitly_abandoned_turns.contains(turn_id))
                {
                    continue;
                }
                if let Some(item) = tool_output_item_v1(&event.data) {
                    projected.push(item);
                }
            }
            "response.aborted" | "turn.cancelled" => {
                if superseded_by_retry(event) {
                    continue;
                }
                if let Some(turn_id) = &event.turn_id {
                    if !explicitly_abandoned_turns.contains(turn_id)
                        && completed_turns.contains(turn_id)
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
    Ok(projected)
}

fn response_output_items(event: &JournalEvent) -> Result<&[Value]> {
    if let Some(output_items) = event.data.get("output_items") {
        return output_items.as_array().map(Vec::as_slice).ok_or_else(|| {
            OxidraError::Session(format!(
                "response.completed at seq {} has a non-array output_items field",
                event.seq
            ))
        });
    }

    let raw_output = event
        .data
        .get("raw_response")
        .and_then(|response| response.get("output"))
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "response.completed at seq {} has no committed output array",
                event.seq
            ))
        })?;
    raw_output.as_array().map(Vec::as_slice).ok_or_else(|| {
        OxidraError::Session(format!(
            "response.completed at seq {} has a non-array raw_response.output field",
            event.seq
        ))
    })
}

/// Validate the role-bearing items returned by a Provider before they can be
/// committed or replayed. Provider output may contain assistant messages, but
/// it may never manufacture user/developer/system messages.
pub fn validate_response_output_items(items: &[Value]) -> Result<()> {
    for (index, item) in items.iter().enumerate() {
        let item_type = item.get("type").and_then(Value::as_str);
        let role = item.get("role").and_then(Value::as_str);
        if item_type == Some("message") && role != Some("assistant") {
            return Err(OxidraError::Provider(format!(
                "response output message at index {index} must have role assistant"
            )));
        }
        if role.is_some_and(|role| role != "assistant") {
            return Err(OxidraError::Provider(format!(
                "response output item at index {index} has forbidden role {role:?}"
            )));
        }
    }
    Ok(())
}

fn validate_user_input_item(item: &Value, seq: u64) -> Result<()> {
    if item.get("role").and_then(Value::as_str) != Some("user") {
        return Err(OxidraError::Session(format!(
            "user.message at seq {seq} does not contain a user-role input item"
        )));
    }
    Ok(())
}

/// Project only events after a verified complete-turn prefix boundary.
pub fn project_tail(events: &[JournalEvent], covers_through_seq: u64) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let boundary_is_valid = complete_prefix_candidates(events)?
        .iter()
        .any(|candidate| candidate.covers_through_seq == covers_through_seq);
    if !boundary_is_valid {
        return Err(OxidraError::Session(format!(
            "sequence {covers_through_seq} is not a complete turn prefix boundary"
        )));
    }

    let boundary_chain = validate_compaction_boundary_chain(events)?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    project_tail_after_validated_cutoff(events, covers_through_seq, &excluded_turn_ids)
}

/// Project the latest validated checkpoint followed by its uncompacted tail.
///
/// An empty validated chain is the only case that uses the original projection.
/// Callers must not turn checkpoint validation errors into an empty chain: when
/// checkpoint events are present, doing so would silently resurrect covered
/// history.
pub fn project_checkpoint_and_tail(
    events: &[JournalEvent],
    chain: &CheckpointChain,
) -> Result<Vec<Value>> {
    let boundary_chain = validate_compaction_boundary_chain(events)?;
    project_checkpoint_and_tail_with_boundary_chain(events, chain, &boundary_chain)
}

pub(crate) fn project_checkpoint_and_tail_with_boundary_chain(
    events: &[JournalEvent],
    chain: &CheckpointChain,
    boundary_chain: &CompactionBoundaryChain,
) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let excluded_turn_ids = boundary_chain.projection_excluded_turn_ids()?;
    project_checkpoint_and_tail_with_exclusions(events, chain, boundary_chain, &excluded_turn_ids)
}

fn project_checkpoint_and_tail_with_exclusions(
    events: &[JournalEvent],
    chain: &CheckpointChain,
    boundary_chain: &CompactionBoundaryChain,
    excluded_turn_ids: &HashSet<String>,
) -> Result<Vec<Value>> {
    chain.ensure_matches(events)?;
    boundary_chain.ensure_checkpoint_projection_safe(chain)?;
    let Some(checkpoint) = chain.latest() else {
        if events
            .iter()
            .any(|event| event.kind == COMPACTION_CHECKPOINT_KIND)
        {
            return Err(OxidraError::Session(
                "checkpoint events are present but the validated chain is empty".to_owned(),
            ));
        }
        return project_events_current(events, excluded_turn_ids);
    };

    let mut projected = vec![compacted_history_item(
        checkpoint.summary_envelope_version,
        &checkpoint.summary,
    )?];
    // Chain validation already rebuilt the cutoff with the checkpoint's
    // historical source format. Revalidating with today's turn reducer would
    // make an old checkpoint unreadable after a future reducer upgrade.
    projected.extend(project_tail_after_validated_cutoff(
        events,
        checkpoint.covers_through_seq,
        excluded_turn_ids,
    )?);
    Ok(projected)
}

/// Checkpoint-aware counterpart to [`project_events_for_recovery_planning`].
/// It preserves every checkpoint safety check while bypassing only the runtime
/// pending-boundary dispatch gate for a non-dispatching context measurement.
pub(crate) fn project_checkpoint_and_tail_for_recovery_planning(
    events: &[JournalEvent],
    chain: &CheckpointChain,
    boundary_chain: &CompactionBoundaryChain,
) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let excluded_turn_ids = boundary_chain.abandoned_turn_ids();
    project_checkpoint_and_tail_with_exclusions(events, chain, boundary_chain, &excluded_turn_ids)
}

/// Build the normal Provider input that would exist if `summary` were
/// committed for `covers_through_seq`.
///
/// This is used only for post-summary measurement before the checkpoint is
/// durable. The owning compaction boundary is necessarily still `Started`, so
/// it deliberately consumes only validated abandon exclusions rather than the
/// runtime pending gate. Compaction management events remain projection
/// neutral and need not be synthesized into the preview.
pub(crate) fn project_compaction_summary_and_tail(
    events: &[JournalEvent],
    covers_through_seq: u64,
    summary_envelope_version: u32,
    summary: &str,
    boundary_chain: &CompactionBoundaryChain,
) -> Result<Vec<Value>> {
    validate_mcp_call_chain_through_version(
        SOURCE_PROJECTION_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6,
        events,
    )?;
    let excluded_turn_ids = boundary_chain.abandoned_turn_ids();
    let mut projected = vec![compacted_history_item(summary_envelope_version, summary)?];
    projected.extend(project_tail_after_validated_cutoff(
        events,
        covers_through_seq,
        &excluded_turn_ids,
    )?);
    Ok(projected)
}

fn project_tail_after_validated_cutoff(
    events: &[JournalEvent],
    covers_through_seq: u64,
    excluded_turn_ids: &HashSet<String>,
) -> Result<Vec<Value>> {
    let tail = events
        .iter()
        .filter(|event| event.seq > covers_through_seq)
        .cloned()
        .collect::<Vec<_>>();
    project_events_current(&tail, excluded_turn_ids)
}

fn is_tool_terminal_v1(kind: &str) -> bool {
    matches!(
        kind,
        "tool.completed"
            | "tool.cancelled"
            | "tool.in_doubt_resolved"
            | "tool.skipped_due_to_cancel"
            | "tool.skipped_due_to_in_doubt"
            | "tool.skipped_due_to_limit"
            | "tool.skipped_due_to_stalled"
            | "tool.skipped_due_to_recovery"
    )
}

fn tool_output_item_v1(data: &Value) -> Option<Value> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::{
        COMPACTION_BOUNDARY_ABANDONED_KIND, COMPACTION_BOUNDARY_STARTED_KIND,
        COMPACTION_PROMPT_VERSION, COMPACTION_STARTED_KIND, Checkpoint, CompactionBoundary,
        CompactionBoundaryAbandoned, CompactionBoundaryStarted, CompactionSource,
        CompactionStarted, SOURCE_DIGEST_VERSION, SUMMARY_ENVELOPE_VERSION, USAGE_CONTRACT_VERSION,
        build_compaction_source, compaction_instructions, validate_checkpoint_chain,
    };
    use crate::turn::{TURN_BOUNDARY_VALIDATOR_VERSION, TURN_BOUNDARY_VERSION};

    fn event(seq: u64, turn_id: Option<&str>, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: chrono::DateTime::from_timestamp(0, 0).expect("valid test timestamp"),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: turn_id.map(str::to_owned),
            data,
        }
    }

    fn frozen_retry_events() -> Vec<JournalEvent> {
        include_str!("../tests/fixtures/retry_recovery_v2.jsonl")
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("retry_recovery_v2 fixture line {}: {error}", index + 1)
                })
            })
            .collect()
    }

    fn boundary_v2_fixture() -> Vec<JournalEvent> {
        include_str!("../tests/fixtures/compaction_boundary_v2.jsonl")
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("compaction_boundary_v2 fixture line {}: {error}", index + 1)
                })
            })
            .collect()
    }

    fn user(seq: u64, turn_id: &str) -> JournalEvent {
        event(
            seq,
            Some(turn_id),
            "user.message",
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "item": {"role": "user", "content": turn_id},
            }),
        )
    }

    fn response(seq: u64, turn_id: &str) -> JournalEvent {
        event(
            seq,
            Some(turn_id),
            "response.completed",
            json!({"output_items": [{
                "type": "message",
                "role": "assistant",
                "id": format!("m-{turn_id}"),
            }]}),
        )
    }

    fn marker(seq: u64, turn_id: &str, start: u64, response: u64) -> JournalEvent {
        event(
            seq,
            Some(turn_id),
            "turn.completed",
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": start,
                "final_response_seq": response,
                "covers_through_seq": seq,
            }),
        )
    }

    fn checkpointed_events(include_display_event: bool) -> Vec<JournalEvent> {
        let mut events = vec![
            user(1, "t1"),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
            user(4, "t2"),
            event(
                5,
                Some("t2"),
                "response.completed",
                json!({
                    "output_items": [{
                        "type": "function_call",
                        "call_id": "call-1",
                        "name": "read",
                        "arguments": "{}",
                    }],
                }),
            ),
            event(6, Some("t2"), "tool.started", json!({"call_id": "call-1"})),
            event(
                7,
                Some("t2"),
                "tool.completed",
                json!({"call_id": "call-1", "output": "tool result"}),
            ),
            response(8, "t2"),
            marker(9, "t2", 4, 8),
            event(
                10,
                None,
                "context.instructions",
                json!({"instructions": "stale instructions must not be projected"}),
            ),
            user(11, "t3"),
        ];
        let mut next_seq = 12;
        if include_display_event {
            events.push(event(
                next_seq,
                None,
                "render.compact",
                json!({"depth": "compact"}),
            ));
            next_seq += 1;
        }

        let source = build_compaction_source(&events, None, 3)
            .expect("first complete turn is a valid source");
        let source_digest = source.digest().expect("digest source");
        let started = CompactionStarted {
            attempt_id: "attempt-1".to_owned(),
            parent_checkpoint_id: None,
            covers_through_seq: 3,
            source,
            source_digest: source_digest.clone(),
            instructions: compaction_instructions(COMPACTION_PROMPT_VERSION)
                .expect("current prompt is registered")
                .to_owned(),
            prompt_version: COMPACTION_PROMPT_VERSION,
            summary_envelope_version: SUMMARY_ENVELOPE_VERSION,
            source_projection_version: SOURCE_PROJECTION_VERSION,
            turn_boundary_validator_version: TURN_BOUNDARY_VALIDATOR_VERSION,
            source_digest_version: SOURCE_DIGEST_VERSION,
            usage_contract_version: USAGE_CONTRACT_VERSION,
            model: "test-model".to_owned(),
            extra: Default::default(),
        };
        events.push(event(
            next_seq,
            None,
            COMPACTION_STARTED_KIND,
            serde_json::to_value(started).expect("serialize start"),
        ));
        next_seq += 1;
        let checkpoint = Checkpoint {
            attempt_id: "attempt-1".to_owned(),
            checkpoint_id: "checkpoint-1".to_owned(),
            parent_checkpoint_id: None,
            covers_through_seq: 3,
            source_digest,
            summary: "The first turn established an older fact.".to_owned(),
            model: "test-model".to_owned(),
            prompt_version: COMPACTION_PROMPT_VERSION,
            summary_envelope_version: SUMMARY_ENVELOPE_VERSION,
            source_projection_version: SOURCE_PROJECTION_VERSION,
            turn_boundary_validator_version: TURN_BOUNDARY_VALIDATOR_VERSION,
            source_digest_version: SOURCE_DIGEST_VERSION,
            usage_contract_version: USAGE_CONTRACT_VERSION,
            usage: json!({
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 10},
                "output_tokens": 20,
                "output_tokens_details": {"reasoning_tokens": 5},
                "total_tokens": 120,
            }),
            duration_ms: 10,
            raw_response: json!({
                "id": "compaction-response",
                "status": "completed",
                "usage": {
                    "input_tokens": 100,
                    "input_tokens_details": {"cached_tokens": 10},
                    "output_tokens": 20,
                    "output_tokens_details": {"reasoning_tokens": 5},
                    "total_tokens": 120,
                },
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": "The first turn established an older fact.",
                    }],
                }],
            }),
            journal_seq: 0,
            extra: Default::default(),
        };
        events.push(event(
            next_seq,
            None,
            COMPACTION_CHECKPOINT_KIND,
            serde_json::to_value(checkpoint).expect("serialize checkpoint"),
        ));
        events
    }

    #[test]
    fn tail_projection_accepts_only_complete_turn_prefixes() {
        let events = vec![
            user(1, "t1"),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
            user(4, "t2"),
            response(5, "t2"),
        ];

        assert_eq!(
            project_tail(&events, 3).expect("explicit marker is a safe cutoff"),
            project_events(&events[3..]).expect("valid tail projection")
        );
        assert!(project_tail(&events, 2).is_err());
        assert!(project_tail(&events, 5).is_err());
    }

    #[test]
    fn global_and_display_events_do_not_change_provider_projection() {
        let base = vec![user(1, "t1"), response(4, "t1")];
        let with_non_provider_events = vec![
            user(1, "t1"),
            event(
                2,
                None,
                "context.instructions",
                json!({"instructions": "diagnostic snapshot only"}),
            ),
            event(3, None, "context.configured", json!({"model":"model"})),
            event(4, None, "context.tools", json!({"digest":"tools"})),
            event(5, None, "render.compact", json!({"depth": "compact"})),
            response(6, "t1"),
            marker(7, "t1", 1, 6),
        ];

        let base_bytes = serde_json::to_vec(&project_events(&base).expect("valid base projection"))
            .expect("serialize projection");
        let enriched_bytes = serde_json::to_vec(
            &project_events(&with_non_provider_events).expect("valid enriched projection"),
        )
        .expect("serialize projection");
        assert_eq!(enriched_bytes, base_bytes);
    }

    #[test]
    fn current_projection_excludes_every_item_from_an_abandoned_compaction_boundary() {
        let boundary = CompactionBoundary {
            version: 1,
            boundary_id: "boundary-v1".to_owned(),
            turn_id: "old-turn".to_owned(),
            user_message_seq: 1,
        };
        let events = vec![
            event(
                1,
                Some("old-turn"),
                "user.message",
                json!({
                    "turn_boundary_version":3,
                    "item":{"role":"user","content":"obsolete prompt"},
                }),
            ),
            event(
                2,
                None,
                COMPACTION_BOUNDARY_STARTED_KIND,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: boundary.clone(),
                    trigger: "test".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            ),
            event(
                3,
                Some("old-turn"),
                "response.completed",
                json!({"output_items":[{
                    "type":"function_call",
                    "call_id":"old-call",
                    "name":"read",
                    "arguments":"{}"
                }]}),
            ),
            event(
                4,
                Some("old-turn"),
                "tool.completed",
                json!({
                    "call_id":"old-call",
                    "tool":"read",
                    "output":{"text":"obsolete tool output"}
                }),
            ),
            event(
                5,
                Some("old-turn"),
                "response.completed",
                json!({"output_items":[{
                    "type":"message",
                    "role":"assistant",
                    "content":[{"type":"output_text","text":"obsolete answer"}]
                }]}),
            ),
            event(
                6,
                None,
                COMPACTION_BOUNDARY_ABANDONED_KIND,
                serde_json::to_value(CompactionBoundaryAbandoned {
                    boundary_id: boundary.boundary_id,
                    turn_id: boundary.turn_id,
                    user_message_seq: boundary.user_message_seq,
                    reason: "replace prompt".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            ),
            user(7, "replacement-turn"),
        ];

        let projected = project_events(&events).expect("validated abandon is projectable");
        let serialized = serde_json::to_string(&projected).unwrap();
        assert!(!serialized.contains("obsolete prompt"));
        assert!(!serialized.contains("old-call"));
        assert!(!serialized.contains("obsolete tool output"));
        assert!(!serialized.contains("obsolete answer"));
        assert!(serialized.contains("replacement-turn"));
    }

    #[test]
    fn current_boundary_projection_does_not_rewrite_frozen_source_v3() {
        let events = boundary_v2_fixture();
        let current = project_events(&events).expect("current boundary view is valid");
        let frozen = project_events_for_compaction(3, &events).expect("v3 stays registered");
        let boundary_aware =
            project_events_for_compaction(4, &events).expect("v4 consumes boundary state");
        let current = serde_json::to_string(&current).unwrap();
        let frozen = serde_json::to_string(&frozen).unwrap();
        let boundary_aware = serde_json::to_string(&boundary_aware).unwrap();
        assert!(!current.contains("\"content\":\"prompt\""));
        assert!(current.contains("replacement"));
        assert!(frozen.contains("\"content\":\"prompt\""));
        assert_eq!(boundary_aware, current);
    }

    #[test]
    fn source_projection_v4_boundary_exclusion_fixture_is_frozen() {
        let events = boundary_v2_fixture();
        let expected: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/boundary_projection_v4.json"
        ))
        .expect("valid frozen boundary-aware projection fixture");

        assert_eq!(
            project_events_for_compaction(4, &events).expect("source v4 is registered"),
            expected
        );
        assert!(
            project_events_for_compaction(3, &events)
                .expect("frozen source v3 remains readable")
                .iter()
                .any(|item| item.get("content") == Some(&json!("prompt"))),
            "source v3 must not gain boundary exclusion retroactively"
        );
    }

    #[test]
    fn pending_boundary_fails_closed_but_checkpointed_owner_can_continue() {
        let pending = vec![
            user(1, "pending-turn"),
            event(
                2,
                None,
                COMPACTION_BOUNDARY_STARTED_KIND,
                serde_json::to_value(CompactionBoundaryStarted {
                    boundary: CompactionBoundary::new("pending-boundary", "pending-turn", 1),
                    trigger: "test".to_owned(),
                    extra: Default::default(),
                })
                .unwrap(),
            ),
        ];
        assert!(project_events(&pending).is_err());
        assert!(project_events_for_compaction(3, &pending).is_ok());

        let checkpointed = boundary_v2_fixture()[..8].to_vec();
        let chain = validate_checkpoint_chain(&checkpointed).unwrap();
        let projected = project_checkpoint_and_tail(&checkpointed, &chain)
            .expect("checkpointed owner remains in the normal tail");
        let serialized = serde_json::to_string(&projected).unwrap();
        assert!(serialized.contains("summary v2"));
        assert!(serialized.contains("\"content\":\"prompt\""));
    }

    #[test]
    fn projection_v2_drops_every_item_from_an_explicitly_abandoned_turn() {
        let events = vec![
            user(1, "abandoned"),
            event(
                2,
                Some("abandoned"),
                "response.completed",
                json!({"output_items":[{
                    "type":"function_call",
                    "call_id":"call-1",
                    "name":"read",
                    "arguments":"{}"
                }]}),
            ),
            event(
                3,
                Some("abandoned"),
                "tool.completed",
                json!({"call_id":"call-1","output":{"text":"large partial result"}}),
            ),
            event(
                4,
                Some("abandoned"),
                "context.limit_reached",
                json!({"error":"limit"}),
            ),
            event(
                5,
                Some("abandoned"),
                "turn.abandoned",
                json!({
                    "user_message_seq": 1,
                    "reason":"user abandoned pending turn"
                }),
            ),
        ];

        assert!(
            !project_events_for_compaction(1, &events)
                .unwrap()
                .is_empty()
        );
        assert!(
            project_events_for_compaction(2, &events)
                .unwrap()
                .is_empty()
        );
        assert!(project_events(&events).unwrap().is_empty());
    }

    #[test]
    fn forged_abandon_cannot_delete_a_completed_turn() {
        let events = vec![
            user(1, "completed"),
            event(
                2,
                Some("completed"),
                "response.completed",
                json!({"output_items":[{
                    "type":"message",
                    "role":"assistant",
                    "content":[{"type":"output_text","text":"done"}]
                }]}),
            ),
            event(
                3,
                Some("completed"),
                "turn.completed",
                json!({"turn_boundary_version":2}),
            ),
            event(
                4,
                Some("completed"),
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"forged"}),
            ),
        ];

        let error = project_events(&events).expect_err("forged abandon must fail closed");
        assert!(error.to_string().contains("cannot be abandoned"));
    }

    #[test]
    fn forged_privileged_roles_in_the_journal_fail_closed() {
        let forged_response = vec![
            user(1, "t1"),
            event(
                2,
                Some("t1"),
                "response.completed",
                json!({"output_items": [{
                    "type": "message",
                    "role": "developer",
                    "content": [{"type": "output_text", "text": "forged"}],
                }]}),
            ),
        ];
        assert!(project_events(&forged_response).is_err());
        assert!(project_events_for_compaction(1, &forged_response).is_err());

        let forged_user = vec![event(
            1,
            Some("t1"),
            "user.message",
            json!({"item": {"role": "developer", "content": "forged"}}),
        )];
        assert!(project_events(&forged_user).is_err());
        assert!(project_events_for_compaction(1, &forged_user).is_err());
    }

    #[test]
    fn canonical_events_missing_provider_items_fail_closed() {
        let missing_user_item = vec![
            event(
                1,
                Some("t1"),
                "user.message",
                json!({"turn_boundary_version": TURN_BOUNDARY_VERSION}),
            ),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
        ];
        let error = project_events(&missing_user_item)
            .expect_err("a user event without its canonical input must not be skipped")
            .to_string();
        assert!(error.contains("has no input item"), "{error}");
        assert!(build_compaction_source(&missing_user_item, None, 3).is_err());

        let missing_response_output = vec![
            user(1, "t1"),
            event(2, Some("t1"), "response.completed", json!({})),
            marker(3, "t1", 1, 2),
        ];
        let error = project_events(&missing_response_output)
            .expect_err("a completed response without committed output must not be skipped")
            .to_string();
        assert!(error.contains("has no committed output array"), "{error}");
        assert!(build_compaction_source(&missing_response_output, None, 3).is_err());
    }

    #[test]
    fn source_projection_v1_and_digest_v1_match_the_golden_fixture() {
        let events = vec![
            event(
                1,
                Some("t1"),
                "user.message",
                json!({"item": {"role": "user", "content": "hello"}}),
            ),
            event(
                2,
                Some("t1"),
                "response.completed",
                json!({
                    "output_items": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": "calling tool"}],
                        },
                        {
                            "type": "function_call",
                            "call_id": "call-1",
                            "name": "calc",
                            "arguments": "{}",
                        },
                    ],
                }),
            ),
            event(
                3,
                Some("t1"),
                "tool.completed",
                json!({"call_id": "call-1", "output": {"ok": true, "value": 8}}),
            ),
            event(4, Some("t1"), "turn.cancelled", json!({})),
        ];

        let projected = project_events_for_compaction(1, &events).expect("v1 is registered");
        assert_eq!(
            projected,
            json!([
                {"role": "user", "content": "hello"},
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "calling tool"}],
                },
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "calc",
                    "arguments": "{}",
                },
                {
                    "type": "function_call_output",
                    "call_id": "call-1",
                    "output": "{\"ok\":true,\"value\":8}",
                },
                {
                    "role": "user",
                    "content": "[Oxidra: the previous turn was cancelled. Do not continue unfinished work from it unless the user requests it again.]",
                },
            ])
            .as_array()
            .expect("golden source is an array")
            .to_owned()
        );
        assert_eq!(
            CompactionSource::new(projected)
                .digest_with_version(1)
                .expect("digest v1 fixture"),
            "a19db4c28d0877d20c98d8eb59d67c7a089bdff99e746f0ea9f5c5bbab250d2d"
        );
    }

    #[test]
    fn projection_v3_keeps_the_prompt_after_a_superseded_cancellation() {
        let events = vec![
            user(1, "limited"),
            event(2, Some("limited"), "context.limit_reached", json!({})),
            event(
                3,
                Some("limited"),
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
            event(4, Some("limited"), "turn.cancelled", json!({})),
            event(
                5,
                Some("limited"),
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-2",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
        ];

        assert!(
            project_events_for_compaction(2, &events).is_err(),
            "frozen v2 did not treat cancellation as a settled retry attempt"
        );
        assert_eq!(
            project_events_for_compaction(3, &events).unwrap(),
            vec![json!({"role":"user","content":"limited"})]
        );
    }

    #[test]
    fn projection_v3_omits_cancellation_notice_superseded_by_retry() {
        let events = vec![
            user(1, "limited"),
            event(2, Some("limited"), "context.limit_reached", json!({})),
            event(
                3,
                Some("limited"),
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
            event(
                4,
                Some("limited"),
                "response.completed",
                json!({"output_items":[{
                    "type":"function_call",
                    "call_id":"call-1",
                    "name":"shell",
                    "arguments":"{}"
                }]}),
            ),
            event(5, Some("limited"), "turn.cancelled", json!({})),
            event(
                6,
                Some("limited"),
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-2",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
        ];

        let v2 = project_events_for_compaction(2, &events).unwrap();
        assert!(v2.iter().any(|item| {
            item.get("content")
                .and_then(Value::as_str)
                .is_some_and(|content| content.contains("previous turn was cancelled"))
        }));
        let v3 = project_events_for_compaction(3, &events).unwrap();
        assert!(!v3.iter().any(|item| {
            item.get("content")
                .and_then(Value::as_str)
                .is_some_and(|content| content.contains("previous turn was cancelled"))
        }));
    }

    #[test]
    fn frozen_source_projection_v2_remains_literal_after_v3_upgrade() {
        let events = frozen_retry_events();
        let expected: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/retry_projection_v2.json"))
                .expect("valid frozen projection fixture");

        assert_eq!(
            project_events_for_compaction(2, &events).expect("frozen v2 projection"),
            expected
        );

        let v3 = project_events_for_compaction(3, &events).expect("current v3 projection");
        assert!(!v3.iter().any(|item| {
            item.get("content")
                .and_then(Value::as_str)
                .is_some_and(|content| content.contains("previous turn was cancelled"))
        }));
        assert_eq!(v3[0], json!({"role":"user","content":"retry prompt"}));
    }

    #[test]
    fn checkpoint_projection_replaces_covered_history_and_preserves_tail_calls() {
        let events = checkpointed_events(false);
        let chain = validate_checkpoint_chain(&events).expect("valid checkpoint chain");
        let projected =
            project_checkpoint_and_tail(&events, &chain).expect("project checkpoint and tail");

        assert_eq!(
            projected.first(),
            Some(
                &compacted_history_item(
                    SUMMARY_ENVELOPE_VERSION,
                    "The first turn established an older fact.",
                )
                .expect("current envelope is registered")
            )
        );
        assert!(
            !projected
                .iter()
                .any(|item| item.get("id") == Some(&json!("m-t1"))),
            "covered response items must not be replayed"
        );
        assert!(projected.iter().any(|item| {
            item.get("type") == Some(&json!("function_call"))
                && item.get("call_id") == Some(&json!("call-1"))
        }));
        assert!(projected.iter().any(|item| {
            item.get("type") == Some(&json!("function_call_output"))
                && item.get("call_id") == Some(&json!("call-1"))
        }));
        assert!(projected.iter().any(|item| {
            item.get("role") == Some(&json!("user")) && item.get("content") == Some(&json!("t3"))
        }));
        let bytes = serde_json::to_vec(&projected).expect("serialize projection");
        assert!(
            !String::from_utf8(bytes)
                .expect("projection is UTF-8")
                .contains("stale instructions")
        );
    }

    #[test]
    fn display_events_do_not_change_checkpoint_projection_bytes() {
        let base = checkpointed_events(false);
        let with_display = checkpointed_events(true);
        let base_chain = validate_checkpoint_chain(&base).expect("valid base chain");
        let display_chain = validate_checkpoint_chain(&with_display).expect("valid display chain");

        let base_bytes = serde_json::to_vec(
            &project_checkpoint_and_tail(&base, &base_chain).expect("project base"),
        )
        .expect("serialize base");
        let display_bytes = serde_json::to_vec(
            &project_checkpoint_and_tail(&with_display, &display_chain)
                .expect("project with display event"),
        )
        .expect("serialize display projection");
        assert_eq!(display_bytes, base_bytes);
    }

    #[test]
    fn invalid_checkpoint_never_falls_back_to_full_history() {
        let mut events = checkpointed_events(false);
        let chain = validate_checkpoint_chain(&events).expect("valid checkpoint chain");
        let checkpoint = events
            .iter_mut()
            .find(|event| event.kind == COMPACTION_CHECKPOINT_KIND)
            .expect("checkpoint event");
        checkpoint.data["parent_checkpoint_id"] = json!("unknown-parent");

        assert!(validate_checkpoint_chain(&events).is_err());
        assert!(project_checkpoint_and_tail(&events, &chain).is_err());
    }

    #[test]
    fn empty_checkpoint_chain_uses_the_original_projection() {
        let events = vec![user(1, "t1"), response(2, "t1")];
        let chain = validate_checkpoint_chain(&events).expect("valid empty checkpoint chain");
        assert_eq!(
            project_checkpoint_and_tail(&events, &chain)
                .expect("project journal without a checkpoint"),
            project_events(&events).expect("valid original projection")
        );
    }
}
