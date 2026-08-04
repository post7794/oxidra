//! Pure projections from canonical journal events into provider input items.
//!
//! Rendering options deliberately do not enter this module. Compact or full
//! terminal output must never change the bytes replayed to the provider.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::compaction::{COMPACTION_CHECKPOINT_KIND, CheckpointChain, compacted_history_item};
use crate::error::{OxidraError, Result};
use crate::session::JournalEvent;
use crate::turn::complete_prefix_candidates;

/// Current immutable event-to-item format used when building compaction input.
pub const SOURCE_PROJECTION_VERSION: u32 = 1;

/// Project only committed events into the stateless Responses `input` array.
/// Partial deltas and aborted responses are intentionally absent.
pub fn project_events(events: &[JournalEvent]) -> Result<Vec<Value>> {
    project_events_v1(events)
}

/// Rebuild the exact event projection recorded by a compaction attempt.
/// Published match arms are immutable; new formats must add a new version.
pub fn project_events_for_compaction(version: u32, events: &[JournalEvent]) -> Result<Vec<Value>> {
    match version {
        1 => project_events_v1(events),
        _ => Err(OxidraError::Session(format!(
            "unsupported compaction source projection version {version}"
        ))),
    }
}

fn project_events_v1(events: &[JournalEvent]) -> Result<Vec<Value>> {
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
                let item = event.data.get("item").ok_or_else(|| {
                    OxidraError::Session(format!(
                        "user.message at seq {} has no input item",
                        event.seq
                    ))
                })?;
                validate_user_input_item(item, event.seq)?;
                let abandoned = event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| abandoned_turns.contains(turn_id));
                if !abandoned {
                    projected.push(item.clone());
                }
            }
            "response.completed" => {
                let items = response_output_items(event)?;
                validate_response_output_items(items)?;
                projected.extend(items.iter().cloned());
            }
            kind if is_tool_terminal_v1(kind) => {
                if let Some(item) = tool_output_item_v1(&event.data) {
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
    let boundary_is_valid = complete_prefix_candidates(events)?
        .iter()
        .any(|candidate| candidate.covers_through_seq == covers_through_seq);
    if !boundary_is_valid {
        return Err(OxidraError::Session(format!(
            "sequence {covers_through_seq} is not a complete turn prefix boundary"
        )));
    }

    project_tail_after_validated_cutoff(events, covers_through_seq)
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
    chain.ensure_matches(events)?;
    let Some(checkpoint) = chain.latest() else {
        if events
            .iter()
            .any(|event| event.kind == COMPACTION_CHECKPOINT_KIND)
        {
            return Err(OxidraError::Session(
                "checkpoint events are present but the validated chain is empty".to_owned(),
            ));
        }
        return project_events(events);
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
    )?);
    Ok(projected)
}

fn project_tail_after_validated_cutoff(
    events: &[JournalEvent],
    covers_through_seq: u64,
) -> Result<Vec<Value>> {
    let tail = events
        .iter()
        .filter(|event| event.seq > covers_through_seq)
        .cloned()
        .collect::<Vec<_>>();
    project_events(&tail)
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
        COMPACTION_PROMPT_VERSION, COMPACTION_STARTED_KIND, Checkpoint, CompactionSource,
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
