//! Pure projections from canonical journal events into provider input items.
//!
//! Rendering options deliberately do not enter this module. Compact or full
//! terminal output must never change the bytes replayed to the provider.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::compaction::{COMPACTION_CHECKPOINT_KIND, CheckpointChain, compacted_history_item};
use crate::error::{OxidraError, Result};
use crate::event_kind::is_tool_terminal;
use crate::session::JournalEvent;
use crate::turn::complete_prefix_candidates;

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
            kind if is_tool_terminal(kind) => {
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

    let tail = events
        .iter()
        .filter(|event| event.seq > covers_through_seq)
        .cloned()
        .collect::<Vec<_>>();
    Ok(project_events(&tail))
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
        return Ok(project_events(events));
    };

    let mut projected = vec![compacted_history_item(&checkpoint.summary)];
    projected.extend(project_tail(events, checkpoint.covers_through_seq)?);
    Ok(projected)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::{
        COMPACTION_PROMPT_VERSION, COMPACTION_STARTED_KIND, Checkpoint, CompactionStarted,
        build_compaction_source, validate_checkpoint_chain,
    };
    use crate::turn::TURN_BOUNDARY_VERSION;

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
            json!({"output_items": [{"type": "message", "id": format!("m-{turn_id}")}]}),
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
            instructions: "Summarize the selected source.".to_owned(),
            prompt_version: COMPACTION_PROMPT_VERSION,
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
            project_events(&events[3..])
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
            event(3, None, "render.compact", json!({"depth": "compact"})),
            response(4, "t1"),
            marker(5, "t1", 1, 4),
        ];

        let base_bytes = serde_json::to_vec(&project_events(&base)).expect("serialize projection");
        let enriched_bytes = serde_json::to_vec(&project_events(&with_non_provider_events))
            .expect("serialize projection");
        assert_eq!(enriched_bytes, base_bytes);
    }

    #[test]
    fn checkpoint_projection_replaces_covered_history_and_preserves_tail_calls() {
        let events = checkpointed_events(false);
        let chain = validate_checkpoint_chain(&events).expect("valid checkpoint chain");
        let projected =
            project_checkpoint_and_tail(&events, &chain).expect("project checkpoint and tail");

        assert_eq!(
            projected.first(),
            Some(&compacted_history_item(
                "The first turn established an older fact."
            ))
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
            project_events(&events)
        );
    }
}
