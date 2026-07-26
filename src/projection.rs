//! Pure projections from canonical journal events into provider input items.
//!
//! Rendering options deliberately do not enter this module. Compact or full
//! terminal output must never change the bytes replayed to the provider.

use std::collections::HashSet;

use serde_json::{Value, json};

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
}
