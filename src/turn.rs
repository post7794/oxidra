//! Deterministic turn boundaries derived from canonical journal events.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::error::{OxidraError, Result};
use crate::session::JournalEvent;

pub const TURN_BOUNDARY_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionEvidence {
    ExplicitMarker,
    InlineResponse,
    LegacyNextUser,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnState {
    Complete(CompletionEvidence),
    Cancelled,
    Aborted,
    Failed,
    Stalled,
    LimitReached,
    InDoubt,
    Incomplete,
    OpenTail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnSpan {
    pub turn_id: String,
    pub start_index: usize,
    pub end_index_exclusive: usize,
    pub covers_from_seq: u64,
    pub covers_through_seq: u64,
    pub state: TurnState,
    /// Whether a later complete boundary may safely cover this turn.
    pub cut_safe: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletePrefix {
    /// Number of successfully completed turns covered by this cutoff.
    pub turn_count: usize,
    pub covers_through_seq: u64,
}

/// Segment user turns without changing or projecting any journal content.
pub fn segment_turns(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    let mut starts = Vec::new();
    let mut seen_turn_ids = HashSet::new();
    for (index, event) in events.iter().enumerate() {
        if event.kind != "user.message" {
            continue;
        }
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!("user.message at seq {} has no turn_id", event.seq))
        })?;
        if !seen_turn_ids.insert(turn_id.to_owned()) {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one user.message"
            )));
        }
        starts.push((index, turn_id.to_owned()));
    }

    let ranges = starts
        .iter()
        .enumerate()
        .map(|(position, (start, turn_id))| {
            let end = starts
                .get(position + 1)
                .map(|(index, _)| *index)
                .unwrap_or(events.len());
            (turn_id.clone(), (*start, end))
        })
        .collect::<HashMap<_, _>>();

    for (index, event) in events.iter().enumerate() {
        let Some(turn_id) = event.turn_id.as_deref() else {
            if is_turn_scoped_kind(&event.kind) {
                return Err(OxidraError::Session(format!(
                    "{} at seq {} has no turn_id",
                    event.kind, event.seq
                )));
            }
            continue;
        };
        let Some((start, end)) = ranges.get(turn_id) else {
            if is_turn_scoped_kind(&event.kind) {
                return Err(OxidraError::Session(format!(
                    "{} at seq {} references unknown turn {turn_id}",
                    event.kind, event.seq
                )));
            }
            continue;
        };
        if index < *start || index >= *end {
            return Err(OxidraError::Session(format!(
                "event at seq {} appears outside turn {turn_id}",
                event.seq
            )));
        }
    }

    let mut turns = Vec::with_capacity(starts.len());
    for (position, (start_index, turn_id)) in starts.iter().enumerate() {
        let end_index_exclusive = starts
            .get(position + 1)
            .map(|(index, _)| *index)
            .unwrap_or(events.len());
        let user_event = &events[*start_index];
        let tagged = boundary_version(user_event)?.is_some();
        let turn_events = events[*start_index..end_index_exclusive]
            .iter()
            .filter(|event| event.turn_id.as_deref() == Some(turn_id.as_str()))
            .collect::<Vec<_>>();
        let markers = turn_events
            .iter()
            .copied()
            .filter(|event| event.kind == "turn.completed")
            .collect::<Vec<_>>();
        if markers.len() > 1 {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one turn.completed marker"
            )));
        }
        let inline_completions = turn_events
            .iter()
            .copied()
            .filter(|event| event.data.get("turn_completion").is_some())
            .collect::<Vec<_>>();
        if inline_completions.len() > 1 {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one inline completion boundary"
            )));
        }

        let calls = validate_call_outputs(&turn_events)?;
        let has_next_user = position + 1 < starts.len();
        let inline_completion = inline_completions.first().copied();
        if let Some(response) = inline_completion {
            validate_inline_completion(user_event, response, &turn_events, &calls)?;
        }
        let (state, covers_through_seq) = if let Some(marker) = markers.first().copied() {
            validate_completed_marker(user_event, marker, &turn_events, &calls)?;
            if let Some(response) = inline_completion {
                let marker_response_seq = required_u64(marker, "final_response_seq")?;
                if marker_response_seq != response.seq {
                    return Err(OxidraError::Session(format!(
                        "turn.completed at seq {} conflicts with inline completion at seq {}",
                        marker.seq, response.seq
                    )));
                }
            }
            (
                TurnState::Complete(CompletionEvidence::ExplicitMarker),
                marker.seq,
            )
        } else if let Some(response) = inline_completion {
            (
                TurnState::Complete(CompletionEvidence::InlineResponse),
                response.seq,
            )
        } else {
            let state = classify_unmarked_turn(&turn_events, tagged, has_next_user, &calls);
            let covers_through_seq = if end_index_exclusive > *start_index {
                events[end_index_exclusive - 1].seq
            } else {
                user_event.seq
            };
            (state, covers_through_seq)
        };
        let cut_safe = match state {
            TurnState::Complete(_) => true,
            TurnState::Cancelled
            | TurnState::Aborted
            | TurnState::Failed
            | TurnState::Stalled
            | TurnState::LimitReached => has_next_user && calls.is_resolved(),
            TurnState::Incomplete => has_next_user && calls.is_resolved(),
            TurnState::InDoubt | TurnState::OpenTail => false,
        };

        turns.push(TurnSpan {
            turn_id: turn_id.clone(),
            start_index: *start_index,
            end_index_exclusive,
            covers_from_seq: user_event.seq,
            covers_through_seq,
            state,
            cut_safe,
        });
    }
    Ok(turns)
}

/// Return complete cutoffs in the contiguous cut-safe prefix.
pub fn complete_prefix_candidates(events: &[JournalEvent]) -> Result<Vec<CompletePrefix>> {
    let mut candidates = Vec::new();
    let mut complete_turns = 0;
    for turn in segment_turns(events)? {
        if !turn.cut_safe {
            break;
        }
        if matches!(turn.state, TurnState::Complete(_)) {
            complete_turns += 1;
            candidates.push(CompletePrefix {
                turn_count: complete_turns,
                covers_through_seq: turn.covers_through_seq,
            });
        }
    }
    Ok(candidates)
}

fn boundary_version(event: &JournalEvent) -> Result<Option<u64>> {
    let Some(value) = event.data.get("turn_boundary_version") else {
        return Ok(None);
    };
    let version = value.as_u64().ok_or_else(|| {
        OxidraError::Session(format!(
            "turn boundary version at seq {} is not an unsigned integer",
            event.seq
        ))
    })?;
    if version != TURN_BOUNDARY_VERSION {
        return Err(OxidraError::Session(format!(
            "unsupported turn boundary version {version} at seq {}",
            event.seq
        )));
    }
    Ok(Some(version))
}

fn validate_completed_marker(
    user_event: &JournalEvent,
    marker: &JournalEvent,
    turn_events: &[&JournalEvent],
    calls: &CallValidation,
) -> Result<()> {
    if boundary_version(marker)? != Some(TURN_BOUNDARY_VERSION) {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} has no boundary version",
            marker.seq
        )));
    }
    let covers_from_seq = required_u64(marker, "covers_from_seq")?;
    let final_response_seq = required_u64(marker, "final_response_seq")?;
    let covers_through_seq = required_u64(marker, "covers_through_seq")?;
    if covers_from_seq != user_event.seq || covers_through_seq != marker.seq {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} has inconsistent coverage",
            marker.seq
        )));
    }
    let final_response = turn_events
        .iter()
        .copied()
        .find(|event| event.seq == final_response_seq)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.completed at seq {} references missing response seq {final_response_seq}",
                marker.seq
            ))
        })?;
    if final_response.kind != "response.completed"
        || final_response.seq >= marker.seq
        || response_has_function_call(final_response)
    {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} does not reference a final response",
            marker.seq
        )));
    }
    let last_response_event_seq = turn_events
        .iter()
        .rev()
        .find(|event| {
            matches!(
                event.kind.as_str(),
                "response.started" | "response.completed" | "response.failed" | "response.aborted"
            )
        })
        .map(|event| event.seq);
    if last_response_event_seq != Some(final_response_seq) {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} does not reference the last response terminal event",
            marker.seq
        )));
    }
    if turn_events
        .iter()
        .any(|event| event.seq > marker.seq || disqualifies_completion(event))
    {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} conflicts with another turn event",
            marker.seq
        )));
    }
    if !calls.is_resolved() {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} leaves unresolved tool calls",
            marker.seq
        )));
    }
    Ok(())
}

fn validate_inline_completion(
    user_event: &JournalEvent,
    response: &JournalEvent,
    turn_events: &[&JournalEvent],
    calls: &CallValidation,
) -> Result<()> {
    let completion = response
        .data
        .get("turn_completion")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "response.completed at seq {} has an invalid inline completion boundary",
                response.seq
            ))
        })?;
    let version = completion
        .get("turn_boundary_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "inline completion at seq {} has no boundary version",
                response.seq
            ))
        })?;
    if version != TURN_BOUNDARY_VERSION {
        return Err(OxidraError::Session(format!(
            "unsupported turn boundary version {version} at seq {}",
            response.seq
        )));
    }
    let field = |name: &str| completion.get(name).and_then(Value::as_u64);
    if field("covers_from_seq") != Some(user_event.seq)
        || field("final_response_seq") != Some(response.seq)
        || field("covers_through_seq") != Some(response.seq)
    {
        return Err(OxidraError::Session(format!(
            "inline completion at seq {} has inconsistent coverage",
            response.seq
        )));
    }
    if response_has_function_call(response)
        || last_response_event_seq(turn_events) != Some(response.seq)
        || turn_events.iter().any(disqualifies_completion)
        || !calls.is_resolved()
    {
        return Err(OxidraError::Session(format!(
            "inline completion at seq {} does not describe a complete turn",
            response.seq
        )));
    }
    Ok(())
}

fn classify_unmarked_turn(
    turn_events: &[&JournalEvent],
    tagged: bool,
    has_next_user: bool,
    calls: &CallValidation,
) -> TurnState {
    if calls.unresolved_in_doubt
        || turn_events
            .iter()
            .any(|event| event.kind == "tool.in_doubt")
            && calls.pending_count > 0
    {
        return TurnState::InDoubt;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "turn.cancelled")
    {
        return TurnState::Cancelled;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "response.aborted")
    {
        return TurnState::Aborted;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "response.failed")
    {
        return TurnState::Failed;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "agent.stalled")
    {
        return TurnState::Stalled;
    }
    if turn_events.iter().any(|event| {
        matches!(
            event.kind.as_str(),
            "agent.limit_reached" | "context.limit_reached"
        )
    }) {
        return TurnState::LimitReached;
    }
    if !tagged && has_next_user && calls.is_resolved() && last_response_is_final(turn_events) {
        return TurnState::Complete(CompletionEvidence::LegacyNextUser);
    }
    if has_next_user {
        TurnState::Incomplete
    } else {
        TurnState::OpenTail
    }
}

fn last_response_is_final(turn_events: &[&JournalEvent]) -> bool {
    turn_events
        .iter()
        .rev()
        .copied()
        .find(|event| {
            matches!(
                event.kind.as_str(),
                "response.started" | "response.completed" | "response.failed" | "response.aborted"
            )
        })
        .is_some_and(|event| {
            event.kind == "response.completed" && !response_has_function_call(event)
        })
}

fn last_response_event_seq(turn_events: &[&JournalEvent]) -> Option<u64> {
    turn_events
        .iter()
        .rev()
        .find(|event| {
            matches!(
                event.kind.as_str(),
                "response.started" | "response.completed" | "response.failed" | "response.aborted"
            )
        })
        .map(|event| event.seq)
}

fn disqualifies_completion(event: &&JournalEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "turn.cancelled"
            | "response.aborted"
            | "response.failed"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
    )
}

#[derive(Default)]
struct CallValidation {
    pending_count: usize,
    unresolved_in_doubt: bool,
    uncertain: bool,
}

impl CallValidation {
    fn is_resolved(&self) -> bool {
        self.pending_count == 0 && !self.unresolved_in_doubt && !self.uncertain
    }
}

fn validate_call_outputs(turn_events: &[&JournalEvent]) -> Result<CallValidation> {
    #[derive(Default)]
    struct CallOccurrence {
        call_id: Option<String>,
        started_seq: Option<u64>,
        in_doubt: bool,
        terminal: bool,
    }

    let mut calls = Vec::<CallOccurrence>::new();
    let mut uncertain = false;
    for event in turn_events {
        if event.kind == "response.completed" {
            for item in response_output_items(event) {
                if item.get("type").and_then(Value::as_str) != Some("function_call") {
                    continue;
                }
                let call_id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                uncertain |= call_id.is_none();
                calls.push(CallOccurrence {
                    call_id,
                    ..CallOccurrence::default()
                });
            }
            continue;
        }

        if event.kind == "tool.started" {
            let call_id = event_call_id(event);
            let position = call_id.and_then(|call_id| {
                calls.iter().position(|call| {
                    !call.terminal
                        && call.started_seq.is_none()
                        && call.call_id.as_deref() == Some(call_id)
                })
            });
            if let Some(position) = position {
                calls[position].started_seq = Some(event.seq);
            } else {
                uncertain = true;
            }
            continue;
        }

        if event.kind == "tool.in_doubt" {
            let call_id = event_call_id(event);
            let started_seq = event.data.get("started_seq").and_then(Value::as_u64);
            let position = started_seq
                .and_then(|started_seq| {
                    calls
                        .iter()
                        .position(|call| !call.terminal && call.started_seq == Some(started_seq))
                })
                .or_else(|| {
                    call_id.and_then(|call_id| {
                        calls.iter().rposition(|call| {
                            !call.terminal
                                && call.started_seq.is_some()
                                && call.call_id.as_deref() == Some(call_id)
                        })
                    })
                })
                .or_else(|| {
                    call_id.and_then(|call_id| {
                        calls.iter().rposition(|call| {
                            !call.terminal && call.call_id.as_deref() == Some(call_id)
                        })
                    })
                });
            if let Some(position) = position {
                calls[position].in_doubt = true;
            } else {
                uncertain = true;
            }
            continue;
        }

        if is_terminal_tool_output(&event.kind) {
            let call_id = event_call_id(event);
            let started_seq = event.data.get("started_seq").and_then(Value::as_u64);
            let position = started_seq
                .and_then(|started_seq| {
                    calls
                        .iter()
                        .position(|call| !call.terminal && call.started_seq == Some(started_seq))
                })
                .or_else(|| {
                    if event.kind == "tool.in_doubt_resolved" {
                        call_id.and_then(|call_id| {
                            calls.iter().rposition(|call| {
                                !call.terminal
                                    && call.in_doubt
                                    && call.call_id.as_deref() == Some(call_id)
                            })
                        })
                    } else if event.kind.starts_with("tool.skipped_due_to_") {
                        call_id.and_then(|call_id| {
                            calls.iter().position(|call| {
                                !call.terminal
                                    && call.started_seq.is_none()
                                    && call.call_id.as_deref() == Some(call_id)
                            })
                        })
                    } else {
                        call_id
                            .and_then(|call_id| {
                                calls.iter().rposition(|call| {
                                    !call.terminal
                                        && !call.in_doubt
                                        && call.started_seq.is_some()
                                        && call.call_id.as_deref() == Some(call_id)
                                })
                            })
                            .or_else(|| {
                                call_id.and_then(|call_id| {
                                    calls.iter().position(|call| {
                                        !call.terminal
                                            && call.started_seq.is_none()
                                            && call.call_id.as_deref() == Some(call_id)
                                    })
                                })
                            })
                    }
                });
            if let Some(position) = position {
                calls[position].terminal = true;
                calls[position].in_doubt = false;
            } else {
                uncertain = true;
            }
        }
    }
    let pending_count = calls.iter().filter(|call| !call.terminal).count();
    Ok(CallValidation {
        pending_count,
        unresolved_in_doubt: calls.iter().any(|call| !call.terminal && call.in_doubt),
        uncertain,
    })
}

fn response_has_function_call(event: &JournalEvent) -> bool {
    response_output_items(event)
        .iter()
        .any(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
}

fn response_output_items(event: &JournalEvent) -> Vec<&Value> {
    event
        .data
        .get("output_items")
        .and_then(Value::as_array)
        .or_else(|| {
            event
                .data
                .get("raw_response")
                .and_then(|response| response.get("output"))
                .and_then(Value::as_array)
        })
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn is_terminal_tool_output(kind: &str) -> bool {
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

fn is_turn_scoped_kind(kind: &str) -> bool {
    matches!(
        kind,
        "user.message"
            | "response.started"
            | "response.completed"
            | "response.failed"
            | "response.aborted"
            | "turn.completed"
            | "turn.cancelled"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
            | "tool.started"
            | "tool.completed"
            | "tool.cancelled"
            | "tool.in_doubt"
            | "tool.in_doubt_resolved"
            | "tool.skipped_due_to_cancel"
            | "tool.skipped_due_to_in_doubt"
            | "tool.skipped_due_to_limit"
            | "tool.skipped_due_to_stalled"
            | "tool.skipped_due_to_recovery"
    )
}

fn required_u64(event: &JournalEvent, field: &str) -> Result<u64> {
    event
        .data
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "{} at seq {} has no valid {field}",
                event.kind, event.seq
            ))
        })
}

fn event_call_id(event: &JournalEvent) -> Option<&str> {
    event
        .data
        .get("call_id")
        .or_else(|| event.data.get("id"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(seq: u64, turn_id: &str, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: chrono::DateTime::from_timestamp(0, 0).expect("valid test timestamp"),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        }
    }

    fn user(seq: u64, turn_id: &str, tagged: bool) -> JournalEvent {
        let mut data = json!({
            "item": {"role": "user", "content": turn_id},
        });
        if tagged {
            data["turn_boundary_version"] = json!(TURN_BOUNDARY_VERSION);
        }
        event(seq, turn_id, "user.message", data)
    }

    fn response(seq: u64, turn_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "response.completed",
            json!({"output_items": [{"type": "message", "id": format!("m-{seq}")}]}),
        )
    }

    fn inline_response(seq: u64, turn_id: &str, covers_from_seq: u64) -> JournalEvent {
        let mut response = response(seq, turn_id);
        response.data["turn_completion"] = json!({
            "turn_boundary_version": TURN_BOUNDARY_VERSION,
            "covers_from_seq": covers_from_seq,
            "final_response_seq": seq,
            "covers_through_seq": seq,
        });
        response
    }

    fn call(seq: u64, turn_id: &str, call_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "response.completed",
            json!({
                "output_items": [{
                    "type": "function_call",
                    "call_id": call_id,
                    "name": "read",
                    "arguments": "{}",
                }],
            }),
        )
    }

    fn tool_output(seq: u64, turn_id: &str, call_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "tool.completed",
            json!({"call_id": call_id, "output": "ok"}),
        )
    }

    fn marker(
        seq: u64,
        turn_id: &str,
        covers_from_seq: u64,
        final_response_seq: u64,
    ) -> JournalEvent {
        event(
            seq,
            turn_id,
            "turn.completed",
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": covers_from_seq,
                "final_response_seq": final_response_seq,
                "covers_through_seq": seq,
            }),
        )
    }

    #[test]
    fn explicit_turn_without_tools_is_complete() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
        ];

        let turns = segment_turns(&events).expect("valid turn");
        assert_eq!(turns.len(), 1);
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
        assert_eq!(turns[0].covers_from_seq, 1);
        assert_eq!(turns[0].covers_through_seq, 3);
        assert!(turns[0].cut_safe);
        assert_eq!(
            complete_prefix_candidates(&events).expect("valid prefix"),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 3,
            }]
        );
    }

    #[test]
    fn inline_response_recovers_the_marker_crash_window() {
        let events = vec![user(1, "t1", true), inline_response(2, "t1", 1)];

        let turns = segment_turns(&events).expect("valid inline boundary");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::InlineResponse)
        );
        assert!(turns[0].cut_safe);
        assert_eq!(turns[0].covers_through_seq, 2);
    }

    #[test]
    fn explicit_turn_with_multiple_tool_rounds_is_complete() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            tool_output(3, "t1", "c1"),
            call(4, "t1", "c2"),
            tool_output(5, "t1", "c2"),
            response(6, "t1"),
            marker(7, "t1", 1, 6),
        ];

        assert_eq!(
            segment_turns(&events).expect("valid turn")[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
    }

    #[test]
    fn cancelled_and_aborted_turns_are_not_complete() {
        let events = vec![
            user(1, "cancelled", true),
            event(2, "cancelled", "turn.cancelled", json!({})),
            user(3, "aborted", true),
            event(4, "aborted", "response.aborted", json!({})),
            user(5, "tail", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::Cancelled);
        assert_eq!(turns[1].state, TurnState::Aborted);
        assert_eq!(turns[2].state, TurnState::OpenTail);
        assert!(turns[0].cut_safe);
        assert!(turns[1].cut_safe);
        assert!(!turns[2].cut_safe);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn unresolved_in_doubt_call_blocks_completion() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            event(3, "t1", "tool.in_doubt", json!({"call_id": "c1"})),
            user(4, "t2", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::InDoubt);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn legacy_middle_turn_closes_but_legacy_tail_stays_open() {
        let events = vec![
            user(1, "legacy-1", false),
            response(2, "legacy-1"),
            user(3, "legacy-2", false),
            response(4, "legacy-2"),
        ];

        let turns = segment_turns(&events).expect("valid legacy turns");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::LegacyNextUser)
        );
        assert_eq!(turns[1].state, TurnState::OpenTail);
        assert_eq!(
            complete_prefix_candidates(&events).expect("valid prefix"),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 2,
            }]
        );
    }

    #[test]
    fn tagged_turn_without_marker_never_uses_legacy_completion() {
        let events = vec![
            user(1, "tagged", true),
            response(2, "tagged"),
            user(3, "next", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::Incomplete);
        assert!(turns[0].cut_safe);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn rejects_marker_with_inconsistent_coverage() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 99, 2),
        ];

        let error = segment_turns(&events).expect_err("coverage must be rejected");
        assert!(error.to_string().contains("inconsistent coverage"));
    }

    #[test]
    fn rejects_marker_that_points_to_a_tool_call_response() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            tool_output(3, "t1", "c1"),
            marker(4, "t1", 1, 2),
        ];

        let error = segment_turns(&events).expect_err("non-final response must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not reference a final response")
        );
    }

    #[test]
    fn rejects_marker_that_points_to_a_missing_response() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 99),
        ];

        let error = segment_turns(&events).expect_err("missing response must be rejected");
        assert!(error.to_string().contains("references missing response"));
    }

    #[test]
    fn rejects_marker_that_points_before_the_last_response() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            response(3, "t1"),
            marker(4, "t1", 1, 2),
        ];

        let error = segment_turns(&events).expect_err("earlier response must be rejected");
        assert!(error.to_string().contains("last response terminal event"));
    }

    #[test]
    fn context_limit_is_a_terminal_non_complete_state() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "context.limit_reached", json!({})),
            user(3, "next", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::LimitReached);
        assert!(complete_prefix_candidates(&events).unwrap().is_empty());
    }

    #[test]
    fn rejects_function_call_output_crossing_turn_boundary() {
        let events = vec![
            user(1, "t1", false),
            call(2, "t1", "c1"),
            user(3, "t2", false),
            tool_output(4, "t2", "c1"),
        ];

        let turns = segment_turns(&events).expect("malformed pairing is conservatively retained");
        assert!(!turns[0].cut_safe);
        assert!(complete_prefix_candidates(&events).unwrap().is_empty());
    }

    #[test]
    fn duplicate_call_ids_follow_started_call_order() {
        let events = vec![
            user(1, "t1", true),
            event(
                2,
                "t1",
                "response.completed",
                json!({"output_items": [
                    {"type": "function_call", "call_id": "same"},
                    {"type": "function_call", "call_id": "same"},
                ]}),
            ),
            event(3, "t1", "tool.started", json!({"call_id": "same"})),
            tool_output(4, "t1", "same"),
            event(5, "t1", "tool.started", json!({"call_id": "same"})),
            tool_output(6, "t1", "same"),
            response(7, "t1"),
            marker(8, "t1", 1, 7),
        ];

        assert_eq!(
            segment_turns(&events).unwrap()[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
    }

    #[test]
    fn segmentation_and_prefix_candidates_are_deterministic() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
            user(4, "t2", true),
            response(5, "t2"),
            marker(6, "t2", 4, 5),
        ];

        let first_turns = segment_turns(&events).expect("valid turns");
        let first_prefixes = complete_prefix_candidates(&events).expect("valid prefixes");
        for _ in 0..3 {
            assert_eq!(segment_turns(&events).expect("valid turns"), first_turns);
            assert_eq!(
                complete_prefix_candidates(&events).expect("valid prefixes"),
                first_prefixes
            );
        }
    }

    #[test]
    fn neutral_global_events_do_not_change_turn_boundaries() {
        let mut global = event(
            2,
            "unused",
            "context.instructions",
            json!({"instructions": "snapshot"}),
        );
        global.turn_id = None;
        let events = vec![
            user(1, "t1", true),
            global,
            response(3, "t1"),
            marker(4, "t1", 1, 3),
        ];

        assert_eq!(
            complete_prefix_candidates(&events).unwrap(),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 4,
            }]
        );
    }

    #[test]
    fn provider_projectable_event_cannot_reference_an_unknown_turn() {
        let events = vec![response(1, "ghost")];

        let error = segment_turns(&events).expect_err("orphan response must be rejected");
        assert!(error.to_string().contains("references unknown turn ghost"));
    }
}
