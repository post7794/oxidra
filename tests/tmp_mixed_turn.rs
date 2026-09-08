use chrono::{DateTime, Utc};
use oxidra::session::JournalEvent;
use oxidra::turn::segment_turns;
use serde_json::json;
fn ev(seq: u64, turn: &str, kind: &str, data: serde_json::Value) -> JournalEvent {
    JournalEvent {
        schema: 1,
        seq,
        ts: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        kind: kind.into(),
        session_id: "mixed".into(),
        turn_id: Some(turn.into()),
        data,
    }
}
#[test]
fn mixed_v2_prefix_is_not_reinterpreted_by_v8_tail() {
    let events = vec![
        ev(1, "legacy", "context.limit_reached", json!({})),
        ev(
            2,
            "legacy",
            "user.message",
            json!({"item":{"role":"user","content":"old"},"turn_boundary_version":2}),
        ),
        ev(
            3,
            "legacy",
            "turn.abandoned",
            json!({"user_message_seq":2,"reason":"old"}),
        ),
        ev(
            4,
            "modern",
            "user.message",
            json!({"item":{"role":"user","content":"new"},"turn_boundary_version":8}),
        ),
        ev(
            5,
            "modern",
            "response.completed",
            json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"turn_completion":{"turn_boundary_version":8,"covers_from_seq":4,"final_response_seq":5,"covers_through_seq":5}}),
        ),
    ];
    let turns =
        segment_turns(&events).expect("mixed historical/current turns must remain readable");
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0].state, oxidra::turn::TurnState::LimitReached);
}
