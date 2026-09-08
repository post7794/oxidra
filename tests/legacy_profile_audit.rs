use chrono::Utc;
use oxidra::session::{JournalEvent, SessionHeader, SessionStore};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

fn event(
    session_id: &str,
    seq: u64,
    kind: &str,
    turn_id: Option<&str>,
    data: serde_json::Value,
) -> JournalEvent {
    JournalEvent {
        schema: 1,
        seq,
        ts: Utc::now(),
        kind: kind.to_owned(),
        session_id: session_id.to_owned(),
        turn_id: turn_id.map(str::to_owned),
        data,
    }
}

#[test]
fn pre_profile_current_turn_version_without_final_lf_reopens() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session_id = "pre-profile-current-turn";
    let events = [
        event(
            session_id,
            1,
            "session.started",
            None,
            serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
        ),
        event(
            session_id,
            2,
            "user.message",
            Some("turn-1"),
            json!({
                "item":{"role":"user","content":"x"},
                "turn_boundary_version": 8,
            }),
        ),
        event(
            session_id,
            3,
            "response.completed",
            Some("turn-1"),
            json!({
                "output_items":[{
                    "type":"message","role":"assistant",
                    "content":[{"type":"output_text","text":"a"}]
                }],
                "turn_completion":{
                    "turn_boundary_version":8,
                    "covers_from_seq":2,
                    "final_response_seq":3,
                    "covers_through_seq":3
                }
            }),
        ),
        event(
            session_id,
            4,
            "turn.completed",
            Some("turn-1"),
            json!({
                "turn_boundary_version":8,
                "covers_from_seq":2,
                "final_response_seq":3,
                "covers_through_seq":4
            }),
        ),
    ];
    let mut bytes = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    let path = store.layout().journal_path(session_id).unwrap();
    fs::write(&path, &bytes).unwrap();
    let error = store.open(session_id).err().map(|error| error.to_string());
    assert!(
        error.is_none(),
        "pre-profile current journal must reopen: {error:?}"
    );
}
