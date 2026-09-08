use chrono::Utc;
use oxidra::session::{JournalEvent, SessionHeader, SessionStore};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

fn evt(seq: u64, kind: &str, turn: Option<&str>, data: serde_json::Value) -> JournalEvent {
    JournalEvent {
        schema: 1,
        seq,
        ts: Utc::now(),
        kind: kind.to_owned(),
        session_id: "legacy-audit".to_owned(),
        turn_id: turn.map(str::to_owned),
        data,
    }
}

fn evt_for(
    session: &str,
    seq: u64,
    kind: &str,
    turn: Option<&str>,
    data: serde_json::Value,
) -> JournalEvent {
    JournalEvent {
        schema: 1,
        seq,
        ts: Utc::now(),
        kind: kind.to_owned(),
        session_id: session.to_owned(),
        turn_id: turn.map(str::to_owned),
        data,
    }
}

#[test]
fn legacy_abandon_recovery_no_lf() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let mut bytes = Vec::new();
    let header = evt(
        1,
        "session.started",
        None,
        serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
    );
    let user = evt(
        2,
        "user.message",
        Some("t"),
        json!({"item":{"role":"user","content":"x"}}),
    );
    let limit = evt(3, "context.limit_reached", Some("t"), json!({}));
    let abandon = evt(
        4,
        "turn.abandoned",
        Some("t"),
        json!({"user_message_seq":2,"reason":"old"}),
    );
    for event in [&header, &user, &limit] {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    bytes.extend(serde_json::to_vec(&abandon).unwrap());
    fs::write(store.layout().journal_path("legacy-audit").unwrap(), &bytes).unwrap();
    let result = store.open("legacy-audit");
    let error = result.err().map(|error| error.to_string());
    println!("error={error:?}");
    assert!(
        error.is_none(),
        "legacy old recovery should remain readable: {error:?}"
    );
}

#[test]
fn legacy_direct_response_then_next_user_no_lf() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let mut bytes = Vec::new();
    let header = evt(
        1,
        "session.started",
        None,
        serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
    );
    let user1 = evt(
        2,
        "user.message",
        Some("t1"),
        json!({"item":{"role":"user","content":"x"}}),
    );
    let response1 = evt(
        3,
        "response.completed",
        Some("t1"),
        json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"a"}]}]}),
    );
    let user2 = evt(
        4,
        "user.message",
        Some("t2"),
        json!({"item":{"role":"user","content":"y"}}),
    );
    for event in [&header, &user1, &response1, &user2] {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    let response2 = evt(
        5,
        "response.completed",
        Some("t2"),
        json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"b"}]}]}),
    );
    bytes.extend(serde_json::to_vec(&response2).unwrap());
    fs::write(store.layout().journal_path("legacy-audit").unwrap(), &bytes).unwrap();
    let result = store.open("legacy-audit");
    let error = result.err().map(|error| error.to_string());
    println!("result_error={error:?}");
    assert!(
        error.is_none(),
        "legacy direct response should remain readable: {error:?}"
    );
}

#[test]
fn legacy_direct_response_followed_by_next_user_no_lf() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let mut bytes = Vec::new();
    let header = evt(
        1,
        "session.started",
        None,
        serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
    );
    let user1 = evt(
        2,
        "user.message",
        Some("t1"),
        json!({"item":{"role":"user","content":"x"}}),
    );
    let response1 = evt(
        3,
        "response.completed",
        Some("t1"),
        json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"a"}]}]}),
    );
    let user2 = evt(
        4,
        "user.message",
        Some("t2"),
        json!({"item":{"role":"user","content":"y"}}),
    );
    for event in [&header, &user1, &response1] {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    bytes.extend(serde_json::to_vec(&user2).unwrap());
    fs::write(store.layout().journal_path("legacy-audit").unwrap(), &bytes).unwrap();
    let error = store
        .open("legacy-audit")
        .err()
        .map(|error| error.to_string());
    println!("direct-next-user error={error:?}");
    assert!(
        error.is_none(),
        "legacy direct response + next user should remain readable: {error:?}"
    );
}

#[test]
fn profile_claim_on_later_event_is_not_silently_ignored() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let mut journal = store
        .create_with_id("legacy-audit", SessionHeader::new(temp.path(), "m"))
        .unwrap();
    journal
        .append_custom_and_sync("custom.audit", None, json!({"ok":true}))
        .unwrap();
    let path = journal.journal_path().to_owned();
    drop(journal);
    let bytes = fs::read(&path).unwrap();
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let first = lines.next().unwrap().to_vec();
    let second = lines.next().unwrap().to_vec();
    let mut raw: serde_json::Value = serde_json::from_slice(&second).unwrap();
    raw.as_object_mut().unwrap().insert(
        "journal_json_profile".to_owned(),
        json!({"name":"bounded-json-v2","version":2}),
    );
    let mut forged = first;
    forged.push(b'\n');
    forged.extend(serde_json::to_vec(&raw).unwrap());
    forged.push(b'\n');
    fs::write(&path, forged).unwrap();
    let result = store.inspect("legacy-audit");
    let error = result.err().map(|error| error.to_string());
    println!("later claim error={error:?}");
    assert!(error.is_some(), "misplaced profile claim must fail closed");
}

#[test]
fn unclaimed_modern_turn_boundary_v8_is_not_misclassified_as_legacy() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session = "modern-no-claim";
    let mut bytes = Vec::new();
    let header = evt_for(
        session,
        1,
        "session.started",
        None,
        serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
    );
    let user = evt_for(
        session,
        2,
        "user.message",
        Some("turn-modern"),
        json!({"item":{"role":"user","content":"x"},"turn_boundary_version":8}),
    );
    let response = evt_for(
        session,
        3,
        "response.completed",
        Some("turn-modern"),
        json!({"output_items":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}),
    );
    let marker = evt_for(
        session,
        4,
        "turn.completed",
        Some("turn-modern"),
        json!({"turn_boundary_version":8,"covers_from_seq":2,"final_response_seq":3,"covers_through_seq":4}),
    );
    for event in [&header, &user, &response] {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    bytes.extend(serde_json::to_vec(&marker).unwrap());
    fs::write(store.layout().journal_path(session).unwrap(), &bytes).unwrap();
    let error = store.open(session).err().map(|error| error.to_string());
    println!("modern no-claim error={error:?}");
    assert!(
        error.is_none(),
        "pre-profile modern v8 journal should remain readable: {error:?}"
    );
}

#[test]
fn unclaimed_modern_unstarted_tool_turn_is_fully_finalized_on_reopen() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session = "modern-unstarted-no-claim";
    let events = [
        evt_for(
            session,
            1,
            "session.started",
            None,
            serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
        ),
        evt_for(
            session,
            2,
            "user.message",
            Some("turn-modern-tool"),
            json!({"item":{"role":"user","content":"x"},"turn_boundary_version":8}),
        ),
        evt_for(
            session,
            3,
            "response.started",
            Some("turn-modern-tool"),
            json!({"response_attempt_id":"attempt-1"}),
        ),
        evt_for(
            session,
            4,
            "response.completed",
            Some("turn-modern-tool"),
            json!({
                "response_attempt_id":"attempt-1",
                "output_items":[{
                    "type":"function_call",
                    "call_id":"call-1",
                    "name":"shell",
                    "arguments":"{}"
                }]
            }),
        ),
    ];
    let mut bytes = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    fs::write(store.layout().journal_path(session).unwrap(), &bytes).unwrap();

    let reopened = store
        .open(session)
        .expect("modern no-claim lifecycle must recover");
    let recovered = reopened.read_events().unwrap();
    println!(
        "kinds={:?}",
        recovered
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        recovered.iter().any(|event| {
            event.kind == "tool.skipped_due_to_cancel"
                && event.turn_id.as_deref() == Some("turn-modern-tool")
        }),
        "unstarted call must be durably skipped"
    );
    assert!(
        recovered.iter().any(|event| {
            event.kind == "turn.cancelled" && event.turn_id.as_deref() == Some("turn-modern-tool")
        }),
        "modern recovered response batch must durably settle its owning turn"
    );
}

#[test]
fn legacy_v2_retry_fixture_with_missing_lf_reopens() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session = "legacy-v2-retry";
    let header = evt_for(
        session,
        1,
        "session.started",
        None,
        serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
    );
    let fixture = include_str!("fixtures/retry_recovery_v2.jsonl");
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &header).unwrap();
    bytes.push(b'\n');
    for line in fixture.lines() {
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        value["seq"] = json!(value["seq"].as_u64().unwrap() + 1);
        value["session_id"] = json!(session);
        for field in ["user_message_seq", "context_limit_seq"] {
            if let Some(seq) = value["data"].get(field).and_then(serde_json::Value::as_u64) {
                value["data"][field] = json!(seq + 1);
            }
        }
        if let Some(completion) = value["data"]
            .get_mut("turn_completion")
            .and_then(serde_json::Value::as_object_mut)
        {
            for field in [
                "covers_from_seq",
                "final_response_seq",
                "covers_through_seq",
            ] {
                if let Some(seq) = completion.get(field).and_then(serde_json::Value::as_u64) {
                    completion.insert(field.to_owned(), json!(seq + 1));
                }
            }
        }
        serde_json::to_writer(&mut bytes, &value).unwrap();
        bytes.push(b'\n');
    }
    let tail = bytes.strip_suffix(b"\n").unwrap().to_vec();
    fs::write(store.layout().journal_path(session).unwrap(), tail).unwrap();
    let error = store.open(session).err().map(|error| error.to_string());
    println!("legacy-v2 retry error={error:?}");
    assert!(
        error.is_none(),
        "historical v2 retry must reopen: {error:?}"
    );
}

#[test]
fn bounded_malformed_user_prefix_does_not_authorize_tail_truncation() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session = "bad-user-before-tail";
    let journal = store
        .create_with_id(session, SessionHeader::new(temp.path(), "m"))
        .unwrap();
    let path = journal.journal_path().to_owned();
    drop(journal);

    let bad_user = evt_for(session, 2, "user.message", Some("t"), json!({}));
    let mut bytes = fs::read(&path).unwrap();
    serde_json::to_writer(&mut bytes, &bad_user).unwrap();
    bytes.push(b'\n');
    bytes.extend_from_slice(
        br#"{"schema":1,"seq":3,"ts":"2026-08-22T00:00:00Z","kind":"response.started","session_id":"bad-user-before-tail","turn_id":"t","data":{"response_attempt_id":"attempt-1""#,
    );
    fs::write(&path, &bytes).unwrap();
    let before = fs::read(&path).unwrap();

    let error = store.open(session).err().map(|error| error.to_string());
    let after = fs::read(&path).unwrap();
    println!(
        "bad user + tail error={error:?}, changed={}",
        before != after
    );
    assert!(
        error.is_some(),
        "malformed bounded user.message must fail closed"
    );
    assert_eq!(
        after, before,
        "failed open must preserve exact crash evidence"
    );
}

#[test]
fn true_legacy_unstarted_tool_turn_is_fully_finalized_on_reopen() {
    let temp = TempDir::new().unwrap();
    let store = SessionStore::new(temp.path()).unwrap();
    let session = "legacy-unstarted-call";
    let events = [
        evt_for(
            session,
            1,
            "session.started",
            None,
            serde_json::to_value(SessionHeader::new(temp.path(), "m")).unwrap(),
        ),
        evt_for(
            session,
            2,
            "user.message",
            Some("turn-legacy-tool"),
            json!({"item":{"role":"user","content":"x"}}),
        ),
        evt_for(
            session,
            3,
            "response.completed",
            Some("turn-legacy-tool"),
            json!({
                "output_items":[{
                    "type":"function_call",
                    "call_id":"call-1",
                    "name":"shell",
                    "arguments":"{}"
                }]
            }),
        ),
    ];
    let mut bytes = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    fs::write(store.layout().journal_path(session).unwrap(), &bytes).unwrap();

    let reopened = store.open(session).expect("legacy call batch must recover");
    let recovered = reopened.read_events().unwrap();
    println!(
        "legacy call kinds={:?}",
        recovered
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>()
    );
    assert!(recovered.iter().any(|event| {
        event.kind == "tool.skipped_due_to_cancel"
            && event.turn_id.as_deref() == Some("turn-legacy-tool")
    }));
    assert!(
        recovered.iter().any(|event| {
            event.kind == "turn.cancelled" && event.turn_id.as_deref() == Some("turn-legacy-tool")
        }),
        "a recovered legacy call batch also needs a durable parent terminal"
    );
}
