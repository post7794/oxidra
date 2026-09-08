//! Public helper regressions run in child processes because stack exhaustion
//! aborts instead of unwinding. A helper must handle unmaterialized fixtures
//! without relying on SessionStore having checked their JSON depth first.

use oxidra::compaction::{CompactionSource, attempt_boundary, validate_checkpoint_chain};
use oxidra::history::serialized_history_tool_output_bytes;
use oxidra::mcp::tool_result_for_display;
use oxidra::session::JournalEvent;
use serde_json::{Value, json};

fn in_child(name: &str, check: impl FnOnce()) {
    const CHILD_CASE: &str = "OXIDRA_PUBLIC_JSON_HELPER_TEST";
    if std::env::var(CHILD_CASE).as_deref() == Ok(name) {
        check();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD_CASE, name)
        .output()
        .expect("run public JSON helper in isolated test process");
    assert!(
        output.status.success(),
        "{name} exited with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn nested_value(depth: usize) -> Value {
    let mut value = Value::Null;
    for _ in 0..depth {
        value = Value::Array(vec![value]);
    }
    value
}

fn event(data: Value) -> JournalEvent {
    JournalEvent {
        schema: 1,
        seq: 1,
        ts: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        kind: "custom.fixture".to_owned(),
        session_id: "fixture".to_owned(),
        turn_id: None,
        data,
    }
}

#[test]
fn history_accounting_handles_deep_public_value() {
    in_child("history_accounting_handles_deep_public_value", || {
        let owned = event(nested_value(20_000));
        assert!(serialized_history_tool_output_bytes("call", &owned.data).is_err());
    });
}

#[test]
fn attempt_boundary_handles_deep_public_value() {
    in_child("attempt_boundary_handles_deep_public_value", || {
        let mut owned = event(json!({"boundary": null}));
        owned.data["boundary"] = nested_value(20_000);
        assert!(attempt_boundary(owned.data.as_object().unwrap()).is_err());
    });
}

#[test]
fn mcp_display_handles_deep_public_value() {
    in_child("mcp_display_handles_deep_public_value", || {
        let owned = event(nested_value(20_000));
        let display = tool_result_for_display(&owned.data);
        assert!(!display.is_empty());
        assert!(display.len() <= 16 * 1024);
    });
}

#[test]
fn compaction_depth_ceiling_preserves_legacy_reader_values() {
    in_child(
        "compaction_depth_ceiling_preserves_legacy_reader_values",
        || {
            let mut accepted_depth = 0;
            for depth in 120..=128 {
                let original = event(nested_value(depth));
                let wire = serde_json::to_vec(&original).unwrap();
                if let Ok(parsed) = serde_json::from_slice::<JournalEvent>(&wire) {
                    accepted_depth = depth;
                    validate_checkpoint_chain(&[parsed]).unwrap();
                }
            }
            assert!(accepted_depth >= 120);
            let source = CompactionSource::new(vec![nested_value(128)]);
            source.digest().unwrap();
        },
    );
}

#[test]
fn turn_reducer_handles_deep_mcp_argument_fixture() {
    in_child("turn_reducer_handles_deep_mcp_argument_fixture", || {
        let epoch = "0190f5e6-7b00-7abc-8000-000000000002";
        let digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let mut events = vec![
            event(json!({
                "coordinator_version":1,
                "call_chain_validator_version":1,
                "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000001",
                "registry_epoch_id":epoch,
                "registry_version":1,
                "stdio_kernel_version":1,
                "schema_profile_version":1,
                "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "registry_digest":digest,
                "provider_names":["mcp_fixture_echo_deadbeef"]
            })),
            event(json!({"turn_boundary_version":6})),
            event(json!({
                "response_attempt_id":"attempt-1",
                "mcp_registry_epoch_id":epoch,
                "mcp_registry_digest":digest,
            })),
            event(json!({
                "response_attempt_id":"attempt-1",
                "output_items":[{
                    "type":"function_call",
                    "call_id":"call-1",
                    "name":"mcp_fixture_echo_deadbeef",
                    "arguments":{},
                }],
            })),
        ];
        for (index, (event, kind)) in events
            .iter_mut()
            .zip([
                "mcp.registry.activated",
                "user.message",
                "response.started",
                "response.completed",
            ])
            .enumerate()
        {
            event.seq = index as u64 + 1;
            event.kind = kind.to_owned();
            event.turn_id = (index > 0).then(|| "turn-1".to_owned());
        }
        oxidra::turn::segment_turns(&events).expect("shallow legacy MCP fixture is valid");
        events[3].data["output_items"][0]["arguments"] = nested_value(20_000);
        assert!(oxidra::turn::segment_turns(&events).is_err());
    });
}
