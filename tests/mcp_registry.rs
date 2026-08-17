#![cfg(any(windows, target_os = "linux"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use oxidra::Result;
use oxidra::context::ToolSurfaceSnapshotV1;
use oxidra::mcp::{
    MCP_EXECUTION_PLAN_VERSION, MCP_TOOL_REGISTRY_VERSION, McpCallApprovalHandler,
    McpCallApprovalRequest, McpCallIdentity, McpExecutionCoordinator, McpProjectConfig,
    McpProviderResponseAdmissionErrorV1, McpProviderResponseCommitErrorV1, McpRegistry,
};
use oxidra::session::{SessionHeader, SessionStore, TurnTransactionAdmissionV1};
use oxidra::turn::TURN_BOUNDARY_VERSION;
use oxidra::types::ToolDefinition;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn explicit_project_config_builds_a_stable_namespaced_registry() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP registry integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP registry fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP registry project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP registry fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP project config");
    let config_path = config_path
        .canonicalize()
        .expect("canonicalize MCP project config");
    let config = McpProjectConfig::load(&root, &config_path).expect("load MCP project config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve MCP execution plan fixture");
    let data_dir = directory.path().join("data");
    let store = SessionStore::new(&data_dir).expect("create MCP coordinator session store");
    let mut journal = store
        .create(SessionHeader::new(&root, "mcp-test"))
        .expect("create MCP coordinator journal");

    let cancellation = CancellationToken::new();
    let mut probe_registry = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut journal,
        &cancellation,
    )
    .await
    .expect("connect lease-bound MCP registry");
    let log_before_duplicate_start = fs::read(&log).expect("read log before duplicate startup");
    let duplicate_start = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut journal,
        &cancellation,
    )
    .await
    .err()
    .expect("one journal generation must not start a second MCP registry");
    assert!(duplicate_start.to_string().contains("already claimed"));
    assert_eq!(
        fs::read(&log).expect("read log after duplicate startup"),
        log_before_duplicate_start,
        "duplicate activation startup must fail before executing MCP code"
    );
    let probe_session_id = journal.session_id().to_owned();
    drop(journal);
    let lock_error = store
        .open(&probe_session_id)
        .err()
        .expect("pre-coordinator activation registry must retain the session lock lease");
    assert!(lock_error.to_string().contains("already open"));
    probe_registry.shutdown().await;
    drop(probe_registry);
    let mut journal = store
        .open(&probe_session_id)
        .expect("open after releasing pre-coordinator activation lease");

    let registry = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut journal,
        &cancellation,
    )
    .await
    .expect("connect MCP registry");
    assert_eq!(MCP_EXECUTION_PLAN_VERSION, 1);
    assert_eq!(MCP_TOOL_REGISTRY_VERSION, 1);
    assert_eq!(registry.config_sha256(), config.source_sha256());
    assert_eq!(
        registry.execution_plan_digest(),
        config.execution_plan_digest()
    );
    assert_eq!(registry.execution_plan_digest().len(), 64);
    assert_eq!(registry.digest().len(), 64);
    let binding = registry.bindings().next().expect("registry binding");
    assert_eq!(binding.server_name, "fixture");
    assert_eq!(binding.raw_tool_name, "echo.v1");
    assert!(binding.provider_name.starts_with("mcp_fixture_echo_v1_"));
    assert_eq!(binding.definition.name, binding.provider_name);
    assert!(binding.output_schema.is_some());
    let provider_name = binding.provider_name.clone();
    let protocol_version = binding.protocol_version.clone();

    let expected_registry_digest = registry.digest().to_owned();
    let approved_registry = registry
        .approve_surface(&expected_registry_digest)
        .expect("approve MCP registry surface");
    let mut coordinator = McpExecutionCoordinator::activate(approved_registry, &mut journal)
        .expect("activate MCP execution coordinator");
    assert_eq!(coordinator.registry_digest(), expected_registry_digest);
    let activation_events = journal.read_events().expect("read MCP activation");
    let activation = activation_events
        .iter()
        .find(|event| event.kind == "mcp.registry.activated")
        .expect("durable MCP registry activation");
    assert!(activation.turn_id.is_none());
    assert_eq!(activation.data["coordinator_version"], 2);
    assert_eq!(activation.data["call_chain_validator_version"], 2);
    assert_eq!(
        activation.data["registry_version"],
        MCP_TOOL_REGISTRY_VERSION
    );
    assert_eq!(activation.data["registry_digest"], expected_registry_digest);
    assert_eq!(
        activation.data["execution_plan_digest"],
        approved.execution_plan_digest()
    );

    // The public typed writer is synchronous, but callers can still hand it a
    // deeply nested in-memory Value.  Preflight must take ownership before any
    // recursive serializer or error-path drop can run.
    let mut deep = Value::Null;
    for _ in 0..50_000 {
        deep = Value::Array(vec![deep]);
    }
    let mut deep_turn = begin_test_turn(&mut journal, "deep-provider-event-turn", "deep event");
    let before_deep_event = journal
        .read_events()
        .expect("read journal before deep Provider event");
    let deep_error = coordinator
        .admit_provider_response_v1(
            &mut journal,
            &deep_turn,
            "deep-provider-event-turn",
            Value::Object(Map::from_iter([
                (
                    "response_attempt_id".to_owned(),
                    Value::String("deep-attempt".to_owned()),
                ),
                ("context".to_owned(), deep),
            ])),
        )
        .err()
        .expect("deep Provider event must fail closed before journaling");
    assert!(matches!(
        deep_error,
        McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
    ));
    assert_eq!(
        journal
            .read_events()
            .expect("read journal after deep Provider event"),
        before_deep_event,
        "deep Provider event rejection must be zero-write"
    );
    journal
        .finish_turn_transaction_v1(&mut deep_turn, Some("deep event rejected"))
        .expect("finish deep event probe turn");

    let mut wide_turn = begin_test_turn(
        &mut journal,
        "wide-provider-event-turn",
        "oversized shallow event",
    );
    let before_wide_event = journal
        .read_events()
        .expect("read journal before oversized Provider event");
    let wide_error = coordinator
        .admit_provider_response_v1(
            &mut journal,
            &wide_turn,
            "wide-provider-event-turn",
            json!({
                "response_attempt_id":"wide-attempt",
                "context":{"blob":"x".repeat(300 * 1024)},
            }),
        )
        .err()
        .expect("oversized shallow Provider event must fail before cloning or journaling");
    assert!(matches!(
        wide_error,
        McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
    ));
    assert_eq!(
        journal
            .read_events()
            .expect("read journal after oversized Provider event"),
        before_wide_event,
        "oversized Provider event rejection must be zero-write"
    );
    journal
        .finish_turn_transaction_v1(&mut wide_turn, Some("wide event rejected"))
        .expect("finish wide event probe turn");

    let mut deep_completed_turn = begin_test_turn(
        &mut journal,
        "deep-completed-event-turn",
        "deep completed event",
    );
    let mut deep_completed_admission = coordinator
        .admit_provider_response_v1(
            &mut journal,
            &deep_completed_turn,
            "deep-completed-event-turn",
            json!({
                "response_attempt_id":"deep-completed-attempt",
                "context":{},
            }),
        )
        .expect("admit deep completed Provider response");
    let before_deep_completed = journal
        .read_events()
        .expect("read journal before deep completion candidate");
    let mut deep_completed = Value::Null;
    for _ in 0..50_000 {
        deep_completed = Value::Array(vec![deep_completed]);
    }
    let deep_completed_error = deep_completed_admission
        .commit_completed_v1(
            &mut journal,
            Value::Object(Map::from_iter([(
                "raw_response".to_owned(),
                deep_completed,
            )])),
        )
        .expect_err("deep completion must be rejected before any terminal write");
    assert!(matches!(
        deep_completed_error,
        McpProviderResponseCommitErrorV1::FallbackPermittedBeforeWrite(_)
    ));
    assert_eq!(
        journal
            .read_events()
            .expect("read journal after deep completion candidate"),
        before_deep_completed,
        "fallback-safe completion rejection must be zero-write"
    );
    deep_completed_admission
        .commit_failed_v1(&mut journal, "deep completion rejected by bounded profile")
        .expect("the same one-shot guard must retain its bounded failure fallback");
    journal
        .finish_turn_transaction_v1(
            &mut deep_completed_turn,
            Some("deep completed event rejected"),
        )
        .expect("finish deep completed event probe turn");
    assert_eq!(
        activation.data["bindings"],
        json!([{
            "provider_name":provider_name.clone(),
            "server_name":"fixture",
            "raw_tool_name":"echo.v1",
            "protocol_version":protocol_version,
        }])
    );
    assert!(activation.data.get("provider_names").is_none());

    // A serde-deserialized snapshot can be internally self-consistent while
    // pointing an MCP alias at a different server/raw binding.  The
    // coordinator must reject it before any context.tools bytes are written;
    // matching only the public epoch/digest claim is insufficient.
    let valid_surface = coordinator
        .surface_claim_v1()
        .expect("derive live MCP surface claim")
        .merge_with(Vec::new())
        .expect("build canonical MCP surface snapshot");
    let valid_value =
        serde_json::to_value(&valid_surface).expect("serialize canonical MCP surface snapshot");
    let mut forged_value = valid_value.clone();
    forged_value["mcp"]["bindings"][0]["server_name"] = Value::String("forged".to_owned());
    let forged_tools: Vec<ToolDefinition> = serde_json::from_value(forged_value["tools"].clone())
        .expect("decode forged tool definitions");
    let forged_claim: oxidra::context::McpSurfaceClaimV1 =
        serde_json::from_value(forged_value["mcp"].clone()).expect("decode forged MCP claim");
    #[derive(serde::Serialize)]
    struct SurfaceDigestPayload<'a> {
        version: u32,
        tools: &'a [ToolDefinition],
        mcp: Option<&'a oxidra::context::McpSurfaceClaimV1>,
    }
    let digest_payload = SurfaceDigestPayload {
        version: forged_value["version"].as_u64().unwrap() as u32,
        tools: &forged_tools,
        mcp: Some(&forged_claim),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"oxidra.context-tool-surface.v1\0");
    hasher.update(serde_json::to_vec(&digest_payload).expect("serialize forged digest payload"));
    forged_value["digest"] = Value::String(hex::encode(hasher.finalize()));
    let forged_surface: ToolSurfaceSnapshotV1 = serde_json::from_value(forged_value)
        .expect("forged snapshot remains self-consistent under its public schema");
    forged_surface
        .validate()
        .expect("forged snapshot should pass self-contained validation");
    let before_forged_append = journal
        .read_events()
        .expect("read journal before forged context.tools append");
    let forged_error = coordinator
        .append_context_tools_v1(&mut journal, &forged_surface)
        .expect_err("forged live binding must be rejected");
    assert!(forged_error.to_string().contains("bindings"));
    assert_eq!(
        journal
            .read_events()
            .expect("read journal after forged context.tools append"),
        before_forged_append,
        "forged surface rejection must be zero-write"
    );

    let mut other_journal = store
        .create(SessionHeader::new(&root, "mcp-other"))
        .expect("create a different MCP coordinator journal");
    let other_error = coordinator
        .execute_call(
            &mut other_journal,
            McpCallIdentity::new("other-turn", "other-call", &provider_name),
            &CancellationToken::new(),
            &mut PanicMcpApproval,
        )
        .await
        .expect_err("a coordinator cannot write into another session");
    assert!(other_error.to_string().contains("different session"));

    let turn_id = "mcp-turn";
    let call_id = "mcp-call";
    let arguments = json!({"text":"registry"});
    let mut turn_admission = begin_test_turn(&mut journal, turn_id, "use MCP");
    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "mcp-response",
        call_id,
        &provider_name,
        &arguments,
    );

    let call_cancellation = CancellationToken::new();
    let mut call_approval = AllowMcpApproval;
    let result = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, call_id, &provider_name),
            &call_cancellation,
            &mut call_approval,
        )
        .await
        .expect("call namespaced MCP tool");
    // The current coordinator/call-chain v2 keeps the complete bounded raw
    // MCP result.  The text-only model envelope belongs to the future v3
    // writer epoch and must not silently replace v2's raw compatibility API.
    assert_eq!(result.output["content"][0]["text"], "registry");
    let events = journal.read_events().expect("read MCP coordinator events");
    let started = events
        .iter()
        .find(|event| event.kind == "tool.started")
        .expect("durable MCP tool.started");
    assert_eq!(started.data["call_id"], call_id);
    assert_eq!(started.data["tool"], provider_name);
    assert_eq!(
        started.data["mcp"]["registry_digest"],
        expected_registry_digest
    );
    assert_eq!(
        started.data["mcp"]["registry_epoch_id"],
        coordinator.registry_epoch_id()
    );
    let completed = events
        .iter()
        .find(|event| event.kind == "tool.completed")
        .expect("durable MCP tool.completed");
    assert_eq!(completed.data["started_seq"], started.seq);
    assert_eq!(completed.data["mcp"], started.data["mcp"]);

    let replay_error = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, call_id, &provider_name),
            &CancellationToken::new(),
            &mut PanicMcpApproval,
        )
        .await
        .expect_err("a terminal call cannot acquire a second dispatch permit");
    assert!(replay_error.to_string().contains("tool.started"));

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "identity-response",
        "identity-call",
        &provider_name,
        &json!({"text":"identity"}),
    );
    let identity_error = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "identity-call", "mcp_missing_fixture_tool"),
            &CancellationToken::new(),
            &mut PanicMcpApproval,
        )
        .await
        .expect_err("an unknown provider name cannot settle a real durable call");
    assert!(identity_error.to_string().contains("durable Provider call"));
    let identity_terminal = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "identity-call", &provider_name),
            &CancellationToken::new(),
            &mut oxidra::mcp::DenyMcpCallApproval,
        )
        .await
        .expect("the original durable call remains recoverable");
    assert_eq!(
        identity_terminal.error_code.as_deref(),
        Some("approval_required")
    );

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "invalid-arguments-response",
        "invalid-arguments-call",
        &provider_name,
        &json!({"text":0.5}),
    );
    let invalid_arguments = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "invalid-arguments-call", &provider_name),
            &CancellationToken::new(),
            &mut PanicMcpApproval,
        )
        .await
        .expect("unsupported durable arguments receive a known pre-start terminal");
    assert_eq!(
        invalid_arguments.error_code.as_deref(),
        Some("validation_error")
    );

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "denied-response",
        "denied-call",
        &provider_name,
        &json!({"text":"denied"}),
    );
    let denied = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "denied-call", &provider_name),
            &CancellationToken::new(),
            &mut oxidra::mcp::DenyMcpCallApproval,
        )
        .await
        .expect("approval denial is a known pre-dispatch terminal");
    assert_eq!(denied.error_code.as_deref(), Some("approval_required"));

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "cancelled-response",
        "cancelled-call",
        &provider_name,
        &json!({"text":"cancelled"}),
    );
    let cancelled_token = CancellationToken::new();
    cancelled_token.cancel();
    let cancelled = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "cancelled-call", &provider_name),
            &cancelled_token,
            &mut PanicMcpApproval,
        )
        .await
        .expect("pre-cancelled MCP call is a known pre-start terminal");
    assert_eq!(cancelled.error_code.as_deref(), Some("cancelled"));

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "output-limit-response",
        "output-limit-call",
        &provider_name,
        &json!({"text":"__oversized_result__"}),
    );
    let output_limit = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "output-limit-call", &provider_name),
            &CancellationToken::new(),
            &mut AllowMcpApproval,
        )
        .await
        .expect("an oversized post-dispatch result is durably in doubt");
    assert_eq!(output_limit.error_code.as_deref(), Some("in_doubt"));
    let output_limit_pending = journal
        .in_doubt()
        .expect("read oversized-result in-doubt snapshot");
    assert_eq!(output_limit_pending.len(), 1);
    journal
        .finish_turn_transaction_v1(&mut turn_admission, Some("fixture turn complete"))
        .expect("finish the first admitted MCP turn");
    journal
        .resolve_all_in_doubt_as_failed(&output_limit_pending)
        .expect("explicitly resolve the oversized-result uncertainty");

    let closed_turn_id = "mcp-closed-after-output-limit-turn";
    let mut turn_admission = begin_test_turn(
        &mut journal,
        closed_turn_id,
        "verify oversized result closed transport",
    );
    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        closed_turn_id,
        "closed-after-output-limit-response",
        "closed-after-output-limit-call",
        &provider_name,
        &json!({"text":"must-not-dispatch"}),
    );
    let closed_after_output_limit = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(
                closed_turn_id,
                "closed-after-output-limit-call",
                &provider_name,
            ),
            &CancellationToken::new(),
            &mut AllowMcpApproval,
        )
        .await
        .expect("the terminated transport is a known no-dispatch failure");
    assert_eq!(
        closed_after_output_limit.error_code.as_deref(),
        Some("transport_closed")
    );
    journal
        .finish_turn_transaction_v1(&mut turn_admission, Some("transport closed"))
        .expect("finish the transport-closed probe turn");

    // Post-dispatch result rejection closes the old stdio stream.  Explicitly
    // reopen the durable session and reconnect the approved registry before
    // exercising the independent JSON-RPC in-doubt path below.
    let session_id = journal.session_id().to_owned();
    coordinator.shutdown().await;
    drop(coordinator);
    drop(journal);
    let mut journal = store
        .open(&session_id)
        .expect("reopen after oversized-result transport termination");
    let eligibility = journal
        .mcp_resume_eligibility()
        .expect("resolved oversized result permits a fresh MCP startup");
    let resumed_registry = McpRegistry::connect_for_resume(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        eligibility,
        &CancellationToken::new(),
    )
    .await
    .expect("reconnect registry after oversized-result transport termination");
    let approved_resumed_registry = resumed_registry
        .approve_surface(&expected_registry_digest)
        .expect("approve unchanged registry after transport termination");
    let mut coordinator = McpExecutionCoordinator::resume(approved_resumed_registry, &journal)
        .expect("resume coordinator after transport termination");
    // Standalone coordinator dispatch admits one-call responses only; a
    // multi-call batch must be owned by an active Agent turn admission.  The
    // in-doubt outcome itself is enough to block a later call, so keep this
    // low-level fixture single-call and exercise the same fail-closed gate.
    let rpc_turn_id = "mcp-rpc-turn";
    let turn_admission = begin_test_turn(&mut journal, rpc_turn_id, "exercise RPC failure");
    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        rpc_turn_id,
        "in-doubt-response",
        "in-doubt-call",
        &provider_name,
        &json!({"text":"__rpc_error__"}),
    );
    let in_doubt = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(rpc_turn_id, "in-doubt-call", &provider_name),
            &CancellationToken::new(),
            &mut AllowMcpApproval,
        )
        .await
        .expect("post-dispatch RPC error is durably in doubt");
    assert_eq!(in_doubt.error_code.as_deref(), Some("in_doubt"));
    let blocked = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(rpc_turn_id, "blocked-call", &provider_name),
            &CancellationToken::new(),
            &mut PanicMcpApproval,
        )
        .await
        .expect_err("an unresolved in-doubt call blocks every later dispatch");
    assert!(blocked.to_string().contains("explicitly resolved"));

    let events = journal.read_events().expect("read MCP terminal variants");
    assert!(events.iter().any(|event| {
        event.kind == "tool.completed"
            && event.data["call_id"] == "denied-call"
            && event.data["error_code"] == "approval_required"
            && event.data.get("started_seq").is_none()
    }));
    assert!(events.iter().any(|event| {
        event.kind == "tool.cancelled"
            && event.data["call_id"] == "cancelled-call"
            && event.data["before_start"] == true
    }));
    assert!(events.iter().any(|event| {
        event.kind == "tool.in_doubt"
            && event.data["call_id"] == "in-doubt-call"
            && event.data["started_seq"].is_u64()
    }));
    assert!(events.iter().any(|event| {
        event.kind == "tool.in_doubt"
            && event.data["call_id"] == "output-limit-call"
            && event.data["error_code"] == "in_doubt"
            && event.data["started_seq"].is_u64()
            && event.data["mcp"]["server_attempt_id"].is_string()
    }));
    let log_text = fs::read_to_string(&log).expect("read MCP registry log");
    assert_eq!(
        log_text
            .lines()
            .filter(|line| *line == "tools/call")
            .count(),
        3,
        "only approved single-use permits may reach the MCP transport"
    );
    let durable_session_id = journal.session_id().to_owned();
    coordinator.shutdown().await;
    drop(coordinator);
    drop(journal);

    let mut reopened = store
        .open(&durable_session_id)
        .expect("reopen and recover MCP coordinator journal");
    let log_before_blocked_resume = fs::read(&log).expect("read log before blocked resume");
    let replacement_start = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut reopened,
        &CancellationToken::new(),
    )
    .await
    .err()
    .expect("an existing activation must reject replacement before MCP startup");
    assert!(
        replacement_start
            .to_string()
            .contains("existing registry activation")
    );
    assert_eq!(
        fs::read(&log).expect("read log after blocked replacement activation"),
        log_before_blocked_resume,
        "existing activation rejection must not execute MCP discovery code"
    );
    let resume_error = reopened
        .mcp_resume_eligibility()
        .err()
        .expect("unresolved in-doubt tools must block resume eligibility");
    assert!(resume_error.to_string().contains("explicitly resolved"));
    assert_eq!(
        fs::read(&log).expect("read log after blocked resume"),
        log_before_blocked_resume,
        "the journal gate must reject unresolved in-doubt tools before MCP startup"
    );
    drop(reopened);

    let mut collision_journal = store
        .create(SessionHeader::new(&root, "mcp-collision"))
        .expect("create collision probe journal");
    let collision = McpRegistry::connect_for_activation(
        &approved,
        [provider_name],
        &mut collision_journal,
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(collision, Err(error) if error.to_string().contains("tool name collision")));
}

#[tokio::test]
async fn resume_rechecks_in_doubt_after_registry_start() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP resume integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP resume fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP resume project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP resume fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP resume config");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize MCP resume config"),
    )
    .expect("load MCP resume config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve MCP resume execution plan");
    let store =
        SessionStore::new(directory.path().join("data")).expect("create MCP resume session store");
    let mut journal = store
        .create(SessionHeader::new(&root, "mcp-resume"))
        .expect("create MCP resume journal");
    let registry = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut journal,
        &CancellationToken::new(),
    )
    .await
    .expect("connect MCP resume registry");
    let registry_digest = registry.digest().to_owned();
    let mut coordinator = McpExecutionCoordinator::activate(
        registry
            .approve_surface(&registry_digest)
            .expect("approve MCP resume surface"),
        &mut journal,
    )
    .expect("activate MCP resume coordinator");
    let durable_epoch = coordinator.registry_epoch_id().to_owned();
    let session_id = journal.session_id().to_owned();
    coordinator.shutdown().await;
    drop(coordinator);
    drop(journal);

    let original_sha = config.source_sha256().to_owned();
    let mut reopened = store
        .open(&session_id)
        .expect("open MCP journal before mismatched resume");
    let eligibility = reopened
        .mcp_resume_eligibility()
        .expect("mint eligibility for mismatched resume");
    fs::write(&config_path, project_config(&python, &script, &log, true))
        .expect("rewrite MCP resume config");
    let changed = McpProjectConfig::load(&root, &config_path).expect("load changed resume config");
    assert_ne!(changed.source_sha256(), original_sha);
    let approved_changed = changed
        .approve_execution(changed.execution_plan_digest())
        .expect("approve changed resume plan");
    let log_before_mismatch = fs::read(&log).expect("read log before mismatched resume");
    let mismatch = McpRegistry::connect_for_resume(
        &approved_changed,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        eligibility,
        &CancellationToken::new(),
    )
    .await;
    let mismatch = match mismatch {
        Ok(mut registry) => {
            registry.shutdown().await;
            panic!("changed config must fail before resume server startup");
        }
        Err(error) => error,
    };
    assert!(mismatch.to_string().contains("durable registry activation"));
    assert_eq!(
        fs::read(&log).expect("read log after mismatched resume"),
        log_before_mismatch,
        "resume config mismatch must be rejected before MCP code executes"
    );
    drop(reopened);
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("restore MCP resume config");

    let mut reopened = store
        .open(&session_id)
        .expect("open clean MCP resume journal");
    let eligibility = reopened
        .mcp_resume_eligibility()
        .expect("mint clean MCP resume eligibility");
    let mut resumed_registry = McpRegistry::connect_for_resume(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        eligibility,
        &CancellationToken::new(),
    )
    .await
    .expect("connect lease-bound MCP resume registry");
    drop(reopened);
    let lock_error = store
        .open(&session_id)
        .err()
        .expect("pre-coordinator resume registry must retain the session lock lease");
    assert!(lock_error.to_string().contains("already open"));
    resumed_registry.shutdown().await;
    let mut reopened = store
        .open(&session_id)
        .expect("resume-registry shutdown releases the pre-coordinator execution lease");
    drop(resumed_registry);

    let eligibility = reopened
        .mcp_resume_eligibility()
        .expect("mint eligibility after releasing the resume-registry probe");
    let resumed_registry = McpRegistry::connect_for_resume(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        eligibility,
        &CancellationToken::new(),
    )
    .await
    .expect("connect clean MCP resume registry");
    let approved_resumed_registry = resumed_registry
        .approve_surface(&registry_digest)
        .expect("approve clean MCP resume surface");
    let resumed = McpExecutionCoordinator::resume(approved_resumed_registry, &reopened)
        .expect("resume clean MCP registry epoch");
    assert_eq!(resumed.registry_epoch_id(), durable_epoch);
    assert_eq!(resumed.registry_digest(), registry_digest);
    drop(reopened);
    let locked_error = store
        .open(&session_id)
        .err()
        .expect("resumed coordinator must retain the exact session lock lease");
    assert!(locked_error.to_string().contains("already open"));
    drop(resumed);

    let mut reopened = open_after_execution_exit(&store, &session_id).await;
    let eligibility = reopened
        .mcp_resume_eligibility()
        .expect("mint MCP eligibility before final validation drift");
    let resumed_registry = McpRegistry::connect_for_resume(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        eligibility,
        &CancellationToken::new(),
    )
    .await
    .expect("start registry for final resume validation");

    let started = reopened
        .append_and_sync(
            "tool.started",
            None,
            json!({
                "call_id":"late-in-doubt-call",
                "tool":"builtin-fixture",
                "arguments":{},
            }),
        )
        .expect("append late generic tool start");
    reopened
        .append_and_sync(
            "tool.in_doubt",
            None,
            json!({
                "started_seq":started.seq,
                "call_id":"late-in-doubt-call",
                "tool":"builtin-fixture",
                "output":{"error":{"code":"in_doubt","message":"fixture"}},
                "is_error":true,
                "error_code":"in_doubt",
            }),
        )
        .expect("append late generic in-doubt terminal");
    let approved_resumed_registry = resumed_registry
        .approve_surface(&registry_digest)
        .expect("approve unchanged MCP resume surface");
    let resume_error = McpExecutionCoordinator::resume(approved_resumed_registry, &reopened)
        .err()
        .expect("final resume validation must reject newly in-doubt state");
    assert!(resume_error.to_string().contains("explicitly resolved"));
}

#[tokio::test]
async fn started_call_forget_keeps_poison_and_old_authority_out_of_reopened_handle() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP drop-guard integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP drop-guard fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP drop-guard project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP drop-guard fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP drop-guard config");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize MCP drop-guard config"),
    )
    .expect("load MCP drop-guard config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve MCP drop-guard execution plan");
    let store = SessionStore::new(directory.path().join("data"))
        .expect("create MCP drop-guard session store");
    let mut journal = store
        .create(SessionHeader::new(&root, "mcp-drop-guard"))
        .expect("create MCP drop-guard journal");
    let registry = McpRegistry::connect_for_activation(
        &approved,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &mut journal,
        &CancellationToken::new(),
    )
    .await
    .expect("connect MCP drop-guard registry");
    let provider_name = registry
        .bindings()
        .next()
        .expect("MCP drop-guard binding")
        .provider_name
        .clone();
    let registry_digest = registry.digest().to_owned();
    let mut coordinator = McpExecutionCoordinator::activate(
        registry
            .approve_surface(&registry_digest)
            .expect("approve MCP drop-guard surface"),
        &mut journal,
    )
    .expect("activate MCP drop-guard coordinator");
    let turn_id = "drop-guard-turn";
    let turn_admission = begin_test_turn(&mut journal, turn_id, "exercise MCP drop guard");
    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "unpolled-response",
        "unpolled-call",
        &provider_name,
        &json!({"text":"unpolled"}),
    );

    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpApproval;
    let unpolled = coordinator.execute_call(
        &mut journal,
        McpCallIdentity::new(turn_id, "unpolled-call", &provider_name),
        &cancellation,
        &mut approval,
    );
    drop(unpolled);
    assert!(
        journal
            .read_events()
            .expect("unpolled execute_call must leave the journal healthy")
            .iter()
            .all(|event| event.kind != "tool.started")
    );

    coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "unpolled-call", &provider_name),
            &CancellationToken::new(),
            &mut AllowMcpApproval,
        )
        .await
        .expect("normally terminalized MCP call");
    journal
        .read_events()
        .expect("normal MCP terminal must not poison the journal");

    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "dropped-response",
        "dropped-call",
        &provider_name,
        &json!({"text":"__hang__"}),
    );
    let calls_before = tool_call_count(&log);
    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpApproval;
    let mut started_future = Box::pin(coordinator.execute_call(
        &mut journal,
        McpCallIdentity::new(turn_id, "dropped-call", &provider_name),
        &cancellation,
        &mut approval,
    ));
    tokio::select! {
        result = &mut started_future => {
            result.expect_err("hanging MCP call unexpectedly returned successfully");
            panic!("hanging MCP call completed before it could be dropped");
        }
        () = wait_for_tool_call_count(&log, calls_before + 1) => {}
    }
    // `mem::forget` intentionally bypasses Drop.  The journal handle remains
    // readable until it is closed, but the pre-armed coordinator poison must
    // still survive the leak and prevent this live transport from being
    // reused after recovery.
    std::mem::forget(started_future);
    let prefix = journal
        .read_events()
        .expect("forgetting the future must not invent a terminal event");
    assert!(prefix.iter().any(|event| event.kind == "tool.started"));

    let session_id = journal.session_id().to_owned();
    drop(journal);
    let locked_error = store
        .open(&session_id)
        .err()
        .expect("live MCP coordinator must retain the session writer lock");
    assert!(locked_error.to_string().contains("already open"));

    // Explicit shutdown first aborts the transport and revokes live journal
    // authority, then releases the execution lease so crash recovery can own
    // the next open generation. The coordinator object itself may remain in
    // scope without retaining the lock after shutdown completes.
    coordinator.shutdown().await;
    let mut reopened = store
        .open(&session_id)
        .expect("reopen after coordinator shutdown and recover dropped MCP call");
    let pending = reopened.in_doubt().expect("read recovered in-doubt set");
    assert_eq!(pending.len(), 1);
    let resume_error = reopened
        .mcp_resume_eligibility()
        .err()
        .expect("recovered in-doubt call must block MCP startup");
    assert!(resume_error.to_string().contains("explicitly resolved"));

    reopened
        .resolve_all_in_doubt_as_failed(&pending)
        .expect("resolve the recovered in-doubt call");
    let retry_turn = "drop-guard-retry-turn";
    let retry_admission = begin_test_turn(
        &mut reopened,
        retry_turn,
        "retry after dropped MCP transport",
    );
    let before_events = reopened
        .read_events()
        .expect("read reopened journal before stale writer probe");
    let stale_writer_error = coordinator
        .admit_provider_response_v1(
            &mut reopened,
            &retry_admission,
            retry_turn,
            json!({
                "response_attempt_id":"retry-response",
                "context":{},
            }),
        )
        .err()
        .expect("revoked coordinator must not cross a shutdown/reopen boundary");
    assert!(matches!(
        &stale_writer_error,
        McpProviderResponseAdmissionErrorV1::RejectedBeforeStart(_)
    ));
    assert!(stale_writer_error.to_string().contains("revoked"));
    assert_eq!(
        reopened
            .read_events()
            .expect("stale writer remains zero-write"),
        before_events
    );
}

#[test]
fn dropping_coordinator_reaps_transport_without_runtime_progress() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP independent reaper test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP independent reaper fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP independent reaper project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP independent reaper fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP independent reaper config");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize MCP independent reaper config"),
    )
    .expect("load MCP independent reaper config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve MCP independent reaper execution plan");
    let store = SessionStore::new(directory.path().join("data"))
        .expect("create MCP independent reaper session store");
    let mut journal = store
        .create(SessionHeader::new(&root, "mcp-independent-reaper"))
        .expect("create MCP independent reaper journal");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build MCP independent reaper runtime");
    let registry = runtime
        .block_on(McpRegistry::connect_for_activation(
            &approved,
            ["read", "edit", "write", "shell", "remember"]
                .into_iter()
                .map(str::to_owned),
            &mut journal,
            &CancellationToken::new(),
        ))
        .expect("connect MCP independent reaper registry");
    let registry_digest = registry.digest().to_owned();
    let coordinator = McpExecutionCoordinator::activate(
        registry
            .approve_surface(&registry_digest)
            .expect("approve MCP independent reaper surface"),
        &mut journal,
    )
    .expect("activate MCP independent reaper coordinator");
    let session_id = journal.session_id().to_owned();

    drop(journal);
    let locked_error = store
        .open(&session_id)
        .err()
        .expect("live coordinator must retain the session lock");
    assert!(locked_error.to_string().contains("already open"));

    // Destroy the current-thread runtime first. The runtime sentinel may only
    // request termination; the independent std reaper must retain the final
    // lease until Child::try_wait has reaped the leader and the native
    // containment is empty. No Tokio runtime is polled below.
    drop(runtime);
    drop(coordinator);
    let reopened = open_after_execution_exit_blocking(&store, &session_id);
    drop(reopened);
}

#[test]
fn dropping_started_call_aborts_transport_while_current_thread_runtime_is_idle() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP started-call drop test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP started-call drop fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP started-call drop project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    let survived = root.join("server-survived-drop.txt");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP started-call drop fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP started-call drop config");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize MCP started-call drop config"),
    )
    .expect("load MCP started-call drop config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve MCP started-call drop execution plan");
    let store = SessionStore::new(directory.path().join("data"))
        .expect("create MCP started-call drop session store");
    let mut journal = store
        .create(SessionHeader::new(&root, "mcp-started-call-drop"))
        .expect("create MCP started-call drop journal");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build MCP started-call drop runtime");
    let registry = runtime
        .block_on(McpRegistry::connect_for_activation(
            &approved,
            ["read", "edit", "write", "shell", "remember"]
                .into_iter()
                .map(str::to_owned),
            &mut journal,
            &CancellationToken::new(),
        ))
        .expect("connect MCP started-call drop registry");
    let provider_name = registry
        .bindings()
        .next()
        .expect("MCP started-call drop binding")
        .provider_name
        .clone();
    let registry_digest = registry.digest().to_owned();
    let mut coordinator = McpExecutionCoordinator::activate(
        registry
            .approve_surface(&registry_digest)
            .expect("approve MCP started-call drop surface"),
        &mut journal,
    )
    .expect("activate MCP started-call drop coordinator");
    let turn_id = "started-call-drop-turn";
    let turn_admission = begin_test_turn(&mut journal, turn_id, "drop an in-flight MCP call");
    append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "started-call-drop-response",
        "started-call-drop-call",
        &provider_name,
        &json!({"text":format!("__drop_probe__:{}", survived.display())}),
    );

    let calls_before = tool_call_count(&log);
    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpApproval;
    let mut started_future = Box::pin(coordinator.execute_call(
        &mut journal,
        McpCallIdentity::new(turn_id, "started-call-drop-call", &provider_name),
        &cancellation,
        &mut approval,
    ));
    runtime.block_on(async {
        tokio::select! {
            result = &mut started_future => {
                result.expect_err("drop-probe MCP call unexpectedly returned successfully");
                panic!("drop-probe MCP call completed before it could be dropped");
            }
            () = wait_for_tool_call_count(&log, calls_before + 1) => {}
        }
    });

    // Do not drive the runtime after dropping the future. The started-call
    // guard must synchronously terminate the exact native containment rather
    // than relying on the transport owner task to observe cancellation.
    drop(started_future);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(
        !survived.exists(),
        "MCP server continued executing after the started-call future was dropped"
    );

    runtime.block_on(coordinator.shutdown());
}

struct AllowMcpApproval;

#[async_trait]
impl McpCallApprovalHandler for AllowMcpApproval {
    async fn approve_mcp_call(
        &mut self,
        _request: &McpCallApprovalRequest,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        Ok(true)
    }
}

struct PanicMcpApproval;

#[async_trait]
impl McpCallApprovalHandler for PanicMcpApproval {
    async fn approve_mcp_call(
        &mut self,
        _request: &McpCallApprovalRequest,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        panic!("approval must not be requested for an invalid or pre-cancelled dispatch")
    }
}

#[allow(clippy::too_many_arguments)]
fn append_provider_call(
    journal: &mut oxidra::session::SessionJournal,
    coordinator: &McpExecutionCoordinator,
    turn_admission: &TurnTransactionAdmissionV1,
    turn_id: &str,
    response_attempt_id: &str,
    call_id: &str,
    provider_name: &str,
    arguments: &Value,
) {
    append_provider_calls(
        journal,
        coordinator,
        turn_admission,
        turn_id,
        response_attempt_id,
        provider_name,
        &[(call_id, arguments.clone())],
    );
}

fn append_provider_calls(
    journal: &mut oxidra::session::SessionJournal,
    coordinator: &McpExecutionCoordinator,
    turn_admission: &TurnTransactionAdmissionV1,
    turn_id: &str,
    response_attempt_id: &str,
    provider_name: &str,
    calls: &[(&str, Value)],
) {
    let mut admission = coordinator
        .admit_provider_response_v1(
            journal,
            turn_admission,
            turn_id,
            json!({
                "response_attempt_id":response_attempt_id,
                "context":{},
            }),
        )
        .expect("admit MCP Provider response");
    let call_items = calls
        .iter()
        .map(|(call_id, arguments)| {
            json!({
                "type":"function_call",
                "call_id":call_id,
                "name":provider_name,
                "arguments":serde_json::to_string(arguments).expect("encode MCP arguments"),
            })
        })
        .collect::<Vec<_>>();
    admission
        .commit_completed_v1(
            journal,
            json!({
                "raw_response":{"output":call_items},
                "output_items":call_items,
                "text":"",
                "usage":{},
            }),
        )
        .expect("append MCP provider call");
}

fn begin_test_turn(
    journal: &mut oxidra::session::SessionJournal,
    turn_id: &str,
    text: &str,
) -> TurnTransactionAdmissionV1 {
    journal
        .begin_turn_transaction_v1(
            turn_id,
            json!({"text":text, "turn_boundary_version":TURN_BOUNDARY_VERSION}),
        )
        .expect("admit MCP test turn")
}

async fn open_after_execution_exit(
    store: &SessionStore,
    session_id: &str,
) -> oxidra::session::SessionJournal {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match store.open(session_id) {
            Ok(journal) => return journal,
            Err(error)
                if error.to_string().contains("already open") && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!(
                "execution owner did not release the session lock after transport exit: {error}"
            ),
        }
    }
}

fn open_after_execution_exit_blocking(
    store: &SessionStore,
    session_id: &str,
) -> oxidra::session::SessionJournal {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match store.open(session_id) {
            Ok(journal) => return journal,
            Err(error)
                if error.to_string().contains("already open") && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!(
                "independent native reaper did not release the session lock after exit: {error}"
            ),
        }
    }
}

fn tool_call_count(log: &Path) -> usize {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "tools/call")
        .count()
}

async fn wait_for_tool_call_count(log: &Path, expected: usize) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if tool_call_count(log) >= expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "MCP fixture did not receive the expected tools/call request"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn execution_digest_mismatch_cannot_start_a_server() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP approval integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP approval fixture");
    let root = directory.path().join("project");
    fs::create_dir_all(&root).expect("create MCP approval project");
    let script = root.join("server.py");
    let log = root.join("server.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP approval fixture");
    let config_path = root.join("mcp.toml");
    fs::write(&config_path, project_config(&python, &script, &log, false))
        .expect("write MCP project config");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize MCP project config"),
    )
    .expect("load MCP project config");

    let error = config
        .approve_execution(&"0".repeat(64))
        .expect_err("mismatched execution approval must fail");
    assert!(error.to_string().contains("does not match"));
    assert!(!log.exists(), "approval failure must not execute MCP code");
}

fn project_config(python: &Path, script: &Path, log: &Path, extra_newline: bool) -> String {
    let mut text = format!(
        "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\nargs = [\"{}\", \"{}\"]\ncwd = \".\"\ninherit_env = [{}]\n",
        quoted_path(python),
        quoted_path(script),
        quoted_path(log),
        inherited_environment()
            .into_iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if extra_newline {
        text.push('\n');
    }
    text
}

fn inherited_environment() -> Vec<&'static str> {
    ["SYSTEMROOT", "WINDIR", "HOME", "TMP", "TEMP"]
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some())
        .collect()
}

fn quoted_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn find_python() -> Option<PathBuf> {
    ["python", "python3", "py"].into_iter().find_map(|name| {
        let output = Command::new(name)
            .args(["-c", "import sys; print(sys.executable)"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let executable = String::from_utf8(output.stdout).ok()?;
        Path::new(executable.trim()).canonicalize().ok()
    })
}

const PYTHON_FIXTURE: &str = r#"
import json
import sys
import time

log_path = sys.argv[1]

def reply(message, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": message["id"]}
    if error is None:
        response["result"] = result
    else:
        response["error"] = error
    print(json.dumps(response), flush=True)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method", "")
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(method + "\n")
    if "id" not in message:
        continue
    if method == "server/discover":
        reply(message, {
            "resultType": "complete",
            "ttlMs": 1000,
            "cacheScope": "private",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {"listChanged": False}},
        })
    elif method == "tools/list":
        reply(message, {
            "resultType": "complete",
            "ttlMs": 1000,
            "cacheScope": "private",
            "tools": [{
                "name": "echo.v1",
                "description": "Echo structured text",
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                    "additionalProperties": False,
                },
            }],
        })
    elif method == "tools/call":
        text = message.get("params", {}).get("arguments", {}).get("text", "")
        if text.startswith("__drop_probe__:"):
            from pathlib import Path
            time.sleep(0.5)
            Path(text.split(":", 1)[1]).write_text("server survived dropped call", encoding="utf-8")
            time.sleep(30)
            reply(message, {
                "resultType": "complete",
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"text": text},
                "isError": False,
            })
            continue
        if text == "__hang__":
            time.sleep(30)
            reply(message, {
                "resultType": "complete",
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"text": text},
                "isError": False,
            })
            continue
        if text == "__rpc_error__":
            reply(message, error={"code": -32001, "message": "fixture call failed after dispatch"})
            continue
        if text == "__oversized_result__":
            reply(message, {
                "resultType": "complete",
                "content": [{"type": "text", "text": "x" * 60000}],
                "structuredContent": {"text": "x" * 60000},
                "isError": False,
            })
            continue
        reply(message, {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"text": text},
            "isError": False,
        })
    else:
        reply(message, error={"code": -32601, "message": "Method not found"})
"#;
