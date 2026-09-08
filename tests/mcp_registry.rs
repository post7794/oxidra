#![cfg(any(windows, target_os = "linux"))]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use oxidra::config::{ContextLimits, ProviderConfig};
use oxidra::context::{ContextRuntime, ToolSurfaceSnapshotV1, measure_prepared_request};
use oxidra::mcp::{
    AllowMcpCallApproval, DenyMcpCallApproval, MCP_EXECUTION_PLAN_VERSION,
    MCP_TOOL_REGISTRY_VERSION, McpCallIdentity, McpExecutionCoordinator, McpProjectConfig,
    McpProviderResponseAdmissionErrorV1, McpRegistry,
};
use oxidra::provider::{OpenAiResponsesProvider, ResponseRequest, SilentStreamObserverV1};
use oxidra::session::{SessionHeader, SessionJournal, SessionStore, TurnTransactionAdmissionV1};
use oxidra::turn::TURN_BOUNDARY_VERSION;
use oxidra::types::ToolDefinition;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

trait SessionJournalFixtureExt {
    fn append_fixture_event_v1(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> oxidra::Result<oxidra::session::JournalEvent>;
}

impl SessionJournalFixtureExt for SessionJournal {
    fn append_fixture_event_v1(
        &mut self,
        kind: impl Into<String>,
        turn_id: Option<&str>,
        data: Value,
    ) -> oxidra::Result<oxidra::session::JournalEvent> {
        // SAFETY: these integration fixtures deliberately construct durable
        // prefixes that are validated by the exercised MCP reducers.
        unsafe { self.append_protocol_event_and_sync_unchecked_v1(kind, turn_id, data) }
    }
}

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
    assert_eq!(activation.data["coordinator_version"], 4);
    assert_eq!(activation.data["call_chain_validator_version"], 4);
    assert_eq!(activation.data["surface_claim_version"], 1);
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
    let deep_provider = fixture_openai_provider();
    let (deep_request, _deep_runtime, mut deep_data) =
        provider_request_materials(&mut journal, &coordinator, &deep_provider, "deep-attempt");
    deep_data["context"]["deep"] = deep;
    let before_deep_event = journal
        .read_events()
        .expect("read journal before deep Provider event");
    let deep_error = coordinator
        .admit_prepared_provider_request_v1(
            &mut journal,
            &deep_turn,
            "deep-provider-event-turn",
            deep_data,
            deep_provider
                .prepare_request(deep_request)
                .expect("seal deep-event Provider request"),
            &deep_provider,
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
    let wide_provider = fixture_openai_provider();
    let (wide_request, _wide_runtime, mut wide_data) =
        provider_request_materials(&mut journal, &coordinator, &wide_provider, "wide-attempt");
    wide_data["context"]["blob"] = Value::String("x".repeat(300 * 1024));
    let before_wide_event = journal
        .read_events()
        .expect("read journal before oversized Provider event");
    let wide_error = coordinator
        .admit_prepared_provider_request_v1(
            &mut journal,
            &wide_turn,
            "wide-provider-event-turn",
            wide_data,
            wide_provider
                .prepare_request(wide_request)
                .expect("seal wide-event Provider request"),
            &wide_provider,
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

    let activation_binding = &activation.data["bindings"][0];
    assert_eq!(activation_binding["provider_name"], provider_name.clone());
    assert_eq!(activation_binding["server_name"], "fixture");
    assert_eq!(activation_binding["raw_tool_name"], "echo.v1");
    assert_eq!(activation_binding["protocol_version"], protocol_version);
    assert_eq!(
        activation_binding["definition_digest"]
            .as_str()
            .expect("activation definition digest")
            .len(),
        64
    );
    assert_eq!(
        activation_binding["output_schema_digest"]
            .as_str()
            .expect("activation output-schema digest")
            .len(),
        64
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
            &mut DenyMcpCallApproval,
        )
        .await
        .expect_err("a coordinator cannot write into another session");
    assert!(other_error.to_string().contains("different session"));

    let turn_id = "mcp-turn";
    let call_id = r#"{"command":"calc.exe"}"#;
    let arguments = json!({"text":"true"});
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
    )
    .await;

    let call_cancellation = CancellationToken::new();
    let mut call_approval = AllowMcpCallApproval;
    let result = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, call_id, &provider_name),
            &call_cancellation,
            &mut call_approval,
        )
        .await
        .expect("call namespaced MCP tool");
    assert_eq!(
        result.output,
        json!({
            "profile_version":1,
            "trust":"untrusted_mcp_tool_output",
            "is_error":false,
            "content":["true"],
        })
    );
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
    assert_eq!(completed.data["output"], result.output);
    assert_eq!(
        completed.data["mcp_raw_result"]["content"][0]["text"],
        "true"
    );

    let replay_error = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, call_id, &provider_name),
            &CancellationToken::new(),
            &mut DenyMcpCallApproval,
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
    )
    .await;
    let identity_error = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "identity-call", "mcp_missing_fixture_tool"),
            &CancellationToken::new(),
            &mut DenyMcpCallApproval,
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
    )
    .await;
    let invalid_arguments = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "invalid-arguments-call", &provider_name),
            &CancellationToken::new(),
            &mut DenyMcpCallApproval,
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
    )
    .await;
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
    )
    .await;
    let cancelled_token = CancellationToken::new();
    cancelled_token.cancel();
    let cancelled = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "cancelled-call", &provider_name),
            &cancelled_token,
            &mut DenyMcpCallApproval,
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
    )
    .await;
    let output_limit = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(turn_id, "output-limit-call", &provider_name),
            &CancellationToken::new(),
            &mut AllowMcpCallApproval,
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
    )
    .await;
    let closed_after_output_limit = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(
                closed_turn_id,
                "closed-after-output-limit-call",
                &provider_name,
            ),
            &CancellationToken::new(),
            &mut AllowMcpCallApproval,
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
    )
    .await;
    let in_doubt = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(rpc_turn_id, "in-doubt-call", &provider_name),
            &CancellationToken::new(),
            &mut AllowMcpCallApproval,
        )
        .await
        .expect("post-dispatch RPC error is durably in doubt");
    assert_eq!(in_doubt.error_code.as_deref(), Some("in_doubt"));
    let blocked = coordinator
        .execute_call(
            &mut journal,
            McpCallIdentity::new(rpc_turn_id, "blocked-call", &provider_name),
            &CancellationToken::new(),
            &mut DenyMcpCallApproval,
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
        .append_fixture_event_v1(
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
        .append_fixture_event_v1(
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
    )
    .await;

    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpCallApproval;
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
            &mut AllowMcpCallApproval,
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
    )
    .await;
    let calls_before = tool_call_count(&log);
    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpCallApproval;
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
    let stale_tools_event_seq = before_events
        .iter()
        .rev()
        .find(|event| event.kind == "context.tools")
        .expect("durable MCP surface before stale writer probe")
        .seq;
    let stale_request = ResponseRequest::new(Vec::new(), coordinator.definitions());
    let stale_provider = fixture_openai_provider();
    let stale_runtime =
        ContextRuntime::from_provider(stale_provider.config(), ContextLimits::default())
            .expect("build stale Provider runtime");
    let stale_measurement = measure_prepared_request(&stale_request, &stale_runtime)
        .expect("measure stale MCP Provider request");
    let stale_writer_error = coordinator
        .admit_prepared_provider_request_v1(
            &mut reopened,
            &retry_admission,
            retry_turn,
            json!({
                "response_attempt_id":"retry-response",
                "context":{
                    "measurement":stale_measurement,
                    "provider_usage_domain":stale_runtime.provider_usage_domain,
                    "tools_event_seq":stale_tools_event_seq,
                },
            }),
            stale_provider
                .prepare_request(stale_request)
                .expect("seal stale Provider request"),
            &stale_provider,
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
fn execution_guardian_retains_generation_gate_after_host_kill() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP host-death guardian test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP guardian fault fixture");
    let root = directory.path().join("project");
    let data_dir = directory.path().join("data");
    let barrier = directory.path().join("guardian-barrier");
    let ready = directory.path().join("host-ready");
    let script = root.join("server.py");
    let log = root.join("server.log");
    let config_path = root.join("mcp.toml");
    fs::create_dir_all(&root).expect("create MCP guardian project");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP guardian server fixture");
    fs::write(
        &config_path,
        guardian_project_config(&python, &script, &log),
    )
    .expect("write MCP guardian project config");

    let mut host = Command::new(std::env::current_exe().expect("resolve MCP test executable"));
    host.args([
        "--ignored",
        "--exact",
        "execution_guardian_host_kill_helper",
        "--nocapture",
    ])
    .env("OXIDRA_GUARDIAN_TEST_ROOT", &root)
    .env("OXIDRA_GUARDIAN_TEST_DATA", &data_dir)
    .env("OXIDRA_GUARDIAN_TEST_CONFIG", &config_path)
    .env("OXIDRA_GUARDIAN_TEST_READY", &ready)
    .env("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1", &barrier)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit());
    let mut host = host.spawn().expect("spawn MCP guardian host helper");

    wait_for_file_v1(&ready, Duration::from_secs(15));
    wait_for_process_log_count_v1(&log, 1, Duration::from_secs(15));
    let old_server_pid = wait_for_logged_pid_v1(&log, "process:", 0, Duration::from_secs(15));
    let old_server = ExactProcessWitnessV1::open(old_server_pid)
        .expect("open exact old MCP server process witness");
    #[cfg(windows)]
    let old_worker = {
        let pid = wait_for_logged_pid_v1(&log, "worker:", 0, Duration::from_secs(15));
        ExactProcessWitnessV1::open(pid).expect("open exact old MCP worker process witness")
    };

    // Begin competing before the owner dies. The contender continuously tries
    // to open the durable session, so a transient execution-gate release cannot
    // hide between two point-in-time probes in the parent test.
    let contender_data = data_dir.clone();
    let (contender_started_tx, contender_started_rx) = mpsc::channel();
    let (contender_open_tx, contender_open_rx) = mpsc::channel();
    let contender = std::thread::spawn(move || {
        let result = match SessionStore::new(&contender_data) {
            Err(error) => Err(error.to_string()),
            Ok(store) => {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut reported_busy = false;
                loop {
                    match store.open("guardian-host-kill") {
                        Ok(journal) => break Ok(journal),
                        Err(error)
                            if (error.to_string().contains("already open")
                                || error.to_string().contains("still terminating"))
                                && Instant::now() < deadline =>
                        {
                            if !reported_busy {
                                let _ = contender_started_tx.send(());
                                reported_busy = true;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => break Err(error.to_string()),
                    }
                }
            }
        };
        let _ = contender_open_tx.send(result);
    });
    contender_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("contender must observe the live owner before host kill");
    host.kill().expect("force-kill MCP guardian host helper");
    let _ = host.wait();

    wait_for_file_v1(
        &barrier.join("host-death-observed"),
        Duration::from_secs(15),
    );
    #[cfg(windows)]
    old_worker.assert_running();
    assert!(
        matches!(contender_open_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "contender opened while the old execution guardian was paused before termination"
    );

    fs::write(barrier.join("allow-terminate"), b"continue")
        .expect("release guardian termination barrier");
    wait_for_file_v1(&barrier.join("containment-empty"), Duration::from_secs(15));
    old_server.wait_for_exit(Duration::from_secs(5));
    #[cfg(windows)]
    old_worker.wait_for_exit(Duration::from_secs(5));
    assert!(
        matches!(contender_open_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "contender opened after containment exit but before guardian gate release"
    );

    fs::write(barrier.join("allow-unlock"), b"continue").expect("release guardian execution gate");
    let mut journal = contender_open_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("contender must open after guardian gate release")
        .unwrap_or_else(|error| panic!("guardian contender failed to open: {error}"));
    contender.join().expect("join guardian contender");
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize guardian contender config"),
    )
    .expect("load guardian contender config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve guardian contender execution plan");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build guardian contender runtime");
    let eligibility = journal
        .mcp_resume_eligibility()
        .expect("durable guardian activation permits resume after old containment exit");
    let resumed_registry = runtime
        .block_on(McpRegistry::connect_for_resume(
            &approved,
            ["read", "edit", "write", "shell", "remember"]
                .into_iter()
                .map(str::to_owned),
            eligibility,
            &CancellationToken::new(),
        ))
        .expect("connect resumed MCP generation only after old containment is empty");
    let registry_digest = resumed_registry.digest().to_owned();
    let mut coordinator = McpExecutionCoordinator::resume(
        resumed_registry
            .approve_surface(&registry_digest)
            .expect("approve unchanged guardian resume surface"),
        &journal,
    )
    .expect("resume the durable guardian registry epoch");
    wait_for_process_log_count_v1(&log, 2, Duration::from_secs(15));
    runtime.block_on(coordinator.shutdown());
}

#[test]
fn execution_guardian_first_death_durably_poison_generation() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP guardian-first fault test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP guardian-first fixture");
    let root = directory.path().join("project");
    let data_dir = directory.path().join("data");
    let barrier = directory.path().join("guardian-barrier");
    let ready = directory.path().join("host-ready");
    let script = root.join("server.py");
    let log = root.join("server.log");
    let config_path = root.join("mcp.toml");
    fs::create_dir_all(&root).expect("create MCP guardian-first project");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP guardian-first server fixture");
    fs::write(
        &config_path,
        guardian_project_config(&python, &script, &log),
    )
    .expect("write MCP guardian-first project config");

    let mut host = Command::new(std::env::current_exe().expect("resolve MCP test executable"));
    host.args([
        "--ignored",
        "--exact",
        "execution_guardian_host_kill_helper",
        "--nocapture",
    ])
    .env("OXIDRA_GUARDIAN_TEST_ROOT", &root)
    .env("OXIDRA_GUARDIAN_TEST_DATA", &data_dir)
    .env("OXIDRA_GUARDIAN_TEST_CONFIG", &config_path)
    .env("OXIDRA_GUARDIAN_TEST_READY", &ready)
    .env("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1", &barrier)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit());
    let mut host = host.spawn().expect("spawn MCP guardian-first host helper");

    wait_for_file_v1(&ready, Duration::from_secs(15));
    wait_for_process_log_count_v1(&log, 1, Duration::from_secs(15));
    let guardian_ready = barrier.join("guardian-ready");
    wait_for_file_v1(&guardian_ready, Duration::from_secs(15));
    let guardian_pid = fs::read_to_string(&guardian_ready)
        .expect("read exact guardian PID")
        .parse::<u32>()
        .expect("parse exact guardian PID");
    let guardian =
        ExactProcessWitnessV1::open(guardian_pid).expect("open exact guardian process witness");
    let old_server_pid = wait_for_logged_pid_v1(&log, "process:", 0, Duration::from_secs(15));
    let old_server = ExactProcessWitnessV1::open(old_server_pid)
        .expect("open exact old MCP server process witness");
    #[cfg(windows)]
    let old_worker = {
        let pid = wait_for_logged_pid_v1(&log, "worker:", 0, Duration::from_secs(15));
        ExactProcessWitnessV1::open(pid).expect("open exact old MCP worker process witness")
    };

    guardian.kill_and_wait(Duration::from_secs(15));
    old_server.assert_running();
    #[cfg(windows)]
    old_worker.assert_running();

    let journal_path = data_dir.join("sessions").join("guardian-host-kill.jsonl");
    let complete_journal_bytes =
        fs::read(&journal_path).expect("inspect guardian-first journal before host death");
    host.kill()
        .expect("force-kill MCP host after its guardian died");
    let _ = host.wait();

    // Model the other half of the same crash prefix: the host can die after
    // appending only part of its next JSONL event.  Quarantine forbids open()
    // from repairing this tail, so the read-only export must preserve it.
    let incomplete_tail = b"{\"schema\":\"oxidra.session.v1\",\"seq\":";
    fs::OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .expect("open guardian-first journal for partial-tail fixture")
        .write_all(incomplete_tail)
        .expect("append guardian-first partial-tail fixture");
    let journal_bytes_before =
        fs::read(&journal_path).expect("inspect guardian-first partial journal");

    let store = SessionStore::new(&data_dir).expect("open guardian-first session store");
    let error = store
        .open("guardian-host-kill")
        .err()
        .expect("stale active generation must fail closed after guardian-first death");
    assert!(error.to_string().contains("fail-closed"), "{error}");
    assert!(
        error
            .to_string()
            .contains("did not persist an exact containment-empty proof"),
        "{error}"
    );
    assert_eq!(
        fs::read(&journal_path).expect("inspect guardian-first journal after rejected reopen"),
        journal_bytes_before,
        "fail-closed gate rejection must happen before journal mutation"
    );

    let delete_error = store
        .delete("guardian-host-kill")
        .expect_err("quarantined generation must not be deletable in place");
    assert!(
        delete_error.to_string().contains("quarantined"),
        "{delete_error}"
    );

    let gate_path = store
        .layout()
        .execution_gate_path_v1("guardian-host-kill")
        .expect("resolve guardian-first gate");
    let gate_bytes_before = fs::read(&gate_path).expect("read quarantined gate state");
    let export_path = directory
        .path()
        .join("guardian-host-kill-export.oxidra-session-export");
    let exported_bytes = store
        .export_read_only_snapshot("guardian-host-kill", &export_path)
        .expect("export quarantined journal without reopening it");
    let archive = fs::read(&export_path).expect("read guardian-first export");
    assert_eq!(exported_bytes, archive.len() as u64);
    let manifest_end = archive
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("read-only export must contain its manifest line");
    let manifest: Value = serde_json::from_slice(&archive[..manifest_end])
        .expect("parse guardian-first export manifest");
    assert_eq!(manifest["format"], "oxidra.session.read_only_export");
    assert_eq!(manifest["resume_allowed"], false);
    assert_eq!(
        manifest["journal_complete_prefix_bytes"],
        complete_journal_bytes.len()
    );
    assert_eq!(
        manifest["journal_incomplete_tail"]["offset"],
        complete_journal_bytes.len()
    );
    assert_eq!(
        manifest["journal_incomplete_tail"]["bytes"],
        incomplete_tail.len()
    );
    assert_eq!(
        manifest["journal_incomplete_tail"]["sha256"],
        hex::encode(Sha256::digest(incomplete_tail))
    );
    assert_eq!(
        &archive[manifest_end + 1..],
        journal_bytes_before,
        "archive must preserve the exact quarantined journal after its non-resumable manifest"
    );
    assert_eq!(
        fs::read(&journal_path).expect("re-read quarantined journal"),
        journal_bytes_before,
        "read-only export must not mutate the source journal"
    );
    assert_eq!(
        fs::read(&gate_path).expect("re-read quarantined gate state"),
        gate_bytes_before,
        "read-only export must not modify or clear quarantine"
    );

    old_server.wait_for_exit(Duration::from_secs(15));
    #[cfg(windows)]
    old_worker.wait_for_exit(Duration::from_secs(15));
}

#[cfg(target_os = "linux")]
#[test]
fn execution_guardian_pins_child_before_arming_parent_death_signal() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP guardian registration-race test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP guardian registration fixture");
    let root = directory.path().join("project");
    let data_dir = directory.path().join("data");
    let barrier = directory.path().join("guardian-barrier");
    let script = root.join("server.py");
    let log = root.join("server.log");
    let config_path = root.join("mcp.toml");
    fs::create_dir_all(&root).expect("create MCP guardian registration project");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP guardian registration fixture");
    fs::write(
        &config_path,
        guardian_project_config(&python, &script, &log),
    )
    .expect("write MCP guardian registration config");

    let mut host = Command::new(std::env::current_exe().expect("resolve MCP test executable"));
    host.args([
        "--ignored",
        "--exact",
        "execution_guardian_registration_host_kill_helper",
        "--nocapture",
    ])
    .env("OXIDRA_GUARDIAN_TEST_ROOT", &root)
    .env("OXIDRA_GUARDIAN_TEST_DATA", &data_dir)
    .env("OXIDRA_GUARDIAN_TEST_CONFIG", &config_path)
    .env("OXIDRA_INTERNAL_GUARDIAN_TEST_BARRIER_V1", &barrier)
    .env("OXIDRA_INTERNAL_GUARDIAN_REGISTER_BARRIER_V1", "1")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit());
    let mut host = host
        .spawn()
        .expect("spawn MCP guardian registration host helper");

    let registration = barrier.join("register-observed");
    wait_for_file_v1(&registration, Duration::from_secs(15));
    let child_pid = fs::read_to_string(&registration)
        .expect("read guardian registration PID")
        .parse::<u32>()
        .expect("parse guardian registration PID");
    let child = ExactProcessWitnessV1::open(child_pid)
        .expect("open exact pre-exec MCP child process witness");
    child.assert_running();

    host.kill()
        .expect("force-kill MCP host before guardian pidfd_open");
    let _ = host.wait();
    child.assert_running();

    let store = SessionStore::new(&data_dir).expect("open guardian registration store");
    let blocked = store
        .open("guardian-registration-kill")
        .err()
        .expect("guardian gate must remain locked before pidfd registration completes");
    assert!(
        blocked.to_string().contains("already open")
            || blocked.to_string().contains("still terminating"),
        "{blocked}"
    );

    // Let the guardian acquire the exact pidfd while the child is still
    // blocked in the earlier pre-exec hook. The following containment hook
    // then observes the dead parent and exits; only after that exact pidfd is
    // signalled and ready may the guardian release the generation gate.
    fs::write(barrier.join("allow-terminate"), b"continue")
        .expect("release guardian termination barrier");
    fs::write(barrier.join("allow-register"), b"continue")
        .expect("release guardian pidfd registration barrier");
    child.wait_for_exit(Duration::from_secs(15));
    wait_for_file_v1(&barrier.join("containment-empty"), Duration::from_secs(15));
    let blocked = store
        .open("guardian-registration-kill")
        .err()
        .expect("guardian gate must remain locked after the exact child exits");
    assert!(
        blocked.to_string().contains("still terminating"),
        "{blocked}"
    );
    fs::write(barrier.join("allow-unlock"), b"continue").expect("release guardian unlock barrier");
    let journal = open_after_execution_exit_blocking(&store, "guardian-registration-kill");
    drop(journal);
}

#[test]
#[ignore = "subprocess helper for execution_guardian_retains_generation_gate_after_host_kill"]
fn execution_guardian_host_kill_helper() {
    let root = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_ROOT").expect("guardian helper project root"),
    );
    let data_dir = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_DATA").expect("guardian helper data directory"),
    );
    let config_path = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_CONFIG").expect("guardian helper config path"),
    );
    let ready = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_READY").expect("guardian helper ready path"),
    );
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize guardian helper config"),
    )
    .expect("load guardian helper config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve guardian helper execution plan");
    let store = SessionStore::new(&data_dir).expect("create guardian helper store");
    let mut journal = store
        .create_with_id(
            "guardian-host-kill",
            SessionHeader::new(&root, "mcp-guardian-host-kill"),
        )
        .expect("create guardian helper journal");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build guardian helper runtime");
    runtime.block_on(async move {
        let registry = McpRegistry::connect_for_activation(
            &approved,
            ["read", "edit", "write", "shell", "remember"]
                .into_iter()
                .map(str::to_owned),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .expect("connect guardian helper registry");
        let registry_digest = registry.digest().to_owned();
        let _coordinator = McpExecutionCoordinator::activate(
            registry
                .approve_surface(&registry_digest)
                .expect("approve guardian helper registry surface"),
            &mut journal,
        )
        .expect("persist guardian helper registry activation");
        fs::write(&ready, b"ready").expect("write guardian helper ready marker");
        std::future::pending::<()>().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "subprocess helper for execution_guardian_pins_child_before_arming_parent_death_signal"]
fn execution_guardian_registration_host_kill_helper() {
    let root = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_ROOT")
            .expect("guardian registration helper project root"),
    );
    let data_dir = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_DATA")
            .expect("guardian registration helper data directory"),
    );
    let config_path = PathBuf::from(
        std::env::var_os("OXIDRA_GUARDIAN_TEST_CONFIG")
            .expect("guardian registration helper config path"),
    );
    let config = McpProjectConfig::load(
        &root,
        &config_path
            .canonicalize()
            .expect("canonicalize guardian registration helper config"),
    )
    .expect("load guardian registration helper config");
    let approved = config
        .approve_execution(config.execution_plan_digest())
        .expect("approve guardian registration helper execution plan");
    let store = SessionStore::new(&data_dir).expect("create guardian registration helper store");
    let mut journal = store
        .create_with_id(
            "guardian-registration-kill",
            SessionHeader::new(&root, "mcp-guardian-registration-kill"),
        )
        .expect("create guardian registration helper journal");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build guardian registration helper runtime");
    runtime.block_on(async move {
        let _registry = McpRegistry::connect_for_activation(
            &approved,
            ["read", "edit", "write", "shell", "remember"]
                .into_iter()
                .map(str::to_owned),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .expect("connect guardian registration helper registry");
        std::future::pending::<()>().await;
    });
}

fn wait_for_file_v1(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.is_file() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_process_log_count_v1(path: &Path, expected: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let count = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.starts_with("process:"))
            .count();
        if count >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} MCP process records"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_logged_pid_v1(path: &Path, prefix: &str, index: usize, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(pid) = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .filter_map(|value| value.parse::<u32>().ok())
            .nth(index)
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {prefix} PID {index} in {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
struct ExactProcessWitnessV1 {
    process_id: u32,
    pidfd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl ExactProcessWitnessV1 {
    fn open(process_id: u32) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;

        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, process_id, 0) };
        if raw == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            process_id,
            pidfd: unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) },
        })
    }

    fn wait_for_exit(&self, timeout: Duration) {
        use std::os::fd::AsRawFd;

        let deadline = Instant::now() + timeout;
        loop {
            let mut descriptor = nix::libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { nix::libc::poll(&mut descriptor, 1, 0) };
            if result > 0 && descriptor.revents & nix::libc::POLLIN != 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "old MCP process {} survived guardian containment-empty proof",
                self.process_id
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_wait(&self, timeout: Duration) {
        use std::os::fd::AsRawFd;

        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                nix::libc::SIGKILL,
                std::ptr::null::<nix::libc::siginfo_t>(),
                0,
            )
        };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(nix::libc::ESRCH),
                "kill exact process {} failed: {error}",
                self.process_id
            );
        }
        self.wait_for_exit(timeout);
    }

    fn assert_running(&self) {
        use std::os::fd::AsRawFd;

        let mut descriptor = nix::libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { nix::libc::poll(&mut descriptor, 1, 0) };
        assert_eq!(
            result, 0,
            "pre-exec MCP child {} exited before guardian pidfd registration",
            self.process_id
        );
    }
}

#[cfg(windows)]
struct ExactProcessWitnessV1 {
    process_id: u32,
    process: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl ExactProcessWitnessV1 {
    fn open(process_id: u32) -> std::io::Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE};

        const SYNCHRONIZE: u32 = 0x0010_0000;

        let raw = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, 0, process_id) };
        if raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            process_id,
            process: unsafe { OwnedHandle::from_raw_handle(raw.cast()) },
        })
    }

    fn wait_for_exit(&self, timeout: Duration) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        let deadline = Instant::now() + timeout;
        loop {
            let result = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) };
            if result == WAIT_OBJECT_0 {
                return;
            }
            assert_eq!(result, WAIT_TIMEOUT, "wait for exact MCP process failed");
            assert!(
                Instant::now() < deadline,
                "old MCP process {} survived guardian containment-empty proof",
                self.process_id
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_wait(&self, timeout: Duration) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::TerminateProcess;

        let result = unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) };
        if result == 0 {
            let error = std::io::Error::last_os_error();
            // ERROR_ACCESS_DENIED is also returned when the exact process has
            // already exited; the subsequent handle wait is authoritative.
            assert_eq!(
                error.raw_os_error(),
                Some(5),
                "kill exact process {} failed: {error}",
                self.process_id
            );
        }
        self.wait_for_exit(timeout);
    }

    fn assert_running(&self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        assert_eq!(
            unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) },
            WAIT_TIMEOUT,
            "old MCP worker exited before the guardian termination barrier was released"
        );
    }
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
    runtime.block_on(append_provider_call(
        &mut journal,
        &coordinator,
        &turn_admission,
        turn_id,
        "started-call-drop-response",
        "started-call-drop-call",
        &provider_name,
        &json!({"text":format!("__drop_probe__:{}", survived.display())}),
    ));

    let calls_before = tool_call_count(&log);
    let cancellation = CancellationToken::new();
    let mut approval = AllowMcpCallApproval;
    let mut started_future = Box::pin(coordinator.execute_call(
        &mut journal,
        McpCallIdentity::new(turn_id, "started-call-drop-call", &provider_name),
        &cancellation,
        &mut approval,
    ));
    runtime.block_on(async {
        tokio::select! {
            result = &mut started_future => {
                let error = result.expect_err("drop-probe MCP call unexpectedly returned successfully");
                panic!("drop-probe MCP call completed before it could be dropped: {error}");
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

fn fixture_openai_provider() -> OpenAiResponsesProvider {
    OpenAiResponsesProvider::new(ProviderConfig {
        api_key: "fixture-key".to_owned(),
        api_base_url: url::Url::parse("http://127.0.0.1:1/v1/")
            .expect("parse fixture Provider URL"),
        model: "mcp-registry-test".to_owned(),
    })
    .expect("create fixture OpenAI Provider")
}

fn openai_provider_for_output(
    output: Vec<Value>,
) -> (
    OpenAiResponsesProvider,
    mpsc::Receiver<Vec<u8>>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind exact-wire Provider fixture");
    let address = listener
        .local_addr()
        .expect("read Provider fixture address");
    let provider = OpenAiResponsesProvider::new(ProviderConfig {
        api_key: "fixture-key".to_owned(),
        api_base_url: url::Url::parse(&format!("http://{address}/v1/"))
            .expect("parse exact-wire Provider URL"),
        model: "mcp-registry-test".to_owned(),
    })
    .expect("create exact-wire OpenAI Provider");
    let (body_tx, body_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept exact-wire Provider request");
        let body = read_http_request_body(&mut stream);
        body_tx.send(body).expect("record exact Provider body");
        let payload = json!({
            "type":"response.completed",
            "response":{"output":output},
        });
        let sse = format!(
            "event: response.completed\ndata: {}\n\n",
            serde_json::to_string(&payload).expect("encode Provider fixture response")
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            sse.len(),
            sse
        )
        .expect("write exact-wire Provider response");
        stream.flush().expect("flush exact-wire Provider response");
    });
    (provider, body_rx, server)
}

fn read_http_request_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let header_end = loop {
        if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).expect("read Provider request");
        assert!(count != 0, "Provider request ended before its headers");
        received.extend_from_slice(&chunk[..count]);
    };
    let headers = std::str::from_utf8(&received[..header_end]).expect("UTF-8 Provider headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid Content-Length"))
        })
        .expect("Provider request Content-Length");
    while received.len() - header_end < content_length {
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).expect("read Provider request body");
        assert!(count != 0, "Provider request ended before its body");
        received.extend_from_slice(&chunk[..count]);
    }
    received[header_end..header_end + content_length].to_vec()
}

fn provider_request_materials(
    journal: &mut oxidra::session::SessionJournal,
    coordinator: &McpExecutionCoordinator,
    provider: &OpenAiResponsesProvider,
    response_attempt_id: &str,
) -> (ResponseRequest, ContextRuntime, Value) {
    let runtime = ContextRuntime::from_provider(provider.config(), ContextLimits::default())
        .expect("build exact MCP Provider runtime");
    let configured_event_seq = journal
        .append_fixture_event_v1("context.configured", None, runtime.configured_event_data())
        .expect("append MCP Provider request context.configured")
        .seq;
    let surface = coordinator
        .surface_claim_v1()
        .expect("derive live MCP surface")
        .merge_with(Vec::new())
        .expect("build exact MCP Provider surface");
    let tools_event = coordinator
        .append_context_tools_v1(journal, &surface)
        .expect("append exact MCP Provider surface");
    let events = journal
        .read_events()
        .expect("read exact MCP Provider request prefix");
    let input = oxidra::projection::project_events(&events)
        .expect("project exact MCP Provider request prefix");
    let request = ResponseRequest::new(input, surface.tools().to_vec());
    let measurement =
        measure_prepared_request(&request, &runtime).expect("measure exact MCP Provider request");
    let context = oxidra::context::decide_context(
        &events,
        &runtime,
        measurement,
        events.last().map(|event| event.seq),
        None,
        None,
        None,
        Some(configured_event_seq),
        tools_event.seq,
    )
    .expect("decide exact MCP Provider request context");
    let data = json!({
        "response_attempt_id":response_attempt_id,
        "context":context.audit_value().expect("encode exact MCP Provider request context"),
    });
    (request, runtime, data)
}

#[allow(clippy::too_many_arguments)]
async fn append_provider_call(
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
    )
    .await;
}

async fn append_provider_calls(
    journal: &mut oxidra::session::SessionJournal,
    coordinator: &McpExecutionCoordinator,
    turn_admission: &TurnTransactionAdmissionV1,
    turn_id: &str,
    response_attempt_id: &str,
    provider_name: &str,
    calls: &[(&str, Value)],
) {
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
    let (provider, captured_body, server) = openai_provider_for_output(call_items);
    let (request, _runtime, data) =
        provider_request_materials(journal, coordinator, &provider, response_attempt_id);
    let request = provider
        .prepare_request(request)
        .expect("seal exact MCP Provider request");
    let expected_body = request.body_bytes().to_vec();
    let prepared = coordinator
        .admit_prepared_provider_request_v1(
            journal,
            turn_admission,
            turn_id,
            data,
            request,
            &provider,
        )
        .expect("admit exact MCP Provider request");
    let mut observer = SilentStreamObserverV1;
    let outcome = prepared
        .respond(&mut observer, CancellationToken::new())
        .await;
    let actual_body = captured_body
        .recv_timeout(Duration::from_secs(5))
        .expect("capture exact Provider wire body");
    assert_eq!(
        actual_body, expected_body,
        "MCP transport changed the sealed Provider body"
    );
    server.join().expect("join exact-wire Provider fixture");
    let committed = outcome
        .commit_v1(journal)
        .expect("append exact MCP Provider result");
    assert_eq!(committed.tool_calls().len(), calls.len());
}

fn begin_test_turn(
    journal: &mut oxidra::session::SessionJournal,
    turn_id: &str,
    text: &str,
) -> TurnTransactionAdmissionV1 {
    journal
        .begin_turn_transaction_v1(
            turn_id,
            json!({
                "item":{"role":"user","content":text},
                "turn_boundary_version":TURN_BOUNDARY_VERSION
            }),
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
                if (error.to_string().contains("already open")
                    || error.to_string().contains("still terminating"))
                    && Instant::now() < deadline =>
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
                if (error.to_string().contains("already open")
                    || error.to_string().contains("still terminating"))
                    && Instant::now() < deadline =>
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

fn guardian_project_config(python: &Path, script: &Path, log: &Path) -> String {
    format!(
        "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\nargs = [\"{}\", \"{}\", \"guardian-worker\"]\ncwd = \".\"\ninherit_env = [{}]\n",
        quoted_path(python),
        quoted_path(script),
        quoted_path(log),
        inherited_environment()
            .into_iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
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
    #[cfg(all(windows, debug_assertions))]
    {
        static GUARDIAN_JOB_TEST_SETUP: std::sync::Once = std::sync::Once::new();
        GUARDIAN_JOB_TEST_SETUP.call_once(|| {
            // Cargo may place the integration-test host in a non-breakaway
            // Job. The production guardian remains fail-closed; this explicit
            // debug-only hook lets the fixture exercise direct
            // TerminateProcess containment instead.
            unsafe {
                std::env::set_var("OXIDRA_INTERNAL_GUARDIAN_ALLOW_SAME_JOB_V1", "1");
            }
        });
    }
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
import os
import subprocess
import sys
import time

log_path = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "default"

with open(log_path, "a", encoding="utf-8") as log:
    log.write(f"process:{os.getpid()}\n")
    if os.name == "nt" and mode == "guardian-worker":
        worker = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.write(f"worker:{worker.pid}\n")

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
