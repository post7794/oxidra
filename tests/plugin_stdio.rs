use std::fs;
use std::process::{Command, Stdio};

use oxidra::plugin::{
    MCP_PROTOCOL_VERSION, PluginActivation, PluginConfig, PluginEnvironment, PluginManifest,
    PluginState, PluginSupervisor, canonical_tool_schema_hash,
};
use oxidra::types::{ToolCall, ToolDefinition};
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn lazy_mcp_plugin_handshakes_calls_and_stays_on_one_connection() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create plugin fixture directory");
    let script = directory.path().join("fixture.py");
    let log = directory.path().join("methods.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let tools = vec![ToolDefinition {
        name: "echo".to_owned(),
        description: "Echo text".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": false
        }),
    }];
    let manifest = PluginManifest {
        name: "fixture".to_owned(),
        protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        command: python,
        args: vec![
            script.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        ],
        cwd: None,
        env: PluginEnvironment::default(),
        schema_hash: canonical_tool_schema_hash(&tools).expect("hash fixture tools"),
        tools,
        dynamic_tools: false,
    };
    let supervisor = PluginSupervisor::new(
        manifest,
        directory.path(),
        PluginConfig {
            activation: PluginActivation::OnCall,
            ..PluginConfig::default()
        },
    )
    .expect("construct plugin supervisor");

    assert_eq!(supervisor.state().await, PluginState::Dormant);
    assert!(
        !log.exists(),
        "on_call plugin started before its first call"
    );

    for (id, text) in [("call-1", "first"), ("call-2", "second")] {
        let result = supervisor
            .call_tool(
                ToolCall {
                    id: id.to_owned(),
                    name: "fixture.echo".to_owned(),
                    arguments: json!({"text": text}),
                },
                CancellationToken::new(),
            )
            .await;
        assert!(!result.is_error, "plugin call failed: {result:?}");
        assert_eq!(result.output["content"][0]["text"], text);
    }
    assert_eq!(supervisor.state().await, PluginState::Ready);
    supervisor.shutdown().await.expect("shutdown MCP fixture");
    assert_eq!(supervisor.state().await, PluginState::Dormant);

    let methods = fs::read_to_string(&log)
        .expect("read fixture method log")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
            "tools/call"
        ]
    );
}

fn find_python() -> Option<String> {
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
        let executable = std::path::Path::new(executable.trim());
        executable
            .canonicalize()
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    })
}

const PYTHON_FIXTURE: &str = r#"
import json
import sys

log_path = sys.argv[1]
tools = [{
    "name": "echo",
    "description": "Echo text",
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
        "additionalProperties": False,
    },
}]

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method", "")
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(method + "\n")
        log.flush()
    if "id" not in message:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": tools}
    elif method == "tools/call":
        text = message.get("params", {}).get("arguments", {}).get("text", "")
        result = {"content": [{"type": "text", "text": text}], "isError": False}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"#;
