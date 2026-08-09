#![cfg(any(windows, target_os = "linux"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use oxidra::mcp::{
    MCP_EXECUTION_PLAN_VERSION, MCP_TOOL_REGISTRY_VERSION, McpProjectConfig, McpRegistry,
};
use serde_json::json;
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

    let cancellation = CancellationToken::new();
    let mut registry = McpRegistry::connect(
        &config,
        ["read", "edit", "write", "shell", "remember"]
            .into_iter()
            .map(str::to_owned),
        &cancellation,
    )
    .await
    .expect("connect MCP registry");
    assert_eq!(MCP_EXECUTION_PLAN_VERSION, 2);
    assert_eq!(MCP_TOOL_REGISTRY_VERSION, 3);
    assert_eq!(registry.config_sha256(), config.source_sha256());
    assert_eq!(
        registry.execution_plan_digest(),
        config.execution_plan_digest()
    );
    assert_eq!(registry.execution_plan_digest().len(), 64);
    assert_eq!(registry.legacy_digest_v1().len(), 64);
    assert_eq!(registry.digest().len(), 64);
    assert_ne!(registry.digest(), registry.legacy_digest_v1());
    let binding = registry.bindings().next().expect("registry binding");
    assert_eq!(binding.server_name, "fixture");
    assert_eq!(binding.raw_tool_name, "echo.v1");
    assert!(binding.provider_name.starts_with("mcp_fixture_echo_v1_"));
    assert_eq!(binding.definition.name, binding.provider_name);
    assert!(binding.output_schema.is_some());
    let provider_name = binding.provider_name.clone();

    let result = registry
        .call_tool(
            &provider_name,
            json!({"text":"registry"}),
            &CancellationToken::new(),
        )
        .await
        .expect("call namespaced MCP tool");
    assert_eq!(result["structuredContent"]["text"], "registry");
    registry.shutdown().await;

    let collision = McpRegistry::connect(&config, [provider_name], &CancellationToken::new()).await;
    assert!(matches!(collision, Err(error) if error.to_string().contains("tool name collision")));

    let original_sha = config.source_sha256().to_owned();
    fs::write(&config_path, project_config(&python, &script, &log, true))
        .expect("rewrite MCP project config");
    let changed = McpProjectConfig::load(&root, &config_path).expect("reload changed config");
    assert_ne!(changed.source_sha256(), original_sha);
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
        reply(message, {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"text": text},
            "isError": False,
        })
    else:
        reply(message, error={"code": -32601, "message": "Method not found"})
"#;
