use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use oxidra::mcp::{
    MCP_LEGACY_PROTOCOL_VERSION, MCP_MODERN_PROTOCOL_VERSION, MCP_STDIO_KERNEL_VERSION,
    McpProtocolEra, McpStdioConfig, McpStdioSession,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn modern_stdio_discovers_lists_calls_and_reuses_one_process() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP fixture directory");
    let script = directory.path().join("mcp_fixture.py");
    let log = directory.path().join("modern.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let mut session = McpStdioSession::connect(
        fixture_config(&python, &script, &log, "modern"),
        CancellationToken::new(),
    )
    .await
    .expect("connect modern MCP fixture");
    assert_eq!(session.era(), McpProtocolEra::Modern);
    assert_eq!(
        session.server_info().map(|info| info.name.as_str()),
        Some("fixture-modern")
    );
    assert_eq!(
        session
            .tools()
            .iter()
            .map(|tool| tool.definition.name.as_str())
            .collect::<Vec<_>>(),
        ["echo", "sleep", "rpc_error"]
    );

    for text in ["first", "second"] {
        let result = session
            .call_tool("echo", json!({"text": text}), &CancellationToken::new())
            .await
            .expect("call modern MCP tool");
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["content"][0]["text"], text);
    }
    session.shutdown().await;

    let log = read_log(&log);
    assert_eq!(process_count(&log), 1, "modern MCP must reuse one process");
    assert_eq!(
        methods(&log),
        ["server/discover", "tools/list", "tools/call", "tools/call"]
    );
}

#[tokio::test]
async fn legacy_stdio_fallback_restarts_then_initializes() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP fixture directory");
    let script = directory.path().join("mcp_fixture.py");
    let log = directory.path().join("legacy.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let mut session = McpStdioSession::connect(
        fixture_config(&python, &script, &log, "legacy"),
        CancellationToken::new(),
    )
    .await
    .expect("connect legacy MCP fixture");
    assert_eq!(session.era(), McpProtocolEra::Legacy);
    assert_eq!(
        session.server_info().map(|info| info.name.as_str()),
        Some("fixture-legacy")
    );
    let result = session
        .call_tool("echo", json!({"text": "legacy"}), &CancellationToken::new())
        .await
        .expect("call legacy MCP tool");
    assert!(result.get("resultType").is_none());
    assert_eq!(result["content"][0]["text"], "legacy");
    session.shutdown().await;

    let log = read_log(&log);
    assert_eq!(
        process_count(&log),
        2,
        "legacy fallback must restart cleanly"
    );
    assert_eq!(
        methods(&log),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
        ]
    );
}

#[tokio::test]
async fn cancelled_mcp_call_is_reported_in_doubt_and_closes_transport() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP fixture directory");
    let script = directory.path().join("mcp_fixture.py");
    let log = directory.path().join("cancel.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let mut session = McpStdioSession::connect(
        fixture_config(&python, &script, &log, "modern"),
        CancellationToken::new(),
    )
    .await
    .expect("connect modern MCP fixture");
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    let error = session
        .call_tool("sleep", json!({"seconds": 5}), &cancellation)
        .await
        .expect_err("cancelled MCP call must fail");
    assert_eq!(error.code, "cancelled");
    assert!(error.in_doubt);
    assert!(error.interrupted);

    let closed = session
        .call_tool(
            "echo",
            json!({"text": "after-cancel"}),
            &CancellationToken::new(),
        )
        .await
        .expect_err("cancelled transport must stay closed");
    assert_eq!(closed.code, "transport_closed");
    assert!(!closed.in_doubt);
}

#[tokio::test]
async fn rpc_error_after_tool_dispatch_is_in_doubt_and_closes_transport() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP fixture directory");
    let script = directory.path().join("mcp_fixture.py");
    let log = directory.path().join("rpc-error.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let mut session = McpStdioSession::connect(
        fixture_config(&python, &script, &log, "modern"),
        CancellationToken::new(),
    )
    .await
    .expect("connect modern MCP fixture");
    let error = session
        .call_tool("rpc_error", json!({}), &CancellationToken::new())
        .await
        .expect_err("post-dispatch JSON-RPC error must fail");
    assert_eq!(error.code, "server_error");
    assert!(error.in_doubt);
    assert!(!error.interrupted);

    let closed = session
        .call_tool(
            "echo",
            json!({"text": "after-rpc-error"}),
            &CancellationToken::new(),
        )
        .await
        .expect_err("in-doubt transport must stay closed");
    assert_eq!(closed.code, "transport_closed");
}

#[tokio::test]
async fn recognized_modern_unsupported_version_does_not_downgrade() {
    let Some(python) = find_python() else {
        eprintln!("skipping MCP stdio integration test: Python is unavailable");
        return;
    };
    let directory = tempfile::tempdir().expect("create MCP fixture directory");
    let script = directory.path().join("mcp_fixture.py");
    let log = directory.path().join("unsupported.log");
    fs::write(&script, PYTHON_FIXTURE).expect("write MCP fixture");

    let error = match McpStdioSession::connect(
        fixture_config(&python, &script, &log, "unsupported"),
        CancellationToken::new(),
    )
    .await
    {
        Ok(mut session) => {
            session.shutdown().await;
            panic!("recognized modern version rejection must fail closed");
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("does not support protocol"));

    let log = read_log(&log);
    assert_eq!(process_count(&log), 1, "must not start a legacy process");
    assert_eq!(methods(&log), ["server/discover"]);
}

fn fixture_config(python: &Path, script: &Path, log: &Path, mode: &str) -> McpStdioConfig {
    let mut config = McpStdioConfig::new("fixture", python);
    config.args = vec![
        script.to_string_lossy().into_owned(),
        log.to_string_lossy().into_owned(),
        mode.to_owned(),
    ];
    config.cwd = script.parent().map(Path::to_path_buf);
    for name in ["SYSTEMROOT", "WINDIR", "HOME", "TMP", "TEMP"] {
        if std::env::var_os(name).is_some() {
            config.inherit_env.push(name.to_owned());
        }
    }
    config
}

fn find_python() -> Option<std::path::PathBuf> {
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

fn read_log(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read MCP fixture log")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn process_count(log: &[String]) -> usize {
    log.iter()
        .filter(|line| line.starts_with("process:"))
        .count()
}

fn methods(log: &[String]) -> Vec<&str> {
    log.iter()
        .filter(|line| !line.starts_with("process:"))
        .map(String::as_str)
        .collect()
}

const PYTHON_FIXTURE: &str = r#"
import json
import os
import sys
import time

log_path = sys.argv[1]
mode = sys.argv[2]

with open(log_path, "a", encoding="utf-8") as log:
    log.write(f"process:{os.getpid()}\n")
    log.flush()

tools = [
    {
        "name": "echo",
        "description": "Echo text",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sleep",
        "description": "Sleep for a bounded test duration",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "number"}},
            "required": ["seconds"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rpc_error",
        "description": "Return a JSON-RPC error after dispatch",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]

def write_response(message, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": message["id"]}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    print(json.dumps(response), flush=True)

def require_modern_meta(message):
    meta = message.get("params", {}).get("_meta", {})
    return (
        meta.get("io.modelcontextprotocol/protocolVersion") == "2026-07-28"
        and meta.get("io.modelcontextprotocol/clientInfo", {}).get("name") == "oxidra"
        and isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict)
    )

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method", "")
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(method + "\n")
        log.flush()
    if "id" not in message:
        continue

    if method == "server/discover":
        if mode == "unsupported":
            write_response(message, error={
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {
                    "requested": "2026-07-28",
                    "supported": ["2027-01-01"],
                },
            })
        elif mode == "legacy":
            write_response(message, error={"code": -32601, "message": "Method not found"})
        elif not require_modern_meta(message):
            write_response(message, error={"code": -32602, "message": "missing modern metadata"})
        else:
            write_response(message, result={
                "resultType": "complete",
                "ttlMs": 1000,
                "cacheScope": "private",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {"listChanged": False}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "fixture-modern",
                        "version": "1",
                    }
                },
            })
    elif method == "initialize":
        if message.get("params", {}).get("protocolVersion") != "2025-11-25":
            write_response(message, error={"code": -32602, "message": "wrong legacy version"})
        else:
            write_response(message, result={
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "fixture-legacy", "version": "1"},
            })
    elif method == "tools/list":
        if mode == "modern" and not require_modern_meta(message):
            write_response(message, error={"code": -32602, "message": "missing modern metadata"})
        else:
            result = {"tools": tools}
            if mode == "modern":
                result["resultType"] = "complete"
                result["ttlMs"] = 1000
                result["cacheScope"] = "private"
            write_response(message, result=result)
    elif method == "tools/call":
        if mode == "modern" and not require_modern_meta(message):
            write_response(message, error={"code": -32602, "message": "missing modern metadata"})
            continue
        params = message.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name == "rpc_error":
            write_response(message, error={"code": -32000, "message": "fixture failure"})
            continue
        if name == "sleep":
            time.sleep(float(arguments.get("seconds", 0)))
            text = "slept"
        else:
            text = arguments.get("text", "")
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        if mode == "modern":
            result["resultType"] = "complete"
        write_response(message, result=result)
    else:
        write_response(message, result={})
"#;

#[test]
fn protocol_constants_are_frozen() {
    assert_eq!(MCP_STDIO_KERNEL_VERSION, 1);
    assert_eq!(MCP_MODERN_PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(MCP_LEGACY_PROTOCOL_VERSION, "2025-11-25");
}
