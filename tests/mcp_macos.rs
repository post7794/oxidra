#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use oxidra::mcp::{McpStdioConfig, McpStdioSession};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn macos_mcp_fails_closed_before_uncontained_code_executes() {
    let directory = tempfile::tempdir().expect("create macOS MCP fixture");
    let server = directory.path().join("server.sh");
    let marker = directory.path().join("started.txt");
    fs::write(&server, "#!/bin/sh\nprintf started > \"$1\"\n").expect("write macOS MCP fixture");
    let mut permissions = fs::metadata(&server)
        .expect("inspect macOS MCP fixture")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&server, permissions).expect("make macOS MCP fixture executable");

    let mut config = McpStdioConfig::new("fixture", server);
    config.args.push(marker.to_string_lossy().into_owned());
    let result = McpStdioSession::connect_trusted(config, CancellationToken::new()).await;
    let error = match result {
        Ok(mut session) => {
            session.shutdown().await;
            panic!("macOS MCP must fail closed until descendant containment exists");
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("descendant containment"));
    assert!(!marker.exists(), "uncontained MCP code executed on macOS");
}
