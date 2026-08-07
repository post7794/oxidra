//! Bounded MCP stdio transport and tool discovery.
//!
//! This module deliberately stops at the session kernel. Agent exposure,
//! project trust and per-tool approval remain separate policy layers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use crate::error::{OxidraError, Result};
use crate::process::ProcessTree;
use crate::types::ToolDefinition;

pub const MCP_MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const MCP_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const MCP_STDIO_KERNEL_VERSION: u32 = 1;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const CANCEL_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_JSON_LINE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_RESULT_BYTES: usize = 50 * 1024;
const MAX_TOOL_SURFACE_BYTES: usize = 512 * 1024;
const MAX_TOOL_PAGES: usize = 64;
const MAX_TOOLS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpProtocolEra {
    Modern,
    Legacy,
}

#[derive(Clone, Debug)]
pub struct McpStdioConfig {
    pub name: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub inherit_env: Vec<String>,
    pub env: BTreeMap<String, String>,
}

impl McpStdioConfig {
    pub fn new(name: impl Into<String>, command: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            inherit_env: Vec::new(),
            env: BTreeMap::new(),
        }
    }

    fn validate(&self) -> Result<ValidatedConfig> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(OxidraError::Config(format!(
                "invalid MCP server name {:?}; use 1-64 ASCII letters, digits, '_' or '-'",
                self.name
            )));
        }
        if !self.command.is_absolute() {
            return Err(OxidraError::Config(format!(
                "MCP server {} command must be an absolute path",
                self.name
            )));
        }
        let command = std::fs::canonicalize(&self.command).map_err(|error| {
            OxidraError::Config(format!(
                "cannot resolve MCP server {} command {}: {error}",
                self.name,
                self.command.display()
            ))
        })?;
        if !command.is_file() {
            return Err(OxidraError::Config(format!(
                "MCP server {} command is not a file: {}",
                self.name,
                command.display()
            )));
        }
        let cwd = self.cwd.as_deref().map(canonical_directory).transpose()?;
        let mut environment_names = BTreeSet::new();
        for name in self
            .inherit_env
            .iter()
            .map(String::as_str)
            .chain(self.env.keys().map(String::as_str))
        {
            if !valid_environment_name(name) {
                return Err(OxidraError::Config(format!(
                    "invalid MCP environment variable name {name:?}"
                )));
            }
            // Windows environment names are case-insensitive. Reject aliases on
            // every platform so one checked-in config cannot change meaning
            // across hosts.
            if !environment_names.insert(name.to_ascii_uppercase()) {
                return Err(OxidraError::Config(format!(
                    "MCP environment variable {name:?} is configured more than once"
                )));
            }
        }
        Ok(ValidatedConfig {
            name: self.name.clone(),
            command,
            args: self.args.clone(),
            cwd,
            inherit_env: self.inherit_env.clone(),
            env: self.env.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct ValidatedConfig {
    name: String,
    command: PathBuf,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    inherit_env: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpCallError {
    pub code: &'static str,
    pub message: String,
    pub in_doubt: bool,
    pub interrupted: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct McpTool {
    pub definition: ToolDefinition,
    pub output_schema: Option<Value>,
}

pub struct McpStdioSession {
    config: ValidatedConfig,
    transport: Option<Transport>,
    era: McpProtocolEra,
    server_info: Option<McpServerInfo>,
    tools: Vec<McpTool>,
    tool_names: BTreeSet<String>,
}

impl McpStdioSession {
    pub async fn connect(config: McpStdioConfig, cancellation: CancellationToken) -> Result<Self> {
        let config = config.validate()?;
        let mut transport = timeout(START_TIMEOUT, Transport::spawn(&config))
            .await
            .map_err(|_| {
                OxidraError::Mcp(format!("MCP server {} start timed out", config.name))
            })??;

        let discovery = transport
            .request(
                "server/discover",
                modern_params(Map::new()),
                DISCOVERY_TIMEOUT,
                &cancellation,
            )
            .await;
        let (mut transport, era, server_info) = match discovery {
            Ok(result) => (
                transport,
                McpProtocolEra::Modern,
                validate_modern_discovery(&config.name, &result)?,
            ),
            Err(ClientError::Rpc(error)) if unsupported_protocol_error(&error) => {
                transport.terminate().await;
                return Err(OxidraError::Mcp(format!(
                    "MCP server {} does not support protocol {MCP_MODERN_PROTOCOL_VERSION}: {error}",
                    config.name
                )));
            }
            Err(ClientError::Rpc(_))
            | Err(ClientError::Timeout { .. })
            | Err(ClientError::Exited { .. })
            | Err(ClientError::Io { .. }) => {
                transport.terminate().await;
                let mut legacy = timeout(START_TIMEOUT, Transport::spawn(&config))
                    .await
                    .map_err(|_| {
                        OxidraError::Mcp(format!(
                            "legacy MCP server {} restart timed out",
                            config.name
                        ))
                    })??;
                let initialized = legacy
                    .request(
                        "initialize",
                        Some(json!({
                            "protocolVersion": MCP_LEGACY_PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": client_info(),
                        })),
                        START_TIMEOUT,
                        &cancellation,
                    )
                    .await
                    .map_err(|error| error.into_oxidra(&config.name, "initialize legacy MCP"))?;
                let server_info = Some(validate_legacy_initialize(&config.name, &initialized)?);
                timeout(
                    START_TIMEOUT,
                    legacy.notify("notifications/initialized", None),
                )
                .await
                .map_err(|_| {
                    OxidraError::Mcp(format!(
                        "legacy MCP server {} initialization notification timed out",
                        config.name
                    ))
                })?
                .map_err(|error| {
                    error.into_oxidra(&config.name, "notify legacy MCP initialization")
                })?;
                (legacy, McpProtocolEra::Legacy, server_info)
            }
            Err(error) => {
                transport.terminate().await;
                return Err(error.into_oxidra(&config.name, "discover MCP server"));
            }
        };

        let tools = load_tools(&config.name, &mut transport, era, &cancellation).await?;
        let tool_names = tools
            .iter()
            .map(|tool| tool.definition.name.clone())
            .collect();
        Ok(Self {
            config,
            transport: Some(transport),
            era,
            server_info,
            tools,
            tool_names,
        })
    }

    pub fn era(&self) -> McpProtocolEra {
        self.era
    }

    pub fn server_info(&self) -> Option<&McpServerInfo> {
        self.server_info.as_ref()
    }

    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Value, McpCallError> {
        if !self.tool_names.contains(name) {
            return Err(McpCallError {
                code: "not_found",
                message: format!("MCP server {} has no tool {name:?}", self.config.name),
                in_doubt: false,
                interrupted: false,
            });
        }
        if !arguments.is_object() {
            return Err(McpCallError {
                code: "validation_error",
                message: "MCP tool arguments must be a JSON object".to_owned(),
                in_doubt: false,
                interrupted: false,
            });
        }
        let expects_structured_content = self
            .tools
            .iter()
            .find(|tool| tool.definition.name == name)
            .is_some_and(|tool| tool.output_schema.is_some());
        let params = match self.era {
            McpProtocolEra::Modern => modern_params(Map::from_iter([
                ("name".to_owned(), Value::String(name.to_owned())),
                ("arguments".to_owned(), arguments),
            ])),
            McpProtocolEra::Legacy => Some(json!({
                "name": name,
                "arguments": arguments,
            })),
        };
        let Some(transport) = self.transport.as_mut() else {
            return Err(McpCallError {
                code: "transport_closed",
                message: format!("MCP server {} session is closed", self.config.name),
                in_doubt: false,
                interrupted: false,
            });
        };
        let result = transport
            .request("tools/call", params, CALL_TIMEOUT, cancellation)
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                let call_error = error.into_call_error(&self.config.name);
                if call_error.in_doubt || call_error.interrupted {
                    if let Some(mut transport) = self.transport.take() {
                        transport.terminate().await;
                    }
                }
                return Err(call_error);
            }
        };
        if self.era == McpProtocolEra::Modern
            && result.get("resultType").and_then(Value::as_str) != Some("complete")
        {
            if let Some(mut transport) = self.transport.take() {
                transport.terminate().await;
            }
            return Err(McpCallError {
                code: "unsupported_interaction",
                message: format!(
                    "MCP server {} returned a nonterminal tools/call result",
                    self.config.name
                ),
                in_doubt: true,
                interrupted: false,
            });
        }
        if let Err(error) =
            validate_tool_call_result(&self.config.name, &result, expects_structured_content)
        {
            if let Some(mut transport) = self.transport.take() {
                transport.terminate().await;
            }
            return Err(McpCallError {
                code: "protocol_error",
                message: error.to_string(),
                in_doubt: true,
                interrupted: false,
            });
        }
        let encoded = serde_json::to_vec(&result).map_err(|error| McpCallError {
            code: "protocol_error",
            message: format!("cannot serialize MCP tool result: {error}"),
            in_doubt: false,
            interrupted: false,
        })?;
        if encoded.len() > MAX_TOOL_RESULT_BYTES {
            return Err(McpCallError {
                code: "output_limit",
                message: format!(
                    "MCP server {} tool result exceeds {MAX_TOOL_RESULT_BYTES} bytes",
                    self.config.name
                ),
                in_doubt: false,
                interrupted: false,
            });
        }
        Ok(result)
    }

    pub async fn shutdown(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.shutdown().await;
        }
    }
}

async fn load_tools(
    server: &str,
    transport: &mut Transport,
    era: McpProtocolEra,
    cancellation: &CancellationToken,
) -> Result<Vec<McpTool>> {
    let mut tools = Vec::new();
    let mut tool_surface_bytes = 0usize;
    let mut cursor = None::<String>;
    for _ in 0..MAX_TOOL_PAGES {
        let mut params = Map::new();
        if let Some(cursor) = &cursor {
            params.insert("cursor".to_owned(), Value::String(cursor.clone()));
        }
        let params = match era {
            McpProtocolEra::Modern => modern_params(params),
            McpProtocolEra::Legacy => Some(Value::Object(params)),
        };
        let result = transport
            .request("tools/list", params, START_TIMEOUT, cancellation)
            .await
            .map_err(|error| error.into_oxidra(server, "list MCP tools"))?;
        if era == McpProtocolEra::Modern {
            validate_cacheable_complete_result(server, "tools/list", &result)?;
        }
        let page = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OxidraError::Mcp(format!("MCP server {server} tools/list has no tools array"))
            })?;
        for value in page {
            tool_surface_bytes = tool_surface_bytes
                .checked_add(serde_json::to_vec(value)?.len())
                .ok_or_else(|| {
                    OxidraError::Mcp(format!("MCP server {server} tool surface size overflowed"))
                })?;
            if tool_surface_bytes > MAX_TOOL_SURFACE_BYTES {
                return Err(OxidraError::Mcp(format!(
                    "MCP server {server} tool surface exceeds {MAX_TOOL_SURFACE_BYTES} bytes"
                )));
            }
            tools.push(parse_tool(server, value)?);
            if tools.len() > MAX_TOOLS {
                return Err(OxidraError::Mcp(format!(
                    "MCP server {server} exposes more than {MAX_TOOLS} tools"
                )));
            }
        }
        cursor = result
            .get("nextCursor")
            .map(|value| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    OxidraError::Mcp(format!(
                        "MCP server {server} tools/list nextCursor is not a string"
                    ))
                })
            })
            .transpose()?;
        if cursor.is_none() {
            break;
        }
    }
    if cursor.is_some() {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} tools/list exceeds {MAX_TOOL_PAGES} pages"
        )));
    }
    let mut names = BTreeSet::new();
    for tool in &tools {
        if !names.insert(tool.definition.name.as_str()) {
            return Err(OxidraError::Mcp(format!(
                "MCP server {server} exposes duplicate tool {:?}",
                tool.definition.name
            )));
        }
    }
    Ok(tools)
}

fn parse_tool(server: &str, value: &Value) -> Result<McpTool> {
    let object = value.as_object().ok_or_else(|| {
        OxidraError::Mcp(format!("MCP server {server} returned a non-object tool"))
    })?;
    let name = object.get("name").and_then(Value::as_str).ok_or_else(|| {
        OxidraError::Mcp(format!(
            "MCP server {server} returned a tool without a name"
        ))
    })?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} returned invalid tool name {name:?}"
        )));
    }
    let description = match object.get("description") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| {
                OxidraError::Mcp(format!(
                    "MCP server {server} tool {name:?} description is not a string"
                ))
            })?
            .to_owned(),
        None => String::new(),
    };
    let input_schema = object.get("inputSchema").cloned().ok_or_else(|| {
        OxidraError::Mcp(format!(
            "MCP server {server} tool {name:?} has no inputSchema"
        ))
    })?;
    if !input_schema.is_object()
        || input_schema.get("type").and_then(Value::as_str) != Some("object")
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} tool {name:?} inputSchema must declare object type"
        )));
    }
    let output_schema = object
        .get("outputSchema")
        .map(|schema| {
            if !schema.is_object() || schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(OxidraError::Mcp(format!(
                    "MCP server {server} tool {name:?} outputSchema must declare object type"
                )));
            }
            Ok(schema.clone())
        })
        .transpose()?;
    Ok(McpTool {
        definition: ToolDefinition {
            name: name.to_owned(),
            description,
            input_schema,
        },
        output_schema,
    })
}

fn validate_modern_discovery(server: &str, result: &Value) -> Result<Option<McpServerInfo>> {
    validate_cacheable_complete_result(server, "server/discover", result)?;
    let versions = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OxidraError::Mcp(format!(
                "MCP server {server} discovery has no supportedVersions"
            ))
        })?;
    if versions.is_empty() || versions.iter().any(|version| !version.is_string()) {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} discovery has invalid supportedVersions"
        )));
    }
    if !versions
        .iter()
        .any(|version| version.as_str() == Some(MCP_MODERN_PROTOCOL_VERSION))
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} does not advertise {MCP_MODERN_PROTOCOL_VERSION}"
        )));
    }
    ensure_tools_capability(server, result)?;
    parse_modern_server_info(server, result)
}

fn validate_legacy_initialize(server: &str, result: &Value) -> Result<McpServerInfo> {
    if result.get("protocolVersion").and_then(Value::as_str) != Some(MCP_LEGACY_PROTOCOL_VERSION) {
        return Err(OxidraError::Mcp(format!(
            "legacy MCP server {server} did not negotiate {MCP_LEGACY_PROTOCOL_VERSION}"
        )));
    }
    ensure_tools_capability(server, result)?;
    parse_server_info(server, result.get("serverInfo"))
}

fn ensure_tools_capability(server: &str, result: &Value) -> Result<()> {
    let tools = result
        .get("capabilities")
        .and_then(|value| value.get("tools"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OxidraError::Mcp(format!(
                "MCP server {server} does not advertise tools capability"
            ))
        })?;
    match tools.get("listChanged") {
        Some(Value::Bool(true)) => {
            return Err(OxidraError::Mcp(format!(
                "MCP server {server} requires dynamic tools/list_changed, which is unsupported"
            )));
        }
        Some(Value::Bool(false)) | None => {}
        Some(_) => {
            return Err(OxidraError::Mcp(format!(
                "MCP server {server} has invalid tools listChanged capability"
            )));
        }
    }
    Ok(())
}

fn validate_cacheable_complete_result(server: &str, method: &str, result: &Value) -> Result<()> {
    if result.get("resultType").and_then(Value::as_str) != Some("complete") {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} returned a nonterminal {method} result"
        )));
    }
    if result.get("ttlMs").and_then(Value::as_u64).is_none() {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} {method} result has no valid ttlMs"
        )));
    }
    if !matches!(
        result.get("cacheScope").and_then(Value::as_str),
        Some("public" | "private")
    ) {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} {method} result has no valid cacheScope"
        )));
    }
    Ok(())
}

fn validate_tool_call_result(
    server: &str,
    result: &Value,
    expects_structured_content: bool,
) -> Result<()> {
    if !result.get("content").is_some_and(Value::is_array) {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} tools/call result has no content array"
        )));
    }
    if result
        .get("isError")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} tools/call result has invalid isError"
        )));
    }
    if expects_structured_content
        && !result
            .get("structuredContent")
            .is_some_and(Value::is_object)
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} tools/call result does not satisfy its declared outputSchema"
        )));
    }
    Ok(())
}

fn parse_modern_server_info(server: &str, result: &Value) -> Result<Option<McpServerInfo>> {
    let Some(metadata) = result.get("_meta") else {
        return Ok(None);
    };
    let metadata = metadata.as_object().ok_or_else(|| {
        OxidraError::Mcp(format!(
            "MCP server {server} discovery _meta is not an object"
        ))
    })?;
    let Some(info) = metadata.get("io.modelcontextprotocol/serverInfo") else {
        return Ok(None);
    };
    parse_server_info(server, Some(info)).map(Some)
}

fn parse_server_info(server: &str, value: Option<&Value>) -> Result<McpServerInfo> {
    let info = value
        .and_then(Value::as_object)
        .ok_or_else(|| OxidraError::Mcp(format!("MCP server {server} has no serverInfo")))?;
    let name = info
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| OxidraError::Mcp(format!("MCP server {server} serverInfo has no name")))?;
    let version = info.get("version").and_then(Value::as_str).ok_or_else(|| {
        OxidraError::Mcp(format!("MCP server {server} serverInfo has no version"))
    })?;
    if name.is_empty() || version.is_empty() {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} serverInfo has an empty name or version"
        )));
    }
    Ok(McpServerInfo {
        name: name.to_owned(),
        version: version.to_owned(),
    })
}

fn unsupported_protocol_error(error: &Value) -> bool {
    // Compatibility is keyed to a recognized modern error shape rather than
    // one numeric code; the modern transport contract explicitly allows
    // protocol-aware errors to evolve.
    error.get("code").is_some_and(Value::is_i64)
        && error.get("message").is_some_and(Value::is_string)
        && error
            .get("data")
            .and_then(|data| data.get("requested"))
            .and_then(Value::as_str)
            == Some(MCP_MODERN_PROTOCOL_VERSION)
        && error
            .get("data")
            .and_then(|data| data.get("supported"))
            .and_then(Value::as_array)
            .is_some_and(|versions| {
                !versions.is_empty() && versions.iter().all(|version| version.as_str().is_some())
            })
}

fn client_info() -> Value {
    json!({
        "name": "oxidra",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn modern_params(mut params: Map<String, Value>) -> Option<Value> {
    params.insert(
        "_meta".to_owned(),
        json!({
            "io.modelcontextprotocol/protocolVersion": MCP_MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": client_info(),
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
    );
    Some(Value::Object(params))
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path).map_err(|error| {
        OxidraError::Config(format!(
            "cannot resolve MCP working directory {}: {error}",
            path.display()
        ))
    })?;
    if !path.is_dir() {
        return Err(OxidraError::Config(format!(
            "MCP working directory is not a directory: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

struct Transport {
    child: Child,
    process_tree: ProcessTree,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Transport {
    async fn spawn(config: &ValidatedConfig) -> Result<Self> {
        let mut command = Command::new(&config.command);
        command
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear();
        if let Some(cwd) = &config.cwd {
            command.current_dir(cwd);
        }
        for name in &config.inherit_env {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.envs(&config.env);
        ProcessTree::configure(&mut command);
        let mut child = command.spawn().map_err(|error| {
            OxidraError::Mcp(format!(
                "failed to start MCP server {} at {}: {error}",
                config.name,
                config.command.display()
            ))
        })?;
        let process_tree = match ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(OxidraError::Mcp(format!(
                    "failed to own MCP server {} process tree: {error}",
                    config.name
                )));
            }
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| OxidraError::Mcp(format!("MCP server {} has no stdin", config.name)))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| OxidraError::Mcp(format!("MCP server {} has no stdout", config.name)))?;
        Ok(Self {
            child,
            process_tree,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    async fn request(
        &mut self,
        method: &str,
        params: Option<Value>,
        duration: Duration,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Value, ClientError> {
        if self
            .child
            .try_wait()
            .map_err(|error| ClientError::Io {
                error,
                after_send: false,
            })?
            .is_some()
        {
            return Err(ClientError::Exited { after_send: false });
        }
        if cancellation.is_cancelled() {
            return Err(ClientError::Cancelled { after_send: false });
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut request = Map::from_iter([
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("id".to_owned(), Value::from(id)),
            ("method".to_owned(), Value::String(method.to_owned())),
        ]);
        if let Some(params) = params {
            request.insert("params".to_owned(), params);
        }
        let request = Value::Object(request);
        let deadline = Instant::now() + duration;
        tokio::select! {
            _ = cancellation.cancelled() => return Err(ClientError::Cancelled { after_send: true }),
            result = timeout(duration, write_json_line(&mut self.stdin, &request)) => {
                match result {
                    Ok(result) => result?,
                    Err(_) => return Err(ClientError::Timeout { after_send: true }),
                }
            }
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cancel_request(id, "timeout").await;
                return Err(ClientError::Timeout { after_send: true });
            }
            let line = tokio::select! {
                _ = cancellation.cancelled() => {
                    self.cancel_request(id, "cancelled").await;
                    return Err(ClientError::Cancelled { after_send: true });
                }
                result = timeout(remaining, read_bounded_line(&mut self.stdout)) => {
                    match result {
                        Ok(Ok(Some(line))) => line,
                        Ok(Ok(None)) => return Err(ClientError::Exited { after_send: true }),
                        Ok(Err(error)) => return Err(ClientError::Io { error, after_send: true }),
                        Err(_) => {
                            self.cancel_request(id, "timeout").await;
                            return Err(ClientError::Timeout { after_send: true });
                        }
                    }
                }
            };
            let message: Value =
                serde_json::from_slice(trim_ascii_end(&line)).map_err(|error| {
                    ClientError::Protocol {
                        message: format!("non-JSON data on MCP stdout: {error}"),
                        after_send: true,
                    }
                })?;
            if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err(ClientError::Protocol {
                    message: "MCP stdout message is not JSON-RPC 2.0".to_owned(),
                    after_send: true,
                });
            }
            let Some(response_id) = message.get("id") else {
                if message.get("method").and_then(Value::as_str)
                    == Some("notifications/tools/list_changed")
                {
                    return Err(ClientError::Protocol {
                        message: "MCP server changed its tool surface during a frozen session"
                            .to_owned(),
                        after_send: true,
                    });
                }
                continue;
            };
            if response_id != &Value::from(id) {
                return Err(ClientError::Protocol {
                    message: format!("MCP response id {response_id} does not match request {id}"),
                    after_send: true,
                });
            }
            if let Some(error) = message.get("error") {
                return Err(ClientError::Rpc(error.clone()));
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| ClientError::Protocol {
                    message: "MCP response has neither result nor error".to_owned(),
                    after_send: true,
                });
        }
    }

    async fn notify(
        &mut self,
        method: &str,
        params: Option<Value>,
    ) -> std::result::Result<(), ClientError> {
        let mut notification = Map::from_iter([
            ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
            ("method".to_owned(), Value::String(method.to_owned())),
        ]);
        if let Some(params) = params {
            notification.insert("params".to_owned(), params);
        }
        write_json_line(&mut self.stdin, &Value::Object(notification)).await
    }

    async fn cancel_request(&mut self, id: u64, reason: &str) {
        let _ = timeout(
            CANCEL_WRITE_TIMEOUT,
            self.notify(
                "notifications/cancelled",
                Some(json!({ "requestId": id, "reason": reason })),
            ),
        )
        .await;
    }

    async fn shutdown(&mut self) {
        let _ = timeout(SHUTDOWN_GRACE, self.stdin.shutdown()).await;
        if timeout(SHUTDOWN_GRACE, self.child.wait()).await.is_err() {
            self.process_tree.terminate(&mut self.child).await;
        } else {
            self.process_tree.terminate_descendants();
        }
    }

    async fn terminate(&mut self) {
        self.process_tree.terminate(&mut self.child).await;
    }
}

async fn read_bounded_line(
    reader: &mut BufReader<ChildStdout>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_JSON_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MCP JSON-RPC line exceeds {MAX_JSON_LINE_BYTES} bytes"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn trim_ascii_end(mut line: &[u8]) -> &[u8] {
    while line.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        line = &line[..line.len() - 1];
    }
    line
}

async fn write_json_line(
    stdin: &mut ChildStdin,
    value: &Value,
) -> std::result::Result<(), ClientError> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| ClientError::Protocol {
        message: format!("failed to serialize MCP JSON-RPC message: {error}"),
        after_send: false,
    })?;
    if bytes.len().saturating_add(1) > MAX_JSON_LINE_BYTES {
        return Err(ClientError::Protocol {
            message: format!("MCP JSON-RPC message exceeds {MAX_JSON_LINE_BYTES} bytes"),
            after_send: false,
        });
    }
    bytes.push(b'\n');
    stdin
        .write_all(&bytes)
        .await
        .map_err(|error| ClientError::Io {
            error,
            after_send: true,
        })?;
    stdin.flush().await.map_err(|error| ClientError::Io {
        error,
        after_send: true,
    })
}

#[derive(Debug)]
enum ClientError {
    Cancelled {
        after_send: bool,
    },
    Timeout {
        after_send: bool,
    },
    Exited {
        after_send: bool,
    },
    Io {
        error: std::io::Error,
        after_send: bool,
    },
    Protocol {
        message: String,
        after_send: bool,
    },
    Rpc(Value),
}

impl ClientError {
    fn after_send(&self) -> bool {
        match self {
            Self::Cancelled { after_send }
            | Self::Timeout { after_send }
            | Self::Exited { after_send }
            | Self::Io { after_send, .. }
            | Self::Protocol { after_send, .. } => *after_send,
            Self::Rpc(_) => true,
        }
    }

    fn message(&self, server: &str, operation: &str) -> String {
        match self {
            Self::Cancelled { .. } => format!("{operation} for MCP server {server} was cancelled"),
            Self::Timeout { .. } => format!("{operation} for MCP server {server} timed out"),
            Self::Exited { .. } => format!("MCP server {server} exited during {operation}"),
            Self::Io { error, .. } => {
                format!("MCP server {server} transport failed during {operation}: {error}")
            }
            Self::Protocol { message, .. } => {
                format!("MCP server {server} protocol violation during {operation}: {message}")
            }
            Self::Rpc(error) => {
                format!("MCP server {server} returned JSON-RPC error during {operation}: {error}")
            }
        }
    }

    fn into_oxidra(self, server: &str, operation: &str) -> OxidraError {
        if matches!(self, Self::Cancelled { .. }) {
            OxidraError::Interrupted
        } else {
            OxidraError::Mcp(self.message(server, operation))
        }
    }

    fn into_call_error(self, server: &str) -> McpCallError {
        let interrupted = matches!(self, Self::Cancelled { .. });
        // A JSON-RPC error proves that the server handled the request, not that
        // the tool's external side effects were rolled back. Only a validated
        // complete tools/call result can close the uncertainty window.
        let in_doubt = self.after_send();
        let code = match self {
            Self::Cancelled { .. } => "cancelled",
            Self::Timeout { .. } => "timeout",
            Self::Exited { .. } => "transport_closed",
            Self::Io { .. } => "transport_error",
            Self::Protocol { .. } => "protocol_error",
            Self::Rpc(_) => "server_error",
        };
        McpCallError {
            code,
            message: self.message(server, "call MCP tool"),
            in_doubt,
            interrupted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdio_config_requires_absolute_executable_and_explicit_environment() {
        let relative = McpStdioConfig::new("fixture", "python");
        assert!(
            relative
                .validate()
                .unwrap_err()
                .to_string()
                .contains("absolute path")
        );

        let mut duplicate = McpStdioConfig::new(
            "fixture",
            std::env::current_exe().expect("resolve test executable"),
        );
        duplicate.inherit_env.push("PATH".to_owned());
        duplicate
            .env
            .insert("PATH".to_owned(), "ignored".to_owned());
        assert!(
            duplicate
                .validate()
                .unwrap_err()
                .to_string()
                .contains("configured more than once")
        );

        let mut cross_platform_alias = McpStdioConfig::new(
            "fixture",
            std::env::current_exe().expect("resolve test executable"),
        );
        cross_platform_alias.inherit_env.push("Path".to_owned());
        cross_platform_alias
            .env
            .insert("PATH".to_owned(), "ignored".to_owned());
        assert!(
            cross_platform_alias
                .validate()
                .unwrap_err()
                .to_string()
                .contains("configured more than once")
        );
    }

    #[test]
    fn tool_names_use_the_registered_ascii_surface() {
        assert!(
            parse_tool(
                "fixture",
                &json!({"name":"admin.tools-list_2","inputSchema":{"type":"object"}}),
            )
            .is_ok()
        );
        assert!(
            parse_tool(
                "fixture",
                &json!({"name":"bad/tool","inputSchema":{"type":"object"}}),
            )
            .is_err()
        );
        assert!(
            parse_tool(
                "fixture",
                &json!({"name":"missing_root_type","inputSchema":{"properties":{}}}),
            )
            .is_err()
        );
        let typed = parse_tool(
            "fixture",
            &json!({
                "name":"typed",
                "inputSchema":{"type":"object"},
                "outputSchema":{"type":"object","properties":{"value":{"type":"string"}}}
            }),
        )
        .expect("parse tool with an output schema");
        assert!(typed.output_schema.is_some());
    }

    #[test]
    fn structured_content_is_required_only_for_declared_output_schema() {
        assert!(
            validate_tool_call_result(
                "fixture",
                &json!({"content":[],"structuredContent":"free-form"}),
                false,
            )
            .is_ok()
        );
        assert!(validate_tool_call_result("fixture", &json!({"content":[]}), true).is_err());
        assert!(
            validate_tool_call_result(
                "fixture",
                &json!({"content":[],"structuredContent":{"value":"ok"}}),
                true,
            )
            .is_ok()
        );
        assert!(
            parse_tool(
                "fixture",
                &json!({"name":"工具","inputSchema":{"type":"object"}}),
            )
            .is_err()
        );
        assert!(
            parse_tool(
                "fixture",
                &json!({
                    "name":"bad_description",
                    "description":42,
                    "inputSchema":{"type":"object"}
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn dynamic_tool_surfaces_are_rejected_until_they_have_an_epoch_protocol() {
        assert!(
            ensure_tools_capability(
                "fixture",
                &json!({"capabilities":{"tools":{"listChanged":false}}}),
            )
            .is_ok()
        );
        assert!(
            ensure_tools_capability(
                "fixture",
                &json!({"capabilities":{"tools":{"listChanged":true}}}),
            )
            .unwrap_err()
            .to_string()
            .contains("dynamic tools/list_changed")
        );
    }

    #[test]
    fn only_registered_modern_unsupported_version_error_blocks_fallback() {
        assert!(unsupported_protocol_error(&json!({
            "code":-32022,
            "message":"Unsupported protocol version",
            "data":{
                "requested":MCP_MODERN_PROTOCOL_VERSION,
                "supported":["2027-01-01"]
            }
        })));
        assert!(unsupported_protocol_error(&json!({
            "code":-32099,
            "message":"A future modern version error",
            "data":{
                "requested":MCP_MODERN_PROTOCOL_VERSION,
                "supported":["2027-01-01"]
            }
        })));
        assert!(!unsupported_protocol_error(&json!({"code":-32022})));
        assert!(!unsupported_protocol_error(&json!({"code":-32601})));
    }
}
