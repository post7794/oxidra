//! Bounded MCP stdio transport and tool discovery.
//!
//! The low-level session kernel, project/registry trust capabilities and the
//! durable execution-coordinator core live here. Agent/CLI exposure and the
//! canonical MCP journal reader remain separate policy layers.

mod config;
mod coordinator;
mod journal;
mod registry;
mod schema;

pub use config::{
    ApprovedMcpProjectConfig, MCP_EXECUTION_PLAN_VERSION, MCP_PROJECT_CONFIG_VERSION,
    MCP_PROJECT_CONFIG_VERSION_V1, McpProjectConfig,
};
pub use coordinator::{
    DenyMcpCallApproval, MCP_ARGUMENT_DIGEST_VERSION, MCP_DISPATCH_PERMIT_VERSION,
    MCP_EXECUTION_COORDINATOR_VERSION, McpCallApprovalHandler, McpCallApprovalRequest,
    McpCallIdentity, McpExecutionCoordinator,
};
pub use journal::MCP_CALL_CHAIN_VALIDATOR_VERSION;
pub(crate) use journal::{
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1, argument_digest_v1, mcp_turn_ids_v1,
    validate_mcp_call_chain_for_version, validate_mcp_call_chain_v1,
};
pub use registry::{ApprovedMcpRegistry, MCP_TOOL_REGISTRY_VERSION, McpRegistry, McpToolBinding};
pub use schema::MCP_SCHEMA_PROFILE_VERSION;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{OxidraError, Result};
use crate::process::ProcessTree;
use crate::types::ToolDefinition;
use crate::untrusted_display;

pub const MCP_MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const MCP_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const MCP_STDIO_KERNEL_VERSION: u32 = 1;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const CANCEL_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_JSON_LINE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_ARGUMENT_BYTES: usize = 256 * 1024;
const MAX_TOOL_RESULT_BYTES: usize = 50 * 1024;
const MAX_TOOL_SURFACE_BYTES: usize = 512 * 1024;
const MAX_TOOL_PAGES: usize = 64;
const MAX_TOOLS: usize = 512;
const MAX_STDERR_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_SERVER_INFO_FIELD_BYTES: usize = 256;

/// Render a raw MCP tool result for a terminal, approval UI or model-facing
/// diagnostic without mutating the protocol value retained by the caller.
pub fn tool_result_for_display(result: &Value) -> String {
    untrusted_display::json_for_display(result)
}

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

    pub fn prepare(&self) -> Result<PreparedMcpStdioConfig> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(OxidraError::Config(format!(
                "invalid MCP server name {}; use 1-64 ASCII letters, digits, '_' or '-'",
                untrusted_display::quoted_single_line(&self.name)
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
                    "invalid MCP environment variable name {}",
                    untrusted_display::quoted_single_line(name)
                )));
            }
            // Windows environment names are case-insensitive. Reject aliases on
            // every platform so one checked-in config cannot change meaning
            // across hosts.
            if !environment_names.insert(name.to_ascii_uppercase()) {
                return Err(OxidraError::Config(format!(
                    "MCP environment variable {} is configured more than once",
                    untrusted_display::quoted_single_line(name)
                )));
            }
        }
        let inherited_env = self
            .inherit_env
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value)))
            .collect();
        Ok(PreparedMcpStdioConfig {
            name: self.name.clone(),
            command,
            args: self.args.clone(),
            cwd,
            inherit_env: self.inherit_env.clone(),
            inherited_env,
            env: self.env.clone(),
        })
    }
}

/// Immutable execution plan produced before any MCP server code is started.
///
/// The command and working directory are canonical paths, and inherited
/// environment values are captured at preparation time. Trust presentation,
/// execution-plan hashing and process spawning all consume this same value.
/// The public v1 digest authorizes paths, arguments and environment
/// capabilities; it deliberately does not claim executable/script content
/// identity and does not hash inherited secret values.
#[derive(Clone)]
pub struct PreparedMcpStdioConfig {
    name: String,
    command: PathBuf,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    inherit_env: Vec<String>,
    inherited_env: BTreeMap<String, OsString>,
    env: BTreeMap<String, String>,
}

impl fmt::Debug for PreparedMcpStdioConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMcpStdioConfig")
            .field("name", &self.name)
            .field("command", &self.command)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("inherit_env", &self.inherit_env)
            .field("explicit_env_names", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PreparedMcpStdioConfig {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn command(&self) -> &Path {
        &self.command
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    pub fn inherit_env(&self) -> &[String] {
        &self.inherit_env
    }

    pub fn explicit_env_names(&self) -> impl Iterator<Item = &str> {
        self.env.keys().map(String::as_str)
    }

    pub(super) fn explicit_env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
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
    validation_input_schema: Value,
    validation_output_schema: Option<Value>,
}

pub struct McpStdioSession {
    attempt_id: String,
    config: PreparedMcpStdioConfig,
    transport: Option<Transport>,
    stderr_capture: Arc<Mutex<StderrCapture>>,
    era: McpProtocolEra,
    server_info: Option<McpServerInfo>,
    tools: Vec<McpTool>,
}

/// Owns an untrusted JSON value across async cancellation boundaries without
/// allowing the compiler-generated future to recursively drop a deep tree.
/// The preflight result is computed before the future is constructed, while
/// the value remains protected by this wrapper's iterative `Drop`.
pub(super) struct PreflightedJsonValue {
    value: Option<Value>,
    preflight: Option<std::result::Result<(), schema::ValidationError>>,
}

pub(super) struct ValidatedMcpArguments {
    value: Option<Value>,
}

impl PreflightedJsonValue {
    fn new(value: Value) -> Self {
        let mut owned = Self {
            value: Some(value),
            preflight: None,
        };
        let preflight = schema::preflight_instance(owned.value.as_ref().expect("owned value"));
        owned.preflight = Some(preflight);
        owned
    }

    fn into_validated(mut self) -> std::result::Result<ValidatedMcpArguments, McpCallError> {
        if let Err(error) = self.preflight.take().expect("preflight result") {
            return Err(McpCallError {
                code: "validation_error",
                message: format!(
                    "MCP tool arguments do not satisfy the bounded instance profile: {}",
                    untrusted_display::text_for_display(&error.to_string())
                ),
                in_doubt: false,
                interrupted: false,
            });
        }
        if let Err(error) = ensure_json_within_limit(
            self.value.as_ref().expect("owned value"),
            MAX_TOOL_ARGUMENT_BYTES,
        ) {
            return Err(McpCallError {
                code: "validation_error",
                message: format!(
                    "MCP tool arguments exceed the bounded input profile: {}",
                    untrusted_display::text_for_display(&error)
                ),
                in_doubt: false,
                interrupted: false,
            });
        }
        Ok(ValidatedMcpArguments {
            value: self.value.take(),
        })
    }
}

impl Drop for PreflightedJsonValue {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop_json_value_iteratively(value);
        }
    }
}

impl ValidatedMcpArguments {
    pub(super) fn as_value(&self) -> &Value {
        self.value.as_ref().expect("validated MCP arguments")
    }

    fn into_value(mut self) -> Value {
        self.value.take().expect("validated MCP arguments")
    }
}

impl Drop for ValidatedMcpArguments {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            drop_json_value_iteratively(value);
        }
    }
}

impl McpStdioSession {
    /// Connect to an MCP executable that the caller already trusts with the
    /// authority of the current OS user.
    ///
    /// This low-level API does not perform project execution-plan approval.
    /// Applications should normally use [`McpProjectConfig::approve_execution`]
    /// followed by [`McpRegistry::connect`].
    pub async fn connect_trusted(
        config: McpStdioConfig,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        Self::connect_prepared(config.prepare()?, cancellation).await
    }

    pub(super) async fn connect_prepared(
        config: PreparedMcpStdioConfig,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        if cancellation.is_cancelled() {
            return Err(OxidraError::Interrupted);
        }
        let stderr_capture = Arc::new(Mutex::new(StderrCapture::default()));
        if cancellation.is_cancelled() {
            return Err(OxidraError::Interrupted);
        }
        let mut transport = timeout(
            START_TIMEOUT,
            Transport::spawn(&config, Arc::clone(&stderr_capture)),
        )
        .await
        .map_err(|_| OxidraError::Mcp(format!("MCP server {} start timed out", config.name)))??;

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
                return Err(OxidraError::Mcp(untrusted_display::text_for_display(
                    &format!(
                        "MCP server {} does not support protocol {MCP_MODERN_PROTOCOL_VERSION}: {}",
                        config.name,
                        untrusted_display::json_for_display(&error)
                    ),
                )));
            }
            Err(ClientError::Rpc(_))
            | Err(ClientError::Timeout { .. })
            | Err(ClientError::Exited { .. })
            | Err(ClientError::Io { .. }) => {
                transport.terminate().await;
                if cancellation.is_cancelled() {
                    return Err(OxidraError::Interrupted);
                }
                let mut legacy = timeout(
                    START_TIMEOUT,
                    Transport::spawn(&config, Arc::clone(&stderr_capture)),
                )
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
        Ok(Self {
            attempt_id: Uuid::now_v7().to_string(),
            config,
            transport: Some(transport),
            stderr_capture,
            era,
            server_info,
            tools,
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

    pub(super) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Return bounded, source-prefixed stderr diagnostics with terminal and
    /// Unicode presentation controls removed. MCP stderr is never connected
    /// directly to the interactive terminal.
    pub fn stderr_snapshot(&self) -> String {
        sanitized_stderr_snapshot(&self.config.name, &self.stderr_capture)
    }

    pub fn call_tool<'a>(
        &'a mut self,
        name: &'a str,
        arguments: Value,
        cancellation: &'a CancellationToken,
    ) -> impl std::future::Future<Output = std::result::Result<Value, McpCallError>> + 'a {
        let prepared = PreflightedJsonValue::new(arguments)
            .into_validated()
            .and_then(|arguments| self.prepare_tool_call(name, arguments));
        async move {
            match prepared {
                Ok(arguments) => {
                    self.dispatch_prepared_tool(name, arguments, cancellation)
                        .await
                }
                Err(error) => Err(error),
            }
        }
    }

    pub(super) fn prepare_tool_call(
        &self,
        name: &str,
        arguments: ValidatedMcpArguments,
    ) -> std::result::Result<ValidatedMcpArguments, McpCallError> {
        let Some(tool) = self.tools.iter().find(|tool| tool.definition.name == name) else {
            return Err(McpCallError {
                code: "not_found",
                message: format!(
                    "MCP server {} has no tool {}",
                    self.config.name,
                    untrusted_display::quoted_single_line(name)
                ),
                in_doubt: false,
                interrupted: false,
            });
        };
        if let Err(error) =
            schema::validate_instance(&tool.validation_input_schema, arguments.as_value())
        {
            return Err(McpCallError {
                code: "validation_error",
                message: format!(
                    "MCP tool arguments do not satisfy inputSchema: {}",
                    untrusted_display::text_for_display(&error.to_string())
                ),
                in_doubt: false,
                interrupted: false,
            });
        }
        Ok(arguments)
    }

    pub(super) async fn dispatch_prepared_tool(
        &mut self,
        name: &str,
        arguments: ValidatedMcpArguments,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Value, McpCallError> {
        let Some(tool) = self.tools.iter().find(|tool| tool.definition.name == name) else {
            return Err(McpCallError {
                code: "not_found",
                message: format!(
                    "MCP server {} has no tool {}",
                    self.config.name,
                    untrusted_display::quoted_single_line(name)
                ),
                in_doubt: false,
                interrupted: false,
            });
        };
        let output_schema = tool.validation_output_schema.clone();
        let arguments = arguments.into_value();
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
            validate_tool_call_result(&self.config.name, &result, output_schema.as_ref())
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
            "MCP server {server} returned invalid tool name {}",
            untrusted_display::quoted_single_line(name)
        )));
    }
    let description = match object.get("description") {
        Some(value) => {
            let description = value.as_str().ok_or_else(|| {
                OxidraError::Mcp(format!(
                    "MCP server {server} tool {name:?} description is not a string"
                ))
            })?;
            untrusted_display::sanitize_text(description)
        }
        None => String::new(),
    };
    let input_schema = object.get("inputSchema").cloned().ok_or_else(|| {
        OxidraError::Mcp(format!(
            "MCP server {server} tool {name:?} has no inputSchema"
        ))
    })?;
    schema::validate_tool_schema(&input_schema, "inputSchema").map_err(|error| {
        OxidraError::Mcp(format!(
            "MCP server {server} tool {name:?} has invalid inputSchema: {}",
            untrusted_display::text_for_display(&error)
        ))
    })?;
    let output_schema = object
        .get("outputSchema")
        .map(|schema| {
            schema::validate_tool_schema(schema, "outputSchema").map_err(|error| {
                OxidraError::Mcp(format!(
                    "MCP server {server} tool {name:?} has invalid outputSchema: {}",
                    untrusted_display::text_for_display(&error)
                ))
            })?;
            Ok::<Value, OxidraError>(schema.clone())
        })
        .transpose()?;
    Ok(McpTool {
        definition: ToolDefinition {
            name: name.to_owned(),
            description,
            input_schema: schema::schema_for_display(&input_schema),
        },
        output_schema: output_schema.as_ref().map(schema::schema_for_display),
        validation_input_schema: input_schema,
        validation_output_schema: output_schema,
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
    output_schema: Option<&Value>,
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
    if let Some(output_schema) = output_schema {
        let structured_content = result.get("structuredContent").ok_or_else(|| {
            OxidraError::Mcp(format!(
                "MCP server {server} tools/call result has no structuredContent required by outputSchema"
            ))
        })?;
        schema::validate_instance(output_schema, structured_content).map_err(|error| {
            OxidraError::Mcp(format!(
                "MCP server {server} tools/call structuredContent does not satisfy outputSchema: {}",
                untrusted_display::text_for_display(&error.to_string())
            ))
        })?;
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
    if name.is_empty()
        || version.is_empty()
        || name.len() > MAX_SERVER_INFO_FIELD_BYTES
        || version.len() > MAX_SERVER_INFO_FIELD_BYTES
    {
        return Err(OxidraError::Mcp(format!(
            "MCP server {server} serverInfo name/version must contain 1-{MAX_SERVER_INFO_FIELD_BYTES} bytes"
        )));
    }
    Ok(McpServerInfo {
        name: untrusted_display::sanitize_single_line(name),
        version: untrusted_display::sanitize_single_line(version),
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
    stderr_task: Option<JoinHandle<()>>,
    next_id: u64,
}

impl Transport {
    async fn spawn(
        config: &PreparedMcpStdioConfig,
        stderr_capture: Arc<Mutex<StderrCapture>>,
    ) -> Result<Self> {
        let mut command = Command::new(&config.command);
        command
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        if let Some(cwd) = &config.cwd {
            command.current_dir(cwd);
        }
        command.envs(&config.inherited_env);
        command.envs(&config.env);
        ProcessTree::configure_suspended(&mut command).map_err(|error| {
            OxidraError::Mcp(format!(
                "MCP server {} cannot be started safely on this platform: {error}",
                config.name
            ))
        })?;
        let mut child = command.spawn().map_err(|error| {
            OxidraError::Mcp(format!(
                "failed to start MCP server {} at {}: {error}",
                config.name,
                config.command.display()
            ))
        })?;
        let mut process_tree = match ProcessTree::attach_contained(&child) {
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
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(OxidraError::Mcp(format!(
                    "MCP server {} has no stdin",
                    config.name
                )));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(OxidraError::Mcp(format!(
                    "MCP server {} has no stdout",
                    config.name
                )));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(OxidraError::Mcp(format!(
                    "MCP server {} has no stderr",
                    config.name
                )));
            }
        };
        let stderr_task = tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_capture)));
        if let Err(error) = process_tree.resume_suspended() {
            process_tree.terminate(&mut child).await;
            stderr_task.abort();
            let _ = stderr_task.await;
            return Err(OxidraError::Mcp(format!(
                "failed to resume MCP server {} after process-tree ownership: {error}",
                config.name
            )));
        }
        Ok(Self {
            child,
            process_tree,
            stdin,
            stdout: BufReader::new(stdout),
            stderr_task: Some(stderr_task),
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
                    message: format!(
                        "MCP response id {} does not match request {id}",
                        untrusted_display::json_for_display(response_id)
                    ),
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
        self.finish_stderr().await;
    }

    async fn terminate(&mut self) {
        self.process_tree.terminate(&mut self.child).await;
        self.finish_stderr().await;
    }

    async fn finish_stderr(&mut self) {
        let Some(mut task) = self.stderr_task.take() else {
            return;
        };
        if timeout(SHUTDOWN_GRACE, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Default)]
struct StderrCapture {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl StderrCapture {
    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= MAX_STDERR_CAPTURE_BYTES {
            self.bytes.clear();
            self.bytes.extend(
                bytes[bytes.len() - MAX_STDERR_CAPTURE_BYTES..]
                    .iter()
                    .copied(),
            );
            self.truncated = true;
            return;
        }
        let overflow = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(MAX_STDERR_CAPTURE_BYTES);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.truncated = true;
        }
        self.bytes.extend(bytes.iter().copied());
    }
}

async fn drain_stderr(mut stderr: ChildStderr, capture: Arc<Mutex<StderrCapture>>) {
    let mut buffer = [0u8; 4096];
    loop {
        let count = match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        if let Ok(mut capture) = capture.lock() {
            capture.push(&buffer[..count]);
        }
    }
}

fn sanitized_stderr_snapshot(server: &str, capture: &Arc<Mutex<StderrCapture>>) -> String {
    let Ok(capture) = capture.lock() else {
        return format!("[mcp:{server} stderr] <capture unavailable>");
    };
    if capture.bytes.is_empty() && !capture.truncated {
        return String::new();
    }
    let bytes = capture.bytes.iter().copied().collect::<Vec<_>>();
    let truncated = capture.truncated;
    drop(capture);

    let prefix = format!("[mcp:{server} stderr] ");
    let mut body = String::with_capacity(bytes.len());
    body.push_str(&prefix);
    let sanitized = untrusted_display::sanitize_text(&String::from_utf8_lossy(&bytes));
    for character in sanitized.chars() {
        match character {
            '\n' => {
                body.push('\n');
                body.push_str(&prefix);
            }
            character => body.push(character),
        }
    }
    body.truncate(body.trim_end_matches(prefix.as_str()).len());

    let needs_truncation = truncated || body.len() > MAX_STDERR_CAPTURE_BYTES;
    if !needs_truncation {
        return body;
    }
    let marker = format!("{prefix}<truncated>\n");
    let budget = MAX_STDERR_CAPTURE_BYTES.saturating_sub(marker.len());
    let tail = prefixed_stderr_tail(&body, &prefix, budget);
    format!("{marker}{tail}")
}

fn prefixed_stderr_tail<'a>(
    body: &'a str,
    prefix: &str,
    budget: usize,
) -> std::borrow::Cow<'a, str> {
    if body.len() <= budget {
        return std::borrow::Cow::Borrowed(body);
    }
    let mut target = body.len().saturating_sub(budget);
    while target < body.len() && !body.is_char_boundary(target) {
        target += 1;
    }
    if let Some(newline) = body[target..].find('\n') {
        let start = target + newline + 1;
        if start < body.len() && body.len().saturating_sub(start) <= budget {
            return std::borrow::Cow::Borrowed(&body[start..]);
        }
    }
    let content_budget = budget.saturating_sub(prefix.len());
    let mut start = body.len().saturating_sub(content_budget);
    while start < body.len() && !body.is_char_boundary(start) {
        start += 1;
    }
    std::borrow::Cow::Owned(format!("{prefix}{}", &body[start..]))
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

pub(super) fn drop_json_value_iteratively(value: Value) {
    let mut pending = vec![JsonDropFrame::Value(value)];
    while let Some(frame) = pending.pop() {
        match frame {
            JsonDropFrame::Value(value) => match value {
                Value::Array(values) => pending.push(JsonDropFrame::Array(values.into_iter())),
                Value::Object(values) => pending.push(JsonDropFrame::Object(values.into_iter())),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            },
            JsonDropFrame::Array(mut values) => {
                if let Some(value) = values.next() {
                    pending.push(JsonDropFrame::Array(values));
                    pending.push(JsonDropFrame::Value(value));
                }
            }
            JsonDropFrame::Object(mut values) => {
                if let Some((_, value)) = values.next() {
                    pending.push(JsonDropFrame::Object(values));
                    pending.push(JsonDropFrame::Value(value));
                }
            }
        }
    }
}

enum JsonDropFrame {
    Value(Value),
    Array(std::vec::IntoIter<Value>),
    Object(serde_json::map::IntoIter),
}

fn ensure_json_within_limit(
    value: &Value,
    maximum_bytes: usize,
) -> std::result::Result<(), String> {
    let mut writer = BoundedJsonWriter::new(maximum_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => Err(format!("JSON value exceeds {maximum_bytes} bytes")),
        Err(error) => Err(format!("cannot serialize JSON value: {error}")),
    }
}

struct BoundedJsonWriter {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(maximum: usize) -> Self {
        Self {
            written: 0,
            maximum,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(buffer.len()) > self.maximum {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded JSON writer limit exceeded"));
        }
        self.written += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
        let message = match self {
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
                format!(
                    "MCP server {server} returned JSON-RPC error during {operation}: {}",
                    untrusted_display::json_for_display(error)
                )
            }
        };
        untrusted_display::text_for_display(&message)
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
                .prepare()
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
                .prepare()
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
                .prepare()
                .unwrap_err()
                .to_string()
                .contains("configured more than once")
        );

        let mut secret = McpStdioConfig::new(
            "fixture",
            std::env::current_exe().expect("resolve test executable"),
        );
        secret
            .env
            .insert("TOKEN".to_owned(), "must-not-appear-in-debug".to_owned());
        let prepared = secret.prepare().expect("prepare secret-bearing config");
        let debug = format!("{prepared:?}");
        assert!(debug.contains("TOKEN"));
        assert!(!debug.contains("must-not-appear-in-debug"));
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
        let output_schema = json!({
            "type":"object",
            "properties":{"value":{"type":"string"}},
            "required":["value"],
            "additionalProperties":false
        });
        assert!(
            validate_tool_call_result(
                "fixture",
                &json!({"content":[],"structuredContent":"free-form"}),
                None,
            )
            .is_ok()
        );
        assert!(
            validate_tool_call_result("fixture", &json!({"content":[]}), Some(&output_schema))
                .is_err()
        );
        assert!(
            validate_tool_call_result(
                "fixture",
                &json!({"content":[],"structuredContent":{"value":"ok"}}),
                Some(&output_schema),
            )
            .is_ok()
        );
        assert!(
            validate_tool_call_result(
                "fixture",
                &json!({"content":[],"structuredContent":{"value":42}}),
                Some(&output_schema),
            )
            .is_err()
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
    fn untrusted_metadata_and_results_have_a_safe_display_projection() {
        let tool = parse_tool(
            "fixture",
            &json!({
                "name":"safe_name",
                "description":"visible\u{202e}hidden\u{200b}",
                "inputSchema":{"type":"object"}
            }),
        )
        .expect("parse display fixture");
        assert_eq!(tool.definition.description, "visible�hidden�");

        let raw = json!({"text":"visible\u{202e}hidden\u{200b}\u{2028}line"});
        let rendered = tool_result_for_display(&raw);
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{200b}'));
        assert!(!rendered.contains('\u{2028}'));
        assert_eq!(raw["text"], "visible\u{202e}hidden\u{200b}\u{2028}line");
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
