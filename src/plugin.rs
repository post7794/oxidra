use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use crate::config::ProjectContext;
use crate::error::{OxidraError, Result};
use crate::process::ProcessTree;
use crate::trust::{TrustStore, execution_hash};
use crate::types::{ToolCall, ToolDefinition, ToolResult};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub const PLUGIN_START_TIMEOUT: Duration = Duration::from_secs(10);
pub const PLUGIN_CALL_TIMEOUT: Duration = Duration::from_secs(120);

const MAX_PROCESS_STARTS_PER_SESSION: usize = 4;
const MAX_MCP_LINE_BYTES: usize = 1024 * 1024;
const MAX_PLUGIN_RESULT_BYTES: usize = 50 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginActivation {
    #[default]
    #[serde(alias = "on-call", alias = "lazy")]
    OnCall,
    Eager,
}

impl PluginActivation {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "on_call" | "on-call" | "lazy" => Ok(Self::OnCall),
            "eager" => Ok(Self::Eager),
            other => Err(OxidraError::Config(format!(
                "invalid plugin activation {other:?}; expected on_call or eager"
            ))),
        }
    }
}

/// Environment access declared by the executable manifest.
///
/// A manifest may use the concise form `"env": ["NAME"]`, or the expanded
/// form `"env": { "inherit": ["NAME"], "set": { "MODE": "mcp" } }`.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PluginEnvironment {
    pub inherit: Vec<String>,
    pub set: BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for PluginEnvironment {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Null => Ok(Self::default()),
            Value::Array(items) => {
                let inherit = items
                    .into_iter()
                    .map(|item| {
                        item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            serde::de::Error::custom("env array entries must be strings")
                        })
                    })
                    .collect::<std::result::Result<Vec<_>, D::Error>>()?;
                Ok(Self {
                    inherit,
                    set: BTreeMap::new(),
                })
            }
            Value::Object(mut object) => {
                let inherit_value = object
                    .remove("inherit")
                    .or_else(|| object.remove("allow"))
                    .unwrap_or_else(|| Value::Array(Vec::new()));
                let inherit = serde_json::from_value::<Vec<String>>(inherit_value)
                    .map_err(serde::de::Error::custom)?;

                let set_value = object.remove("set").or_else(|| object.remove("values"));
                let mut set = match set_value {
                    Some(value) => serde_json::from_value::<BTreeMap<String, String>>(value)
                        .map_err(serde::de::Error::custom)?,
                    None => BTreeMap::new(),
                };

                // A flat object is also accepted as a set of literal values.
                for (name, value) in object {
                    let value = value.as_str().ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "environment value for {name:?} must be a string"
                        ))
                    })?;
                    set.insert(name, value.to_owned());
                }

                Ok(Self { inherit, set })
            }
            _ => Err(serde::de::Error::custom(
                "env must be a string array or an object",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PluginConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub activation: PluginActivation,
    /// Optional path used by project config loaders. `PluginSupervisor::load`
    /// accepts a path directly, so callers need not populate this field.
    #[serde(default, alias = "path")]
    pub manifest: Option<PathBuf>,
    /// Values supplied by project config. Every key must be declared by the
    /// manifest's environment allowlist.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            activation: PluginActivation::OnCall,
            manifest: None,
            env: BTreeMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub name: String,
    #[serde(alias = "protocol_version")]
    pub protocol_version: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default, alias = "environment")]
    pub env: PluginEnvironment,
    #[serde(default, deserialize_with = "deserialize_manifest_tools")]
    pub tools: Vec<ToolDefinition>,
    #[serde(
        default,
        alias = "schema_hash",
        alias = "toolsSchemaHash",
        alias = "tools_schema_hash",
        alias = "toolsSchemaSha256",
        alias = "tools_schema_sha256"
    )]
    pub schema_hash: String,
    #[serde(default, alias = "dynamic_tools")]
    pub dynamic_tools: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestTool {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(alias = "parameters", alias = "input_schema")]
    input_schema: Value,
}

fn deserialize_manifest_tools<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ToolDefinition>, D::Error>
where
    D: Deserializer<'de>,
{
    let tools = Vec::<ManifestTool>::deserialize(deserializer)?;
    Ok(tools
        .into_iter()
        .map(|tool| ToolDefinition {
            name: tool.name,
            description: tool.description,
            input_schema: tool.input_schema,
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginState {
    Dormant,
    Starting,
    Ready,
    Failed {
        reason: String,
        recoverable: bool,
        in_doubt: bool,
    },
}

#[derive(Debug)]
struct FailureState {
    reason: String,
    recoverable: bool,
    in_doubt: bool,
}

enum RuntimeState {
    Dormant,
    Starting,
    Ready(Arc<Mutex<McpClient>>),
    Failed(FailureState),
}

/// A lazy, session-scoped supervisor for one MCP stdio plugin.
pub struct PluginSupervisor {
    manifest: PluginManifest,
    config: PluginConfig,
    manifest_dir: PathBuf,
    resolved_executable: Option<PathBuf>,
    expected_schema_hash: String,
    trust_project: Option<ProjectContext>,
    trusted_execution_hash: Option<String>,
    runtime_tools: std::sync::RwLock<Vec<ToolDefinition>>,
    state: Mutex<RuntimeState>,
    operation: Mutex<()>,
    starts: AtomicUsize,
}

impl PluginSupervisor {
    /// Load a manifest referenced by project configuration. Relative paths
    /// are resolved from `project_root`; `name` is checked against the signed
    /// manifest name so a config typo cannot silently retarget a plugin.
    pub fn from_manifest(
        name: impl AsRef<str>,
        manifest_path: impl AsRef<Path>,
        project_root: impl AsRef<Path>,
        activation: PluginActivation,
    ) -> Result<Self> {
        let path = manifest_path.as_ref();
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            project_root.as_ref().join(path)
        };
        let config = PluginConfig {
            activation,
            ..PluginConfig::default()
        };
        let mut supervisor = Self::load(path, config)?;
        if supervisor.manifest.name != name.as_ref() {
            return Err(OxidraError::Config(format!(
                "project plugin name {:?} does not match manifest name {:?}",
                name.as_ref(),
                supervisor.manifest.name
            )));
        }
        let executable =
            resolve_executable_path(&supervisor.manifest.command, &supervisor.manifest_dir)
                .map_err(|error| {
                    OxidraError::Config(format!(
                        "cannot resolve executable for plugin {}: {error}",
                        supervisor.manifest.name
                    ))
                })?;
        supervisor.resolved_executable = Some(executable);
        Ok(supervisor)
    }

    pub fn load(path: impl AsRef<Path>, config: PluginConfig) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(|error| {
            OxidraError::Plugin(format!(
                "failed to read manifest {}: {error}",
                path.display()
            ))
        })?;
        let manifest: PluginManifest = serde_json::from_str(&contents).map_err(|error| {
            OxidraError::Plugin(format!("invalid manifest {}: {error}", path.display()))
        })?;
        let directory = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self::new(manifest, directory, config)
    }

    pub fn new(
        manifest: PluginManifest,
        manifest_dir: impl Into<PathBuf>,
        config: PluginConfig,
    ) -> Result<Self> {
        let expected_schema_hash = validate_manifest(&manifest)?;
        validate_config(&manifest, &config)?;
        let runtime_tools = manifest.tools.clone();
        Ok(Self {
            manifest,
            config,
            manifest_dir: manifest_dir.into(),
            resolved_executable: None,
            expected_schema_hash,
            trust_project: None,
            trusted_execution_hash: None,
            runtime_tools: std::sync::RwLock::new(runtime_tools),
            state: Mutex::new(RuntimeState::Dormant),
            operation: Mutex::new(()),
            starts: AtomicUsize::new(0),
        })
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn config(&self) -> &PluginConfig {
        &self.config
    }

    /// Bind this supervisor to the exact project snapshot approved by the
    /// CLI. The snapshot is re-hashed before every process spawn, including a
    /// lazy first call, so files changed during a session cannot bypass trust.
    pub fn bind_trust(&mut self, project: ProjectContext, execution_hash: String) {
        self.trust_project = Some(project);
        self.trusted_execution_hash = Some(execution_hash);
    }

    pub fn namespaced_name(&self, local_name: &str) -> String {
        format!("{}.{}", self.manifest.name, local_name)
    }

    /// Static definitions are available without spawning the plugin.
    pub fn static_tools(&self) -> Vec<ToolDefinition> {
        if !self.config.enabled {
            return Vec::new();
        }
        self.runtime_tools
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|tool| ToolDefinition {
                name: self.namespaced_name(&tool.name),
                description: tool.description.clone(),
                input_schema: tool.input_schema.clone(),
            })
            .collect()
    }

    pub async fn state(&self) -> PluginState {
        match &*self.state.lock().await {
            RuntimeState::Dormant => PluginState::Dormant,
            RuntimeState::Starting => PluginState::Starting,
            RuntimeState::Ready(_) => PluginState::Ready,
            RuntimeState::Failed(failure) => PluginState::Failed {
                reason: failure.reason.clone(),
                recoverable: failure.recoverable,
                in_doubt: failure.in_doubt,
            },
        }
    }

    pub async fn activate_if_eager(&self, cancellation: CancellationToken) -> Result<()> {
        if self.config.enabled && self.config.activation == PluginActivation::Eager {
            self.activate(cancellation).await
        } else {
            Ok(())
        }
    }

    pub async fn activate(&self, cancellation: CancellationToken) -> Result<()> {
        let _operation = self.operation.lock().await;
        self.activate_locked(&cancellation).await.map(|_| ())
    }

    pub async fn ping(&self, cancellation: CancellationToken) -> Result<()> {
        let _operation = self.operation.lock().await;
        let client = self.activate_locked(&cancellation).await?;
        let response = client
            .lock()
            .await
            .request("ping", Some(json!({})), PLUGIN_CALL_TIMEOUT, &cancellation)
            .await;
        match response {
            Ok(_) => Ok(()),
            Err(error) => {
                self.record_runtime_error(&error, false).await;
                Err(error.into_oxidra(&self.manifest.name))
            }
        }
    }

    /// Invoke a plugin tool and preserve the MCP result object verbatim.
    pub async fn call(
        &self,
        namespaced_tool_name: &str,
        arguments: Value,
        cancellation: &CancellationToken,
    ) -> Result<Value> {
        let _operation = self.operation.lock().await;
        let local_name = self.local_tool_name(namespaced_tool_name)?;
        let client = self.activate_locked(cancellation).await?;
        let response = client
            .lock()
            .await
            .request(
                "tools/call",
                Some(json!({ "name": local_name, "arguments": arguments })),
                PLUGIN_CALL_TIMEOUT,
                cancellation,
            )
            .await;
        match response {
            Ok(value) => Ok(value),
            Err(error) => {
                self.record_runtime_error(&error, true).await;
                Err(error.into_call_oxidra(&self.manifest.name, true))
            }
        }
    }

    /// Tool-registry friendly wrapper that turns operational errors into a
    /// structured result rather than aborting the whole agent turn.
    pub async fn call_tool(&self, call: ToolCall, cancellation: CancellationToken) -> ToolResult {
        let call_id = call.id;
        match self.call(&call.name, call.arguments, &cancellation).await {
            Ok(output) => {
                if serde_json::to_vec(&output)
                    .is_ok_and(|bytes| bytes.len() > MAX_PLUGIN_RESULT_BYTES)
                {
                    return ToolResult::error(
                        call_id,
                        "output_limit",
                        format!("plugin result exceeds the {MAX_PLUGIN_RESULT_BYTES}-byte limit"),
                    );
                }
                let is_error = output
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if is_error {
                    ToolResult {
                        call_id,
                        output,
                        is_error: true,
                        error_code: Some("plugin_error".to_owned()),
                    }
                } else {
                    ToolResult::success(call_id, output)
                }
            }
            Err(error) => {
                let code = match &error {
                    OxidraError::Interrupted => "cancelled",
                    OxidraError::Tool { code, .. } => code.as_str(),
                    OxidraError::Plugin(message) if message.contains("in_doubt") => "in_doubt",
                    OxidraError::Plugin(_) => "plugin_error",
                    _ => "plugin_error",
                };
                ToolResult::error(call_id, code, error.to_string())
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _operation = self.operation.lock().await;
        let old_state = {
            let mut state = self.state.lock().await;
            std::mem::replace(&mut *state, RuntimeState::Dormant)
        };
        if let RuntimeState::Ready(client) = old_state {
            client.lock().await.terminate().await?;
        }
        Ok(())
    }

    async fn activate_locked(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Arc<Mutex<McpClient>>> {
        if !self.config.enabled {
            return Err(OxidraError::Plugin(format!(
                "plugin {} is disabled",
                self.manifest.name
            )));
        }

        if let Err(error) = self.verify_trust_snapshot() {
            let reason = error.message(&self.manifest.name);
            self.set_failed(reason, false, false).await;
            return Err(error.into_oxidra(&self.manifest.name));
        }

        let current = {
            let state = self.state.lock().await;
            match &*state {
                RuntimeState::Ready(client) => Some(Ok(client.clone())),
                RuntimeState::Failed(failure) if !failure.recoverable => {
                    Some(Err(OxidraError::Plugin(failure.reason.clone())))
                }
                RuntimeState::Starting => Some(Err(OxidraError::Plugin(format!(
                    "plugin {} is already starting",
                    self.manifest.name
                )))),
                RuntimeState::Dormant | RuntimeState::Failed(_) => None,
            }
        };
        if let Some(current) = current {
            let client = current?;
            let is_alive = {
                let mut client = client.lock().await;
                client.is_alive()?
            };
            if is_alive {
                return Ok(client);
            }
            self.set_failed("plugin exited while idle".to_owned(), true, false)
                .await;
        }

        *self.state.lock().await = RuntimeState::Starting;
        let mut last_error = None;
        for attempt in 0..2 {
            if cancellation.is_cancelled() {
                *self.state.lock().await = RuntimeState::Dormant;
                return Err(OxidraError::Interrupted);
            }
            if self.starts.fetch_add(1, Ordering::SeqCst) >= MAX_PROCESS_STARTS_PER_SESSION {
                let reason = format!(
                    "plugin {} exhausted its session restart budget",
                    self.manifest.name
                );
                self.set_failed(reason.clone(), false, false).await;
                return Err(OxidraError::Plugin(reason));
            }

            match self.start_once(cancellation).await {
                Ok(client) => {
                    let client = Arc::new(Mutex::new(client));
                    *self.state.lock().await = RuntimeState::Ready(client.clone());
                    return Ok(client);
                }
                Err(ClientError::Cancelled) => {
                    *self.state.lock().await = RuntimeState::Dormant;
                    return Err(OxidraError::Interrupted);
                }
                Err(error) => {
                    let retryable = error.retryable_startup();
                    last_error = Some(error);
                    if !retryable || attempt == 1 {
                        break;
                    }
                }
            }
        }

        let error = last_error.unwrap_or_else(|| ClientError::Protocol {
            message: "plugin startup failed without an error".to_owned(),
            after_send: false,
        });
        let reason = error.message(&self.manifest.name);
        self.set_failed(reason.clone(), false, false).await;
        Err(error.into_oxidra(&self.manifest.name))
    }

    async fn start_once(
        &self,
        cancellation: &CancellationToken,
    ) -> std::result::Result<McpClient, ClientError> {
        let mut client = self.spawn_client().await?;
        let result = {
            tokio::select! {
                _ = cancellation.cancelled() => Err(ClientError::Cancelled),
                result = timeout(
                    PLUGIN_START_TIMEOUT,
                    self.handshake(&mut client, cancellation),
                ) => {
                    result.unwrap_or(Err(ClientError::Timeout { after_send: false }))
                }
            }
        };
        match result {
            Ok(()) => Ok(client),
            Err(error) => {
                client.terminate().await.ok();
                Err(error)
            }
        }
    }

    async fn handshake(
        &self,
        client: &mut McpClient,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), ClientError> {
        let initialized = client
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "oxidra",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
                PLUGIN_START_TIMEOUT,
                cancellation,
            )
            .await?;
        let negotiated = initialized
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::Protocol {
                message: "initialize result omitted protocolVersion".to_owned(),
                after_send: true,
            })?;
        if negotiated != MCP_PROTOCOL_VERSION {
            return Err(ClientError::Permanent(format!(
                "server negotiated unsupported protocol {negotiated:?}"
            )));
        }

        client.notify("notifications/initialized", None).await?;
        let listed = client
            .request(
                "tools/list",
                Some(json!({})),
                PLUGIN_START_TIMEOUT,
                cancellation,
            )
            .await?;
        let tools_value = listed
            .get("tools")
            .cloned()
            .ok_or_else(|| ClientError::Protocol {
                message: "tools/list result omitted tools".to_owned(),
                after_send: true,
            })?;
        let tools = parse_mcp_tools(tools_value)?;
        validate_tool_set(&tools).map_err(|error| ClientError::Permanent(error.to_string()))?;
        let actual = canonical_tool_schema_hash(&tools)
            .map_err(|error| ClientError::Permanent(error.to_string()))?;
        if !self.expected_schema_hash.is_empty() && actual != self.expected_schema_hash {
            return Err(ClientError::Permanent(format!(
                "tools/list schema hash mismatch: manifest={}, runtime={actual}",
                self.expected_schema_hash
            )));
        }
        *self
            .runtime_tools
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = tools;
        Ok(())
    }

    async fn spawn_client(&self) -> std::result::Result<McpClient, ClientError> {
        self.verify_trust_snapshot()?;
        let executable = match &self.resolved_executable {
            Some(path) => path.clone(),
            None => resolve_executable_path(&self.manifest.command, &self.manifest_dir).map_err(
                |error| ClientError::Permanent(format!("cannot resolve executable: {error}")),
            )?,
        };
        let mut command = Command::new(executable);
        command
            .args(&self.manifest.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .env_clear();

        for &name in minimal_environment_names() {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, value) in &self.manifest.env.set {
            command.env(name, value);
        }
        for name in &self.manifest.env.inherit {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, value) in &self.config.env {
            command.env(name, value);
        }

        let cwd = self
            .manifest
            .cwd
            .as_ref()
            .map(|cwd| {
                if cwd.is_absolute() {
                    cwd.clone()
                } else {
                    self.manifest_dir.join(cwd)
                }
            })
            .unwrap_or_else(|| self.manifest_dir.clone());
        command.current_dir(cwd);
        ProcessTree::configure(&mut command);

        let mut child = command.spawn().map_err(|error| ClientError::Io {
            error,
            after_send: false,
        })?;
        let mut process_tree = match ProcessTree::attach(&child) {
            Ok(process_tree) => process_tree,
            Err(error) => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(2), child.wait()).await;
                return Err(ClientError::Io {
                    error,
                    after_send: false,
                });
            }
        };
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(ClientError::Protocol {
                    message: "failed to open plugin stdin".to_owned(),
                    after_send: false,
                });
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                process_tree.terminate(&mut child).await;
                return Err(ClientError::Protocol {
                    message: "failed to open plugin stdout".to_owned(),
                    after_send: false,
                });
            }
        };
        Ok(McpClient {
            child,
            process_tree,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: AtomicU64::new(1),
        })
    }

    fn verify_trust_snapshot(&self) -> std::result::Result<(), ClientError> {
        let (Some(project), Some(expected)) = (&self.trust_project, &self.trusted_execution_hash)
        else {
            return Ok(());
        };
        let actual = execution_hash(project).map_err(|error| {
            ClientError::Permanent(format!("trust snapshot could not be read: {error}"))
        })?;
        if &actual == expected {
            return Ok(());
        }
        if let Ok(mut store) = TrustStore::load() {
            let _ = store.revoke(&project.root);
        }
        Err(ClientError::Permanent(
            "project plugin trust was revoked because its execution files changed; restart and confirm trust again"
                .to_owned(),
        ))
    }

    fn local_tool_name<'a>(&self, namespaced: &'a str) -> Result<&'a str> {
        let prefix = format!("{}.", self.manifest.name);
        let local = namespaced.strip_prefix(&prefix).ok_or_else(|| {
            OxidraError::tool(
                "not_found",
                format!(
                    "tool {namespaced:?} does not belong to plugin {}",
                    self.manifest.name
                ),
            )
        })?;
        if !self
            .runtime_tools
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|tool| tool.name == local)
        {
            return Err(OxidraError::tool(
                "not_found",
                format!("plugin {} has no tool {local:?}", self.manifest.name),
            ));
        }
        Ok(local)
    }

    async fn record_runtime_error(&self, error: &ClientError, tool_was_sent: bool) {
        if !error.breaks_transport() {
            return;
        }
        let in_doubt = tool_was_sent && error.after_send();
        let reason = if in_doubt {
            format!("in_doubt: {}", error.message(&self.manifest.name))
        } else {
            error.message(&self.manifest.name)
        };
        let recoverable = self.starts.load(Ordering::SeqCst) < MAX_PROCESS_STARTS_PER_SESSION
            && !matches!(error, ClientError::Permanent(_));
        self.set_failed(reason, recoverable, in_doubt).await;
    }

    async fn set_failed(&self, reason: String, recoverable: bool, in_doubt: bool) {
        let old = {
            let mut state = self.state.lock().await;
            std::mem::replace(
                &mut *state,
                RuntimeState::Failed(FailureState {
                    reason,
                    recoverable,
                    in_doubt,
                }),
            )
        };
        if let RuntimeState::Ready(client) = old {
            let _ = client.lock().await.terminate().await;
        }
    }
}

struct McpClient {
    child: Child,
    process_tree: ProcessTree,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: AtomicU64,
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
        if line.len().saturating_add(take) > MAX_MCP_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("plugin JSON-RPC line exceeds {MAX_MCP_LINE_BYTES} bytes"),
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

impl McpClient {
    async fn request(
        &mut self,
        method: &str,
        params: Option<Value>,
        duration: Duration,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Value, ClientError> {
        if !self.is_alive().map_err(|error| ClientError::Io {
            error,
            after_send: false,
        })? {
            return Err(ClientError::Exited { after_send: false });
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = Map::new();
        request.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        request.insert("id".to_owned(), Value::from(id));
        request.insert("method".to_owned(), Value::String(method.to_owned()));
        if let Some(params) = params {
            request.insert("params".to_owned(), params);
        }
        let deadline = Instant::now() + duration;
        let write_remaining = deadline.saturating_duration_since(Instant::now());
        if write_remaining.is_zero() {
            return Err(ClientError::Timeout { after_send: false });
        }
        let request = Value::Object(request);
        let write = write_json_line(&mut self.stdin, &request, true);
        tokio::select! {
            _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
            result = timeout(write_remaining, write) => {
                match result {
                    Ok(result) => result?,
                    Err(_) => return Err(ClientError::Timeout { after_send: true }),
                }
            }
        }

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = timeout(
                    Duration::from_millis(100),
                    write_cancel_notification(&mut self.stdin, id, "timeout"),
                )
                .await;
                return Err(ClientError::Timeout { after_send: true });
            }
            let stdin = &mut self.stdin;
            let stdout = &mut self.stdout;
            let read = read_bounded_line(stdout);
            tokio::pin!(read);
            let line = tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = timeout(
                        Duration::from_millis(100),
                        write_cancel_notification(stdin, id, "cancelled"),
                    )
                    .await;
                    return Err(ClientError::Cancelled);
                }
                result = timeout(remaining, &mut read) => {
                    match result {
                        Ok(Ok(Some(line))) => line,
                        Ok(Ok(None)) => return Err(ClientError::Exited { after_send: true }),
                        Ok(Err(error)) => return Err(ClientError::Io { error, after_send: true }),
                        Err(_) => {
                            let _ = timeout(
                                Duration::from_millis(100),
                                write_cancel_notification(stdin, id, "timeout"),
                            )
                            .await;
                            return Err(ClientError::Timeout { after_send: true });
                        }
                    }
                }
            };

            let message: Value =
                serde_json::from_slice(trim_ascii_end(&line)).map_err(|error| {
                    ClientError::Protocol {
                        message: format!("non-JSON data on plugin stdout: {error}"),
                        after_send: true,
                    }
                })?;
            if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err(ClientError::Protocol {
                    message: "plugin stdout message is not JSON-RPC 2.0".to_owned(),
                    after_send: true,
                });
            }

            // Notifications do not carry an id and are outside the fixed MVP
            // subset; preserving protocol synchronization is sufficient here.
            let Some(response_id) = message.get("id") else {
                continue;
            };
            if response_id != &Value::from(id) {
                // Calls are serialized. A different id is therefore a late
                // response to a cancelled request and can be discarded.
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(ClientError::Rpc(error.clone()));
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| ClientError::Protocol {
                    message: "JSON-RPC response has neither result nor error".to_owned(),
                    after_send: true,
                });
        }
    }

    async fn notify(
        &mut self,
        method: &str,
        params: Option<Value>,
    ) -> std::result::Result<(), ClientError> {
        let mut notification = Map::new();
        notification.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        notification.insert("method".to_owned(), Value::String(method.to_owned()));
        if let Some(params) = params {
            notification.insert("params".to_owned(), params);
        }
        write_json_line(&mut self.stdin, &Value::Object(notification), false).await
    }

    fn is_alive(&mut self) -> std::io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    async fn terminate(&mut self) -> std::io::Result<()> {
        self.process_tree.terminate(&mut self.child).await;
        Ok(())
    }
}

async fn write_json_line(
    stdin: &mut ChildStdin,
    value: &Value,
    after_send: bool,
) -> std::result::Result<(), ClientError> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| ClientError::Protocol {
        message: format!("failed to serialize JSON-RPC message: {error}"),
        after_send,
    })?;
    if bytes.len().saturating_add(1) > MAX_MCP_LINE_BYTES {
        return Err(ClientError::Protocol {
            message: format!("JSON-RPC message exceeds {MAX_MCP_LINE_BYTES} bytes"),
            after_send,
        });
    }
    bytes.push(b'\n');
    stdin
        .write_all(&bytes)
        .await
        .map_err(|error| ClientError::Io { error, after_send })?;
    stdin.flush().await.map_err(|error| ClientError::Io {
        error,
        after_send: true,
    })
}

async fn write_cancel_notification(stdin: &mut ChildStdin, id: u64, reason: &str) {
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": { "requestId": id, "reason": reason }
    });
    let _ = write_json_line(stdin, &notification, true).await;
}

#[derive(Debug)]
enum ClientError {
    Cancelled,
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
    Permanent(String),
}

impl ClientError {
    fn after_send(&self) -> bool {
        match self {
            Self::Timeout { after_send }
            | Self::Exited { after_send }
            | Self::Io { after_send, .. }
            | Self::Protocol { after_send, .. } => *after_send,
            Self::Rpc(_) | Self::Cancelled => true,
            Self::Permanent(_) => false,
        }
    }

    fn breaks_transport(&self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::Timeout { .. }
                | Self::Exited { .. }
                | Self::Io { .. }
                | Self::Protocol { .. }
                | Self::Permanent(_)
        )
    }

    fn retryable_startup(&self) -> bool {
        !matches!(self, Self::Cancelled | Self::Permanent(_))
    }

    fn message(&self, plugin: &str) -> String {
        match self {
            Self::Cancelled => format!("plugin {plugin} operation cancelled"),
            Self::Timeout { .. } => format!("plugin {plugin} operation timed out"),
            Self::Exited { .. } => format!("plugin {plugin} process exited"),
            Self::Io { error, .. } => format!("plugin {plugin} transport error: {error}"),
            Self::Protocol { message, .. } => {
                format!("plugin {plugin} protocol violation: {message}")
            }
            Self::Rpc(error) => format!("plugin {plugin} JSON-RPC error: {error}"),
            Self::Permanent(message) => format!("plugin {plugin} failed: {message}"),
        }
    }

    fn into_oxidra(self, plugin: &str) -> OxidraError {
        match self {
            Self::Cancelled => OxidraError::Interrupted,
            Self::Timeout { .. } => OxidraError::tool(
                "timeout",
                format!("plugin {plugin} operation exceeded its timeout"),
            ),
            Self::Exited { .. } => {
                OxidraError::tool("process_exit", format!("plugin {plugin} process exited"))
            }
            Self::Io { error, .. } => OxidraError::tool(
                "process_exit",
                format!("plugin {plugin} transport error: {error}"),
            ),
            Self::Protocol { message, .. } => OxidraError::tool(
                "protocol_error",
                format!("plugin {plugin} protocol violation: {message}"),
            ),
            Self::Rpc(error) => OxidraError::tool(
                "plugin_rpc_error",
                format!("plugin {plugin} JSON-RPC error: {error}"),
            ),
            Self::Permanent(message) => {
                OxidraError::Plugin(format!("plugin {plugin} failed: {message}"))
            }
        }
    }

    fn into_call_oxidra(self, plugin: &str, tool_was_sent: bool) -> OxidraError {
        let in_doubt = tool_was_sent && self.after_send() && self.breaks_transport();
        if in_doubt {
            OxidraError::Plugin(format!("in_doubt: {}", self.message(plugin)))
        } else {
            self.into_oxidra(plugin)
        }
    }
}

fn minimal_environment_names() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &[
            "PATH",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "TEMP",
            "TMP",
        ]
    }
    #[cfg(not(windows))]
    {
        &["PATH", "TMPDIR"]
    }
}

pub fn resolve_executable_path(command: &str, manifest_dir: &Path) -> std::io::Result<PathBuf> {
    let command_path = Path::new(command);
    if command_path.is_absolute() || command.contains('/') || command.contains('\\') {
        let candidate = if command_path.is_absolute() {
            command_path.to_owned()
        } else {
            manifest_dir.join(command_path)
        };
        return std::fs::canonicalize(candidate);
    }

    let path = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "PATH is not set"))?;
    for directory in std::env::split_paths(&path) {
        // Empty PATH components have platform-specific current-directory
        // semantics. Skip them so a project cannot shadow a declared command.
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(command);
        if let Some(path) = existing_executable_candidate(&candidate) {
            return std::fs::canonicalize(path);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("command {command:?} was not found on PATH"),
    ))
}

fn existing_executable_candidate(candidate: &Path) -> Option<PathBuf> {
    if candidate.is_file() {
        return Some(candidate.to_owned());
    }
    #[cfg(windows)]
    {
        if candidate.extension().is_none() {
            let extensions = std::env::var_os("PATHEXT")
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_owned());
            for extension in extensions
                .split(';')
                .filter(|extension| !extension.is_empty())
            {
                let mut with_extension = candidate.as_os_str().to_os_string();
                with_extension.push(extension);
                let with_extension = PathBuf::from(with_extension);
                if with_extension.is_file() {
                    return Some(with_extension);
                }
            }
        }
    }
    None
}

fn parse_mcp_tools(value: Value) -> std::result::Result<Vec<ToolDefinition>, ClientError> {
    let tools = serde_json::from_value::<Vec<ManifestTool>>(value).map_err(|error| {
        ClientError::Protocol {
            message: format!("invalid tools/list result: {error}"),
            after_send: true,
        }
    })?;
    Ok(tools
        .into_iter()
        .map(|tool| ToolDefinition {
            name: tool.name,
            description: tool.description,
            input_schema: tool.input_schema,
        })
        .collect())
}

pub fn validate_manifest(manifest: &PluginManifest) -> Result<String> {
    if !valid_plugin_name(&manifest.name) {
        return Err(OxidraError::Config(format!(
            "invalid plugin name {:?}; use ASCII letters, digits, '_' or '-'",
            manifest.name
        )));
    }
    if manifest.protocol_version != MCP_PROTOCOL_VERSION {
        return Err(OxidraError::Config(format!(
            "plugin {} declares unsupported MCP protocol {:?}",
            manifest.name, manifest.protocol_version
        )));
    }
    if manifest.command.trim().is_empty() {
        return Err(OxidraError::Config(format!(
            "plugin {} has an empty command",
            manifest.name
        )));
    }
    validate_tool_set(&manifest.tools)?;
    validate_environment(&manifest.env)?;

    let declared = normalize_sha256(&manifest.schema_hash);
    if manifest.dynamic_tools && !manifest.schema_hash.trim().is_empty() && declared.is_none() {
        return Err(OxidraError::Config(format!(
            "plugin {} schema_hash must be a 64-character SHA-256 hex digest when provided",
            manifest.name
        )));
    }
    let actual = canonical_tool_schema_hash(&manifest.tools)?;
    if !manifest.dynamic_tools && declared.as_deref() != Some(actual.as_str()) {
        let declared = declared.unwrap_or_else(|| "<missing>".to_owned());
        return Err(OxidraError::Config(format!(
            "plugin {} manifest schema hash mismatch: declared={declared}, computed={actual}",
            manifest.name
        )));
    }
    Ok(if manifest.dynamic_tools {
        declared.unwrap_or_default()
    } else {
        actual
    })
}

fn validate_config(manifest: &PluginManifest, config: &PluginConfig) -> Result<()> {
    if manifest.dynamic_tools && config.activation != PluginActivation::Eager {
        return Err(OxidraError::Config(format!(
            "plugin {} declares dynamic tools and must use eager activation",
            manifest.name
        )));
    }
    let allowed: BTreeSet<&str> = manifest
        .env
        .inherit
        .iter()
        .map(String::as_str)
        .chain(manifest.env.set.keys().map(String::as_str))
        .collect();
    for name in config.env.keys() {
        if !allowed.contains(name.as_str()) {
            return Err(OxidraError::Config(format!(
                "plugin {} config supplies undeclared environment variable {name:?}",
                manifest.name
            )));
        }
    }
    Ok(())
}

fn validate_environment(environment: &PluginEnvironment) -> Result<()> {
    let mut seen = BTreeSet::new();
    for name in environment
        .inherit
        .iter()
        .map(String::as_str)
        .chain(environment.set.keys().map(String::as_str))
    {
        if !valid_environment_name(name) {
            return Err(OxidraError::Config(format!(
                "invalid plugin environment variable name {name:?}"
            )));
        }
        if !seen.insert(name) {
            return Err(OxidraError::Config(format!(
                "plugin environment variable {name:?} is declared more than once"
            )));
        }
    }
    Ok(())
}

fn validate_tool_set(tools: &[ToolDefinition]) -> Result<()> {
    let mut names = BTreeSet::new();
    for tool in tools {
        if tool.name.trim().is_empty() || tool.name.chars().any(char::is_whitespace) {
            return Err(OxidraError::Config(format!(
                "invalid plugin tool name {:?}",
                tool.name
            )));
        }
        if !names.insert(tool.name.as_str()) {
            return Err(OxidraError::Config(format!(
                "duplicate plugin tool name {:?}",
                tool.name
            )));
        }
        if !tool.input_schema.is_object() {
            return Err(OxidraError::Config(format!(
                "input schema for tool {:?} must be a JSON object",
                tool.name
            )));
        }
    }
    Ok(())
}

fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn normalize_sha256(value: &str) -> Option<String> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// Hash the semantic MCP tool surface. Object keys and tool ordering do not
/// affect the digest; array ordering inside an input schema remains meaningful.
pub fn canonical_tool_schema_hash(tools: &[ToolDefinition]) -> Result<String> {
    let mut tools = tools.to_vec();
    tools.sort_by(|left, right| left.name.cmp(&right.name));
    let value = Value::Array(
        tools
            .into_iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                })
            })
            .collect(),
    );
    let canonical = canonical_json(&value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(hex::encode(digest))
}

fn canonical_json(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value).map_err(OxidraError::from),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", values.join(",")))
        }
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical_json(value)?
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("{{{}}}", entries.join(",")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, description: &str, schema: Value) -> ToolDefinition {
        ToolDefinition {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: schema,
        }
    }

    fn manifest(tools: Vec<ToolDefinition>) -> PluginManifest {
        let schema_hash = canonical_tool_schema_hash(&tools).unwrap();
        PluginManifest {
            name: "fixture".to_owned(),
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
            command: "fixture-server".to_owned(),
            args: Vec::new(),
            cwd: None,
            env: PluginEnvironment::default(),
            tools,
            schema_hash,
            dynamic_tools: false,
        }
    }

    #[test]
    fn canonical_hash_ignores_object_and_tool_order() {
        let first = vec![
            tool(
                "write",
                "Write a value",
                json!({
                    "type": "object",
                    "properties": { "z": { "type": "integer" }, "a": { "type": "string" } },
                    "required": ["a", "z"]
                }),
            ),
            tool("read", "Read a value", json!({ "type": "object" })),
        ];
        let second = vec![
            tool("read", "Read a value", json!({ "type": "object" })),
            tool(
                "write",
                "Write a value",
                json!({
                    "required": ["a", "z"],
                    "properties": { "a": { "type": "string" }, "z": { "type": "integer" } },
                    "type": "object"
                }),
            ),
        ];

        assert_eq!(
            canonical_tool_schema_hash(&first).unwrap(),
            canonical_tool_schema_hash(&second).unwrap()
        );
        let changed = vec![tool(
            "read",
            "A different description",
            json!({ "type": "object" }),
        )];
        assert_ne!(
            canonical_tool_schema_hash(&first).unwrap(),
            canonical_tool_schema_hash(&changed).unwrap()
        );
    }

    #[test]
    fn manifest_hash_is_verified() {
        let tools = vec![tool(
            "echo",
            "Echo input",
            json!({ "type": "object", "properties": {} }),
        )];
        let valid = manifest(tools);
        assert!(validate_manifest(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.tools[0].description = "changed after hashing".to_owned();
        let error = validate_manifest(&invalid).unwrap_err().to_string();
        assert!(error.contains("schema hash mismatch"), "{error}");
    }

    #[test]
    fn dynamic_manifest_may_defer_schema_hash_to_runtime() {
        let mut manifest = manifest(Vec::new());
        manifest.dynamic_tools = true;
        manifest.schema_hash.clear();
        assert!(validate_manifest(&manifest).is_ok());
    }

    #[test]
    fn manifest_and_activation_environment_deserialize() {
        let tools = vec![tool("echo", "Echo", json!({ "type": "object" }))];
        let hash = canonical_tool_schema_hash(&tools).unwrap();
        let text = format!(
            r#"{{
                "name": "fixture",
                "protocolVersion": "{MCP_PROTOCOL_VERSION}",
                "command": "fixture-server",
                "env": {{ "inherit": ["API_KEY"], "set": {{ "MODE": "test" }} }},
                "tools": [{{
                    "name": "echo",
                    "description": "Echo",
                    "inputSchema": {{ "type": "object" }}
                }}],
                "schemaHash": "sha256:{hash}"
            }}"#
        );
        let manifest: PluginManifest = serde_json::from_str(&text).unwrap();
        assert_eq!(manifest.env.inherit, vec!["API_KEY"]);
        assert_eq!(
            manifest.env.set.get("MODE").map(String::as_str),
            Some("test")
        );
        assert!(validate_manifest(&manifest).is_ok());

        let config: PluginConfig = toml::from_str(
            r#"
                activation = "eager"
                [env]
                API_KEY = "fixture-key"
            "#,
        )
        .unwrap();
        assert_eq!(config.activation, PluginActivation::Eager);
        assert_eq!(
            config.env.get("API_KEY").map(String::as_str),
            Some("fixture-key")
        );
    }

    #[test]
    fn config_cannot_inject_undeclared_environment() {
        let tools = vec![tool("echo", "Echo", json!({ "type": "object" }))];
        let manifest = manifest(tools);
        let config = PluginConfig {
            env: BTreeMap::from([("API_KEY".to_owned(), "secret".to_owned())]),
            ..PluginConfig::default()
        };
        let error = PluginSupervisor::new(manifest, ".", config)
            .err()
            .expect("configuration should be rejected")
            .to_string();
        assert!(error.contains("undeclared environment variable"), "{error}");
    }
}
