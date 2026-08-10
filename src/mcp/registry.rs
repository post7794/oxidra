use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    ApprovedMcpProjectConfig, MCP_EXECUTION_PLAN_VERSION, MCP_LEGACY_PROTOCOL_VERSION,
    MCP_MODERN_PROTOCOL_VERSION, MCP_SCHEMA_PROFILE_VERSION, MCP_STDIO_KERNEL_VERSION,
    McpCallError, McpProtocolEra, McpStdioSession,
};
use crate::error::{OxidraError, Result};
use crate::types::ToolDefinition;
use crate::untrusted_display;

pub const MCP_TOOL_REGISTRY_VERSION: u32 = 1;

const MAX_PROVIDER_TOOL_NAME_BYTES: usize = 64;
const TOOL_NAME_HASH_HEX_BYTES: usize = 12;
const MAX_REGISTRY_TOOLS: usize = 512;
const MAX_REGISTRY_SURFACE_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct McpToolBinding {
    pub provider_name: String,
    pub server_name: String,
    pub raw_tool_name: String,
    pub protocol_version: String,
    pub definition: ToolDefinition,
    pub output_schema: Option<Value>,
}

pub struct McpRegistry {
    config_sha256: String,
    execution_plan_digest: String,
    digest: String,
    sessions: BTreeMap<String, McpStdioSession>,
    bindings: BTreeMap<String, McpToolBinding>,
}

impl McpRegistry {
    pub async fn connect(
        config: &ApprovedMcpProjectConfig,
        reserved_provider_names: impl IntoIterator<Item = String>,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let mut sessions = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let mut provider_names = reserved_provider_names.into_iter().collect::<BTreeSet<_>>();
        let mut runtime_servers = Vec::new();
        let mut surface_bytes = 0usize;

        for server_config in config.servers() {
            let session = match McpStdioSession::connect_prepared(
                server_config.clone(),
                cancellation.clone(),
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    shutdown_sessions(&mut sessions).await;
                    return Err(error);
                }
            };
            let protocol_version = match session.era() {
                McpProtocolEra::Modern => MCP_MODERN_PROTOCOL_VERSION,
                McpProtocolEra::Legacy => MCP_LEGACY_PROTOCOL_VERSION,
            };
            runtime_servers.push(RuntimeServerDigest {
                name: server_config.name().to_owned(),
                protocol_version: protocol_version.to_owned(),
            });
            for tool in session.tools() {
                if bindings.len() >= MAX_REGISTRY_TOOLS {
                    shutdown_sessions(&mut sessions).await;
                    return Err(OxidraError::Mcp(format!(
                        "MCP registry exposes more than {MAX_REGISTRY_TOOLS} tools"
                    )));
                }
                let raw_tool_name = tool.definition.name.clone();
                let provider_name = provider_tool_name(server_config.name(), &raw_tool_name);
                if !provider_names.insert(provider_name.clone()) {
                    shutdown_sessions(&mut sessions).await;
                    return Err(OxidraError::Mcp(format!(
                        "MCP provider tool name collision at {provider_name:?}"
                    )));
                }
                let description = if tool.definition.description.is_empty() {
                    format!("MCP tool {}/{raw_tool_name}.", server_config.name())
                } else {
                    format!(
                        "MCP tool {}/{}: {}",
                        server_config.name(),
                        raw_tool_name,
                        tool.definition.description
                    )
                };
                let definition = ToolDefinition {
                    name: provider_name.clone(),
                    description,
                    input_schema: tool.definition.input_schema.clone(),
                };
                let definition_bytes = serde_json::to_vec(&definition)?.len();
                let output_schema_bytes = tool
                    .output_schema
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?
                    .map_or(0, |bytes| bytes.len());
                surface_bytes = surface_bytes
                    .checked_add(definition_bytes)
                    .and_then(|value| value.checked_add(output_schema_bytes))
                    .ok_or_else(|| {
                        OxidraError::Mcp("MCP registry surface size overflowed".to_owned())
                    })?;
                if surface_bytes > MAX_REGISTRY_SURFACE_BYTES {
                    shutdown_sessions(&mut sessions).await;
                    return Err(OxidraError::Mcp(format!(
                        "MCP registry surface exceeds {MAX_REGISTRY_SURFACE_BYTES} bytes"
                    )));
                }
                bindings.insert(
                    provider_name.clone(),
                    McpToolBinding {
                        provider_name,
                        server_name: server_config.name().to_owned(),
                        raw_tool_name,
                        protocol_version: protocol_version.to_owned(),
                        definition,
                        output_schema: tool.output_schema.clone(),
                    },
                );
            }

            let name = server_config.name().to_owned();
            if sessions.insert(name.clone(), session).is_some() {
                shutdown_sessions(&mut sessions).await;
                return Err(OxidraError::Mcp(format!(
                    "MCP registry contains duplicate server {name:?}"
                )));
            }
        }

        let digest = registry_digest(config.execution_plan_digest(), &runtime_servers, &bindings)?;
        Ok(Self {
            config_sha256: config.source_sha256().to_owned(),
            execution_plan_digest: config.execution_plan_digest().to_owned(),
            digest,
            sessions,
            bindings,
        })
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub fn execution_plan_digest(&self) -> &str {
        &self.execution_plan_digest
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn bindings(&self) -> impl Iterator<Item = &McpToolBinding> {
        self.bindings.values()
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.bindings
            .values()
            .map(|binding| binding.definition.clone())
            .collect()
    }

    pub fn stderr_snapshots(&self) -> BTreeMap<String, String> {
        self.sessions
            .iter()
            .filter_map(|(name, session)| {
                let snapshot = session.stderr_snapshot();
                (!snapshot.is_empty()).then(|| (name.clone(), snapshot))
            })
            .collect()
    }

    pub async fn call_tool(
        &mut self,
        provider_name: &str,
        arguments: Value,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Value, McpCallError> {
        let Some(binding) = self.bindings.get(provider_name) else {
            return Err(McpCallError {
                code: "not_found",
                message: format!(
                    "MCP registry has no provider tool {}",
                    untrusted_display::quoted_single_line(provider_name)
                ),
                in_doubt: false,
                interrupted: false,
            });
        };
        let server_name = binding.server_name.clone();
        let raw_tool_name = binding.raw_tool_name.clone();
        let Some(session) = self.sessions.get_mut(&server_name) else {
            return Err(McpCallError {
                code: "transport_closed",
                message: format!("MCP server {server_name} session is unavailable"),
                in_doubt: false,
                interrupted: false,
            });
        };
        session
            .call_tool(&raw_tool_name, arguments, cancellation)
            .await
    }

    pub async fn shutdown(&mut self) {
        shutdown_sessions(&mut self.sessions).await;
    }
}

async fn shutdown_sessions(sessions: &mut BTreeMap<String, McpStdioSession>) {
    for session in sessions.values_mut() {
        session.shutdown().await;
    }
    sessions.clear();
}

fn provider_tool_name(server_name: &str, raw_tool_name: &str) -> String {
    let identity = format!("{server_name}\0{raw_tool_name}");
    let hash = hex::encode(Sha256::digest(identity.as_bytes()));
    let suffix = &hash[..TOOL_NAME_HASH_HEX_BYTES];
    let readable = format!("{server_name}_{raw_tool_name}").replace('.', "_");
    let readable_budget = MAX_PROVIDER_TOOL_NAME_BYTES
        .saturating_sub("mcp_".len())
        .saturating_sub(1)
        .saturating_sub(suffix.len());
    let readable = &readable[..readable.len().min(readable_budget)];
    format!("mcp_{readable}_{suffix}")
}

fn registry_digest(
    execution_plan_digest: &str,
    servers: &[RuntimeServerDigest],
    bindings: &BTreeMap<String, McpToolBinding>,
) -> Result<String> {
    let tools = bindings.values().map(ToolDigest::from).collect::<Vec<_>>();
    let payload = RegistryDigest {
        registry_version: MCP_TOOL_REGISTRY_VERSION,
        kernel_version: MCP_STDIO_KERNEL_VERSION,
        execution_plan_version: MCP_EXECUTION_PLAN_VERSION,
        schema_profile_version: MCP_SCHEMA_PROFILE_VERSION,
        execution_plan_digest,
        servers,
        tools: &tools,
    };
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&payload)?)))
}

#[derive(Serialize)]
struct RegistryDigest<'a> {
    registry_version: u32,
    kernel_version: u32,
    execution_plan_version: u32,
    schema_profile_version: u32,
    execution_plan_digest: &'a str,
    servers: &'a [RuntimeServerDigest],
    tools: &'a [ToolDigest<'a>],
}

#[derive(Serialize)]
struct RuntimeServerDigest {
    name: String,
    protocol_version: String,
}

#[derive(Serialize)]
struct ToolDigest<'a> {
    provider_name: &'a str,
    server_name: &'a str,
    raw_tool_name: &'a str,
    protocol_version: &'a str,
    definition: &'a ToolDefinition,
    output_schema: &'a Option<Value>,
}

impl<'a> From<&'a McpToolBinding> for ToolDigest<'a> {
    fn from(binding: &'a McpToolBinding) -> Self {
        Self {
            provider_name: &binding.provider_name,
            server_name: &binding.server_name,
            raw_tool_name: &binding.raw_tool_name,
            protocol_version: &binding.protocol_version,
            definition: &binding.definition,
            output_schema: &binding.output_schema,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_are_bounded_stable_and_collision_resistant() {
        let dotted = provider_tool_name("server", "admin.list");
        let underscored = provider_tool_name("server", "admin_list");
        assert_ne!(dotted, underscored);
        assert_eq!(dotted, provider_tool_name("server", "admin.list"));
        for name in [
            dotted,
            underscored,
            provider_tool_name("long-server-name", &"x".repeat(128)),
        ] {
            assert!(name.len() <= MAX_PROVIDER_TOOL_NAME_BYTES);
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            );
        }
    }

    #[test]
    fn registry_digest_is_frozen_and_binds_all_transitive_versions() {
        let servers = vec![RuntimeServerDigest {
            name: "fixture".to_owned(),
            protocol_version: MCP_MODERN_PROTOCOL_VERSION.to_owned(),
        }];
        let provider_name = provider_tool_name("fixture", "echo.v1");
        let mut bindings = BTreeMap::new();
        bindings.insert(
            provider_name.clone(),
            McpToolBinding {
                provider_name: provider_name.clone(),
                server_name: "fixture".to_owned(),
                raw_tool_name: "echo.v1".to_owned(),
                protocol_version: MCP_MODERN_PROTOCOL_VERSION.to_owned(),
                definition: ToolDefinition {
                    name: provider_name,
                    description: "MCP tool fixture/echo.v1: Echo text".to_owned(),
                    input_schema: serde_json::json!({
                        "type":"object",
                        "properties":{"text":{"type":"string"}},
                        "required":["text"],
                        "additionalProperties":false
                    }),
                },
                output_schema: Some(serde_json::json!({
                    "type":"object",
                    "properties":{"text":{"type":"string"}}
                })),
            },
        );
        assert_eq!(MCP_TOOL_REGISTRY_VERSION, 1);
        assert_eq!(
            registry_digest(&"f".repeat(64), &servers, &bindings)
                .expect("compute registry fixture digest"),
            "586faa88eb55358cb7b8952c0f50d3140c77a186e5e7dc879987313da12f0459"
        );
        assert_ne!(
            registry_digest(&"0".repeat(64), &servers, &bindings)
                .expect("compute changed registry digest"),
            registry_digest(&"f".repeat(64), &servers, &bindings)
                .expect("compute registry fixture digest")
        );
    }
}
