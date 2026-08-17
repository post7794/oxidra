use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::coordinator::{DispatchPermit, McpResumeEligibility, McpResumePermit};
use super::{
    ApprovedMcpProjectConfig, BoundedMcpJsonValue, MCP_EXECUTION_PLAN_VERSION,
    MCP_LEGACY_PROTOCOL_VERSION, MCP_MODERN_PROTOCOL_VERSION, MCP_SCHEMA_PROFILE_VERSION,
    MCP_STDIO_KERNEL_VERSION, McpCallError, McpProtocolEra, McpStdioSession, TransportAbortHandle,
    ValidatedMcpArguments,
};
use crate::context::McpSurfaceBindingV1;
use crate::error::{OxidraError, Result};
use crate::session::{SessionExecutionLeaseV1, SessionJournal};
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

/// Durable, non-lossy identity of a Provider-visible MCP binding.
///
/// The registry digest covers the complete tool surface, but an offline
/// journal reader cannot invert that digest to prove which raw server tool a
/// Provider alias selected.  Coordinator v2 therefore persists this bounded,
/// sorted identity view in the activation event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct McpToolBindingIdentity {
    pub provider_name: String,
    pub server_name: String,
    pub raw_tool_name: String,
    pub protocol_version: String,
}

pub struct McpRegistry {
    config_sha256: String,
    execution_plan_digest: String,
    digest: String,
    sessions: BTreeMap<String, McpStdioSession>,
    bindings: BTreeMap<String, McpToolBinding>,
    dispatch_authority: Option<RegistryDispatchAuthority>,
    /// Present when registry startup was bound to a locked session journal
    /// before any MCP process was spawned. Test-only empty registries may omit
    /// it, but coordinator activation/resume then fail closed.
    execution_lease: Option<SessionExecutionLeaseV1>,
}

struct RegistryDispatchAuthority {
    coordinator_id: String,
    registry_epoch_id: String,
}

pub struct ApprovedMcpRegistry {
    registry: McpRegistry,
}

/// A discovered registry whose process startup was authorized by a recovered
/// journal capability.  This type cannot be passed to a new activation.
pub struct McpResumeRegistry {
    registry: McpRegistry,
    permit: McpResumePermit,
}

/// Surface-approved resume registry.  Only this type is accepted by
/// `McpExecutionCoordinator::resume`.
pub struct ApprovedMcpResumeRegistry {
    registry: McpRegistry,
    permit: McpResumePermit,
}

pub(super) struct PreparedMcpRegistryCall {
    binding: McpToolBinding,
    server_attempt_id: String,
    arguments: ValidatedMcpArguments,
    transport_abort: TransportAbortHandle,
}

impl ApprovedMcpRegistry {
    pub(super) fn into_parts(self) -> (McpRegistry, Option<SessionExecutionLeaseV1>) {
        let mut registry = self.registry;
        let execution_lease = registry.execution_lease.take();
        (registry, execution_lease)
    }
}

impl ApprovedMcpResumeRegistry {
    pub(super) fn into_parts(
        self,
    ) -> (
        McpRegistry,
        McpResumePermit,
        Option<SessionExecutionLeaseV1>,
    ) {
        let mut registry = self.registry;
        let execution_lease = registry.execution_lease.take();
        (registry, self.permit, execution_lease)
    }
}

impl McpResumeRegistry {
    pub fn config_sha256(&self) -> &str {
        self.registry.config_sha256()
    }

    pub fn execution_plan_digest(&self) -> &str {
        self.registry.execution_plan_digest()
    }

    pub fn digest(&self) -> &str {
        self.registry.digest()
    }

    pub fn bindings(&self) -> impl Iterator<Item = &McpToolBinding> {
        self.registry.bindings()
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.registry.definitions()
    }

    pub fn stderr_snapshots(&self) -> BTreeMap<String, String> {
        self.registry.stderr_snapshots()
    }

    pub fn approve_surface(self, expected_digest: &str) -> Result<ApprovedMcpResumeRegistry> {
        if self.registry.digest != expected_digest {
            return Err(OxidraError::Mcp(
                "MCP registry approval does not match the discovered surface digest".to_owned(),
            ));
        }
        Ok(ApprovedMcpResumeRegistry {
            registry: self.registry,
            permit: self.permit,
        })
    }

    pub async fn shutdown(&mut self) {
        self.registry.shutdown().await;
    }
}

impl PreparedMcpRegistryCall {
    pub(super) fn binding(&self) -> &McpToolBinding {
        &self.binding
    }

    pub(super) fn server_attempt_id(&self) -> &str {
        &self.server_attempt_id
    }

    pub(super) fn arguments(&self) -> &Value {
        self.arguments.as_value()
    }

    pub(super) fn transport_abort_handle(&self) -> TransportAbortHandle {
        self.transport_abort.clone()
    }
}

impl McpRegistry {
    /// Connect a registry whose process startup is bound to an already-open
    /// session journal.  The journal consumes its one-shot activation-start
    /// slot and validates the durable prefix before the first child spawn.
    /// The resulting lease travels with the registry through surface approval
    /// and coordinator activation; dropping the journal alone therefore
    /// cannot open a second generation while these transports remain alive.
    pub async fn connect_for_activation(
        config: &ApprovedMcpProjectConfig,
        reserved_provider_names: impl IntoIterator<Item = String>,
        journal: &mut SessionJournal,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let execution_lease = journal.claim_mcp_activation_startup_v1()?;
        Self::connect_inner(
            config,
            reserved_provider_names,
            cancellation,
            Some(execution_lease),
        )
        .await
    }

    /// Connect a live registry for an existing durable MCP epoch.
    ///
    /// `eligibility` can only be minted from a recovered `SessionJournal` and
    /// is consumed here before any server is spawned.  The resulting registry
    /// can only be consumed by `McpExecutionCoordinator::resume` for that same
    /// journal handle; it cannot create a new activation.
    pub async fn connect_for_resume(
        config: &ApprovedMcpProjectConfig,
        reserved_provider_names: impl IntoIterator<Item = String>,
        eligibility: McpResumeEligibility<'_>,
        cancellation: &CancellationToken,
    ) -> Result<McpResumeRegistry> {
        eligibility.validate_config(config.source_sha256(), config.execution_plan_digest())?;
        let execution_lease = eligibility.execution_lease();
        let permit = eligibility.into_permit();
        let registry = Self::connect_inner(
            config,
            reserved_provider_names,
            cancellation,
            Some(execution_lease),
        )
        .await?;
        Ok(McpResumeRegistry { registry, permit })
    }

    async fn connect_inner(
        config: &ApprovedMcpProjectConfig,
        reserved_provider_names: impl IntoIterator<Item = String>,
        cancellation: &CancellationToken,
        execution_lease: Option<SessionExecutionLeaseV1>,
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
                execution_lease
                    .as_ref()
                    .map(SessionExecutionLeaseV1::clone_v1),
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
            dispatch_authority: None,
            execution_lease,
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

    /// Convert a discovered registry into the surface-trust capability that
    /// the execution coordinator alone can consume.
    pub fn approve_surface(self, expected_digest: &str) -> Result<ApprovedMcpRegistry> {
        if self.digest != expected_digest {
            return Err(OxidraError::Mcp(
                "MCP registry approval does not match the discovered surface digest".to_owned(),
            ));
        }
        Ok(ApprovedMcpRegistry { registry: self })
    }

    pub fn bindings(&self) -> impl Iterator<Item = &McpToolBinding> {
        self.bindings.values()
    }

    pub(super) fn binding_identity_snapshot(&self) -> Vec<McpToolBindingIdentity> {
        self.bindings
            .values()
            .map(|binding| McpToolBindingIdentity {
                provider_name: binding.provider_name.clone(),
                server_name: binding.server_name.clone(),
                raw_tool_name: binding.raw_tool_name.clone(),
                protocol_version: binding.protocol_version.clone(),
            })
            .collect()
    }

    /// Derive the complete surface identity from the same live binding table
    /// used for dispatch.  Surface snapshots and the future activation-v3
    /// writer must share this function so definition/output-schema digests
    /// cannot drift through independent reimplementation.
    pub(super) fn surface_binding_snapshot_v1(&self) -> Result<Vec<McpSurfaceBindingV1>> {
        self.bindings
            .values()
            .map(|binding| {
                McpSurfaceBindingV1::from_parts(
                    binding.provider_name.clone(),
                    binding.server_name.clone(),
                    binding.raw_tool_name.clone(),
                    binding.protocol_version.clone(),
                    &binding.definition,
                    binding.output_schema.as_ref(),
                )
            })
            .collect()
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

    pub(super) fn prepare_call(
        &self,
        provider_name: &str,
        arguments: ValidatedMcpArguments,
    ) -> std::result::Result<PreparedMcpRegistryCall, McpCallError> {
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
        let Some(session) = self.sessions.get(&binding.server_name) else {
            return Err(McpCallError {
                code: "transport_closed",
                message: format!("MCP server {} session is unavailable", binding.server_name),
                in_doubt: false,
                interrupted: false,
            });
        };
        let Some(transport_abort) = session.transport_abort_handle() else {
            return Err(McpCallError {
                code: "transport_closed",
                message: format!("MCP server {} session is closed", binding.server_name),
                in_doubt: false,
                interrupted: false,
            });
        };
        let prepared = session.prepare_tool_call(&binding.raw_tool_name, arguments)?;
        Ok(PreparedMcpRegistryCall {
            binding: binding.clone(),
            server_attempt_id: session.attempt_id().to_owned(),
            arguments: prepared,
            transport_abort,
        })
    }

    pub(super) fn bind_dispatch_authority(
        &mut self,
        coordinator_id: &str,
        registry_epoch_id: &str,
    ) -> Result<()> {
        if self.dispatch_authority.is_some()
            || coordinator_id.is_empty()
            || registry_epoch_id.is_empty()
        {
            return Err(OxidraError::Mcp(
                "MCP registry dispatch authority is invalid or already bound".to_owned(),
            ));
        }
        self.dispatch_authority = Some(RegistryDispatchAuthority {
            coordinator_id: coordinator_id.to_owned(),
            registry_epoch_id: registry_epoch_id.to_owned(),
        });
        Ok(())
    }

    pub(super) async fn dispatch(
        &mut self,
        permit: DispatchPermit,
        prepared: PreparedMcpRegistryCall,
        cancellation: &CancellationToken,
    ) -> std::result::Result<BoundedMcpJsonValue, McpCallError> {
        let Some(authority) = &self.dispatch_authority else {
            return Err(McpCallError {
                code: "dispatch_permit_invalid",
                message: "MCP registry has no bound dispatch authority".to_owned(),
                in_doubt: false,
                interrupted: false,
            });
        };
        permit.validate(
            &authority.coordinator_id,
            &authority.registry_epoch_id,
            &self.digest,
            &prepared,
        )?;
        let server_name = prepared.binding.server_name.clone();
        let raw_tool_name = prepared.binding.raw_tool_name.clone();
        let Some(session) = self.sessions.get_mut(&server_name) else {
            return Err(McpCallError {
                code: "transport_closed",
                message: format!("MCP server {server_name} session is unavailable"),
                in_doubt: false,
                interrupted: false,
            });
        };
        if session.attempt_id() != prepared.server_attempt_id {
            return Err(McpCallError {
                code: "dispatch_permit_invalid",
                message: "MCP server attempt changed after approval".to_owned(),
                in_doubt: false,
                interrupted: false,
            });
        }
        session
            .dispatch_prepared_tool(&raw_tool_name, prepared.arguments, cancellation)
            .await
    }

    pub async fn shutdown(&mut self) {
        shutdown_sessions(&mut self.sessions).await;
        // Explicit shutdown is the hand-off point at which no transport can
        // execute anymore. Release a pre-start session lease even when the
        // registry wrapper remains owned by its caller.
        self.execution_lease.take();
    }

    pub(super) fn abort_transports(&self) {
        for session in self.sessions.values() {
            if let Some(handle) = session.transport_abort_handle() {
                handle.abort();
            }
        }
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
    fn surface_digest_mismatch_cannot_create_dispatch_capability() {
        let registry = McpRegistry {
            config_sha256: "c".repeat(64),
            execution_plan_digest: "e".repeat(64),
            digest: "d".repeat(64),
            sessions: BTreeMap::new(),
            bindings: BTreeMap::new(),
            dispatch_authority: None,
            execution_lease: None,
        };
        let error = registry
            .approve_surface(&"0".repeat(64))
            .err()
            .expect("surface mismatch must not produce an approved registry");
        assert!(error.to_string().contains("surface digest"));
    }

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
