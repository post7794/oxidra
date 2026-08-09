use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{McpStdioConfig, PreparedMcpStdioConfig};
use crate::error::{OxidraError, Result};

pub const MCP_PROJECT_CONFIG_VERSION_V1: u32 = 1;
pub const MCP_PROJECT_CONFIG_VERSION: u32 = MCP_PROJECT_CONFIG_VERSION_V1;
pub const MCP_EXECUTION_PLAN_VERSION_V1: u32 = 1;
pub const MCP_EXECUTION_PLAN_VERSION: u32 = MCP_EXECUTION_PLAN_VERSION_V1;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_SERVERS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_INHERITED_ENV: usize = 32;

#[derive(Clone, Debug)]
pub struct McpProjectConfig {
    source_path: PathBuf,
    source_sha256: String,
    execution_plan_digest: String,
    servers: Vec<PreparedMcpStdioConfig>,
}

impl McpProjectConfig {
    /// Load an explicitly selected project-local MCP configuration.
    ///
    /// Selecting the absolute path is the trust gesture for this invocation;
    /// Oxidra never auto-discovers or auto-enables this file.
    pub fn load(project_root: &Path, source_path: &Path) -> Result<Self> {
        if !source_path.is_absolute() {
            return Err(OxidraError::Config(
                "MCP config path must be absolute and explicitly selected".to_owned(),
            ));
        }
        let project_root = fs::canonicalize(project_root).map_err(|error| {
            OxidraError::Config(format!(
                "cannot resolve MCP project root {}: {error}",
                project_root.display()
            ))
        })?;
        if !project_root.is_dir() {
            return Err(OxidraError::Config(format!(
                "MCP project root is not a directory: {}",
                project_root.display()
            )));
        }
        let metadata = fs::symlink_metadata(source_path).map_err(|error| {
            OxidraError::Config(format!(
                "cannot inspect MCP config {}: {error}",
                source_path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(OxidraError::Config(format!(
                "MCP config must not be a symbolic link: {}",
                source_path.display()
            )));
        }
        if !metadata.is_file() {
            return Err(OxidraError::Config(format!(
                "MCP config is not a file: {}",
                source_path.display()
            )));
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(OxidraError::Config(format!(
                "MCP config exceeds {MAX_CONFIG_BYTES} bytes: {}",
                source_path.display()
            )));
        }
        let source_path = fs::canonicalize(source_path).map_err(|error| {
            OxidraError::Config(format!(
                "cannot resolve MCP config {}: {error}",
                source_path.display()
            ))
        })?;
        if !source_path.starts_with(&project_root) {
            return Err(OxidraError::Config(format!(
                "MCP config {} is outside project root {}",
                source_path.display(),
                project_root.display()
            )));
        }
        let bytes = fs::read(&source_path)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(OxidraError::Config(format!(
                "MCP config exceeds {MAX_CONFIG_BYTES} bytes: {}",
                source_path.display()
            )));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            OxidraError::Config(format!(
                "MCP config is not UTF-8: {}",
                source_path.display()
            ))
        })?;
        let raw: RawProjectConfig = toml::from_str(text).map_err(|error: toml::de::Error| {
            OxidraError::Config(format!(
                "invalid MCP config {}: {}",
                source_path.display(),
                error.message()
            ))
        })?;
        if raw.version != MCP_PROJECT_CONFIG_VERSION_V1 {
            return Err(OxidraError::Config(format!(
                "unsupported MCP project config version {}; expected {MCP_PROJECT_CONFIG_VERSION_V1}",
                raw.version
            )));
        }
        if raw.servers.is_empty() || raw.servers.len() > MAX_SERVERS {
            return Err(OxidraError::Config(format!(
                "MCP config must contain 1-{MAX_SERVERS} servers"
            )));
        }

        let mut names = BTreeSet::new();
        let mut servers = Vec::with_capacity(raw.servers.len());
        for raw_server in raw.servers {
            if !names.insert(raw_server.name.clone()) {
                return Err(OxidraError::Config(format!(
                    "MCP config contains duplicate server name {:?}",
                    raw_server.name
                )));
            }
            if raw_server.args.len() > MAX_ARGS
                || raw_server
                    .args
                    .iter()
                    .any(|argument| argument.is_empty() || argument.len() > MAX_ARG_BYTES)
            {
                return Err(OxidraError::Config(format!(
                    "MCP server {} args must contain at most {MAX_ARGS} non-empty values of at most {MAX_ARG_BYTES} bytes",
                    raw_server.name
                )));
            }
            if raw_server.inherit_env.len() > MAX_INHERITED_ENV {
                return Err(OxidraError::Config(format!(
                    "MCP server {} inherits more than {MAX_INHERITED_ENV} environment variables",
                    raw_server.name
                )));
            }
            if !raw_server.command.is_absolute() {
                return Err(OxidraError::Config(format!(
                    "MCP server {} command must be an absolute path",
                    raw_server.name
                )));
            }
            let cwd = match raw_server.cwd {
                Some(cwd) => {
                    if cwd.is_absolute() {
                        return Err(OxidraError::Config(format!(
                            "MCP server {} cwd must be relative to the project root",
                            raw_server.name
                        )));
                    }
                    let cwd = fs::canonicalize(project_root.join(&cwd)).map_err(|error| {
                        OxidraError::Config(format!(
                            "cannot resolve MCP server {} cwd {}: {error}",
                            raw_server.name,
                            cwd.display()
                        ))
                    })?;
                    if !cwd.starts_with(&project_root) || !cwd.is_dir() {
                        return Err(OxidraError::Config(format!(
                            "MCP server {} cwd escapes the project root",
                            raw_server.name
                        )));
                    }
                    cwd
                }
                None => project_root.clone(),
            };
            let mut server = McpStdioConfig::new(raw_server.name, raw_server.command);
            server.args = raw_server.args;
            server.cwd = Some(cwd);
            server.inherit_env = raw_server.inherit_env;
            servers.push(server.prepare()?);
        }

        let source_sha256 = hex::encode(Sha256::digest(&bytes));
        let execution_plan_digest = execution_plan_digest_v1(&source_sha256, &servers)?;

        Ok(Self {
            source_path,
            source_sha256,
            execution_plan_digest,
            servers,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub fn execution_plan_digest(&self) -> &str {
        &self.execution_plan_digest
    }

    pub fn servers(&self) -> &[PreparedMcpStdioConfig] {
        &self.servers
    }
}

fn execution_plan_digest_v1(
    source_sha256: &str,
    servers: &[PreparedMcpStdioConfig],
) -> Result<String> {
    let servers = servers
        .iter()
        .map(ExecutionServerDigestV1::from)
        .collect::<Vec<_>>();
    let payload = ExecutionPlanDigestV1 {
        execution_plan_version: MCP_EXECUTION_PLAN_VERSION_V1,
        project_config_version: MCP_PROJECT_CONFIG_VERSION_V1,
        source_sha256,
        servers: &servers,
    };
    execution_plan_payload_digest_v1(&payload)
}

fn execution_plan_payload_digest_v1(payload: &ExecutionPlanDigestV1<'_>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}

#[derive(Serialize)]
struct ExecutionPlanDigestV1<'a> {
    execution_plan_version: u32,
    project_config_version: u32,
    source_sha256: &'a str,
    servers: &'a [ExecutionServerDigestV1<'a>],
}

#[derive(Serialize)]
struct ExecutionServerDigestV1<'a> {
    name: &'a str,
    command: EncodedOsValueV1,
    args: &'a [String],
    cwd: Option<EncodedOsValueV1>,
    inherit_env: &'a [String],
    inherited_env: Vec<InheritedEnvironmentDigestV1<'a>>,
    explicit_env: &'a std::collections::BTreeMap<String, String>,
}

impl<'a> From<&'a PreparedMcpStdioConfig> for ExecutionServerDigestV1<'a> {
    fn from(server: &'a PreparedMcpStdioConfig) -> Self {
        let inherited_env = server
            .inherit_env()
            .iter()
            .map(|name| InheritedEnvironmentDigestV1 {
                name,
                value: server
                    .inherited_env()
                    .get(name)
                    .map(|value| encode_os_value_v1(value.as_os_str())),
            })
            .collect();
        Self {
            name: server.name(),
            command: encode_os_value_v1(server.command().as_os_str()),
            args: server.args(),
            cwd: server
                .cwd()
                .map(|path| encode_os_value_v1(path.as_os_str())),
            inherit_env: server.inherit_env(),
            inherited_env,
            explicit_env: server.explicit_env(),
        }
    }
}

#[derive(Serialize)]
struct InheritedEnvironmentDigestV1<'a> {
    name: &'a str,
    value: Option<EncodedOsValueV1>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct EncodedOsValueV1 {
    encoding: &'static str,
    data_hex: String,
}

#[cfg(unix)]
fn encode_os_value_v1(value: &OsStr) -> EncodedOsValueV1 {
    use std::os::unix::ffi::OsStrExt;

    EncodedOsValueV1 {
        encoding: "unix-bytes",
        data_hex: hex::encode(value.as_bytes()),
    }
}

#[cfg(windows)]
fn encode_os_value_v1(value: &OsStr) -> EncodedOsValueV1 {
    use std::os::windows::ffi::OsStrExt;

    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    EncodedOsValueV1 {
        encoding: "windows-wtf16le",
        data_hex: hex::encode(bytes),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProjectConfig {
    version: u32,
    servers: Vec<RawServerConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerConfig {
    name: String,
    command: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<PathBuf>,
    #[serde(default)]
    inherit_env: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted_path(path: &Path) -> String {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    fn write_config(root: &Path, body: &str) -> PathBuf {
        let path = root.join("mcp.toml");
        fs::write(&path, body).expect("write MCP config fixture");
        path.canonicalize()
            .expect("canonicalize MCP config fixture")
    }

    #[test]
    fn project_config_requires_explicit_absolute_local_file_and_frozen_schema() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("nested")).expect("create project fixture");
        let executable = std::env::current_exe().expect("resolve test executable");
        let path = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\ncwd = \"nested\"\ninherit_env = [\"PATH\"]\n",
                quoted_path(&executable)
            ),
        );
        let config = McpProjectConfig::load(&root, &path).expect("load MCP config");
        assert_eq!(config.servers().len(), 1);
        let expected_cwd = root
            .join("nested")
            .canonicalize()
            .expect("canonicalize expected cwd");
        assert_eq!(config.servers()[0].cwd(), Some(expected_cwd.as_path()));
        assert_eq!(config.source_sha256().len(), 64);
        assert_eq!(config.execution_plan_digest().len(), 64);
        assert_eq!(config.source_path(), path);

        assert!(McpProjectConfig::load(&root, Path::new("mcp.toml")).is_err());

        let unknown = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\n[servers.env]\nSECRET = \"must-not-be-in-project-config\"\n",
                quoted_path(&executable)
            ),
        );
        assert!(
            McpProjectConfig::load(&root, &unknown)
                .unwrap_err()
                .to_string()
                .contains("invalid MCP config")
        );
    }

    #[test]
    fn project_config_rejects_duplicate_servers_and_cwd_escape() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).expect("create project fixture");
        fs::create_dir_all(&outside).expect("create outside fixture");
        let executable = quoted_path(&std::env::current_exe().expect("resolve test executable"));
        let duplicate = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"same\"\ncommand = \"{executable}\"\n\n[[servers]]\nname = \"same\"\ncommand = \"{executable}\"\n"
            ),
        );
        assert!(
            McpProjectConfig::load(&root, &duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate server")
        );

        let escaped = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"escape\"\ncommand = \"{executable}\"\ncwd = \"../outside\"\n"
            ),
        );
        assert!(
            McpProjectConfig::load(&root, &escaped)
                .unwrap_err()
                .to_string()
                .contains("escapes the project root")
        );
    }

    #[test]
    fn prepared_config_freezes_canonical_target_and_execution_identity() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("nested")).expect("create project fixture");
        let target_a = root.join("server-a.bin");
        let target_b = root.join("server-b.bin");
        fs::write(&target_a, b"a").expect("write first target");
        fs::write(&target_b, b"b").expect("write second target");
        let configured_a = root.join("nested").join("..").join("server-a.bin");
        let config_path = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\n",
                quoted_path(&configured_a)
            ),
        );
        let config = McpProjectConfig::load(&root, &config_path).expect("load MCP config");
        let prepared_command = config.servers()[0].command().to_path_buf();
        assert_eq!(
            prepared_command,
            target_a.canonicalize().expect("canonicalize target a")
        );
        let original_digest = config.execution_plan_digest().to_owned();

        fs::write(
            &config_path,
            format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\n",
                quoted_path(&target_b)
            ),
        )
        .expect("rewrite MCP config");
        assert_eq!(config.servers()[0].command(), prepared_command.as_path());
        assert_eq!(config.execution_plan_digest(), original_digest);

        let reloaded = McpProjectConfig::load(&root, &config_path).expect("reload MCP config");
        assert_eq!(
            reloaded.servers()[0].command(),
            target_b.canonicalize().expect("canonicalize target b")
        );
        assert_ne!(reloaded.execution_plan_digest(), original_digest);
    }

    #[test]
    fn prepared_config_is_not_retargeted_by_later_symlink_changes() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("create project fixture");
        let target_a = root.join("server-a.bin");
        let target_b = root.join("server-b.bin");
        fs::write(&target_a, b"a").expect("write first target");
        fs::write(&target_b, b"b").expect("write second target");
        let link = root.join("server-link.bin");
        if !make_file_link(&target_a, &link) {
            eprintln!("skipping symlink fixture: symbolic links are unavailable");
            return;
        }
        let config_path = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\n",
                quoted_path(&link)
            ),
        );
        let config = McpProjectConfig::load(&root, &config_path).expect("load MCP config");
        let original_digest = config.execution_plan_digest().to_owned();
        assert_eq!(
            config.servers()[0].command(),
            target_a.canonicalize().expect("canonicalize target a")
        );

        fs::remove_file(&link).expect("remove first link");
        assert!(make_file_link(&target_b, &link));
        assert_eq!(
            config.servers()[0].command(),
            target_a.canonicalize().expect("canonicalize target a")
        );
        assert_eq!(config.execution_plan_digest(), original_digest);
        let reloaded = McpProjectConfig::load(&root, &config_path).expect("reload MCP config");
        assert_eq!(
            reloaded.servers()[0].command(),
            target_b.canonicalize().expect("canonicalize target b")
        );
        assert_ne!(reloaded.execution_plan_digest(), original_digest);
    }

    #[test]
    fn lossless_os_encoding_distinguishes_lossy_path_collisions() {
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;
            let first = OsString::from_vec(vec![0x80]);
            let second = OsString::from_vec(vec![0x81]);
            assert_eq!(first.to_string_lossy(), second.to_string_lossy());
            assert_ne!(
                encode_os_value_v1(first.as_os_str()),
                encode_os_value_v1(second.as_os_str())
            );
        }
        #[cfg(windows)]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            let first = OsString::from_wide(&[0xd800]);
            let second = OsString::from_wide(&[0xd801]);
            assert_eq!(first.to_string_lossy(), second.to_string_lossy());
            assert_ne!(
                encode_os_value_v1(first.as_os_str()),
                encode_os_value_v1(second.as_os_str())
            );
        }
    }

    #[test]
    fn execution_plan_digest_v1_is_frozen() {
        let args = vec!["--stdio".to_owned()];
        let inherit_env = vec!["HOME".to_owned()];
        let explicit_env =
            std::collections::BTreeMap::from([("MODE".to_owned(), "fixture".to_owned())]);
        let servers = vec![ExecutionServerDigestV1 {
            name: "fixture",
            command: EncodedOsValueV1 {
                encoding: "unix-bytes",
                data_hex: "2f746f6f6c732f66697874757265".to_owned(),
            },
            args: &args,
            cwd: Some(EncodedOsValueV1 {
                encoding: "unix-bytes",
                data_hex: "2f776f726b7370616365".to_owned(),
            }),
            inherit_env: &inherit_env,
            inherited_env: vec![InheritedEnvironmentDigestV1 {
                name: &inherit_env[0],
                value: Some(EncodedOsValueV1 {
                    encoding: "unix-bytes",
                    data_hex: "2f686f6d652f66697874757265".to_owned(),
                }),
            }],
            explicit_env: &explicit_env,
        }];
        let payload = ExecutionPlanDigestV1 {
            execution_plan_version: MCP_EXECUTION_PLAN_VERSION_V1,
            project_config_version: MCP_PROJECT_CONFIG_VERSION_V1,
            source_sha256: &"a".repeat(64),
            servers: &servers,
        };
        assert_eq!(
            execution_plan_payload_digest_v1(&payload)
                .expect("compute execution-plan fixture digest"),
            "9726e289677890bde47190b36ccf76b601c9838c0a2ce5d92af23a614f9fb228"
        );
    }

    #[cfg(unix)]
    fn make_file_link(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn make_file_link(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}
