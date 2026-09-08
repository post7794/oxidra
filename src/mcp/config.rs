use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{McpStdioConfig, PreparedMcpStdioConfig};
use crate::error::{OxidraError, Result};
use crate::untrusted_display;

pub const MCP_PROJECT_CONFIG_VERSION_V1: u32 = 1;
pub const MCP_PROJECT_CONFIG_VERSION: u32 = MCP_PROJECT_CONFIG_VERSION_V1;
pub const MCP_EXECUTION_PLAN_VERSION: u32 = 1;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_SERVERS: usize = 16;
const MAX_ARGS: usize = super::MAX_STDIO_ARGS_V1;
const MAX_ARG_BYTES: usize = super::MAX_STDIO_ARG_BYTES_V1;
const MAX_INHERITED_ENV: usize = super::MAX_STDIO_INHERITED_ENV_V1;

#[derive(Clone, Debug)]
pub struct McpProjectConfig {
    source_path: PathBuf,
    source_sha256: String,
    execution_plan_digest: String,
    servers: Vec<PreparedMcpStdioConfig>,
}

/// Capability proving that the caller approved the exact prepared execution
/// plan that will be spawned.
///
/// Approval grants the MCP process the authority of the current OS user. It is
/// not a filesystem or network sandbox, and later per-tool approval cannot
/// revoke side effects performed during server startup or discovery.
#[derive(Clone, Debug)]
pub struct ApprovedMcpProjectConfig {
    config: McpProjectConfig,
}

impl McpProjectConfig {
    /// Load an explicitly selected project-local MCP configuration.
    ///
    /// Loading is passive: it does not start code and is not itself approval.
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
            let display_name = untrusted_display::sanitize_single_line(&raw_server.name);
            if !names.insert(raw_server.name.clone()) {
                return Err(OxidraError::Config(format!(
                    "MCP config contains duplicate server name {}",
                    untrusted_display::quoted_single_line(&raw_server.name)
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
                    display_name
                )));
            }
            if raw_server.inherit_env.len() > MAX_INHERITED_ENV {
                return Err(OxidraError::Config(format!(
                    "MCP server {} inherits more than {MAX_INHERITED_ENV} environment variables",
                    display_name
                )));
            }
            if !raw_server.command.is_absolute() {
                return Err(OxidraError::Config(format!(
                    "MCP server {} command must be an absolute path",
                    display_name
                )));
            }
            let cwd = match raw_server.cwd {
                Some(cwd) => {
                    if cwd.is_absolute() {
                        return Err(OxidraError::Config(format!(
                            "MCP server {} cwd must be relative to the project root",
                            display_name
                        )));
                    }
                    let cwd = fs::canonicalize(project_root.join(&cwd)).map_err(|error| {
                        OxidraError::Config(format!(
                            "cannot resolve MCP server {} cwd {}: {error}",
                            display_name,
                            cwd.display()
                        ))
                    })?;
                    if !cwd.starts_with(&project_root) || !cwd.is_dir() {
                        return Err(OxidraError::Config(format!(
                            "MCP server {} cwd escapes the project root",
                            display_name
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
        let execution_plan_digest = execution_plan_digest(&source_sha256, &servers)?;

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

    /// Return the immutable, canonical execution plan that an approval UI
    /// must present. Registry spawn consumes these same prepared values.
    pub fn prepared_servers(&self) -> &[PreparedMcpStdioConfig] {
        &self.servers
    }

    /// Bind an external trust decision to this immutable prepared plan.
    ///
    /// The expected digest must come from the approval UI or durable trust
    /// record. Passing `self.execution_plan_digest()` without such a decision
    /// defeats the policy boundary even though the bytes still match.
    pub fn approve_execution(&self, expected_digest: &str) -> Result<ApprovedMcpProjectConfig> {
        if expected_digest != self.execution_plan_digest {
            return Err(OxidraError::Config(
                "MCP execution approval does not match the prepared plan digest".to_owned(),
            ));
        }
        Ok(ApprovedMcpProjectConfig {
            config: self.clone(),
        })
    }
}

impl ApprovedMcpProjectConfig {
    pub fn source_sha256(&self) -> &str {
        self.config.source_sha256()
    }

    pub fn execution_plan_digest(&self) -> &str {
        self.config.execution_plan_digest()
    }

    pub(super) fn servers(&self) -> &[PreparedMcpStdioConfig] {
        self.config.prepared_servers()
    }
}

fn execution_plan_digest(
    source_sha256: &str,
    servers: &[PreparedMcpStdioConfig],
) -> Result<String> {
    // The first publishable version intentionally binds the permission to
    // inherit named variables, not their values. A public SHA-256 over a
    // low-entropy secret would be an
    // offline guessing oracle. The prepared config still freezes the actual
    // values used by this spawn, but secret rotation does not change the
    // public trust identity.
    let servers = servers
        .iter()
        .map(ExecutionServerDigest::from)
        .collect::<Vec<_>>();
    let payload = ExecutionPlanDigest {
        execution_plan_version: MCP_EXECUTION_PLAN_VERSION,
        project_config_version: MCP_PROJECT_CONFIG_VERSION_V1,
        trust_model: "path-command-and-environment-capabilities",
        source_sha256,
        servers: &servers,
    };
    execution_plan_payload_digest(&payload)
}

fn execution_plan_payload_digest(payload: &ExecutionPlanDigest<'_>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}

#[derive(Serialize)]
struct ExecutionPlanDigest<'a> {
    execution_plan_version: u32,
    project_config_version: u32,
    trust_model: &'static str,
    source_sha256: &'a str,
    servers: &'a [ExecutionServerDigest<'a>],
}

#[derive(Serialize)]
struct ExecutionServerDigest<'a> {
    name: &'a str,
    command: EncodedOsValue,
    args: &'a [String],
    cwd: Option<EncodedOsValue>,
    inherit_env: &'a [String],
    explicit_env_names: Vec<&'a str>,
}

impl<'a> From<&'a PreparedMcpStdioConfig> for ExecutionServerDigest<'a> {
    fn from(server: &'a PreparedMcpStdioConfig) -> Self {
        Self {
            name: server.name(),
            command: encode_os_value(server.command().as_os_str()),
            args: server.args(),
            cwd: server.cwd().map(|path| encode_os_value(path.as_os_str())),
            inherit_env: server.inherit_env(),
            explicit_env_names: server.explicit_env().keys().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct EncodedOsValue {
    encoding: &'static str,
    data_hex: String,
}

#[cfg(unix)]
fn encode_os_value(value: &OsStr) -> EncodedOsValue {
    use std::os::unix::ffi::OsStrExt;

    EncodedOsValue {
        encoding: "unix-bytes",
        data_hex: hex::encode(value.as_bytes()),
    }
}

#[cfg(windows)]
fn encode_os_value(value: &OsStr) -> EncodedOsValue {
    use std::os::windows::ffi::OsStrExt;

    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    EncodedOsValue {
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
        assert_eq!(config.prepared_servers().len(), 1);
        let expected_cwd = root
            .join("nested")
            .canonicalize()
            .expect("canonicalize expected cwd");
        assert_eq!(
            config.prepared_servers()[0].cwd(),
            Some(expected_cwd.as_path())
        );
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
        let prepared_command = config.prepared_servers()[0].command().to_path_buf();
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
        assert_eq!(
            config.prepared_servers()[0].command(),
            prepared_command.as_path()
        );
        assert_eq!(config.execution_plan_digest(), original_digest);

        let reloaded = McpProjectConfig::load(&root, &config_path).expect("reload MCP config");
        assert_eq!(
            reloaded.prepared_servers()[0].command(),
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
            config.prepared_servers()[0].command(),
            target_a.canonicalize().expect("canonicalize target a")
        );

        fs::remove_file(&link).expect("remove first link");
        assert!(make_file_link(&target_b, &link));
        assert_eq!(
            config.prepared_servers()[0].command(),
            target_a.canonicalize().expect("canonicalize target a")
        );
        assert_eq!(config.execution_plan_digest(), original_digest);
        let reloaded = McpProjectConfig::load(&root, &config_path).expect("reload MCP config");
        assert_eq!(
            reloaded.prepared_servers()[0].command(),
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
                encode_os_value(first.as_os_str()),
                encode_os_value(second.as_os_str())
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
                encode_os_value(first.as_os_str()),
                encode_os_value(second.as_os_str())
            );
        }
    }

    #[test]
    fn execution_plan_digest_is_frozen_without_environment_values() {
        let args = vec!["--stdio".to_owned()];
        let inherit_env = vec!["HOME".to_owned()];
        let explicit_env =
            std::collections::BTreeMap::from([("MODE".to_owned(), "fixture".to_owned())]);
        let server = PreparedMcpStdioConfig {
            name: "fixture".to_owned(),
            command: PathBuf::from("/tools/fixture"),
            args,
            cwd: Some(PathBuf::from("/workspace")),
            inherit_env,
            inherited_env: std::collections::BTreeMap::from([(
                "HOME".to_owned(),
                std::ffi::OsString::from("/home/fixture"),
            )]),
            env: explicit_env,
        };
        let servers = vec![ExecutionServerDigest::from(&server)];
        let payload = ExecutionPlanDigest {
            execution_plan_version: MCP_EXECUTION_PLAN_VERSION,
            project_config_version: MCP_PROJECT_CONFIG_VERSION_V1,
            trust_model: "path-command-and-environment-capabilities",
            source_sha256: &"a".repeat(64),
            servers: &servers,
        };
        assert_eq!(
            execution_plan_payload_digest(&payload).expect("compute execution-plan fixture digest"),
            if cfg!(windows) {
                "fa1fa7c5ebfe507b578545ee6f4971f801f12e11c3d2a28f5779369d33bdf464"
            } else {
                "88c129e9e009e4b4b0ae79a24079c6270024e6bcf162728b125d05a09b6819a1"
            }
        );
    }

    #[test]
    fn execution_plan_does_not_expose_inherited_secret_values() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("create project fixture");
        let executable = std::env::current_exe().expect("resolve test executable");
        let variable = format!("OXIDRA_MCP_SECRET_{}", uuid::Uuid::now_v7().simple());
        let config_path = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\ninherit_env = [\"{variable}\"]\n",
                quoted_path(&executable)
            ),
        );
        unsafe { std::env::set_var(&variable, "first-low-entropy-secret") };
        let first = McpProjectConfig::load(&root, &config_path).expect("load first MCP config");
        unsafe { std::env::set_var(&variable, "second-low-entropy-secret") };
        let second = McpProjectConfig::load(&root, &config_path).expect("load second MCP config");
        unsafe { std::env::remove_var(&variable) };

        assert_eq!(
            first.execution_plan_digest(),
            second.execution_plan_digest()
        );
        assert_ne!(
            first.prepared_servers()[0].inherited_env.get(&variable),
            second.prepared_servers()[0].inherited_env.get(&variable)
        );
    }

    #[test]
    fn execution_plan_is_path_based_not_argument_file_content_identity() {
        let temp = tempfile::tempdir().expect("create config fixture");
        let root = temp.path().join("project");
        fs::create_dir_all(&root).expect("create project fixture");
        let executable = std::env::current_exe().expect("resolve test executable");
        let script = root.join("server.py");
        fs::write(&script, "print('first')\n").expect("write first script");
        let config_path = write_config(
            &root,
            &format!(
                "version = 1\n\n[[servers]]\nname = \"fixture\"\ncommand = \"{}\"\nargs = [\"{}\"]\n",
                quoted_path(&executable),
                quoted_path(&script)
            ),
        );
        let first = McpProjectConfig::load(&root, &config_path).expect("load first MCP config");
        fs::write(&script, "print('replacement')\n").expect("replace script content");
        let second = McpProjectConfig::load(&root, &config_path).expect("reload MCP config");

        assert_eq!(
            first.execution_plan_digest(),
            second.execution_plan_digest()
        );
        assert_eq!(first.source_sha256(), second.source_sha256());
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
