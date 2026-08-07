use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::McpStdioConfig;
use crate::error::{OxidraError, Result};

pub const MCP_PROJECT_CONFIG_VERSION: u32 = 1;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_SERVERS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_INHERITED_ENV: usize = 32;

#[derive(Clone, Debug)]
pub struct McpProjectConfig {
    source_path: PathBuf,
    source_sha256: String,
    servers: Vec<McpStdioConfig>,
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
        if raw.version != MCP_PROJECT_CONFIG_VERSION {
            return Err(OxidraError::Config(format!(
                "unsupported MCP project config version {}; expected {MCP_PROJECT_CONFIG_VERSION}",
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
            server.validate()?;
            servers.push(server);
        }

        Ok(Self {
            source_path,
            source_sha256: hex::encode(Sha256::digest(&bytes)),
            servers,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub fn servers(&self) -> &[McpStdioConfig] {
        &self.servers
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
        assert_eq!(
            config.servers()[0].cwd.as_deref(),
            Some(expected_cwd.as_path())
        );
        assert_eq!(config.source_sha256().len(), 64);
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
}
