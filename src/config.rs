use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::Deserialize;
use url::Url;

use crate::error::{OxidraError, Result};

pub const DEFAULT_MODEL: &str = "gpt-5.6-sol";
pub const DEFAULT_CONTEXT_WINDOW: u64 = 128_000;
pub const DEFAULT_RESERVE_TOKENS: u64 = 16_384;
pub const DEFAULT_API_BASE_URL: &str = "https://api.openai.com/v1/";

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub api_key: String,
    pub api_base_url: Url,
    pub model: String,
}

#[derive(Clone, Debug)]
pub struct ProjectContext {
    pub root: PathBuf,
    pub config_path: Option<PathBuf>,
    pub config: ProjectConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(default)]
    pub plugins: Vec<ProjectPlugin>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPlugin {
    pub name: String,
    pub manifest: PathBuf,
    #[serde(default = "default_activation")]
    pub activation: String,
}

fn default_activation() -> String {
    "on_call".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    provider: Option<UserProviderConfig>,
    context: Option<UserContextConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserProviderConfig {
    api_base_url: Option<String>,
    model: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserContextConfig {
    context_window: Option<u64>,
    reserve_tokens: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ContextLimits {
    pub context_window: Option<u64>,
    pub reserve_tokens: u64,
}

impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            context_window: Some(DEFAULT_CONTEXT_WINDOW),
            reserve_tokens: DEFAULT_RESERVE_TOKENS,
        }
    }
}

impl ProviderConfig {
    pub fn resolve(
        cli_api_key: Option<String>,
        cli_base_url: Option<String>,
        cli_model: Option<String>,
    ) -> Result<Self> {
        let user = load_user_config()?;
        let user_provider = user.provider.unwrap_or_default();

        let primary_key = cli_api_key.or_else(|| nonempty_env("API_KEY"));
        let (api_key, env_base_url, env_model) = if let Some(key) = primary_key {
            (key, nonempty_env("API_BASE_URL"), nonempty_env("MODEL"))
        } else if let Some(key) = nonempty_env("OPENAI_API_KEY") {
            (
                key,
                nonempty_env("OPENAI_BASE_URL"),
                nonempty_env("OPENAI_MODEL"),
            )
        } else {
            return Err(OxidraError::Config(
                "missing API_KEY (or OPENAI_API_KEY fallback)".to_owned(),
            ));
        };

        let base_url = cli_base_url
            .or(env_base_url)
            .or(user_provider.api_base_url)
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_owned());
        let model = cli_model
            .or(env_model)
            .or(user_provider.model)
            .unwrap_or_else(|| DEFAULT_MODEL.to_owned());

        let mut api_base_url = Url::parse(&base_url)?;
        if !api_base_url.path().ends_with('/') {
            let path = format!("{}/", api_base_url.path());
            api_base_url.set_path(&path);
        }

        Ok(Self {
            api_key,
            api_base_url,
            model,
        })
    }

    pub fn responses_url(&self) -> Result<Url> {
        Ok(self.api_base_url.join("responses")?)
    }
}

impl ContextLimits {
    pub fn load(cli_context_window: Option<u64>, cli_reserve_tokens: Option<u64>) -> Result<Self> {
        let user = load_user_config()?;
        let user_context = user.context.unwrap_or_default();
        Ok(Self {
            context_window: cli_context_window
                .or_else(|| parse_env_u64("OXIDRA_CONTEXT_WINDOW"))
                .or(user_context.context_window)
                .or(Some(DEFAULT_CONTEXT_WINDOW)),
            reserve_tokens: cli_reserve_tokens
                .or_else(|| parse_env_u64("OXIDRA_RESERVE_TOKENS"))
                .or(user_context.reserve_tokens)
                .unwrap_or(DEFAULT_RESERVE_TOKENS),
        })
    }
}

impl ProjectContext {
    pub fn resolve(cwd: Option<PathBuf>, config_override: Option<PathBuf>) -> Result<Self> {
        let cwd_was_explicit = cwd.is_some();
        let start = match cwd {
            Some(path) => path,
            None => env::current_dir()?,
        };
        let start = canonical_directory(&start)?;

        let (root, config_path) = if let Some(path) = config_override {
            let path = absolute_from(&start, &path);
            let path = path.canonicalize().map_err(|error| {
                OxidraError::Config(format!("cannot resolve config {}: {error}", path.display()))
            })?;
            if path.file_name().and_then(|name| name.to_str()) != Some("config.toml")
                || path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    != Some(".oxidra")
            {
                return Err(OxidraError::Config(format!(
                    "config must be named <project>/.oxidra/config.toml: {}",
                    path.display()
                )));
            }
            let root = path
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| {
                    OxidraError::Config(format!(
                        "config must be under <project>/.oxidra: {}",
                        path.display()
                    ))
                })?
                .canonicalize()?;
            (root, Some(path))
        } else if cwd_was_explicit {
            let candidate = start.join(".oxidra").join("config.toml");
            let config = candidate.is_file().then_some(candidate);
            (start, config)
        } else {
            match find_project_config(&start) {
                Some(path) => {
                    let root = path
                        .parent()
                        .and_then(Path::parent)
                        .expect("known .oxidra/config.toml shape")
                        .canonicalize()?;
                    (root, Some(path))
                }
                None => (start, None),
            }
        };

        let config = match config_path.as_deref() {
            Some(path) => {
                let text = fs::read_to_string(path)?;
                toml::from_str(&text)?
            }
            None => ProjectConfig::default(),
        };

        let mut plugin_names = HashSet::new();
        for plugin in &config.plugins {
            if !plugin_names.insert(plugin.name.as_str()) {
                return Err(OxidraError::Config(format!(
                    "duplicate plugin name {:?}",
                    plugin.name
                )));
            }
            if plugin.activation != "on_call" && plugin.activation != "eager" {
                return Err(OxidraError::Config(format!(
                    "plugin {} has invalid activation {:?}",
                    plugin.name, plugin.activation
                )));
            }
        }

        Ok(Self {
            root,
            config_path,
            config,
        })
    }

    pub fn resolve_manifest(&self, manifest: &Path) -> PathBuf {
        absolute_from(&self.root, manifest)
    }
}

pub fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", "oxidra")
        .ok_or_else(|| OxidraError::Config("cannot resolve user data directory".to_owned()))
}

fn load_user_config() -> Result<UserConfig> {
    let path = user_config_dir()?.join("config.toml");
    if !path.is_file() {
        return Ok(UserConfig::default());
    }
    let text = fs::read_to_string(&path)?;
    Ok(toml::from_str(&text)?)
}

fn user_config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    if let Some(path) = nonempty_env_path("APPDATA").or_else(|| nonempty_env_path("LOCALAPPDATA")) {
        return Ok(path.join("oxidra"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(path) = nonempty_env_path("XDG_CONFIG_HOME").filter(|path| path.is_absolute()) {
        return Ok(path.join("oxidra"));
    }

    #[cfg(target_os = "macos")]
    if let Some(path) = nonempty_env_path("HOME") {
        return Ok(path.join("Library/Application Support/oxidra"));
    }

    Ok(project_dirs()?.config_dir().to_path_buf())
}

fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|error| {
        OxidraError::Config(format!("cannot resolve cwd {}: {error}", path.display()))
    })?;
    if !canonical.is_dir() {
        return Err(OxidraError::Config(format!(
            "cwd is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        let candidate = directory.join(".oxidra").join("config.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = directory.parent();
    }
    None
}

fn absolute_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_env_u64(name: &str) -> Option<u64> {
    nonempty_env(name).and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_url_joins_without_dropping_v1() {
        let config = ProviderConfig {
            api_key: "secret".to_owned(),
            api_base_url: Url::parse("https://example.test/v1/").unwrap(),
            model: DEFAULT_MODEL.to_owned(),
        };
        assert_eq!(
            config.responses_url().unwrap().as_str(),
            "https://example.test/v1/responses"
        );
    }

    #[test]
    fn context_limits_are_bounded_by_default() {
        let limits = ContextLimits::default();
        assert_eq!(limits.context_window, Some(DEFAULT_CONTEXT_WINDOW));
        assert_eq!(limits.reserve_tokens, DEFAULT_RESERVE_TOKENS);
    }
}
