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
    pub fn resolve(cwd: Option<PathBuf>) -> Result<Self> {
        let cwd_was_explicit = cwd.is_some();
        let start = match cwd {
            Some(path) => path,
            None => env::current_dir()?,
        };
        let start = canonical_directory(&start)?;
        let root = if cwd_was_explicit {
            start
        } else {
            find_git_root(&start).unwrap_or(start)
        };
        Ok(Self { root })
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

fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        if directory.join(".git").exists() {
            return Some(directory.to_owned());
        }
        current = directory.parent();
    }
    None
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

    #[test]
    fn finds_nearest_git_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let nested = root.join("src").join("deep");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_git_root(&nested), Some(root));
    }
}
