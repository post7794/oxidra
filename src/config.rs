use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::Deserialize;
use url::Url;

use crate::auth::{CredentialLookup, CredentialStore, CredentialStoreKind};
use crate::error::{OxidraError, Result};

pub const DEFAULT_MODEL: &str = "gpt-5.6-sol";
pub const DEFAULT_CONTEXT_WINDOW: u64 = 128_000;
pub const DEFAULT_RESERVE_TOKENS: u64 = 16_384;
pub const DEFAULT_API_BASE_URL: &str = "https://api.openai.com/v1/";

#[derive(Clone)]
pub struct ProviderConfig {
    pub api_key: String,
    pub api_base_url: Url,
    pub model: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderSettings {
    pub api_base_url: Url,
    pub model: String,
    pub credential_store: CredentialStoreKind,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderConfig")
            .field("api_key", &"<redacted>")
            .field("api_base_url", &self.api_base_url)
            .field("model", &self.model)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ProjectContext {
    pub root: PathBuf,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    provider: Option<UserProviderConfig>,
    auth: Option<UserAuthConfig>,
    context: Option<UserContextConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserProviderConfig {
    api_base_url: Option<String>,
    model: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAuthConfig {
    credential_store: Option<CredentialStoreKind>,
}

#[derive(Default, Deserialize)]
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
        let user_auth = user.auth.unwrap_or_default();
        let primary_key = cli_api_key.or_else(|| nonempty_env("API_KEY"));
        let (api_key, env_base_url, env_model) = if let Some(key) = primary_key {
            (
                Some(key),
                nonempty_env("API_BASE_URL"),
                nonempty_env("MODEL"),
            )
        } else if let Some(key) = nonempty_env("OPENAI_API_KEY") {
            (
                Some(key),
                nonempty_env("OPENAI_BASE_URL"),
                nonempty_env("OPENAI_MODEL"),
            )
        } else {
            (None, nonempty_env("API_BASE_URL"), nonempty_env("MODEL"))
        };
        let settings = resolve_settings(
            user_provider,
            user_auth,
            cli_base_url,
            cli_model,
            env_base_url,
            env_model,
        )?;
        let api_key = match api_key {
            Some(api_key) => api_key,
            None => {
                let store = CredentialStore::platform_default(settings.credential_store)?;
                match store.lookup(&settings.api_base_url)? {
                    CredentialLookup::Found(api_key) => api_key,
                    CredentialLookup::Missing => {
                        return Err(OxidraError::Config(
                            "missing API_KEY or stored credential; run `oxidra auth login`"
                                .to_owned(),
                        ));
                    }
                    CredentialLookup::BaseUrlMismatch { stored_base_url } => {
                        return Err(OxidraError::Config(format!(
                            "stored credential is bound to {stored_base_url}, not {}; run `oxidra auth login`",
                            settings.api_base_url
                        )));
                    }
                }
            }
        };
        Ok(Self {
            api_key,
            api_base_url: settings.api_base_url,
            model: settings.model,
        })
    }

    pub fn responses_url(&self) -> Result<Url> {
        Ok(self.api_base_url.join("responses")?)
    }
}

pub(crate) fn load_provider_settings(
    cli_base_url: Option<String>,
    cli_model: Option<String>,
) -> Result<ProviderSettings> {
    let user = load_user_config()?;
    resolve_settings(
        user.provider.unwrap_or_default(),
        user.auth.unwrap_or_default(),
        cli_base_url,
        cli_model,
        nonempty_env("API_BASE_URL").or_else(|| nonempty_env("OPENAI_BASE_URL")),
        nonempty_env("MODEL").or_else(|| nonempty_env("OPENAI_MODEL")),
    )
}

fn resolve_settings(
    user_provider: UserProviderConfig,
    user_auth: UserAuthConfig,
    cli_base_url: Option<String>,
    cli_model: Option<String>,
    env_base_url: Option<String>,
    env_model: Option<String>,
) -> Result<ProviderSettings> {
    let base_url = cli_base_url
        .or(env_base_url)
        .or(user_provider.api_base_url)
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_owned());
    let model = cli_model
        .or(env_model)
        .or(user_provider.model)
        .unwrap_or_else(|| DEFAULT_MODEL.to_owned());
    let api_base_url = normalize_base_url(&base_url)?;
    Ok(ProviderSettings {
        api_base_url,
        model,
        credential_store: user_auth.credential_store.unwrap_or_default(),
    })
}

fn normalize_base_url(base_url: &str) -> Result<Url> {
    let mut api_base_url = Url::parse(base_url)?;
    if !api_base_url.path().ends_with('/') {
        let path = format!("{}/", api_base_url.path());
        api_base_url.set_path(&path);
    }
    Ok(api_base_url)
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
    parse_user_config(&path, &text)
}

fn parse_user_config(path: &Path, text: &str) -> Result<UserConfig> {
    toml::from_str(text).map_err(|error: toml::de::Error| {
        OxidraError::Config(format!(
            "invalid user config {}: {}",
            path.display(),
            error.message()
        ))
    })
}

pub(crate) fn user_config_dir() -> Result<PathBuf> {
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
    fn provider_config_debug_redacts_api_key() {
        let config = ProviderConfig {
            api_key: "sk-super-secret".to_owned(),
            api_base_url: Url::parse("https://example.test/v1/").unwrap(),
            model: DEFAULT_MODEL.to_owned(),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("sk-super-secret"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn parses_persistent_provider_credentials() {
        let config = parse_user_config(
            Path::new("config.toml"),
            r#"
                [provider]
                api_base_url = "https://example.test/v1"
                model = "configured-model"

                [auth]
                credential_store = "file"
            "#,
        )
        .unwrap();
        let provider = config.provider.unwrap();
        assert_eq!(
            provider.api_base_url.as_deref(),
            Some("https://example.test/v1")
        );
        assert_eq!(provider.model.as_deref(), Some("configured-model"));
        assert_eq!(
            config.auth.unwrap().credential_store,
            Some(CredentialStoreKind::File)
        );
    }

    #[test]
    fn legacy_inline_provider_key_is_rejected_without_echoing_secret() {
        let error = parse_user_config(
            Path::new("config.toml"),
            "[provider]\napi_key = \"sk-secret\"\n",
        )
        .err()
        .unwrap();
        let rendered = error.to_string();
        assert!(rendered.contains("invalid user config"));
        assert!(!rendered.contains("sk-secret"));
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
