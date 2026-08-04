use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
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
            .field("api_base_url", &display_safe_url(&self.api_base_url))
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
    #[serde(default)]
    models: HashMap<String, UserModelContextConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserModelContextConfig {
    context_window: Option<u64>,
    reserve_tokens: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextValueSource {
    Cli,
    Environment,
    ModelConfig,
    GlobalConfig,
    BuiltinDefault,
}

impl ContextValueSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Environment => "environment",
            Self::ModelConfig => "model_config",
            Self::GlobalConfig => "global_config",
            Self::BuiltinDefault => "builtin_default",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContextLimits {
    pub context_window: Option<u64>,
    pub reserve_tokens: u64,
    pub context_window_source: ContextValueSource,
    pub reserve_tokens_source: ContextValueSource,
}

impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            context_window: Some(DEFAULT_CONTEXT_WINDOW),
            reserve_tokens: DEFAULT_RESERVE_TOKENS,
            context_window_source: ContextValueSource::BuiltinDefault,
            reserve_tokens_source: ContextValueSource::BuiltinDefault,
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
    validate_public_base_url(&api_base_url)?;
    if !api_base_url.path().ends_with('/') {
        let path = format!("{}/", api_base_url.path());
        api_base_url.set_path(&path);
    }
    Ok(api_base_url)
}

fn validate_public_base_url(url: &Url) -> Result<()> {
    // Provider URL 会出现在诊断与审计域中，配置边界直接禁止携带秘密。
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OxidraError::Config(
            "API base URL must not contain username or password information".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OxidraError::Config(
            "API base URL must not contain query parameters or a fragment".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn display_safe_url(url: &Url) -> String {
    // 即使调用方绕过正常配置构造 ProviderConfig，显示层也必须二次脱敏。
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

impl ContextLimits {
    pub fn load(
        model: &str,
        cli_context_window: Option<u64>,
        cli_reserve_tokens: Option<u64>,
    ) -> Result<Self> {
        let user = load_user_config()?;
        let user_context = user.context.unwrap_or_default();
        let env_window = parse_env_u64("OXIDRA_CONTEXT_WINDOW")?;
        let env_reserve = parse_env_u64("OXIDRA_RESERVE_TOKENS")?;
        resolve_context_limits(
            &user_context,
            model,
            cli_context_window,
            cli_reserve_tokens,
            env_window,
            env_reserve,
        )
    }

    pub fn usable_tokens(&self) -> Option<u64> {
        self.context_window
            .map(|window| window.saturating_sub(self.reserve_tokens))
    }

    pub fn trigger_tokens(&self) -> Option<u64> {
        self.usable_tokens()
            .map(|usable| ((u128::from(usable) * 80) / 100) as u64)
    }

    pub fn target_tokens(&self) -> Option<u64> {
        self.usable_tokens().map(|usable| usable / 2)
    }
}

fn resolve_context_limits(
    user_context: &UserContextConfig,
    model: &str,
    cli_context_window: Option<u64>,
    cli_reserve_tokens: Option<u64>,
    env_window: Option<u64>,
    env_reserve: Option<u64>,
) -> Result<ContextLimits> {
    let model_context = user_context.models.get(model);
    let (context_window, context_window_source) = first_context_value(
        cli_context_window,
        env_window,
        model_context.and_then(|context| context.context_window),
        user_context.context_window,
        DEFAULT_CONTEXT_WINDOW,
    );
    let (reserve_tokens, reserve_tokens_source) = first_context_value(
        cli_reserve_tokens,
        env_reserve,
        model_context.and_then(|context| context.reserve_tokens),
        user_context.reserve_tokens,
        DEFAULT_RESERVE_TOKENS,
    );
    if context_window == 0 {
        return Err(OxidraError::Config(
            "context_window must be greater than zero".to_owned(),
        ));
    }
    if reserve_tokens >= context_window {
        return Err(OxidraError::Config(format!(
            "reserve_tokens ({reserve_tokens}) must be smaller than context_window ({context_window})"
        )));
    }
    Ok(ContextLimits {
        context_window: Some(context_window),
        reserve_tokens,
        context_window_source,
        reserve_tokens_source,
    })
}

fn first_context_value(
    cli: Option<u64>,
    environment: Option<u64>,
    model: Option<u64>,
    global: Option<u64>,
    builtin: u64,
) -> (u64, ContextValueSource) {
    if let Some(value) = cli {
        (value, ContextValueSource::Cli)
    } else if let Some(value) = environment {
        (value, ContextValueSource::Environment)
    } else if let Some(value) = model {
        (value, ContextValueSource::ModelConfig)
    } else if let Some(value) = global {
        (value, ContextValueSource::GlobalConfig)
    } else {
        (builtin, ContextValueSource::BuiltinDefault)
    }
}

impl ProjectContext {
    pub fn resolve(cwd: Option<PathBuf>) -> Result<Self> {
        let root = match cwd {
            Some(path) => canonical_directory(&path)?,
            None => default_project_root(&env::current_dir()?)?,
        };
        Ok(Self { root })
    }
}

fn default_project_root(current_dir: &Path) -> Result<PathBuf> {
    canonical_directory(current_dir)
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

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_env_u64(name: &str) -> Result<Option<u64>> {
    nonempty_env(name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| OxidraError::Config(format!("{name} must be an unsigned integer")))
        })
        .transpose()
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
            api_base_url: Url::parse(
                "https://url-user:url-password@example.test/v1/?signature=secret#fragment",
            )
            .unwrap(),
            model: DEFAULT_MODEL.to_owned(),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("sk-super-secret"));
        assert!(!rendered.contains("url-user"));
        assert!(!rendered.contains("url-password"));
        assert!(!rendered.contains("signature"));
        assert!(!rendered.contains("fragment"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn provider_base_url_rejects_secret_bearing_components_without_echoing_them() {
        for value in [
            "https://secret-user:secret-password@example.test/v1/",
            "https://example.test/v1/?signature=super-secret",
            "https://example.test/v1/#private-fragment",
        ] {
            let error = normalize_base_url(value).unwrap_err().to_string();
            assert!(!error.contains("secret-user"));
            assert!(!error.contains("secret-password"));
            assert!(!error.contains("super-secret"));
            assert!(!error.contains("private-fragment"));
        }
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
        assert_eq!(
            limits.context_window_source,
            ContextValueSource::BuiltinDefault
        );
        assert_eq!(limits.usable_tokens(), Some(111_616));
        assert_eq!(limits.trigger_tokens(), Some(89_292));
        assert_eq!(limits.target_tokens(), Some(55_808));
    }

    #[test]
    fn model_context_overrides_global_but_not_environment_or_cli() {
        let config = parse_user_config(
            Path::new("config.toml"),
            r#"
                [context]
                context_window = 128000
                reserve_tokens = 16000

                [context.models."grok-4.5"]
                context_window = 256000
                reserve_tokens = 32000
            "#,
        )
        .unwrap();
        let context = config.context.unwrap();
        let model = resolve_context_limits(&context, "grok-4.5", None, None, None, None).unwrap();
        assert_eq!(model.context_window, Some(256_000));
        assert_eq!(model.reserve_tokens, 32_000);
        assert_eq!(model.context_window_source, ContextValueSource::ModelConfig);

        let environment = resolve_context_limits(
            &context,
            "grok-4.5",
            None,
            None,
            Some(512_000),
            Some(48_000),
        )
        .unwrap();
        assert_eq!(environment.context_window, Some(512_000));
        assert_eq!(
            environment.context_window_source,
            ContextValueSource::Environment
        );

        let cli = resolve_context_limits(
            &context,
            "grok-4.5",
            Some(1_000_000),
            Some(64_000),
            Some(512_000),
            Some(48_000),
        )
        .unwrap();
        assert_eq!(cli.context_window, Some(1_000_000));
        assert_eq!(cli.context_window_source, ContextValueSource::Cli);
    }

    #[test]
    fn context_rejects_reserve_that_consumes_the_window() {
        let error = resolve_context_limits(
            &UserContextConfig::default(),
            "model",
            Some(10_000),
            Some(10_000),
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be smaller"));
    }

    #[test]
    fn project_context_keeps_the_selected_directory_as_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let nested = root.join("src").join("deep");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(&nested).unwrap();
        let resolved = default_project_root(&nested).unwrap();
        assert_eq!(resolved, nested.canonicalize().unwrap());
    }
}
