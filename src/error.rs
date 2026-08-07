use thiserror::Error;

pub type Result<T> = std::result::Result<T, OxidraError>;

#[derive(Debug, Error)]
pub enum OxidraError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("provider context window limit reached: {0}")]
    ProviderContextLimit(String),
    #[error("response aborted: {0}")]
    ResponseAborted(String),
    #[error("stream observer error: {0}")]
    Observer(#[source] Box<OxidraError>),
    #[error("tool error ({code}): {message}")]
    Tool { code: String, message: String },
    #[error("MCP error: {0}")]
    Mcp(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("approval required: {0}")]
    ApprovalRequired(String),
    #[error("context window limit reached")]
    ContextLimit,
    #[error("execution limit reached: {0}")]
    Limit(String),
    #[error("operation interrupted")]
    Interrupted,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

impl OxidraError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Toml(_) | Self::Url(_) => 2,
            Self::ApprovalRequired(_) => 3,
            Self::ContextLimit | Self::ProviderContextLimit(_) => 4,
            Self::Observer(error) => error.exit_code(),
            Self::Interrupted => 130,
            _ => 1,
        }
    }

    pub fn observer(error: Self) -> Self {
        match error {
            existing @ Self::Observer(_) => existing,
            other => Self::Observer(Box::new(other)),
        }
    }

    pub fn tool(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Tool {
            code: code.into(),
            message: message.into(),
        }
    }
}
