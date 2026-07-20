use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::user_config_dir;
use crate::error::{OxidraError, Result};

const AUTH_FILE_NAME: &str = "auth.json";
const AUTH_FILE_MAX_BYTES: u64 = 64 * 1024;
const AUTH_SCHEMA_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "oxidra";
const KEYRING_ACCOUNT: &str = "default-provider";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialStoreKind {
    #[default]
    Keyring,
    File,
}

impl std::fmt::Display for CredentialStoreKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyring => formatter.write_str("keyring"),
            Self::File => formatter.write_str("file"),
        }
    }
}

pub(crate) enum CredentialLookup {
    Missing,
    Found(String),
    BaseUrlMismatch { stored_base_url: String },
}

pub(crate) enum CredentialStatus {
    Missing,
    Bound,
    BaseUrlMismatch { stored_base_url: String },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRecord {
    version: u32,
    api_base_url: String,
    api_key: String,
}

pub(crate) struct CredentialStore {
    kind: CredentialStoreKind,
    file_path: PathBuf,
}

impl CredentialStore {
    pub(crate) fn platform_default(kind: CredentialStoreKind) -> Result<Self> {
        Ok(Self::new(kind, user_config_dir()?.join(AUTH_FILE_NAME)))
    }

    fn new(kind: CredentialStoreKind, file_path: PathBuf) -> Self {
        Self { kind, file_path }
    }

    pub(crate) fn kind(&self) -> CredentialStoreKind {
        self.kind
    }

    pub(crate) fn lookup(&self, expected_base_url: &Url) -> Result<CredentialLookup> {
        let Some(record) = self.read_record()? else {
            return Ok(CredentialLookup::Missing);
        };
        let stored_base_url = normalize_record_base_url(&record.api_base_url)?;
        if stored_base_url != expected_base_url.as_str() {
            return Ok(CredentialLookup::BaseUrlMismatch { stored_base_url });
        }
        if record.api_key.trim().is_empty() {
            return Err(OxidraError::Config(
                "stored API credential is empty; run `oxidra auth login`".to_owned(),
            ));
        }
        Ok(CredentialLookup::Found(record.api_key))
    }

    pub(crate) fn status(&self, expected_base_url: &Url) -> Result<CredentialStatus> {
        Ok(match self.lookup(expected_base_url)? {
            CredentialLookup::Missing => CredentialStatus::Missing,
            CredentialLookup::Found(_) => CredentialStatus::Bound,
            CredentialLookup::BaseUrlMismatch { stored_base_url } => {
                CredentialStatus::BaseUrlMismatch { stored_base_url }
            }
        })
    }

    pub(crate) fn save(&self, api_base_url: &Url, api_key: &str) -> Result<()> {
        if api_key.trim().is_empty() {
            return Err(OxidraError::Config("API key cannot be empty".to_owned()));
        }
        let record = CredentialRecord {
            version: AUTH_SCHEMA_VERSION,
            api_base_url: api_base_url.as_str().to_owned(),
            api_key: api_key.to_owned(),
        };
        let encoded = serde_json::to_string(&record)?;
        match self.kind {
            CredentialStoreKind::Keyring => keyring_set_password(encoded),
            CredentialStoreKind::File => write_auth_file(&self.file_path, encoded.as_bytes()),
        }
    }

    pub(crate) fn delete(&self) -> Result<bool> {
        match self.kind {
            CredentialStoreKind::Keyring => keyring_delete_credential(),
            CredentialStoreKind::File => match fs::remove_file(&self.file_path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            },
        }
    }

    fn read_record(&self) -> Result<Option<CredentialRecord>> {
        let encoded = match self.kind {
            CredentialStoreKind::Keyring => match keyring_get_password()? {
                Some(value) => value,
                None => return Ok(None),
            },
            CredentialStoreKind::File => {
                let metadata = match fs::metadata(&self.file_path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error.into()),
                };
                if metadata.len() > AUTH_FILE_MAX_BYTES {
                    return Err(OxidraError::Config(format!(
                        "credential file exceeds the {AUTH_FILE_MAX_BYTES}-byte limit"
                    )));
                }
                fs::read_to_string(&self.file_path)?
            }
        };
        let record: CredentialRecord = serde_json::from_str(&encoded)
            .map_err(|error| OxidraError::Config(format!("invalid credential record: {error}")))?;
        if record.version != AUTH_SCHEMA_VERSION {
            return Err(OxidraError::Config(format!(
                "unsupported credential record version {}",
                record.version
            )));
        }
        Ok(Some(record))
    }
}

// Secret Service's Tokio backend can deadlock when its blocking facade runs on
// a runtime worker. A dedicated OS thread also keeps native credential prompts
// and IPC from blocking Oxidra's async loop on every platform.
fn keyring_get_password() -> Result<Option<String>> {
    let result = std::thread::spawn(|| {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
        entry.get_password()
    })
    .join()
    .map_err(|_| OxidraError::Config("system credential store thread panicked".to_owned()))?;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(keyring_error(error)),
    }
}

fn keyring_set_password(encoded: String) -> Result<()> {
    std::thread::spawn(move || {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
        entry.set_password(&encoded)
    })
    .join()
    .map_err(|_| OxidraError::Config("system credential store thread panicked".to_owned()))?
    .map_err(keyring_error)
}

fn keyring_delete_credential() -> Result<bool> {
    let result = std::thread::spawn(|| {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?;
        entry.delete_credential()
    })
    .join()
    .map_err(|_| OxidraError::Config("system credential store thread panicked".to_owned()))?;
    match result {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(error) => Err(keyring_error(error)),
    }
}

fn keyring_error(error: keyring::Error) -> OxidraError {
    OxidraError::Config(format!("system credential store error: {error}"))
}

fn normalize_record_base_url(value: &str) -> Result<String> {
    let mut url = Url::parse(value).map_err(|_| {
        OxidraError::Config("stored credential has an invalid API base URL".to_owned())
    })?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url.to_string())
}

fn write_auth_file(path: &Path, encoded: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn file_store(directory: &TempDir) -> CredentialStore {
        CredentialStore::new(
            CredentialStoreKind::File,
            directory.path().join("auth.json"),
        )
    }

    #[test]
    fn file_credentials_are_bound_to_the_normalized_base_url() {
        let directory = TempDir::new().unwrap();
        let store = file_store(&directory);
        let base = Url::parse("https://example.test/v1/").unwrap();
        store.save(&base, "secret").unwrap();

        assert!(matches!(
            store.status(&base).unwrap(),
            CredentialStatus::Bound
        ));
        assert!(matches!(
            store.lookup(&base).unwrap(),
            CredentialLookup::Found(key) if key == "secret"
        ));
        assert!(matches!(
            store
                .status(&Url::parse("https://proxy.test/v1/").unwrap())
                .unwrap(),
            CredentialStatus::BaseUrlMismatch { stored_base_url }
                if stored_base_url == "https://example.test/v1/"
        ));
    }

    #[test]
    fn file_credentials_can_be_deleted_idempotently() {
        let directory = TempDir::new().unwrap();
        let store = file_store(&directory);
        let base = Url::parse("https://example.test/v1/").unwrap();
        store.save(&base, "secret").unwrap();
        assert!(store.delete().unwrap());
        assert!(!store.delete().unwrap());
        assert!(matches!(
            store.lookup(&base).unwrap(),
            CredentialLookup::Missing
        ));
    }

    #[test]
    fn credential_errors_never_echo_the_secret_payload() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("auth.json");
        fs::write(
            &path,
            r#"{"version":1,"api_base_url":"x","api_key":"secret"}"#,
        )
        .unwrap();
        let store = CredentialStore::new(CredentialStoreKind::File, path);
        let error = store
            .lookup(&Url::parse("https://example.test/v1/").unwrap())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret"));
    }
}
