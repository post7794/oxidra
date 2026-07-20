use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{OxidraError, Result};

pub const MAX_MEMORY_FILE_BYTES: usize = 64 * 1024;
pub const MAX_INJECTED_MEMORY_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryEntry {
    pub id: String,
    pub content: String,
    pub modified: DateTime<Utc>,
    pub bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryInjection {
    pub text: String,
    pub omitted: usize,
    pub included: usize,
}

#[derive(Clone, Debug)]
pub struct MemoryStore {
    directory: PathBuf,
}

impl MemoryStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    pub fn list(&self) -> Result<Vec<MemoryEntry>> {
        self.load_entries().map(|(entries, _)| entries)
    }

    fn load_entries(&self) -> Result<(Vec<MemoryEntry>, usize)> {
        let mut entries = Vec::new();
        let mut unreadable = 0;
        for item in fs::read_dir(&self.directory)? {
            let item = item?;
            let path = item.path();
            if path.extension().and_then(|value| value.to_str()) != Some("md") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                unreadable += 1;
                continue;
            }
            if metadata.len() > MAX_MEMORY_FILE_BYTES as u64 {
                unreadable += 1;
                continue;
            }
            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            entries.push(MemoryEntry {
                id: id.to_owned(),
                bytes: content.len(),
                content,
                modified: DateTime::<Utc>::from(modified),
            });
        }
        entries.sort_by(|left, right| {
            right
                .modified
                .cmp(&left.modified)
                .then_with(|| right.id.cmp(&left.id))
        });
        Ok((entries, unreadable))
    }

    pub fn show(&self, id: &str) -> Result<String> {
        validate_id(id)?;
        let path = self.path_for(id);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| OxidraError::Config(format!("memory {id} not found: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(OxidraError::Config(format!(
                "memory {id} is not a regular file"
            )));
        }
        if metadata.len() > MAX_MEMORY_FILE_BYTES as u64 {
            return Err(OxidraError::Config(format!(
                "memory {id} exceeds {MAX_MEMORY_FILE_BYTES} bytes"
            )));
        }
        Ok(fs::read_to_string(path)?)
    }

    pub fn remember(&self, content: &str) -> Result<MemoryEntry> {
        if content.trim().is_empty() {
            return Err(OxidraError::tool(
                "validation_error",
                "memory content must not be empty",
            ));
        }
        if content.len() > MAX_MEMORY_FILE_BYTES {
            return Err(OxidraError::tool(
                "validation_error",
                format!("memory content exceeds {MAX_MEMORY_FILE_BYTES} bytes"),
            ));
        }
        fs::create_dir_all(&self.directory)?;
        let id = Uuid::now_v7().to_string();
        let path = self.path_for(&id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        let modified = file
            .metadata()?
            .modified()
            .unwrap_or_else(|_| SystemTime::now());
        Ok(MemoryEntry {
            id,
            content: content.to_owned(),
            bytes: content.len(),
            modified: DateTime::<Utc>::from(modified),
        })
    }

    pub fn forget(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        let path = self.path_for(id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(OxidraError::Config(format!(
                        "memory {id} is not a regular file"
                    )));
                }
                fs::remove_file(path)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Packs complete memory entries in deterministic mtime order. An entry
    /// that does not fit is omitted as a whole; no content is summarized or
    /// partially truncated.
    pub fn injection(&self) -> Result<MemoryInjection> {
        let (entries, mut omitted) = self.load_entries()?;
        let mut text = String::new();
        let mut included = 0;
        for entry in entries {
            let rendered = format!(
                "<oxidra-memory id=\"{}\">\n{}\n</oxidra-memory>\n",
                entry.id, entry.content
            );
            if text.len().saturating_add(rendered.len()) > MAX_INJECTED_MEMORY_BYTES {
                omitted += 1;
                continue;
            }
            text.push_str(&rendered);
            included += 1;
        }
        Ok(MemoryInjection {
            text,
            omitted,
            included,
        })
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.md"))
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn validate_id(id: &str) -> Result<()> {
    if valid_id(id) {
        Ok(())
    } else {
        Err(OxidraError::Config(format!("invalid memory id: {id:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn remembers_lists_shows_and_forgets_plain_text() {
        let directory = TempDir::new().unwrap();
        let store = MemoryStore::new(directory.path()).unwrap();
        let entry = store.remember("use small focused commits").unwrap();
        assert_eq!(store.show(&entry.id).unwrap(), "use small focused commits");
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.forget(&entry.id).unwrap());
        assert!(!store.forget(&entry.id).unwrap());
    }

    #[test]
    fn injection_skips_complete_entries_that_do_not_fit() {
        let directory = TempDir::new().unwrap();
        let store = MemoryStore::new(directory.path()).unwrap();
        fs::write(
            directory
                .path()
                .join("00000000-0000-0000-0000-000000000001.md"),
            "small",
        )
        .unwrap();
        let oversized = "x".repeat(MAX_INJECTED_MEMORY_BYTES);
        fs::write(
            directory
                .path()
                .join("00000000-0000-0000-0000-000000000002.md"),
            oversized,
        )
        .unwrap();
        let injection = store.injection().unwrap();
        assert_eq!(injection.included, 1);
        assert_eq!(injection.omitted, 1);
        assert!(injection.text.contains("small"));
        assert!(!injection.text.contains(&"x".repeat(64)));
    }
}
