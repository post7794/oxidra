use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};
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
    pub provenance: MemoryProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryProvenance {
    Known {
        project_root: String,
        created: String,
    },
    Unknown,
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
            let file_text = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            let parsed = parse_memory_file(&file_text);
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            entries.push(MemoryEntry {
                id: id.to_owned(),
                bytes: file_text.len(),
                content: parsed.content,
                provenance: parsed.provenance,
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

    pub fn show(&self, id: &str) -> Result<MemoryEntry> {
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
        let file_text = fs::read_to_string(path)?;
        let parsed = parse_memory_file(&file_text);
        Ok(MemoryEntry {
            id: id.to_owned(),
            content: parsed.content,
            provenance: parsed.provenance,
            modified: DateTime::<Utc>::from(metadata.modified().unwrap_or(UNIX_EPOCH)),
            bytes: file_text.len(),
        })
    }

    pub fn remember(&self, content: &str, project_root: &Path) -> Result<MemoryEntry> {
        if content.trim().is_empty() {
            return Err(OxidraError::tool(
                "validation_error",
                "memory content must not be empty",
            ));
        }
        let project_root = project_root.to_string_lossy();
        if project_root.contains(['\r', '\n']) {
            return Err(OxidraError::tool(
                "validation_error",
                "project root cannot be represented in memory frontmatter",
            ));
        }
        let created = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let file_text = render_memory_file(&project_root, &created, content);
        if file_text.len() > MAX_MEMORY_FILE_BYTES {
            return Err(OxidraError::tool(
                "validation_error",
                format!("complete memory file exceeds {MAX_MEMORY_FILE_BYTES} bytes"),
            ));
        }
        fs::create_dir_all(&self.directory)?;
        let id = Uuid::now_v7().to_string();
        let path = self.path_for(&id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(file_text.as_bytes())?;
        file.sync_all()?;
        let modified = file
            .metadata()?
            .modified()
            .unwrap_or_else(|_| SystemTime::now());
        Ok(MemoryEntry {
            id,
            content: content.to_owned(),
            bytes: file_text.len(),
            provenance: MemoryProvenance::Known {
                project_root: project_root.into_owned(),
                created,
            },
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
        let mut injected_body_bytes = 0_usize;
        let mut included = 0;
        for entry in entries {
            if entry.content.is_empty() {
                omitted += 1;
                continue;
            }
            if injected_body_bytes.saturating_add(entry.content.len()) > MAX_INJECTED_MEMORY_BYTES {
                omitted += 1;
                continue;
            }
            if !text.is_empty() {
                text.push_str("\n\n");
            }
            text.push_str(&entry.content);
            injected_body_bytes += entry.content.len();
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

#[derive(Debug)]
struct ParsedMemory {
    content: String,
    provenance: MemoryProvenance,
}

fn render_memory_file(project_root: &str, created: &str, content: &str) -> String {
    format!("---\nproject_root: {project_root}\ncreated: {created}\n---\n{content}")
}

fn parse_memory_file(file_text: &str) -> ParsedMemory {
    let legacy = || ParsedMemory {
        content: file_text.to_owned(),
        provenance: MemoryProvenance::Unknown,
    };
    let mut lines = file_text.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return legacy();
    };
    if trim_line_ending(first) != "---" {
        return legacy();
    }

    let mut consumed = first.len();
    let mut project_root = None;
    let mut created = None;
    let mut closed = false;
    for line in lines {
        consumed += line.len();
        let line = trim_line_ending(line);
        if line == "---" {
            closed = true;
            break;
        }
        let mut parts = line.splitn(2, ':');
        let Some(key) = parts.next().map(str::trim) else {
            return legacy();
        };
        let Some(value) = parts.next().map(str::trim) else {
            return legacy();
        };
        if value.is_empty() {
            return legacy();
        }
        match key {
            "project_root" if project_root.is_none() => project_root = Some(value.to_owned()),
            "created" if created.is_none() => created = Some(value.to_owned()),
            _ => return legacy(),
        }
    }

    let (Some(project_root), Some(created)) = (project_root, created) else {
        return legacy();
    };
    if !closed || DateTime::parse_from_rfc3339(&created).is_err() {
        return legacy();
    }
    ParsedMemory {
        content: file_text[consumed..].to_owned(),
        provenance: MemoryProvenance::Known {
            project_root,
            created,
        },
    }
}

fn trim_line_ending(line: &str) -> &str {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.strip_suffix('\r').unwrap_or(line)
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
        let entry = store
            .remember("use small focused commits", Path::new(r"C:\work:tree"))
            .unwrap();
        let shown = store.show(&entry.id).unwrap();
        assert_eq!(shown.content, "use small focused commits");
        assert!(matches!(
            shown.provenance,
            MemoryProvenance::Known { ref project_root, .. } if project_root == r"C:\work:tree"
        ));
        let raw = fs::read_to_string(store.path_for(&entry.id)).unwrap();
        let header = raw.lines().take(4).collect::<Vec<_>>();
        assert_eq!(header[0], "---");
        assert_eq!(header[1], r"project_root: C:\work:tree");
        assert!(header[2].starts_with("created: "));
        assert_eq!(header[3], "---");
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.forget(&entry.id).unwrap());
        assert!(!store.forget(&entry.id).unwrap());
    }

    #[test]
    fn parses_windows_path_and_timestamp_colons_without_splitting_values() {
        let file = concat!(
            "---\n",
            "project_root: C:\\Users\\me\\repo:work\n",
            "created: 2026-07-20T12:34:56+08:00\n",
            "---\n",
            "body"
        );
        let parsed = parse_memory_file(file);
        assert_eq!(parsed.content, "body");
        assert_eq!(
            parsed.provenance,
            MemoryProvenance::Known {
                project_root: r"C:\Users\me\repo:work".to_owned(),
                created: "2026-07-20T12:34:56+08:00".to_owned(),
            }
        );
    }

    #[test]
    fn legacy_file_without_frontmatter_is_all_body_with_unknown_provenance() {
        let file = "legacy: body\nwith all text";
        let parsed = parse_memory_file(file);
        assert_eq!(parsed.content, file);
        assert_eq!(parsed.provenance, MemoryProvenance::Unknown);
    }

    #[test]
    fn frontmatter_with_any_extra_key_falls_back_without_losing_text() {
        let file = concat!(
            "---\n",
            "project_root: C:\\repo\n",
            "created: 2026-07-20T12:34:56+08:00\n",
            "tags: forbidden\n",
            "---\n",
            "body"
        );
        let parsed = parse_memory_file(file);
        assert_eq!(parsed.content, file);
        assert_eq!(parsed.provenance, MemoryProvenance::Unknown);
    }

    #[test]
    fn complete_file_size_is_checked_before_write() {
        let directory = TempDir::new().unwrap();
        let store = MemoryStore::new(directory.path()).unwrap();
        let project = Path::new("project");
        let overhead = render_memory_file("project", "2026-07-20T00:00:00Z", "").len();
        let fitting = "x".repeat(MAX_MEMORY_FILE_BYTES - overhead);
        let entry = store.remember(&fitting, project).unwrap();
        assert_eq!(entry.bytes, MAX_MEMORY_FILE_BYTES);
        assert_eq!(
            fs::metadata(store.path_for(&entry.id)).unwrap().len(),
            MAX_MEMORY_FILE_BYTES as u64
        );

        let too_large = "x".repeat(MAX_MEMORY_FILE_BYTES - overhead + 1);
        assert!(store.remember(&too_large, project).is_err());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn injection_strips_frontmatter_and_budgets_only_body() {
        let directory = TempDir::new().unwrap();
        let store = MemoryStore::new(directory.path()).unwrap();
        let id = "00000000-0000-0000-0000-000000000001";
        let body = "x".repeat(MAX_INJECTED_MEMORY_BYTES);
        let file = render_memory_file(r"C:\repo:with-colon", "2026-07-20T12:34:56+08:00", &body);
        assert!(file.len() > MAX_INJECTED_MEMORY_BYTES);
        fs::write(store.path_for(id), file).unwrap();

        let injection = store.injection().unwrap();
        assert_eq!(injection.included, 1);
        assert_eq!(injection.omitted, 0);
        assert_eq!(injection.text, body);
        assert!(!injection.text.contains("project_root"));
        assert!(!injection.text.contains("created:"));
        assert!(!injection.text.contains(r"C:\repo:with-colon"));
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
        let oversized = "x".repeat(MAX_INJECTED_MEMORY_BYTES + 1);
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
