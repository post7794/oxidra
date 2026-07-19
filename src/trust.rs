use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::ProjectContext;
use crate::error::{OxidraError, Result};
use crate::session::user_data_dir;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TrustDatabase {
    #[serde(default)]
    projects: BTreeMap<String, TrustRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrustRecord {
    execution_hash: String,
}

#[derive(Clone, Debug)]
pub struct TrustStore {
    path: PathBuf,
    database: TrustDatabase,
}

impl TrustStore {
    pub fn load() -> Result<Self> {
        let path = user_data_dir()?.join("trust.json");
        let database = if path.is_file() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            TrustDatabase::default()
        };
        Ok(Self { path, database })
    }

    pub fn is_trusted(&self, root: &Path, execution_hash: &str) -> bool {
        self.database
            .projects
            .get(&root_key(root))
            .is_some_and(|record| record.execution_hash == execution_hash)
    }

    pub fn trust(&mut self, root: &Path, execution_hash: String) -> Result<()> {
        self.database
            .projects
            .insert(root_key(root), TrustRecord { execution_hash });
        self.save()
    }

    pub fn revoke(&mut self, root: &Path) -> Result<()> {
        self.database.projects.remove(&root_key(root));
        self.save()
    }

    fn save(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| OxidraError::Config("invalid trust database path".to_owned()))?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".trust-{}.tmp", uuid::Uuid::now_v7()));
        {
            let mut file = fs::File::create(&temporary)?;
            serde_json::to_writer_pretty(&mut file, &self.database)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        if let Err(error) = replace_existing(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        Ok(())
    }
}

#[cfg(windows)]
fn replace_existing(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_existing(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

pub fn execution_hash(project: &ProjectContext) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_path(&mut hasher, &project.root);

    if let Some(config_path) = &project.config_path {
        hash_file(&mut hasher, config_path)?;
    } else {
        hasher.update(b"no-project-config");
    }

    let lock_path = project.root.join(".oxidra").join("lock.toml");
    if lock_path.is_file() {
        hash_file(&mut hasher, &lock_path)?;
    }

    let mut manifests: Vec<_> = project
        .config
        .plugins
        .iter()
        .map(|plugin| project.resolve_manifest(&plugin.manifest))
        .collect();
    manifests.sort();
    for manifest in manifests {
        hash_file(&mut hasher, &manifest)?;
        hash_manifest_executable(&mut hasher, &manifest)?;
    }

    Ok(hex::encode(hasher.finalize()))
}

fn hash_manifest_executable(hasher: &mut Sha256, manifest_path: &Path) -> Result<()> {
    let bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()),
    };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(());
    };
    let Some(command) = manifest.get("command").and_then(Value::as_str) else {
        return Ok(());
    };
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let candidate = resolve_manifest_executable(command, manifest_dir);
    match candidate {
        Some(candidate) if candidate.is_file() => hash_file(hasher, &candidate)?,
        Some(candidate) => {
            hash_path(hasher, &candidate);
            hasher.update(b"missing-executable");
        }
        None => {
            hasher.update(b"unresolved-command:");
            hasher.update(command.as_bytes());
        }
    }

    // Interpreted plugins commonly pass their entrypoint as an argument (for
    // example `python plugin.py`). Bind any argument that names a file next to
    // the manifest so replacing the script revokes trust as well.
    if let Some(args) = manifest.get("args").and_then(Value::as_array) {
        for argument in args.iter().filter_map(Value::as_str) {
            let path = Path::new(argument);
            let candidate =
                if path.is_absolute() || argument.contains('/') || argument.contains('\\') {
                    if path.is_absolute() {
                        path.to_owned()
                    } else {
                        manifest_dir.join(path)
                    }
                } else {
                    manifest_dir.join(path)
                };
            if candidate.is_file() {
                hash_file(hasher, &candidate)?;
            }
        }
    }
    Ok(())
}

fn resolve_manifest_executable(command: &str, manifest_dir: &Path) -> Option<PathBuf> {
    let command_path = Path::new(command);
    if command_path.is_absolute() || command.contains('/') || command.contains('\\') {
        return Some(if command_path.is_absolute() {
            command_path.to_owned()
        } else {
            manifest_dir.join(command_path)
        });
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        if candidate.extension().is_none() {
            let extensions = std::env::var_os("PATHEXT")
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_owned());
            for extension in extensions
                .split(';')
                .filter(|extension| !extension.is_empty())
            {
                let mut with_extension = candidate.as_os_str().to_os_string();
                with_extension.push(extension);
                let with_extension = PathBuf::from(with_extension);
                if with_extension.is_file() {
                    return Some(with_extension);
                }
            }
        }
    }
    None
}

fn hash_file(hasher: &mut Sha256, path: &Path) -> Result<()> {
    hash_path(hasher, path);
    let bytes = fs::read(path).map_err(|error| {
        OxidraError::Config(format!(
            "cannot read {} for trust hash: {error}",
            path.display()
        ))
    })?;
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

fn hash_path(hasher: &mut Sha256, path: &Path) {
    let encoded = native_path_bytes(path);
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
}

fn root_key(root: &Path) -> String {
    hex::encode(Sha256::digest(native_path_bytes(root)))
}

fn native_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(any(windows, unix)))]
    {
        path.to_string_lossy().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_requires_matching_hash() {
        let mut store = TrustStore {
            path: PathBuf::from("unused"),
            database: TrustDatabase::default(),
        };
        let root = Path::new("project");
        store.database.projects.insert(
            root_key(root),
            TrustRecord {
                execution_hash: "a".to_owned(),
            },
        );
        assert!(store.is_trusted(root, "a"));
        assert!(!store.is_trusted(root, "b"));
    }
}
