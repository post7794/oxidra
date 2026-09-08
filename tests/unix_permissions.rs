#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use oxidra::session::{SessionHeader, SessionStore};
use tempfile::TempDir;

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn session_state_and_read_only_exports_are_private() {
    let temp = TempDir::new().unwrap();
    let data = temp.path().join("oxidra");
    for name in ["sessions", "artifacts", "locks"] {
        fs::create_dir_all(data.join(name)).unwrap();
        fs::set_permissions(data.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();

    let store = SessionStore::new(&data).unwrap();
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&store.layout().sessions_dir), 0o700);
    assert_eq!(mode(&store.layout().artifacts_dir), 0o700);
    assert_eq!(mode(&store.layout().locks_dir), 0o700);

    let session_id = "private-modes";
    let journal = store
        .create_with_id(session_id, SessionHeader::new("project", "model"))
        .unwrap();
    let journal_path = journal.journal_path().to_owned();
    let artifact_dir = journal.artifact_dir().to_owned();
    let lock_path = store.layout().lock_path(session_id).unwrap();
    assert_eq!(mode(&journal_path), 0o600);
    assert_eq!(mode(&artifact_dir), 0o700);
    assert_eq!(mode(&lock_path), 0o600);
    drop(journal);

    let destination = temp.path().join("snapshot.oxidra-session-export");
    store
        .export_read_only_snapshot(session_id, &destination)
        .unwrap();
    assert_eq!(mode(&destination), 0o600);
}
