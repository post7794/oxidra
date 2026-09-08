//! Small platform-specific helpers for private durable state files.
//!
//! Unix mode-bit hygiene is part of the session trust boundary: journals and
//! execution markers contain prompts, provider responses and tool results.
//! These helpers do not enumerate or remove extended/POSIX ACL entries and do
//! not attest remote-filesystem permission semantics; deployments must choose a
//! data root whose enclosing namespace and additional ACLs are already trusted.
//! Windows currently relies on the caller's data-root ACL; these helpers are
//! intentionally no-ops there rather than pretending mode bits provide an
//! ACL guarantee.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn enforce_private_file(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub(crate) fn private_create_options(_options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        _options.mode(0o600);
    }
}

pub(crate) async fn ensure_private_dir_async(path: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

/// Applies the private-file mode to the exact async file handle already opened
/// by the caller, rather than resolving the pathname a second time.
pub(crate) async fn enforce_private_file_handle_async(_file: &tokio::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .await?;
    }
    Ok(())
}

/// Opens a path for reading while refusing to follow a racing final-component
/// symbolic link/reparse point on supported platforms. Callers must still
/// inspect metadata from the returned handle and must not treat this as
/// handle-relative containment of the parent path.
pub(crate) async fn open_read_only_no_follow(path: &Path) -> io::Result<File> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            // FILE_FLAG_OPEN_REPARSE_POINT
            options.custom_flags(0x0020_0000);
        }
        options.open(path)
    })
    .await
    .map_err(|error| io::Error::other(format!("filesystem open worker failed: {error}")))?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_open_does_not_follow_the_final_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.txt");
        let link = directory.path().join("link.txt");
        fs::write(&target, "secret").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        open_read_only_no_follow(&link)
            .await
            .expect_err("final symlink must not be followed");
    }
}
