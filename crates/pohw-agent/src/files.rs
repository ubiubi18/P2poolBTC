use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    validate_existing_ancestors(path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if is_link_like(&metadata) || !metadata.is_dir() {
            bail!("{} must be a non-symlink directory", path.display());
        }
    } else {
        std::fs::create_dir_all(path)
            .with_context(|| format!("create private directory {}", path.display()))?;
    }
    set_private_dir_mode(path)?;
    Ok(())
}

fn validate_existing_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().skip(1) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_link_like(&metadata) => {
                if !trusted_system_symlink(ancestor, &metadata)? {
                    bail!(
                        "{} has an unsafe symlink ancestor {}",
                        path.display(),
                        ancestor.display()
                    );
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect directory ancestor"),
        }
    }
    Ok(())
}

pub(crate) fn is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}

#[cfg(unix)]
fn trusted_system_symlink(path: &Path, metadata: &std::fs::Metadata) -> Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let parent_metadata = std::fs::metadata(parent)?;
    Ok(metadata.uid() == 0 && parent_metadata.permissions().mode() & 0o022 == 0)
}

#[cfg(not(unix))]
fn trusted_system_symlink(_path: &Path, _metadata: &std::fs::Metadata) -> Result<bool> {
    Ok(false)
}

pub fn read_limited_regular(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if is_link_like(&metadata) || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if metadata.len() > max_bytes as u64 {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    let file = open_read_nofollow(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    Ok(bytes)
}

pub fn install_private_if_absent(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let existing = read_limited_regular(path, bytes.len().saturating_add(1))?;
        if existing != bytes {
            bail!(
                "refusing to replace different existing file {}",
                path.display()
            );
        }
        set_private_file_mode(path)?;
        return Ok(());
    }
    atomic_write(path, bytes, false)
}

pub fn atomic_replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if is_link_like(&metadata) || !metadata.is_file() {
            bail!("refusing to replace non-regular file {}", path.display());
        }
    }
    atomic_write(path, bytes, true)
}

pub fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    ensure_private_dir(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_private_create(&mut options);
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    Ok(())
}

pub fn private_log_file(path: &Path) -> Result<File> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    ensure_private_dir(parent)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if is_link_like(&metadata) || !metadata.is_file() {
            bail!("refusing non-regular log file {}", path.display());
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).append(true);
    configure_private_create(&mut options);
    options
        .open(path)
        .with_context(|| format!("open private log {}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    ensure_private_dir(parent)?;
    let temp = unique_temp_path(path);
    create_private_file(&temp, bytes)?;
    let result = if replace {
        std::fs::rename(&temp, path)
    } else {
        match std::fs::hard_link(&temp, path) {
            Ok(()) => std::fs::remove_file(&temp),
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                Err(error)
            }
        }
    };
    result.with_context(|| format!("install {}", path.display()))?;
    set_private_file_mode(path)?;
    sync_directory(parent)?;
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let mut nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("pohw-agent");
    path.with_file_name(format!(".{name}.{}.tmp", hex::encode(nonce)))
}

#[cfg(unix)]
fn configure_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

#[cfg(not(unix))]
fn open_read_nofollow(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("open {}", path.display()))
}

#[cfg(unix)]
fn set_private_dir_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set private mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_dir_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set private mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_install_refuses_different_existing_content() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        install_private_if_absent(&path, b"one").unwrap();
        install_private_if_absent(&path, b"one").unwrap();
        assert!(install_private_if_absent(&path, b"two").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_reader_rejects_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let link = temp.path().join("link");
        std::fs::write(&source, b"secret").unwrap();
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(read_limited_regular(&link, 1024).is_err());
    }
}
