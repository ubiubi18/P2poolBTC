use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn secure_output_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("output directory must be absolute: {}", path.display());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "output path must be a non-symlink directory: {}",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .with_context(|| format!("failed to create output directory {}", path.display()))?;
            set_directory_mode(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve output directory {}", path.display()))?;
    let metadata = fs::metadata(&canonical)?;
    reject_unsafe_directory_permissions(&canonical, &metadata)?;
    Ok(canonical)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("output artifact has no parent directory")?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "artifact parent must be a non-symlink directory: {}",
            parent.display()
        );
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite artifact {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn deterministic_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(unix)]
fn reject_unsafe_directory_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!(
            "refusing group/world-writable output directory {}; run chmod go-w first",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unsafe_directory_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path) -> Result<()> {
    Ok(())
}
