//! Operations shared by the two Cryptera front-ends (Tauri GUI and CLI).
//!
//! Everything crypto-related lives in `crypto_core_rs`; this crate only owns
//! the layer above it: folder → TAR archiving, safe extraction, and the
//! named security/integrity profiles. Both front-ends must behave identically,
//! so this code exists exactly once — in particular the extraction hardening
//! (path traversal, absolute paths, links) has a single implementation.

use std::path::{Path, PathBuf};

use crypto_core_rs::ControlFlags;
use tempfile::NamedTempFile;

pub const ERR_IO: &str = "IO_ERROR";
pub const ERR_TAR: &str = "TAR_ERROR";
pub const ERR_EXTRACT: &str = "EXTRACT_ERROR";

/// Header flag marking the payload as a TAR container (see FORMAT_SPEC.md).
pub const META_FLAG_TAR_CONTAINER: u8 = 0x20;
/// Header flag marking the stored filename as encrypted (see FORMAT_SPEC.md).
pub const META_FLAG_ENC_FILENAME: u8 = 0x40;

/// Error carrying a stable machine-readable `code` plus a human detail.
/// The GUI maps `code` to a localized string; the CLI maps it to an exit code.
#[derive(Debug, Clone)]
pub struct OpError {
    pub code: String,
    pub message: String,
}

impl OpError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

impl From<crypto_core_rs::CoreError> for OpError {
    fn from(e: crypto_core_rs::CoreError) -> Self {
        Self {
            code: e.code.to_string(),
            message: e.message,
        }
    }
}

/// Argon2 parameters (passes, memory KiB, lanes) for a named security profile.
/// Unknown names fall back to Standard.
pub fn sec_profile_params(profile: &str) -> (u32, u32, u16) {
    match profile {
        "Strong" => (6, 256 * 1024, 4),
        "Paranoid" => (10, 512 * 1024, 8),
        _ => (3, 64 * 1024, 2),
    }
}

/// Reed-Solomon (data, parity) shard counts for a named integrity profile.
/// Unknown names fall back to Medium.
pub fn int_profile_params(profile: &str) -> (u16, u16) {
    match profile {
        "Low" => (28, 4),
        "High" => (12, 12),
        "Max" => (8, 24),
        _ => (24, 8),
    }
}

pub fn tar_suffix(comp: &str) -> &'static str {
    match comp {
        "gz" => ".tar.gz",
        "bz2" => ".tar.bz2",
        "xz" => ".tar.xz",
        _ => ".tar",
    }
}

/// Archive base name derived from the folder name, with a sensible
/// fallback for paths without a final component (e.g. filesystem root).
pub fn tar_base_name(folder: &Path) -> String {
    let name = folder
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if name.is_empty() {
        "archive".to_string()
    } else {
        name
    }
}

/// Number of entries `create_tar` will walk, so the archiving phase can report
/// a real percentage instead of sitting at 0%. Counted with the same walk
/// options as `create_tar`, and cheap next to the archiving itself.
pub fn count_entries(folder: &Path) -> u64 {
    walkdir::WalkDir::new(folder)
        .follow_links(false)
        .into_iter()
        .count() as u64
}

/// Pack `folder` into a temporary TAR (optionally compressed) and return the
/// temp file together with the archive name to store in the header.
///
/// `progress` is called with the number of walked entries every 10 entries.
pub fn create_tar(
    folder: &Path,
    comp: &str,
    skip_special: bool,
    ctrl: &ControlFlags,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(NamedTempFile, String), OpError> {
    let base_name = tar_base_name(folder);
    let tmp = NamedTempFile::new().map_err(|e| OpError::new(ERR_IO, e.to_string()))?;

    let file = tmp
        .reopen()
        .map_err(|e| OpError::new(ERR_IO, e.to_string()))?;
    let writer: Box<dyn std::io::Write> = match comp {
        "gz" => Box::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::default(),
        )),
        "bz2" => Box::new(bzip2::write::BzEncoder::new(
            file,
            bzip2::Compression::default(),
        )),
        "xz" => Box::new(xz2::write::XzEncoder::new(file, 6)),
        _ => Box::new(file),
    };

    let mut builder = tar::Builder::new(writer);
    let base_prefix = PathBuf::from(&base_name);

    let mut count = 0;
    for entry in walkdir::WalkDir::new(folder).follow_links(false) {
        ctrl.wait_if_paused()?;

        count += 1;
        if count % 10 == 0 {
            if let Some(cb) = progress.as_deref_mut() {
                cb(count);
            }
        }

        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                if skip_special {
                    continue;
                } else {
                    return Err(OpError::new(ERR_TAR, "Failed to read directory entry"));
                }
            }
        };

        if skip_special && entry.file_type().is_symlink() {
            continue;
        }

        let path = entry.path();
        let rel = match path.strip_prefix(folder) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let tar_path = if rel.as_os_str().is_empty() {
            base_prefix.clone()
        } else {
            base_prefix.join(rel)
        };

        if entry.file_type().is_dir() {
            builder
                .append_dir(&tar_path, path)
                .map_err(|e| OpError::new(ERR_TAR, e.to_string()))?;
        } else if entry.file_type().is_file() {
            builder
                .append_path_with_name(path, &tar_path)
                .map_err(|e| OpError::new(ERR_TAR, e.to_string()))?;
        }
    }

    if let Some(cb) = progress.as_mut() {
        cb(count);
    }

    builder
        .finish()
        .map_err(|e| OpError::new(ERR_TAR, e.to_string()))?;
    Ok((tmp, format!("{base_name}{}", tar_suffix(comp))))
}

/// Unpack a TAR (compression auto-detected from the extension) into `out_dir`,
/// rejecting entries that would escape it and skipping links.
pub fn safe_extract_tar(tar_path: &str, out_dir: &str) -> Result<(), OpError> {
    extract_inner(tar_path, out_dir).map_err(|e| OpError::new(ERR_EXTRACT, e.to_string()))
}

fn extract_inner(tar_path: &str, out_dir: &str) -> Result<(), std::io::Error> {
    let out_dir = Path::new(out_dir).to_path_buf();
    let file = std::fs::File::open(tar_path)?;

    let path_str = tar_path.to_lowercase();
    let decoder: Box<dyn std::io::Read> =
        if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            Box::new(flate2::read::GzDecoder::new(file))
        } else if path_str.ends_with(".tar.bz2") || path_str.ends_with(".tbz2") {
            Box::new(bzip2::read::BzDecoder::new(file))
        } else if path_str.ends_with(".tar.xz") || path_str.ends_with(".txz") {
            Box::new(xz2::read::XzDecoder::new(file))
        } else {
            Box::new(file)
        };

    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        // Prevent Zip Slip
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Zip Slip attempt detected",
            ));
        }

        if path.is_absolute() {
            continue;
        }

        // Prevent Windows UNC / Drive letters
        let path_lossy = path.to_string_lossy();
        if path_lossy.contains(':') || path_lossy.starts_with(r"\\") {
            continue;
        }

        // Skip Symlinks/Hardlinks as per policy
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            continue;
        }

        // Double check destination (validation done by unpack_in)
        entry.unpack_in(&out_dir)?;
    }
    Ok(())
}

/// The decrypted payload is a TAR container that can be extracted.
pub fn is_tar_container(flags: u8) -> bool {
    flags & META_FLAG_TAR_CONTAINER != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_fall_back_to_defaults() {
        assert_eq!(
            sec_profile_params("Nonsense"),
            sec_profile_params("Standard")
        );
        assert_eq!(int_profile_params("Nonsense"), int_profile_params("Medium"));
        assert_eq!(sec_profile_params("Paranoid"), (10, 512 * 1024, 8));
        assert_eq!(int_profile_params("Max"), (8, 24));
    }

    #[test]
    fn tar_names_follow_compression() {
        assert_eq!(tar_suffix("gz"), ".tar.gz");
        assert_eq!(tar_suffix("none"), ".tar");
        assert_eq!(tar_base_name(Path::new("/tmp/photos")), "photos");
        assert_eq!(tar_base_name(Path::new("/")), "archive");
    }

    #[test]
    fn roundtrip_folder_through_tar() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/a.txt"), b"hello").unwrap();

        let ctrl = ControlFlags::new();
        let (tmp, name) = create_tar(src.path(), "gz", true, &ctrl, None).unwrap();
        assert!(name.ends_with(".tar.gz"));

        // safe_extract_tar sniffs the compression from the extension, so the
        // temp file has to carry it.
        let tar_path = tmp.path().with_extension("tar.gz");
        std::fs::copy(tmp.path(), &tar_path).unwrap();

        let out = tempfile::tempdir().unwrap();
        safe_extract_tar(tar_path.to_str().unwrap(), out.path().to_str().unwrap()).unwrap();

        let base = tar_base_name(src.path());
        let extracted = out.path().join(&base).join("sub/a.txt");
        assert_eq!(std::fs::read(extracted).unwrap(), b"hello");
        let _ = std::fs::remove_file(&tar_path);
    }

    #[test]
    fn extraction_rejects_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("evil.tar");
        {
            let f = std::fs::File::create(&tar_path).unwrap();
            let mut b = tar::Builder::new(f);
            let payload = b"pwned";
            let mut header = tar::Header::new_gnu();
            // The name is written into the raw header: the safe setters refuse
            // to emit `..`, which is exactly the entry we need to test against.
            let name = b"../escaped.txt";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &payload[..]).unwrap();
            b.finish().unwrap();
        }

        let out = tempfile::tempdir().unwrap();
        let err = safe_extract_tar(tar_path.to_str().unwrap(), out.path().to_str().unwrap())
            .expect_err("path traversal must be rejected");
        assert_eq!(err.code, ERR_EXTRACT);
        assert!(!dir.path().join("escaped.txt").exists());
    }
}
