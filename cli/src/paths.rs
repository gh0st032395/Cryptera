//! Default output paths, and the sanitizing of names that come out of a
//! container header.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// `photos` → `photos.ecf`, `report.pdf` → `report.ecf`.
///
/// Files get their extension replaced (the original name is restored from the
/// header on decrypt); folders get the suffix appended, so `my.stuff` stays
/// distinguishable from `my`. Same rule as the GUI's auto-filled output field.
pub fn default_encrypt_output(input: &Path, is_dir: bool) -> PathBuf {
    if is_dir {
        let mut s: OsString = input.as_os_str().to_owned();
        s.push(".ecf");
        PathBuf::from(s)
    } else {
        input.with_extension("ecf")
    }
}

/// Strip a trailing `.ecf` (any case). Anything else gets `.out` appended so we
/// never propose an output equal to the input.
pub fn strip_ecf(input: &Path) -> PathBuf {
    let is_ecf = input
        .extension()
        .map(|e| e.eq_ignore_ascii_case("ecf"))
        .unwrap_or(false);
    if is_ecf {
        input.with_extension("")
    } else {
        let mut s: OsString = input.as_os_str().to_owned();
        s.push(".out");
        PathBuf::from(s)
    }
}

/// Default output for a single-file decrypt: the name stored in the header,
/// next to the container, falling back to the input name without `.ecf`.
pub fn default_decrypt_output(input: &Path, stored_name: &str) -> PathBuf {
    match sanitize_stored_filename(stored_name) {
        Some(name) => match input.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
            _ => PathBuf::from(name),
        },
        None => strip_ecf(input),
    }
}

/// A filename read from a container header is attacker-controlled: accept it
/// only if it is a single, ordinary path component. Anything with separators,
/// `..`, a drive letter or a UNC prefix is discarded rather than repaired.
pub fn sanitize_stored_filename(name: &str) -> Option<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return None;
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains(':') {
        return None;
    }
    if trimmed.contains('\0') {
        return None;
    }
    if is_windows_reserved(trimmed) {
        return None;
    }
    // Belt and braces: after all the checks above this must be one Normal
    // component.
    let mut comps = Path::new(trimmed).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Some(trimmed),
        _ => None,
    }
}

/// Windows reserved device names (CON, NUL, COM1-9, LPT1-9, ...) are devices,
/// not files, whatever the extension: `CON.txt` still opens the console. A
/// container is untrusted input, so a stored name that resolves to a device is
/// rejected on every platform (the container may be opened on Windows later).
fn is_windows_reserved(name: &str) -> bool {
    // Compare the stem before the first '.', case-insensitively.
    let stem = name.split('.').next().unwrap_or(name);
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return true;
    }
    // COM1-9 / LPT1-9 (and the COM²/COM³ superscript variants Windows also
    // reserves are out of scope for ASCII names).
    let up = stem.to_ascii_uppercase();
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = up.strip_prefix(prefix) {
            if rest.len() == 1 && rest.as_bytes()[0].is_ascii_digit() && rest != "0" {
                return true;
            }
        }
    }
    false
}

/// True when the directory exists and holds at least one entry.
pub fn dir_is_non_empty(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_defaults_match_the_gui() {
        assert_eq!(
            default_encrypt_output(Path::new("/a/report.pdf"), false),
            PathBuf::from("/a/report.ecf")
        );
        assert_eq!(
            default_encrypt_output(Path::new("/a/noext"), false),
            PathBuf::from("/a/noext.ecf")
        );
        assert_eq!(
            default_encrypt_output(Path::new("/a/my.stuff"), true),
            PathBuf::from("/a/my.stuff.ecf")
        );
    }

    #[test]
    fn decrypt_defaults_prefer_the_stored_name() {
        assert_eq!(
            default_decrypt_output(Path::new("/a/blob.ecf"), "report.pdf"),
            PathBuf::from("/a/report.pdf")
        );
        assert_eq!(
            default_decrypt_output(Path::new("/a/blob.ecf"), ""),
            PathBuf::from("/a/blob")
        );
        assert_eq!(
            default_decrypt_output(Path::new("blob.bin"), ""),
            PathBuf::from("blob.bin.out")
        );
    }

    #[test]
    fn hostile_stored_names_are_discarded() {
        for name in [
            "../../etc/passwd",
            "/etc/passwd",
            r"..\..\windows\system32",
            r"C:\evil.exe",
            "sub/dir.txt",
            "..",
            ".",
            "   ",
            "",
        ] {
            assert!(
                sanitize_stored_filename(name).is_none(),
                "{name:?} must be rejected"
            );
        }
        assert_eq!(sanitize_stored_filename("ok name.txt"), Some("ok name.txt"));
        assert_eq!(sanitize_stored_filename(" report.pdf "), Some("report.pdf"));
    }

    #[test]
    fn traversal_in_stored_name_cannot_escape_the_container_dir() {
        let out = default_decrypt_output(Path::new("/safe/blob.ecf"), "../../etc/passwd");
        assert_eq!(out, PathBuf::from("/safe/blob"));
    }

    #[test]
    fn windows_device_names_are_rejected_regardless_of_extension() {
        for name in [
            "CON",
            "con",
            "NUL",
            "nul.txt",
            "AUX",
            "PRN.pdf",
            "COM1",
            "com9",
            "LPT1",
            "lpt3.dat",
            "Aux.tar.gz",
        ] {
            assert!(
                sanitize_stored_filename(name).is_none(),
                "{name:?} must be rejected as a reserved device name"
            );
        }
        // Names that merely start like a device but are not one stay valid.
        assert_eq!(sanitize_stored_filename("CONFIG"), Some("CONFIG"));
        assert_eq!(sanitize_stored_filename("COM10"), Some("COM10"));
        assert_eq!(sanitize_stored_filename("COM0"), Some("COM0"));
        assert_eq!(sanitize_stored_filename("LPT.txt"), Some("LPT.txt"));
    }
}
