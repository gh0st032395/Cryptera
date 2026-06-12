// audit.rs — JSONL audit log for Cryptera
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix timestamp in seconds (UTC).
    pub ts: u64,
    /// Operation: "encrypt" | "decrypt" | "verify"
    pub op: String,
    /// Input file path
    pub file: String,
    /// File size in megabytes (optional — may be 0 for folders)
    pub size_mb: Option<f64>,
    /// Operation duration in seconds
    pub duration_s: Option<f64>,
    /// "OK" or "ERR"
    pub status: String,
    /// Error message if status == "ERR"
    pub error: Option<String>,
}

pub struct AuditLogger {
    log_file: PathBuf,
}

impl AuditLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        let log_file = log_dir.join("audit.jsonl");
        Self { log_file }
    }

    fn ensure_dir(&self) -> Result<(), String> {
        if let Some(parent) = self.log_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Append an entry to the log file.
    pub fn log(&self, entry: &AuditEntry) -> Result<(), String> {
        self.ensure_dir()?;
        let json = serde_json::to_string(entry).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{}", json).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Read recent entries, newest first. Returns at most `max` entries.
    pub fn read_recent(&self, max: usize) -> Vec<AuditEntry> {
        if !self.log_file.exists() {
            return Vec::new();
        }
        let file = match File::open(&self.log_file) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut entries: Vec<AuditEntry> = reader
            .lines()
            .map_while(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect();
        entries.reverse(); // newest first
        entries.truncate(max);
        entries
    }

    /// Delete the log file (clear all entries).
    pub fn clear(&self) -> Result<(), String> {
        if self.log_file.exists() {
            std::fs::remove_file(&self.log_file).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Returns the platform-appropriate default log directory.
pub fn default_log_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("Cryptera").join("logs");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("cryptera")
                .join("logs");
        }
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("cryptera").join("logs");
        }
    }
    PathBuf::from("./logs")
}

/// Current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Size of a file in megabytes (returns None if not accessible or zero).
pub fn file_size_mb(path: &str) -> Option<f64> {
    let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if bytes > 0 {
        Some(bytes as f64 / 1_000_000.0)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_entry(op: &str, status: &str) -> AuditEntry {
        AuditEntry {
            ts: 1_700_000_000,
            op: op.to_string(),
            file: "/tmp/test.ecf".to_string(),
            size_mb: Some(1.5),
            duration_s: Some(0.3),
            status: status.to_string(),
            error: None,
        }
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let logger = AuditLogger::new(dir.path().to_path_buf());

        logger.log(&make_entry("encrypt", "OK")).unwrap();
        logger.log(&make_entry("decrypt", "ERR")).unwrap();

        let entries = logger.read_recent(10);
        assert_eq!(entries.len(), 2);
        // newest first — last written should be first
        assert_eq!(entries[0].op, "decrypt");
        assert_eq!(entries[1].op, "encrypt");
    }

    #[test]
    fn clear_removes_entries() {
        let dir = tempdir().unwrap();
        let logger = AuditLogger::new(dir.path().to_path_buf());

        logger.log(&make_entry("verify", "OK")).unwrap();
        assert_eq!(logger.read_recent(10).len(), 1);

        logger.clear().unwrap();
        assert_eq!(logger.read_recent(10).len(), 0);
    }

    #[test]
    fn read_recent_respects_limit() {
        let dir = tempdir().unwrap();
        let logger = AuditLogger::new(dir.path().to_path_buf());

        for _ in 0..10 {
            logger.log(&make_entry("encrypt", "OK")).unwrap();
        }
        let entries = logger.read_recent(3);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn empty_log_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let logger = AuditLogger::new(dir.path().to_path_buf());
        assert!(logger.read_recent(100).is_empty());
    }

    #[test]
    fn entries_with_special_characters_stay_valid_jsonl() {
        let dir = tempdir().unwrap();
        let logger = AuditLogger::new(dir.path().to_path_buf());

        let tricky_file = "/tmp/Ünïcodé \"quoted\" \\backslash\\ \nnewline.ecf";
        let entry = AuditEntry {
            ts: 1_700_000_000,
            op: "decrypt".to_string(),
            file: tricky_file.to_string(),
            size_mb: Some(0.1),
            duration_s: Some(1.2),
            status: "ERR".to_string(),
            error: Some("CORRUPT_BEYOND_FEC".to_string()),
        };
        logger.log(&entry).unwrap();
        logger.log(&make_entry("encrypt", "OK")).unwrap();

        // Every non-empty line of the file must be standalone valid JSON.
        let raw = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            serde_json::from_str::<AuditEntry>(line).expect("line must be valid JSON");
        }

        let entries = logger.read_recent(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].file, tricky_file);
        assert_eq!(entries[1].error.as_deref(), Some("CORRUPT_BEYOND_FEC"));
    }
}
