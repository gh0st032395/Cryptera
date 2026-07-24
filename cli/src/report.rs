//! Output formatting: one JSON object on stdout, or human-readable lines.
//!
//! Progress and stage notices always go to stderr so that `--json` stdout stays
//! a single parseable document even while a long job is running.

use std::cell::Cell;
use std::io::Write;
use std::path::Path;

use cryptera_ops::{META_FLAG_ENC_FILENAME, META_FLAG_TAR_CONTAINER};
use crypto_core_rs::MetaInfo;
use serde::Serialize;

use crate::error::CliError;

#[derive(Serialize)]
pub struct MetaReport {
    pub filename: String,
    pub filename_encrypted: bool,
    pub container: bool,
    pub version: u8,
    pub k: u16,
    pub r: u16,
    pub parity_overhead_pct: u32,
    pub shard_size: u32,
    pub plain_size: u64,
    pub stored_size: u64,
    pub flags: u8,
    pub argon2_time: u32,
    pub argon2_mem_kib: u32,
    pub argon2_par: u16,
}

impl From<&MetaInfo> for MetaReport {
    fn from(m: &MetaInfo) -> Self {
        let total = m.k as u32 + m.r as u32;
        Self {
            filename: m.filename.clone(),
            filename_encrypted: m.flags & META_FLAG_ENC_FILENAME != 0,
            container: m.flags & META_FLAG_TAR_CONTAINER != 0,
            version: m.version,
            k: m.k,
            r: m.r,
            parity_overhead_pct: (m.r as u32 * 100).checked_div(total).unwrap_or(0),
            shard_size: m.shard_size,
            plain_size: m.plain_size,
            stored_size: m.stored_size,
            flags: m.flags,
            argon2_time: m.argon2_time,
            argon2_mem_kib: m.argon2_mem_kib,
            argon2_par: m.argon2_par,
        }
    }
}

#[derive(Serialize)]
struct Success<'a> {
    ok: bool,
    op: &'a str,
    input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    container: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extracted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<MetaReport>,
}

#[derive(Serialize)]
struct Failure<'a> {
    ok: bool,
    code: &'a str,
    message: &'a str,
}

pub struct Reporter {
    json: bool,
    quiet: bool,
    tty: bool,
    last_percent: Cell<i32>,
}

impl Reporter {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self {
            json,
            quiet,
            tty: crate::stderr_is_tty(),
            last_percent: Cell::new(-1),
        }
    }

    /// Announce a phase change (archiving, encrypting, extracting, ...).
    pub fn stage(&self, stage: &str) {
        if self.quiet {
            return;
        }
        self.last_percent.set(-1);
        let _ = writeln!(std::io::stderr(), "{stage}...");
    }

    /// Byte/shard progress. On a terminal this repaints one line; when stderr
    /// is redirected only every 10% is emitted, one line each, so logs stay
    /// small.
    pub fn progress(&self, stage: &str, done: u64, total: u64) {
        if self.quiet || total == 0 {
            return;
        }
        let percent = ((done.min(total) as f64 / total as f64) * 100.0) as i32;
        let last = self.last_percent.get();
        let step = if self.tty { 1 } else { 10 };
        if percent < last + step && percent != 100 {
            return;
        }
        if percent == last {
            return;
        }
        self.last_percent.set(percent);
        let mut err = std::io::stderr();
        if self.tty {
            let _ = write!(err, "\r{stage}: {percent:3}%");
            if percent >= 100 {
                let _ = writeln!(err);
            }
        } else {
            let _ = writeln!(err, "{stage}: {percent}%");
        }
        let _ = err.flush();
    }

    pub fn encrypt_done(
        &self,
        input: &Path,
        output: &Path,
        container: bool,
        archive_suffix: Option<&str>,
        stored_size: u64,
    ) {
        if self.json {
            self.emit(&Success {
                ok: true,
                op: "encrypt",
                input: input.to_string_lossy().into_owned(),
                output: Some(output.to_string_lossy().into_owned()),
                container: Some(container),
                archive_name: archive_suffix.map(|s| s.to_string()),
                extracted: None,
                stored_size: Some(stored_size),
                meta: None,
            });
        } else {
            println!("{}", output.display());
            if !self.quiet {
                let kind = if container { "folder" } else { "file" };
                eprintln!(
                    "encrypted {kind} {} -> {} ({stored_size} bytes)",
                    input.display(),
                    output.display()
                );
            }
        }
    }

    pub fn decrypt_done(&self, input: &Path, output: &Path, extracted: bool, meta: &MetaInfo) {
        if self.json {
            self.emit(&Success {
                ok: true,
                op: "decrypt",
                input: input.to_string_lossy().into_owned(),
                output: Some(output.to_string_lossy().into_owned()),
                container: Some(meta.flags & META_FLAG_TAR_CONTAINER != 0),
                archive_name: None,
                extracted: Some(extracted),
                stored_size: None,
                meta: Some(crate::meta_report(meta)),
            });
        } else {
            println!("{}", output.display());
            if !self.quiet {
                let verb = if extracted { "extracted" } else { "decrypted" };
                eprintln!("{verb} {} -> {}", input.display(), output.display());
            }
        }
    }

    pub fn verify_done(&self, input: &Path, meta: &MetaInfo) {
        if self.json {
            self.emit(&Success {
                ok: true,
                op: "verify",
                input: input.to_string_lossy().into_owned(),
                output: None,
                container: Some(meta.flags & META_FLAG_TAR_CONTAINER != 0),
                archive_name: None,
                extracted: None,
                stored_size: None,
                meta: Some(crate::meta_report(meta)),
            });
        } else {
            println!("OK");
            if !self.quiet {
                print_meta_lines(meta);
            }
        }
    }

    pub fn meta_done(&self, input: &Path, meta: &MetaInfo) {
        if self.json {
            self.emit(&Success {
                ok: true,
                op: "meta",
                input: input.to_string_lossy().into_owned(),
                output: None,
                container: Some(meta.flags & META_FLAG_TAR_CONTAINER != 0),
                archive_name: None,
                extracted: None,
                stored_size: None,
                meta: Some(crate::meta_report(meta)),
            });
        } else {
            print_meta_lines(meta);
        }
    }

    pub fn failure(&self, err: &CliError) {
        if self.json {
            let payload = Failure {
                ok: false,
                code: &err.code,
                message: &err.message,
            };
            match serde_json::to_string(&payload) {
                Ok(s) => println!("{s}"),
                Err(_) => println!("{{\"ok\":false,\"code\":\"{}\"}}", err.code),
            }
        } else {
            eprintln!("error [{}]: {}", err.code, err.message);
        }
    }

    fn emit<T: Serialize>(&self, payload: &T) {
        match serde_json::to_string(payload) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error [JSON_ERROR]: {e}"),
        }
    }
}

fn print_meta_lines(meta: &MetaInfo) {
    let r = MetaReport::from(meta);
    let name = if !r.filename.is_empty() {
        r.filename.clone()
    } else if r.filename_encrypted {
        "(encrypted)".to_string()
    } else {
        "(hidden)".to_string()
    };
    println!(
        "type:          {}",
        if r.container {
            "folder archive"
        } else {
            "single file"
        }
    );
    println!("filename:      {name}");
    println!("format:        v{}", r.version);
    println!(
        "shards:        {} data / {} parity ({}% overhead)",
        r.k, r.r, r.parity_overhead_pct
    );
    println!("shard size:    {} bytes", r.shard_size);
    println!("plain size:    {} bytes", r.plain_size);
    println!("stored size:   {} bytes", r.stored_size);
    println!(
        "argon2:        t={} m={} KiB p={}",
        r.argon2_time, r.argon2_mem_kib, r.argon2_par
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(flags: u8, k: u16, r: u16) -> MetaInfo {
        MetaInfo {
            filename: String::new(),
            version: 5,
            k,
            r,
            shard_size: 4096,
            plain_size: 10,
            stored_size: 20,
            flags,
            argon2_time: 3,
            argon2_mem_kib: 65536,
            argon2_par: 2,
        }
    }

    #[test]
    fn parity_overhead_is_reported_as_a_share_of_the_stripe() {
        assert_eq!(MetaReport::from(&meta(0, 24, 8)).parity_overhead_pct, 25);
        assert_eq!(MetaReport::from(&meta(0, 12, 12)).parity_overhead_pct, 50);
        assert_eq!(MetaReport::from(&meta(0, 0, 0)).parity_overhead_pct, 0);
    }

    #[test]
    fn header_flags_are_decoded() {
        let r = MetaReport::from(&meta(
            META_FLAG_TAR_CONTAINER | META_FLAG_ENC_FILENAME,
            24,
            8,
        ));
        assert!(r.container);
        assert!(r.filename_encrypted);
        let plain = MetaReport::from(&meta(0, 24, 8));
        assert!(!plain.container);
        assert!(!plain.filename_encrypted);
    }

    #[test]
    fn json_shape_is_stable() {
        let payload = Success {
            ok: true,
            op: "verify",
            input: "a.ecf".into(),
            output: None,
            container: Some(false),
            archive_name: None,
            extracted: None,
            stored_size: None,
            meta: Some(MetaReport::from(&meta(0, 24, 8))),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["op"], "verify");
        assert_eq!(json["meta"]["k"], 24);
        // Absent fields must not appear as nulls: scripts test with `has`.
        assert!(json.get("output").is_none());
        assert!(json.get("extracted").is_none());
    }
}
