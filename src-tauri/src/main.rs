#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;

use secrecy::{ExposeSecret, Secret};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crypto_core_rs::{
    decrypt_file_ex_rs_controlled, encrypt_file_rs_controlled, get_keyfile_hash_rs,
    read_metadata_rs, verify_file_integrity_rs_controlled, ControlFlags, MetaInfo,
};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tempfile::NamedTempFile;

#[derive(Default)]
struct AppState {
    control: Mutex<Option<ControlFlags>>,
}

struct AuditState {
    logger: Mutex<audit::AuditLogger>,
}

/// Structured command error sent to the frontend over IPC.
/// `code` is a stable identifier the UI maps to localized messages;
/// `message` is a human-readable detail used only as fallback/logging aid.
#[derive(Serialize, Clone, Debug)]
struct CmdError {
    code: String,
    message: String,
}

impl CmdError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl From<crypto_core_rs::CoreError> for CmdError {
    fn from(e: crypto_core_rs::CoreError) -> Self {
        Self {
            code: e.code.to_string(),
            message: e.message,
        }
    }
}

const ERR_PASSWORD_REQUIRED: &str = "PASSWORD_REQUIRED";
const ERR_INPUT_REQUIRED: &str = "INPUT_REQUIRED";
const ERR_OUTPUT_REQUIRED: &str = "OUTPUT_REQUIRED";
const ERR_OUTPUT_EXISTS: &str = "OUTPUT_EXISTS";
const ERR_IO: &str = "IO_ERROR";
const ERR_TAR: &str = "TAR_ERROR";
const ERR_EXTRACT: &str = "EXTRACT_ERROR";
const ERR_STATE_LOCK: &str = "STATE_LOCK";
const ERR_NO_ACTIVE_JOB: &str = "NO_ACTIVE_JOB";
const ERR_UNKNOWN: &str = "UNKNOWN_ERROR";

fn set_active_control(
    state: &tauri::State<'_, AppState>,
    ctrl: ControlFlags,
) -> Result<(), CmdError> {
    let mut guard = state
        .control
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    *guard = Some(ctrl);
    Ok(())
}

fn clear_active_control(state: &tauri::State<'_, AppState>) -> Result<(), CmdError> {
    let mut guard = state
        .control
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    *guard = None;
    Ok(())
}

#[derive(Deserialize)]
struct EncryptRequest {
    input_file: String,
    input_folder: String,
    output_file: String,
    #[serde(deserialize_with = "deserialize_secret")]
    password: Secret<String>,
    keyfile_path: Option<String>,
    folder_comp: String,
    file_comp: String,
    skip_special: bool,
    enable_pwchk: bool,
    hide_filename: bool,
    sec_profile: String,
    int_profile: String,
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<Secret<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    Ok(Secret::new(s))
}

#[derive(Deserialize)]
struct DecryptRequest {
    input_file: String,
    output_path: String,
    #[serde(deserialize_with = "deserialize_secret")]
    password: Secret<String>,
    keyfile_path: Option<String>,
    extract: bool,
    keep_tar: bool,
}

#[derive(Deserialize)]
struct VerifyRequest {
    input_file: String,
    #[serde(deserialize_with = "deserialize_secret")]
    password: Secret<String>,
    keyfile_path: Option<String>,
}

#[derive(Deserialize)]
struct MetadataRequest {
    input_file: String,
}

#[derive(Serialize, Clone)]
struct ProgressPayload {
    stage: String,
    done: u64,
    total: u64,
    percent: f32,
}

#[derive(Serialize, Clone)]
struct StatusPayload {
    code: String,
    message: String,
}

#[derive(Serialize, Clone)]
struct MetaInfoDto {
    filename: String,
    version: u8,
    k: u16,
    r: u16,
    shard_size: u32,
    plain_size: u64,
    stored_size: u64,
    flags: u8,
    argon2_time: u32,
    argon2_mem_kib: u32,
    argon2_par: u16,
}

impl From<MetaInfo> for MetaInfoDto {
    fn from(info: MetaInfo) -> Self {
        Self {
            filename: info.filename,
            version: info.version,
            k: info.k,
            r: info.r,
            shard_size: info.shard_size,
            plain_size: info.plain_size,
            stored_size: info.stored_size,
            flags: info.flags,
            argon2_time: info.argon2_time,
            argon2_mem_kib: info.argon2_mem_kib,
            argon2_par: info.argon2_par,
        }
    }
}

#[derive(Serialize)]
struct DecryptResult {
    meta: Option<MetaInfoDto>,
}

#[derive(Serialize)]
struct VerifyResult {
    meta: MetaInfoDto,
}

fn sec_profile_params(profile: &str) -> (u32, u32, u16) {
    match profile {
        "Strong" => (6, 256 * 1024, 4),
        "Paranoid" => (10, 512 * 1024, 8),
        _ => (3, 64 * 1024, 2),
    }
}

fn int_profile_params(profile: &str) -> (u16, u16) {
    match profile {
        "Low" => (28, 4),
        "High" => (12, 12),
        "Max" => (8, 24),
        _ => (24, 8),
    }
}

fn emit_status(window: &tauri::Window, code: &str, message: &str) {
    let payload = StatusPayload {
        code: code.to_string(),
        message: message.to_string(),
    };
    let _ = window.emit("status", payload);
}

fn emit_progress(window: &tauri::Window, stage: &str, done: u64, total: u64) {
    let percent = if total > 0 {
        done as f32 / total as f32
    } else {
        0.0
    };
    let payload = ProgressPayload {
        stage: stage.to_string(),
        done,
        total,
        percent,
    };
    let _ = window.emit("progress", payload);
}

fn ensure_parent_dir(path: &str) -> Result<(), CmdError> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| CmdError::new(ERR_IO, e.to_string()))?;
        }
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<(), CmdError> {
    if !path.is_empty() {
        std::fs::create_dir_all(path).map_err(|e| CmdError::new(ERR_IO, e.to_string()))?;
    }
    Ok(())
}

fn tar_suffix(comp: &str) -> &'static str {
    match comp {
        "gz" => ".tar.gz",
        "bz2" => ".tar.bz2",
        "xz" => ".tar.xz",
        _ => ".tar",
    }
}

fn create_tar(
    folder: &Path,
    comp: &str,
    skip_special: bool,
    ctrl: &ControlFlags,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(NamedTempFile, String), CmdError> {
    let base_name = folder
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let tmp = NamedTempFile::new().map_err(|e| CmdError::new(ERR_IO, e.to_string()))?;

    let file = tmp.reopen().map_err(|e| CmdError::new(ERR_IO, e.to_string()))?;
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
        ctrl.wait_if_paused().map_err(CmdError::from)?;

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
                    return Err(CmdError::new(ERR_TAR, "Failed to read directory entry"));
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
                .map_err(|e| CmdError::new(ERR_TAR, e.to_string()))?;
        } else if entry.file_type().is_file() {
            builder
                .append_path_with_name(path, &tar_path)
                .map_err(|e| CmdError::new(ERR_TAR, e.to_string()))?;
        }
    }

    if let Some(cb) = progress.as_mut() {
        cb(count);
    }

    builder
        .finish()
        .map_err(|e| CmdError::new(ERR_TAR, e.to_string()))?;
    Ok((tmp, format!("{base_name}{}", tar_suffix(comp))))
}

fn safe_extract_tar(tar_path: &str, out_dir: &str) -> Result<(), std::io::Error> {
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

#[tauri::command]
fn set_pause(pause: bool, state: tauri::State<AppState>) -> Result<(), CmdError> {
    let guard = state
        .control
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    if let Some(ctrl) = guard.as_ref() {
        ctrl.set_pause(pause);
        Ok(())
    } else {
        Err(CmdError::new(ERR_NO_ACTIVE_JOB, "No active job"))
    }
}

#[tauri::command]
fn cancel_job(state: tauri::State<AppState>) -> Result<(), CmdError> {
    let guard = state
        .control
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    if let Some(ctrl) = guard.as_ref() {
        ctrl.request_cancel();
        Ok(())
    } else {
        Err(CmdError::new(ERR_NO_ACTIVE_JOB, "No active job"))
    }
}

#[tauri::command]
async fn encrypt(
    req: EncryptRequest,
    window: tauri::Window,
    state: tauri::State<'_, AppState>,
    audit_state: tauri::State<'_, AuditState>,
) -> Result<(), CmdError> {
    if req.password.expose_secret().trim().is_empty() {
        return Err(CmdError::new(ERR_PASSWORD_REQUIRED, "Password required"));
    }
    if req.input_file.is_empty() && req.input_folder.is_empty() {
        return Err(CmdError::new(
            ERR_INPUT_REQUIRED,
            "Input file or folder required",
        ));
    }
    if req.output_file.is_empty() {
        return Err(CmdError::new(ERR_OUTPUT_REQUIRED, "Output path required"));
    }

    if std::path::Path::new(&req.output_file).exists() {
        return Err(CmdError::new(
            ERR_OUTPUT_EXISTS,
            "Output file already exists. Overwrite protection enabled.",
        ));
    }

    ensure_parent_dir(&req.output_file)?;

    let input_path = if !req.input_file.is_empty() {
        req.input_file.clone()
    } else {
        req.input_folder.clone()
    };
    let size_mb = audit::file_size_mb(&input_path);
    let t0 = std::time::Instant::now();

    let ctrl = ControlFlags::new();
    set_active_control(&state, ctrl.clone())?;

    let window_clone = window.clone();
    let join_res = tauri::async_runtime::spawn_blocking(move || -> Result<(), CmdError> {
        emit_status(&window_clone, "backend_enc_start", "Starting encryption...");
        let kf_hash = match req.keyfile_path.as_deref() {
            Some(p) => Some(get_keyfile_hash_rs(p).map_err(CmdError::from)?),
            None => None,
        };
        let (argon2_t, argon2_m, argon2_p) = sec_profile_params(&req.sec_profile);
        let (k, r) = int_profile_params(&req.int_profile);

        if !req.input_folder.is_empty() {
            emit_status(
                &window_clone,
                "backend_enc_archiving",
                "Creating archive...",
            );
            let mut archive_progress = |done: u64| {
                emit_progress(&window_clone, "archiving", done, 0);
            };
            let (tmp_tar, base_name) = create_tar(
                Path::new(&req.input_folder),
                &req.folder_comp,
                req.skip_special,
                &ctrl,
                Some(&mut archive_progress),
            )?;
            let tar_path = tmp_tar.path().to_string_lossy().to_string();
            let original_name = if req.hide_filename {
                Some("")
            } else {
                Some(base_name.as_str())
            };
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            encrypt_file_rs_controlled(
                &tar_path,
                &req.output_file,
                req.password.expose_secret(),
                kf_hash.as_deref(),
                None,
                req.enable_pwchk,
                Some(k),
                Some(r),
                None,
                Some(argon2_t),
                Some(argon2_m),
                Some(argon2_p),
                original_name,
                true,
                Some(&ctrl),
                Some(&mut progress),
            )
            .map_err(CmdError::from)?;
        } else {
            let comp = if req.file_comp == "none" {
                None
            } else {
                Some(req.file_comp.as_str())
            };
            let original_name = if req.hide_filename { Some("") } else { None };
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            // The core writes to an unpredictable NamedTempFile next to the
            // output and renames it atomically, so no intermediate file is
            // needed here.
            encrypt_file_rs_controlled(
                &req.input_file,
                &req.output_file,
                req.password.expose_secret(),
                kf_hash.as_deref(),
                comp,
                req.enable_pwchk,
                Some(k),
                Some(r),
                None,
                Some(argon2_t),
                Some(argon2_m),
                Some(argon2_p),
                original_name,
                false,
                Some(&ctrl),
                Some(&mut progress),
            )
            .map_err(CmdError::from)?;
        }
        emit_progress(&window_clone, "encrypt", 1, 1);
        emit_status(&window_clone, "backend_enc_complete", "Encryption complete");
        Ok(())
    })
    .await;

    let res: Result<(), CmdError> = match join_res {
        Ok(inner) => inner,
        Err(e) => Err(CmdError::new(ERR_UNKNOWN, e.to_string())),
    };
    clear_active_control(&state)?;

    // Write audit entry
    let entry = audit::AuditEntry {
        ts: audit::unix_now(),
        op: "encrypt".to_string(),
        file: input_path,
        size_mb,
        duration_s: Some(t0.elapsed().as_secs_f64()),
        status: if res.is_ok() { "OK" } else { "ERR" }.to_string(),
        error: res.as_ref().err().map(|e| e.code.clone()),
    };
    if let Ok(logger) = audit_state.logger.lock() {
        let _ = logger.log(&entry);
    }

    res
}

#[tauri::command]
async fn decrypt(
    req: DecryptRequest,
    window: tauri::Window,
    state: tauri::State<'_, AppState>,
    audit_state: tauri::State<'_, AuditState>,
) -> Result<DecryptResult, CmdError> {
    if req.password.expose_secret().trim().is_empty() {
        return Err(CmdError::new(ERR_PASSWORD_REQUIRED, "Password required"));
    }
    if req.input_file.is_empty() {
        return Err(CmdError::new(ERR_INPUT_REQUIRED, "Input file required"));
    }
    if req.output_path.is_empty() {
        return Err(CmdError::new(ERR_OUTPUT_REQUIRED, "Output path required"));
    }

    if req.extract {
        ensure_dir(&req.output_path)?;
    } else {
        if std::path::Path::new(&req.output_path).exists() {
            return Err(CmdError::new(
                ERR_OUTPUT_EXISTS,
                "Output file already exists. Overwrite protection enabled.",
            ));
        }
        ensure_parent_dir(&req.output_path)?;
    }

    let input_path = req.input_file.clone();
    let size_mb = audit::file_size_mb(&input_path);
    let t0 = std::time::Instant::now();

    let ctrl = ControlFlags::new();
    set_active_control(&state, ctrl.clone())?;

    let window_clone = window.clone();
    let join_res =
        tauri::async_runtime::spawn_blocking(move || -> Result<DecryptResult, CmdError> {
            emit_status(&window_clone, "backend_dec_start", "Starting decryption...");
            let kf_hash = match req.keyfile_path.as_deref() {
                Some(p) => Some(get_keyfile_hash_rs(p).map_err(CmdError::from)?),
                None => None,
            };
            if !req.extract {
                let mut progress = |stage: &str, done: u64, total: u64| {
                    emit_progress(&window_clone, stage, done, total);
                };
                // The core writes to an unpredictable NamedTempFile next to
                // the output and renames it atomically.
                let meta = decrypt_file_ex_rs_controlled(
                    &req.input_file,
                    &req.output_path,
                    req.password.expose_secret(),
                    kf_hash.as_deref(),
                    Some(&ctrl),
                    Some(&mut progress),
                )
                .map_err(CmdError::from)?;
                emit_progress(&window_clone, "decrypt", 1, 1);
                emit_status(&window_clone, "backend_dec_complete", "Decryption complete");
                return Ok(DecryptResult {
                    meta: Some(MetaInfoDto::from(meta)),
                });
            }

            emit_status(
                &window_clone,
                "backend_dec_archive",
                "Decrypting archive...",
            );
            let tmp_tar = NamedTempFile::new().map_err(|e| CmdError::new(ERR_IO, e.to_string()))?;
            let tar_path = tmp_tar.path().to_string_lossy().to_string();
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            let meta = decrypt_file_ex_rs_controlled(
                &req.input_file,
                &tar_path,
                req.password.expose_secret(),
                kf_hash.as_deref(),
                Some(&ctrl),
                Some(&mut progress),
            )
            .map_err(CmdError::from)?;

            emit_status(&window_clone, "backend_dec_extract", "Extracting files...");
            safe_extract_tar(&tar_path, &req.output_path)
                .map_err(|e| CmdError::new(ERR_EXTRACT, e.to_string()))?;

            if req.keep_tar {
                let target = Path::new(&req.output_path).join("decrypted.tar");
                let _ = std::fs::copy(&tar_path, target);
            }

            emit_progress(&window_clone, "decrypt", 1, 1);
            emit_status(&window_clone, "backend_dec_complete", "Extraction complete");
            Ok(DecryptResult {
                meta: Some(MetaInfoDto::from(meta)),
            })
        })
        .await;

    let res: Result<DecryptResult, CmdError> = match join_res {
        Ok(inner) => inner,
        Err(e) => Err(CmdError::new(ERR_UNKNOWN, e.to_string())),
    };
    clear_active_control(&state)?;

    // Write audit entry
    let entry = audit::AuditEntry {
        ts: audit::unix_now(),
        op: "decrypt".to_string(),
        file: input_path,
        size_mb,
        duration_s: Some(t0.elapsed().as_secs_f64()),
        status: if res.is_ok() { "OK" } else { "ERR" }.to_string(),
        error: res.as_ref().err().map(|e| e.code.clone()),
    };
    if let Ok(logger) = audit_state.logger.lock() {
        let _ = logger.log(&entry);
    }

    res
}

#[tauri::command]
async fn verify(
    req: VerifyRequest,
    window: tauri::Window,
    state: tauri::State<'_, AppState>,
    audit_state: tauri::State<'_, AuditState>,
) -> Result<VerifyResult, CmdError> {
    if req.password.expose_secret().trim().is_empty() {
        return Err(CmdError::new(ERR_PASSWORD_REQUIRED, "Password required"));
    }
    if req.input_file.is_empty() {
        return Err(CmdError::new(ERR_INPUT_REQUIRED, "Input file required"));
    }

    let input_path = req.input_file.clone();
    let size_mb = audit::file_size_mb(&input_path);
    let t0 = std::time::Instant::now();

    let ctrl = ControlFlags::new();
    set_active_control(&state, ctrl.clone())?;

    let window_clone = window.clone();
    let join_res =
        tauri::async_runtime::spawn_blocking(move || -> Result<VerifyResult, CmdError> {
            emit_status(&window_clone, "backend_verify_start", "Verifying...");
            let kf_hash = match req.keyfile_path.as_deref() {
                Some(p) => Some(get_keyfile_hash_rs(p).map_err(CmdError::from)?),
                None => None,
            };
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            let meta = verify_file_integrity_rs_controlled(
                &req.input_file,
                req.password.expose_secret(),
                kf_hash.as_deref(),
                Some(&ctrl),
                Some(&mut progress),
            )
            .map_err(CmdError::from)?;
            emit_status(&window_clone, "backend_verify_ok", "Verification OK");
            Ok(VerifyResult {
                meta: MetaInfoDto::from(meta),
            })
        })
        .await;

    let res: Result<VerifyResult, CmdError> = match join_res {
        Ok(inner) => inner,
        Err(e) => Err(CmdError::new(ERR_UNKNOWN, e.to_string())),
    };
    clear_active_control(&state)?;

    // Write audit entry
    let entry = audit::AuditEntry {
        ts: audit::unix_now(),
        op: "verify".to_string(),
        file: input_path,
        size_mb,
        duration_s: Some(t0.elapsed().as_secs_f64()),
        status: if res.is_ok() { "OK" } else { "ERR" }.to_string(),
        error: res.as_ref().err().map(|e| e.code.clone()),
    };
    if let Ok(logger) = audit_state.logger.lock() {
        let _ = logger.log(&entry);
    }

    res
}

#[tauri::command]
fn read_metadata(req: MetadataRequest) -> Result<MetaInfoDto, CmdError> {
    if req.input_file.is_empty() {
        return Err(CmdError::new(ERR_INPUT_REQUIRED, "Input file required"));
    }
    read_metadata_rs(&req.input_file)
        .map(MetaInfoDto::from)
        .map_err(CmdError::from)
}

/// Audit log commands
#[tauri::command]
fn get_audit_log(
    audit_state: tauri::State<'_, AuditState>,
) -> Result<Vec<audit::AuditEntry>, CmdError> {
    let logger = audit_state
        .logger
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    Ok(logger.read_recent(500))
}

#[tauri::command]
fn clear_audit_log(audit_state: tauri::State<'_, AuditState>) -> Result<(), CmdError> {
    let logger = audit_state
        .logger
        .lock()
        .map_err(|_| CmdError::new(ERR_STATE_LOCK, "State lock failed"))?;
    logger.clear().map_err(|e| CmdError::new(ERR_IO, e))
}

/// Open file dialog — supports single or multiple selection.
#[tauri::command]
async fn open_file_dialog(
    window: tauri::Window,
    default_path: Option<String>,
    multiple: Option<bool>,
) -> Result<serde_json::Value, CmdError> {
    let multi = multiple.unwrap_or(false);
    tauri::async_runtime::spawn_blocking(move || {
        let mut builder = window.dialog().file();
        if let Some(path) = default_path {
            builder = builder.set_directory(path);
        }
        if multi {
            let files = builder.blocking_pick_files();
            let paths: Vec<String> = files
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| p.into_path().ok())
                .map(|p| p.to_string_lossy().to_string())
                .collect();
            Ok(serde_json::json!(paths))
        } else {
            let file = builder.blocking_pick_file();
            Ok(serde_json::json!(file
                .and_then(|p| p.into_path().ok())
                .map(|p| p.to_string_lossy().to_string())))
        }
    })
    .await
    .map_err(|e| CmdError::new(ERR_UNKNOWN, e.to_string()))?
}

#[tauri::command]
async fn open_folder_dialog(
    window: tauri::Window,
    default_path: Option<String>,
) -> Result<Option<String>, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut builder = window.dialog().file();
        if let Some(path) = default_path {
            builder = builder.set_directory(path);
        }
        let folder = builder.blocking_pick_folder();
        Ok(folder
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().to_string()))
    })
    .await
    .map_err(|e| CmdError::new(ERR_UNKNOWN, e.to_string()))?
}

#[tauri::command]
async fn save_file_dialog(
    window: tauri::Window,
    default_path: Option<String>,
) -> Result<Option<String>, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut builder = window.dialog().file();
        if let Some(path) = default_path {
            let p = Path::new(&path);
            if let Some(parent) = p.parent() {
                builder = builder.set_directory(parent);
            } else {
                builder = builder.set_directory(p);
            }
            if let Some(name) = p.file_name() {
                builder = builder.set_file_name(name.to_string_lossy());
            }
        }
        let file = builder.blocking_save_file();
        Ok(file
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().to_string()))
    })
    .await
    .map_err(|e| CmdError::new(ERR_UNKNOWN, e.to_string()))?
}

/// Build a 16×16 RGBA icon with a stylised lock shape.
fn build_tray_icon_rgba() -> (Vec<u8>, u32, u32) {
    const W: usize = 16;
    const H: usize = 16;
    let mut data = vec![0u8; W * H * 4];
    let set = |data: &mut Vec<u8>, x: usize, y: usize, rgba: [u8; 4]| {
        let i = (y * W + x) * 4;
        data[i..i + 4].copy_from_slice(&rgba);
    };
    let accent = [0x35u8, 0xd0u8, 0xa1u8, 0xffu8]; // #35d0a1
                                                   // Shackle (top arc of lock): rows 2–7, columns 4–11
    for y in 2usize..=7 {
        for x in 4usize..=11 {
            let on_left_wall = x == 4 && y >= 5;
            let on_right_wall = x == 11 && y >= 5;
            let on_top = y == 2 && (5..=10).contains(&x);
            let on_side_top = (x == 5 || x == 10) && y == 3;
            if on_left_wall || on_right_wall || on_top || on_side_top {
                set(&mut data, x, y, accent);
            }
        }
    }
    // Body (rectangle): rows 7–13, columns 3–12
    for y in 7usize..=13 {
        for x in 3usize..=12 {
            set(&mut data, x, y, accent);
        }
    }
    // Keyhole cutout in body
    for y in 9usize..=12 {
        for x in 6usize..=9 {
            let top_circle = y == 9 && (6..=9).contains(&x);
            let stem = (10..=12).contains(&y) && x == 7;
            let stem2 = (10..=12).contains(&y) && x == 8;
            if !(top_circle || stem || stem2) {
                set(&mut data, x, y, [0x00, 0x00, 0x00, 0x00]);
            }
        }
    }
    (data, W as u32, H as u32)
}

fn main() {
    let log_dir = audit::default_log_dir();
    let audit_logger = audit::AuditLogger::new(log_dir);

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .manage(AuditState {
            logger: Mutex::new(audit_logger),
        })
        .setup(|app| {
            use tauri::menu::{MenuBuilder, MenuItemBuilder};
            use tauri::tray::TrayIconBuilder;

            let show_item = MenuItemBuilder::with_id("show", "Open Cryptera").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app)
                .items(&[&show_item, &quit_item])
                .build()?;

            let (rgba, w, h) = build_tray_icon_rgba();
            let icon = tauri::image::Image::new_owned(rgba, w, h);

            TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Cryptera — right-click for options")
                .icon(icon)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Override window close → hide to tray (first close hides, tray "Quit" exits)
            if let Some(win) = app.get_webview_window("main") {
                let win_hide = win.clone();
                win.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = win_hide.hide();
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            encrypt,
            decrypt,
            verify,
            read_metadata,
            set_pause,
            cancel_job,
            open_file_dialog,
            open_folder_dialog,
            save_file_dialog,
            get_audit_log,
            clear_audit_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn security_profile_mapping_is_stable() {
        assert_eq!(sec_profile_params("Standard"), (3, 64 * 1024, 2));
        assert_eq!(sec_profile_params("Strong"), (6, 256 * 1024, 4));
        assert_eq!(sec_profile_params("Paranoid"), (10, 512 * 1024, 8));
        assert_eq!(sec_profile_params("unknown"), (3, 64 * 1024, 2));
    }

    #[test]
    fn integrity_profile_mapping_is_stable() {
        assert_eq!(int_profile_params("Medium"), (24, 8));
        assert_eq!(int_profile_params("Low"), (28, 4));
        assert_eq!(int_profile_params("High"), (12, 12));
        assert_eq!(int_profile_params("Max"), (8, 24));
        assert_eq!(int_profile_params("unknown"), (24, 8));
    }

    #[test]
    fn tar_suffix_mapping_is_stable() {
        assert_eq!(tar_suffix("none"), ".tar");
        assert_eq!(tar_suffix("gz"), ".tar.gz");
        assert_eq!(tar_suffix("bz2"), ".tar.bz2");
        assert_eq!(tar_suffix("xz"), ".tar.xz");
    }

    #[test]
    fn safe_extract_tar_rejects_zip_slip_entries() {
        let dir = tempdir().expect("tempdir");
        let tar_path = dir.path().join("malicious.tar");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        // Build a valid tar first.
        {
            let tar_file = File::create(&tar_path).expect("create tar");
            let mut builder = tar::Builder::new(tar_file);
            let payload = b"evil";
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "safe.txt", &payload[..])
                .expect("append safe entry");
            builder.finish().expect("finish tar");
        }

        // Mutate first entry name to "../escape.txt" and fix checksum.
        let mut raw = std::fs::read(&tar_path).expect("read tar");
        let header = &mut raw[..512];
        for b in &mut header[..100] {
            *b = 0;
        }
        let evil_name = b"../escape.txt";
        header[..evil_name.len()].copy_from_slice(evil_name);
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        header[148..156].copy_from_slice(chk.as_bytes());
        std::fs::write(&tar_path, &raw).expect("write mutated tar");

        let err = safe_extract_tar(
            tar_path.to_str().expect("utf8 path"),
            out_dir.to_str().expect("utf8 path"),
        )
        .expect_err("zip slip path must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!dir.path().join("escape.txt").exists());
    }
}
