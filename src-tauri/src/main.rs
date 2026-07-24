#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod audit;

use secrecy::{ExposeSecret, Secret};
use std::path::Path;
use std::sync::Mutex;

use crypto_core_rs::{
    decrypt_file_ex_rs_controlled, encrypt_file_rs_controlled, get_keyfile_hash_rs,
    read_metadata_rs, verify_file_integrity_rs_controlled, ControlFlags, MetaInfo,
};
// Archiving, extraction and the named profiles are shared with the CLI so both
// front-ends behave identically; see the `cryptera_ops` crate.
use cryptera_ops::{
    count_entries, create_tar, int_profile_params, safe_extract_tar, sec_profile_params, OpError,
};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::UpdaterExt;
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

impl From<OpError> for CmdError {
    fn from(e: OpError) -> Self {
        Self {
            code: e.code,
            message: e.message,
        }
    }
}

const ERR_PASSWORD_REQUIRED: &str = "PASSWORD_REQUIRED";
const ERR_INPUT_REQUIRED: &str = "INPUT_REQUIRED";
const ERR_OUTPUT_REQUIRED: &str = "OUTPUT_REQUIRED";
const ERR_OUTPUT_EXISTS: &str = "OUTPUT_EXISTS";
const ERR_IO: &str = "IO_ERROR";
const ERR_STATE_LOCK: &str = "STATE_LOCK";
const ERR_NO_ACTIVE_JOB: &str = "NO_ACTIVE_JOB";
const ERR_UPDATE: &str = "UPDATE_ERROR";
const ERR_UNKNOWN: &str = "UNKNOWN_ERROR";

// Tray identity + tooltips. The tooltip doubles as feedback that closing the
// window only hid it to the tray (the app keeps running).
const TRAY_ID: &str = "main-tray";
const TRAY_TOOLTIP_DEFAULT: &str = "Cryptera — right-click for options";
const TRAY_TOOLTIP_HIDDEN: &str = "Cryptera is running — double-click the tray icon to reopen";

// Ties this crate's recompilation to the frontend contents. `build.rs` sets
// CRYPTERA_FRONTEND_HASH from a hash of every file under ../ui; referencing it
// here forces `generate_context!` (which embeds the frontend) to re-run on any
// UI change, so a release bundle can never ship stale embedded HTML/JS.
const _: &str = env!("CRYPTERA_FRONTEND_HASH");

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

/// Shared scaffolding for the long-running commands: registers fresh
/// control flags, runs `job` on a blocking thread, clears the active
/// control and writes the audit entry (status + stable error code only).
async fn run_operation<T, F>(
    state: tauri::State<'_, AppState>,
    audit_state: tauri::State<'_, AuditState>,
    op_name: &'static str,
    input_path: String,
    job: F,
) -> Result<T, CmdError>
where
    T: Send + 'static,
    F: FnOnce(ControlFlags) -> Result<T, CmdError> + Send + 'static,
{
    let size_mb = audit::file_size_mb(&input_path);
    let t0 = std::time::Instant::now();

    let ctrl = ControlFlags::new();
    set_active_control(&state, ctrl.clone())?;

    let join_res = tauri::async_runtime::spawn_blocking(move || job(ctrl)).await;
    let res: Result<T, CmdError> = match join_res {
        Ok(inner) => inner,
        Err(e) => Err(CmdError::new(ERR_UNKNOWN, e.to_string())),
    };
    clear_active_control(&state)?;

    let entry = audit::AuditEntry {
        ts: audit::unix_now(),
        op: op_name.to_string(),
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

    run_operation(state, audit_state, "encrypt", input_path, move |ctrl| {
        let window_clone = window;
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
            // Pre-count entries so the archiving phase reports real progress
            // instead of sitting at 0% (total was previously emitted as 0).
            let total_entries = count_entries(Path::new(&req.input_folder));
            let mut archive_progress = |done: u64| {
                emit_progress(&window_clone, "archiving", done, total_entries);
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
    .await
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

    run_operation(state, audit_state, "decrypt", input_path, move |ctrl| {
        let window_clone = window;
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
        safe_extract_tar(&tar_path, &req.output_path)?;

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
    .await
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

    run_operation(state, audit_state, "verify", input_path, move |ctrl| {
        emit_status(&window, "backend_verify_start", "Verifying...");
        let kf_hash = match req.keyfile_path.as_deref() {
            Some(p) => Some(get_keyfile_hash_rs(p).map_err(CmdError::from)?),
            None => None,
        };
        let mut progress = |stage: &str, done: u64, total: u64| {
            emit_progress(&window, stage, done, total);
        };
        let meta = verify_file_integrity_rs_controlled(
            &req.input_file,
            req.password.expose_secret(),
            kf_hash.as_deref(),
            Some(&ctrl),
            Some(&mut progress),
        )
        .map_err(CmdError::from)?;
        emit_status(&window, "backend_verify_ok", "Verification OK");
        Ok(VerifyResult {
            meta: MetaInfoDto::from(meta),
        })
    })
    .await
}

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Open the GitHub releases page in the system browser. The app itself
/// performs no network calls (CSP connect-src 'none'); update checks are
/// an explicit user action in the browser.
#[tauri::command]
fn open_releases_page() -> Result<(), CmdError> {
    open::that("https://github.com/gh0st032395/Cryptera/releases")
        .map_err(|e| CmdError::new(ERR_IO, e.to_string()))
}

#[derive(Serialize, Clone)]
struct UpdateInfo {
    available: bool,
    version: String,
    current_version: String,
    notes: String,
    date: Option<String>,
}

/// Check the signed update manifest (GitHub Releases) for a newer version.
/// All network access is on the Rust side; the webview keeps CSP
/// connect-src 'none'. Updates are only installed after signature
/// verification against the embedded public key.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<UpdateInfo, CmdError> {
    let updater = app
        .updater()
        .map_err(|e| CmdError::new(ERR_UPDATE, e.to_string()))?;
    match updater.check().await {
        Ok(Some(update)) => Ok(UpdateInfo {
            available: true,
            version: update.version.clone(),
            current_version: update.current_version.clone(),
            notes: update.body.clone().unwrap_or_default(),
            date: update.date.map(|d| d.to_string()),
        }),
        Ok(None) => Ok(UpdateInfo {
            available: false,
            version: String::new(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            notes: String::new(),
            date: None,
        }),
        Err(e) => Err(CmdError::new(ERR_UPDATE, e.to_string())),
    }
}

/// Download the pending update (emitting "update-progress" as a 0..1
/// fraction), verify its signature, install it and relaunch the app.
#[tauri::command]
async fn install_update(app: tauri::AppHandle, window: tauri::Window) -> Result<(), CmdError> {
    let updater = app
        .updater()
        .map_err(|e| CmdError::new(ERR_UPDATE, e.to_string()))?;
    let update = updater
        .check()
        .await
        .map_err(|e| CmdError::new(ERR_UPDATE, e.to_string()))?
        .ok_or_else(|| CmdError::new(ERR_UPDATE, "No update available"))?;

    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let percent = match total {
                    Some(t) if t > 0 => downloaded as f64 / t as f64,
                    _ => 0.0,
                };
                let _ = window.emit("update-progress", percent);
            },
            || {},
        )
        .await
        .map_err(|e| CmdError::new(ERR_UPDATE, e.to_string()))?;

    // Never returns: the app is relaunched into the new version.
    app.restart()
}

/// Total and available system memory in MiB, used by the UI to warn when
/// a high-memory Argon2 profile may not fit.
#[tauri::command]
fn get_memory_info() -> serde_json::Value {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    serde_json::json!({
        "total_mb": sys.total_memory() / (1024 * 1024),
        "available_mb": sys.available_memory() / (1024 * 1024),
    })
}

/// File passed on the command line (double-click on an .ecf file once the
/// file association is installed). macOS delivers opened files through
/// RunEvent::Opened instead of argv; see main().
#[tauri::command]
fn get_launch_file() -> Option<String> {
    std::env::args()
        .nth(1)
        .filter(|arg| arg.to_lowercase().ends_with(".ecf") && Path::new(arg).is_file())
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
        .plugin(tauri_plugin_updater::Builder::new().build())
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

            TrayIconBuilder::with_id(TRAY_ID)
                .menu(&menu)
                .tooltip(TRAY_TOOLTIP_DEFAULT)
                .icon(icon)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                        if let Some(tray) = app.tray_by_id(TRAY_ID) {
                            let _ = tray.set_tooltip(Some(TRAY_TOOLTIP_DEFAULT));
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
                        let _ = tray.set_tooltip(Some(TRAY_TOOLTIP_DEFAULT));
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
                        // The window vanishing silently looks like a full quit;
                        // signal via the tray tooltip that the app is still alive.
                        if let Some(tray) = win_hide.app_handle().tray_by_id(TRAY_ID) {
                            let _ = tray.set_tooltip(Some(TRAY_TOOLTIP_HIDDEN));
                        }
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
            get_launch_file,
            get_app_version,
            open_releases_page,
            check_update,
            install_update,
            get_memory_info,
            set_pause,
            cancel_job,
            open_file_dialog,
            open_folder_dialog,
            save_file_dialog,
            get_audit_log,
            clear_audit_log,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, _event| {
            // macOS delivers files opened via Finder/file association as
            // RunEvent::Opened (argv is not used there).
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = _event {
                let paths: Vec<String> = urls
                    .iter()
                    .filter_map(|u| u.to_file_path().ok())
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|p| p.to_lowercase().ends_with(".ecf"))
                    .collect();
                if !paths.is_empty() {
                    if let Some(win) = _app_handle.get_webview_window("main") {
                        let _ = win.emit("launch-file", paths);
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_error_preserves_core_error_code() {
        let core_err = crypto_core_rs::CoreError::new("PASSWORD_INVALID", "details with /paths");
        let cmd_err = CmdError::from(core_err);
        assert_eq!(cmd_err.code, "PASSWORD_INVALID");
        assert_eq!(cmd_err.message, "details with /paths");
    }

    // Profile mapping, TAR naming and the extraction hardening moved to the
    // shared `cryptera_ops` crate and are covered by its own tests.
    #[test]
    fn cmd_error_preserves_op_error_code() {
        let op_err = OpError::new(cryptera_ops::ERR_EXTRACT, "Zip Slip attempt detected");
        let cmd_err = CmdError::from(op_err);
        assert_eq!(cmd_err.code, "EXTRACT_ERROR");
    }
}
