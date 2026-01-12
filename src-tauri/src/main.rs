use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use secrecy::{Secret, ExposeSecret};

use crypto_core_rs::{
    decrypt_file_ex_rs_controlled,
    encrypt_file_rs_controlled,
    get_keyfile_hash_rs,
    read_metadata_rs,
    verify_file_integrity_rs_controlled,
    ControlFlags,
    MetaInfo,
};
use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tauri_plugin_dialog::DialogExt;
use tempfile::NamedTempFile;

#[derive(Default)]
struct AppState {
    control: Mutex<Option<ControlFlags>>,
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

fn emit_status(window: &tauri::Window, msg: &str) {
    let _ = window.emit("status", msg.to_string());
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
    let _ = window.emit("status", format!("{stage}: {done}/{total}"));
}

fn ensure_parent_dir(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<(), String> {
    if !path.is_empty() {
        std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
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
) -> Result<(NamedTempFile, String), String> {
    let base_name = folder
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let tmp = NamedTempFile::new().map_err(|e| e.to_string())?;

    let file = tmp.reopen().map_err(|e| e.to_string())?;
    let writer: Box<dyn std::io::Write> = match comp {
        "gz" => Box::new(flate2::write::GzEncoder::new(file, flate2::Compression::default())),
        "bz2" => Box::new(bzip2::write::BzEncoder::new(file, bzip2::Compression::default())),
        "xz" => Box::new(xz2::write::XzEncoder::new(file, 6)),
        _ => Box::new(file),
    };

    let mut builder = tar::Builder::new(writer);
    let base_prefix = PathBuf::from(&base_name);

    let mut count = 0;
    for entry in walkdir::WalkDir::new(folder).follow_links(false) {
        if ctrl.cancel.load(Ordering::SeqCst) {
            return Err("Operation cancelled".to_string());
        }
        while ctrl.pause.load(Ordering::SeqCst) {
            if ctrl.cancel.load(Ordering::SeqCst) {
                return Err("Operation cancelled".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

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
                    return Err("Failed to read directory entry".to_string());
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
            builder.append_dir(&tar_path, path).map_err(|e| e.to_string())?;
        } else if entry.file_type().is_file() {
            builder
                .append_path_with_name(path, &tar_path)
                .map_err(|e| e.to_string())?;
        }
    }

    if let Some(cb) = progress.as_deref_mut() {
        cb(count);
    }

    builder.finish().map_err(|e| e.to_string())?;
    Ok((tmp, format!("{base_name}{}", tar_suffix(comp))))
}

fn safe_extract_tar(tar_path: &str, out_dir: &str) -> Result<(), std::io::Error> {
    let out_dir = Path::new(out_dir).to_path_buf();
    let file = std::fs::File::open(tar_path)?;

    let path_str = tar_path.to_lowercase();
    let decoder: Box<dyn std::io::Read> = if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
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
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
             return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Zip Slip attempt detected"));
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

        // Double check destination
        let dest = out_dir.join(&*path);
        // unpack_in protects against traversal but we added explicit checks above too
        entry.unpack_in(&out_dir)?; 
    }
    Ok(())
}

#[tauri::command]
fn set_pause(pause: bool, state: tauri::State<AppState>) -> Result<(), String> {
    let guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
    if let Some(ctrl) = guard.as_ref() {
        ctrl.pause.store(pause, Ordering::SeqCst);
        Ok(())
    } else {
        Err("No active job".to_string())
    }
}

#[tauri::command]
fn cancel_job(state: tauri::State<AppState>) -> Result<(), String> {
    let guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
    if let Some(ctrl) = guard.as_ref() {
        ctrl.cancel.store(true, Ordering::SeqCst);
        Ok(())
    } else {
        Err("No active job".to_string())
    }
}

#[tauri::command]
async fn encrypt(req: EncryptRequest, window: tauri::Window, state: tauri::State<'_, AppState>) -> Result<(), String> {
    if req.password.expose_secret().trim().is_empty() {
        return Err("Password required".to_string());
    }
    if req.input_file.is_empty() && req.input_folder.is_empty() {
        return Err("Input file or folder required".to_string());
    }
    if req.output_file.is_empty() {
        return Err("Output path required".to_string());
    }

    if std::path::Path::new(&req.output_file).exists() {
        return Err("Output file already exists. Overwrite protection enabled.".to_string());
    }

    ensure_parent_dir(&req.output_file)?;

    let ctrl = ControlFlags {
        cancel: Arc::new(AtomicBool::new(false)),
        pause: Arc::new(AtomicBool::new(false)),
    };
    let ctrl_state = ControlFlags {
        cancel: ctrl.cancel.clone(),
        pause: ctrl.pause.clone(),
    };
    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = Some(ctrl_state);
    }

    let window_clone = window.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        emit_status(&window_clone, "Starting encryption...");
        let kf_hash = match req.keyfile_path.as_deref() {
            Some(p) => Some(get_keyfile_hash_rs(p).map_err(|e| e.message)?),
            None => None,
        };
        let (argon2_t, argon2_m, argon2_p) = sec_profile_params(&req.sec_profile);
        let (k, r) = int_profile_params(&req.int_profile);

        if !req.input_folder.is_empty() {
            emit_status(&window_clone, "Creating archive...");
            let mut archive_progress = |done: u64| {
                emit_progress(&window_clone, "archiving", done, 0);
            };
            let (tmp_tar, base_name) =
                create_tar(Path::new(&req.input_folder), &req.folder_comp, req.skip_special, &ctrl, Some(&mut archive_progress))?;
            let tar_path = tmp_tar.path().to_string_lossy().to_string();
            let original_name = if req.hide_filename { Some("") } else { Some(base_name.as_str()) };
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
            .map_err(|e| e.message)?;
        } else {
             let comp = if req.file_comp == "none" { None } else { Some(req.file_comp.as_str()) };
            let original_name = if req.hide_filename { Some("") } else { None };
            let tmp_output_path = format!("{}.tmp", req.output_file);
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            encrypt_file_rs_controlled(
                &req.input_file,
                &tmp_output_path,
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
            .map_err(|e| e.message)?;
            
            // Atomic rename
            std::fs::rename(&tmp_output_path, &req.output_file).map_err(|e| format!("Failed to rename temp file: {}", e))?;
        }
        emit_progress(&window_clone, "encrypt", 1, 1);
        emit_status(&window_clone, "Encryption complete");
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?;

    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = None;
    }

    res
}

#[tauri::command]
async fn decrypt(req: DecryptRequest, window: tauri::Window, state: tauri::State<'_, AppState>) -> Result<DecryptResult, String> {
    if req.password.expose_secret().trim().is_empty() {
        return Err("Password required".to_string());
    }
    if req.input_file.is_empty() {
        return Err("Input file required".to_string());
    }
    if req.output_path.is_empty() {
        return Err("Output path required".to_string());
    }

    if req.extract {
        ensure_dir(&req.output_path)?;
    } else {
        if std::path::Path::new(&req.output_path).exists() {
            return Err("Output file already exists. Overwrite protection enabled.".to_string());
        }
        ensure_parent_dir(&req.output_path)?;
    }

    let ctrl = ControlFlags {
        cancel: Arc::new(AtomicBool::new(false)),
        pause: Arc::new(AtomicBool::new(false)),
    };
    let ctrl_state = ControlFlags {
        cancel: ctrl.cancel.clone(),
        pause: ctrl.pause.clone(),
    };
    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = Some(ctrl_state);
    }

    let window_clone = window.clone();
    let res = tauri::async_runtime::spawn_blocking(move || -> Result<DecryptResult, String> {
        emit_status(&window_clone, "Starting decryption...");
        let kf_hash = match req.keyfile_path.as_deref() {
            Some(p) => Some(get_keyfile_hash_rs(p).map_err(|e| e.message)?),
            None => None,
        };
        if !req.extract {
            let mut progress = |stage: &str, done: u64, total: u64| {
                emit_progress(&window_clone, stage, done, total);
            };
            let tmp_output_path = format!("{}.tmp", req.output_path);
            let meta = decrypt_file_ex_rs_controlled(
                &req.input_file,
                &tmp_output_path,
                req.password.expose_secret(),
                kf_hash.as_deref(),
                Some(&ctrl),
                Some(&mut progress),
            )
            .map_err(|e| e.message)?;
            
            // Atomic rename
            std::fs::rename(&tmp_output_path, &req.output_path).map_err(|e| format!("Failed to rename temp file: {}", e))?;

            emit_progress(&window_clone, "decrypt", 1, 1);
            emit_status(&window_clone, "Decryption complete");
            return Ok(DecryptResult {
                meta: Some(MetaInfoDto::from(meta)),
            });
        }

        emit_status(&window_clone, "Decrypting archive...");
        let tmp_tar = NamedTempFile::new().map_err(|e| e.to_string())?;
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
        .map_err(|e| e.message)?;

        emit_status(&window_clone, "Extracting files...");
        safe_extract_tar(&tar_path, &req.output_path).map_err(|e| e.to_string())?;

        if req.keep_tar {
            let target = Path::new(&req.output_path).join("decrypted.tar");
            let _ = std::fs::copy(&tar_path, target);
        }

        emit_progress(&window_clone, "decrypt", 1, 1);
        emit_status(&window_clone, "Extraction complete");
        Ok(DecryptResult {
            meta: Some(MetaInfoDto::from(meta)),
        })
    })
    .await
    .map_err(|e| e.to_string())?;

    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = None;
    }

    res
}

#[tauri::command]
async fn verify(req: VerifyRequest, window: tauri::Window, state: tauri::State<'_, AppState>) -> Result<(), String> {
    if req.password.expose_secret().trim().is_empty() {
        return Err("Password required".to_string());
    }
    if req.input_file.is_empty() {
        return Err("Input file required".to_string());
    }

    let ctrl = ControlFlags {
        cancel: Arc::new(AtomicBool::new(false)),
        pause: Arc::new(AtomicBool::new(false)),
    };
    let ctrl_state = ControlFlags {
        cancel: ctrl.cancel.clone(),
        pause: ctrl.pause.clone(),
    };
    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = Some(ctrl_state);
    }

    let window_clone = window.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        emit_status(&window_clone, "Verifying...");
        let kf_hash = match req.keyfile_path.as_deref() {
            Some(p) => Some(get_keyfile_hash_rs(p).map_err(|e| e.message)?),
            None => None,
        };
        let mut progress = |stage: &str, done: u64, total: u64| {
            emit_progress(&window_clone, stage, done, total);
        };
        verify_file_integrity_rs_controlled(
            &req.input_file,
            req.password.expose_secret(),
            kf_hash.as_deref(),
            Some(&ctrl),
            Some(&mut progress),
        )
        .map_err(|e| e.message)?;
        emit_status(&window_clone, "Verification OK");
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?;

    {
        let mut guard = state.control.lock().map_err(|_| "State lock failed".to_string())?;
        *guard = None;
    }

    res
}

#[tauri::command]
fn read_metadata(req: MetadataRequest) -> Result<MetaInfoDto, String> {
    if req.input_file.is_empty() {
        return Err("Input file required".to_string());
    }
    read_metadata_rs(&req.input_file)
        .map(MetaInfoDto::from)
        .map_err(|e| e.message)
}

#[tauri::command]
async fn open_file_dialog(window: tauri::Window, default_path: Option<String>) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut builder = window.dialog().file();
        if let Some(path) = default_path {
            builder = builder.set_directory(path);
        }
        let file = builder.blocking_pick_file();
        Ok(file
            .and_then(|p| p.into_path().ok())
            .map(|p| p.to_string_lossy().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn open_folder_dialog(window: tauri::Window, default_path: Option<String>) -> Result<Option<String>, String> {
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
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn save_file_dialog(window: tauri::Window, default_path: Option<String>) -> Result<Option<String>, String> {
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
    .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            encrypt,
            decrypt,
            verify,
            read_metadata,
            set_pause,
            cancel_job,
            open_file_dialog,
            open_folder_dialog,
            save_file_dialog
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
