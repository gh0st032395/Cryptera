use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use crypto_core_rs::{
    decrypt_file_ex_rs_controlled,
    encrypt_file_rs_controlled,
    read_metadata_rs,
    verify_file_integrity_rs_controlled,
    ControlFlags,
    MetaInfo,
};
use eframe::egui;
use rfd::FileDialog;
use tar::Archive;
use tempfile::NamedTempFile;

const FILE_COMP_CHOICES: [&str; 2] = ["none", "lzma"];
const TAR_COMP_CHOICES: [&str; 4] = ["none", "gz", "bz2", "xz"];
const SEC_PROFILES: [&str; 3] = ["Standard", "Strong", "Paranoid"];
const INT_PROFILES: [&str; 4] = ["Low", "Medium", "High", "Max"];

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Encrypt,
    Decrypt,
}

enum WorkerMsg {
    Status(String),
    Progress(f32),
    Done(Result<(), String>),
    Meta(Option<MetaInfo>),
}

struct CryptoGuiApp {
    tab: Tab,
    busy: bool,
    status: String,
    progress: f32,
    rx: Option<Receiver<WorkerMsg>>,
    ctrl: Option<ControlFlags>,
    style_applied: bool,

    // Encrypt fields
    enc_file: String,
    enc_folder: String,
    enc_output: String,
    use_keyfile: bool,
    keyfile_path: String,
    folder_comp: String,
    file_comp: String,
    skip_special: bool,
    enable_pwchk: bool,
    hide_filename: bool,
    sec_profile: String,
    int_profile: String,

    // Decrypt fields
    dec_file: String,
    dec_output: String,
    dec_use_keyfile: bool,
    dec_keyfile_path: String,
    keep_tar: bool,
    meta_info: Option<MetaInfo>,
}

impl Default for CryptoGuiApp {
    fn default() -> Self {
        Self {
            tab: Tab::Encrypt,
            busy: false,
            status: "Ready".to_string(),
            progress: 0.0,
            rx: None,
            ctrl: None,
            style_applied: false,

            enc_file: String::new(),
            enc_folder: String::new(),
            enc_output: String::new(),
            use_keyfile: false,
            keyfile_path: String::new(),
            folder_comp: "none".to_string(),
            file_comp: "none".to_string(),
            skip_special: true,
            enable_pwchk: true,
            hide_filename: false,
            sec_profile: "Standard".to_string(),
            int_profile: "Medium".to_string(),

            dec_file: String::new(),
            dec_output: String::new(),
            dec_use_keyfile: false,
            dec_keyfile_path: String::new(),
            keep_tar: false,
            meta_info: None,
        }
    }
}

impl CryptoGuiApp {
    fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        if !busy {
            self.progress = 0.0;
            self.ctrl = None;
        }
    }

    fn poll_worker(&mut self) {
        let messages = {
            let mut msgs = Vec::new();
            if let Some(rx) = self.rx.as_ref() {
                while let Ok(msg) = rx.try_recv() {
                    msgs.push(msg);
                }
            }
            msgs
        };

        for msg in messages {
            match msg {
                WorkerMsg::Status(s) => self.status = s,
                WorkerMsg::Progress(p) => self.progress = p,
                WorkerMsg::Meta(m) => self.meta_info = m,
                WorkerMsg::Done(res) => {
                    self.set_busy(false);
                    self.rx = None;
                    match res {
                        Ok(_) => self.status = "Done".to_string(),
                        Err(e) => self.status = format!("Error: {e}"),
                    }
                }
            }
        }
    }

    fn browse_enc_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.enc_file = path.display().to_string();
            self.enc_folder.clear();
            if self.enc_output.is_empty() {
                self.enc_output = format!("{}.ecf", self.enc_file);
            }
        }
    }

    fn browse_enc_folder(&mut self) {
        if let Some(path) = FileDialog::new().pick_folder() {
            self.enc_folder = path.display().to_string();
            self.enc_file.clear();
            if self.enc_output.is_empty() {
                self.enc_output = format!("{}.ecf", self.enc_folder);
            }
        }
    }

    fn browse_enc_output(&mut self) {
        if let Some(path) = FileDialog::new().set_file_name("output.ecf").save_file() {
            self.enc_output = path.display().to_string();
        }
    }

    fn browse_keyfile(&mut self, decrypt: bool) {
        if let Some(path) = FileDialog::new().pick_file() {
            if decrypt {
                self.dec_keyfile_path = path.display().to_string();
            } else {
                self.keyfile_path = path.display().to_string();
            }
        }
    }

    fn browse_dec_file(&mut self) {
        if let Some(path) = FileDialog::new().add_filter("Encrypted", &["ecf"]).pick_file() {
            self.dec_file = path.display().to_string();
            self.meta_info = read_metadata_rs(&self.dec_file).ok();
        }
    }

    fn browse_dec_output(&mut self) {
        if let Some(path) = FileDialog::new().save_file() {
            self.dec_output = path.display().to_string();
        }
    }

    fn start_encrypt(&mut self) {
        let input_file = self.enc_file.clone();
        let input_folder = self.enc_folder.clone();
        let output_file = self.enc_output.clone();
        let keyfile = if self.use_keyfile {
            Some(self.keyfile_path.clone())
        } else {
            None
        };
        let folder_comp = self.folder_comp.clone();
        let file_comp = self.file_comp.clone();
        let skip_special = self.skip_special;
        let enable_pwchk = self.enable_pwchk;
        let hide_filename = self.hide_filename;
        let sec_profile = self.sec_profile.clone();
        let int_profile = self.int_profile.clone();

        if input_file.is_empty() && input_folder.is_empty() {
            self.status = "Select a file or folder".to_string();
            return;
        }
        if output_file.is_empty() {
            self.status = "Select output file".to_string();
            return;
        }

        let password = match rpassword::prompt_password("Encryption Password: ") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                self.status = "Password required".to_string();
                return;
            }
        };

        let (tx, rx) = mpsc::channel();
        let ctrl = ControlFlags {
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pause: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let ctrl_worker = ControlFlags {
            cancel: ctrl.cancel.clone(),
            pause: ctrl.pause.clone(),
        };
        self.ctrl = Some(ctrl);
        self.rx = Some(rx);
        self.set_busy(true);
        self.status = "Working...".to_string();

        thread::spawn(move || {
            let _ = tx.send(WorkerMsg::Status("Preparing...".to_string()));
            let res = encrypt_worker(
                &input_file,
                &input_folder,
                &output_file,
                &password,
                keyfile.as_deref(),
                &folder_comp,
                &file_comp,
                skip_special,
                enable_pwchk,
                hide_filename,
                &sec_profile,
                &int_profile,
                ctrl_worker,
                tx.clone(),
            );
            let _ = tx.send(WorkerMsg::Done(res));
        });
    }

    fn start_decrypt(&mut self, extract: bool) {
        let input_file = self.dec_file.clone();
        let output_path = self.dec_output.clone();
        let keyfile = if self.dec_use_keyfile {
            Some(self.dec_keyfile_path.clone())
        } else {
            None
        };
        let keep_tar = self.keep_tar;

        if input_file.is_empty() {
            self.status = "Select input file".to_string();
            return;
        }
        if output_path.is_empty() {
            self.status = "Select output path".to_string();
            return;
        }

        let password = match rpassword::prompt_password("Decryption Password: ") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                self.status = "Password required".to_string();
                return;
            }
        };

        let (tx, rx) = mpsc::channel();
        let ctrl = ControlFlags {
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pause: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let ctrl_worker = ControlFlags {
            cancel: ctrl.cancel.clone(),
            pause: ctrl.pause.clone(),
        };
        self.ctrl = Some(ctrl);
        self.rx = Some(rx);
        self.set_busy(true);
        self.status = "Working...".to_string();

        thread::spawn(move || {
            let _ = tx.send(WorkerMsg::Status("Decrypting...".to_string()));
            let res = decrypt_worker(
                &input_file,
                &output_path,
                &password,
                keyfile.as_deref(),
                extract,
                keep_tar,
                ctrl_worker,
                tx.clone(),
            );
            let _ = tx.send(WorkerMsg::Done(res));
        });
    }

    fn start_verify(&mut self) {
        let input_file = self.dec_file.clone();
        let keyfile = if self.dec_use_keyfile {
            Some(self.dec_keyfile_path.clone())
        } else {
            None
        };

        if input_file.is_empty() {
            self.status = "Select input file".to_string();
            return;
        }

        let password = match rpassword::prompt_password("Verification Password: ") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                self.status = "Password required".to_string();
                return;
            }
        };

        let (tx, rx) = mpsc::channel();
        let ctrl = ControlFlags {
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pause: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let ctrl_worker = ControlFlags {
            cancel: ctrl.cancel.clone(),
            pause: ctrl.pause.clone(),
        };
        self.ctrl = Some(ctrl);
        self.rx = Some(rx);
        self.set_busy(true);
        self.status = "Verifying...".to_string();

        thread::spawn(move || {
            let res = verify_worker(
                &input_file,
                &password,
                keyfile.as_deref(),
                ctrl_worker,
                tx.clone(),
            );
            let _ = tx.send(WorkerMsg::Done(res));
        });
    }
}

fn encrypt_worker(
    input_file: &str,
    input_folder: &str,
    output_file: &str,
    password: &str,
    keyfile: Option<&str>,
    folder_comp: &str,
    file_comp: &str,
    skip_special: bool,
    enable_pwchk: bool,
    hide_filename: bool,
    sec_profile: &str,
    int_profile: &str,
    ctrl: ControlFlags,
    tx: Sender<WorkerMsg>,
) -> Result<(), String> {
    let kf_hash = match keyfile {
        Some(p) => Some(crypto_core_rs::get_keyfile_hash_rs(p).map_err(|e| e.message)?),
        None => None,
    };

    let (argon2_t, argon2_m, argon2_p) = match sec_profile {
        "Standard" => (3, 64 * 1024, 2),
        "Strong" => (6, 256 * 1024, 4),
        "Paranoid" => (10, 512 * 1024, 8),
        _ => (3, 64 * 1024, 2),
    };
    let (k, r) = match int_profile {
        "Low" => (28, 4),
        "Medium" => (24, 8),
        "High" => (12, 12),
        "Max" => (8, 24),
        _ => (24, 8),
    };

    if !input_folder.is_empty() {
        let _ = tx.send(WorkerMsg::Status("Creating TAR...".to_string()));
        let (tmp_tar, base_name) =
            create_tar(Path::new(input_folder), folder_comp, skip_special, &ctrl)?;
        let tar_path = tmp_tar.path().to_string_lossy().to_string();
        let original_name = if hide_filename { Some("") } else { Some(base_name.as_str()) };
        let mut progress = |stage: &str, done: u64, total: u64| {
            let pct = if total > 0 { done as f32 / total as f32 } else { 0.0 };
            let _ = tx.send(WorkerMsg::Progress(pct));
            let _ = tx.send(WorkerMsg::Status(format!("{stage}: {done}/{total}")));
        };
        encrypt_file_rs_controlled(
            &tar_path,
            output_file,
            password,
            kf_hash.as_deref(),
            None,
            enable_pwchk,
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
        let _ = tx.send(WorkerMsg::Status("Encryption complete".to_string()));
        return Ok(());
    }

    let original_name = if hide_filename { Some("") } else { None };
    let comp = if file_comp == "none" { None } else { Some(file_comp) };
    let mut progress = |stage: &str, done: u64, total: u64| {
        let pct = if total > 0 { done as f32 / total as f32 } else { 0.0 };
        let _ = tx.send(WorkerMsg::Progress(pct));
        let _ = tx.send(WorkerMsg::Status(format!("{stage}: {done}/{total}")));
    };
    encrypt_file_rs_controlled(
        input_file,
        output_file,
        password,
        kf_hash.as_deref(),
        comp,
        enable_pwchk,
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
    let _ = tx.send(WorkerMsg::Status("Encryption complete".to_string()));
    Ok(())
}

fn decrypt_worker(
    input_file: &str,
    output_path: &str,
    password: &str,
    keyfile: Option<&str>,
    extract: bool,
    keep_tar: bool,
    ctrl: ControlFlags,
    tx: Sender<WorkerMsg>,
) -> Result<(), String> {
    let kf_hash = match keyfile {
        Some(p) => Some(crypto_core_rs::get_keyfile_hash_rs(p).map_err(|e| e.message)?),
        None => None,
    };

    if !extract {
        let mut progress = |stage: &str, done: u64, total: u64| {
            let pct = if total > 0 { done as f32 / total as f32 } else { 0.0 };
            let _ = tx.send(WorkerMsg::Progress(pct));
            let _ = tx.send(WorkerMsg::Status(format!("{stage}: {done}/{total}")));
        };
        decrypt_file_ex_rs_controlled(
            input_file,
            output_path,
            password,
            kf_hash.as_deref(),
            Some(&ctrl),
            Some(&mut progress),
        )
        .map_err(|e| e.message)?;
        let _ = tx.send(WorkerMsg::Status("Decryption complete".to_string()));
        return Ok(());
    }

    let _ = tx.send(WorkerMsg::Status("Decrypting...".to_string()));
    let tmp_tar = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    let tar_path = tmp_tar.path().to_string_lossy().to_string();
    let mut progress = |stage: &str, done: u64, total: u64| {
        let pct = if total > 0 { done as f32 / total as f32 } else { 0.0 };
        let _ = tx.send(WorkerMsg::Progress(pct));
        let _ = tx.send(WorkerMsg::Status(format!("{stage}: {done}/{total}")));
    };
    let meta = decrypt_file_ex_rs_controlled(
        input_file,
        &tar_path,
        password,
        kf_hash.as_deref(),
        Some(&ctrl),
        Some(&mut progress),
    )
    .map_err(|e| e.message)?;
    let _ = tx.send(WorkerMsg::Meta(Some(meta.clone())));

    let _ = tx.send(WorkerMsg::Status("Extracting...".to_string()));
    safe_extract_tar(&tar_path, output_path).map_err(|e| e.to_string())?;

    if keep_tar {
        let target = Path::new(output_path).join("decrypted.tar");
        let _ = std::fs::copy(&tar_path, target);
    }

    let _ = tx.send(WorkerMsg::Status("Extract complete".to_string()));
    Ok(())
}

fn verify_worker(
    input_file: &str,
    password: &str,
    keyfile: Option<&str>,
    ctrl: ControlFlags,
    tx: Sender<WorkerMsg>,
) -> Result<(), String> {
    let kf_hash = match keyfile {
        Some(p) => Some(crypto_core_rs::get_keyfile_hash_rs(p).map_err(|e| e.message)?),
        None => None,
    };
    let mut progress = |stage: &str, done: u64, total: u64| {
        let pct = if total > 0 { done as f32 / total as f32 } else { 0.0 };
        let _ = tx.send(WorkerMsg::Progress(pct));
        let _ = tx.send(WorkerMsg::Status(format!("{stage}: {done}/{total}")));
    };
    verify_file_integrity_rs_controlled(
        input_file,
        password,
        kf_hash.as_deref(),
        Some(&ctrl),
        Some(&mut progress),
    )
    .map_err(|e| e.message)?;
    let _ = tx.send(WorkerMsg::Status("Verification OK".to_string()));
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
) -> Result<(NamedTempFile, String), String> {
    let base_name = folder
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let tmp = NamedTempFile::new().map_err(|e: std::io::Error| e.to_string())?;

    let file = tmp.reopen().map_err(|e: std::io::Error| e.to_string())?;

    let writer: Box<dyn std::io::Write> = match comp {
        "gz" => Box::new(flate2::write::GzEncoder::new(file, flate2::Compression::default())),
        "bz2" => Box::new(bzip2::write::BzEncoder::new(file, bzip2::Compression::default())),
        "xz" => Box::new(xz2::write::XzEncoder::new(file, 6)),
        _ => Box::new(file),
    };

    let mut builder = tar::Builder::new(writer);
    let base_prefix = PathBuf::from(&base_name);

    for entry in walkdir::WalkDir::new(folder).follow_links(false) {
        if ctrl.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Operation cancelled".to_string());
        }
        while ctrl.pause.load(std::sync::atomic::Ordering::SeqCst) {
            if ctrl.cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("Operation cancelled".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
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
            builder
                .append_dir(&tar_path, path)
                .map_err(|e: std::io::Error| e.to_string())?;
        } else if entry.file_type().is_file() {
            builder
                .append_path_with_name(path, &tar_path)
                .map_err(|e: std::io::Error| e.to_string())?;
        }
    }

    builder.finish().map_err(|e: std::io::Error| e.to_string())?;
    Ok((tmp, format!("{base_name}{}", tar_suffix(comp))))
}

fn safe_extract_tar(tar_path: &str, out_dir: &str) -> Result<(), std::io::Error> {
    let out_dir = Path::new(out_dir).to_path_buf();
    let file = std::fs::File::open(tar_path)?;
    let mut archive = Archive::new(file);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.is_absolute() {
            continue;
        }
        let dest = out_dir.join(&*path);
        let dest_abs = dest.canonicalize().unwrap_or(dest.clone());
        if !dest_abs.starts_with(&out_dir) {
            continue;
        }
        entry.unpack(dest)?;
    }
    Ok(())
}

impl eframe::App for CryptoGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();

        if !self.style_applied {
            let mut visuals = egui::Visuals::light();
            visuals.panel_fill = egui::Color32::from_rgb(245, 246, 248);
            visuals.window_fill = egui::Color32::from_rgb(255, 255, 255);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(240, 242, 245);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(232, 236, 242);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(225, 230, 238);
            visuals.selection.bg_fill = egui::Color32::from_rgb(61, 113, 202);
            visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
            ctx.set_visuals(visuals);
            self.style_applied = true;
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("CryptoV2");
                ui.add_space(8.0);
                ui.label("Rust GUI");
            });
        });

        egui::SidePanel::left("side").resizable(false).default_width(190.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("Actions");
            ui.add_space(6.0);
            ui.selectable_value(&mut self.tab, Tab::Encrypt, "Encrypt");
            ui.selectable_value(&mut self.tab, Tab::Decrypt, "Decrypt");
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label("Status");
            ui.label(&self.status);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            match self.tab {
                Tab::Encrypt => self.render_encrypt(ui),
                Tab::Decrypt => self.render_decrypt(ui),
            }
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Progress");
                ui.add_space(6.0);
                ui.add(egui::ProgressBar::new(self.progress).show_percentage());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(ctrl) = &self.ctrl {
                        let paused = ctrl.pause.load(std::sync::atomic::Ordering::SeqCst);
                        let pause_text = if paused { "Resume" } else { "Pause" };
                        if ui.button(pause_text).clicked() {
                            ctrl.pause.store(!paused, std::sync::atomic::Ordering::SeqCst);
                        }
                        if ui.button("Cancel").clicked() {
                            ctrl.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                });
            });
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

impl CryptoGuiApp {
    fn render_encrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Encrypt");
        ui.add_space(6.0);

        card(ui, "Source", |ui| {
            labeled_text(ui, "File", &mut self.enc_file);
            if ui.button("Browse File").clicked() && !self.busy {
                self.browse_enc_file();
            }
            ui.add_space(6.0);
            labeled_text(ui, "Folder", &mut self.enc_folder);
            if ui.button("Browse Folder").clicked() && !self.busy {
                self.browse_enc_folder();
            }
            ui.add_space(6.0);
            labeled_text(ui, "Output", &mut self.enc_output);
            if ui.button("Save As").clicked() && !self.busy {
                self.browse_enc_output();
            }
        });

        ui.add_space(10.0);
        card(ui, "Options", |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.use_keyfile, "Use Keyfile");
                ui.add_space(6.0);
                ui.text_edit_singleline(&mut self.keyfile_path);
                if ui.button("Browse").clicked() && self.use_keyfile && !self.busy {
                    self.browse_keyfile(false);
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                egui::ComboBox::from_label("Folder Compression")
                    .selected_text(&self.folder_comp)
                    .show_ui(ui, |ui| {
                        for v in TAR_COMP_CHOICES {
                            ui.selectable_value(&mut self.folder_comp, v.to_string(), v);
                        }
                    });
                ui.add_space(10.0);
                egui::ComboBox::from_label("File Compression")
                    .selected_text(&self.file_comp)
                    .show_ui(ui, |ui| {
                        for v in FILE_COMP_CHOICES {
                            ui.selectable_value(&mut self.file_comp, v.to_string(), v);
                        }
                    });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.skip_special, "Skip invalid/locked");
                ui.checkbox(&mut self.enable_pwchk, "Fast password check");
                ui.checkbox(&mut self.hide_filename, "Hide filename");
            });
        });

        ui.add_space(10.0);
        card(ui, "Profiles", |ui| {
            ui.horizontal(|ui| {
                egui::ComboBox::from_label("Security")
                    .selected_text(&self.sec_profile)
                    .show_ui(ui, |ui| {
                        for v in SEC_PROFILES {
                            ui.selectable_value(&mut self.sec_profile, v.to_string(), v);
                        }
                    });
                ui.add_space(10.0);
                egui::ComboBox::from_label("Integrity")
                    .selected_text(&self.int_profile)
                    .show_ui(ui, |ui| {
                        for v in INT_PROFILES {
                            ui.selectable_value(&mut self.int_profile, v.to_string(), v);
                        }
                    });
            });
        });

        ui.add_space(12.0);
        let btn = egui::Button::new("Start Encryption").min_size(egui::vec2(180.0, 32.0));
        if ui.add_enabled(!self.busy, btn).clicked() {
            self.start_encrypt();
        }
    }

    fn render_decrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decrypt");
        ui.add_space(6.0);

        card(ui, "Encrypted File", |ui| {
            labeled_text(ui, "Input", &mut self.dec_file);
            if ui.button("Browse").clicked() && !self.busy {
                self.browse_dec_file();
            }
            ui.add_space(6.0);
            labeled_text(ui, "Output", &mut self.dec_output);
            if ui.button("Save As").clicked() && !self.busy {
                self.browse_dec_output();
            }
        });

        ui.add_space(10.0);
        card(ui, "Options", |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.dec_use_keyfile, "Use Keyfile");
                ui.text_edit_singleline(&mut self.dec_keyfile_path);
                if ui.button("Browse").clicked() && self.dec_use_keyfile && !self.busy {
                    self.browse_keyfile(true);
                }
            });
            ui.add_space(6.0);
            ui.checkbox(&mut self.keep_tar, "Keep decrypted TAR when extracting");
        });

        ui.add_space(10.0);
        egui::CollapsingHeader::new("Technical Details")
            .default_open(false)
            .show(ui, |ui| {
                if let Some(meta) = &self.meta_info {
                    ui.label(format!("Version: {}", meta.version));
                    ui.label(format!("Plain Size: {} bytes", meta.plain_size));
                    ui.label(format!("Stored Size: {} bytes", meta.stored_size));
                    ui.label(format!("k={}, r={}, shard={}", meta.k, meta.r, meta.shard_size));
                    ui.label(format!(
                        "Argon2id t={}, m={} KiB, p={}",
                        meta.argon2_time, meta.argon2_mem_kib, meta.argon2_par
                    ));
                    ui.label(format!(
                        "Filename: {}",
                        if meta.filename.is_empty() { "(Hidden)" } else { &meta.filename }
                    ));
                } else {
                    ui.label("No metadata loaded.");
                }
            });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let btn = egui::Button::new("Decrypt to File").min_size(egui::vec2(140.0, 28.0));
            if ui.add_enabled(!self.busy, btn).clicked() {
                self.start_decrypt(false);
            }
            let btn = egui::Button::new("Decrypt & Extract").min_size(egui::vec2(160.0, 28.0));
            if ui.add_enabled(!self.busy, btn).clicked() {
                self.start_decrypt(true);
            }
            let btn = egui::Button::new("Verify").min_size(egui::vec2(100.0, 28.0));
            if ui.add_enabled(!self.busy, btn).clicked() {
                self.start_verify();
            }
        });
    }
}

fn card(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(255, 255, 255))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(225, 230, 238)))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).strong());
            ui.add_space(6.0);
            add_contents(ui);
        });
}

fn labeled_text(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).color(egui::Color32::from_rgb(90, 95, 105)));
        ui.add(egui::TextEdit::singleline(value).desired_width(320.0));
    });
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "CryptoV2 - Rust GUI",
        options,
        Box::new(|_cc| Box::new(CryptoGuiApp::default())),
    )
}
