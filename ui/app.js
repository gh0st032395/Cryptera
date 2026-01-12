let statusText = null;
let progressFill = null;
let progressValue = null;
let pauseBtn = null;
let cancelBtn = null;
let resetBtn = null;

window.addEventListener("error", (e) => {
  const status = document.getElementById("statusText");
  if (status) status.textContent = `JS error: ${e.message}`;
  console.error("JS error:", e);
});

window.addEventListener("unhandledrejection", (e) => {
  const status = document.getElementById("statusText");
  if (status) status.textContent = `Promise error: ${e.reason}`;
  console.error("Promise error:", e);
});

const tauri = window.__TAURI__ || {};
const invoke = tauri?.core?.invoke || tauri?.tauri?.invoke || tauri?.invoke;
const eventApi = tauri?.event || tauri?.core?.event || tauri?.tauri?.event;
const windowApi = tauri?.window || tauri?.core?.window;

const translations = {
  en: {
    nav_encrypt: "Encrypt",
    nav_decrypt: "Decrypt",
    nav_verify: "Verify",
    nav_about: "About",
    hero_title: "Secure Data, Accelerated Workflow.",
    hero_subtitle: "Local-first encryption powered by Rust. Precision control, zero knowledge.",
    metric_engine: "Core Engine",
    metric_mode: "Operation Mode",
    metric_local: "Local Device",
    panel_encrypt_title: "Encryption",
    panel_encrypt_desc: "Secure files or directories with advanced cryptography.",
    card_source: "Input Selection",
    seg_file: "Single File",
    seg_folder: "Directory",
    label_file_path: "Source File",
    btn_choose: "Select...",
    label_folder_path: "Source Directory",
    label_output_file: "Destination File",
    btn_save_as: "Browse...",
    card_security: "Security Parameters",
    label_password: "Encryption Password",
    label_keyfile: "Keyfile (Optional)",
    label_sec_profile: "Security Profile",
    opt_standard: "Standard",
    opt_strong: "High",
    opt_paranoid: "Maximum",
    label_int_profile: "Redundancy Level",
    opt_medium: "Balanced",
    opt_low: "Low Overhead",
    opt_high: "High Redundancy",
    opt_max: "Max Resilience",
    card_options: "Processing Options",
    label_file_comp: "Pre-compression",
    opt_none: "None",
    opt_zlib: "Deflate (Docs)",
    opt_lzma: "LZMA2 (Best)",
    label_folder_comp: "Archive Compression",
    opt_gz: "Gzip (Fast)",
    opt_bz2: "Bzip2 (Ratio)",
    opt_xz: "XZ (Best)",
    check_skip_special: "exclude symbolic links & system files",
    check_pwchk: "Enable fast password verification",
    check_hide_filename: "Obfuscate original filename in header",
    btn_start_enc: "Execute Encryption",
    panel_decrypt_title: "Decryption",
    panel_decrypt_desc: "Restore original data from encrypted containers.",
    label_encrypted_file: "Source Encrypted File",
    label_output_path: "Destination Folder",
    btn_select: "Select...",
    meta_title: "File Metadata",
    meta_empty: "No metadata loaded. Select a file to analyze.",
    btn_read_meta: "Analyze Metadata",
    card_credentials: "Decryption Credentials",
    check_auto_extract: "Auto-extract archives upon completion",
    check_keep_tar: "Retain intermediate TAR archive",
    btn_start_dec: "Execute Decryption",
    panel_verify_title: "Integrity Check",
    panel_verify_desc: "Validate file integrity without performing decryption.",
    card_target: "Target Analysis",
    btn_run_ver: "Run Integrity Check",
    panel_about_title: "System Info",
    panel_about_desc: "Architecture and version details.",
    about_text: "CryptoV2 is a high-performance local encryption utility powered by Rust. It leverages AES-GCM-256 and Argon2id relative to erasure coding for maximum resilience. Zero cloud dependencies, absolute privacy.",
    label_language: "Interface Language",

    // Tooltips
    tooltip_sec_standard: "Argon2id: 3 passes, 64MB RAM. Standard security suitable for most use cases.",
    tooltip_sec_strong: "Argon2id: 6 passes, 256MB RAM. Enhanced protection against hardware brute-force.",
    tooltip_sec_paranoid: "Argon2id: 10 passes, 512MB RAM. Maximum derivation cost; slower but extremely secure.",
    tooltip_int_profile: "Controls the ratio of parity shards to data shards for error recovery.",
    tooltip_int_medium: "24 Data / 8 Parity. Recovers from 25% corruption. Balanced overhead.",
    tooltip_int_low: "28 Data / 4 Parity. Recovers from 12% corruption. Minimal space overhead.",
    tooltip_int_high: "12 Data / 12 Parity. Recovers from 50% corruption. High reliability.",
    tooltip_int_max: "8 Data / 24 Parity. Recovers from 75% corruption. Extreme redundancy.",
    tooltip_file_comp: "Compression algorithm applied before encryption.",
    tooltip_file_comp_none: "No compression. Fastest processing.",
    tooltip_file_comp_zlib: "Standard Deflate compression. Efficient for text/documents.",
    tooltip_file_comp_lzma: "High-ratio LZMA2 compression. Slower but most effective.",
    tooltip_folder_comp: "Compression algorithm used for the folder archive container.",
    tooltip_folder_comp_none: "No compression. Store only.",
    tooltip_folder_comp_gz: "Gzip compression. Fast and widely compatible.",
    tooltip_folder_comp_bz2: "Bzip2 compression. Better ratio than Gzip.",
    tooltip_folder_comp_xz: "XZ/LZMA compression. Maximum reduction, higher CPU usage.",
    tooltip_skip_special: "Prevents errors by skipping symbolic links, sockets, and device nodes.",
    tooltip_enable_pwchk: "Stores a hash in the header to confirm password correctness instantly before decryption.",
    tooltip_hide_filename: "Encrypts the original filename inside the header. output file will need a random name.",
  },
  it: {
    nav_encrypt: "Cifra",
    nav_decrypt: "Decifra",
    nav_verify: "Verifica",
    nav_about: "Info",
    hero_title: "Protezione Dati, Flusso Rapido.",
    hero_subtitle: "Cifratura locale basata su Rust. Controllo totale, privacy assoluta.",
    metric_engine: "Motore Core",
    metric_mode: "Modalità",
    metric_local: "Locale",
    panel_encrypt_title: "Cifratura",
    panel_encrypt_desc: "Proteggi file o directory con crittografia avanzata.",
    card_source: "Selezione Input",
    seg_file: "File Singolo",
    seg_folder: "Directory",
    label_file_path: "File Sorgente",
    btn_choose: "Seleziona...",
    label_folder_path: "Directory Sorgente",
    label_output_file: "File di Destinazione",
    btn_save_as: "Sfoglia...",
    card_security: "Parametri di Sicurezza",
    label_password: "Password di Cifratura",
    label_keyfile: "File Chiave (Opzionale)",
    label_sec_profile: "Profilo di Sicurezza",
    opt_standard: "Standard",
    opt_strong: "Alta",
    opt_paranoid: "Massima",
    label_int_profile: "Livello Ridondanza",
    opt_medium: "Bilanciato",
    opt_low: "Basso Overhead",
    opt_high: "Alta Ridondanza",
    opt_max: "Resilienza Max",
    card_options: "Opzioni di Processo",
    label_file_comp: "Pre-compressione",
    opt_none: "Nessuna",
    opt_zlib: "Deflate (Docs)",
    opt_lzma: "LZMA2 (Best)",
    label_folder_comp: "Compressione Archivio",
    opt_gz: "Gzip (Veloce)",
    opt_bz2: "Bzip2 (Ratio)",
    opt_xz: "XZ (Best)",
    check_skip_special: "Escludi link simbolici e file di sistema",
    check_pwchk: "Abilita verifica rapida password",
    check_hide_filename: "Offusca nome originale nel file cifrato",
    btn_start_enc: "Esegui Cifratura",
    panel_decrypt_title: "Decifratura",
    panel_decrypt_desc: "Ripristina i dati originali dai contenitori cifrati.",
    label_encrypted_file: "File Cifrato Sorgente",
    label_output_path: "Cartella di Destinazione",
    btn_select: "Seleziona...",
    meta_title: "Metadati File",
    meta_empty: "Nessun metadato. Seleziona un file per l'analisi.",
    btn_read_meta: "Analizza Metadati",
    card_credentials: "Credenziali Decifratura",
    check_auto_extract: "Estrai automaticamente archivi al termine",
    check_keep_tar: "Mantieni l'archivio intermedio TAR",
    btn_start_dec: "Esegui Decifratura",
    panel_verify_title: "Controllo Integrità",
    panel_verify_desc: "Verifica l'integrità del file senza decifrarlo.",
    card_target: "Analisi Target",
    btn_run_ver: "Avvia Verifica",
    panel_about_title: "Informazioni",
    panel_about_desc: "Dettagli versione e architettura.",
    about_text: "CryptoV2 è un'utility di cifratura ad alte prestazioni. Utilizza AES-GCM-256 e Argon2id con codifica di cancellazione (Reed-Solomon) per garantire la massima resilienza dei dati. Zero dipendenze cloud, privacy locale assoluta.",
    label_language: "Lingua Interfaccia",

    // Tooltips
    tooltip_sec_standard: "Argon2id: 3 passaggi, 64MB RAM. Sicurezza standard adatta alla maggior parte dei casi.",
    tooltip_sec_strong: "Argon2id: 6 passaggi, 256MB RAM. Protezione avanzata contro attacchi hardware.",
    tooltip_sec_paranoid: "Argon2id: 10 passaggi, 512MB RAM. Costo di derivazione massimo; più lento ma estremamente sicuro.",
    tooltip_int_profile: "Controlla il rapporto tra frammenti di parità e dati per il recupero errori.",
    tooltip_int_medium: "24 Dati / 8 Parità. Recupera fino al 25% di corruzione. Overhead bilanciato.",
    tooltip_int_low: "28 Dati / 4 Parità. Recupera fino al 12% di corruzione. Minimo spazio extra.",
    tooltip_int_high: "12 Dati / 12 Parità. Recupera fino al 50% di corruzione. Alta affidabilità.",
    tooltip_int_max: "8 Dati / 24 Parità. Recupera fino al 75% di corruzione. Ridondanza estrema.",
    tooltip_file_comp: "Algoritmo di compressione applicato al file prima della cifratura.",
    tooltip_file_comp_none: "Nessuna compressione. Elaborazione più veloce.",
    tooltip_file_comp_zlib: "Compressione Deflate standard. Efficiente per testi/documenti.",
    tooltip_file_comp_lzma: "Compressione LZMA2 ad alto rapporto. Più lento ma molto efficace.",
    tooltip_folder_comp: "Algoritmo di compressione usato per il contenitore della cartella.",
    tooltip_folder_comp_none: "Nessuna compressione. Archiviazione diretta.",
    tooltip_folder_comp_gz: "Compressione Gzip. Veloce e ampiamente compatibile.",
    tooltip_folder_comp_bz2: "Compressione Bzip2. Rapporto migliore di Gzip.",
    tooltip_folder_comp_xz: "Compressione XZ/LZMA. Riduzione massima, uso CPU più alto.",
    tooltip_skip_special: "Previene errori saltando link simbolici, socket e nodi di dispositivo.",
    tooltip_enable_pwchk: "Memorizza un hash nell'header per confermare istantaneamente la password prima della decifratura.",
    tooltip_hide_filename: "Cifra il nome file originale nell'header. Il file di output dovrà avere un nome casuale.",
  }
};

const state = {
  busy: false,
  paused: false,
  mode: "file",
  language: "en",
};

let encFile = null;
let encFolder = null;
let encOutput = null;
let encPassword = null;
let encKeyfile = null;
let encFileComp = null;
let encFolderComp = null;
let encSkipSpecial = null;
let encEnablePwchk = null;
let encHideFilename = null;
let encSecProfile = null;
let encIntProfile = null;

let decFile = null;
let decOutput = null;
let decPassword = null;
let decKeyfile = null;
let decExtract = null;
let decKeepTar = null;
let metaContent = null;
let verMetaContent = null;

let verFile = null;
let verPassword = null;
let verKeyfile = null;

function setStatus(text) {
  if (!statusText) {
    statusText = document.getElementById("statusText");
  }
  if (!statusText) return;
  statusText.textContent = text;
}

function setProgress(percent) {
  if (!progressFill || !progressValue) {
    progressFill = document.getElementById("progressFill");
    progressValue = document.getElementById("progressValue");
  }
  if (!progressFill || !progressValue) return;
  const safe = Math.max(0, Math.min(1, percent || 0));
  progressFill.style.width = `${Math.round(safe * 100)}%`;
  progressValue.textContent = `${Math.round(safe * 100)}%`;
}

function setBusy(value) {
  state.busy = value;
  document.querySelectorAll("button").forEach((btn) => {
    if (btn.classList.contains("ghost")) return;
    btn.disabled = value;
  });
  if (!pauseBtn || !cancelBtn) {
    pauseBtn = document.getElementById("pauseBtn");
    cancelBtn = document.getElementById("cancelBtn");
  }
  if (pauseBtn) pauseBtn.disabled = !value;
  if (cancelBtn) cancelBtn.disabled = !value;
}

function updateMode(mode) {
  state.mode = mode;
  document.querySelectorAll(".seg").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.mode === mode);
  });
  if (encFile) encFile.disabled = mode !== "file";
  if (encFolder) encFolder.disabled = mode !== "folder";
  const encFileBtn = document.getElementById("encFileBtn");
  const encFolderBtn = document.getElementById("encFolderBtn");
  if (encFileBtn) encFileBtn.disabled = mode !== "file";
  if (encFolderBtn) encFolderBtn.disabled = mode !== "folder";
}

async function pickFile(target, defaultPath = null) {
  if (!invoke) return;
  try {
    const selected = await invoke("open_file_dialog", { defaultPath });
    if (selected) target.value = selected;
  } catch (err) {
    setStatus(String(err));
  }
}

async function pickFolder(target, defaultPath = null) {
  if (!invoke) return;
  try {
    const selected = await invoke("open_folder_dialog", { defaultPath });
    if (selected) target.value = selected;
  } catch (err) {
    setStatus(String(err));
  }
}

async function pickSave(target, defaultPath = null) {
  if (!invoke) return;
  try {
    const selected = await invoke("save_file_dialog", { defaultPath });
    if (selected) target.value = selected;
  } catch (err) {
    setStatus(String(err));
  }
}

function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.dataset.tab;
      document.querySelectorAll(".panel").forEach((panel) => {
        panel.classList.toggle("active", panel.id === `panel-${target}`);
      });
    });
  });
}

function bindWindowControls() {
  if (!windowApi) {
    console.error("Window API not found");
    return;
  }
  const appWindow = windowApi.getCurrentWindow();
  if (!appWindow) return;

  document.getElementById("titlebar-minimize")?.addEventListener("click", () => appWindow.minimize());
  document.getElementById("titlebar-maximize")?.addEventListener("click", () => appWindow.toggleMaximize());
  document.getElementById("titlebar-close")?.addEventListener("click", () => appWindow.close());
}

function bindEvents() {
  document.querySelectorAll(".seg").forEach((btn) => {
    btn.addEventListener("click", () => updateMode(btn.dataset.mode));
  });

  const onClick = (id, handler) => {
    const el = document.getElementById(id);
    if (!el) {
      setStatus(`Missing element: ${id}`);
      return;
    }
    el.addEventListener("click", async (e) => {
      // debug log removed
      try {
        await handler(e);
      } catch (err) {
        setStatus(`Handler error: ${err}`);
        console.error(err);
      }
    });
  };

  onClick("encFileBtn", async () => {
    await pickFile(encFile);
    if (encFile.value && encOutput) {
      try {
        const path = encFile.value.trim();
        const sep = path.includes("\\") ? "\\" : "/";
        const lastDot = path.lastIndexOf(".");
        let suggested = "";
        if (lastDot > path.lastIndexOf(sep)) {
          // Replace extension
          suggested = path.substring(0, lastDot) + ".ecf";
        } else {
          // Append extension
          suggested = path + ".ecf";
        }
        encOutput.value = suggested;
      } catch (e) {
        console.error("Smart enc path failed", e);
      }
    }
  });
  onClick("encFolderBtn", async () => {
    await pickFolder(encFolder);
    if (encFolder.value && encOutput) {
      try {
        const path = encFolder.value.trim();
        // For folder, typically just append .ecf
        encOutput.value = path + ".ecf";
      } catch (e) {
        console.error("Smart enc path failed", e);
      }
    }
  });
  onClick("encOutputBtn", async () => {
    const currentVal = encOutput.value.trim();
    await pickSave(encOutput, currentVal || null);
  });
  onClick("encKeyfileBtn", () => pickFile(encKeyfile));

  onClick("decFileBtn", async () => {
    await pickFile(decFile);
    if (decFile.value) {
      checkFileMetadata(decFile.value);
    }
  });
  onClick("decOutputBtn", async () => {
    const currentVal = decOutput.value.trim();
    if (decExtract && decExtract.checked) {
      await pickFolder(decOutput, currentVal || null);
    } else {
      await pickSave(decOutput, currentVal || null);
    }
  });
  onClick("decKeyfileBtn", () => pickFile(decKeyfile));

  onClick("verFileBtn", async () => {
    await pickFile(verFile);
    if (verFile && verFile.value.trim()) {
      handleReadVerifyMeta();
    }
  });
  onClick("verKeyfileBtn", () => pickFile(verKeyfile));

  onClick("encryptBtn", handleEncrypt);
  onClick("decryptBtn", handleDecrypt);
  onClick("verifyBtn", handleVerify);
  onClick("readMetaBtn", handleReadMeta);
  onClick("readVerifyMetaBtn", handleReadVerifyMeta);

  if (pauseBtn) pauseBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      // Optimistically we don't toggle yet. We ask the backend first.
      const newPausedState = !state.paused;
      await invoke("set_pause", { pause: newPausedState });

      // If success, update UI
      state.paused = newPausedState;
      pauseBtn.textContent = state.paused ? "Resume" : "Pause";
    } catch (err) {
      setStatus(String(err));
    }
  });

  if (cancelBtn) cancelBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      await invoke("cancel_job");
    } catch (err) {
      setStatus(String(err));
    }
  });

  if (resetBtn) resetBtn.addEventListener("click", handleReset);
}

async function handleEncrypt() {
  if (!invoke) return;
  setBusy(true);
  setProgress(0);
  setStatus("Encrypting...");

  const payload = {
    input_file: state.mode === "file" ? encFile.value.trim() : "",
    input_folder: state.mode === "folder" ? encFolder.value.trim() : "",
    output_file: encOutput.value.trim(),
    password: encPassword.value,
    keyfile_path: encKeyfile.value.trim() ? encKeyfile.value.trim() : null,
    folder_comp: encFolderComp.value,
    file_comp: encFileComp.value,
    skip_special: encSkipSpecial.checked,
    enable_pwchk: encEnablePwchk.checked,
    hide_filename: encHideFilename.checked,
    sec_profile: encSecProfile.value,
    int_profile: encIntProfile.value,
  };

  try {
    await invoke("encrypt", { req: payload });
  } catch (err) {
    setStatus(String(err));
  } finally {
    setBusy(false);
    state.paused = false;
    pauseBtn.textContent = "Pause";
  }
}

async function handleDecrypt() {
  if (!invoke) return;
  setBusy(true);
  setProgress(0);
  setStatus("Decrypting...");

  const payload = {
    input_file: decFile.value.trim(),
    output_path: decOutput.value.trim(),
    password: decPassword.value,
    keyfile_path: decKeyfile.value.trim() ? decKeyfile.value.trim() : null,
    extract: decExtract.checked,
    keep_tar: decKeepTar.checked,
  };

  try {
    const result = await invoke("decrypt", { req: payload });
    if (result && result.meta) {
      renderMeta(result.meta);
    }
  } catch (err) {
    setStatus(String(err));
  } finally {
    setBusy(false);
    state.paused = false;
    pauseBtn.textContent = "Pause";
  }
}

async function handleVerify() {
  if (!invoke) return;
  setBusy(true);
  setProgress(0);
  setStatus("Verifying...");

  const payload = {
    input_file: verFile.value.trim(),
    password: verPassword.value,
    keyfile_path: verKeyfile.value.trim() ? verKeyfile.value.trim() : null,
  };

  try {
    await invoke("verify", { req: payload });
  } catch (err) {
    setStatus(String(err));
  } finally {
    setBusy(false);
    state.paused = false;
    pauseBtn.textContent = "Pause";
  }
}

async function handleReadMeta() {
  if (!invoke) return;
  const payload = { input_file: decFile.value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMeta(result);
  } catch (err) {
    setStatus(String(err));
  }
}



function handleReset() {
  if (state.busy) return; // Don't reset if busy

  // Clear Inputs
  const clearIds = [
    "encFile", "encFolder", "encOutput", "encPassword", "encKeyfile",
    "decFile", "decOutput", "decPassword", "decKeyfile",
    "verFile", "verPassword", "verKeyfile"
  ];
  clearIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  // Reset Selects/Checkboxes
  if (encFileComp) encFileComp.value = "none";
  if (encFolderComp) encFolderComp.value = "none";
  if (encSecProfile) encSecProfile.value = "Standard";
  if (encIntProfile) encIntProfile.value = "Medium";
  if (encSkipSpecial) encSkipSpecial.checked = true;
  if (encEnablePwchk) encEnablePwchk.checked = true;
  if (encHideFilename) encHideFilename.checked = false;

  if (decExtract) decExtract.checked = true;
  if (decKeepTar) decKeepTar.checked = false;

  // Clear Metadata
  if (metaContent) metaContent.textContent = "No metadata loaded.";
  if (verMetaContent) verMetaContent.textContent = "No metadata loaded.";

  // Reset Global State
  setProgress(0);
  setStatus("Ready");
  setBusy(false);
  updateMode("file");

  // Reset Panels (Visual only, default to Encrypt)
  // Reset Panels (Visual only, default to Encrypt)
  document.querySelector('.nav-item[data-tab="encrypt"]').click();

  // Reset Custom Select Visuals
  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const input = wrapper.querySelector("input[type='hidden']");
    const trigger = wrapper.querySelector(".select-trigger");
    const options = wrapper.querySelectorAll(".option");

    // Reset trigger text
    if (input && trigger) {
      // Find the option that matches the current input value (which was just reset)
      const matchingOpt = Array.from(options).find(o => o.dataset.value === input.value);
      if (matchingOpt) trigger.textContent = matchingOpt.textContent;
    }
  });
}

function renderMeta(meta) {
  renderMetaTo(metaContent, meta);
}

function renderMetaTo(target, meta) {
  if (!target) return;
  if (!meta) {
    target.textContent = "No metadata available.";
    return;
  }
  const isContainer = (meta.flags & 32) !== 0;
  const typeLabel = isContainer ? "Archive (Folder)" : "Single File";

  target.innerHTML = `
    <div><strong>Type:</strong> ${typeLabel}</div>
    <div><strong>Filename:</strong> ${meta.filename || "(hidden)"}</div>
    <div><strong>Version:</strong> ${meta.version}</div>
    <div><strong>Shard:</strong> ${meta.shard_size} bytes</div>
    <div><strong>K/R:</strong> ${meta.k} / ${meta.r}</div>
    <div><strong>Plain size:</strong> ${meta.plain_size} bytes</div>
    <div><strong>Stored size:</strong> ${meta.stored_size} bytes</div>
  `;
}

async function checkFileMetadata(path) {
  if (!invoke || !path) return;
  try {
    const meta = await invoke("read_metadata", { req: { input_file: path } });
    if (meta) {
      renderMeta(meta);
      const isContainer = (meta.flags & 32) !== 0;
      if (decExtract) {
        decExtract.checked = isContainer;
        setStatus(isContainer ? "Detected Folder: Auto-extract ON" : "Detected File: Auto-extract OFF");
      }

      // Smart Output Path Logic
      if (decOutput) {
        try {
          const sep = path.includes("\\") ? "\\" : "/";
          const dir = path.substring(0, path.lastIndexOf(sep));
          const baseName = path.split(sep).pop();
          const nameNoExt = baseName.replace(/\.ecf$/i, "");

          let suggested = "";
          if (isContainer) {
            // Folder suggestions
            suggested = `${dir}${sep}${nameNoExt}`;
          } else {
            // File suggestion
            if (meta.filename && meta.filename.trim().length > 0) {
              suggested = `${dir}${sep}${meta.filename}`;
            } else {
              suggested = `${dir}${sep}${nameNoExt}`;
            }
          }
          decOutput.value = suggested;
        } catch (e) {
          console.error("Smart path calc failed", e);
        }
      }
    }
  } catch (err) {
    console.error("Auto-detect failed:", err);
  }
}

async function bindProgressEvents() {
  if (!eventApi || !eventApi.listen) return;
  try {
    // Handle File Drop
    await eventApi.listen("tauri://file-drop", async (e) => {
      if (e && e.payload && e.payload.length > 0) {
        const path = e.payload[0];
        const activePanel = document.querySelector(".panel.active");
        if (!activePanel) return;

        if (activePanel.id === "panel-encrypt") {
          const modeFile = document.querySelector(".seg[data-mode='file']").classList.contains("active");
          if (modeFile) {
            encFile.value = path;
            // Trigger smart calculation
            if (encOutput) {
              const sep = path.includes("\\") ? "\\" : "/";
              const lastDot = path.lastIndexOf(".");
              let suggested = "";
              if (lastDot > path.lastIndexOf(sep)) {
                suggested = path.substring(0, lastDot) + ".ecf";
              } else {
                suggested = path + ".ecf";
              }
              encOutput.value = suggested;
            }
          } else {
            encFolder.value = path;
            if (encOutput) encOutput.value = path + ".ecf";
          }
        } else if (activePanel.id === "panel-decrypt") {
          decFile.value = path;
          checkFileMetadata(path);
        } else if (activePanel.id === "panel-verify") {
          verFile.value = path;
          handleReadVerifyMeta();
        }
      }
    });

    await eventApi.listen("progress", (e) => {
      if (e && e.payload) {
        setProgress(e.payload.percent);
      }
    });
    await eventApi.listen("status", (e) => {
      if (e && e.payload) {
        setStatus(e.payload);
        const match = String(e.payload).match(/(\d+)\/(\d+)/);
        if (match) {
          const done = Number(match[1]);
          const total = Number(match[2]);
          if (total > 0) {
            setProgress(done / total);
          }
        }
      }
    });
  } catch (err) {
    console.error("Event bind error:", err);
  }
}


function setupTooltips() {
  const tooltip = document.createElement("div");
  tooltip.className = "custom-tooltip";
  tooltip.style.display = "none";
  document.body.appendChild(tooltip);

  let timer = null;

  const showTooltip = (e, text) => {
    tooltip.textContent = text;
    tooltip.style.display = "block";
    moveTooltip(e);
  };

  const moveTooltip = (e) => {
    const x = e.clientX + 15;
    const y = e.clientY + 15;
    // Boundary checks
    const right = x + tooltip.offsetWidth;
    const bottom = y + tooltip.offsetHeight;

    let finalX = x;
    let finalY = y;

    if (right > window.innerWidth) finalX = e.clientX - tooltip.offsetWidth - 10;
    if (bottom > window.innerHeight) finalY = e.clientY - tooltip.offsetHeight - 10;

    tooltip.style.left = `${finalX}px`;
    tooltip.style.top = `${finalY}px`;
  };

  const hideTooltip = () => {
    tooltip.style.display = "none";
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const attach = (el) => {
    // Remove old listeners to prevent duplicates if re-running
    // (Ideally we handle this cleanly, but a quick dirty way is acceptable for this scope 
    // or we just trust 'once' or aggressive replacement. 
    // Here we will just add new ones assuming fresh elements or simple DOM)

    el.addEventListener("mouseenter", (e) => {
      const text = el.getAttribute("data-tooltip");
      if (!text) return;

      timer = setTimeout(() => {
        showTooltip(e, text);
      }, 600); // 600ms delay
    });

    el.addEventListener("mousemove", (e) => {
      // If tooltip is visible, move it
      if (tooltip.style.display === "block") {
        moveTooltip(e);
      }
    });

    el.addEventListener("mouseleave", hideTooltip);
    el.addEventListener("mousedown", hideTooltip);
  };

  // Initial attach
  document.querySelectorAll("[data-tooltip]").forEach(attach);

  // Expose attach for dynamic elements
  window.attachTooltip = attach;
}

function updateLanguage(lang) {
  state.language = lang;
  const dict = translations[lang] || translations["en"];

  // Update Text
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (dict[key]) {
      el.textContent = dict[key];
    }
  });

  // Update Tooltips
  document.querySelectorAll("[data-i18n-tooltip]").forEach(el => {
    const key = el.getAttribute("data-i18n-tooltip");
    if (dict[key]) {
      el.setAttribute("data-tooltip", dict[key]);
    }
  });

  // Update Custom Select Triggers if they match an option
  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const input = wrapper.querySelector("input[type='hidden']");
    const trigger = wrapper.querySelector(".select-trigger");
    const options = wrapper.querySelectorAll(".option");

    if (input && trigger) {
      const matchingOpt = Array.from(options).find(o => o.dataset.value === input.value);
      if (matchingOpt) trigger.textContent = matchingOpt.textContent;
    }
  });
}

function setupCustomSelects() {
  const disconnectOutside = () => {
    document.querySelectorAll(".custom-select.open").forEach(el => el.classList.remove("open"));
  };

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".custom-select")) {
      disconnectOutside();
    }
  });

  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const trigger = wrapper.querySelector(".select-trigger");
    const input = wrapper.querySelector("input[type='hidden']");
    const options = wrapper.querySelectorAll(".option");

    trigger.addEventListener("click", () => {
      // Close others
      document.querySelectorAll(".custom-select.open").forEach(el => {
        if (el !== wrapper) el.classList.remove("open");
      });
      wrapper.classList.toggle("open");
    });

    options.forEach(opt => {
      opt.addEventListener("click", (e) => {
        e.stopPropagation(); // prevent bubbling to wrapper
        const val = opt.dataset.value;
        const text = opt.textContent;

        if (input) {
          input.value = val;
          // If this is the language selector, trigger update
          if (input.id === "languageSelect") {
            updateLanguage(val);
          }
        }
        trigger.textContent = text;

        // Visual selection state
        options.forEach(o => o.classList.remove("selected"));
        opt.classList.add("selected");

        wrapper.classList.remove("open");
      });

      // Attach tooltip logic to options since they are dynamic-ish
      if (window.attachTooltip) window.attachTooltip(opt);
    });
  });
}

function assertBackendApi() {
  if (!invoke) return false;
  if (!eventApi || !eventApi.listen) return false;
  return true;
}

async function handleReadVerifyMeta() {
  if (!invoke) return;
  const payload = { input_file: verFile.value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMetaTo(verMetaContent, result);
  } catch (err) {
    setStatus(String(err));
  }
}

function bootInit() {
  try {
    statusText = document.getElementById("statusText");
    if (statusText) statusText.textContent = "JS loaded";
    progressFill = document.getElementById("progressFill");
    progressValue = document.getElementById("progressValue");
    pauseBtn = document.getElementById("pauseBtn");
    cancelBtn = document.getElementById("cancelBtn");
    resetBtn = document.getElementById("resetBtn");

    encFile = document.getElementById("encFile");
    encFolder = document.getElementById("encFolder");
    encOutput = document.getElementById("encOutput");
    encPassword = document.getElementById("encPassword");
    encKeyfile = document.getElementById("encKeyfile");
    encFileComp = document.getElementById("encFileComp");
    encFolderComp = document.getElementById("encFolderComp");
    encSkipSpecial = document.getElementById("encSkipSpecial");
    encEnablePwchk = document.getElementById("encEnablePwchk");
    encHideFilename = document.getElementById("encHideFilename");
    encSecProfile = document.getElementById("encSecProfile");
    encIntProfile = document.getElementById("encIntProfile");

    decFile = document.getElementById("decFile");
    decOutput = document.getElementById("decOutput");
    decPassword = document.getElementById("decPassword");
    decKeyfile = document.getElementById("decKeyfile");
    decExtract = document.getElementById("decExtract");
    decKeepTar = document.getElementById("decKeepTar");
    metaContent = document.getElementById("metaContent");
    verMetaContent = document.getElementById("verMetaContent");

    verFile = document.getElementById("verFile");
    verPassword = document.getElementById("verPassword");
    verKeyfile = document.getElementById("verKeyfile");

    bindNavigation();
    bindWindowControls();
    bindEvents();
    bindProgressEvents();
    bindProgressEvents();
    setupTooltips(); // Init tooltips
    setupCustomSelects(); // Init custom selects
    if (!assertBackendApi()) return;

    // Init Language
    updateLanguage("en");

    updateMode("file");
    setProgress(0);
    setBusy(false); // Ensure buttons are correct state
    setStatus("Ready");
  } catch (err) {
    setStatus(`Init error: ${err}`);
    console.error(err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootInit, { once: true });
} else {
  bootInit();
}
