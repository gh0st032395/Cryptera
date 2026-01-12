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
    hero_title: "Secure files, fast workflows.",
    hero_subtitle: "Offline encryption with Rust core. Clean UI, precise control.",
    metric_engine: "Engine",
    metric_mode: "Mode",
    metric_local: "Local Only",
    panel_encrypt_title: "Encrypt",
    panel_encrypt_desc: "Protect a file or a folder with strong crypto defaults.",
    card_source: "Source",
    seg_file: "File",
    seg_folder: "Folder",
    label_file_path: "File path",
    btn_choose: "Choose",
    label_folder_path: "Folder path",
    label_output_file: "Output file",
    btn_save_as: "Save As",
    card_security: "Security",
    label_password: "Password",
    label_keyfile: "Keyfile (optional)",
    label_sec_profile: "Security profile",
    opt_standard: "Standard",
    opt_strong: "Strong",
    opt_paranoid: "Paranoid",
    label_int_profile: "Integrity profile",
    opt_medium: "Medium",
    opt_low: "Low",
    opt_high: "High",
    opt_max: "Max",
    card_options: "Options",
    label_file_comp: "File compression",
    opt_none: "none",
    opt_zlib: "zlib",
    opt_lzma: "lzma",
    label_folder_comp: "Folder archive compression",
    opt_gz: "gz",
    opt_bz2: "bz2",
    opt_xz: "xz",
    check_skip_special: "Skip symlinks and special entries",
    check_pwchk: "Enable password check record",
    check_hide_filename: "Hide original filename",
    btn_start_enc: "Start Encryption",
    panel_decrypt_title: "Decrypt",
    panel_decrypt_desc: "Recover files and optionally extract archived folders.",
    label_encrypted_file: "Encrypted file",
    label_output_path: "Output path",
    btn_select: "Select",
    meta_title: "Metadata",
    meta_empty: "No metadata loaded.",
    btn_read_meta: "Read Metadata",
    card_credentials: "Credentials",
    check_auto_extract: "Auto extract TAR containers",
    check_keep_tar: "Keep decrypted TAR",
    btn_start_dec: "Start Decryption",
    panel_verify_title: "Verify",
    panel_verify_desc: "Validate integrity without decrypting.",
    card_target: "Target",
    btn_run_ver: "Run Verification",
    panel_about_title: "About",
    panel_about_desc: "Local security, no compromises.",
    about_text: "CryptoV2 is a local encryption app based on Rust. Uses AES-GCM and Argon2id with erasure coding for integrity and recovery. No uploads, no external services.",
    label_language: "Language",

    // Tooltips
    tooltip_sec_standard: "Argon2id: 3 passes, 64MB RAM. Balanced security (Default).",
    tooltip_sec_strong: "Argon2id: 6 passes, 256MB RAM. Heavy protection against brute-force.",
    tooltip_sec_paranoid: "Argon2id: 10 passes, 512MB RAM. Maximum security, slower encryption.",
    tooltip_int_profile: "Determines how many recovery shards are generated for file redundancy.",
    tooltip_int_medium: "24 Data / 8 Parity shards. Good balance.",
    tooltip_int_low: "28 Data / 4 Parity shards. Minimal overhead.",
    tooltip_int_high: "12 Data / 12 Parity shards. High redundancy (50% overhead).",
    tooltip_int_max: "8 Data / 24 Parity shards. Maximum redundancy (300% overhead).",
    tooltip_file_comp: "Compresses the file before encryption to save space.",
    tooltip_file_comp_none: "No compression. Fastest.",
    tooltip_file_comp_zlib: "DEFLATE compression. Good for documents.",
    tooltip_file_comp_lzma: "LZMA compression. Best ratio, slower.",
    tooltip_folder_comp: "Compresses the TAR archive when encrypting a folder.",
    tooltip_folder_comp_none: "No compression.",
    tooltip_folder_comp_gz: "Gzip. Fast and widely compatible.",
    tooltip_folder_comp_bz2: "Bzip2. Better compression than Gzip.",
    tooltip_folder_comp_xz: "XZ/LZMA. Best compression, slower.",
    tooltip_skip_special: "If checked, symbolic links and special device files will be detected and skipped to prevent errors.",
    tooltip_enable_pwchk: "Adds a hashed check value to the header. Allows validating the password before attempting full decryption.",
    tooltip_hide_filename: "Stores the original filename inside the encrypted header, so the output file can have a random name.",
  },
  it: {
    nav_encrypt: "Cifra",
    nav_decrypt: "Decifra",
    nav_verify: "Verifica",
    nav_about: "Info",
    hero_title: "File sicuri, flusso veloce.",
    hero_subtitle: "Cifratura offline con core Rust. UI pulita, controllo totale.",
    metric_engine: "Motore",
    metric_mode: "Modo",
    metric_local: "Locale",
    panel_encrypt_title: "Cifra",
    panel_encrypt_desc: "Proteggi un file o cartella con crittografia forte.",
    card_source: "Sorgente",
    seg_file: "File",
    seg_folder: "Cartella",
    label_file_path: "Percorso file",
    btn_choose: "Scegli",
    label_folder_path: "Percorso cartella",
    label_output_file: "File output",
    btn_save_as: "Salva come",
    card_security: "Sicurezza",
    label_password: "Password",
    label_keyfile: "Keyfile (opzionale)",
    label_sec_profile: "Profilo sicurezza",
    opt_standard: "Standard",
    opt_strong: "Forte",
    opt_paranoid: "Paranoico",
    label_int_profile: "Profilo integrità",
    opt_medium: "Medio",
    opt_low: "Basso",
    opt_high: "Alto",
    opt_max: "Max",
    card_options: "Opzioni",
    label_file_comp: "Compressione file",
    opt_none: "nessuna",
    opt_zlib: "zlib",
    opt_lzma: "lzma",
    label_folder_comp: "Compressione archivio",
    opt_gz: "gz",
    opt_bz2: "bz2",
    opt_xz: "xz",
    check_skip_special: "Salta link simbolici e file speciali",
    check_pwchk: "Abilita record di controllo password",
    check_hide_filename: "Nascondi nome file originale",
    btn_start_enc: "Avvia Cifratura",
    panel_decrypt_title: "Decifra",
    panel_decrypt_desc: "Recupera file ed estrai archivi opzionalmente.",
    label_encrypted_file: "File cifrato",
    label_output_path: "Percorso output",
    btn_select: "Seleziona",
    meta_title: "Metadati",
    meta_empty: "Nessun metadato caricato.",
    btn_read_meta: "Leggi Metadati",
    card_credentials: "Credenziali",
    check_auto_extract: "Estrai automaticamente container TAR",
    check_keep_tar: "Mantieni TAR decifrato",
    btn_start_dec: "Avvia Decifratura",
    panel_verify_title: "Verifica",
    panel_verify_desc: "Valida integrità senza decifrare.",
    card_target: "Target",
    btn_run_ver: "Esegui Verifica",
    panel_about_title: "Info",
    panel_about_desc: "Sicurezza locale, senza compromessi.",
    about_text: "CryptoV2 è un'app di cifratura locale basata su Rust. Usa AES-GCM e Argon2id con codifica ridondante per integrità e recupero. Nessun upload, nessun servizio esterno.",
    label_language: "Lingua",

    // Tooltips
    tooltip_sec_standard: "Argon2id: 3 passaggi, 64MB RAM. Sicurezza bilanciata (Default).",
    tooltip_sec_strong: "Argon2id: 6 passaggi, 256MB RAM. Protezione pesante contro brute-force.",
    tooltip_sec_paranoid: "Argon2id: 10 passaggi, 512MB RAM. Massima sicurezza, cifratura più lenta.",
    tooltip_int_profile: "Determina quanti frammenti di recupero sono generati per ridondanza.",
    tooltip_int_medium: "24 Dati / 8 Parità. Buon bilanciamento.",
    tooltip_int_low: "28 Dati / 4 Parità. Overhead minimo.",
    tooltip_int_high: "12 Dati / 12 Parità. Alta ridondanza (50% overhead).",
    tooltip_int_max: "8 Dati / 24 Parità. Massima ridondanza (300% overhead).",
    tooltip_file_comp: "Comprime il file prima di cifrare per risparmiare spazio.",
    tooltip_file_comp_none: "Nessuna compressione. Più veloce.",
    tooltip_file_comp_zlib: "Compressione DEFLATE. Buona per documenti.",
    tooltip_file_comp_lzma: "Compressione LZMA. Miglior ratio, più lento.",
    tooltip_folder_comp: "Comprime l'archivio TAR quando cifri una cartella.",
    tooltip_folder_comp_none: "Nessuna compressione.",
    tooltip_folder_comp_gz: "Gzip. Veloce e ampiamente compatibile.",
    tooltip_folder_comp_bz2: "Bzip2. Compressione migliore di Gzip.",
    tooltip_folder_comp_xz: "XZ/LZMA. Compressione migliore, più lenta.",
    tooltip_skip_special: "Se attivo, link simbolici e file speciali vengono saltati per evitare errori.",
    tooltip_enable_pwchk: "Aggiunge un valore di hash all'header. Permette di validare la password prima di decifrare.",
    tooltip_hide_filename: "Salva il nome originale dentro l'header cifrato, così il file di output può avere un nome casuale.",
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
