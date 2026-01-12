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

const state = {
  busy: false,
  paused: false,
  mode: "file",
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
  document.querySelector('.nav-item[data-tab="encrypt"]').click();
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

function assertTauri() {
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
    bindEvents();
    bindProgressEvents();
    if (!assertTauri()) return;
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
