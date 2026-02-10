import {
  invoke,
  eventApi,
  pickFile,
  pickFolder,
  pickSave,
  bindWindowControls,
} from "./modules/tauri-bridge.js";
import { translations } from "./modules/i18n.js";
import {
  state,
  setStatus,
  setProgress,
  setBusy,
  updateMode,
  renderMetaTo,
} from "./modules/ui-state.js";

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
let progressEventsBound = false;

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
  if (progressEventsBound) return;
  progressEventsBound = true;
  if (!eventApi || !eventApi.listen) {
    console.warn("Event API not available, skipping drag-drop bind.");
    return;
  }

  // Prevent default browser behavior to ensure drop is allowed
  document.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
  });
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
  });

  try {
    const handleDrop = (paths) => {
      if (!paths || paths.length === 0) return;

      const path = paths[0];
      const activePanel = document.querySelector(".panel.active");
      if (!activePanel) return;

      if (activePanel.id === "panel-encrypt") {
        const modeFile = document.querySelector(".seg[data-mode='file']").classList.contains("active");
        if (modeFile) {
          if (encFile) encFile.value = path;
          // Trigger smart calculation
          if (encOutput) {
            const sep = path.includes("\\") ? "\\" : "/";
            const lastDot = path.lastIndexOf(".");
            let suggested = "";
            if (lastDot > path.lastIndexOf(sep)) {
              suggested = path.substring(0, lastDot) + ".ecf";
            } else {
              suggested = path.substring(0, lastDot) + ".ecf";
              // Fallback if no dot
              if (lastDot === -1) suggested = path + ".ecf";
            }
            encOutput.value = suggested;
          }
        } else {
          if (encFolder) encFolder.value = path;
          if (encOutput) encOutput.value = path + ".ecf";
        }
      } else if (activePanel.id === "panel-decrypt") {
        if (decFile) decFile.value = path;
        checkFileMetadata(path);
      } else if (activePanel.id === "panel-verify") {
        if (verFile) verFile.value = path;
        handleReadVerifyMeta();
      }
    };

    // Handle v1/standard File Drop
    await eventApi.listen("tauri://file-drop", async (e) => {
      if (e && e.payload && e.payload.length > 0) {
        handleDrop(e.payload);
      }
    });

    // Handle v2 drag-drop (sometimes payload structure varies)
    await eventApi.listen("tauri://drag-drop", async (e) => {
      // payload might be { paths: [], position: {} } or just paths
      if (e && e.payload) {
        if (Array.isArray(e.payload)) {
          handleDrop(e.payload);
        } else if (e.payload.paths && Array.isArray(e.payload.paths)) {
          handleDrop(e.payload.paths);
        }
      }
    });

    // Listen to progress events
    await eventApi.listen("progress", (e) => {
      if (e && e.payload) {
        setProgress(e.payload.percent);
      }
    });

    // Listen to status events
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

    console.log("Drag & Drop listeners bound successfully.");

  } catch (err) {
    console.error("Event bind error:", err);
    setStatus("DnD Bind Error");
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
    setStatus("JS loaded");
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

