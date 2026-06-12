// app.js - bootstrap: element wiring and module initialization only.
// Feature logic lives in ./modules/ (operations, batch, metadata, ...).
import {
  invoke,
  eventApi,
  pickFile,
  pickFolder,
  pickSave,
  bindWindowControls,
} from "./modules/tauri-bridge.js";
import { t, updateLanguage } from "./modules/i18n.js";
import { state, setStatus, setProgress, setBusy, updateMode } from "./modules/ui-state.js";
import { $ } from "./modules/dom.js";
import { errorToText } from "./modules/errors.js";
import { refreshPasswordStrengthMeters, bindPasswordEvents } from "./modules/password.js";
import { renderHistory, clearHistory } from "./modules/history.js";
import { addBatchFiles, removeSelectedBatchFile, clearBatchFiles, handleBatchDecrypt } from "./modules/batch.js";
import { loadAuditLog, clearAuditLog } from "./modules/audit-view.js";
import {
  handleEncrypt,
  handleDecrypt,
  handleVerify,
  handleReadMeta,
  handleReadVerifyMeta,
  handleReset,
} from "./modules/operations.js";
import { checkFileMetadata, resetDecryptAutoFillState, bindMetadataDirtyTracking } from "./modules/metadata.js";
import { bindDragAndDrop } from "./modules/dnd.js";
import { bindBackendEvents } from "./modules/events.js";
import { initTheme } from "./modules/theme.js";
import { setupTooltips } from "./modules/tooltip.js";
import { setupCustomSelects } from "./modules/select.js";

// ── Global error handlers ─────────────────────────────────────────────────────
window.addEventListener("error", (e) => {
  const status = $("statusText");
  if (status) status.textContent = `JS error: ${e.message}`;
  console.error("JS error:", e);
});

window.addEventListener("unhandledrejection", (e) => {
  const status = $("statusText");
  if (status) status.textContent = `Promise error: ${errorToText(e.reason)}`;
  console.error("Promise error:", e);
});

// ── Navigation ────────────────────────────────────────────────────────────────
function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const target = btn.dataset.tab;
      document.querySelectorAll(".panel").forEach((panel) => {
        panel.classList.toggle("active", panel.id === `panel-${target}`);
      });
      // Auto-load dynamic panels
      if (target === "history") renderHistory();
      if (target === "audit") loadAuditLog();
    });
  });
}

// ── Event binding ─────────────────────────────────────────────────────────────
function bindEvents() {
  document.querySelectorAll(".seg").forEach((btn) => {
    btn.addEventListener("click", () => updateMode(btn.dataset.mode));
  });

  const onClick = (id, handler) => {
    const el = $(id);
    if (!el) {
      setStatus(`${t("status_missing_element_prefix")}: ${id}`, "warn");
      return;
    }
    el.addEventListener("click", async (e) => {
      try {
        await handler(e);
      } catch (err) {
        setStatus(`${t("status_handler_error_prefix")}: ${errorToText(err)}`, "error");
        console.error(err);
      }
    });
  };

  // Encrypt panel
  onClick("encFileBtn", async () => {
    const encFile = $("encFile");
    const encOutput = $("encOutput");
    await pickFile(encFile);
    if (encFile.value && encOutput) {
      try {
        const path = encFile.value.trim();
        const sep = path.includes("\\") ? "\\" : "/";
        const lastDot = path.lastIndexOf(".");
        let suggested = "";
        if (lastDot > path.lastIndexOf(sep)) {
          suggested = path.substring(0, lastDot) + ".ecf";
        } else {
          suggested = path + ".ecf";
        }
        encOutput.value = suggested;
      } catch (e) {
        console.error("Smart enc path failed", e);
      }
    }
  });
  onClick("encFolderBtn", async () => {
    const encFolder = $("encFolder");
    const encOutput = $("encOutput");
    await pickFolder(encFolder);
    if (encFolder.value && encOutput) {
      encOutput.value = encFolder.value.trim() + ".ecf";
    }
  });
  onClick("encOutputBtn", async () => {
    const encOutput = $("encOutput");
    const currentVal = encOutput.value.trim();
    await pickSave(encOutput, currentVal || null);
  });
  onClick("encKeyfileBtn", () => pickFile($("encKeyfile")));

  // Decrypt panel
  onClick("decFileBtn", async () => {
    const decFile = $("decFile");
    await pickFile(decFile);
    if (decFile.value) {
      resetDecryptAutoFillState();
      checkFileMetadata(decFile.value);
    }
  });
  onClick("decOutputBtn", async () => {
    const decOutput = $("decOutput");
    const decExtract = $("decExtract");
    const currentVal = decOutput.value.trim();
    if (decExtract && decExtract.checked) {
      await pickFolder(decOutput, currentVal || null);
    } else {
      await pickSave(decOutput, currentVal || null);
    }
  });
  onClick("decKeyfileBtn", () => pickFile($("decKeyfile")));

  // Verify panel
  onClick("verFileBtn", async () => {
    const verFile = $("verFile");
    await pickFile(verFile);
    if (verFile && verFile.value.trim()) handleReadVerifyMeta();
  });
  onClick("verKeyfileBtn", () => pickFile($("verKeyfile")));

  // Batch panel
  onClick("batchAddBtn", async () => {
    const result = await invoke("open_file_dialog", { multiple: true, filter: "ECF Files (*.ecf)" });
    if (Array.isArray(result)) {
      addBatchFiles(result);
    } else if (typeof result === "string" && result) {
      addBatchFiles([result]);
    }
  });
  onClick("batchRemoveBtn", removeSelectedBatchFile);
  onClick("batchClearBtn", clearBatchFiles);
  const batchKeyfileEl = $("batchKeyfile");
  if (batchKeyfileEl) {
    onClick("batchKeyfileBtn", () => pickFile(batchKeyfileEl));
  }
  const batchOutputFolderEl = $("batchOutputFolder");
  if (batchOutputFolderEl) {
    onClick("batchOutputFolderBtn", async () => pickFolder(batchOutputFolderEl));
  }
  onClick("batchDecryptBtn", handleBatchDecrypt);

  // History / Audit panel
  onClick("clearHistoryBtn", clearHistory);
  onClick("refreshAuditBtn", loadAuditLog);
  onClick("clearAuditBtn", clearAuditLog);

  // About panel
  onClick("checkUpdatesBtn", () => invoke("open_releases_page"));

  // Warn when the selected Argon2 profile may not fit in available RAM
  const encSecProfileEl = $("encSecProfile");
  if (encSecProfileEl) {
    encSecProfileEl.addEventListener("change", () => warnIfLowMemory(encSecProfileEl.value));
  }

  // Main action buttons
  onClick("encryptBtn", handleEncrypt);
  onClick("decryptBtn", handleDecrypt);
  onClick("verifyBtn", handleVerify);
  onClick("readMetaBtn", handleReadMeta);
  onClick("readVerifyMetaBtn", handleReadVerifyMeta);

  // Pause / Cancel / Reset
  const pauseBtn = $("pauseBtn");
  const cancelBtn = $("cancelBtn");
  const resetBtn = $("resetBtn");

  if (pauseBtn) pauseBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      const newPausedState = !state.paused;
      await invoke("set_pause", { pause: newPausedState });
      state.paused = newPausedState;
      pauseBtn.textContent = state.paused ? "Resume" : "Pause";
    } catch (err) {
      setStatus(errorToText(err), "error");
    }
  });

  if (cancelBtn) cancelBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      await invoke("cancel_job");
    } catch (err) {
      setStatus(errorToText(err), "error");
    }
  });

  if (resetBtn) resetBtn.addEventListener("click", handleReset);
}

function assertBackendApi() {
  if (!invoke) return false;
  if (!eventApi || !eventApi.listen) return false;
  return true;
}

// ── Memory guard for Argon2 profiles ──────────────────────────────────────────
const PROFILE_MEMORY_MB = { Standard: 64, Strong: 256, Paranoid: 512 };

async function warnIfLowMemory(profile) {
  const need = PROFILE_MEMORY_MB[profile];
  if (!invoke || !need || need <= PROFILE_MEMORY_MB.Standard) return;
  try {
    const mem = await invoke("get_memory_info");
    const avail = Number(mem?.available_mb || 0);
    // Keep headroom for the OS and the app itself.
    if (avail > 0 && avail < need + 256) {
      setStatus(
        t("warn_low_memory").replace("{need}", String(need)).replace("{avail}", String(avail)),
        "warn",
      );
    }
  } catch (err) {
    console.error("memory info:", err);
  }
}

// ── Launch file (.ecf opened via file association) ───────────────────────────
function openDecryptWith(path) {
  const decFile = $("decFile");
  if (!decFile || !path) return;
  decFile.value = path;
  resetDecryptAutoFillState();
  checkFileMetadata(path);
  const tab = document.querySelector('.nav-item[data-tab="decrypt"]');
  if (tab) tab.click();
}

async function applyLaunchFile() {
  if (!invoke) return;
  try {
    // Windows/Linux: path arrives as a command-line argument.
    const path = await invoke("get_launch_file");
    if (path) openDecryptWith(path);
  } catch (err) {
    console.error("launch file:", err);
  }
  // macOS: paths arrive as a runtime event from RunEvent::Opened.
  if (eventApi && eventApi.listen) {
    await eventApi.listen("launch-file", (e) => {
      const p = Array.isArray(e?.payload) ? e.payload[0] : e?.payload;
      if (p) openDecryptWith(p);
    });
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
function bootInit() {
  try {
    setStatus(t("status_js_loaded"), "info");

    initTheme();
    bindNavigation();
    bindWindowControls();
    bindEvents();
    bindPasswordEvents();
    bindMetadataDirtyTracking();
    bindDragAndDrop();
    bindBackendEvents();
    setupTooltips();
    setupCustomSelects();

    if (!assertBackendApi()) return;

    updateLanguage("en");
    updateMode("file");
    refreshPasswordStrengthMeters();
    setProgress(0);
    setBusy(false);
    setStatus(t("status_ready"), "success");
    applyLaunchFile().catch((err) => console.error(err));
    invoke("get_app_version")
      .then((v) => {
        const el = $("appVersion");
        if (el) el.textContent = v;
      })
      .catch(() => { /* non-critical */ });
  } catch (err) {
    setStatus(`${t("status_init_error_prefix")}: ${errorToText(err)}`, "error");
    console.error(err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootInit, { once: true });
} else {
  bootInit();
}
