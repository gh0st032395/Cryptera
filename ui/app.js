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

// ── Element refs ──────────────────────────────────────────────────────────────
let pauseBtn = null;
let cancelBtn = null;
let resetBtn = null;

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

let encPasswordStrengthFill = null;
let encPasswordStrengthText = null;
let encPasswordFeedback = null;
let decPasswordStrengthFill = null;
let decPasswordStrengthText = null;
let verPasswordStrengthFill = null;
let verPasswordStrengthText = null;

let progressEventsBound = false;

// ── Global error handlers ─────────────────────────────────────────────────────
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

// ── i18n helper ───────────────────────────────────────────────────────────────
function t(key) {
  const dict = translations[state.language] || translations.en;
  return dict[key] || key;
}

// ── Error mapping ─────────────────────────────────────────────────────────────
function normalizeErrorMessage(err) {
  return String(err || "").trim().toLowerCase();
}

function mapErrorToUserFeedback(action, err) {
  const raw = normalizeErrorMessage(err);

  if (raw.includes("password required")) return { message: t("err_password_required"), level: "warn" };
  if (raw.includes("input file required") || raw.includes("input file or folder required")) return { message: t("err_input_required"), level: "warn" };
  if (raw.includes("output path required")) return { message: t("err_output_required"), level: "warn" };
  if (raw.includes("output file already exists")) return { message: t("err_output_exists"), level: "warn" };
  if (raw.includes("wrong password") || raw.includes("password_invalid")) return { message: t("err_password_invalid"), level: "error" };
  if (raw.includes("header authentication failed") || raw.includes("header_auth_failed")) return { message: t("err_header_auth"), level: "error" };
  if (raw.includes("header not found") || raw.includes("header invalid") || raw.includes("invalid header") || raw.includes("unsupported version")) return { message: t("err_header_invalid"), level: "error" };
  if (raw.includes("truncated") || raw.includes("unexpected eof")) return { message: t("err_file_truncated"), level: "error" };
  if (raw.includes("corrupt_beyond_fec") || raw.includes("failed recovery")) return { message: t("err_corrupt_beyond_fec"), level: "error" };
  if (raw.includes("cancelled")) return { message: t("err_cancelled"), level: "warn" };
  if (raw.includes("state lock failed") || raw.includes("no active job")) return { message: t("err_internal_state"), level: "error" };

  if (action === "encrypt") return { message: t("err_encrypt_generic"), level: "error" };
  if (action === "decrypt") return { message: t("err_decrypt_generic"), level: "error" };
  if (action === "verify") return { message: t("err_verify_generic"), level: "error" };
  return { message: t("err_internal_state"), level: "error" };
}

function inferStatusLevelFromPayload(payload) {
  const raw = normalizeErrorMessage(payload);
  if (!raw) return "info";
  if (raw.includes("error") || raw.includes("failed")) return "error";
  if (raw.includes("cancelled")) return "warn";
  if (raw.includes("ok") || raw.includes("complete")) return "success";
  return "info";
}

function localizeBackendStatusPayload(payload) {
  if (!payload || typeof payload !== "object") return null;
  const code = String(payload.code || "").trim();
  if (!code) return null;
  const key = `status_${code}`;
  const localized = t(key);
  const text = localized !== key ? localized : String(payload.message || code);

  let level = "info";
  if (code.endsWith("_ok") || code.endsWith("_complete")) level = "success";
  if (code.includes("error") || code.includes("failed")) level = "error";
  if (code.includes("cancel")) level = "warn";
  return { text, level };
}

// ── Password strength ─────────────────────────────────────────────────────────
function assessPasswordStrength(password) {
  const value = password || "";
  if (!value) {
    return { level: 0, width: 0, labelKey: "pwd_strength_very_weak", length: 0, feedbackKeys: ["pwd_feedback_too_short"] };
  }

  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasNumber = /\d/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);

  const feedbackKeys = [];
  if (value.length < 10) feedbackKeys.push("pwd_feedback_too_short");
  if (!hasUpper) feedbackKeys.push("pwd_feedback_add_upper");
  if (!hasLower) feedbackKeys.push("pwd_feedback_add_lower");
  if (!hasNumber) feedbackKeys.push("pwd_feedback_add_number");
  if (!hasSpecial) feedbackKeys.push("pwd_feedback_add_special");

  let points = 0;
  if (value.length >= 8) points += 1;
  if (value.length >= 10) points += 1;
  if (hasLower && hasUpper) points += 1;
  if (hasNumber) points += 1;
  if (hasSpecial) points += 1;

  let level = 0;
  if (points <= 1) level = 0;
  else if (points === 2) level = 1;
  else if (points === 3) level = 2;
  else if (points === 4) level = 3;
  else level = 4;

  const labelMap = [
    "pwd_strength_very_weak",
    "pwd_strength_weak",
    "pwd_strength_medium",
    "pwd_strength_strong",
    "pwd_strength_very_strong",
  ];
  return {
    level,
    width: (level / 4) * 100,
    labelKey: labelMap[level],
    length: value.length,
    feedbackKeys,
  };
}

function meetsEncryptionPasswordPolicy(assessment) {
  return assessment.length >= 10 && assessment.level >= 2;
}

function updatePasswordStrengthMeter(password, fillEl, textEl, feedbackEl) {
  if (!fillEl || !textEl) return;
  const assessment = assessPasswordStrength(password);
  fillEl.style.width = `${Math.round(assessment.width)}%`;
  fillEl.classList.remove("strength-0", "strength-1", "strength-2", "strength-3", "strength-4");
  fillEl.classList.add(`strength-${assessment.level}`);
  textEl.textContent = `${t("pwd_strength_prefix")}: ${t(assessment.labelKey)}`;

  // Show feedback hints (only for the element that has a feedback container)
  if (feedbackEl) {
    if (assessment.level >= 4) {
      feedbackEl.textContent = t("pwd_feedback_great");
    } else if (assessment.level >= 3) {
      feedbackEl.textContent = t("pwd_feedback_good");
    } else if (assessment.feedbackKeys.length > 0) {
      feedbackEl.textContent = assessment.feedbackKeys.map(k => t(k)).join(" · ");
    } else {
      feedbackEl.textContent = "";
    }
  }
}

function refreshPasswordStrengthMeters() {
  updatePasswordStrengthMeter(encPassword?.value || "", encPasswordStrengthFill, encPasswordStrengthText, encPasswordFeedback);
  updatePasswordStrengthMeter(decPassword?.value || "", decPasswordStrengthFill, decPasswordStrengthText, null);
  updatePasswordStrengthMeter(verPassword?.value || "", verPasswordStrengthFill, verPasswordStrengthText, null);
}

// ── Meta helpers ──────────────────────────────────────────────────────────────
function getMetaLabels() {
  return {
    noMetaText: t("meta_no_data_available"),
    typeArchive: t("meta_type_archive"),
    typeFile: t("meta_type_file"),
    hiddenName: t("meta_hidden_filename"),
    typeLabel: t("meta_label_type"),
    filenameLabel: t("meta_label_filename"),
    versionLabel: t("meta_label_version"),
    shardLabel: t("meta_label_shard"),
    krLabel: t("meta_label_kr"),
    plainSizeLabel: t("meta_label_plain_size"),
    storedSizeLabel: t("meta_label_stored_size"),
  };
}

function renderMeta(meta) {
  renderMetaTo(metaContent, meta, getMetaLabels());
}

// ── Theme toggle ──────────────────────────────────────────────────────────────
const _themes = ["dark", "light", "system"];
let _themeIndex = 0;

const _sunIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
const _moonIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
const _systemIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`;

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "system") {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = prefersDark ? "dark" : "light";
  } else {
    root.dataset.theme = theme;
  }
  // Update icon
  const btn = document.getElementById("themeToggleBtn");
  if (btn) {
    if (theme === "light") btn.innerHTML = _moonIcon;
    else if (theme === "system") btn.innerHTML = _systemIcon;
    else btn.innerHTML = _sunIcon;
    btn.title = t(`theme_${theme}`);
  }
}

function cycleTheme() {
  _themeIndex = (_themeIndex + 1) % _themes.length;
  const theme = _themes[_themeIndex];
  applyTheme(theme);
  try { localStorage.setItem("cryptera_theme", theme); } catch (_) { /* ignore */ }
}

function initTheme() {
  let saved = "dark";
  try { saved = localStorage.getItem("cryptera_theme") || "dark"; } catch (_) { /* ignore */ }
  _themeIndex = _themes.indexOf(saved);
  if (_themeIndex < 0) _themeIndex = 0;
  applyTheme(_themes[_themeIndex]);
  const btn = document.getElementById("themeToggleBtn");
  if (btn) btn.addEventListener("click", cycleTheme);
  // React to system changes when theme is "system"
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (_themes[_themeIndex] === "system") applyTheme("system");
  });
}

// ── Operation History ─────────────────────────────────────────────────────────
const _history = [];  // max 100 entries
const _MAX_HISTORY = 100;

/**
 * @param {"encrypt"|"decrypt"|"verify"|"batch"} op
 * @param {string} filename
 * @param {boolean} success
 * @param {number} durationMs
 */
function logOperation(op, filename, success, durationMs) {
  const entry = {
    ts: new Date(),
    op,
    filename: filename || "—",
    success,
    durationMs,
  };
  _history.unshift(entry);
  if (_history.length > _MAX_HISTORY) _history.length = _MAX_HISTORY;
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatTimestamp(date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function basename(path) {
  if (!path) return "—";
  const norm = path.replace(/\\/g, "/");
  return norm.split("/").pop() || path;
}

function renderHistory() {
  const listEl = document.getElementById("historyList");
  if (!listEl) return;
  if (_history.length === 0) {
    listEl.innerHTML = `<div class="history-empty" data-i18n="history_empty">${t("history_empty")}</div>`;
    return;
  }
  listEl.innerHTML = _history.map(entry => {
    const opKey = `history_op_${entry.op}`;
    const opLabel = t(opKey);
    const statusClass = entry.success ? "hi-status-ok" : "hi-status-err";
    const statusText = entry.success ? "✓ OK" : "✗ ERR";
    const dur = formatDuration(entry.durationMs);
    const ts = formatTimestamp(entry.ts);
    return `<div class="history-item">
      <span class="hi-op">${opLabel}</span>
      <span class="hi-file">${basename(entry.filename)}</span>
      <span class="${statusClass}">${statusText}</span>
      <span class="hi-time">${ts} · ${dur}</span>
    </div>`;
  }).join("");
}

// ── Verify result details ─────────────────────────────────────────────────────
function showVerifyResult(success, meta) {
  const box = document.getElementById("verResultBox");
  const content = document.getElementById("verResultContent");
  if (!box || !content) return;

  if (!success) {
    box.style.display = "block";
    content.innerHTML = `<span style="color:#ff8b8b">✗ ${t("ver_result_fail")}</span>`;
    return;
  }

  box.style.display = "block";
  let html = `<div style="color:var(--accent);font-weight:600;margin-bottom:6px">✓ ${t("ver_result_ok")}</div>`;
  if (meta) {
    html += `<div><strong>${t("ver_result_shards")}:</strong> ${meta.k} / ${meta.r}</div>`;
    html += `<div><strong>${t("ver_result_plain_size")}:</strong> ${meta.plain_size} bytes</div>`;
    const fecPct = meta.r && (meta.k + meta.r) > 0
      ? Math.round((meta.r / (meta.k + meta.r)) * 100)
      : 0;
    html += `<div><strong>${t("ver_result_fec")}:</strong> ${fecPct}% parity overhead</div>`;
  }
  content.innerHTML = html;
}

// ── Batch Decrypt ─────────────────────────────────────────────────────────────
/** @type {{ path: string; status: "pending"|"running"|"ok"|"error"; error?: string }[]} */
const _batchFiles = [];
let _batchSelectedIndex = -1;

function renderBatchList() {
  const listEl = document.getElementById("batchFileList");
  if (!listEl) return;
  if (_batchFiles.length === 0) {
    listEl.innerHTML = `<div class="batch-empty" data-i18n="batch_empty">${t("batch_empty")}</div>`;
    _batchSelectedIndex = -1;
    return;
  }
  listEl.innerHTML = _batchFiles.map((item, idx) => {
    let statusClass = "";
    let statusText = t("batch_status_pending");
    if (item.status === "ok") { statusClass = "ok"; statusText = t("batch_status_ok"); }
    else if (item.status === "error") { statusClass = "err"; statusText = t("batch_status_err"); }
    else if (item.status === "running") { statusText = t("batch_status_running"); }
    const selected = idx === _batchSelectedIndex ? " style=\"border-color:var(--accent);\"" : "";
    return `<div class="batch-file-item" data-index="${idx}"${selected}>
      <span class="bfi-name" title="${item.path}">${basename(item.path)}</span>
      <span class="bfi-status ${statusClass}">${statusText}${item.error ? `: ${item.error}` : ""}</span>
      <button class="bfi-remove" data-index="${idx}" aria-label="Remove">✕</button>
    </div>`;
  }).join("");

  // Bind row click for selection
  listEl.querySelectorAll(".batch-file-item").forEach(row => {
    row.addEventListener("click", (e) => {
      if (e.target.classList.contains("bfi-remove")) return;
      _batchSelectedIndex = Number(row.dataset.index);
      renderBatchList();
    });
  });

  // Bind remove buttons
  listEl.querySelectorAll(".bfi-remove").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = Number(btn.dataset.index);
      _batchFiles.splice(idx, 1);
      if (_batchSelectedIndex >= _batchFiles.length) _batchSelectedIndex = _batchFiles.length - 1;
      renderBatchList();
    });
  });
}

async function handleBatchDecrypt() {
  if (!invoke) return;
  if (_batchFiles.length === 0) {
    setStatus(t("err_input_required"), "warn");
    return;
  }
  const batchPassword = document.getElementById("batchPassword");
  const batchKeyfile = document.getElementById("batchKeyfile");
  const batchOutputFolder = document.getElementById("batchOutputFolder");
  const batchExtract = document.getElementById("batchExtract");
  const batchSummaryBox = document.getElementById("batchSummaryBox");
  const batchSummaryContent = document.getElementById("batchSummaryContent");

  if (!batchPassword || !batchPassword.value) {
    setStatus(t("err_password_required"), "warn");
    return;
  }

  // Reset statuses
  _batchFiles.forEach(f => { f.status = "pending"; f.error = undefined; });
  renderBatchList();
  if (batchSummaryBox) batchSummaryBox.style.display = "none";

  setBusy(true);
  let successCount = 0;
  let errorCount = 0;
  const t0 = Date.now();

  for (let i = 0; i < _batchFiles.length; i++) {
    const item = _batchFiles[i];
    item.status = "running";
    renderBatchList();
    setProgress(i / _batchFiles.length);
    setStatus(`${i + 1}/${_batchFiles.length}: ${basename(item.path)}`, "info");

    const sep = item.path.includes("\\") ? "\\" : "/";
    const dir = batchOutputFolder && batchOutputFolder.value.trim()
      ? batchOutputFolder.value.trim()
      : item.path.substring(0, item.path.lastIndexOf(sep));

    const payload = {
      input_file: item.path,
      output_path: dir,
      password: batchPassword.value,
      keyfile_path: batchKeyfile && batchKeyfile.value.trim() ? batchKeyfile.value.trim() : null,
      extract: batchExtract ? batchExtract.checked : true,
      keep_tar: false,
    };

    const itemT0 = Date.now();
    try {
      await invoke("decrypt", { req: payload });
      item.status = "ok";
      successCount++;
      logOperation("batch", item.path, true, Date.now() - itemT0);
    } catch (err) {
      item.status = "error";
      item.error = mapErrorToUserFeedback("decrypt", err).message;
      errorCount++;
      logOperation("batch", item.path, false, Date.now() - itemT0);
    }
    renderBatchList();
  }

  setProgress(1);
  setBusy(false);

  const totalMs = Date.now() - t0;
  const summaryText = `${successCount} ${t("batch_summary_ok")}, ${errorCount} ${t("batch_summary_err")} — ${formatDuration(totalMs)}`;
  setStatus(summaryText, errorCount > 0 ? "warn" : "success");

  if (batchSummaryBox && batchSummaryContent) {
    batchSummaryContent.textContent = summaryText;
    batchSummaryBox.style.display = "block";
  }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
function renderAuditTable(entries) {
  const tbody = document.getElementById("auditTableBody");
  if (!tbody) return;
  if (!entries || entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="audit-empty" data-i18n="audit_empty">${t("audit_empty")}</td></tr>`;
    return;
  }
  tbody.innerHTML = entries.map(e => {
    const statusClass = e.status === "OK" ? "audit-status-ok" : "audit-status-err";
    const sizeMb = e.size_mb != null ? `${Number(e.size_mb).toFixed(2)} MB` : "—";
    const dur = e.duration_s != null ? `${Number(e.duration_s).toFixed(1)}s` : "—";
    const ts = e.ts ? new Date(e.ts).toLocaleString() : "—";
    const fileName = basename(e.file || "—");
    return `<tr>
      <td>${ts}</td>
      <td>${e.op || "—"}</td>
      <td title="${e.file || ""}">${fileName}</td>
      <td>${sizeMb}</td>
      <td>${dur}</td>
      <td class="${statusClass}">${e.status || "—"}</td>
    </tr>`;
  }).join("");
}

async function loadAuditLog() {
  if (!invoke) return;
  try {
    const entries = await invoke("get_audit_log", {});
    renderAuditTable(entries);
  } catch (err) {
    console.error("Failed to load audit log:", err);
    const tbody = document.getElementById("auditTableBody");
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="audit-empty" style="color:#ff8b8b">${err}</td></tr>`;
    }
  }
}

async function clearAuditLog() {
  if (!invoke) return;
  try {
    await invoke("clear_audit_log", {});
    renderAuditTable([]);
  } catch (err) {
    console.error("Failed to clear audit log:", err);
  }
}

// ── Navigation ────────────────────────────────────────────────────────────────
function bindNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
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
    const el = document.getElementById(id);
    if (!el) {
      setStatus(`${t("status_missing_element_prefix")}: ${id}`, "warn");
      return;
    }
    el.addEventListener("click", async (e) => {
      try {
        await handler(e);
      } catch (err) {
        setStatus(`${t("status_handler_error_prefix")}: ${err}`, "error");
        console.error(err);
      }
    });
  };

  // Encrypt panel
  onClick("encFileBtn", async () => {
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
    await pickFolder(encFolder);
    if (encFolder.value && encOutput) {
      encOutput.value = encFolder.value.trim() + ".ecf";
    }
  });
  onClick("encOutputBtn", async () => {
    const currentVal = encOutput.value.trim();
    await pickSave(encOutput, currentVal || null);
  });
  onClick("encKeyfileBtn", () => pickFile(encKeyfile));

  // Decrypt panel
  onClick("decFileBtn", async () => {
    await pickFile(decFile);
    if (decFile.value) checkFileMetadata(decFile.value);
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

  // Verify panel
  onClick("verFileBtn", async () => {
    await pickFile(verFile);
    if (verFile && verFile.value.trim()) handleReadVerifyMeta();
  });
  onClick("verKeyfileBtn", () => pickFile(verKeyfile));

  // Batch panel
  onClick("batchAddBtn", async () => {
    const result = await invoke("open_file_dialog", { multiple: true, filter: "ECF Files (*.ecf)" });
    if (Array.isArray(result)) {
      result.forEach(path => {
        if (!_batchFiles.find(f => f.path === path)) {
          _batchFiles.push({ path, status: "pending" });
        }
      });
    } else if (typeof result === "string" && result) {
      if (!_batchFiles.find(f => f.path === result)) {
        _batchFiles.push({ path: result, status: "pending" });
      }
    }
    renderBatchList();
  });
  onClick("batchRemoveBtn", () => {
    if (_batchSelectedIndex >= 0 && _batchSelectedIndex < _batchFiles.length) {
      _batchFiles.splice(_batchSelectedIndex, 1);
      if (_batchSelectedIndex >= _batchFiles.length) _batchSelectedIndex = _batchFiles.length - 1;
      renderBatchList();
    }
  });
  onClick("batchClearBtn", () => {
    _batchFiles.length = 0;
    _batchSelectedIndex = -1;
    renderBatchList();
  });
  const batchKeyfileEl = document.getElementById("batchKeyfile");
  if (batchKeyfileEl) {
    onClick("batchKeyfileBtn", () => pickFile(batchKeyfileEl));
  }
  const batchOutputFolderEl = document.getElementById("batchOutputFolder");
  if (batchOutputFolderEl) {
    onClick("batchOutputFolderBtn", async () => pickFolder(batchOutputFolderEl));
  }
  onClick("batchDecryptBtn", handleBatchDecrypt);

  // History / Audit panel
  onClick("clearHistoryBtn", () => {
    _history.length = 0;
    renderHistory();
  });
  onClick("refreshAuditBtn", loadAuditLog);
  onClick("clearAuditBtn", clearAuditLog);

  // Main action buttons
  onClick("encryptBtn", handleEncrypt);
  onClick("decryptBtn", handleDecrypt);
  onClick("verifyBtn", handleVerify);
  onClick("readMetaBtn", handleReadMeta);
  onClick("readVerifyMetaBtn", handleReadVerifyMeta);

  // Pause / Cancel / Reset
  if (pauseBtn) pauseBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      const newPausedState = !state.paused;
      await invoke("set_pause", { pause: newPausedState });
      state.paused = newPausedState;
      pauseBtn.textContent = state.paused ? "Resume" : "Pause";
    } catch (err) {
      setStatus(String(err), "error");
    }
  });

  if (cancelBtn) cancelBtn.addEventListener("click", async () => {
    if (!invoke) return;
    try {
      await invoke("cancel_job");
    } catch (err) {
      setStatus(String(err), "error");
    }
  });

  if (resetBtn) resetBtn.addEventListener("click", handleReset);

  // Password meters
  if (encPassword) {
    encPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(encPassword.value, encPasswordStrengthFill, encPasswordStrengthText, encPasswordFeedback);
    });
  }
  if (decPassword) {
    decPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(decPassword.value, decPasswordStrengthFill, decPasswordStrengthText, null);
    });
  }
  if (verPassword) {
    verPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(verPassword.value, verPasswordStrengthFill, verPasswordStrengthText, null);
    });
  }
}

// ── Main operations ───────────────────────────────────────────────────────────
async function handleEncrypt() {
  if (!invoke) return;
  const assessment = assessPasswordStrength(encPassword.value);
  if (!meetsEncryptionPasswordPolicy(assessment)) {
    setStatus(t("pwd_policy_violation"), "warn");
    updatePasswordStrengthMeter(encPassword.value, encPasswordStrengthFill, encPasswordStrengthText, encPasswordFeedback);
    return;
  }
  setBusy(true);
  setProgress(0);
  setStatus(t("status_encrypting"), "info");

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

  const t0 = Date.now();
  try {
    await invoke("encrypt", { req: payload });
    logOperation("encrypt", payload.input_file || payload.input_folder, true, Date.now() - t0);
  } catch (err) {
    logOperation("encrypt", payload.input_file || payload.input_folder, false, Date.now() - t0);
    const feedback = mapErrorToUserFeedback("encrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("encrypt error:", err);
  } finally {
    setBusy(false);
    state.paused = false;
    if (pauseBtn) pauseBtn.textContent = "Pause";
  }
}

async function handleDecrypt() {
  if (!invoke) return;
  setBusy(true);
  setProgress(0);
  setStatus(t("status_decrypting"), "info");

  const payload = {
    input_file: decFile.value.trim(),
    output_path: decOutput.value.trim(),
    password: decPassword.value,
    keyfile_path: decKeyfile.value.trim() ? decKeyfile.value.trim() : null,
    extract: decExtract.checked,
    keep_tar: decKeepTar.checked,
  };

  const t0 = Date.now();
  try {
    const result = await invoke("decrypt", { req: payload });
    logOperation("decrypt", payload.input_file, true, Date.now() - t0);
    if (result && result.meta) renderMeta(result.meta);
  } catch (err) {
    logOperation("decrypt", payload.input_file, false, Date.now() - t0);
    const feedback = mapErrorToUserFeedback("decrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("decrypt error:", err);
  } finally {
    setBusy(false);
    state.paused = false;
    if (pauseBtn) pauseBtn.textContent = "Pause";
  }
}

async function handleVerify() {
  if (!invoke) return;
  setBusy(true);
  setProgress(0);
  setStatus(t("status_verifying"), "info");
  // Hide previous result
  const verResultBox = document.getElementById("verResultBox");
  if (verResultBox) verResultBox.style.display = "none";

  const payload = {
    input_file: verFile.value.trim(),
    password: verPassword.value,
    keyfile_path: verKeyfile.value.trim() ? verKeyfile.value.trim() : null,
  };

  const t0 = Date.now();
  try {
    const result = await invoke("verify", { req: payload });
    logOperation("verify", payload.input_file, true, Date.now() - t0);
    // Show meta details — result may be MetaInfo directly or null
    showVerifyResult(true, result && result.meta ? result.meta : result);
  } catch (err) {
    logOperation("verify", payload.input_file, false, Date.now() - t0);
    showVerifyResult(false, null);
    const feedback = mapErrorToUserFeedback("verify", err);
    setStatus(feedback.message, feedback.level);
    console.error("verify error:", err);
  } finally {
    setBusy(false);
    state.paused = false;
    if (pauseBtn) pauseBtn.textContent = "Pause";
  }
}

async function handleReadMeta() {
  if (!invoke) return;
  const payload = { input_file: decFile.value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMeta(result);
  } catch (err) {
    const feedback = mapErrorToUserFeedback("decrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("read metadata error:", err);
  }
}

async function handleReadVerifyMeta() {
  if (!invoke) return;
  const payload = { input_file: verFile.value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMetaTo(verMetaContent, result, getMetaLabels());
  } catch (err) {
    const feedback = mapErrorToUserFeedback("verify", err);
    setStatus(feedback.message, feedback.level);
    console.error("read verify metadata error:", err);
  }
}

function handleReset() {
  if (state.busy) return;

  const clearIds = [
    "encFile", "encFolder", "encOutput", "encPassword", "encKeyfile",
    "decFile", "decOutput", "decPassword", "decKeyfile",
    "verFile", "verPassword", "verKeyfile",
    "batchPassword", "batchKeyfile", "batchOutputFolder",
  ];
  clearIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  if (encFileComp) encFileComp.value = "none";
  if (encFolderComp) encFolderComp.value = "none";
  if (encSecProfile) encSecProfile.value = "Standard";
  if (encIntProfile) encIntProfile.value = "Medium";
  if (encSkipSpecial) encSkipSpecial.checked = true;
  if (encEnablePwchk) encEnablePwchk.checked = true;
  if (encHideFilename) encHideFilename.checked = false;
  if (decExtract) decExtract.checked = true;
  if (decKeepTar) decKeepTar.checked = false;

  if (metaContent) metaContent.textContent = t("meta_empty");
  if (verMetaContent) verMetaContent.textContent = t("meta_empty");
  const verResultBox = document.getElementById("verResultBox");
  if (verResultBox) verResultBox.style.display = "none";

  setProgress(0);
  setStatus(t("status_ready"), "success");
  setBusy(false);
  updateMode("file");
  refreshPasswordStrengthMeters();

  document.querySelector('.nav-item[data-tab="encrypt"]').click();

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

// ── File metadata helpers ─────────────────────────────────────────────────────
async function checkFileMetadata(path) {
  if (!invoke || !path) return;
  try {
    const meta = await invoke("read_metadata", { req: { input_file: path } });
    if (meta) {
      renderMeta(meta);
      const isContainer = (meta.flags & 32) !== 0;
      if (decExtract) {
        decExtract.checked = isContainer;
        setStatus(isContainer ? t("status_detected_folder") : t("status_detected_file"), "info");
      }
      if (decOutput) {
        try {
          const sep = path.includes("\\") ? "\\" : "/";
          const dir = path.substring(0, path.lastIndexOf(sep));
          const baseName = path.split(sep).pop();
          const nameNoExt = baseName.replace(/\.ecf$/i, "");
          let suggested = "";
          if (isContainer) {
            suggested = `${dir}${sep}${nameNoExt}`;
          } else {
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

// ── Progress & DnD events ─────────────────────────────────────────────────────
async function bindProgressEvents() {
  if (progressEventsBound) return;
  progressEventsBound = true;
  if (!eventApi || !eventApi.listen) {
    console.warn("Event API not available, skipping drag-drop bind.");
    return;
  }

  document.addEventListener('dragover', (e) => { e.preventDefault(); e.stopPropagation(); });
  document.addEventListener('drop', (e) => { e.preventDefault(); e.stopPropagation(); });
  document.addEventListener("contextmenu", (e) => { e.preventDefault(); });

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
          if (encOutput) {
            const sep = path.includes("\\") ? "\\" : "/";
            const lastDot = path.lastIndexOf(".");
            let suggested = lastDot > path.lastIndexOf(sep) ? path.substring(0, lastDot) + ".ecf" : path + ".ecf";
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
      } else if (activePanel.id === "panel-batch") {
        // Add all dropped files to batch queue
        paths.forEach(p => {
          if (!_batchFiles.find(f => f.path === p)) {
            _batchFiles.push({ path: p, status: "pending" });
          }
        });
        renderBatchList();
      }
    };

    await eventApi.listen("tauri://file-drop", async (e) => {
      if (e && e.payload && e.payload.length > 0) handleDrop(e.payload);
    });

    await eventApi.listen("tauri://drag-drop", async (e) => {
      if (e && e.payload) {
        if (Array.isArray(e.payload)) handleDrop(e.payload);
        else if (e.payload.paths && Array.isArray(e.payload.paths)) handleDrop(e.payload.paths);
      }
    });

    await eventApi.listen("progress", (e) => {
      if (e && e.payload) setProgress(e.payload.percent);
    });

    await eventApi.listen("status", (e) => {
      if (e && e.payload) {
        const localizedPayload = localizeBackendStatusPayload(e.payload);
        if (localizedPayload) {
          setStatus(localizedPayload.text, localizedPayload.level);
          return;
        }
        setStatus(e.payload, inferStatusLevelFromPayload(e.payload));
        const match = String(e.payload).match(/(\d+)\/(\d+)/);
        if (match) {
          const done = Number(match[1]);
          const total = Number(match[2]);
          if (total > 0) setProgress(done / total);
        }
      }
    });

    console.log("Drag & Drop listeners bound successfully.");
  } catch (err) {
    console.error("Event bind error:", err);
    setStatus(t("status_dnd_bind_error"), "error");
  }
}

// ── Tooltips ──────────────────────────────────────────────────────────────────
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
    let finalX = x, finalY = y;
    if (x + tooltip.offsetWidth > window.innerWidth) finalX = e.clientX - tooltip.offsetWidth - 10;
    if (y + tooltip.offsetHeight > window.innerHeight) finalY = e.clientY - tooltip.offsetHeight - 10;
    tooltip.style.left = `${finalX}px`;
    tooltip.style.top = `${finalY}px`;
  };

  const hideTooltip = () => {
    tooltip.style.display = "none";
    if (timer) { clearTimeout(timer); timer = null; }
  };

  const attach = (el) => {
    el.addEventListener("mouseenter", (e) => {
      const text = el.getAttribute("data-tooltip");
      if (!text) return;
      timer = setTimeout(() => showTooltip(e, text), 600);
    });
    el.addEventListener("mousemove", (e) => {
      if (tooltip.style.display === "block") moveTooltip(e);
    });
    el.addEventListener("mouseleave", hideTooltip);
    el.addEventListener("mousedown", hideTooltip);
  };

  document.querySelectorAll("[data-tooltip]").forEach(attach);
  window.attachTooltip = attach;
}

// ── Language ──────────────────────────────────────────────────────────────────
function updateLanguage(lang) {
  state.language = lang;
  const dict = translations[lang] || translations["en"];

  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (dict[key]) el.textContent = dict[key];
  });

  document.querySelectorAll("[data-i18n-tooltip]").forEach(el => {
    const key = el.getAttribute("data-i18n-tooltip");
    if (dict[key]) el.setAttribute("data-tooltip", dict[key]);
  });

  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const input = wrapper.querySelector("input[type='hidden']");
    const trigger = wrapper.querySelector(".select-trigger");
    const options = wrapper.querySelectorAll(".option");
    if (input && trigger) {
      const matchingOpt = Array.from(options).find(o => o.dataset.value === input.value);
      if (matchingOpt) trigger.textContent = matchingOpt.textContent;
    }
  });

  refreshPasswordStrengthMeters();
}

// ── Custom selects ────────────────────────────────────────────────────────────
function setupCustomSelects() {
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".custom-select")) {
      document.querySelectorAll(".custom-select.open").forEach(el => el.classList.remove("open"));
    }
  });

  document.querySelectorAll(".custom-select").forEach(wrapper => {
    const trigger = wrapper.querySelector(".select-trigger");
    const input = wrapper.querySelector("input[type='hidden']");
    const options = wrapper.querySelectorAll(".option");

    if (!trigger) return;
    trigger.addEventListener("click", () => {
      document.querySelectorAll(".custom-select.open").forEach(el => {
        if (el !== wrapper) el.classList.remove("open");
      });
      wrapper.classList.toggle("open");
    });

    options.forEach(opt => {
      opt.addEventListener("click", (e) => {
        e.stopPropagation();
        const val = opt.dataset.value;
        const text = opt.textContent;
        if (input) {
          input.value = val;
          if (input.id === "languageSelect") updateLanguage(val);
        }
        trigger.textContent = text;
        options.forEach(o => o.classList.remove("selected"));
        opt.classList.add("selected");
        wrapper.classList.remove("open");
      });
      if (window.attachTooltip) window.attachTooltip(opt);
    });
  });
}

function assertBackendApi() {
  if (!invoke) return false;
  if (!eventApi || !eventApi.listen) return false;
  return true;
}

// ── Boot ──────────────────────────────────────────────────────────────────────
function bootInit() {
  try {
    setStatus(t("status_js_loaded"), "info");

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

    encPasswordStrengthFill = document.getElementById("encPasswordStrengthFill");
    encPasswordStrengthText = document.getElementById("encPasswordStrengthText");
    encPasswordFeedback = document.getElementById("encPasswordFeedback");
    decPasswordStrengthFill = document.getElementById("decPasswordStrengthFill");
    decPasswordStrengthText = document.getElementById("decPasswordStrengthText");
    verPasswordStrengthFill = document.getElementById("verPasswordStrengthFill");
    verPasswordStrengthText = document.getElementById("verPasswordStrengthText");

    initTheme();
    bindNavigation();
    bindWindowControls();
    bindEvents();
    bindProgressEvents();
    setupTooltips();
    setupCustomSelects();

    if (!assertBackendApi()) return;

    updateLanguage("en");
    updateMode("file");
    refreshPasswordStrengthMeters();
    setProgress(0);
    setBusy(false);
    setStatus(t("status_ready"), "success");
  } catch (err) {
    setStatus(`${t("status_init_error_prefix")}: ${err}`, "error");
    console.error(err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootInit, { once: true });
} else {
  bootInit();
}
