// batch.js - batch decrypt queue state, rendering and execution
import { invoke } from "./tauri-bridge.js";
import { t } from "./i18n.js";
import { setStatus, setProgress, setBusy } from "./ui-state.js";
import { $, escapeHtml, basename, formatDuration, META_FLAG_TAR_CONTAINER } from "./dom.js";
import { mapErrorToUserFeedback, isCancelledError } from "./errors.js";
import { logOperation } from "./history.js";
import { clearPasswordFields } from "./password.js";

/** @type {{ path: string; status: "pending"|"running"|"ok"|"error"; error?: string }[]} */
const _batchFiles = [];
let _batchSelectedIndex = -1;

export function isEcfFile(path) {
  return /\.ecf$/i.test(String(path || "").trim());
}

/** Add paths to the batch queue, skipping duplicates and non-.ecf files. */
export function addBatchFiles(paths) {
  const skipped = [];
  paths.forEach((p) => {
    if (!p) return;
    if (!isEcfFile(p)) {
      skipped.push(p);
      return;
    }
    if (!_batchFiles.find((f) => f.path === p)) {
      _batchFiles.push({ path: p, status: "pending" });
    }
  });
  if (skipped.length > 0) {
    setStatus(`${t("batch_invalid_file")}: ${skipped.map(basename).join(", ")}`, "warn");
  }
  renderBatchList();
}

export function removeSelectedBatchFile() {
  if (_batchSelectedIndex >= 0 && _batchSelectedIndex < _batchFiles.length) {
    _batchFiles.splice(_batchSelectedIndex, 1);
    if (_batchSelectedIndex >= _batchFiles.length) _batchSelectedIndex = _batchFiles.length - 1;
    renderBatchList();
  }
}

export function clearBatchFiles() {
  _batchFiles.length = 0;
  _batchSelectedIndex = -1;
  renderBatchList();
}

export function renderBatchList() {
  const listEl = $("batchFileList");
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
      <span class="bfi-name" title="${escapeHtml(item.path)}">${escapeHtml(basename(item.path))}</span>
      <span class="bfi-status ${statusClass}">${escapeHtml(statusText)}${item.error ? `: ${escapeHtml(item.error)}` : ""}</span>
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

export async function handleBatchDecrypt() {
  if (!invoke) return;
  if (_batchFiles.length === 0) {
    setStatus(t("err_input_required"), "warn");
    return;
  }
  const batchPassword = $("batchPassword");
  const batchKeyfile = $("batchKeyfile");
  const batchOutputFolder = $("batchOutputFolder");
  const batchExtract = $("batchExtract");
  const batchSummaryBox = $("batchSummaryBox");
  const batchSummaryContent = $("batchSummaryContent");

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
  let sawCancelled = false;
  const t0 = Date.now();

  for (let i = 0; i < _batchFiles.length; i++) {
    const item = _batchFiles[i];
    item.status = "running";
    renderBatchList();
    setProgress(i / _batchFiles.length);
    setStatus(`${i + 1}/${_batchFiles.length}: ${basename(item.path)}`, "info");

    const sep = item.path.includes("\\") ? "\\" : "/";
    const lastSep = item.path.lastIndexOf(sep);
    const baseDir = (batchOutputFolder && batchOutputFolder.value.trim())
      || (lastSep > 0 ? item.path.substring(0, lastSep) : ".");
    const baseName = basename(item.path).replace(/\.ecf$/i, "");
    const join = (name) => `${baseDir}${baseDir.endsWith(sep) ? "" : sep}${name}`;

    // Per-file routing: the single global "auto-extract" toggle only makes
    // sense for folder archives. Inspect each file's header so single-file
    // .ecf entries decrypt to a real output file path instead of being treated
    // as a TAR container — which previously failed with EXTRACT_ERROR (extract
    // on) or OUTPUT_EXISTS (extract off, output_path was the folder).
    let extract;
    let outputPath;
    try {
      const meta = await invoke("read_metadata", { req: { input_file: item.path } });
      const isContainer = !!meta && (meta.flags & META_FLAG_TAR_CONTAINER) !== 0;
      if (isContainer) {
        extract = batchExtract ? batchExtract.checked : true;
        outputPath = extract ? baseDir : join(`${baseName}.tar`);
      } else {
        extract = false;
        const rawName = meta && meta.filename ? String(meta.filename).trim() : "";
        // basename() strips any path separators to avoid writing outside baseDir.
        outputPath = join(rawName ? basename(rawName) : baseName);
      }
    } catch (_) {
      // Metadata unreadable: fall back to the previous folder-extract behavior.
      extract = batchExtract ? batchExtract.checked : true;
      outputPath = baseDir;
    }

    const payload = {
      input_file: item.path,
      output_path: outputPath,
      password: batchPassword.value,
      keyfile_path: batchKeyfile && batchKeyfile.value.trim() ? batchKeyfile.value.trim() : null,
      extract,
      keep_tar: false,
    };

    const itemT0 = Date.now();
    try {
      await invoke("decrypt", { req: payload });
      item.status = "ok";
      successCount++;
      logOperation("batch", item.path, true, Date.now() - itemT0);
    } catch (err) {
      if (isCancelledError(err)) sawCancelled = true;
      item.status = "error";
      item.error = mapErrorToUserFeedback("decrypt", err).message;
      errorCount++;
      logOperation("batch", item.path, false, Date.now() - itemT0);
    }
    renderBatchList();
  }

  if (!sawCancelled) clearPasswordFields(batchPassword);
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
