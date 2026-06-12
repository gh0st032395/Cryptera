// operations.js - encrypt / decrypt / verify / metadata handlers and reset
import { invoke } from "./tauri-bridge.js";
import { t } from "./i18n.js";
import { state, setStatus, setProgress, setBusy, updateMode, renderMetaTo } from "./ui-state.js";
import { $, escapeHtml, syncSelectTriggers } from "./dom.js";
import { mapErrorToUserFeedback, isCancelledError } from "./errors.js";
import {
  assessPasswordStrength,
  meetsEncryptionPasswordPolicy,
  updatePasswordStrengthMeter,
  refreshPasswordStrengthMeters,
  clearPasswordFields,
} from "./password.js";
import { logOperation } from "./history.js";
import { renderMeta, getMetaLabels, resetDecryptAutoFillState } from "./metadata.js";

function resetPauseButton() {
  state.paused = false;
  const pauseBtn = $("pauseBtn");
  if (pauseBtn) pauseBtn.textContent = "Pause";
}

// ── Verify result details ─────────────────────────────────────────────────────
export function showVerifyResult(success, meta) {
  const box = $("verResultBox");
  const content = $("verResultContent");
  if (!box || !content) return;

  if (!success) {
    box.style.display = "block";
    content.innerHTML = `<span style="color:#ff8b8b">✗ ${t("ver_result_fail")}</span>`;
    return;
  }

  box.style.display = "block";
  let html = `<div style="color:var(--accent);font-weight:600;margin-bottom:6px">✓ ${t("ver_result_ok")}</div>`;
  if (meta) {
    html += `<div><strong>${t("ver_result_shards")}:</strong> ${escapeHtml(meta.k)} / ${escapeHtml(meta.r)}</div>`;
    html += `<div><strong>${t("ver_result_plain_size")}:</strong> ${escapeHtml(meta.plain_size)} bytes</div>`;
    const fecPct = meta.r && (meta.k + meta.r) > 0
      ? Math.round((meta.r / (meta.k + meta.r)) * 100)
      : 0;
    html += `<div><strong>${t("ver_result_fec")}:</strong> ${fecPct}% parity overhead</div>`;
  }
  content.innerHTML = html;
}

// ── Main operations ───────────────────────────────────────────────────────────
export async function handleEncrypt() {
  if (!invoke) return;
  const encPassword = $("encPassword");
  const assessment = assessPasswordStrength(encPassword.value);
  if (!meetsEncryptionPasswordPolicy(assessment)) {
    setStatus(t("pwd_policy_violation"), "warn");
    updatePasswordStrengthMeter(encPassword.value, $("encPasswordStrengthFill"), $("encPasswordStrengthText"), $("encPasswordFeedback"));
    return;
  }
  setBusy(true);
  setProgress(0);
  setStatus(t("status_encrypting"), "info");

  const payload = {
    input_file: state.mode === "file" ? $("encFile").value.trim() : "",
    input_folder: state.mode === "folder" ? $("encFolder").value.trim() : "",
    output_file: $("encOutput").value.trim(),
    password: encPassword.value,
    keyfile_path: $("encKeyfile").value.trim() ? $("encKeyfile").value.trim() : null,
    folder_comp: $("encFolderComp").value,
    file_comp: $("encFileComp").value,
    skip_special: $("encSkipSpecial").checked,
    enable_pwchk: $("encEnablePwchk").checked,
    hide_filename: $("encHideFilename").checked,
    sec_profile: $("encSecProfile").value,
    int_profile: $("encIntProfile").value,
  };

  const t0 = Date.now();
  let cancelled = false;
  try {
    await invoke("encrypt", { req: payload });
    logOperation("encrypt", payload.input_file || payload.input_folder, true, Date.now() - t0);
  } catch (err) {
    cancelled = isCancelledError(err);
    logOperation("encrypt", payload.input_file || payload.input_folder, false, Date.now() - t0);
    const feedback = mapErrorToUserFeedback("encrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("encrypt error:", err);
  } finally {
    if (!cancelled) clearPasswordFields(encPassword);
    setBusy(false);
    resetPauseButton();
  }
}

export async function handleDecrypt() {
  if (!invoke) return;
  const decPassword = $("decPassword");
  setBusy(true);
  setProgress(0);
  setStatus(t("status_decrypting"), "info");

  const payload = {
    input_file: $("decFile").value.trim(),
    output_path: $("decOutput").value.trim(),
    password: decPassword.value,
    keyfile_path: $("decKeyfile").value.trim() ? $("decKeyfile").value.trim() : null,
    extract: $("decExtract").checked,
    keep_tar: $("decKeepTar").checked,
  };

  const t0 = Date.now();
  let cancelled = false;
  try {
    const result = await invoke("decrypt", { req: payload });
    logOperation("decrypt", payload.input_file, true, Date.now() - t0);
    if (result && result.meta) renderMeta(result.meta);
  } catch (err) {
    cancelled = isCancelledError(err);
    logOperation("decrypt", payload.input_file, false, Date.now() - t0);
    const feedback = mapErrorToUserFeedback("decrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("decrypt error:", err);
  } finally {
    if (!cancelled) clearPasswordFields(decPassword);
    setBusy(false);
    resetPauseButton();
  }
}

export async function handleVerify() {
  if (!invoke) return;
  const verPassword = $("verPassword");
  setBusy(true);
  setProgress(0);
  setStatus(t("status_verifying"), "info");
  // Hide previous result
  const verResultBox = $("verResultBox");
  if (verResultBox) verResultBox.style.display = "none";

  const payload = {
    input_file: $("verFile").value.trim(),
    password: verPassword.value,
    keyfile_path: $("verKeyfile").value.trim() ? $("verKeyfile").value.trim() : null,
  };

  const t0 = Date.now();
  let cancelled = false;
  try {
    const result = await invoke("verify", { req: payload });
    logOperation("verify", payload.input_file, true, Date.now() - t0);
    // Show meta details — result may be MetaInfo directly or null
    showVerifyResult(true, result && result.meta ? result.meta : result);
  } catch (err) {
    cancelled = isCancelledError(err);
    logOperation("verify", payload.input_file, false, Date.now() - t0);
    showVerifyResult(false, null);
    const feedback = mapErrorToUserFeedback("verify", err);
    setStatus(feedback.message, feedback.level);
    console.error("verify error:", err);
  } finally {
    if (!cancelled) clearPasswordFields(verPassword);
    setBusy(false);
    resetPauseButton();
  }
}

export async function handleReadMeta() {
  if (!invoke) return;
  const payload = { input_file: $("decFile").value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMeta(result);
  } catch (err) {
    const feedback = mapErrorToUserFeedback("decrypt", err);
    setStatus(feedback.message, feedback.level);
    console.error("read metadata error:", err);
  }
}

export async function handleReadVerifyMeta() {
  if (!invoke) return;
  const payload = { input_file: $("verFile").value.trim() };
  try {
    const result = await invoke("read_metadata", { req: payload });
    renderMetaTo($("verMetaContent"), result, getMetaLabels());
  } catch (err) {
    const feedback = mapErrorToUserFeedback("verify", err);
    setStatus(feedback.message, feedback.level);
    console.error("read verify metadata error:", err);
  }
}

export function handleReset() {
  if (state.busy) return;

  const clearIds = [
    "encFile", "encFolder", "encOutput", "encPassword", "encKeyfile",
    "decFile", "decOutput", "decPassword", "decKeyfile",
    "verFile", "verPassword", "verKeyfile",
    "batchPassword", "batchKeyfile", "batchOutputFolder",
  ];
  clearIds.forEach(id => {
    const el = $(id);
    if (el) el.value = "";
  });

  const setVal = (id, value) => { const el = $(id); if (el) el.value = value; };
  const setChecked = (id, value) => { const el = $(id); if (el) el.checked = value; };
  setVal("encFileComp", "none");
  setVal("encFolderComp", "none");
  setVal("encSecProfile", "Standard");
  setVal("encIntProfile", "Medium");
  setChecked("encSkipSpecial", true);
  setChecked("encEnablePwchk", true);
  setChecked("encHideFilename", false);
  setChecked("decExtract", true);
  setChecked("decKeepTar", false);

  resetDecryptAutoFillState();
  const metaContent = $("metaContent");
  const verMetaContent = $("verMetaContent");
  if (metaContent) metaContent.textContent = t("meta_empty");
  if (verMetaContent) verMetaContent.textContent = t("meta_empty");
  const verResultBox = $("verResultBox");
  if (verResultBox) verResultBox.style.display = "none";

  setProgress(0);
  setStatus(t("status_ready"), "success");
  setBusy(false);
  updateMode("file");
  refreshPasswordStrengthMeters();

  document.querySelector('.nav-item[data-tab="encrypt"]').click();

  syncSelectTriggers();
}
