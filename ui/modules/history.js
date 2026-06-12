// history.js - volatile in-memory ring buffer of recent operations
import { t } from "./i18n.js";
import { $, escapeHtml, basename, formatDuration, formatTimestamp } from "./dom.js";

const _history = [];
const _MAX_HISTORY = 100;

/**
 * @param {"encrypt"|"decrypt"|"verify"|"batch"} op
 * @param {string} filename
 * @param {boolean} success
 * @param {number} durationMs
 */
export function logOperation(op, filename, success, durationMs) {
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

export function renderHistory() {
  const listEl = $("historyList");
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
      <span class="hi-op">${escapeHtml(opLabel)}</span>
      <span class="hi-file">${escapeHtml(basename(entry.filename))}</span>
      <span class="${statusClass}">${statusText}</span>
      <span class="hi-time">${ts} · ${dur}</span>
    </div>`;
  }).join("");
}

export function clearHistory() {
  _history.length = 0;
  renderHistory();
}
