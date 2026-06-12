// audit-view.js - rendering of the persistent JSONL audit log
import { invoke } from "./tauri-bridge.js";
import { t } from "./i18n.js";
import { $, escapeHtml, basename } from "./dom.js";
import { errorToText } from "./errors.js";

export function renderAuditTable(entries) {
  const tbody = $("auditTableBody");
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
      <td>${escapeHtml(ts)}</td>
      <td>${escapeHtml(e.op || "—")}</td>
      <td title="${escapeHtml(e.file || "")}">${escapeHtml(fileName)}</td>
      <td>${sizeMb}</td>
      <td>${dur}</td>
      <td class="${statusClass}">${escapeHtml(e.status || "—")}</td>
    </tr>`;
  }).join("");
}

export async function loadAuditLog() {
  if (!invoke) return;
  try {
    const entries = await invoke("get_audit_log", {});
    renderAuditTable(entries);
  } catch (err) {
    console.error("Failed to load audit log:", err);
    const tbody = $("auditTableBody");
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="audit-empty" style="color:#ff8b8b">${escapeHtml(errorToText(err))}</td></tr>`;
    }
  }
}

export async function clearAuditLog() {
  if (!invoke) return;
  try {
    await invoke("clear_audit_log", {});
    renderAuditTable([]);
  } catch (err) {
    console.error("Failed to clear audit log:", err);
  }
}
