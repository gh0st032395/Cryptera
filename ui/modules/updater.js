// updater.js - in-app check / download / install of signed updates.
//
// All network access happens on the Rust side (signature-verified updater);
// the webview keeps CSP connect-src 'none'. The startup check is opt-in so
// the app stays fully offline by default.
import { invoke, eventApi } from "./tauri-bridge.js";
import { t } from "./i18n.js";
import { $, escapeHtml } from "./dom.js";
import { setStatus } from "./ui-state.js";
import { errorToText } from "./errors.js";

function showProgress(fraction) {
  const wrap = $("updateProgressWrap");
  const fill = $("updateProgressFill");
  const value = $("updateProgressValue");
  if (wrap) wrap.style.display = "flex";
  const pct = Math.max(0, Math.min(100, Math.round((fraction || 0) * 100)));
  if (fill) fill.style.width = `${pct}%`;
  if (value) value.textContent = `${pct}%`;
}

function openUpdateDialog(info) {
  const overlay = $("updateOverlay");
  if (!overlay) return;
  $("updateCurrent").textContent = info.current_version || "—";
  $("updateNew").textContent = info.version || "—";
  const notes = $("updateNotes");
  if (notes) {
    const body = (info.notes || "").trim();
    notes.style.display = body ? "block" : "none";
    notes.innerHTML = escapeHtml(body);
  }
  const installBtn = $("updateInstall");
  const laterBtn = $("updateLater");
  const wrap = $("updateProgressWrap");
  if (wrap) wrap.style.display = "none";
  if (installBtn) installBtn.disabled = false;
  if (laterBtn) laterBtn.disabled = false;

  // The dialog must never trap the user: Escape and a click on the
  // backdrop dismiss it, in addition to the Later button.
  const close = () => {
    overlay.style.display = "none";
    installBtn?.removeEventListener("click", onInstall);
    laterBtn?.removeEventListener("click", onLater);
    document.removeEventListener("keydown", onKey);
    overlay.removeEventListener("mousedown", onBackdrop);
  };
  const onLater = () => close();
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const onBackdrop = (e) => { if (e.target === overlay) close(); };
  const onInstall = async () => {
    if (installBtn) installBtn.disabled = true;
    if (laterBtn) laterBtn.disabled = true;
    showProgress(0);
    setStatus(t("update_installing"), "info");
    try {
      // On success the backend relaunches the app, so this never returns.
      await invoke("install_update");
    } catch (err) {
      setStatus(`${t("update_error")}: ${errorToText(err)}`, "error");
      close();
    }
  };
  installBtn?.addEventListener("click", onInstall);
  laterBtn?.addEventListener("click", onLater);
  document.addEventListener("keydown", onKey);
  overlay.addEventListener("mousedown", onBackdrop);
  overlay.style.display = "flex";
  installBtn?.focus();
}

/**
 * Check for a newer signed release.
 * @param {boolean} manual true when triggered by the user (shows
 *   "up to date" / error feedback); false for the silent startup check.
 */
export async function checkForUpdates(manual) {
  if (!invoke) return;
  if (manual) setStatus(t("update_checking"), "info");
  try {
    const info = await invoke("check_update");
    if (info && info.available) {
      if (manual) {
        openUpdateDialog(info);
      } else {
        // Startup check must never pop a blocking dialog: just notify, the
        // user opens the dialog from About when they want to.
        setStatus(
          t("update_available_banner").replace("{version}", info.version || ""),
          "info",
        );
      }
    } else if (manual) {
      setStatus(t("update_none"), "success");
    }
  } catch (err) {
    if (manual) setStatus(`${t("update_error")}: ${errorToText(err)}`, "error");
    else console.error("update check:", err);
  }
}

export function bindUpdater() {
  const btn = $("checkUpdatesBtn");
  if (btn) btn.addEventListener("click", () => checkForUpdates(true));

  if (eventApi && eventApi.listen) {
    eventApi.listen("update-progress", (e) => {
      if (typeof e?.payload === "number") showProgress(e.payload);
    });
  }

  // No automatic update check at startup: the app makes zero network calls
  // until the user explicitly presses "Check for updates" in About. This is
  // intentional — an update box must never appear on its own at launch.
}
