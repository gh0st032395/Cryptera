// warning.js - one-time "no password recovery" confirmation before encrypting
import { $ } from "./dom.js";

const ACK_KEY = "cryptera_pwd_warning_ack";

function hasAcknowledged() {
  try { return localStorage.getItem(ACK_KEY) === "1"; } catch (_) { return false; }
}

/**
 * Resolve true when the user may proceed with encryption. Shows the
 * irreversibility warning the first time; once explicitly confirmed it is
 * remembered and never shown again.
 */
export function confirmPasswordWarning() {
  if (hasAcknowledged()) return Promise.resolve(true);
  return new Promise((resolve) => {
    const overlay = $("pwdWarningOverlay");
    const confirmBtn = $("pwdWarningConfirm");
    const cancelBtn = $("pwdWarningCancel");
    if (!overlay || !confirmBtn || !cancelBtn) {
      resolve(true);
      return;
    }

    const close = (result) => {
      overlay.style.display = "none";
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      document.removeEventListener("keydown", onKey);
      resolve(result);
    };
    const onConfirm = () => {
      try { localStorage.setItem(ACK_KEY, "1"); } catch (_) { /* ignore */ }
      close(true);
    };
    const onCancel = () => close(false);
    const onKey = (e) => {
      if (e.key === "Escape") close(false);
    };

    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    document.addEventListener("keydown", onKey);
    overlay.style.display = "flex";
    confirmBtn.focus();
  });
}
