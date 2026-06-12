// errors.js - mapping of backend errors and status payloads to user feedback
import { t } from "./i18n.js";

export function normalizeErrorMessage(err) {
  return String(err || "").trim().toLowerCase();
}

/**
 * Human-readable text for an error of unknown shape (structured CmdError
 * `{code, message}` from the backend, Error instance, or plain string).
 */
export function errorToText(err) {
  if (err && typeof err === "object") {
    if (err.message) return String(err.message);
    if (err.code) return String(err.code);
  }
  return String(err || "");
}

export function isCancelledError(err) {
  if (err && typeof err === "object" && err.code === "CANCELLED") return true;
  return String(err || "").toLowerCase().includes("cancelled");
}

// Stable backend/core error codes → i18n key + status level.
const ERROR_CODE_FEEDBACK = {
  PASSWORD_REQUIRED: { key: "err_password_required", level: "warn" },
  INPUT_REQUIRED: { key: "err_input_required", level: "warn" },
  OUTPUT_REQUIRED: { key: "err_output_required", level: "warn" },
  OUTPUT_EXISTS: { key: "err_output_exists", level: "warn" },
  PASSWORD_INVALID: { key: "err_password_invalid", level: "error" },
  HEADER_AUTH_FAILED: { key: "err_header_auth", level: "error" },
  HEADER_INVALID: { key: "err_header_invalid", level: "error" },
  PARAMS_OUT_OF_LIMITS: { key: "err_header_invalid", level: "error" },
  TRUNCATED: { key: "err_file_truncated", level: "error" },
  CORRUPT_BEYOND_FEC: { key: "err_corrupt_beyond_fec", level: "error" },
  CANCELLED: { key: "err_cancelled", level: "warn" },
  STATE_LOCK: { key: "err_internal_state", level: "error" },
  NO_ACTIVE_JOB: { key: "err_internal_state", level: "error" },
  IO_ERROR: { key: "err_io", level: "error" },
  TAR_ERROR: { key: "err_tar", level: "error" },
  EXTRACT_ERROR: { key: "err_extract", level: "error" },
};

export function mapErrorToUserFeedback(action, err) {
  const code = err && typeof err === "object" ? String(err.code || "") : "";
  const feedback = ERROR_CODE_FEEDBACK[code];
  if (feedback) return { message: t(feedback.key), level: feedback.level };

  if (action === "encrypt") return { message: t("err_encrypt_generic"), level: "error" };
  if (action === "decrypt") return { message: t("err_decrypt_generic"), level: "error" };
  if (action === "verify") return { message: t("err_verify_generic"), level: "error" };
  return { message: t("err_internal_state"), level: "error" };
}

export function inferStatusLevelFromPayload(payload) {
  const raw = normalizeErrorMessage(payload);
  if (!raw) return "info";
  if (raw.includes("error") || raw.includes("failed")) return "error";
  if (raw.includes("cancelled")) return "warn";
  if (raw.includes("ok") || raw.includes("complete")) return "success";
  return "info";
}

export function localizeBackendStatusPayload(payload) {
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
