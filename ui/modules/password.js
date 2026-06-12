// password.js - strength assessment, encryption policy and password hygiene
import { t, onLanguageChange } from "./i18n.js";
import { state } from "./ui-state.js";
import { $ } from "./dom.js";

export function assessPasswordStrength(password) {
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

export function meetsEncryptionPasswordPolicy(assessment) {
  return assessment.length >= 10 && assessment.level >= 2;
}

export function updatePasswordStrengthMeter(password, fillEl, textEl, feedbackEl) {
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

export function refreshPasswordStrengthMeters() {
  updatePasswordStrengthMeter($("encPassword")?.value || "", $("encPasswordStrengthFill"), $("encPasswordStrengthText"), $("encPasswordFeedback"));
  updatePasswordStrengthMeter($("decPassword")?.value || "", $("decPasswordStrengthFill"), $("decPasswordStrengthText"), null);
  updatePasswordStrengthMeter($("verPassword")?.value || "", $("verPasswordStrengthFill"), $("verPasswordStrengthText"), null);
}

// ── Password hygiene ──────────────────────────────────────────────────────────
const PASSWORD_FIELD_IDS = [
  "encPassword", "decPassword", "verPassword", "batchPassword",
];
const PASSWORD_AUTO_CLEAR_MS = 5 * 60 * 1000;
let _pwdAutoClearTimer = null;

export function clearPasswordFields(...inputs) {
  inputs.forEach((el) => {
    if (el) el.value = "";
  });
  refreshPasswordStrengthMeters();
}

export function clearAllPasswordFields() {
  clearPasswordFields(...PASSWORD_FIELD_IDS.map((id) => $(id)));
}

function schedulePasswordAutoClear() {
  if (_pwdAutoClearTimer) clearTimeout(_pwdAutoClearTimer);
  _pwdAutoClearTimer = setTimeout(() => {
    _pwdAutoClearTimer = null;
    if (state.busy) {
      schedulePasswordAutoClear();
      return;
    }
    clearAllPasswordFields();
  }, PASSWORD_AUTO_CLEAR_MS);
}

/** Bind strength meters, the inactivity auto-clear and language refresh. */
export function bindPasswordEvents() {
  PASSWORD_FIELD_IDS.forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("input", schedulePasswordAutoClear);
  });

  const encPassword = $("encPassword");
  if (encPassword) {
    encPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(encPassword.value, $("encPasswordStrengthFill"), $("encPasswordStrengthText"), $("encPasswordFeedback"));
    });
  }
  const decPassword = $("decPassword");
  if (decPassword) {
    decPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(decPassword.value, $("decPasswordStrengthFill"), $("decPasswordStrengthText"), null);
    });
  }
  const verPassword = $("verPassword");
  if (verPassword) {
    verPassword.addEventListener("input", () => {
      updatePasswordStrengthMeter(verPassword.value, $("verPasswordStrengthFill"), $("verPasswordStrengthText"), null);
    });
  }

  onLanguageChange(refreshPasswordStrengthMeters);
}
