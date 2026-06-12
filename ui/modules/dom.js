// dom.js - DOM helpers shared across UI modules

/**
 * Escape a value for safe interpolation into HTML markup.
 * Must be applied to every dynamic value rendered via innerHTML that can
 * contain attacker-controlled data (filenames from .ecf headers, paths,
 * error messages).
 */
export function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

/** Header flag bits mirrored from src/lib.rs (HDR_FLAG_*). */
export const META_FLAG_TAR_CONTAINER = 0x20;
