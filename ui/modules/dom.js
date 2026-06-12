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

/** Shorthand for document.getElementById. */
export function $(id) {
    return document.getElementById(id);
}

export function basename(path) {
    if (!path) return "—";
    const norm = path.replace(/\\/g, "/");
    return norm.split("/").pop() || path;
}

export function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
}

export function formatTimestamp(date) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Re-align every custom select's visible trigger text with its hidden input value. */
export function syncSelectTriggers() {
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
