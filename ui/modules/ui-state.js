// ui-state.js - UI state management and rendering
export const state = {
    busy: false,
    paused: false,
    mode: "file",
    language: "en",
};

let statusText = null;
let progressFill = null;
let progressValue = null;
let pauseBtn = null;
let cancelBtn = null;

export function setStatus(text) {
    if (!statusText) {
        statusText = document.getElementById("statusText");
    }
    if (!statusText) return;
    statusText.textContent = text;
}

export function setProgress(percent) {
    if (!progressFill || !progressValue) {
        progressFill = document.getElementById("progressFill");
        progressValue = document.getElementById("progressValue");
    }
    if (!progressFill || !progressValue) return;
    const safe = Math.max(0, Math.min(1, percent || 0));
    progressFill.style.width = `${Math.round(safe * 100)}%`;
    progressValue.textContent = `${Math.round(safe * 100)}%`;
}

export function setBusy(value) {
    state.busy = value;
    document.querySelectorAll("button").forEach((btn) => {
        if (btn.classList.contains("ghost")) return;
        btn.disabled = value;
    });
    if (!pauseBtn || !cancelBtn) {
        pauseBtn = document.getElementById("pauseBtn");
        cancelBtn = document.getElementById("cancelBtn");
    }
    if (pauseBtn) pauseBtn.disabled = !value;
    if (cancelBtn) cancelBtn.disabled = !value;
}

export function updateMode(mode) {
    state.mode = mode;
    document.querySelectorAll(".seg").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.mode === mode);
    });

    const encFile = document.getElementById("encFile");
    const encFolder = document.getElementById("encFolder");
    if (encFile) encFile.disabled = mode !== "file";
    if (encFolder) encFolder.disabled = mode !== "folder";

    const encFileBtn = document.getElementById("encFileBtn");
    const encFolderBtn = document.getElementById("encFolderBtn");
    if (encFileBtn) encFileBtn.disabled = mode !== "file";
    if (encFolderBtn) encFolderBtn.disabled = mode !== "folder";
}

export function renderMetaTo(target, meta) {
    if (!target) return;
    if (!meta) {
        target.textContent = "No metadata available.";
        return;
    }
    const isContainer = (meta.flags & 32) !== 0;
    const typeLabel = isContainer ? "Archive (Folder)" : "Single File";

    target.innerHTML = "";

    const createLine = (label, value) => {
        const div = document.createElement("div");
        const strong = document.createElement("strong");
        strong.textContent = label + ": ";
        div.appendChild(strong);
        div.appendChild(document.createTextNode(value));
        return div;
    };

    target.appendChild(createLine("Type", typeLabel));
    target.appendChild(createLine("Filename", meta.filename || "(hidden)"));
    target.appendChild(createLine("Version", meta.version));
    target.appendChild(createLine("Shard", `${meta.shard_size} bytes`));
    target.appendChild(createLine("K/R", `${meta.k} / ${meta.r}`));
    target.appendChild(createLine("Plain size", `${meta.plain_size} bytes`));
    target.appendChild(createLine("Stored size", `${meta.stored_size} bytes`));
}
