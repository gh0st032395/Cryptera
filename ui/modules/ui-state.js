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

export function setStatus(text, level = "info") {
    if (!statusText) {
        statusText = document.getElementById("statusText");
    }
    if (!statusText) return;
    statusText.textContent = text;
    statusText.classList.remove("status-info", "status-success", "status-warn", "status-error");
    const allowed = ["info", "success", "warn", "error"];
    const safeLevel = allowed.includes(level) ? level : "info";
    statusText.classList.add(`status-${safeLevel}`);
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

export function renderMetaTo(target, meta, labels = {}) {
    const noMetaText = labels.noMetaText || "No metadata available.";
    const typeArchive = labels.typeArchive || "Archive (Folder)";
    const typeFile = labels.typeFile || "Single File";
    const hiddenName = labels.hiddenName || "(hidden)";
    const typeLabel = labels.typeLabel || "Type";
    const filenameLabel = labels.filenameLabel || "Filename";
    const versionLabel = labels.versionLabel || "Version";
    const shardLabel = labels.shardLabel || "Shard";
    const krLabel = labels.krLabel || "K/R";
    const plainSizeLabel = labels.plainSizeLabel || "Plain size";
    const storedSizeLabel = labels.storedSizeLabel || "Stored size";

    if (!target) return;
    if (!meta) {
        target.textContent = noMetaText;
        return;
    }
    const isContainer = (meta.flags & 32) !== 0;
    const typeValue = isContainer ? typeArchive : typeFile;

    target.innerHTML = "";

    const createLine = (label, value) => {
        const div = document.createElement("div");
        const strong = document.createElement("strong");
        strong.textContent = label + ": ";
        div.appendChild(strong);
        div.appendChild(document.createTextNode(value));
        return div;
    };

    target.appendChild(createLine(typeLabel, typeValue));
    target.appendChild(createLine(filenameLabel, meta.filename || hiddenName));
    target.appendChild(createLine(versionLabel, meta.version));
    target.appendChild(createLine(shardLabel, `${meta.shard_size} bytes`));
    target.appendChild(createLine(krLabel, `${meta.k} / ${meta.r}`));
    target.appendChild(createLine(plainSizeLabel, `${meta.plain_size} bytes`));
    target.appendChild(createLine(storedSizeLabel, `${meta.stored_size} bytes`));
}
