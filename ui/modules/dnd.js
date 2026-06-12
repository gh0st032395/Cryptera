// dnd.js - drag & drop routing to the active panel
import { eventApi } from "./tauri-bridge.js";
import { $ } from "./dom.js";
import { checkFileMetadata, resetDecryptAutoFillState } from "./metadata.js";
import { addBatchFiles } from "./batch.js";
import { handleReadVerifyMeta } from "./operations.js";

function handleDrop(paths) {
  if (!paths || paths.length === 0) return;
  const path = paths[0];
  const activePanel = document.querySelector(".panel.active");
  if (!activePanel) return;

  if (activePanel.id === "panel-encrypt") {
    const modeFile = document.querySelector(".seg[data-mode='file']").classList.contains("active");
    if (modeFile) {
      const encFile = $("encFile");
      const encOutput = $("encOutput");
      if (encFile) encFile.value = path;
      if (encOutput) {
        const sep = path.includes("\\") ? "\\" : "/";
        const lastDot = path.lastIndexOf(".");
        const suggested = lastDot > path.lastIndexOf(sep) ? path.substring(0, lastDot) + ".ecf" : path + ".ecf";
        encOutput.value = suggested;
      }
    } else {
      const encFolder = $("encFolder");
      const encOutput = $("encOutput");
      if (encFolder) encFolder.value = path;
      if (encOutput) encOutput.value = path + ".ecf";
    }
  } else if (activePanel.id === "panel-decrypt") {
    const decFile = $("decFile");
    if (decFile) decFile.value = path;
    resetDecryptAutoFillState();
    checkFileMetadata(path);
  } else if (activePanel.id === "panel-verify") {
    const verFile = $("verFile");
    if (verFile) verFile.value = path;
    handleReadVerifyMeta();
  } else if (activePanel.id === "panel-batch") {
    // Add all dropped files to batch queue (.ecf only)
    addBatchFiles(paths);
  }
}

export async function bindDragAndDrop() {
  document.addEventListener('dragover', (e) => { e.preventDefault(); e.stopPropagation(); });
  document.addEventListener('drop', (e) => { e.preventDefault(); e.stopPropagation(); });
  document.addEventListener("contextmenu", (e) => { e.preventDefault(); });

  if (!eventApi || !eventApi.listen) {
    console.warn("Event API not available, skipping drag-drop bind.");
    return;
  }

  await eventApi.listen("tauri://file-drop", async (e) => {
    if (e && e.payload && e.payload.length > 0) handleDrop(e.payload);
  });

  await eventApi.listen("tauri://drag-drop", async (e) => {
    if (e && e.payload) {
      if (Array.isArray(e.payload)) handleDrop(e.payload);
      else if (e.payload.paths && Array.isArray(e.payload.paths)) handleDrop(e.payload.paths);
    }
  });
}
