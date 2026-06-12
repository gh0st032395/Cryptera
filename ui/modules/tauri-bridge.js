// tauri-bridge.js - Tauri API bridge and event handling
export const tauri = window.__TAURI__ || {};
export const invoke = tauri?.core?.invoke || tauri?.tauri?.invoke || tauri?.invoke;
export const eventApi = tauri?.event || tauri?.core?.event || tauri?.tauri?.event;
export const windowApi = tauri?.window || tauri?.core?.window;

// Errors are rethrown as-is so structured backend errors ({code, message})
// reach the caller intact.
export async function pickFile(target, defaultPath = null) {
    if (!invoke) return;
    const selected = await invoke("open_file_dialog", { defaultPath });
    if (selected) target.value = selected;
}

export async function pickFolder(target, defaultPath = null) {
    if (!invoke) return;
    const selected = await invoke("open_folder_dialog", { defaultPath });
    if (selected) target.value = selected;
}

export async function pickSave(target, defaultPath = null) {
    if (!invoke) return;
    const selected = await invoke("save_file_dialog", { defaultPath });
    if (selected) target.value = selected;
}

export function bindWindowControls() {
    if (!windowApi) {
        console.error("Window API not found");
        return;
    }
    const appWindow = windowApi.getCurrentWindow();
    if (!appWindow) return;

    document.getElementById("titlebar-minimize")?.addEventListener("click", () => appWindow.minimize());
    document.getElementById("titlebar-maximize")?.addEventListener("click", () => appWindow.toggleMaximize());
    document.getElementById("titlebar-close")?.addEventListener("click", () => appWindow.close());
}
