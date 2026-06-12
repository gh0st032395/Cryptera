// events.js - backend progress/status event listeners
import { eventApi } from "./tauri-bridge.js";
import { setStatus, setProgress } from "./ui-state.js";
import { localizeBackendStatusPayload, inferStatusLevelFromPayload } from "./errors.js";

export async function bindBackendEvents() {
  if (!eventApi || !eventApi.listen) {
    console.warn("Event API not available, skipping backend event bind.");
    return;
  }

  await eventApi.listen("progress", (e) => {
    if (e && e.payload) setProgress(e.payload.percent);
  });

  await eventApi.listen("status", (e) => {
    if (e && e.payload) {
      const localizedPayload = localizeBackendStatusPayload(e.payload);
      if (localizedPayload) {
        setStatus(localizedPayload.text, localizedPayload.level);
        return;
      }
      setStatus(e.payload, inferStatusLevelFromPayload(e.payload));
      const match = String(e.payload).match(/(\d+)\/(\d+)/);
      if (match) {
        const done = Number(match[1]);
        const total = Number(match[2]);
        if (total > 0) setProgress(done / total);
      }
    }
  });
}
