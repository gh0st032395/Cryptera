// metadata.js - .ecf metadata reading, rendering and decrypt auto-fill
import { invoke } from "./tauri-bridge.js";
import { t } from "./i18n.js";
import { setStatus, renderMetaTo } from "./ui-state.js";
import { $, META_FLAG_TAR_CONTAINER } from "./dom.js";

export function getMetaLabels() {
  return {
    noMetaText: t("meta_no_data_available"),
    typeArchive: t("meta_type_archive"),
    typeFile: t("meta_type_file"),
    hiddenName: t("meta_hidden_filename"),
    encryptedName: t("meta_encrypted_filename"),
    typeLabel: t("meta_label_type"),
    filenameLabel: t("meta_label_filename"),
    versionLabel: t("meta_label_version"),
    shardLabel: t("meta_label_shard"),
    krLabel: t("meta_label_kr"),
    plainSizeLabel: t("meta_label_plain_size"),
    storedSizeLabel: t("meta_label_stored_size"),
  };
}

export function renderMeta(meta) {
  renderMetaTo($("metaContent"), meta, getMetaLabels());
}

// Guards against two issues when the user picks files in quick succession:
// a stale read_metadata response rendering the wrong file's metadata
// (request token), and auto-population overwriting fields the user already
// edited by hand (dirty flags, reset whenever a new file is selected).
let _metaRequestToken = 0;
let _decOutputDirty = false;
let _decExtractDirty = false;

export function resetDecryptAutoFillState() {
  _decOutputDirty = false;
  _decExtractDirty = false;
}

/** Track manual edits so metadata auto-fill never overwrites user intent. */
export function bindMetadataDirtyTracking() {
  const decOutput = $("decOutput");
  const decExtract = $("decExtract");
  if (decOutput) decOutput.addEventListener("input", () => { _decOutputDirty = true; });
  if (decExtract) decExtract.addEventListener("change", () => { _decExtractDirty = true; });
}

export async function checkFileMetadata(path) {
  if (!invoke || !path) return;
  const token = ++_metaRequestToken;
  try {
    const meta = await invoke("read_metadata", { req: { input_file: path } });
    if (token !== _metaRequestToken) return; // stale response, a newer pick won
    if (meta) {
      renderMeta(meta);
      const isContainer = (meta.flags & META_FLAG_TAR_CONTAINER) !== 0;
      const decExtract = $("decExtract");
      const decOutput = $("decOutput");
      if (decExtract && !_decExtractDirty) {
        decExtract.checked = isContainer;
        setStatus(isContainer ? t("status_detected_folder") : t("status_detected_file"), "info");
      }
      if (decOutput && !_decOutputDirty) {
        try {
          const sep = path.includes("\\") ? "\\" : "/";
          const dir = path.substring(0, path.lastIndexOf(sep));
          const baseName = path.split(sep).pop();
          const nameNoExt = baseName.replace(/\.ecf$/i, "");
          let suggested = "";
          if (isContainer) {
            suggested = `${dir}${sep}${nameNoExt}`;
          } else {
            if (meta.filename && meta.filename.trim().length > 0) {
              suggested = `${dir}${sep}${meta.filename}`;
            } else {
              suggested = `${dir}${sep}${nameNoExt}`;
            }
          }
          decOutput.value = suggested;
        } catch (e) {
          console.error("Smart path calc failed", e);
        }
      }
    }
  } catch (err) {
    if (token !== _metaRequestToken) return;
    console.error("Auto-detect failed:", err);
  }
}
