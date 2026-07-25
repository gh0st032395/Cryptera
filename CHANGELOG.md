# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- **Compressed folder archives could not be extracted.** Extraction picked the
  decompressor from the file-name extension, but the folder-archive codec
  (gz/bz2/xz) is recorded nowhere in the `.ecf` header — only in the stored
  name's suffix. The GUI decrypts into an unnamed temp file, so it failed to
  extract **any** compressed folder (`EXTRACT_ERROR`, nothing written, and the
  keep-tar fallback never ran); the CLI failed the same way whenever the folder
  was encrypted with `--hide-filename`. `safe_extract_tar` now detects the codec
  from the archive's magic bytes, independent of any name, fixing both front-ends
  (regression tests for all three codecs from a suffix-less path). The kept
  archive (`--keep-tar` / "keep tar") is now named for its real compression
  (`decrypted.tar.gz`) instead of always `decrypted.tar`.

### Security

- **Bumped crossbeam-epoch to 0.9.20** (RUSTSEC-2026-0204, invalid-pointer
  dereference; reached transitively via rayon) in the root and Tauri lockfiles.
- **CLI rejects Windows reserved device names** (`CON`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`, with any extension) when deriving an output path from a
  container's stored filename, alongside the existing separator/`..`/drive-letter
  checks.

---

## [2.1.0] — 2026-07-24

### Added

- **`cryptera` CLI — Cryptera is now scriptable on Windows, macOS and Linux.**
  New `cli/` crate producing a standalone binary (no GUI, no webview) with
  `encrypt`, `decrypt`, `verify` and `meta` over the same core and the same
  `.ecf` format as the app. Built for automation: `--json` emits a single object
  on stdout, progress goes to stderr only, and exit codes are stable (0 ok,
  1 error, 2 usage, 3 wrong password, 4 corrupt, 5 output exists, 6 cancelled).
  Passwords are deliberately not accepted as arguments — argv is world-readable
  — and come from stdin, a file, an environment variable, or a no-echo prompt.
  Folders are TAR-archived exactly as in the GUI, and containers are
  auto-extracted on decrypt. Release builds for the three platforms (macOS
  universal) are attached to every GitHub release and smoke-tested in CI.

### Changed

- **Shared `ops/` crate.** Folder archiving, the entry pre-count behind the
  archiving progress bar, the hardened TAR extraction
  (path-traversal, absolute paths and links) and the security/integrity profile
  tables moved out of the Tauri backend into `cryptera_ops`, so the GUI and the
  CLI cannot drift apart — in particular the extraction hardening now has one
  implementation instead of two.
- **Encrypt panel no longer shows controls the selected mode ignores.** The
  File/Folder selector now drives which source picker exists at all; previously
  both rows were shown and the inactive one was merely disabled, which read as
  redundant (2.0.4 fixed that disabling being lost after each job; hiding makes
  the state unrepresentable instead). The same applies to the compression
  selects and "skip symlinks", which the backend only reads in one of the two
  modes. Switching mode also clears the abandoned source path and the output
  derived from it.

### Security

- **Container filenames are sanitized before use as paths.** When the CLI
  derives an output name from the header, the stored name is accepted only if it
  is a single ordinary path component: separators, `..`, drive letters and UNC
  prefixes are rejected rather than repaired.

---

## [2.0.4] — 2026-06-16

### Fixed

- **Startup modals ("An update is available" + "There is no password recovery")
  appeared on launch in RELEASE builds — the actual root cause.** The CSP
  `style-src 'self'` blocks inline `style=` attributes. The modal overlays are
  hidden with inline `style="display:none"` while `.modal-overlay` is
  `display:flex` in the stylesheet, so under the strict release CSP they became
  visible at startup. `tauri dev` relaxes the CSP, which is why the bug only
  reproduced in release — including clean CI bundles built from the 2.0.3 tag
  (the 2.0.3 "embed staleness" change did not address this). Fixed by allowing
  `'unsafe-inline'` in `style-src`; `script-src` stays `'self'` and all dynamic
  content is still escaped, so script injection is not enabled.
- **Batch decrypt** now inspects each file's header and routes single-file
  `.ecf` vs TAR archives correctly, instead of assuming a container (which
  failed with `EXTRACT_ERROR` / `OUTPUT_EXISTS` on single files).
- File/Folder source gating is re-applied after an operation completes.
- The selected UI language is now persisted across restarts.
- About text corrected: "CryptoV2" → "Cryptera"; removed dead startup-update
  i18n keys.

### Changed

- The system-tray tooltip now signals that the app keeps running when the
  window is closed to the tray.
- Folder archiving reports real progress instead of staying at 0%.
- `build.rs` forces the frontend content re-hash on every build so incremental
  and cloud-synced (e.g. OneDrive) builds always re-embed the current UI.

---

## [2.0.3] — 2026-06-14

### Fixed

- **Update dialog appeared at launch in installed builds (real root cause).**
  The frontend is embedded into the binary at compile time by
  `generate_context!`, but Tauri did not track the `ui/` files as build inputs.
  Editing only frontend files therefore did not trigger a recompile, so release
  bundles (local **and** CI) kept shipping the *old* embedded HTML/JS — the
  pre-fix updater that auto-opened the update dialog on launch — even though the
  source was already corrected. Debug (`tauri dev`) reads `ui/` from disk and
  was never affected, which is why the bug showed up only in installed builds.
  `build.rs` now fingerprints the whole `ui/` tree and exposes it as a rustc
  env referenced by `main.rs`, forcing the asset-embedding crate to recompile
  whenever any frontend file changes. Bundles can no longer ship stale UI.

---

## [2.0.2] — 2026-06-14

### Fixed

- **Update dialog opening on launch in installed builds** — the startup
  auto-update check (removed in the source for 2.0.1) had never actually been
  shipped: the published v2.0.0 / v2.0.1 installers were built from earlier
  sources and still opened the update dialog on launch — and on v2.0.0 it could
  not be dismissed, locking the app. 2.0.2 is the first release built from the
  corrected sources: the app makes no network calls at launch and the update box
  only ever appears from About → "Check for updates" (always dismissible via
  Escape / backdrop / Later).

---

## [2.0.1] — 2026-06-13

### Fixed

- **macOS launch freeze** — the window was configured `transparent: true` without
  `macOSPrivateApi`, which on macOS produced a window that rendered but did not
  receive mouse/keyboard input (the app appeared frozen, often behind the update
  dialog). Transparency is now disabled; the frameless custom titlebar is
  unchanged and the app is interactive on Windows and macOS.
- **Update dialog could trap the user** — it now always closes with Escape or a
  click on the backdrop, in addition to the Later button, and can never cover the
  UI permanently.
- **No update check at startup** — update checking is now manual only, via the
  "Check for updates" button in About; the app makes zero network calls at
  launch and an update box can never appear on its own. The dialog (only opened
  by that button) is fully dismissible (Escape / backdrop / Later).

---

## [2.0.0] — 2026-06-12

### Changed — **BREAKING: file format header v5**

- **Encrypted filename** — the original filename is now stored AES-256-GCM-encrypted
  inside the header (`FLAG_ENC_FILENAME`, reserved nonce `(nonce_base, 0xFFFFFFFE,
  0xFFFFFFFE)`, dedicated AAD context `ECF1-FNAME-V5`). Plaintext filenames are no
  longer written. Files produced by 2.x are **not readable by 1.x**; all v1–v4 files
  remain fully readable (pinned by committed fixtures in `tests/fixtures/`).
- `read_metadata` (no password) reports an empty filename for v5 files; decrypt and
  verify return the real name after header authentication. The UI shows an
  "(encrypted — shown after decrypt/verify)" placeholder.
- Maximum stored filename length: 4096 bytes (`MAX_FILENAME_LEN`).

### Added

- **Release pipeline** — pushing a `v*` tag builds installers for Windows
  (`.msi`/NSIS), macOS (universal `.dmg`) and Linux (`.deb`/`.rpm`/AppImage) and
  attaches them with `SHA256SUMS.txt` to a draft GitHub release. Binaries are not
  yet code-signed.
- **`.ecf` file association** — double-clicking an encrypted file opens the app on
  the Decrypt panel with the file preloaded (argv on Windows/Linux,
  `RunEvent::Opened` on macOS). Bundle identifier renamed to `com.cryptera.app`.
- **Irreversibility warning** — a one-time confirmation before the first encryption
  makes explicit that no password recovery exists.
- **Signed in-app auto-updater** (`tauri-plugin-updater`) — the About panel checks
  GitHub for a newer release; on confirmation the app downloads it, verifies its
  signature against an embedded public key, installs it and relaunches. A
  download progress bar is shown. Startup checks are **opt-in** (off by default);
  the updater is the only component that touches the network (Rust side), while
  the webview keeps `connect-src 'none'` and encryption stays fully offline.
- **About panel** — shows the running app version.
- **Memory guard** — selecting the Strong/Paranoid Argon2 profile warns when
  available RAM is insufficient instead of failing mid-encryption.
- Structured `{code, message}` errors across the Tauri IPC boundary; the frontend
  maps stable codes to localized messages (EN/IT).
- v4 format fixtures and backward-compatibility tests; FEC recovery-budget tests;
  pause/cancel regression tests.
- Custom selects: full keyboard support and ARIA state sync; status live region.
- Per-block shard encryption/decryption parallelized with rayon.

### Changed

- Audit log stores only stable error codes (no raw messages or paths).
- Password fields are cleared after each completed operation and auto-clear after
  5 minutes of inactivity.
- Pause/cancel is event-driven (`Condvar`) instead of a 50ms polling loop.
- `ui/app.js` split into feature modules (no build step required).
- Core decrypt/verify share one block-processing path; per-shard heap allocations
  removed from the hot loops.
- `FORMAT_SPEC.md` rewritten for v5 and realigned with the implementation.

### Fixed

- HTML injection via filenames/paths/errors rendered in history, batch and audit
  views (now escaped).
- Stale `read_metadata` responses can no longer overwrite the decrypt panel;
  manual edits to output path/auto-extract are preserved.
- Batch queue validates the `.ecf` extension and no longer produces an empty
  output directory for separator-less paths.
- Predictable `{output}.tmp` files removed from the backend (the core already
  writes via an unpredictable temp file with atomic rename).
- Encrypting a filesystem root no longer yields a `.tar`-named archive.

---

## [1.1.0] — 2026-05-12

### Added

**GUI — New tabs and features (Rust/Tauri frontend)**

- **Dark / Light / System theme toggle** — button in the titlebar cycles through three
  themes; preference persisted to `localStorage`; reacts to `prefers-color-scheme`
  changes in System mode.
- **Password strength feedback** — encrypt panel now shows per-rule hints below the
  strength meter: "Add uppercase letters", "Add numbers", etc., rather than just a
  colour bar.
- **Operation History tab** — in-memory ring-buffer (max 100 entries) of every
  encrypt / decrypt / verify / batch operation with timestamp, status and duration;
  cleared on app exit.
- **Verify Details** — after a successful `Run Verification`, the panel now shows
  file integrity result, k/r shard ratio, FEC parity overhead percentage, and
  plaintext size.
- **Batch Decrypt tab** — multi-file queue with per-file status (pending / running /
  OK / ERR), sequential decryption using a single shared password, optional output
  folder override, drag-and-drop support, and a final summary card.
- **Audit Log tab** — persistent JSONL audit log (`%APPDATA%\Cryptera\logs\audit.jsonl`
  on Windows, `~/.local/share/cryptera/logs/audit.jsonl` on Linux); backend writes
  one entry per operation with timestamp, file, size, duration and status; frontend
  table with Refresh / Clear Log controls.
- **System Tray** — window close button hides to tray instead of quitting; tray icon
  (programmatic 16×16 lock-shape RGBA) with "Open Cryptera" and "Quit" menu items;
  double-click on icon restores the window.
- **Multi-file dialog** — `open_file_dialog` Tauri command now accepts `multiple: bool`
  for batch file selection.

**CSS refactor**

- All hardcoded `rgba` colours replaced by 30+ CSS custom properties in `:root`.
- New `:root[data-theme="light"]` block provides a complete light-mode palette with
  correctly adapted glass, border, button, tooltip, meter-track and body-background
  variables.
- History, Audit and Batch panels have dedicated CSS component classes.

**i18n**

- ~60 new translation keys in both English and Italian covering all new UI features.

**Rust — `src-tauri/`**

- New `audit.rs` module: `AuditLogger` (JSONL append / read\_recent / clear),
  `AuditEntry` serde struct, `default_log_dir()`, `unix_now()`, `file_size_mb()`.
- `get_audit_log` and `clear_audit_log` Tauri commands.
- `verify` command now returns `VerifyResult { meta: MetaInfoDto }` (previously `()`).
- Audit entry written after every `encrypt` / `decrypt` / `verify` command (records
  timing and error).
- `tray-icon`, `image-ico`, `image-png` features enabled for Tauri.
- `core:window:allow-hide`, `allow-show`, `allow-set-focus` added to capabilities.
- `tauri::Manager` imported to resolve `get_webview_window` in setup callback.

### Changed

- `Cargo.toml` (root), `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `VERSION`
  bumped from `1.0.0` to `1.1.0`.

### Fixed

- CTA button text (`color: #0b0f14`) was unreadable on a light background; added
  `:root[data-theme="light"] .cta { color: #ffffff }` override.

### Tests

- 4 new unit tests for `audit.rs`: roundtrip write/read, clear, limit, empty-log.
- Total test suite: **8 / 8 passing**.

---

## [1.0.0] — 2026-02-10

- First production release candidate.
- Added authenticated header format `v4` with backward-compatible read support.
- Hardened secret handling with zeroizing buffers.
- Improved atomic output replacement to avoid data loss on replace failures.
- Added automated crypto regression tests and backend unit tests.
- Added fuzzing harness targets for header parsing and decrypt/verify paths.
- Added CI security checks with `cargo-audit` and `cargo-deny`.
- Introduced release version coordination via `VERSION` and validation script.
