# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
