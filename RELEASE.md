# Release Process

## Version source of truth
- `VERSION`

## Files that must match `VERSION`
- `Cargo.toml`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `package.json`

## Pre-release checklist
1. Update `VERSION`
2. Update `CHANGELOG.md`
3. Run:
   - `./scripts/check-version.ps1`
   - `cargo check`
   - `cargo test`
   - `cargo test --manifest-path src-tauri/Cargo.toml`
   - `cargo check --manifest-path fuzz/Cargo.toml`
   - `cargo audit`
   - `cargo deny check advisories bans licenses sources`
   - `pushd src-tauri; cargo audit; popd`
   - `pushd src-tauri; cargo deny check advisories bans licenses sources --config ../deny.toml; popd`
4. Manual smoke test with `cargo tauri dev`: encrypt file, encrypt folder,
   decrypt, verify, batch (one good + one corrupted file), open a `.ecf`
   by double-click, language/theme switch, tray hide/restore.
5. Create and push the tag: `v<version>` (example: `v2.0.0`)

## Automated release pipeline

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which:

1. **verify** — checks version alignment, checks the tag matches `VERSION`,
   runs the core test suite, then creates a **draft** GitHub release.
2. **build** — builds installers on Windows (`.msi`, NSIS `-setup.exe`),
   macOS (universal `.dmg`) and Linux (`.deb`, `.rpm`, `.AppImage`) and
   uploads them to the draft release.
3. **checksums** — downloads every asset, generates `SHA256SUMS.txt` and
   attaches it to the release.

The release stays in **draft**: review the assets, paste the relevant
`CHANGELOG.md` section into the release notes, then publish manually.

### Not yet automated (requires credentials)

- **Code signing / notarization** — Windows Authenticode and Apple
  Developer ID certificates are not configured. Until they are, users
  will see SmartScreen/Gatekeeper warnings. When available, wire the
  signing env vars into the `build` job.
- **Auto-updater** — `tauri-plugin-updater` requires a signing keypair
  for update manifests. The in-app "Check for updates" button only opens
  the GitHub Releases page in the browser; the app itself performs no
  network calls.
