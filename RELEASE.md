# Release Process

## Version source of truth
- `VERSION`

## Files that must match `VERSION`
- `Cargo.toml`
- `ops/Cargo.toml`
- `cli/Cargo.toml`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `package.json`

The `ops`, `cli` and `src-tauri` manifests also pin their path dependencies
with `=<version>`; `check-version.ps1` verifies those pins too.

## Pre-release checklist
1. Update `VERSION`
2. Update `CHANGELOG.md`
3. Run:
   - `./scripts/check-version.ps1`
   - `cargo check`
   - `cargo test`
   - `cargo test --manifest-path ops/Cargo.toml`
   - `cargo test --manifest-path cli/Cargo.toml`
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
2. **build** (`tauri-apps/tauri-action`) — builds installers on Windows
   (`.msi`, NSIS `-setup.exe`), macOS (universal `.dmg`) and Linux
   (`.deb`, `.rpm`, `.AppImage`), **signs them with the updater key**,
   generates the updater manifest `latest.json` and uploads everything to
   the draft release.
3. **cli** — builds the standalone `cryptera` binary for Windows, macOS
   (universal, via `lipo`) and Linux, smoke-tests each one (encrypt → verify →
   decrypt, plus the exit-code-3 contract for a wrong password) and uploads the
   archives to the draft release.
4. **checksums** — downloads every asset, generates `SHA256SUMS.txt` and
   attaches it to the release.

The release stays in **draft**: review the assets, paste the relevant
`CHANGELOG.md` section into the release notes, then publish manually.
The in-app updater only sees **published, non-prerelease** releases (it
reads `releases/latest/download/latest.json`), so a draft never triggers
an update prematurely.

## Auto-updater signing key (one-time setup — REQUIRED before first release)

The auto-updater installs an update only if its signature verifies against
the public key embedded in the app. This key is **free and self-generated**
(it is *not* the paid OS code-signing certificate). Until it is configured,
the `verify` job fails on purpose (placeholder-pubkey guard).

On a trusted machine (never in CI):

```bash
cargo install tauri-cli --version '^2' --locked   # if not already installed
cargo tauri signer generate -w ~/.cryptera-updater.key
```

This prints a **public key** and writes the **private key** to the file.
Then:

1. Put the public key in `src-tauri/tauri.conf.json` →
   `plugins.updater.pubkey` (replacing `REPLACE_WITH_TAURI_UPDATER_PUBKEY`).
   Commit this — the public key is meant to be embedded.
2. In the GitHub repo, add **Settings → Secrets and variables → Actions**:
   - `TAURI_SIGNING_PRIVATE_KEY` — the contents of `~/.cryptera-updater.key`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password you chose (may be empty)
3. **Guard the private key like the crown jewel**: whoever holds it can push
   a malicious auto-update to every install. If it leaks, rotate it
   (generate a new pair, ship an app update with the new pubkey).

### Still not automated (requires paid credentials)

- **OS code signing / notarization** — Windows Authenticode and Apple
  Developer ID certificates are not configured, so SmartScreen/Gatekeeper
  will warn on first launch. The updater signature is independent of this
  and already protects the update channel; OS signing additionally removes
  the install-time warnings. When certificates are available, add their
  env vars to the `build` job.
