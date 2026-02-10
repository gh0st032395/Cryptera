# Release Process

## Version source of truth
- `VERSION`

## Files that must match `VERSION`
- `Cargo.toml`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

## Pre-release checklist
1. Update `VERSION`
2. Update `CHANGELOG.md`
3. Run:
   - `./scripts/check-version.ps1`
   - `cargo check`
   - `cargo test`
   - `cargo check --manifest-path fuzz/Cargo.toml`
4. Create tag: `v<version>` (example: `v1.0.0`)
