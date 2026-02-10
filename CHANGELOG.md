# Changelog

## 1.0.0 - 2026-02-10
- First production release candidate.
- Added authenticated header format `v4` with backward-compatible read support.
- Hardened secret handling with zeroizing buffers.
- Improved atomic output replacement to avoid data loss on replace failures.
- Added automated crypto regression tests and backend unit tests.
- Added fuzzing harness targets for header parsing and decrypt/verify paths.
- Added CI security checks with `cargo-audit` and `cargo-deny`.
- Introduced release version coordination via `VERSION` and validation script.
