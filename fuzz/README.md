# Fuzzing

Prerequisite:
- `cargo install cargo-fuzz`

Run targets:

```bash
cargo fuzz run header_blob
cargo fuzz run decrypt_path
```

Targets focus on header parsing and decrypt/verify entry paths for malformed input hardening.
