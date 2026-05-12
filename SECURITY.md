# Security Documentation — Cryptera v1.1

## Overview

Cryptera is a local-only desktop encryption tool providing confidentiality, integrity, and
corruption resistance through modern cryptographic primitives and error correction codes.
The application is built in Rust (crypto core + Tauri backend) with a pure HTML/JS frontend.
No network connections are made; all cryptographic operations run on-device.

---

## Cryptographic Primitives

### Encryption: AES-256-GCM

- **Algorithm**: AES-256 in Galois/Counter Mode
- **Key Size**: 256 bits (32 bytes)
- **Authentication**: Built-in AEAD (Authenticated Encryption with Associated Data)
- **Tag Length**: 128 bits (16 bytes)
- **Nonce Strategy**: See "Nonce Generation" below

### Key Derivation: Argon2id

- **Algorithm**: Argon2id (hybrid mode - resistant to both GPU and side-channel attacks)
- **Salt**: 128 bits (16 bytes), cryptographically random per file
- **Default Parameters**: 
  - Time cost (iterations): 3
  - Memory cost: 64 MB (65536 KiB)
  - Parallelism: 2 threads
- **Configurable**: Users can adjust via "Security Profiles" (Standard/Strong/Paranoid)
- **Output**: 256-bit encryption key

### Integrity: CRC32 + GCM Authentication

- **Per-Shard CRC**: CRC32 with 2x redundancy for fast hardware-friendly corruption detection.
- **GCM Tags**: 128-bit authentication tag per encrypted shard.
- **Header Authentication**: Header metadata is included as **AAD** (Associated Authenticated Data) in every GCM operation, ensuring its integrity without a separate HMAC.

### Error Correction: Reed-Solomon (GF(256))

- **Algorithm**: Systematic MDS Reed-Solomon codes over Galois Field 256
- **Default Profile**: Medium (k=24, r=8) → 33% overhead, tolerate 8 corrupted shards
- **Configurable**: Low/Medium/High/Max profiles available
- **Performance**: Numba-accelerated when available

---

## Security Guarantees

### ✅ Confidentiality

- **Protection**: AES-256-GCM provides semantic security
- **Key Strength**: 2^256 keyspace (brute force infeasible)
- **Nonce Uniqueness**: Guaranteed unique nonces per shard (see below)

### ✅ Integrity & Authenticity

- **Tamper Detection**: GCM authentication tags detect any modification
- **Header Protection**: Metadata included in authenticated data
- **Cryptographic Binding**: Encrypted data cryptographically bound to header

### ✅ Password Protection

- **KDF Strength**: Argon2id work factor configurable (default: 3 iterations, 64MB RAM)
- **Salt Uniqueness**: Random 128-bit salt per file
- **Dictionary Resistance**: Memory-hard function resists GPU/ASIC attacks
- **Optional Keyfile**: Two-factor protection combining password and keyfile.
- **Keyfile Construction**: `HMAC-SHA256(key=SHA256(keyfile), msg=password)`. This prevents entropy loss and ensures even huge keyfiles are processed safely (via streaming hash).

---

## Keyfile Threat Model

### What a keyfile provides

A keyfile adds a **possession factor** to the password's knowledge factor. An attacker
who steals the encrypted file and learns the password (e.g., via keylogger) still cannot
decrypt without the keyfile. Conversely, an attacker who steals the keyfile but not the
password gains nothing.

### Construction detail

```
kf_hash   = SHA-256(keyfile_bytes)   // streamed in 64 KiB chunks
secret    = HMAC-SHA256(key=kf_hash, msg=password_utf8)
master_key = Argon2id(password=secret, salt=file_salt, …)
```

HMAC is used (not simple concatenation) so that:
- Very large keyfiles are processed in constant output size (no entropy dilution).
- The password and keyfile contribute independently: a weak password is not rescued
  by a strong keyfile, but a strong keyfile raises the bar even for a weak password.

### Minimum keyfile requirements

| Property | Recommendation |
|----------|----------------|
| **Entropy** | ≥ 128 bits true randomness (e.g., 16 bytes from `/dev/urandom`) |
| **Format** | Any file: binary blob, text, image, certificate, etc. |
| **Size** | Any size; 32–256 bytes is practical |
| **Storage** | Different physical medium from the encrypted file (e.g., USB key) |
| **Backup** | Must be backed up; loss of keyfile = permanent loss of access |

### ⚠️ Threats NOT mitigated by keyfile

| Threat | Status |
|--------|--------|
| Attacker has BOTH password AND keyfile | **Not protected** (by definition) |
| Keyfile on same disk as encrypted file | **Provides no isolation benefit** |
| File-system forensics recovering deleted keyfile | **Not protected** |
| Attacker with live system access (RAM dump) | **Not protected** |

### Keyfile storage best practices

1. Store the keyfile on a hardware token (USB, smart card) separate from the host.
2. Never store the keyfile in the same directory or backup set as the `.ecf` files.
3. For archival use, store an encrypted copy of the keyfile in a password manager.

---

### ✅ Corruption Resistance

- **Forward Error Correction**: Reed-Solomon can recover from partial data loss
- **Graceful Degradation**: Files remain decryptable even with shard corruption
- **Header Redundancy**: Header stored at both start and end of file

---

## Nonce Generation Strategy

**Critical for GCM security**: Nonces must NEVER repeat with the same key.

### Design

```
nonce (96 bits total) = nonce_base (32 bits) || block_index (32 bits) || shard_index (32 bits)
```

- **nonce_base**: Random 32-bit value, generated once per file
- **block_index**: Incremental counter per data block (0, 1, 2, ...)
- **shard_index**: Incremental counter per shard within block (0 to m-1)

### Collision Resistance

- Each file has unique random `nonce_base` (2^32 space)
- Each (key, nonce) pair used exactly once per file
- **Maximum file size**: ~1.5 PiB (1536 TiB)
    - Calculated as: $2^{32}$ blocks × $(k \times shard\_size)$.
    - With default $k=24$ and $shard\_size=16$ KiB, block size is 384 KiB.
- **Guarantee**: No nonce reuse within a single file
- **Guarantee**: Statistically negligible collision across files (different salts → different keys)

---

## Privacy Considerations

### Audit Log Privacy

Cryptera writes a persistent JSONL audit log of every encrypt / decrypt / verify
operation. **This log may contain sensitive information** and is stored unencrypted.

**Default log paths:**
- **Windows:** `%APPDATA%\Cryptera\logs\audit.jsonl`
- **Linux / macOS:** `~/.local/share/cryptera/logs/audit.jsonl`

**Data written per entry:**

| Field     | Content                                  | Privacy Impact |
|-----------|------------------------------------------|----------------|
| `ts`      | UTC Unix timestamp (seconds)             | Reveals usage timing |
| `op`      | Operation type (encrypt/decrypt/verify)  | Low |
| `file`    | **Full filesystem path of the source file** | **⚠ Reveals file names and paths** |
| `size_mb` | File size in MB                          | Reveals approximate original file size |
| `duration_s` | Processing time in seconds            | Low |
| `status`  | "ok" or "error"                          | Low |
| `error`   | Error message if failed                  | May reveal partial file content |

> **⚠️ Privacy Warning:** The audit log records the full paths of every file
> you encrypt or decrypt. Anyone with read access to the log file (other users,
> backup services, forensic tools) can reconstruct a history of your file operations
> even if the encrypted files themselves are protected.

**Mitigation options:**
- Use **Clear Log** in the Audit tab to wipe the log when not needed.
- Restrict filesystem permissions on `%APPDATA%\Cryptera\logs\` to your user only.
- Encrypt the `Cryptera` AppData directory with OS-level full-disk encryption (BitLocker, FileVault, LUKS).
- Consider disabling the audit log for sensitive sessions (planned feature).

**Future hardening (roadmap):**
- Option to hash/anonymize file paths in log entries.
- Option to disable audit logging entirely from settings.
- Log encryption with app-local key.

---

### Metadata Visibility

**The following metadata is stored IN CLEAR in the file header:**

| Field | Purpose | Privacy Impact |
|-------|---------|----------------|
| Version | File format version (V3+) | None |
| Encryption params | k, r, shard_size | Reveals integrity profile choice |
| KDF params | Argon2 t/m/p | Reveals security profile choice |
| Plain size (V3) | Original plaintext size (pre-comp) | **Reveals original size** |
| Stored size (V3) | Compressed size (post-comp) | Reveals compression efficiency |
| Compression flag | zlib/lzma/none | Reveals compression choice |
| Filename (V2+) | Original filename | **Optional (Flag-based in V3)** |

### Evolution Strategy

1. **Versioning**:
   - **Version 3 (Current)**: Supports dual size fields and flag-based metadata.
   - **Major changes** (e.g. new algorithms, header layout change) increment VERSION.
2. **Extensions (Future)**:
   - For optional metadata, use the area after the primary fields.
   - Prefer adding flags to `flags` byte before blindly appending data.
   - Readers should check VERSION; V3 readers can fall back to reading V1/V2 by assuming `plain_size == stored_size`.

### DoS Protection (V3+)
- **Decompression Limit**: Encrypted files now store `Plain Size`. The decompressor strictly enforces this limit to prevent "Decompression Bomb" attacks. Decrypt builds will fail if they attempt to write more than the expected plaintext size.

**Mitigation:**
- Use "Hide original filename" checkbox for privacy
- Metadata leakage is by design (needed for decryption parameter recovery)
- Consider encrypting file inside encrypted container if metadata privacy critical

### Traffic Analysis

- File size reveals approximate plaintext size (+ overhead%)
- Access patterns not protected
- Consider using full-disk encryption or VPN for transport privacy

---

## Threat Model

### ✅ Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Confidentiality breach | AES-256-GCM encryption |
| Brute force attack | Argon2id work factor |
| Dictionary attack | Argon2id + salt + optional keyfile |
| Data tampering | GCM authentication tags |
| Partial file corruption | Reed-Solomon FEC |
| Header corruption | Redundant header storage |
| Password guessing | Optional PWCHK for fast rejection |
| Nonce reuse | Unique (random_base &#124;&#124; counter) per shard |

### ⚠️ Out of Scope

| Threat | Status |
|--------|--------|
| Side-channel attacks (timing, power) | **Not protected** |
| Forward secrecy | **Not provided** (static password) |
| Metadata privacy (file size, params) | **Limited** (by design) |
| Traffic analysis | **Not protected** |
| Malware on decryption machine | **Not protected** |
| Keylogger / shoulder surfing | **Not protected** |
| Quantum computing | **Future threat** (AES-256 ≈ 128-bit post-quantum) |

---

## Best Practices

### For Users

1. **Strong Passwords**: Use 16+ characters, mixed case, numbers, symbols
2. **Keyfiles**: Add keyfile for 2-factor security (password + possession)
3. **Security Profiles**: Use "Strong" or "Paranoid" for sensitive data
4. **Integrity Profiles**: Use "High" or "Max" for critical archival data
5. **Verify Decryption**: Always verify decrypted content matches original
6. **Secure Storage**: Store encrypted files on separate media from keyfiles
7. **Backup Strategy**: Keep multiple copies (corruption resistance ≠ backup)

### For Developers

1. **Dependency audit**: Run `cargo audit` and `cargo deny check` before releases
2. **Test coverage**: `cargo test --all-features` (core) + `cargo test` in `src-tauri/`
3. **Entropy source**: All randomness via `rand::rngs::OsRng` (OS CSPRNG)
4. **Memory safety**: Rust ownership prevents buffer overflows; secrets use `secrecy::Secret` + `zeroize`
5. **Error handling**: All Tauri commands return `Result<T, String>`; never `.unwrap()` in command handlers
6. **Key zeroization**: `Zeroizing<Vec<u8>>` is used for all derived key material
7. **Clippy gates**: CI enforces `-D warnings`; no unsafe code outside explicitly reviewed sections

---

## Compliance & Audit

### Standards Alignment

- **NIST**: AES-256 approved (FIPS 197)
- **Argon2**: Winner of Password Hashing Competition 2015
- **GCM**: NIST SP 800-38D approved mode

### Audit Trail

- All parameters logged in file header (auditable)
- Version field enables format evolution tracking
- Deterministic decryption (same input → same output)

---

## Known Limitations

1. **No Perfect Forward Secrecy**: Password compromise → all past files compromised
2. **Metadata Leakage**: File size, encryption params visible
3. **Memory Requirements**: High integrity settings can use significant RAM
4. **No Built-in Key Management**: Users responsible for password/keyfile security
5. **Single-threaded Decryption**: No parallel shard decryption (future enhancement)

---

## Incident Response

If you suspect a security vulnerability:

1. **Do not** publicly disclose before coordinated disclosure
2. Contact maintainers privately
3. Provide: Description, reproduction steps, impact assessment
4. Expected response time: 48-72 hours for acknowledgment

---

## Changelog

### App v1.1.0 / Header v4 (current)
- Header Authentication Tag: HMAC binding between key and header (anti-tampering).
- `stored_size` field: accurate decompression limit enforcement.
- LZMA2 compression flag.
- TAR container flag for folder encryption.
- Keyfile HMAC construction (replaces naive concatenation).
- Audit JSONL log with per-operation entries.
- Persistent system tray.

### App v1.0.0 / Header v4 (initial)
- Full Rust rewrite of the crypto core.
- AES-256-GCM + Argon2id + Reed-Solomon in Rust (`crypto_core_rs` crate).
- Tauri v2 GUI (`crypto_tauri` crate).
- Header v4 format with PWCHK optional record and header redundancy.
- Automated crypto regression tests and fuzzing harness.

### Header v3 (legacy Python era)
- Dual size tracking (Plain vs Stored) for accurate compression handling.
- Enforcement of decompression limits (anti-DoS).
- Enhanced privacy: explicit flag for filename metadata.
- Secure TAR extraction (manual walk, strict permissions).

### Header v1 / v2 (legacy)
- v2: Optional filename metadata; PWCHK record.
- v1: Initial format — AES-256-GCM + Argon2id + Reed-Solomon + header redundancy.

---

## References

- [NIST AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [GCM Mode NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Reed-Solomon Codes](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
