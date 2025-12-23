# Security Documentation

## Overview

CryptoV2 is a file encryption tool providing confidentiality, integrity, and corruption resistance through modern cryptographic primitives and error correction codes.

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

1. **Review Dependencies**: Audit `pycryptodome`, `argon2-cffi` versions
2. **Test Coverage**: Run full test suite before deployment
3. **Entropy Source**: Ensure OS provides quality randomness (`os.urandom`)
4. **Memory Safety**: Be aware of potential memory limits with large files + high integrity settings
5. **Error Handling**: Always check return codes from `decrypt_file_ex`

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

### V3 (Current)
- Dual size tracking (Plain vs Stored) for accurate compression handling.
- Enforcement of decompression limits (anti-DoS).
- Enhanced privacy: explicit flag for filename metadata.
- Secure TAR extraction (manual walk, strict permissions).
- Integrated CLI tool.

### V2 (Legacy)
- Added optional filename metadata
- Initial implementation
- AES-256-GCM + Argon2id + Reed-Solomon
- Header redundancy
- PWCHK optional record

---

## References

- [NIST AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [GCM Mode NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Reed-Solomon Codes](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
