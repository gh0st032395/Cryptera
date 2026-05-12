# ECF1 File Format Specification — Header v4

> **Version:** 4 (current)  
> **Magic:** `ECF1`  
> **Status:** Stable  
> **Source of truth:** `src/lib.rs` constants block

All multi-byte integers are **big-endian** unless noted otherwise.  
Byte offsets listed are relative to the start of each section.

---

## Table of Contents

1. [File Layout Overview](#1-file-layout-overview)
2. [Start Header](#2-start-header)
3. [Header Body](#3-header-body)
4. [Flags Byte](#4-flags-byte)
5. [Optional PWCHK Record](#5-optional-pwchk-record)
6. [Header Authentication Tag](#6-header-authentication-tag)
7. [Data & Parity Shards](#7-data--parity-shards)
8. [End Trailer](#8-end-trailer)
9. [Nonce Construction](#9-nonce-construction)
10. [Key Derivation](#10-key-derivation)
11. [Parameter Constraints](#11-parameter-constraints)
12. [Version History](#12-version-history)

---

## 1. File Layout Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  START HEADER  (variable length)                                │
│    Magic "ECF1" · hdr_len · Header Body · hdr_crc              │
├─────────────────────────────────────────────────────────────────┤
│  PWCHK RECORD  (60 bytes, only if FLAG_PWCHK set)               │
├─────────────────────────────────────────────────────────────────┤
│  HEADER AUTH TAG  (16 bytes)                                    │
├─────────────────────────────────────────────────────────────────┤
│  DATA SHARDS  (num_blocks × k shards)                           │
│    Each shard: nonce(12) · ciphertext(shard_size) · tag(16)     │
│                · crc32×2(8)                                     │
├─────────────────────────────────────────────────────────────────┤
│  PARITY SHARDS  (num_blocks × r shards)                         │
│    Same per-shard layout as data shards                         │
├─────────────────────────────────────────────────────────────────┤
│  END TRAILER  (variable length)                                 │
│    Header Body copy · hdr_crc · hdr_len · Magic "ECCT"         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Start Header

```
Offset  Size  Type    Field
──────  ────  ──────  ─────────────────────────────────────────────
0       4     bytes   magic = 0x45 0x43 0x46 0x31  ("ECF1")
4       2     u16 BE  hdr_len  — length of Header Body in bytes
6       …     bytes   Header Body  (hdr_len bytes, see §3)
6+hdr_len  4  u32 BE  hdr_crc  — CRC32 of (magic + hdr_len + Header Body)
```

**Total start header size:** `10 + hdr_len` bytes minimum.

---

## 3. Header Body

The Header Body is the byte range `[6 .. 6+hdr_len)` within the Start Header.

```
Offset  Size  Type    Field
──────  ────  ──────  ─────────────────────────────────────────────
0       1     u8      version     = 4  (current format version)
1       1     u8      alg         = 1  (AES-256-GCM)
2       1     u8      kdf         = 1  (Argon2id)
3       1     u8      crc_type    = 1  (CRC32)
4       1     u8      salt_len    = 16 (always 16 in v4)
5       16    bytes   salt        — random Argon2 salt (OsRng)
21      4     u32 BE  nonce_base  — random per-file nonce seed (OsRng)
25      8     u64 BE  plain_size  — original plaintext size (bytes, pre-compression)
33      8     u64 BE  stored_size — compressed size (bytes; equals plain_size if uncompressed)
41      4     u32 BE  shard_size  — data bytes per shard (default: 16384)
45      2     u16 BE  k           — number of data shards per block (default: 24)
47      2     u16 BE  r           — number of parity shards per block (default: 8)
49      4     u32 BE  argon2_time — Argon2 iteration count (default: 3)
53      4     u32 BE  argon2_mem  — Argon2 memory cost in KiB (default: 65536)
57      2     u16 BE  argon2_par  — Argon2 parallelism (default: 2)
59      1     u8      tag_len     = 16 (AES-GCM authentication tag length)
60      1     u8      flags       — bitfield (see §4)

[OPTIONAL — present only if FLAG_HAS_FILENAME (bit 4) is set]
61      2     u16 BE  fname_len   — byte length of UTF-8 filename
63      …     UTF-8   filename    — original filename (fname_len bytes, no NUL)
```

**Minimum header body size:** 61 bytes (no filename).  
**Maximum header body size:** 8192 bytes (`MAX_HEADER_LEN`).

---

## 4. Flags Byte

| Bit | Mask | Name                   | Meaning                                            |
|-----|------|------------------------|----------------------------------------------------|
| 0   | 0x01 | `FLAG_PWCHK`           | PWCHK password-check record follows header auth    |
| 1   | 0x02 | `FLAG_COMPRESS_ZLIB`   | Plaintext was compressed with zlib before encrypt  |
| 2   | 0x04 | *(reserved)*           | —                                                  |
| 3   | 0x08 | `FLAG_COMPRESS_LZMA`   | Plaintext was compressed with LZMA2 before encrypt |
| 4   | 0x10 | `FLAG_HAS_FILENAME`    | Filename field present in header body              |
| 5   | 0x20 | `FLAG_TAR_CONTAINER`   | Payload is a TAR archive (folder encryption)       |
| 6-7 | 0xC0 | *(reserved)*           | —                                                  |

Flags 1 (`ZLIB`) and 3 (`LZMA`) are mutually exclusive. A reader receiving both set
should return `HEADER_INVALID`.

---

## 5. Optional PWCHK Record

Present immediately after the Start Header **only when** `FLAG_PWCHK` (0x01) is set.  
Total size: **60 bytes**.

```
Offset  Size  Type     Field
──────  ────  ───────  ──────────────────────────────────────────────────────
0       4     bytes    pwchk_magic = 0x50 0x57 0x43 0x4B  ("PWCK")
4       4     u32 BE   crc32_copy_1 — CRC32 of the 32-byte plaintext
8       4     u32 BE   crc32_copy_2 — same value (2× redundancy, CRC_COPIES=2)
12      32    bytes    plaintext    = "ECF1-PASSWORD-CHECK-RECORD-000\x00\x00"
44      16    bytes    gcm_tag      — AES-256-GCM authentication tag
                                     nonce: nonce12(nonce_base, 0xFFFFFFFF, 0xFFFFFFFF)
                                     aad:   full Start Header bytes (magic→hdr_crc)
```

A reader with the wrong password will fail GCM tag verification here before
attempting to derive the key and decrypt all shards, allowing fast rejection.
This record is encrypted with the same derived key as the payload shards.

---

## 6. Header Authentication Tag

Present immediately after the PWCHK record (or immediately after the Start Header
if `FLAG_PWCHK` is not set).  
Total size: **16 bytes**.

```
Derivation:
  auth_key  = HMAC-SHA256(master_key, "ECF1-HEADER-AUTH-V1")[..32]
  auth_tag  = HMAC-SHA256(auth_key,  start_header_bytes || hdr_crc_bytes)[..16]
```

This tag cryptographically binds the header to the encryption key. Any header
modification — including parameter tampering — will be detected before shard
decryption begins.

---

## 7. Data & Parity Shards

The payload is split into **blocks**. Each block contains `k` data shards and `r`
parity shards (Reed-Solomon over GF(256)).

```
num_blocks = ceil(stored_size / (k × shard_size))
```

All data shards are emitted first (all blocks × k), followed by all parity shards
(all blocks × r).

**Per-shard layout (data shards):**

```
Offset  Size         Type    Field
──────  ───────────  ──────  ──────────────────────────────────────────────────
0       12           bytes   nonce   — see §9
12      shard_size   bytes   ciphertext  (last shard of last block may be shorter)
12+S    16           bytes   gcm_tag — AES-256-GCM authentication tag
28+S    4            u32 BE  crc32_copy_1 — CRC32 of ciphertext bytes
32+S    4            u32 BE  crc32_copy_2 — same (2× redundancy)

where S = shard_size (or actual ciphertext length for the final partial shard)
```

**Per-shard layout (parity shards):**  
Identical structure. The parity shard plaintext is the Reed-Solomon parity data;
it is encrypted and tagged exactly like data shards.

**Associated Authenticated Data (AAD) for all shards:**
```
aad = start_header_bytes  (magic + hdr_len + Header Body + hdr_crc)
```

This binding ensures shards cannot be mixed across different files or paired with
a tampered header.

---

## 8. End Trailer

The trailer duplicates the header at the end of the file to allow partial-read
recovery when the start is corrupted.

```
Offset              Size      Type     Field
──────              ────────  ───────  ──────────────────────────────────────
0                   hdr_len   bytes    Header Body copy (identical to §3)
hdr_len             4         u32 BE   hdr_crc  (same value as in Start Header)
hdr_len + 4         2         u16 BE   hdr_len  (same value, for back-scanning)
hdr_len + 6         4         bytes    trailer_magic = 0x45 0x43 0x43 0x54  ("ECCT")
```

A reader can locate the trailer by seeking to `EOF − 10` and reading backward to
find the `ECCT` magic.

---

## 9. Nonce Construction

Each AES-256-GCM shard uses a unique 96-bit (12-byte) nonce:

```
nonce[0..4]  = nonce_base    (u32 BE) — random per-file seed
nonce[4..8]  = block_index   (u32 BE) — 0-based block counter
nonce[8..12] = shard_index   (u32 BE) — 0-based shard counter within block
                                        (data shards: 0..k, parity: k..k+r)
```

**PWCHK nonce:** `nonce12(nonce_base, 0xFFFF_FFFF, 0xFFFF_FFFF)` — a reserved value
that cannot collide with any data shard index.

**Maximum file size:**  
With default `k=24`, `shard_size=16 KiB`:  
`2^32 blocks × 24 shards × 16 KiB = 1536 TiB` before nonce exhaustion.

---

## 10. Key Derivation

```
Inputs:
  password   — UTF-8 string
  salt       — 16 bytes (random, from header)
  t          — Argon2 iterations  (header field argon2_time)
  m          — Argon2 memory KiB  (header field argon2_mem)
  p          — Argon2 parallelism (header field argon2_par)
  keyfile    — optional file path

Step 1 (optional keyfile blending):
  If keyfile provided:
    kf_hash   = SHA-256(file_contents)   // streaming, 64 KiB chunks
    secret    = HMAC-SHA256(key=kf_hash, msg=password_bytes)
  Else:
    secret    = password_bytes

Step 2 (KDF):
  master_key = Argon2id(
      password = secret,
      salt     = salt,
      t_cost   = t,
      m_cost   = m,
      p_cost   = p,
      tag_len  = 32   // 256-bit AES key
  )
```

The `master_key` is used directly as the AES-256 key for all shards and the PWCHK
record. A separate `auth_key` (§6) is derived from `master_key` via HMAC to avoid
key reuse.

---

## 11. Parameter Constraints

| Parameter     | Min    | Max      | Default  | Unit |
|---------------|--------|----------|----------|------|
| `k`           | 1      | 64       | 24       | shards |
| `r`           | 1      | 64       | 8        | shards |
| `k + r`       | —      | 255      | 32       | shards (GF(256) limit) |
| `shard_size`  | 1 024  | 1 048 576| 16 384   | bytes |
| `argon2_time` | 1      | 10       | 3        | iterations |
| `argon2_mem`  | 8 192  | 524 288  | 65 536   | KiB |
| `argon2_par`  | 1      | 8        | 2        | threads |
| `salt_len`    | 16     | 16       | 16       | bytes (fixed) |
| `tag_len`     | 16     | 16       | 16       | bytes (fixed) |
| Header Body   | —      | 8 192    | ~61      | bytes |

A reader that encounters values outside these ranges MUST return
`DECRYPT_PARAMS_OUT_OF_LIMITS` without attempting decryption.

---

## 12. Version History

| Version | Changes |
|---------|---------|
| **v4** (current) | Header Auth Tag (HMAC binding key to header); `stored_size` field; LZMA2 compression flag; TAR container flag; filename length made u16 |
| v3 | Dual `plain_size` / `stored_size` fields; decompression bomb limit; hide-filename flag |
| v2 | Optional filename metadata; PWCHK optional record |
| v1 | Initial format: single-size field, mandatory filename |

Readers implementing v4 MUST be able to parse v3 headers by treating
`stored_size == plain_size` when the v3 field is absent, and fall back to v2/v1
by assuming no filename or PWCHK record.

---

*This document is auto-maintained. For the normative reference, read `src/lib.rs`
(constants block, `write_header`, `parse_header`, and `encrypt_file_ex`).*
