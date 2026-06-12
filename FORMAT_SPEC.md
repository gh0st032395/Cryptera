# ECF1 File Format Specification — Header v5

> **Version:** 5 (current)  
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
5. [Encrypted Filename Record (v5)](#5-encrypted-filename-record-v5)
6. [Optional PWCHK Record](#6-optional-pwchk-record)
7. [Header Authentication Tag](#7-header-authentication-tag)
8. [Data & Parity Shards](#8-data--parity-shards)
9. [End Trailer](#9-end-trailer)
10. [Nonce Construction](#10-nonce-construction)
11. [Key Derivation](#11-key-derivation)
12. [Parameter Constraints](#12-parameter-constraints)
13. [Version History](#13-version-history)

---

## 1. File Layout Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  START HEADER  (variable length)                                │
│    Magic "ECF1" · hdr_len · Header Body · hdr_crc               │
│    · Header Auth Tag (16 bytes, v4+)                            │
├─────────────────────────────────────────────────────────────────┤
│  PWCHK RECORD  (60 bytes, only if FLAG_PWCHK set)               │
├─────────────────────────────────────────────────────────────────┤
│  BLOCKS  (num_blocks × (k + r) shards, block by block)          │
│    Each shard: crc32×2(8) · ciphertext(shard_size) · tag(16)    │
│    Within a block: k data shards, then r parity shards          │
├─────────────────────────────────────────────────────────────────┤
│  END TRAILER  (variable length)                                 │
│    Header Body copy · hdr_crc · Header Auth Tag (v4+)           │
│    · hdr_len · Magic "ECCT"                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Start Header

```
Offset      Size  Type    Field
──────      ────  ──────  ─────────────────────────────────────────────
0           4     bytes   magic = 0x45 0x43 0x46 0x31  ("ECF1")
4           2     u16 BE  hdr_len  — length of Header Body in bytes
6           …     bytes   Header Body  (hdr_len bytes, see §3)
6+hdr_len   4     u32 BE  hdr_crc  — CRC32 of (magic + hdr_len + Header Body)
10+hdr_len  16    bytes   header auth tag  (v4+, see §7)
```

**Total start header size:** `26 + hdr_len` bytes (v4+).  
The byte range `[0 .. 6+hdr_len)` — magic, length and Header Body, **without**
`hdr_crc` — is called the **header prefix** and is used as AAD base (see §8).

---

## 3. Header Body

The Header Body is the byte range `[6 .. 6+hdr_len)` within the Start Header.

```
Offset  Size  Type    Field
──────  ────  ──────  ─────────────────────────────────────────────
0       1     u8      version     = 5  (current format version)
1       1     u8      alg         = 1  (AES-256-GCM)
2       1     u8      kdf         = 1  (Argon2id)
3       1     u8      crc_type    = 1  (CRC32)
4       1     u8      salt_len    = 16 (always 16)
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

[v5 — present only if FLAG_ENC_FILENAME (bit 6) is set]
61      2     u16 BE  fname_ct_len — byte length of the filename plaintext
63      …     bytes   fname_ct     — AES-256-GCM ciphertext (fname_ct_len bytes)
…       16    bytes   fname_tag    — GCM authentication tag (see §5)

[legacy v2-v4 — present only if FLAG_HAS_FILENAME (bit 4) is set]
61      2     u16 BE  fname_len   — byte length of UTF-8 filename
63      …     UTF-8   filename    — original filename, PLAINTEXT (no NUL)
```

**Minimum header body size:** 61 bytes (no filename).  
**Maximum header body size:** 8192 bytes (`MAX_HEADER_LEN`).  
**Maximum filename length:** 4096 bytes (`MAX_FILENAME_LEN`).

---

## 4. Flags Byte

| Bit | Mask | Name                   | Meaning                                              |
|-----|------|------------------------|------------------------------------------------------|
| 0   | 0x01 | `FLAG_PWCHK`           | PWCHK password-check record follows the start header |
| 1   | 0x02 | `FLAG_COMPRESS_ZLIB`   | Plaintext was compressed with zlib before encrypt    |
| 2   | 0x04 | *(reserved)*           | —                                                    |
| 3   | 0x08 | `FLAG_COMPRESS_LZMA`   | Plaintext was compressed with LZMA2 before encrypt   |
| 4   | 0x10 | `FLAG_HAS_FILENAME`    | Legacy (v2-v4): plaintext filename in header body    |
| 5   | 0x20 | `FLAG_TAR_CONTAINER`   | Payload is a TAR archive (folder encryption)         |
| 6   | 0x40 | `FLAG_ENC_FILENAME`    | v5+: encrypted filename record in header body        |
| 7   | 0x80 | *(reserved)*           | —                                                    |

Flags 1 (`ZLIB`) and 3 (`LZMA`) are mutually exclusive. The v5 writer never sets
`FLAG_HAS_FILENAME`; it stores the filename only via `FLAG_ENC_FILENAME`.

---

## 5. Encrypted Filename Record (v5)

Since v5 the original filename is stored **encrypted** inside the Header Body
(layout in §3). Without the password the name is opaque; `read_metadata`
returns an empty filename for such files, while decrypt/verify recover it after
key derivation and header authentication.

```
ciphertext = AES-256-GCM-Encrypt(
    key   = master_key,
    nonce = nonce12(nonce_base, 0xFFFF_FFFE, 0xFFFF_FFFE),   // reserved, see §10
    aad   = "ECF1-FNAME-V5",
    msg   = filename_utf8_bytes
)
```

The record's integrity is covered twice: by its own GCM tag and by the v4+
header authentication tag (§7), which spans the entire Header Body.

To not store any filename at all, the writer omits the record and leaves
`FLAG_ENC_FILENAME` clear ("hide filename" option).

---

## 6. Optional PWCHK Record

Present immediately after the Start Header (including the header auth tag)
**only when** `FLAG_PWCHK` (0x01) is set.  
Total size: **60 bytes**.

```
Offset  Size  Type     Field
──────  ────  ───────  ──────────────────────────────────────────────────────
0       4     bytes    pwchk_magic = 0x50 0x57 0x43 0x4B  ("PWCK")
4       4     u32 BE   crc32_copy_1 — CRC32 of (ct || gcm_tag)
8       4     u32 BE   crc32_copy_2 — same value (2× redundancy, CRC_COPIES=2)
12      32    bytes    ct           — AES-256-GCM ciphertext of the fixed
                                      plaintext "ECF1-PASSWORD-CHECK-RECORD-000\x00\x00"
44      16    bytes    gcm_tag      — AES-256-GCM authentication tag
                                      nonce: nonce12(nonce_base, 0xFFFFFFFF, 0xFFFFFFFF)
                                      aad:   header prefix (§2) || "PWCK"
```

After deriving the key, a reader with the wrong password fails GCM verification
here and can reject the file before reading any shard. The record is encrypted
with the same master key as the payload shards.

> **Key-commitment note.** AES-GCM is not key-committing on its own, but the
> v4+ header auth tag (§7) is an HMAC-SHA256 keyed by the derived key and is
> verified **before** the PWCHK record is used, committing the file to a single
> key. For this reason the PWCHK record intentionally remains GCM-based in v5.

---

## 7. Header Authentication Tag

Part of the Start Header, immediately after `hdr_crc` (and duplicated in the
trailer). Present for v4+.  
Total size: **16 bytes**.

```
Derivation:
  auth_key  = HMAC-SHA256(master_key, "ECF1-HEADER-AUTH-V1")[..32]
  auth_tag  = HMAC-SHA256(auth_key, header_prefix || hdr_crc_be)[..16]
```

This tag cryptographically binds the header to the encryption key. Any header
modification — including parameter tampering — is detected after key
derivation and before any payload processing.

---

## 8. Data & Parity Shards

The payload is split into **blocks**. Each block contains `k` data shards and
`r` parity shards (systematic Reed-Solomon over GF(256), primitive polynomial
0x11D). Blocks are written sequentially; **within each block** the `k` data
shards come first, followed by the `r` parity shards.

```
num_blocks = max(1, ceil(stored_size / (k × shard_size)))
```

The final block is zero-padded to full size; `stored_size` determines how many
bytes of the last block are valid.

**Per-shard layout (identical for data and parity shards):**

```
Offset  Size         Type    Field
──────  ───────────  ──────  ──────────────────────────────────────────────────
0       4            u32 BE  crc32_copy_1 — CRC32 of (ciphertext || gcm_tag)
4       4            u32 BE  crc32_copy_2 — same value (2× redundancy)
8       shard_size   bytes   ciphertext   — always full shard_size bytes
8+S     16           bytes   gcm_tag      — AES-256-GCM authentication tag

where S = shard_size
```

The nonce is **not stored**; it is derived (§10).

**Associated Authenticated Data (AAD) for every shard:**
```
aad = header_prefix (§2) || block_index_be (u32) || shard_index_be (u32)
```

This binds every shard to its file, its block and its position, so shards
cannot be reordered, duplicated, or mixed across files.

---

## 9. End Trailer

The trailer duplicates the header at the end of the file to allow recovery
when the start of the file is corrupted.

```
Offset           Size      Type     Field
──────           ────────  ───────  ──────────────────────────────────────
0                hdr_len   bytes    Header Body copy (identical to §3)
hdr_len          4         u32 BE   hdr_crc  (same value as in Start Header)
hdr_len + 4      16        bytes    header auth tag (v4+, same as §7)
hdr_len + 20     2         u16 BE   hdr_len  (same value, for back-scanning)
hdr_len + 22     4         bytes    trailer_magic = 0x45 0x43 0x43 0x54  ("ECCT")
```

A reader locates the trailer by seeking to `EOF − 4` and matching the `ECCT`
magic, then reading `hdr_len` from the preceding 2 bytes.

---

## 10. Nonce Construction

Each AES-256-GCM operation uses a unique 96-bit (12-byte) nonce:

```
nonce[0..4]  = nonce_base    (u32 BE) — random per-file seed
nonce[4..8]  = block_index   (u32 BE) — 0-based block counter
nonce[8..12] = shard_index   (u32 BE) — 0-based shard counter within block
                                        (data shards: 0..k, parity: k..k+r)
```

**Reserved sentinel coordinates** (cannot collide with shard nonces because
`shard_index ≤ 254` for payload shards):

| Record             | block field   | shard field   |
|--------------------|---------------|---------------|
| PWCHK (§6)         | `0xFFFF_FFFF` | `0xFFFF_FFFF` |
| Filename (§5, v5+) | `0xFFFF_FFFE` | `0xFFFF_FFFE` |

Nonce uniqueness across files is guaranteed by the per-file random salt: every
file derives a distinct master key, so nonce reuse across files is harmless.

**Maximum file size:**  
With default `k=24`, `shard_size=16 KiB`:  
`2^32 blocks × 24 shards × 16 KiB = 1536 TiB` before nonce exhaustion.

---

## 11. Key Derivation

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

Readers MUST validate all header parameters against §12 **before** running
Argon2, so a malicious header cannot request unbounded KDF cost.

The `master_key` is used directly as the AES-256 key for all shards, the PWCHK
record and the encrypted filename record. A separate `auth_key` (§7) is derived
from `master_key` via HMAC to avoid key reuse.

---

## 12. Parameter Constraints

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
| Filename      | —      | 4 096    | —        | bytes |

A reader that encounters values outside these ranges MUST return
`DECRYPT_PARAMS_OUT_OF_LIMITS` without attempting decryption.

---

## 13. Version History

| Version | Changes |
|---------|---------|
| **v5** (current) | Filename stored AES-256-GCM-encrypted in the header (`FLAG_ENC_FILENAME`, reserved nonce `0xFFFFFFFE`); plaintext filename no longer written |
| v4 | Header Auth Tag (HMAC binding key to header); `stored_size` field; LZMA2 compression flag; TAR container flag; filename length made u16 |
| v3 | Dual `plain_size` / `stored_size` fields; decompression bomb limit; hide-filename flag |
| v2 | Optional filename metadata; PWCHK optional record |
| v1 | Initial format: single-size field, mandatory filename |

Readers implementing v5 MUST keep parsing the legacy plaintext filename of
v2-v4 files (`FLAG_HAS_FILENAME`), MUST parse v3 headers by treating
`stored_size == plain_size` when the v3 field is absent, and fall back to v2/v1
by assuming no filename or PWCHK record.

---

*This document is maintained by hand. For the normative reference, read
`src/lib.rs` (constants block, `write_header`, `parse_header`,
`open_and_authenticate` and `process_blocks`).*
