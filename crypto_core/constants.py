# =========================
# File container constants
# =========================
MAGIC = b"ECF1"     # file magic
TRAILER = b"ECCT"   # trailer magic (for header recovery)

VERSION = 2

ALG_AES_GCM = 1
KDF_ARGON2ID = 1
CRC_CRC32 = 1

TAG_LEN = 16
KEY_LEN = 32


# =========================
# Default parameters
# =========================
# ECC layout - MEDIUM profile (33% overhead, good balance)
K_DATA = 24
R_PARITY = 8
SHARD_SIZE = 16 * 1024  # 16 KiB for better I/O performance
# => Can tolerate up to 8 corrupted shards per block (~33% overhead)

# Argon2id tuning (default for ENCRYPT)
ARGON2_TIME = 3
ARGON2_MEM_KIB = 65536       # 64 MiB
ARGON2_PAR = 2

# Per-shard CRC is duplicated twice (more robust to CRC field corruption)
CRC_COPIES = 2

# Safety limits (header length)
MAX_HEADER_LEN = 8192


# =========================
# Hard limits (anti-DoS)
# =========================
ARGON2_TIME_MIN = 1
ARGON2_TIME_MAX = 10

ARGON2_MEM_KIB_MIN = 8 * 1024          # 8 MiB
ARGON2_MEM_KIB_MAX = 512 * 1024        # 512 MiB (scegli tu)

ARGON2_PAR_MIN = 1
ARGON2_PAR_MAX = 8

K_MIN = 1
K_MAX = 64
R_MIN = 1
R_MAX = 64

SHARD_SIZE_MIN = 1024                  # 1 KiB
SHARD_SIZE_MAX = 1024 * 1024           # 1 MiB

MAX_BLOCKS_U32 = 2**32                 # num_blocks must be < 2**32


# =========================
# Header flags + PW-check
# =========================
HDR_FLAG_PWCHK = 0x01
HDR_FLAG_COMPRESS_ZLIB = 0x02
HDR_FLAG_COMPRESS_ZSTD = 0x04 # Reserved / Example
HDR_FLAG_COMPRESS_LZMA = 0x08

ENABLE_PWCHK_RECORD = True
PWCHK_MAGIC = b"PWCK"
PWCHK_PLAINTEXT_LEN = 32
PWCHK_PLAINTEXT = (
    b"ECF1-PASSWORD-CHECK-RECORD-000"[:PWCHK_PLAINTEXT_LEN]
).ljust(PWCHK_PLAINTEXT_LEN, b"\x00")

# PWCHK record layout:
# magic(4) + crc_copies(4*CRC_COPIES) + ct(32) + tag(16)
PWCHK_RECORD_SIZE = 4 + (4 * CRC_COPIES) + PWCHK_PLAINTEXT_LEN + TAG_LEN


# =========================
# Decrypt diagnostics
# =========================
class DecryptError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message or code


DECRYPT_OK = "OK"
DECRYPT_PASSWORD_INVALID = "PASSWORD_INVALID"
DECRYPT_CORRUPT_BEYOND_FEC = "CORRUPT_BEYOND_FEC"
DECRYPT_HEADER_INVALID = "HEADER_INVALID"
DECRYPT_PARAMS_OUT_OF_LIMITS = "PARAMS_OUT_OF_LIMITS"
DECRYPT_TRUNCATED = "TRUNCATED"
DECRYPT_IO_ERROR = "IO_ERROR"
DECRYPT_UNKNOWN_ERROR = "UNKNOWN_ERROR"

# =========================
# UI Profiles
# =========================
PROFILES_SECURITY = {
    "Standard": {"t": 3, "m": 64*1024, "p": 2}, 
    "Strong":   {"t": 6, "m": 256*1024, "p": 4},
    "Paranoid": {"t": 10, "m": 512*1024, "p": 8},
}

PROFILES_INTEGRITY = {
    "Low":      {"k": 28, "r": 4},  # ~14%
    "Medium":   {"k": 24, "r": 8},  # ~33%
    "High":     {"k": 12, "r": 12}, # 100% (Default)
    "Max":      {"k": 8, "r": 24}   # 300%
}
