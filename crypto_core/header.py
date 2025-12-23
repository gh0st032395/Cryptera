import struct
import zlib
from Crypto.Random import get_random_bytes
from .constants import *

def _nonce12(nonce_base: int, block_index: int, shard_index: int) -> bytes:
    # 12-byte nonce = nonce_base|block_index|shard_index
    return struct.pack(">III", nonce_base, block_index, shard_index)


def _build_header(plain_size: int, stored_size: int, salt: bytes, nonce_base: int,
                  shard_size: int, k: int, r: int, flags: int,
                  t: int, m: int, p: int, filename: str = "") -> bytes:
    # Header bytes (excluding MAGIC and header_len):
    # version u8, alg u8, kdf u8, crc u8
    # salt_len u8, salt
    # nonce_base u32
    # plain_size u64
    # stored_size u64 (V3+)
    # shard_size u32
    # k u16, r u16
    # argon2 time u32, mem_kib u32, par u16
    # tag_len u8, flags u8
    # V2/V3 (with flag): filename_len u16, filename_bytes [...]
    
    parts = [
        struct.pack(">BBBB", VERSION, ALG_AES_GCM, KDF_ARGON2ID, CRC_CRC32),
        struct.pack(">B", len(salt)),
        salt,
        struct.pack(">I", nonce_base),
        struct.pack(">Q", plain_size),
    ]

    if VERSION >= 3:
        parts.append(struct.pack(">Q", stored_size))

    parts.extend([
        struct.pack(">I", shard_size),
        struct.pack(">HH", k, r),
        struct.pack(">IIH", t, m, p),
        struct.pack(">BB", TAG_LEN, flags & 0xFF),
    ])

    if flags & HDR_FLAG_HAS_FILENAME:
        fname_bytes = filename.encode("utf-8") if filename else b""
        parts.append(struct.pack(">H", len(fname_bytes)))
        parts.append(fname_bytes)

    return b"".join(parts)


def _pack_header(plain_size: int, stored_size: int, k: int, r: int, shard_size: int, 
                 flags: int, t: int, m: int, p: int, filename: str = ""):
    salt = get_random_bytes(16)
    nonce_base = struct.unpack(">I", get_random_bytes(4))[0]

    # Flags are passed in, no need to force them here.
    
    hdr = _build_header(plain_size, stored_size, salt, nonce_base, shard_size, k, r, flags, t, m, p, filename)
    hdr_len = len(hdr)
    if hdr_len == 0 or hdr_len > MAX_HEADER_LEN:
        raise ValueError("Header length out of bounds")

    prefix = MAGIC + struct.pack(">H", hdr_len) + hdr
    hdr_crc = zlib.crc32(prefix) & 0xFFFFFFFF

    start_header = prefix + struct.pack(">I", hdr_crc)
    trailer = hdr + struct.pack(">I", hdr_crc) + struct.pack(">H", hdr_len) + TRAILER

    return start_header, trailer, prefix, hdr, hdr_len, hdr_crc, salt, nonce_base, flags

# ... (_read_header functions unchanged) ...

def _parse_header(hdr: bytes):
    off = 0
    version, alg, kdf, crc_type = struct.unpack_from(">BBBB", hdr, off)
    off += 4

    salt_len = struct.unpack_from(">B", hdr, off)[0]
    off += 1
    salt = hdr[off:off + salt_len]
    off += salt_len

    nonce_base = struct.unpack_from(">I", hdr, off)[0]
    off += 4

    plain_size = struct.unpack_from(">Q", hdr, off)[0]
    off += 8

    if version >= 3:
        stored_size = struct.unpack_from(">Q", hdr, off)[0]
        off += 8
    else:
        # V1/V2: stored_size is the same as plain_size
        stored_size = plain_size

    shard_size = struct.unpack_from(">I", hdr, off)[0]
    off += 4

    k, r = struct.unpack_from(">HH", hdr, off)
    off += 4

    t_cost, mem_kib, par = struct.unpack_from(">IIH", hdr, off)
    off += 10

    tag_len, flags = struct.unpack_from(">BB", hdr, off)
    off += 2
    
    filename = ""
    # V3 uses flag. V2 always had it if bytes remained.
    had_filename = False
    if version >= 3:
        if flags & HDR_FLAG_HAS_FILENAME:
            had_filename = True
    elif version == 2:
        had_filename = True # Try to read if v2

    if had_filename:
        # Check if we have bytes left for filename len
        if off + 2 <= len(hdr):
            fname_len = struct.unpack_from(">H", hdr, off)[0]
            off += 2
            if off + fname_len <= len(hdr):
                try:
                    filename = hdr[off:off+fname_len].decode("utf-8")
                except UnicodeDecodeError:
                    pass # Ignore broken filenames
                off += fname_len

    return {
        "version": version,
        "alg": alg,
        "kdf": kdf,
        "crc_type": crc_type,
        "salt": salt,
        "nonce_base": nonce_base,
        "plain_size": plain_size,
        "stored_size": stored_size,
        "file_size": stored_size, # Backward compat for loop calculations
        "shard_size": shard_size,
        "k": k,
        "r": r,
        "argon2_time": t_cost,
        "argon2_mem_kib": mem_kib,
        "argon2_par": par,
        "tag_len": tag_len,
        "flags": flags,
        "filename": filename
    }


def _read_header_from_start(f):
    magic = f.read(4)
    if magic != MAGIC:
        return None

    raw_len = f.read(2)
    if len(raw_len) != 2:
        return None
    hdr_len = struct.unpack(">H", raw_len)[0]
    if hdr_len == 0 or hdr_len > MAX_HEADER_LEN:
        return None

    hdr = f.read(hdr_len)
    if len(hdr) != hdr_len:
        return None

    raw_crc = f.read(4)
    if len(raw_crc) != 4:
        return None
    hdr_crc = struct.unpack(">I", raw_crc)[0]

    prefix = magic + raw_len + hdr
    if (zlib.crc32(prefix) & 0xFFFFFFFF) != hdr_crc:
        return None

    return hdr, hdr_len, hdr_crc


def _read_header_from_end(f):
    import os
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size < 4 + 2 + 4:
        return None

    f.seek(size - 4)
    if f.read(4) != TRAILER:
        return None

    f.seek(size - 4 - 2)
    hdr_len = struct.unpack(">H", f.read(2))[0]
    if hdr_len == 0 or hdr_len > MAX_HEADER_LEN:
        return None

    f.seek(size - 4 - 2 - 4)
    hdr_crc = struct.unpack(">I", f.read(4))[0]

    f.seek(size - 4 - 2 - 4 - hdr_len)
    hdr = f.read(hdr_len)
    if len(hdr) != hdr_len:
        return None

    prefix = MAGIC + struct.pack(">H", hdr_len) + hdr
    if (zlib.crc32(prefix) & 0xFFFFFFFF) != hdr_crc:
        return None

    return hdr, hdr_len, hdr_crc



