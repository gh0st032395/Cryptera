import os
import math
import struct
import tempfile
import zlib
import lzma
import hashlib
from typing import Optional, Tuple, Callable
import threading
import numpy as np

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

from .constants import *
from .galois import _get_G, _fec_encode, _fec_decode
from .header import (
    _nonce12, _pack_header, _read_header_from_start, _read_header_from_end, _parse_header
)

# =========================
# Progress callback
# =========================
# progress_cb(stage: str, done: int, total: int)
ProgressCallback = Callable[[str, int, int], None]


def _progress(progress_cb: Optional[ProgressCallback], stage: str, done: int, total: int) -> None:
    if progress_cb is not None:
        progress_cb(stage, int(done), int(total))


def _validate_limits(*,
                     k: int, r: int, shard_size: int,
                     argon2_time: int, argon2_mem_kib: int, argon2_par: int,
                     num_blocks: Optional[int] = None) -> None:
    # Argon2 limits
    if not (ARGON2_TIME_MIN <= argon2_time <= ARGON2_TIME_MAX):
        raise LimitsExceededError(f"argon2_time out of limits: {argon2_time}")
    if not (ARGON2_MEM_KIB_MIN <= argon2_mem_kib <= ARGON2_MEM_KIB_MAX):
        raise LimitsExceededError(f"argon2_mem_kib out of limits: {argon2_mem_kib}")
    if not (ARGON2_PAR_MIN <= argon2_par <= ARGON2_PAR_MAX):
        raise LimitsExceededError(f"argon2_par out of limits: {argon2_par}")

    # ECC layout limits
    if not (K_MIN <= k <= K_MAX):
        raise LimitsExceededError(f"k out of limits: {k}")
    if not (R_MIN <= r <= R_MAX):
        raise LimitsExceededError(f"r out of limits: {r}")
    if k + r > 255:
        raise LimitsExceededError(f"k+r must be <= 255, got {k+r}")

    # Shard size limits
    if not (SHARD_SIZE_MIN <= shard_size <= SHARD_SIZE_MAX):
        raise LimitsExceededError(f"shard_size out of limits: {shard_size}")

    # Blocks limit (nonce safety)
    if num_blocks is not None:
        if not (0 < num_blocks < MAX_BLOCKS_U32):
            raise LimitsExceededError(f"num_blocks out of limits: {num_blocks}")


import hmac

def _derive_key(password: str, salt: bytes, t: int, mem_kib: int, par: int, keyfile: bytes = None) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password non valida (vuota o non stringa).")

    secret = password.encode("utf-8")
    if keyfile:
        # Robust construction: HMAC-SHA256(key=hash(keyfile), msg=password)
        # We first hash the keyfile to get a fixed-size key
        kf_key = hashlib.sha256(keyfile).digest()
        secret = hmac.new(kf_key, secret, hashlib.sha256).digest()

    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=t,
        memory_cost=mem_kib,
        parallelism=par,
        hash_len=KEY_LEN,
        type=Type.ID,
    )

# =========================
# Compression Helpers
# =========================
def _compression_stream(f_in, block_size: int, alg: str):
    """
    Yields chunks of `block_size` from compressed stream of `f_in`.
    """
    if alg == "zlib":
        compressor = zlib.compressobj(level=6)
    elif alg == "lzma":
        compressor = lzma.LZMACompressor(preset=6)
    else:
        # No compression
        while True:
            chunk = f_in.read(block_size)
            if not chunk:
                break
            yield chunk
        return

    # Reader buffer
    buf_size = 64 * 1024
    
    # Internal buffer for compressed data
    out_buf = b""
    
    while True:
        # If we have enough data for a block, yield it
        while len(out_buf) >= block_size:
            yield out_buf[:block_size]
            out_buf = out_buf[block_size:]
            
        # Read from source
        chunk = f_in.read(buf_size)
        if not chunk:
            # EOF source, flush compressor
            out_buf += compressor.flush()
            # Yield remaining
            while len(out_buf) > 0:
                grab = min(len(out_buf), block_size)
                yield out_buf[:grab]
                out_buf = out_buf[grab:]
            break
            
        # Compress
        out_buf += compressor.compress(chunk)


def _decompression_stream(f_out, alg: str):
    """
    Returns an object with .write() that decompresses on the fly and writes to f_out.
    """
    class DecompressorWriter:
        def __init__(self, target, algo):
            self.target = target
            if algo == "zlib":
                self.dec = zlib.decompressobj() 
            elif algo == "lzma":
                self.dec = lzma.LZMADecompressor()
            else:
                self.dec = None

        def write(self, b):
            if self.dec:
                # Decompress as much as possible. 
                # Note: if max_length was used, we'd need a loop here, but we don't.
                # However, being robust doesn't hurt.
                data = self.dec.decompress(b)
                if data:
                    self.target.write(data)
                
                # Check for unconsumed tail (though unlikely without max_length)
                while hasattr(self.dec, 'unconsumed_tail') and self.dec.unconsumed_tail:
                    tail = self.dec.unconsumed_tail
                    data = self.dec.decompress(tail)
                    if data:
                        self.target.write(data)
                    else:
                        break
            else:
                self.target.write(b)
        
        def close(self):
            if self.dec:
                # Some decompressors might have residues if not fully finished
                # We call decompress with empty bytes to signal EOF if supported by the object style
                try:
                    # zlib/lzma decompressors in Python don't strictly have a flush() 
                    # but we can check if they are finished.
                    if hasattr(self.dec, 'unconsumed_tail') and self.dec.unconsumed_tail:
                        while self.dec.unconsumed_tail:
                            data = self.dec.decompress(self.dec.unconsumed_tail)
                            if data:
                                self.target.write(data)
                            else:
                                break
                                
                except Exception:
                    pass
            # We don't close self.target here because it's usually managed by a 'with' block outside
            # but we ensure it is flushed.
            if hasattr(self.target, 'flush'):
                self.target.flush()
            
    return DecompressorWriter(f_out, alg)


# =========================
# Public API
# =========================

# ... (Previous imports)

def encrypt_file(input_file: str, output_file: str, password: str,
                 keyfile: bytes = None, compress_alg: str = None,
                 enable_pwchk: bool = True,
                 k: int = None, r: int = None, shard_size: int = None,
                 argon2_t: int = None, argon2_m: int = None, argon2_p: int = None,
                 control_event: threading.Event = None,
                 progress_cb: Optional[ProgressCallback] = None,
                 original_filename: str = None) -> None:
    
    # Defaults
    k = k or K_DATA
    r = r or R_PARITY
    shard_size = shard_size or SHARD_SIZE
    argon2_t = argon2_t or ARGON2_TIME
    argon2_m = argon2_m or ARGON2_MEM_KIB
    argon2_p = argon2_p or ARGON2_PAR
    
    filename_meta = os.path.basename(original_filename) if original_filename else os.path.basename(input_file)
    
    # Phase 1: Compression (Optional)
    processing_file = input_file
    temp_compressed = None
    
    flags = 0
    if enable_pwchk and ENABLE_PWCHK_RECORD:
        flags |= HDR_FLAG_PWCHK
        
    try:
        if compress_alg:
            if compress_alg == "zlib":
                flags |= HDR_FLAG_COMPRESS_ZLIB
            elif compress_alg == "lzma":
                flags |= HDR_FLAG_COMPRESS_LZMA
            
            # Create a temp file for the compressed data
            out_dir = os.path.dirname(os.path.abspath(output_file)) or "."
            fd, temp_compressed = tempfile.mkstemp(prefix="comp_", dir=out_dir)
            os.close(fd)
            
            # STREAMING COMPRESSION
            _progress(progress_cb, "compress", 0, 100)
            
            # Use helper
            with open(input_file, "rb") as f_in, open(temp_compressed, "wb") as f_c:
                 stream_iter = _compression_stream(f_in, 64*1024, compress_alg)
                 for chunk in stream_iter:
                    # Check Pause
                    if control_event and not control_event.is_set():
                        control_event.wait()
                    f_c.write(chunk)
            
            processing_file = temp_compressed
        
        # Phase 2: Encryption
        file_size = os.path.getsize(processing_file)
        
        m = k + r
        block_size = k * shard_size

        num_blocks = math.ceil(file_size / block_size) if file_size else 1

        # Header with REAL size
        start_header, trailer, prefix, hdr, hdr_len, hdr_crc, salt, nonce_base, flags = _pack_header(
            file_size=file_size,
            k=k,
            r=r,
            shard_size=shard_size,
            flags=flags,
            t=argon2_t, m=argon2_m, p=argon2_p,
            filename=filename_meta
        )

        _validate_limits(
            k=k, r=r, shard_size=shard_size,
            argon2_time=argon2_t, argon2_mem_kib=argon2_m, argon2_par=argon2_p,
            num_blocks=num_blocks
        )

        G = _get_G(k, r)
        key = _derive_key(password, salt, argon2_t, argon2_m, argon2_p, keyfile)

        out_dir = os.path.dirname(os.path.abspath(output_file)) or "."
        tmp_name = None
        try:
            with open(processing_file, "rb") as f_in, tempfile.NamedTemporaryFile("wb", delete=False, dir=out_dir, prefix="tmp_enc_") as f_out:
                tmp_name = f_out.name

                f_out.write(start_header)

                if flags & HDR_FLAG_PWCHK:
                    nonce = _nonce12(nonce_base, 0xFFFFFFFF, 0xFFFFFFFF)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    cipher.update(prefix + PWCHK_MAGIC)
                    ct = cipher.encrypt(PWCHK_PLAINTEXT)
                    tag = cipher.digest()
                    crc = zlib.crc32(ct + tag) & 0xFFFFFFFF

                    f_out.write(PWCHK_MAGIC)
                    f_out.write(struct.pack(">" + "I" * CRC_COPIES, *([crc] * CRC_COPIES)))
                    f_out.write(ct)
                    f_out.write(tag)

                _progress(progress_cb, "encrypt", 0, num_blocks)

                for block_index in range(num_blocks):
                    # Check Pause
                    if control_event and not control_event.is_set():
                        control_event.wait()

                    chunk = f_in.read(block_size)
                    if len(chunk) < block_size:
                        chunk += b"\x00" * (block_size - len(chunk))

                    data = np.frombuffer(chunk, dtype=np.uint8).reshape(k, shard_size).copy()
                    coded = _fec_encode(data, G, k, r)

                    for shard_index in range(m):
                        shard_plain = coded[shard_index].tobytes()
                        nonce = _nonce12(nonce_base, block_index, shard_index)

                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        cipher.update(prefix + struct.pack(">II", block_index, shard_index))

                        ct = cipher.encrypt(shard_plain)
                        tag = cipher.digest()

                        crc = zlib.crc32(ct + tag) & 0xFFFFFFFF
                        f_out.write(struct.pack(">" + "I" * CRC_COPIES, *([crc] * CRC_COPIES)))
                        f_out.write(ct)
                        f_out.write(tag)

                    _progress(progress_cb, "encrypt", block_index + 1, num_blocks)

                f_out.write(trailer)

            # Atomic rename
            os.replace(tmp_name, output_file)
            tmp_name = None # Clear so finally doesn't delete it
        finally:
            if tmp_name and os.path.exists(tmp_name):
                os.remove(tmp_name)
        
    finally:
        if temp_compressed and os.path.exists(temp_compressed):
            os.remove(temp_compressed)


def decrypt_file_ex(input_file: str, output_file: str, password: str,
                    keyfile: bytes = None,
                    control_event: threading.Event = None,
                    progress_cb: Optional[ProgressCallback] = None) -> Tuple[bool, str, str, dict]:
    
    global LAST_DECRYPT_STATUS, LAST_DECRYPT_MESSAGE
    LAST_DECRYPT_STATUS, LAST_DECRYPT_MESSAGE = DECRYPT_OK, ""
    
    metadata = {}

    tmp_name = None
    try:
        file_total_size = os.path.getsize(input_file)

        with open(input_file, "rb") as f_in:
            start_hdr = _read_header_from_start(f_in)
            if start_hdr is not None:
                hdr, hdr_len, hdr_crc = start_hdr
            else:
                hdr_end = _read_header_from_end(f_in)
                if hdr_end is None:
                    raise HeaderInvalidError("Header not found.")
                hdr, hdr_len, hdr_crc = hdr_end

            params = _parse_header(hdr)
            metadata = {
                "filename": params.get("filename", ""),
                "k": params["k"],
                "r": params["r"],
                "version": params["version"],
                "flags": params["flags"]
            }
            
            # Validate version - support V1 (backward compat) and V2 (current)
            if params["version"] > VERSION:
                raise UnsupportedVersionError(f"Unsupported version {params['version']} (max {VERSION})")
            if params["version"] < 1:
                raise HeaderInvalidError(f"Invalid version {params['version']}")

            k = params["k"]
            r = params["r"]
            shard_size = params["shard_size"]
            m = k + r
            block_size = k * shard_size
            
            # Check compression flags
            comp_alg = None
            if params["flags"] & HDR_FLAG_COMPRESS_ZLIB:
                comp_alg = "zlib"
            elif params["flags"] & HDR_FLAG_COMPRESS_LZMA:
                comp_alg = "lzma"

            num_blocks = math.ceil(params["file_size"] / block_size) if params["file_size"] else 1

            _validate_limits(
                k=k, r=r, shard_size=shard_size,
                argon2_time=params["argon2_time"], argon2_mem_kib=params["argon2_mem_kib"], argon2_par=params["argon2_par"],
                num_blocks=num_blocks
            )

            prefix = MAGIC + struct.pack(">H", hdr_len) + hdr
            
            pwchk_present = (params["flags"] & HDR_FLAG_PWCHK) != 0
            header_size = 4 + 2 + hdr_len + 4
            data_offset = header_size

            key = _derive_key(
                password=password,
                salt=params["salt"],
                t=params["argon2_time"],
                mem_kib=params["argon2_mem_kib"],
                par=params["argon2_par"],
                keyfile=keyfile
            )
            
            # PW Check Block
            if pwchk_present:
                f_in.seek(data_offset)
                blob = f_in.read(PWCHK_RECORD_SIZE)
                if len(blob) != PWCHK_RECORD_SIZE:
                    raise TruncatedFileError(f"File truncated at password check record (expected {PWCHK_RECORD_SIZE} bytes, got {len(blob)})")
                off = 4 + (4*CRC_COPIES)
                ct = blob[off:off+PWCHK_PLAINTEXT_LEN]
                off += PWCHK_PLAINTEXT_LEN
                tag = blob[off:off+16]
                
                nonce = _nonce12(params["nonce_base"], 0xFFFFFFFF, 0xFFFFFFFF)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cipher.update(prefix + PWCHK_MAGIC)
                try:
                    pt = cipher.decrypt_and_verify(ct, tag)
                except ValueError:
                    raise WrongPasswordError("Wrong password or corrupted keyfile.")
                    
                data_offset += PWCHK_RECORD_SIZE

            G = _get_G(k, r)

            out_dir = os.path.dirname(os.path.abspath(output_file)) or "."
            tmp_name = None
            try:
                with tempfile.NamedTemporaryFile("wb", delete=False, dir=out_dir, prefix="tmp_dec_") as f_out:
                    tmp_name = f_out.name
                    
                    # Wrap f_out with decompressor if needed
                    writer = _decompression_stream(f_out, comp_alg)

                    f_in.seek(data_offset)
                    _progress(progress_cb, "decrypt", 0, num_blocks)

                    for block_index in range(num_blocks):
                        # Check Pause
                        if control_event and not control_event.is_set():
                            control_event.wait()

                        plain_shards = [None] * m
                        present = [False] * m

                        for shard_index in range(m):
                            crc_fields = f_in.read(4 * CRC_COPIES)
                            if not crc_fields: break  # Normal end of blocks
                            if len(crc_fields) != 4 * CRC_COPIES:
                                raise TruncatedFileError(f"File truncated at CRC fields (block {block_index}, shard {shard_index})")
                            crc_vals = list(struct.unpack(">" + "I" * CRC_COPIES, crc_fields))
                            
                            ct = f_in.read(shard_size)
                            if len(ct) != shard_size:
                                raise TruncatedFileError(f"File truncated at shard data (block {block_index}, shard {shard_index})")
                            tag = f_in.read(TAG_LEN)
                            if len(tag) != TAG_LEN:
                                raise TruncatedFileError(f"File truncated at authentication tag (block {block_index}, shard {shard_index})")
                            
                            crc_calc = zlib.crc32(ct + tag) & 0xFFFFFFFF
                            if crc_calc not in crc_vals: continue

                            nonce = _nonce12(params["nonce_base"], block_index, shard_index)
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            cipher.update(prefix + struct.pack(">II", block_index, shard_index))

                            try:
                                pt = cipher.decrypt_and_verify(ct, tag)
                                plain_shards[shard_index] = np.frombuffer(pt, dtype=np.uint8)
                                present[shard_index] = True
                            except ValueError:
                                continue

                        if all(present[:k]):
                            data_block = np.stack(plain_shards[:k], axis=0).astype(np.uint8)
                        else:
                            if sum(present) < k:
                                raise CorruptedDataError(f"Block {block_index} failed recovery (too many corrupted shards).")
                            data_block = _fec_decode(plain_shards, present, G, k, r)

                        byte_data = data_block.tobytes()
                        
                        # Handle padding
                        if block_index == num_blocks - 1:
                            valid_bytes = params["file_size"] - (block_index * block_size)
                            writer.write(byte_data[:valid_bytes])
                        else:
                            writer.write(byte_data)

                        _progress(progress_cb, "decrypt", block_index + 1, num_blocks)
                    
                    writer.close()

                # Atomic rename
                os.replace(tmp_name, output_file)
                tmp_name = None
            finally:
                if tmp_name and os.path.exists(tmp_name):
                    os.remove(tmp_name)

    except DecryptError as e:
        return False, e.code, e.message, metadata
    except Exception as e:
        return False, DECRYPT_UNKNOWN_ERROR, str(e), metadata

    return True, DECRYPT_OK, "OK", metadata


def decrypt_file(input_file: str, output_file: str, password: str, progress_cb=None):
    ok, _, _, _ = decrypt_file_ex(input_file, output_file, password, progress_cb=progress_cb)
    return ok
