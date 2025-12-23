import os
import sys
import pytest
import struct
import random
import numpy as np

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file_ex
from crypto_core.constants import PWCHK_RECORD_SIZE

def corrupt_file_at_shards(file_path, header_size, block_idx, shard_indices, shard_size, m):
    # m = k + r
    # Each shard has 4*CRC_COPIES + shard_size + 16 bytes
    from crypto_core.constants import CRC_COPIES, TAG_LEN
    shard_record_size = (4 * CRC_COPIES) + shard_size + TAG_LEN
    block_size_on_disk = m * shard_record_size
    
    with open(file_path, "r+b") as f:
        for s_idx in shard_indices:
            offset = header_size + (block_idx * block_size_on_disk) + (s_idx * shard_record_size)
            f.seek(offset)
            # Corrupt CRC and Data
            f.write(b"\xFF" * (4 * CRC_COPIES + shard_size))

def test_fec_thresholds(tmp_path):
    # Use fixed parameters for deterministic testing
    k, r, shard_size = 4, 2, 1024
    m = k + r
    input_file = tmp_path / "input.bin"
    # 2 blocks of data
    data = os.urandom(k * shard_size * 2)
    input_file.write_bytes(data)
    
    password = "password"
    enc_file = tmp_path / "test.ecf"
    dec_file = tmp_path / "test.dec"
    
    encrypt_file(str(input_file), str(enc_file), password, k=k, r=r, shard_size=shard_size)
    
    # Get header size
    with open(enc_file, "rb") as f:
        # MAGIC(4) + LEN(2) + HDR + CRC(4)
        f.read(4)
        h_len = struct.unpack(">H", f.read(2))[0]
        header_size = 4 + 2 + h_len + 4 + PWCHK_RECORD_SIZE
        
    # Case 1: Corrupt exactly r shards (2 shards) in the second block (idx 1)
    # Should recover
    shards_to_corrupt = [0, 1]
    corrupt_file_at_shards(enc_file, header_size, 1, shards_to_corrupt, shard_size, m)
    
    ok, code, msg, meta = decrypt_file_ex(str(enc_file), str(dec_file), password)
    assert ok is True, f"Recovery failed with {r} corrupted shards: {msg}"
    assert dec_file.read_bytes() == data
    
    # Case 2: Corrupt r+1 shards (3 shards) in the first block (idx 0)
    # Should FAIL
    shards_to_corrupt = [2, 3, 4]
    corrupt_file_at_shards(enc_file, header_size, 0, shards_to_corrupt, shard_size, m)
    
    ok, code, msg, meta = decrypt_file_ex(str(enc_file), str(dec_file), password)
    assert ok is False
    assert code == "CORRUPT_BEYOND_FEC"
    assert "Block 0 failed" in msg

if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        test_fec_thresholds(Path(tmp))
        print("FEC Threshold tests passed")
