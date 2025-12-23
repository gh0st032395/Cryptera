import os
import pytest
from crypto_core.cipher import encrypt_file, decrypt_file_ex

def test_truncated_blocks(tmp_path):
    input_file = tmp_path / "big.txt"
    input_file.write_text("Hello " * 1000)
    output_file = tmp_path / "big.ecf"
    
    encrypt_file(str(input_file), str(output_file), "password", k=2, r=1, shard_size=1024)
    
    # Truncate the file (remove last 1000 bytes)
    size = os.path.getsize(output_file)
    with open(output_file, "r+b") as f:
        f.truncate(size - 1000)
    
    # Try to decrypt
    dec_file = tmp_path / "big.dec"
    ok, code, msg, meta = decrypt_file_ex(str(output_file), str(dec_file), "password")
    
    assert not ok
    assert code == "TRUNCATED"
