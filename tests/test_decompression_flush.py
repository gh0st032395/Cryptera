import os
import sys
import zlib
import pytest

# Add parent dir to path so we can import crypto_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file

def test_decompress_flush_regression(tmp_path):
    # Create a dummy file with specific size to stress chunking
    # 1MB of random-ish data that is compressible
    input_file = tmp_path / "input.bin"
    data = b"STRESSING_DECOMPRESSION" * 50000 
    input_file.write_bytes(data)
    
    enc_file = tmp_path / "input.ecf"
    dec_file = tmp_path / "output.bin"
    password = "password123"
    
    # Encrypt with zlib compression
    encrypt_file(
        str(input_file), 
        str(enc_file), 
        password, 
        compress_alg="zlib",
        shard_size=1024, # Smaller shard size
        k=2, r=1
    )
    
    # Decrypt
    assert decrypt_file(str(enc_file), str(dec_file), password) is True
    
    # Verify
    decrypted_data = dec_file.read_bytes()
    assert len(decrypted_data) == len(data), f"ZLIB length mismatch: {len(decrypted_data)} != {len(data)}"
    assert decrypted_data == data, "ZLIB data mismatch"

    # Encrypt with lzma compression
    encrypt_file(
        str(input_file), 
        str(enc_file), 
        password, 
        compress_alg="lzma",
        shard_size=1024,
        k=2, r=1
    )
    
    # Decrypt
    assert decrypt_file(str(enc_file), str(dec_file), password) is True
    
    # Verify
    decrypted_data = dec_file.read_bytes()
    assert len(decrypted_data) == len(data), f"LZMA length mismatch: {len(decrypted_data)} != {len(data)}"
    assert decrypted_data == data, "LZMA data mismatch"

if __name__ == "__main__":
    # Manual run if needed
    import shutil
    tmp = "./tmp_test"
    if os.path.exists(tmp): shutil.rmtree(tmp)
    os.makedirs(tmp)
    from pathlib import Path
    test_decompress_flush_regression(Path(tmp))
    print("Test passed!")
