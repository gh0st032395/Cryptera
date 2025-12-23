import os
import pytest
from crypto_core.cipher import encrypt_file
from crypto_core.header import _read_header_from_start, _parse_header

def test_sizes_with_compression(tmp_path):
    # Create a highly compressible file
    content = b"A" * 100000
    input_file = tmp_path / "large.bin"
    input_file.write_bytes(content)
    output_file = tmp_path / "compressed.ecf"
    
    encrypt_file(str(input_file), str(output_file), "password", compress_alg="zlib")
    
    with open(output_file, "rb") as f:
        h = _read_header_from_start(f)
        params = _parse_header(h[0])
        
        assert params["plain_size"] == 100000
        # Stored size should be much smaller
        assert params["stored_size"] < 10000 
        assert params["stored_size"] > 0

def test_sizes_without_compression(tmp_path):
    content = b"Hello World"
    input_file = tmp_path / "small.txt"
    input_file.write_bytes(content)
    output_file = tmp_path / "raw.ecf"
    
    encrypt_file(str(input_file), str(output_file), "password")
    
    with open(output_file, "rb") as f:
        h = _read_header_from_start(f)
        params = _parse_header(h[0])
        
        assert params["plain_size"] == len(content)
        assert params["stored_size"] == len(content)
