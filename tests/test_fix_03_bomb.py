import os
import pytest
import struct
import zlib
from crypto_core.cipher import decrypt_file_ex, encrypt_file
from crypto_core.header import _read_header_from_start, _parse_header, _pack_header
from crypto_core.constants import MAGIC

def test_decompression_bomb_limit(tmp_path):
    # Create a small encrypted file but with a malicious small plain_size in header
    input_file = tmp_path / "normal.txt"
    input_file.write_text("This is more than 5 bytes of data.")
    output_file = tmp_path / "bomb.ecf"
    
    # We'll manually craft a header with a small plain_size
    # but actual data is larger.
    # Actually, it's easier to just use encrypt_file and then Patch the header.
    encrypt_file(str(input_file), str(output_file), "password", compress_alg="zlib")
    
    # Read header
    with open(output_file, "r+b") as f:
        # We need to find where plain_size is.
        # Magic(4) + len(2) + Version(1) + Alg(1) + KDF(1) + CRC(1) + SaltLen(1) + Salt(16) + NonceBase(4) = 31 bytes offset
        f.seek(31)
        # Overwrite plain_size (u64) with 5
        f.write(struct.pack(">Q", 5))
        # Note: this breaks CRC, so we need to disable CRC check or fix it.
        # But wait, decrypt_file_ex checks CRC of the header.
        # Better: use _pack_header directly to build a "malicious" header then write it.
        pass

    # A better way: test that if the decompressor produces more than plain_size, it fails.
    # Let's mock a file that claims to be 10 bytes but decompresses to 100.
    
    # I'll just use a test that verifies the limit is enforced.
    from crypto_core.cipher import _decompression_stream
    from crypto_core.constants import DecryptError
    from io import BytesIO
    
    target = BytesIO()
    # Limit to 10 bytes
    writer = _decompression_stream(target, algorithm="zlib", limit=10)
    
    # Compressed data that expands to 20 bytes
    large_data = b"X" * 20
    comp = zlib.compress(large_data)
    
    with pytest.raises(DecryptError) as excinfo:
        writer.write(comp)
        writer.close()
    
    assert excinfo.value.code == "DECOMPRESSION_BOMB"
