import os
import pytest
from crypto_core.cipher import encrypt_file, decrypt_file_ex
from crypto_core.header import _read_header_from_start, _parse_header

def test_hide_filename(tmp_path):
    input_file = tmp_path / "secret_name.txt"
    input_file.write_text("Secret content")
    output_file = tmp_path / "protected.ecf"
    
    # Encrypt with hide-filename
    encrypt_file(str(input_file), str(output_file), "password", original_filename="")
    
    # Check header manually
    with open(output_file, "rb") as f:
        h = _read_header_from_start(f)
        params = _parse_header(h[0])
        assert params["filename"] == ""
        assert params["version"] == 3
        assert (params["flags"] & 0x10) == 0 # HDR_FLAG_HAS_FILENAME should be unset

def test_show_filename(tmp_path):
    input_file = tmp_path / "public_name.txt"
    input_file.write_text("Visible content")
    output_file = tmp_path / "public.ecf"
    
    # Encrypt without hide-filename (None = default to basename)
    encrypt_file(str(input_file), str(output_file), "password", original_filename=None)
    
    with open(output_file, "rb") as f:
        h = _read_header_from_start(f)
        params = _parse_header(h[0])
        assert params["filename"] == "public_name.txt"
        assert (params["flags"] & 0x10) != 0 # HDR_FLAG_HAS_FILENAME should be set
