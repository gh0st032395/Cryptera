import subprocess
import sys
import os
import pytest

def test_cli_roundtrip(tmp_path):
    input_file = tmp_path / "cli_test.txt"
    input_file.write_text("CLI encryption works!")
    enc_file = tmp_path / "cli_test.ecf"
    dec_file = tmp_path / "cli_test.dec"
    
    # Encrypt
    res = subprocess.run([
        sys.executable, "-m", "crypto_core", 
        "encrypt", str(input_file), str(enc_file), 
        "--password", "cli_pass", "--compress", "zlib"
    ], capture_output=True, text=True)
    
    assert res.returncode == 0
    assert os.path.exists(enc_file)
    
    # Decrypt
    res = subprocess.run([
        sys.executable, "-m", "crypto_core", 
        "decrypt", str(enc_file), str(dec_file), 
        "--password", "cli_pass"
    ], capture_output=True, text=True)
    
    assert res.returncode == 0
    assert dec_file.read_text() == "CLI encryption works!"

def test_cli_wrong_password(tmp_path):
    input_file = tmp_path / "secret.txt"
    input_file.write_text("Secret")
    enc_file = tmp_path / "secret.ecf"
    dec_file = tmp_path / "secret.dec"
    
    subprocess.run([
        sys.executable, "-m", "crypto_core", 
        "encrypt", str(input_file), str(enc_file), 
        "--password", "correct"
    ])
    
    res = subprocess.run([
        sys.executable, "-m", "crypto_core", 
        "decrypt", str(enc_file), str(dec_file), 
        "--password", "wrong"
    ], capture_output=True, text=True)
    
    assert res.returncode != 0
    assert "PASSWORD_INVALID" in res.stderr
