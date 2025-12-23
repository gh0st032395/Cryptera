import os
import sys
import pytest
import tempfile
import shutil

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file_ex

def test_atomic_write_cleanup_on_error(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_text("Some data to encrypt")
    output_file = tmp_path / "output.ecf"
    
    # We want to trigger an error DURING encryption to see if tmp file is cleaned
    # We can do this by passing a control_event that we clear, and then we'll kill the thread? 
    # Or just mock the write to fail.
    # Actually, a simpler way is to use a non-existent compression algorithm or something that might fail mid-way.
    # But those are validated early.
    
    # Let's use a custom exception in a progress callback to abort.
    def abort_progress(stage, done, total):
        if stage == "encrypt" and done > 0:
            raise RuntimeError("Intentional Abort")
            
    try:
        encrypt_file(str(input_file), str(output_file), "password", progress_cb=abort_progress)
    except RuntimeError:
        pass
    
    # Verify output file does NOT exist
    assert not output_file.exists(), "Output file shouldn't exist after failure"
    
    # Also verify NO leftover temp files in the output directory
    leftovers = list(tmp_path.glob("tmp*")) + list(tmp_path.glob("comp_*"))
    # In some cases, tempfile might leave things if delete=False was used.
    # We need to ensure encrypt_file cleans these up.
    assert len(leftovers) == 0, f"Leftover temp files found: {leftovers}"

def test_header_fallback_to_trailer(tmp_path):
    input_file = tmp_path / "input.txt"
    data = "Secret Data for Fallback Test"
    input_file.write_text(data)
    enc_file = tmp_path / "input.ecf"
    dec_file = tmp_path / "output.txt"
    
    encrypt_file(str(input_file), str(enc_file), "password")
    
    # Corrupt the start header (first few bytes after MAGIC)
    with open(enc_file, "r+b") as f:
        f.seek(4) # Skip MAGIC
        f.write(b"\xFF\xFF") # Corrupt length
        
    # Decrypt should still work because of the trailer
    ok, code, msg, meta = decrypt_file_ex(str(enc_file), str(dec_file), "password")
    assert ok is True, f"Decryption failed even with valid trailer: {msg}"
    assert dec_file.read_text() == data

def test_header_both_corrupt_fails(tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_text("data")
    enc_file = tmp_path / "input.ecf"
    dec_file = tmp_path / "output.txt"
    
    encrypt_file(str(input_file), str(enc_file), "password")
    
    # Corrupt start header
    with open(enc_file, "r+b") as f:
        f.seek(4)
        f.write(b"\xFF\xFF")
        
        # Corrupt trailer (near end)
        f.seek(0, os.SEEK_END)
        f.seek(f.tell() - 10)
        f.write(b"\x00" * 10)
        
    ok, code, msg, meta = decrypt_file_ex(str(enc_file), str(dec_file), "password")
    assert ok is False
    assert code == "HEADER_INVALID"

if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        # test_header_fallback_to_trailer(p)
        # test_header_both_corrupt_fails(p)
        test_atomic_write_cleanup_on_error(p)
        print("Tests passed locally")
