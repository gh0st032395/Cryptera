import unittest
import os
import sys
import shutil
import tempfile
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file_ex
from crypto_core.constants import DECRYPT_HEADER_INVALID

class TestHeaderFuzzing(unittest.TestCase):
    """Fuzzing tests for header parsing robustness"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.password = "FuzzTest123!"
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_random_header_bytes(self):
        """Test that random header bytes don't crash, return clean error"""
        test_file = os.path.join(self.test_dir, "fuzz_random.ecf")
        dec_path = os.path.join(self.test_dir, "output.dec")
        
        # Create file with completely random bytes
        with open(test_file, "wb") as f:
            # Random header-like size (typical encrypted file might be 1KB-1MB)
            size = random.randint(1024, 10240)
            f.write(os.urandom(size))
        
        # Attempt decrypt - should not crash
        try:
            ok, code, msg, meta = decrypt_file_ex(test_file, dec_path, self.password)
            self.assertFalse(ok, "Random bytes should not decrypt successfully")
            # Expected error: HEADER_INVALID or similar
            self.assertIn(code, ["HEADER_INVALID", "IO_ERROR", "TRUNCATED", "UNKNOWN_ERROR"],
                         f"Unexpected error code: {code}")
        except Exception as e:
            # Even exceptions should be controlled (DecryptError, not random crashes)
            self.fail(f"Fuzzing caused unhandled exception: {type(e).__name__}: {str(e)}")
    
    def test_valid_magic_corrupted_header(self):
        """Test file with valid magic but corrupted header data"""
        input_path = os.path.join(self.test_dir, "input.bin")
        with open(input_path, "wb") as f:
            f.write(b"Test data for fuzzing")
        
        enc_path = input_path + ".ecf"
        fuzz_path = os.path.join(self.test_dir, "fuzz_magic.ecf")
        
        # Create valid encrypted file
        encrypt_file(input_path, enc_path, self.password, k=4, r=2, shard_size=1024)
        
        # Copy and corrupt header (keep magic, corrupt rest)
        with open(enc_path, "rb") as f:
            data = bytearray(f.read())
        
        # Keep magic (first 4 bytes) but randomize bytes 4-100
        data[4:100] = os.urandom(96)
        
        with open(fuzz_path, "wb") as f:
            f.write(data)
        
        # Attempt decrypt
        dec_path = os.path.join(self.test_dir, "output.dec")
        try:
            ok, code, msg, meta = decrypt_file_ex(fuzz_path, dec_path, self.password)
            self.assertFalse(ok, "Corrupted header should fail validation")
            # Should detect header corruption
            self.assertIn(code, ["HEADER_INVALID", "PASSWORD_INVALID", "TRUNCATED"],
                         f"Expected header error, got: {code}")
        except Exception as e:
            self.fail(f"Corrupted header caused crash: {type(e).__name__}: {str(e)}")
    
    def test_truncated_at_various_points(self):
        """Test file truncated at different offsets"""
        input_path = os.path.join(self.test_dir, "input.bin")
        with open(input_path, "wb") as f:
            f.write(os.urandom(5000))
        
        enc_path = input_path + ".ecf"
        encrypt_file(input_path, enc_path, self.password, k=4, r=2, shard_size=1024)
        
        orig_size = os.path.getsize(enc_path)
        
        # Test truncation at 10%, 25%, 50%, 75%, 90%
        for pct in [0.1, 0.25, 0.5, 0.75, 0.9]:
            with self.subTest(percent=pct):
                fuzz_path = os.path.join(self.test_dir, f"fuzz_{int(pct*100)}pct.ecf")
                
                # Copy and truncate
                with open(enc_path, "rb") as f_in, open(fuzz_path, "wb") as f_out:
                    truncate_at = int(orig_size * pct)
                    f_out.write(f_in.read(truncate_at))
                
                # Attempt decrypt
                dec_path = os.path.join(self.test_dir, f"output_{int(pct*100)}.dec")
                try:
                    ok, code, msg, meta = decrypt_file_ex(fuzz_path, dec_path, self.password)
                    self.assertFalse(ok, f"Truncated file at {pct*100}% should not decrypt")
                    # Should preferably return TRUNCATED
                    if pct >= 0.5:  # Likely to hit data section
                        self.assertIn(code, ["TRUNCATED", "CORRUPT_BEYOND_FEC", "HEADER_INVALID"],
                                     f"At {pct*100}%, expected reasonable error, got: {code}")
                except Exception as e:
                    # Acceptable if it's a controlled DecryptError
                    if "DecryptError" not in str(type(e)):
                        self.fail(f"Truncated at {pct*100}% caused unhandled exception: {e}")

if __name__ == '__main__':
    # Run with: python -m pytest tests/test_fuzzing.py -v
    unittest.main()
