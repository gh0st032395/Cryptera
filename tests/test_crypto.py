import unittest
import os
import sys
import shutil
import tempfile
import struct
import random

# Add parent dir to path so we can import crypto_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file_ex
from crypto_core.constants import *
from crypto_core.header import _read_header_from_start, _parse_header

class TestCryptoSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.password = "Secr3tP@ssw0rd!"
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_file(self, size):
        path = os.path.join(self.test_dir, f"input_{size}.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(size))
        return path

    def _verify_round_trip(self, input_path, password, cleanup=True, **kwargs):
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"
        
        encrypt_file(input_path, enc_path, password, **kwargs)
        
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, password)
        self.assertTrue(ok, f"Decryption failed: {msg}")
        
        with open(input_path, "rb") as fRef, open(dec_path, "rb") as fDec:
            self.assertEqual(fRef.read(), fDec.read(), "Decrypted content mismatch")
            
        if cleanup:
            if os.path.exists(enc_path): os.remove(enc_path)
            if os.path.exists(dec_path): os.remove(dec_path)
            
        return enc_path, dec_path, meta

    def test_round_trip_sizes(self):
        """Test encryption/decryption with various file sizes."""
        # Empty
        self._verify_round_trip(self._create_file(0), self.password)
        # Small
        self._verify_round_trip(self._create_file(100), self.password)
        # Exact block size multiple (assuming k=12, shard=4096 => 49152)
        # 49152 * 2 = 98304
        self._verify_round_trip(self._create_file(98304), self.password)
        # One byte over
        self._verify_round_trip(self._create_file(98305), self.password)

    def test_corruption_recovery(self):
        """Test Reed-Solomon error correction."""
        k, r, shard_size = 4, 2, 1024 # Min allowed is 1024
        input_path = self._create_file(k * shard_size * 2) # 2 blocks
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"

        encrypt_file(input_path, enc_path, self.password, k=k, r=r, shard_size=shard_size)

        # Size of one full block (data + parity) = (k+r) * shard_size
        block_len = (k+r) * shard_size
        
        # Corrupt 2 shards (r=2) in the first block
        # We need to skip the header. Header size is variable, so we read it.
        with open(enc_path, "rb") as f:
            hdr_parts = _read_header_from_start(f)
            # MAGIC(4) + LEN(2) + HDR + CRC(4) + PWCHK_RECORD
            start_offset = len(hdr_parts[0]) + 6 + 4 + PWCHK_RECORD_SIZE
        
        # Corrupt shard 0 and 1 (indexes 0 and 1)
        with open(enc_path, "r+b") as f:
            f.seek(start_offset)
            # Write garbage to first 2 shards
            f.write(b'X' * (shard_size * 2))

        # Decrypt should succeed
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertTrue(ok, f"Recovery failed with 2 corrupted shards (r=2): {msg}")
        
        # Verify content
        with open(input_path, "rb") as f1, open(dec_path, "rb") as f2:
            self.assertEqual(f1.read(), f2.read())
            
        # Corrupt 3 shards (r=2) -> Should fail
        with open(enc_path, "r+b") as f:
            f.seek(start_offset)
            f.write(b'Y' * (shard_size * 3))
            
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertFalse(ok, "Decryption succeeded with too many corrupted shards!")
        self.assertEqual(code, "CORRUPT_BEYOND_FEC")

    def test_header_modes(self):
        """Test header redundancy."""
        input_path = self._create_file(1024)
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"
        
        encrypt_file(input_path, enc_path, self.password)
        
        # 1. Kill Start Header
        with open(enc_path, "r+b") as f:
            f.seek(10) # Inside header
            f.write(b'\x00' * 50)
            
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertTrue(ok, f"Failed to recover from corrupt start header: {msg}")

        # 2. Kill Trailer too -> Fail
        with open(enc_path, "r+b") as f:
            f.seek(0, os.SEEK_END)
            # Just truncate trailer
            f.seek(f.tell() - 50) 
            f.write(b'\x00' * 50)
            
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertFalse(ok, "Should fail when both headers are corrupt")

    def test_passwords_and_flags(self):
        """Test correct/incorrect password and PWCHK flag."""
        input_path = self._create_file(50)
        enc_path, dec_path, _ = self._verify_round_trip(input_path, self.password, cleanup=False)
        
        # Wrong Password
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, "WrongPass")
        self.assertFalse(ok)
        self.assertEqual(code, "PASSWORD_INVALID")
        
        # No PWCHK record (Paranoid)
        encrypt_file(input_path, enc_path, self.password, enable_pwchk=False)
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertTrue(ok)
        
        # Wrong Pass with No PWCHK -> Fails at HMAC/MAC check usually or padding
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, "WrongPass")
        self.assertFalse(ok)
        # Code might be MAC_INVALID or generic, but result is Fail.

    def test_metadata_v2(self):
        """Verify filename metadata."""
        input_path = self._create_file(10)
        original_name = "secret_plans_v2.txt"
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"
        
        encrypt_file(input_path, enc_path, self.password, original_filename=original_name)
        
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertTrue(ok)
        self.assertEqual(meta.get("filename"), original_name)
    
    def test_truncated_file_detection(self):
        """Verify TRUNCATED error is returned for incomplete files."""
        input_path = self._create_file(5000)  # Small file
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"
        
        # Encrypt normally
        encrypt_file(input_path, enc_path, self.password, k=4, r=2, shard_size=1024)
        
        # Get original size
        original_size = os.path.getsize(enc_path)
        
        # Truncate file to 80% (cut mid-stream)
        truncated_size = int(original_size * 0.8)
        with open(enc_path, "r+b") as f:
            f.truncate(truncated_size)
        
        # Attempt decrypt - should get TRUNCATED error
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        self.assertFalse(ok, "Decryption should fail on truncated file")
        self.assertEqual(code, "TRUNCATED", f"Expected TRUNCATED error, got {code}")
        self.assertIn("truncated", msg.lower(), "Error message should mention truncation")
        
if __name__ == '__main__':
    unittest.main()
