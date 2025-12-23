import unittest
import os
import sys
import shutil
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core import encrypt_file, decrypt_file_ex

class TestLargeFiles(unittest.TestCase):
    """Smoke tests for large files - marked as slow"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.password = "LargeFileTest123!"
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_50mb_file(self):
        """Test 50MB file encryption/decryption - realistic scenario"""
        print("\n[SLOW TEST] Creating 50MB test file...")
        
        size_mb = 50
        input_path = os.path.join(self.test_dir, "large_50mb.bin")
        
        # Create 50MB file
        start = time.time()
        with open(input_path, "wb") as f:
            # Write in 1MB chunks for speed
            chunk = os.urandom(1024 * 1024)  # 1MB
            for _ in range(size_mb):
                f.write(chunk)
        create_time = time.time() - start
        print(f"  File created in {create_time:.2f}s")
        
        enc_path = input_path + ".ecf"
        dec_path = input_path + ".dec"
        
        # Encrypt
        print("  Encrypting...")
        start = time.time()
        encrypt_file(input_path, enc_path, self.password)
        enc_time = time.time() - start
        print(f"  Encrypted in {enc_time:.2f}s")
        
        # Decrypt
        print("  Decrypting...")
        start = time.time()
        ok, code, msg, meta = decrypt_file_ex(enc_path, dec_path, self.password)
        dec_time = time.time() - start
        print(f"  Decrypted in {dec_time:.2f}s")
        
        self.assertTrue(ok, f"Decryption failed: {msg}")
        
        # Verify size match
        orig_size = os.path.getsize(input_path)
        dec_size = os.path.getsize(dec_path)
        self.assertEqual(orig_size, dec_size, "Size mismatch after round-trip")
        
        # Verify content (sample-based for speed)
        print("  Verifying content (sampling)...")
        with open(input_path, "rb") as f_orig, open(dec_path, "rb") as f_dec:
            # Check first 1MB
            self.assertEqual(f_orig.read(1024*1024), f_dec.read(1024*1024))
            
            # Check middle 1MB
            mid = orig_size // 2
            f_orig.seek(mid)
            f_dec.seek(mid)
            self.assertEqual(f_orig.read(1024*1024), f_dec.read(1024*1024))
            
            # Check last 1MB
            f_orig.seek(-1024*1024, 2)
            f_dec.seek(-1024*1024, 2)
            self.assertEqual(f_orig.read(), f_dec.read())
        
        print(f"  ✅ 50MB test passed - Total time: {enc_time + dec_time:.2f}s")

if __name__ == '__main__':
    # Run with: python -m pytest tests/test_large_files.py -v -s
    unittest.main()
