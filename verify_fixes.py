import os
import shutil
import hashlib
import unittest
import tempfile
import struct
from crypto_core import encrypt_file, decrypt_file_ex
from crypto_core.constants import *
from crypto_core.header import _read_header_from_start, _parse_header

class TestCryptoCore(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.input_file = os.path.join(self.test_dir, "test_input.bin")
        self.output_file = os.path.join(self.test_dir, "test_output.ecf")
        self.decrypted_file = os.path.join(self.test_dir, "test_decrypted.bin")
        self.password = "secure_password_123"
        
        # Create random input file (1MB)
        with open(self.input_file, "wb") as f:
            f.write(os.urandom(1024 * 1024))
            
        self.input_hash = self._get_hash(self.input_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _get_hash(self, filepath):
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def test_basic_flow(self):
        """Test basic encryption and decryption."""
        print("\n[TEST] Basic Flow")
        encrypt_file(self.input_file, self.output_file, self.password)
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password)
        
        self.assertTrue(ok, f"Decryption failed: {msg}")
        self.assertEqual(self.input_hash, self._get_hash(self.decrypted_file))
        print(" -> OK")

    def test_advanced_params_persistence(self):
        """Test that custom Argon2 and ECC params are stored in header and used."""
        print("\n[TEST] Advanced Params Persistence")
        
        # Custom params (Profile: Strong/Paranoid mimic)
        custom_t = 4
        custom_m = 128 * 1024
        custom_p = 4
        custom_k = 20
        custom_r = 4
        
        encrypt_file(
            self.input_file, self.output_file, self.password,
            argon2_t=custom_t, argon2_m=custom_m, argon2_p=custom_p,
            k=custom_k, r=custom_r
        )
        
        # Check Header
        with open(self.output_file, "rb") as f:
            hdr_parts = _read_header_from_start(f)
            self.assertIsNotNone(hdr_parts)
            hdr, _, _ = hdr_parts
            params = _parse_header(hdr)
            
        # Verify params in header
        self.assertEqual(params['argon2_time'], custom_t)
        self.assertEqual(params['argon2_mem_kib'], custom_m)
        self.assertEqual(params['argon2_par'], custom_p)
        self.assertEqual(params['k'], custom_k)
        self.assertEqual(params['r'], custom_r)
        
        # Verify Decryption works automatically
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password)
        self.assertTrue(ok, f"Decryption failed with custom params: {msg}")
        self.assertEqual(self.input_hash, self._get_hash(self.decrypted_file))
        print(" -> OK")

    def test_compression_and_keyfile(self):
        """Test compression (zlib) and Keyfile HMAC-SHA256 construction."""
        print("\n[TEST] Compression + Keyfile")
        keyfile_data = b"my_secret_keyfile_content"
        
        encrypt_file(
            self.input_file, self.output_file, self.password,
            compress_alg="zlib",
            keyfile=keyfile_data
        )
        
        # Verify Header Flag
        with open(self.output_file, "rb") as f:
            hdr_parts = _read_header_from_start(f)
            params = _parse_header(hdr_parts[0])
            self.assertTrue(params['flags'] & HDR_FLAG_COMPRESS_ZLIB, "ZLIB flag not set")

        # 1. Decrypt with correct keyfile
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password, keyfile=keyfile_data)
        self.assertTrue(ok, f"Decryption failed (Correct Keyfile): {msg}")
        self.assertEqual(self.input_hash, self._get_hash(self.decrypted_file))

        # 2. Decrypt with WRONG keyfile
        wrong_kf = b"wrong_keyfile"
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password, keyfile=wrong_kf)
        self.assertFalse(ok, "Decryption should fail with wrong keyfile")
        print(" -> OK")

    def test_pwchk_flag_logic(self):
        """Test that disabling PWCHK prevents the record from being written/checked."""
        print("\n[TEST] PWCHK Flag Logic")
        
        # Encrypt with PWCHK DISABLED
        encrypt_file(self.input_file, self.output_file, self.password, enable_pwchk=False)
        
        with open(self.output_file, "rb") as f:
            hdr_parts = _read_header_from_start(f)
            params = _parse_header(hdr_parts[0])
            self.assertFalse(params['flags'] & HDR_FLAG_PWCHK, "PWCHK flag shouldn't be set")
            
        # Decrypt should still work (via trial and error on MAC/Padding usually, 
        # but here the function handles it gracefully by checking flag)
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password)
        self.assertTrue(ok, "Decryption should succeed even without PWCHK record")
        print(" -> OK")
        
    def test_header_integrity(self):
        """Test Header Redundancy and Failure."""
        print("\n[TEST] Header Integrity")
        encrypt_file(self.input_file, self.output_file, self.password)
        
        # 1. Corrupt Start Header (K offset)
        with open(self.output_file, "r+b") as f:
            f.seek(6 + 37) 
            f.write(struct.pack(">H", 9999))
            
        # Decrypt should SUCCEED via Trailer (Redundancy)
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password)
        self.assertTrue(ok, "Redundancy failed! Trailer should have been used.")
        print(" -> Redundancy OK (Start corrupt -> Trailer used)")
        
        # 2. Corrupt Trailer as well
        with open(self.output_file, "r+b") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # Trailer location: size - 4 - 2 - 4 - hdr_len - ...
            # Easier: Just truncate the file to kill the trailer
            f.seek(size - 100)
            f.write(b"\x00" * 100)
            
        ok, code, msg, meta = decrypt_file_ex(self.output_file, self.decrypted_file, self.password)
        self.assertFalse(ok, "Decryption succeeded with BOTH headers corrupted!")
        print(" -> Failure OK (Both corrupt -> Failed)")

    def test_fec_thresholds(self):
        """Test FEC recovery: <= r is OK, > r fails (AG-006)."""
        print("\n[TEST] FEC Thresholds")
        k, r = 24, 8
        shard_size = 1024
        encrypt_file(self.input_file, self.output_file, self.password, k=k, r=r, shard_size=shard_size)
        
        # Calculate offsets
        # Header (6 + 37 + filename len) + PWCHK (Optional)
        # Simplified: scan for magic
        with open(self.output_file, "rb") as f:
            ecf_data = bytearray(f.read())
            
        m = k + r
        # Find start of block 0. It follows the start header and optional PWCHK.
        # We know k=24, r=8, shard_size=1024.
        # Header version 3 is roughly 52-60 bytes + filename.
        # PWCHK is 52 + 16 bytes = 68 bytes.
        
        # Let's find first FEC block by looking for a pattern or just using the header length
        params = _parse_header(_read_header_from_start(open(self.output_file, "rb"))[0])
        header_len = _read_header_from_start(open(self.output_file, "rb"))[1]
        data_offset = 4 + 2 + header_len + 4 # Magic + len + hdr + crc
        if params['flags'] & HDR_FLAG_PWCHK:
            data_offset += PWCHK_RECORD_SIZE
            
        shard_total_len = CRC_BLOCK_SIZE + shard_size + TAG_LEN # 4*CRC_COPIES + 1024 + 16
        
        # 1. Corrupt exactly r shards in block 0
        tmp_ecf = self.output_file + ".tmp"
        corrupted_data = bytearray(ecf_data)
        for i in range(r):
            pos = data_offset + (i * shard_total_len) + (4 * CRC_COPIES) # corrupt data start
            corrupted_data[pos] ^= 0xFF 
            
        with open(tmp_ecf, "wb") as f:
            f.write(corrupted_data)
            
        ok, code, msg, meta = decrypt_file_ex(tmp_ecf, self.decrypted_file, self.password)
        self.assertTrue(ok, f"FEC failed to recover {r} shards: {msg}")
        self.assertEqual(self.input_hash, self._get_hash(self.decrypted_file))
        print(f" -> Recovered {r} shards OK")
        
        # 2. Corrupt r + 1 shards
        corrupted_data[data_offset + (r * shard_total_len) + (4 * CRC_COPIES)] ^= 0xFF
        with open(tmp_ecf, "wb") as f:
            f.write(corrupted_data)
            
        ok, code, msg, meta = decrypt_file_ex(tmp_ecf, self.decrypted_file, self.password)
        self.assertFalse(ok, "FEC should HAVE FAILED to recover r+1 shards")
        self.assertEqual(code, "CORRUPT_BEYOND_FEC")
        print(" -> Failure with r+1 shards OK")

if __name__ == "__main__":
    unittest.main()
