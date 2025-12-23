import os
import sys
import pytest
import struct

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.header import _nonce12
from crypto_core.cipher import _validate_limits
from crypto_core.constants import MAX_BLOCKS_U32, LimitsExceededError

def test_nonce_uniqueness():
    nonce_base = 0x12345678
    seen = set()
    
    # Test a sample of indices
    # We can't test 2^32 * 255 nonces, but we can test boundaries
    test_indices = [
        (0, 0), (0, 1), (1, 0), (1, 1),
        (MAX_BLOCKS_U32 - 1, 0), (MAX_BLOCKS_U32 - 1, 254),
        (0x7FFFFFFF, 128),
        # PWCHK nonce
        (0xFFFFFFFF, 0xFFFFFFFF)
    ]
    
    for b, s in test_indices:
        nonce = _nonce12(nonce_base, b, s)
        assert len(nonce) == 12
        assert nonce not in seen, f"Duplicate nonce found for block={b}, shard={s}"
        seen.add(nonce)

def test_nonce_overflow_behavior():
    # Verify that _validate_limits raises LimitsExceededError for overflow
    # num_blocks must be < 2**32
    
    # Valid
    _validate_limits(k=24, r=8, shard_size=1024, argon2_time=3, argon2_mem_kib=65536, argon2_par=2, num_blocks=MAX_BLOCKS_U32 - 1)
    
    # Invalid (exactly at limit)
    with pytest.raises(LimitsExceededError) as exc:
        _validate_limits(k=24, r=8, shard_size=1024, argon2_time=3, argon2_mem_kib=65536, argon2_par=2, num_blocks=MAX_BLOCKS_U32)
    assert "num_blocks out of limits" in str(exc.value)

    # Invalid (way over)
    with pytest.raises(LimitsExceededError):
         _validate_limits(k=24, r=8, shard_size=1024, argon2_time=3, argon2_mem_kib=65536, argon2_par=2, num_blocks=MAX_BLOCKS_U32 + 100)

if __name__ == "__main__":
    test_nonce_uniqueness()
    # test_nonce_overflow_behavior()
    print("Nonce tests passed")
