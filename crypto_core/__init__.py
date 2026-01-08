try:
    from crypto_core_rs import (
        encrypt_file,
        decrypt_file,
        decrypt_file_ex,
        get_keyfile_hash,
        read_metadata,
        verify_file_integrity,
    )
except Exception:
    from .cipher import (
        encrypt_file,
        decrypt_file,
        decrypt_file_ex,
        get_keyfile_hash,
        read_metadata,
        verify_file_integrity,
    )
