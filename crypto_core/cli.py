import argparse
import sys
import os
import getpass
import hashlib
from .cipher import encrypt_file, decrypt_file_ex
from .constants import PROFILES_SECURITY, PROFILES_INTEGRITY

def _get_keyfile_hash(path):
    """Compute SHA-256 of keyfile in a streaming fashion (AG-002)"""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    return sha.digest()

def main():
    parser = argparse.ArgumentParser(description="CryptoV2 CLI - Secure File Encryptor/Decryptor")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Source file")
    enc_parser.add_argument("output", help="Target .ecf file")
    enc_parser.add_argument("--password", "-p", help="Encryption password (will prompt if omitted)")
    enc_parser.add_argument("--keyfile", "-k", help="Path to optional keyfile")
    enc_parser.add_argument("--compress", "-c", choices=["zlib", "lzma"], help="Compression algorithm")
    enc_parser.add_argument("--hide-filename", action="store_true", help="Do not store original filename")
    enc_parser.add_argument("--security", choices=PROFILES_SECURITY.keys(), default="Standard", 
                            help="Security profile (Argon2 params)")
    enc_parser.add_argument("--integrity", choices=PROFILES_INTEGRITY.keys(), default="Medium",
                            help="Integrity profile (ECC params)")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Source .ecf file")
    dec_parser.add_argument("output", help="Target output path")
    dec_parser.add_argument("--password", "-p", help="Decryption password (will prompt if omitted)")
    dec_parser.add_argument("--keyfile", "-k", help="Path to optional keyfile")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "encrypt":
            password = args.password
            if not password:
                password = getpass.getpass("Encryption Password: ")
                if not password:
                    print("Error: Password cannot be empty.", file=sys.stderr)
                    sys.exit(1)

            sec = PROFILES_SECURITY[args.security]
            int_p = PROFILES_INTEGRITY[args.integrity]
            
            kf_hash = None
            if args.keyfile:
                kf_hash = _get_keyfile_hash(args.keyfile)

            print(f"Encrypting {args.input} -> {args.output}...")
            encrypt_file(
                args.input, args.output, password,
                keyfile_hash=kf_hash,
                compress_alg=args.compress,
                original_filename="" if args.hide_filename else None,
                k=int_p['k'], r=int_p['r'],
                argon2_t=sec['t'], argon2_m=sec['m'], argon2_p=sec['p']
            )
            print("Encryption complete.")

        elif args.command == "decrypt":
            password = args.password
            if not password:
                password = getpass.getpass("Decryption Password: ")

            kf_hash = None
            if args.keyfile:
                kf_hash = _get_keyfile_hash(args.keyfile)

            print(f"Decrypting {args.input} -> {args.output}...")
            ok, code, msg, meta = decrypt_file_ex(
                args.input, args.output, password,
                keyfile_hash=kf_hash
            )
            
            if ok:
                print(f"Decryption complete. Original filename: {meta.get('filename', 'Unknown')}")
            else:
                print(f"ERROR [{code}]: {msg}", file=sys.stderr)
                sys.exit(1)

    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
