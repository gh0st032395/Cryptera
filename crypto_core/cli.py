import argparse
import sys
import os
from .cipher import encrypt_file, decrypt_file_ex
from .constants import PROFILES_SECURITY, PROFILES_INTEGRITY

def main():
    parser = argparse.ArgumentParser(description="CryptoV2 CLI - Secure File Encryptor/Decryptor")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Source file")
    enc_parser.add_argument("output", help="Target .ecf file")
    enc_parser.add_argument("--password", "-p", required=True, help="Encryption password")
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
    dec_parser.add_argument("--password", "-p", required=True, help="Decryption password")
    dec_parser.add_argument("--keyfile", "-k", help="Path to optional keyfile")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "encrypt":
            sec = PROFILES_SECURITY[args.security]
            int_p = PROFILES_INTEGRITY[args.integrity]
            
            keyfile_data = None
            if args.keyfile:
                with open(args.keyfile, "rb") as f:
                    keyfile_data = f.read()

            print(f"Encrypting {args.input} -> {args.output}...")
            encrypt_file(
                args.input, args.output, args.password,
                keyfile=keyfile_data,
                compress_alg=args.compress,
                original_filename="" if args.hide_filename else None,
                k=int_p['k'], r=int_p['r'],
                argon2_t=sec['t'], argon2_m=sec['m'], argon2_p=sec['p']
            )
            print("Encryption complete.")

        elif args.command == "decrypt":
            keyfile_data = None
            if args.keyfile:
                with open(args.keyfile, "rb") as f:
                    keyfile_data = f.read()

            print(f"Decrypting {args.input} -> {args.output}...")
            ok, code, msg, meta = decrypt_file_ex(
                args.input, args.output, args.password,
                keyfile=keyfile_data
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
