import argparse
import sys
import os
import getpass
import tempfile
from .cipher import encrypt_file, decrypt_file_ex, get_keyfile_hash, read_metadata, verify_file_integrity
from .constants import PROFILES_SECURITY, PROFILES_INTEGRITY, HDR_FLAG_COMPRESS_ZLIB, HDR_FLAG_COMPRESS_LZMA, HDR_FLAG_TAR_CONTAINER
from .archive import _create_tar_from_folder, _tar_suffix

def main():
    parser = argparse.ArgumentParser(description="CryptoV2 CLI - Secure File Encryptor/Decryptor")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Encrypt (file)
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

    # Encrypt (folder)
    enc_folder = subparsers.add_parser("encrypt-folder", help="Encrypt a folder (auto TAR)")
    enc_folder.add_argument("input", help="Source folder")
    enc_folder.add_argument("output", help="Target .ecf file")
    enc_folder.add_argument("--password", "-p", help="Encryption password (will prompt if omitted)")
    enc_folder.add_argument("--keyfile", "-k", help="Path to optional keyfile")
    enc_folder.add_argument("--tar-compress", choices=["none", "gz", "bz2", "xz"], default="none",
                            help="Folder TAR compression")
    enc_folder.add_argument("--skip-special", action="store_true",
                            help="Skip symlinks/locked items when archiving")
    enc_folder.add_argument("--hide-filename", action="store_true", help="Do not store original filename")
    enc_folder.add_argument("--security", choices=PROFILES_SECURITY.keys(), default="Standard", 
                            help="Security profile (Argon2 params)")
    enc_folder.add_argument("--integrity", choices=PROFILES_INTEGRITY.keys(), default="Medium",
                            help="Integrity profile (ECC params)")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Source .ecf file")
    dec_parser.add_argument("output", help="Target output path")
    dec_parser.add_argument("--password", "-p", help="Decryption password (will prompt if omitted)")
    dec_parser.add_argument("--keyfile", "-k", help="Path to optional keyfile")

    # Info
    info_parser = subparsers.add_parser("info", help="Read encrypted file metadata")
    info_parser.add_argument("input", help="Source .ecf file")

    # Verify
    verify_parser = subparsers.add_parser("verify", help="Verify encrypted file integrity")
    verify_parser.add_argument("input", help="Source .ecf file")
    verify_parser.add_argument("--password", "-p", help="Decryption password (will prompt if omitted)")
    verify_parser.add_argument("--keyfile", "-k", help="Path to optional keyfile")

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
                kf_hash = get_keyfile_hash(args.keyfile)

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

        elif args.command == "encrypt-folder":
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
                kf_hash = get_keyfile_hash(args.keyfile)

            tmp_tar = None
            try:
                fd, tmp_tar = tempfile.mkstemp(suffix=_tar_suffix(args.tar_compress))
                os.close(fd)
                _create_tar_from_folder(args.input, tmp_tar, args.tar_compress, args.skip_special)

                base_name = os.path.basename(args.input) + _tar_suffix(args.tar_compress)
                original_name = "" if args.hide_filename else base_name

                print(f"Encrypting {args.input} -> {args.output} (TAR)...")
                encrypt_file(
                    tmp_tar, args.output, password,
                    keyfile_hash=kf_hash,
                    compress_alg=None,
                    original_filename=original_name,
                    k=int_p['k'], r=int_p['r'],
                    argon2_t=sec['t'], argon2_m=sec['m'], argon2_p=sec['p'],
                    is_tar_container=True
                )
                print("Encryption complete.")
            finally:
                if tmp_tar and os.path.exists(tmp_tar):
                    os.remove(tmp_tar)

        elif args.command == "decrypt":
            password = args.password
            if not password:
                password = getpass.getpass("Decryption Password: ")

            kf_hash = None
            if args.keyfile:
                kf_hash = get_keyfile_hash(args.keyfile)

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

        elif args.command == "info":
            meta = read_metadata(args.input)
            flags = meta.get("flags", 0)
            comp = "none"
            if flags & HDR_FLAG_COMPRESS_ZLIB:
                comp = "zlib"
            elif flags & HDR_FLAG_COMPRESS_LZMA:
                comp = "lzma"

            container = "tar" if (flags & HDR_FLAG_TAR_CONTAINER) else "none"

            print(f"Format Version: {meta.get('version')}")
            print(f"Plain Size:     {meta.get('plain_size')} bytes")
            print(f"Stored Size:    {meta.get('stored_size')} bytes")
            print(f"Integrity:      k={meta.get('k')}, r={meta.get('r')}, shard={meta.get('shard_size')} bytes")
            print(f"Security:       Argon2id (t={meta.get('argon2_time')}, m={meta.get('argon2_mem_kib')} KiB, p={meta.get('argon2_par')})")
            print(f"Compression:    {comp}")
            print(f"Container:      {container}")
            print(f"Filename:       {meta.get('filename') or '(Hidden)'}")

        elif args.command == "verify":
            password = args.password
            if not password:
                password = getpass.getpass("Decryption Password: ")

            kf_hash = None
            if args.keyfile:
                kf_hash = get_keyfile_hash(args.keyfile)

            print(f"Verifying {args.input}...")
            ok, code, msg, meta = verify_file_integrity(
                args.input, password,
                keyfile_hash=kf_hash
            )
            if ok:
                print("Verification OK.")
            else:
                print(f"ERROR [{code}]: {msg}", file=sys.stderr)
                sys.exit(1)

    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
