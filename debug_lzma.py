import sys
import os
sys.path.insert(0, os.path.abspath("."))
from crypto_core import encrypt_file, decrypt_file_ex
from pathlib import Path
import shutil

tmp = Path("./tmp_debug")
if tmp.exists(): shutil.rmtree(tmp)
tmp.mkdir()

input_file = tmp / "input.bin"
data = b"STRESSING_DECOMPRESSION" * 50000 
input_file.write_bytes(data)

enc_file = tmp / "input.ecf"
dec_file = tmp / "output.bin"
password = "password123"

print("Starting LZMA test...")
encrypt_file(
    str(input_file), 
    str(enc_file), 
    password, 
    compress_alg="lzma",
    shard_size=1024,
    k=2, r=1
)

ok, code, msg, meta = decrypt_file_ex(str(enc_file), str(dec_file), password)
print(f"Result: {ok}, Code: {code}, Msg: {msg}")

if ok:
    dec_data = dec_file.read_bytes()
    print(f"Length match: {len(dec_data) == len(data)}")
    print(f"Data match: {dec_data == data}")
else:
    import traceback
    # Traceback is not available since we caught it, but we have msg.
    pass
