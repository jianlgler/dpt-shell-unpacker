import sys
import os
import re
from Crypto.Cipher import AES

# Default key for the reference sample: DPT_UNKNOWN_DATA from the native lib's .data.
# Pass --key <hex> (e.g. from extract_key.py) for any other sample.
AES_KEY = bytes.fromhex("YOUR-KEY-HERE-OTHERWISE-THE-TOOL-WILL-EXTRACT-IT-AUTOMATICALLY")

def iv_of(key):
    # The IV is the key with the 4th and 10th bytes patched by the C code
    iv = bytearray(key)
    iv[3], iv[9] = 0x2f, 0x76
    return bytes(iv)

AES_IV = iv_of(AES_KEY)

def unpad(data):
    # Standard PKCS7 unpadding
    padding_len = data[-1]
    return data[:-padding_len]

def main():
    global AES_KEY, AES_IV
    argv = sys.argv[1:]
    if '--key' in argv:
        i = argv.index('--key')
        try:
            AES_KEY = bytes.fromhex(argv[i + 1])
            assert len(AES_KEY) == 16
        except (IndexError, ValueError, AssertionError):
            print("[!] --key needs 16 bytes as hex (32 hex digits)")
            sys.exit(1)
        AES_IV = iv_of(AES_KEY)
        del argv[i:i + 2]
    if len(argv) < 1:
        print(f"Usage: python3 {sys.argv[0]} <path_to_d_shell_data_001> [--key <hex>]")
        sys.exit(1)

    file_path = argv[0]
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    print("[+] Reading encrypted config...")
    with open(file_path, "rb") as f:
        enc_cfg = f.read()

    print("[+] Decrypting using AES-128-CBC...")
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    
    try:
        dec_cfg = unpad(cipher.decrypt(enc_cfg))
    except Exception as e:
        print(f"[!] Padding error (might not be PKCS7): {e}")
        dec_cfg = cipher.decrypt(enc_cfg) # Fallback to raw

    print("\n--- Decrypted Config File (Raw Bytes) ---")
    print(dec_cfg)
    
    print("\n--- Extracted Strings ---")
    strings = re.findall(b'[ -~]{4,}', dec_cfg)
    for s in strings:
        print(s.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    main()
