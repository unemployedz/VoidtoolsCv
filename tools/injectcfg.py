# language: Python, file: tools/injectcfg.py
#!/usr/bin/env python3
import sys, os, secrets
from Crypto.Cipher import AES

def pkcs7(b, n=16):
    p = n - (len(b) % n)
    return b + bytes([p]) * p

def main():
    if len(sys.argv) != 3:
        print("usage: injectcfg.py <out.h> <token:chatid>", file=sys.stderr); sys.exit(1)
    token = os.environ.get("TG_TOKEN", "")
    chat  = os.environ.get("TG_CHAT",  "")
    if not token or not chat:
        print("TG_TOKEN / TG_CHAT not set", file=sys.stderr); sys.exit(1)
    data = (token + ":" + chat).encode()
    key  = secrets.token_bytes(32)
    iv   = secrets.token_bytes(16)
    ct   = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7(data))
    with open(sys.argv[1], "w") as o:
        o.write("// auto-generated, do not commit\n#pragma once\n#include <cstdint>\n")
        o.write(f"#define CFG_CIPHER_LEN {len(ct)}\n")
        o.write("static const uint8_t g_cfg_key[32] = {\n    ")
        o.write(", ".join(f"0x{b:02x}" for b in key)); o.write("\n};\n")
        o.write("static const uint8_t g_cfg_iv[16] = {\n    ")
        o.write(", ".join(f"0x{b:02x}" for b in iv));  o.write("\n};\n")
        o.write(f"static const uint8_t g_cfg_blob[{len(ct)}] = {{\n")
        for i in range(0, len(ct), 16):
            o.write("    " + ", ".join(f"0x{b:02x}" for b in ct[i:i+16]) + ",\n")
        o.write("};\n")

if __name__ == "__main__":
    main()
