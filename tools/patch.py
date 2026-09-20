# language: Python, file: tools/patch.py
#!/usr/bin/env python3
import sys, struct, zlib

def main():
    if len(sys.argv) != 3:
        print("usage: patch.py <pe> <marker>", file=sys.stderr); sys.exit(1)
    path, marker = sys.argv[1], sys.argv[2].encode()
    with open(path, "rb") as f: data = bytearray(f.read())
    off = data.find(marker)
    if off < 0:
        print("marker not found", file=sys.stderr); sys.exit(1)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff     = e_lfanew + 4
    nsec     = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off  = coff + 20 + opt_size
    text = None
    for i in range(nsec):
        base = sec_off + i * 40
        name = bytes(data[base:base+8]).rstrip(b"\x00")
        if name == b".text":
            vsize   = struct.unpack_from("<I", data, base + 8)[0]
            raw_sz  = struct.unpack_from("<I", data, base + 16)[0]
            raw_off = struct.unpack_from("<I", data, base + 20)[0]
            text = (vsize, raw_sz, raw_off)
            break
    if not text:
        print("no .text", file=sys.stderr); sys.exit(1)
    vsize, raw_sz, raw_off = text
    buf = bytes(data[raw_off:raw_off + raw_sz]) + b"\x00" * (vsize - raw_sz)
    crc = zlib.crc32(buf) & 0xFFFFFFFF
    struct.pack_into("<I", data, off, crc)
    with open(path, "wb") as f: f.write(data)
    print(f"wrote crc 0x{crc:08x} at {off:#x}")

if __name__ == "__main__":
    main()
