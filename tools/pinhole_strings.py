#!/usr/bin/env python3
"""
pinhole_strings.py - PINHOLE string-obfuscation decryptor.

Sensitive strings in the PINHOLE RAT are stored encrypted and decrypted on demand
by FUN_140021460, called from 412 sites with a per-string 32-bit key. The per-byte
routine combines a golden-ratio mix, the PCG64 multiplier, and a bit-serial
modular exponentiation. This module reproduces it.

Recovered plaintexts include the curl fallback command line with the ##STATUS##
marker, the /api/vncpc and /api/stlbrwsr endpoints, the DDR delimiters, and the
Spanish internal error strings. See docs/02-pinhole-internals.md.

Usage:
    # decrypt a single blob with a known key
    pinhole_strings.py --hex <ciphertext-hex> --key 0xDEADBEEF

    # sweep a binary: for every 4-byte little-endian key candidate near each
    # referenced blob, try decryption and print printable results
    pinhole_strings.py --scan pinhole_rat.bin

MIT License. For defensive research.
"""
import argparse, string

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}


def dec_byte(c: int, key: int, idx: int) -> int:
    A = (key + 0x3F2A1B8C + ((idx ^ 0xA5) * 0x9E3779B1)) & M32
    B = (A * 0xAFEC16B1 + 0x3F8554AC) & M32
    u = ((((B * 0x5851F42D4C957F2D) & M64) >> 33) & M32) | 1  # PCG64 multiplier
    r = 0x4C957F01
    for bit in range(8):
        if (0x7F >> bit) & 1:
            r = (r * u) & M32
        u = (u * u) & M32
    D = ((idx * 0x9E3779B1) + key) & M32
    E = (D * 0xAFEC16B1 + 0x3F8554AC) & M32
    off = (((E * 0x5851F42D4C957F2D) & M64) >> 33) & M32
    return ((r * c - off) & M32) & 0xFF


def decrypt(ct: bytes, key: int) -> bytes:
    return bytes(dec_byte(ct[i], key, i) for i in range(len(ct)))


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if x in PRINTABLE) / len(b)


def scan(data: bytes, min_len=5, max_len=128, thresh=0.9):
    """
    Heuristic sweep: for each offset, try the 4-byte LE value at nearby offsets as
    the key and decrypt a window; report windows that decode to mostly-printable
    ASCII ending at a NUL. This finds strings without the xref map; for precise
    results, drive dec_byte() with (pointer, key) pairs extracted from the disasm.
    """
    seen = set()
    for i in range(0, len(data) - 8):
        # candidate keys: the dword right before the blob, and at the blob start
        for koff in (i - 4, i):
            if koff < 0 or koff + 4 > len(data):
                continue
            key = int.from_bytes(data[koff:koff + 4], "little")
            out = bytearray()
            for j in range(i, min(i + max_len, len(data))):
                b = dec_byte(data[j], key, j - i)
                if b == 0:
                    break
                out.append(b)
            if len(out) >= min_len and _printable_ratio(out) >= thresh:
                s = bytes(out)
                if s not in seen:
                    seen.add(s)
    return sorted(seen, key=len, reverse=True)


def main():
    ap = argparse.ArgumentParser(description="PINHOLE string decryptor")
    ap.add_argument("--hex", help="ciphertext as hex")
    ap.add_argument("--key", help="32-bit key (hex or dec)")
    ap.add_argument("--scan", help="binary to heuristically sweep")
    ap.add_argument("--min-len", type=int, default=6)
    a = ap.parse_args()

    if a.hex and a.key:
        ct = bytes.fromhex(a.hex)
        key = int(a.key, 0) & M32
        out = decrypt(ct, key)
        print(repr(out))
        return

    if a.scan:
        data = open(a.scan, "rb").read()
        for s in scan(data, min_len=a.min_len):
            try:
                print(s.decode("ascii"))
            except UnicodeDecodeError:
                print(repr(s))
        return

    ap.print_help()


if __name__ == "__main__":
    main()
