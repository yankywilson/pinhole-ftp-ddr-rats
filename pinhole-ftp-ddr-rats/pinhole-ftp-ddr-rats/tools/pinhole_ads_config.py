#!/usr/bin/env python3
"""
pinhole_ads_config.py - PINHOLE Alternate Data Stream config extractor.

Some PINHOLE builds stage a small configuration blob in an NTFS Alternate Data
Stream (ADS) rather than inline. The config is encoded with a base-41 alphabet and
then XORed with a SplitMix64-derived keystream. This module reverses both steps.

Encoding (recovered):
  alphabet = "0123456789abcdefghijklmnopqrstuvwxyz.-_:/"   (41 symbols)
  1. base-41 decode the ASCII text back to raw bytes (big-endian symbol packing)
  2. XOR each byte with a SplitMix64 keystream seeded from the first 8 bytes

SplitMix64 (standard):
  z = (seed += 0x9E3779B97F4A7C15)
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
  z = (z ^ (z >> 27)) * 0x94D049BB133111EB
  z =  z ^ (z >> 31)

The decoded config carries the sleep/jitter, build token, and the DDR resolver
list. Field layout varies by build; this tool emits the raw decoded bytes and a
best-effort printable rendering.

Usage:
    # from a file containing the ADS text
    pinhole_ads_config.py config_ads.txt

    # from a live host (PowerShell), first dump the stream:
    #   Get-Content .\file.exe -Stream <name> | Out-File config_ads.txt -Encoding ascii

MIT License. For defensive research.
"""
import argparse, string

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz.-_:/"
BASE = len(ALPHABET)  # 41
IDX = {c: i for i, c in enumerate(ALPHABET)}
M64 = 0xFFFFFFFFFFFFFFFF
PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}


def base41_decode(text: str) -> bytes:
    """Decode base-41 text (big-endian) to raw bytes."""
    text = "".join(ch for ch in text.strip() if ch in IDX)
    n = 0
    for ch in text:
        n = n * BASE + IDX[ch]
    # convert big integer to bytes
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big") if length else b""


def splitmix64_stream(seed: int, count: int):
    s = seed & M64
    out = bytearray()
    while len(out) < count:
        s = (s + 0x9E3779B97F4A7C15) & M64
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        z = z ^ (z >> 31)
        out += z.to_bytes(8, "little")
    return bytes(out[:count])


def decode_config(text: str):
    raw = base41_decode(text)
    if len(raw) < 8:
        return raw
    seed = int.from_bytes(raw[:8], "little")
    body = raw[8:]
    ks = splitmix64_stream(seed, len(body))
    dec = bytes(body[i] ^ ks[i] for i in range(len(body)))
    return dec


def _render(b: bytes) -> str:
    return "".join(chr(x) if x in PRINTABLE and x >= 0x20 else "." for x in b)


def main():
    ap = argparse.ArgumentParser(description="PINHOLE ADS config extractor")
    ap.add_argument("input", help="file containing the base-41 ADS text")
    ap.add_argument("-o", "--output", help="write raw decoded bytes here")
    a = ap.parse_args()
    text = open(a.input, "r", errors="ignore").read()
    dec = decode_config(text)
    print(f"[+] decoded {len(dec)} bytes")
    print("[+] hex   :", dec[:128].hex())
    print("[+] ascii :", _render(dec[:128]))
    if a.output:
        open(a.output, "wb").write(dec)
        print(f"[+] written to {a.output}")


if __name__ == "__main__":
    main()
