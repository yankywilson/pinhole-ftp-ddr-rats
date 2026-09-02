#!/usr/bin/env python3
"""
donut_cipher_fork.py - Reference implementation of PINHOLE's modified Donut cipher.

PINHOLE's loader embeds a Donut instance whose payload region is encrypted with a
FORK of Donut's Chaskey routine: 24 rounds instead of the stock 16, and different
rotation constants. This is why stock Donut unpackers fail on the sample.

Stock Donut Chaskey rounds : 16, rotations (5,16,8,13,7,16)
This fork                  : 24, rotations (14,5,4,15,9,14)

Decrypting the reference instance with this routine yields the cleartext DLL list
"ole32;oleaut32;wininet;mscoree;shell32", confirming the parameters.

Key material lives in cleartext in the instance header:
    master key (mk)  at +0x04, 16 bytes
    counter/nonce    at +0x14, 16 bytes
CTR mode wraps the block cipher; the counter is incremented from the LAST byte
backward (little-endian style, high-index first).

Reference values (analyzed build):
    mk  = 19d01baf70ed8e9cc7abbf3ba27af957
    ctr = 2c48a8d90b846dcb8f7e54ceecfabf99

Usage:
    from donut_cipher_fork import donut_decrypt
    plain = donut_decrypt(ciphertext, mk_bytes, ctr_bytes)

MIT License. For defensive research.
"""
import struct

M32 = 0xFFFFFFFF
ROUNDS = 24
ROT = (14, 5, 4, 15, 9, 14)  # r1..r6


def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & M32
def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & M32


def _chaskey_block(v, key):
    """One 128-bit block through the 24-round modified Chaskey with key whitening."""
    w = [(v[i] ^ key[i]) & M32 for i in range(4)]  # pre-whiten
    r1, r2, r3, r4, r5, r6 = ROT
    for _ in range(ROUNDS):
        w[0] = (w[0] + w[1]) & M32
        w[1] = _rotl(w[1], r1) ^ w[0]
        t = _rotl(w[3], r2) ^ ((w[2] + w[3]) & M32)
        w[2] = (w[2] + w[3] + w[1]) & M32
        w[0] = (_rotr(w[0], r3) + t) & M32
        w[3] = _rotr(t, r4) ^ w[0]
        w[1] = _rotr(w[1], r5) ^ w[2]
        w[2] = _rotl(w[2], r6) & M32
    return [(w[i] ^ key[i]) & M32 for i in range(4)]  # post-whiten


def _ctr_inc(ctr: bytearray):
    """Increment the 16-byte counter from the last byte backward."""
    i = len(ctr) - 1
    while i >= 0:
        ctr[i] = (ctr[i] + 1) & 0xFF
        if ctr[i] != 0:
            break
        i -= 1


def donut_decrypt(ct: bytes, mk: bytes, ctr: bytes) -> bytes:
    """CTR-mode decrypt with the modified Chaskey block function."""
    assert len(mk) == 16 and len(ctr) == 16
    key = list(struct.unpack("<4I", mk))
    counter = bytearray(ctr)
    out = bytearray()
    for off in range(0, len(ct), 16):
        blk = list(struct.unpack("<4I", counter.ljust(16, b"\x00")[:16]))
        ks = _chaskey_block(blk, key)
        ks_bytes = struct.pack("<4I", *ks)
        chunk = ct[off:off + 16]
        out += bytes(chunk[i] ^ ks_bytes[i] for i in range(len(chunk)))
        _ctr_inc(counter)
    return bytes(out)


if __name__ == "__main__":
    import argparse, binascii
    ap = argparse.ArgumentParser(description="PINHOLE Donut cipher-fork decryptor")
    ap.add_argument("instance", help="raw Donut instance (from the unpacked stage)")
    ap.add_argument("--mk", default="19d01baf70ed8e9cc7abbf3ba27af957",
                    help="master key hex (default: reference build)")
    ap.add_argument("--ctr", default="2c48a8d90b846dcb8f7e54ceecfabf99",
                    help="counter/nonce hex (default: reference build)")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x23C,
                    help="offset where the encrypted region begins (default 0x23C)")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    data = open(a.instance, "rb").read()
    dec = donut_decrypt(data[a.start:], binascii.unhexlify(a.mk), binascii.unhexlify(a.ctr))
    if b"ole32" in dec or b"wininet" in dec:
        print("[OK] recognizable DLL names present in decrypted output")
    if a.output:
        open(a.output, "wb").write(dec)
        print(f"[+] written to {a.output}")
    else:
        print(dec[:96].hex())
