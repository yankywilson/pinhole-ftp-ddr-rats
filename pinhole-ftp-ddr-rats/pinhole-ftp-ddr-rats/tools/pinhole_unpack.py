#!/usr/bin/env python3
"""
pinhole_unpack.py - PINHOLE multi-stage loader unpacker.

Recovers the packed loader stage from the Layer-1 container that PINHOLE fetches
from its Cloudflare Worker (/api/bc). The page-cipher model is documented and
validated byte-for-byte against the reference build:

    stage SHA256 = 89495a1b14cf37d1824af6937956efdc748ea3edb0e84c1e82d89b60cba451b1

Cipher model (Layer 4), fully reverse-engineered:
  * The stage is XORed with an 8-byte keystream, applied independently per 4KB page.
  * Keystream bytes 1-7 are IDENTICAL across every page; only byte 0 varies.
  * The decoded stage begins with the MinGW register-save prologue
    41 55 41 54 55 57 56 53 (push r13/r12/rbp/rdi/rsi/rbx).

Recovery strategy (blind, no reference needed):
  1. De-JPEG (Layer 1): strip 4-byte header, decrement every byte by 1.
  2. Locate the stage (Layers 2/3): for each page-aligned offset, recover a
     prologue-consistent shared tail and disassemble the whole candidate stage
     with capstone. The true offset yields near-total instruction coverage; a
     coincidental prologue match elsewhere covers almost nothing (observed:
     4094/4096 vs 76/4096 on the reference build).
  3. Recover the keystream (Layer 4): the shared 7-byte tail comes from the
     aligned-block column modes; page-0 byte 0 is pinned by the prologue and the
     final page's byte 0 by its period-8 tail leak. Interior-page byte 0 values
     are chosen by maximal capstone coverage.

Known limitation: blind byte-0 selection for an *interior* page can be ambiguous
when two candidates differ only in a register-encoding nibble that linear
disassembly resynchronizes past (e.g. d6 vs da on page 2 of the reference build).
When the exact keystream is known it can be supplied with --keys for a guaranteed
byte-perfect result; the reference keystream is documented in
../docs/01-pinhole-loader-chain.md. All other layers and the shared tail recover
exactly and unattended.

Layer 5 (Donut cipher fork) reference impl: ../analysis/donut_cipher_fork.py
Layer 6 (aPLib) is standard; run any aPLib depacker on the Layer-5 output.

Usage:
    python3 pinhole_unpack.py <bc_original.bin> [-o stage.bin]
    python3 pinhole_unpack.py <bc.bin> --keys d4bac3d1d219813f,d7...,d6...,d1... -o stage.bin
    python3 pinhole_unpack.py --dejpeg-only <bc.bin> -o container.bin

Requires: capstone  (pip install capstone).  MIT License. For defensive research.
"""
import argparse, hashlib, sys, math
from collections import Counter
from itertools import product

try:
    import capstone
    _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
except Exception:
    _MD = None

STAGE_SIZE = 15552          # cross-build constant
PAGE = 0x1000
REF_STAGE_SHA256 = "89495a1b14cf37d1824af6937956efdc748ea3edb0e84c1e82d89b60cba451b1"
STAGE_PROLOGUE = bytes.fromhex("4155415455575653")


def dejpeg(container: bytes) -> bytes:
    """Layer 1: strip the 4-byte fake-JPEG header, decrement every byte by 1."""
    if container[:4] != b"\xFF\xD8\xFF\xE0":
        print("[!] warning: input does not start with FF D8 FF E0", file=sys.stderr)
    return bytes((b - 1) & 0xFF for b in container[4:])


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _coverage(buf: bytes) -> int:
    """Bytes consumed by capstone's linear disassembly from offset 0."""
    if _MD is None:
        # fallback density score if capstone missing
        common = set(range(0x50, 0x62)) | {0x48, 0x49, 0x4C, 0x4D, 0x89, 0x8B,
                                           0xE8, 0xC3, 0xFF, 0x0F, 0x85, 0x74, 0x75}
        return sum(1 for x in buf if x in common)
    return sum(ins.size for ins in _MD.disasm(buf, 0))


def _tail_candidates(page: bytes, topn: int = 3):
    cols = [Counter() for _ in range(8)]
    for i in range(0, len(page) - 8, 8):
        for j in range(8):
            cols[j][page[i + j]] += 1
    return [[c for c, _ in cols[j].most_common(topn)] for j in range(1, 8)]


def _prologue_tails(page0: bytes):
    """All shared 7-byte tails for which some byte 0 makes page0 start with the prologue."""
    tails = []
    for combo in product(*_tail_candidates(page0)):
        tail = bytes(combo)
        for b0 in range(256):
            ks = bytes([b0]) + tail
            if bytes(page0[i] ^ ks[i] for i in range(8)) == STAGE_PROLOGUE:
                tails.append(tail)
                break
    return tails


def _best_b0_for_page(page: bytes, tail: bytes):
    best_s, best_b0 = -1, 0
    for b0 in range(256):
        ks = bytes([b0]) + tail
        dec = bytes(page[i] ^ ks[i % 8] for i in range(len(page)))
        s = _coverage(dec)
        if s > best_s:
            best_s, best_b0 = s, b0
    return best_s, best_b0


def _score_offset(seg: bytes):
    """
    Best (coverage, tail) over prologue-consistent tails at this offset. Coverage
    is measured over the WHOLE decrypted stage as one instruction stream, so a
    coincidental page-0 prologue match at a wrong offset (which cannot decode the
    rest of the stage as code) scores far below the true offset.
    """
    best = None
    for tail in _prologue_tails(seg[:PAGE]):
        dec = bytearray()
        for p in range(0, len(seg), PAGE):
            _, b0 = _best_b0_for_page(seg[p:p + PAGE], tail)
            ks = bytes([b0]) + tail
            page = seg[p:p + PAGE]
            dec += bytes(page[i] ^ ks[i % 8] for i in range(len(page)))
        total = _coverage(bytes(dec))
        if best is None or total > best[0]:
            best = (total, tail)
    return best  # None if no prologue-consistent tail


def find_stage_and_keys(container: bytes):
    """Locate the stage and recover per-page keystreams. Returns (offset, keys, tail)."""
    scored = []
    for off in range(0, len(container) - STAGE_SIZE + 1, PAGE):
        r = _score_offset(container[off:off + STAGE_SIZE])
        if r is not None:
            scored.append((r[0], off, r[1]))
    if scored:
        scored.sort(key=lambda t: t[0], reverse=True)
        _, off, tail = scored[0]
    else:
        off = min(range(0, len(container) - STAGE_SIZE + 1, PAGE),
                  key=lambda o: _entropy(container[o:o + STAGE_SIZE]))
        tail = bytes(c[0] for c in _tail_candidates(container[off:off + PAGE], 1))
    seg = container[off:off + STAGE_SIZE]
    keys = []
    for p in range(0, len(seg), PAGE):
        _, b0 = _best_b0_for_page(seg[p:p + PAGE], tail)
        keys.append(bytes([b0]) + tail)
    return off, keys, tail


def decrypt_stage_with_keys(stage_ct: bytes, keys):
    out = bytearray()
    for idx, p in enumerate(range(0, len(stage_ct), PAGE)):
        page = stage_ct[p:p + PAGE]; ks = keys[idx]
        out += bytes(page[i] ^ ks[i % 8] for i in range(len(page)))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="PINHOLE multi-stage unpacker")
    ap.add_argument("input", help="bc_original.bin (Layer-1 container from /api/bc)")
    ap.add_argument("-o", "--output", help="write recovered stage here")
    ap.add_argument("--keys", help="comma-separated 8-byte hex keystreams, one per 4KB page "
                                    "(guarantees byte-perfect output for a known build)")
    ap.add_argument("--dejpeg-only", action="store_true",
                    help="only strip the fake-JPEG wrapper and write the container")
    args = ap.parse_args()

    data = open(args.input, "rb").read()
    if data[:4] == b"\xFF\xD8\xFF\xE0":
        container = dejpeg(data)
        print(f"[+] Layer 1: de-JPEG -> {len(container)} bytes")
    else:
        container = data
        print("[i] input already de-JPEG'd")

    if args.dejpeg_only:
        if args.output:
            open(args.output, "wb").write(container)
            print(f"[+] container written to {args.output}")
        return

    if _MD is None:
        print("[!] capstone not installed - offset/keystream recovery is degraded. "
              "pip install capstone", file=sys.stderr)

    if args.keys:
        keys = [bytes.fromhex(k.strip()) for k in args.keys.split(",")]
        # locate offset by prologue under the supplied page-0 key
        off = None
        for o in range(0, len(container) - STAGE_SIZE + 1, PAGE):
            pg = container[o:o + PAGE]
            if bytes(pg[i] ^ keys[0][i % 8] for i in range(8)) == STAGE_PROLOGUE:
                off = o; break
        if off is None:
            print("[!] supplied keys do not locate the prologue; aborting", file=sys.stderr)
            sys.exit(2)
        print(f"[+] Layer 2/3: stage located at offset 0x{off:X} (via --keys)")
    else:
        off, keys, tail = find_stage_and_keys(container)
        print(f"[+] Layer 2/3: stage located at offset 0x{off:X} ({STAGE_SIZE} bytes)")
        print(f"    shared keystream tail (bytes 1-7) = {tail.hex()}")

    stage = decrypt_stage_with_keys(container[off:off + STAGE_SIZE], keys)
    print("[+] Layer 4: page cipher decrypted")
    for i, k in enumerate(keys):
        print(f"    page {i} keystream = {k.hex()}")
    digest = hashlib.sha256(stage).hexdigest()
    print(f"    stage SHA256 = {digest}")
    if digest == REF_STAGE_SHA256:
        print("    [OK] byte-perfect vs reference build")
    else:
        print("    [i] not the reference build (other build, or interior byte-0 ambiguity - "
              "supply --keys for a guaranteed result; see docs/01-pinhole-loader-chain.md)")

    if args.output:
        open(args.output, "wb").write(stage)
        print(f"[+] stage written to {args.output}")
    print("[i] Next: Layer 5 (analysis/donut_cipher_fork.py), then aPLib.")


if __name__ == "__main__":
    main()
