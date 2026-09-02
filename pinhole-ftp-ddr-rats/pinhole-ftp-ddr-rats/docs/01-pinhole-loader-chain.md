# PINHOLE Loader Chain — Six-Layer Unpacking

**Reverse-engineering reference.** Every layer below was reproduced from the sample; the unpacker in [`tools/pinhole_unpack.py`](../tools/pinhole_unpack.py) walks the chain and its output hashes to known values.

The PINHOLE second stage arrives from the Cloudflare Worker path (`/api/bc`) as a **93,380-byte blob disguised as a JPEG**. It is unpacked through six layers before the final RAT executes. Every offset in the chain is **per-build randomized** — the constants below are for the analyzed 2026-08-31 build and will differ between builds. The one cross-build constant is the decoded stage size, **15,552 bytes**.

## Layer overview

| Layer | Mechanism | In → Out |
|-------|-----------|----------|
| 1 | Fake JPEG header + global byte-decrement | 93,380 → 93,376 |
| 2 | Junk-prologue container, self-referential offsets | (container) |
| 3 | Stage extraction at fixed offset | → 15,552 |
| 4 | 8-byte page cipher (per-4KB-page XOR) | 15,552 → 15,552 |
| 5 | **Donut instance — custom cipher fork** | 70,575 (encrypted region) |
| 6 | aPLib decompression | 64,357 → 149,504 |

Then: Halo's Gate syscall resolution → Early Bird APC injection into a suspended `ApplicationFrameHost.exe`.

---

## Layer 1 — Fake JPEG wrapper — **CORROBORATED + detail added**

The container opens with `FF D8 FF E0` (JPEG SOI + APP0) and an APP0 length field of `0x6710` (26,384), but **no `JFIF` identifier string follows**. This makes it an invalid JPEG that every real parser rejects, while still passing a naïve "starts with FF D8" magic check.

**Deobfuscation:** strip the first 4 bytes, then **decrement every remaining byte by 1** (`b = (b - 1) & 0xFF`). Result: the 93,376-byte Layer-2 container.

YARA anchor for the wrapper (see [`detections/yara/`](../detections/yara/)):
```
$hdr  = { FF D8 FF E0 [0-8] 67 10 20 45 01 01 }
```

## Layer 2 — Container with self-referential offsets — **NOVEL (build delta)**

The container begins with a **38-byte junk prologue** of multi-byte NOPs (`66 0F 1F 44 00 00`, `0F 1F 84 00 00 00 00 00`) padded with `F5`, `F8`, `90`. An `E8` (call rel32) at offset `0x26` has displacement `0x113AF`, targeting `0x113DA`. A `uint32` at `0x2B` equals **70,575**, which is exactly the distance from `0x2B` to `0x113DA` — a self-consistency check the loader uses to locate its own Donut instance.

**Build-to-build variation** (this is the useful part for tracking builds):

| Element | STRU build (2026-08-21) | Analyzed build (2026-08-31) |
|---------|------------------------|-----------------------------|
| Junk prologue length | 56 bytes | **38 bytes** |
| `call` offset | `0x38` | **`0x26`** |
| Config offset | `0x3D` | **`0x2B`** |
| Config length | 60,131 | **70,575** |
| XOR stub offset | `0xEB20` | **`0x113DA`** |
| Stage offset | `0x10000` | **`0x13000`** |
| **Stage size** | **15,552** | **15,552 — unchanged** |
| Loader XOR key | `1F 3B 39 27` | (build-specific; differs) |
| Page-cipher key page 0 | `01 4D 63 02 A3 61 A3 15` | **`d4 ba c3 d1 d2 19 81 3f`** |

> **CORRECTION / caution for trackers:** the loader XOR key and page-cipher key are **per-build** and must never be used as cross-build IOCs. Only the 15,552-byte stage size is stable. Several downstream write-ups treat build-specific constants as durable indicators; they are not.

## Layer 3 — Stage extraction — **VALIDATED**

The encrypted stage sits at offset `0x13000`, length `0x3CC0` (15,552). Its entropy (~7.2) is visibly lower than the surrounding container (~7.97), which is itself a weak locator.

## Layer 4 — 8-byte page cipher — **VALIDATED (byte-perfect)**

The stage is encrypted with a **repeating 8-byte XOR keystream applied independently per 4 KB page**. Bytes 1–7 of the keystream are constant across all pages; **only byte 0 changes per page.**

Recovered keystreams for the analyzed build:

| Page | Offset | Keystream |
|------|--------|-----------|
| 0 | `0x13000` | `d4 ba c3 d1 d2 19 81 3f` |
| 1 | `0x14000` | `d7 ba c3 d1 d2 19 81 3f` |
| 2 | `0x15000` | `d6 ba c3 d1 d2 19 81 3f` |
| 3 | `0x16000` | `d1 ba c3 d1 d2 19 81 3f` |

Byte-0 sequence `D4 D7 D6 D1` → deltas `0, 3, 2, 5` from page 0. The exact derivation formula (index-mix vs. carryless multiply) is **unresolved — OPEN**; it needs a second build to disambiguate, and it is operationally irrelevant because the keystream recovers directly from ciphertext.

**Three independent recovery methods**, any one sufficient:
1. **Frequency analysis** — the most common aligned 8-byte block in a page is the keystream XOR `0x00` (works only on high-repetition pages).
2. **Known-plaintext from the decoded stage** — reliable on all pages.
3. **Page-3 tail leak** — the final bytes repeat with period 8, leaking the keystream verbatim.

The unpacker uses a **disassembly-scoring** approach (test all 256 byte-0 candidates per page, pick the one that maximizes valid x64 instruction density) so it works without prior knowledge of the plaintext. **Validation:** the reproduced stage hashes to `89495a1b14cf37d1824af6937956efdc748ea3edb0e84c1e82d89b60cba451b1`, matching the reference — byte-perfect. The decoded stage disassembles to 3,852 instructions with 100% coverage of all 15,552 bytes, and instructions cross page boundaries cleanly, proving all four keystreams simultaneously correct.

The decoded stage is MinGW-w64 x86-64 position-independent code, entry prologue `AUATUWVSH`, that takes a pointer to the Donut instance in RCX.

## Layer 5 — Donut instance: the cipher fork — **NOVEL (high confidence)**

This is the most important reverse-engineering result in the loader chain, and it is why **every public Donut unpacker fails on this sample.**

The stage carries an embedded [Donut](https://github.com/TheWover/donut) instance (70,575 bytes) whose payload region (`0x23C` → end) is encrypted. The key material is stored in cleartext in the instance header — master key at `+0x04` (16 bytes), counter/nonce at `+0x14` (16 bytes):

```
master key (mk) : 19d01baf70ed8e9cc7abbf3ba27af957
counter    (ctr): 2c48a8d90b846dcb8f7e54ceecfabf99
Maru IV         : 5b91f64740054828   (at +0x28)
```

Stock Donut uses **Chaskey with 16 rounds** for its encryption. This sample uses a **modified Chaskey with 24 rounds and different rotation constants**:

| | Stock Donut Chaskey | This fork |
|-|--------------------|-----------|
| Rounds | 16 | **24** |
| Rotation constants | 5, 16, 8, 13, 7, 16 | **14, 5, 4, 15, 9, 14** |

The round function, with pre- and post-whitening XOR against the master key, and a CTR-mode wrapper whose counter **increments from the last byte backward**:

```c
// per-block, 24 rounds; see analysis/donut_cipher_fork.py for the full impl
w0 = (w0 + w1) & M32;
w1 = ROTL(w1, 14) ^ w0;
t  = ROTL(w3, 5) ^ ((w2 + w3) & M32);
w2 = (w2 + w3 + w1) & M32;
w0 = (ROTR(w0, 4) + t) & M32;
w3 = ROTR(t, 15) ^ w0;
w1 = ROTR(w1, 9) ^ w2;
w2 = ROTL(w2, 14);
```

**Validation:** decrypting the instance with this routine yields a coherent Donut instance whose DLL-name field reads `ole32;oleaut32;wininet;mscoree;shell32`. A reference implementation is in [`analysis/donut_cipher_fork.py`](../analysis/donut_cipher_fork.py).

Decrypted instance fields of note:

| Field | Offset | Value |
|-------|--------|-------|
| `api_cnt` | — | 61 |
| `dll_names` | — | `ole32;oleaut32;wininet;mscoree;shell32` |
| module master key | `+0xC78` | `e5c026b9537984864c4966ada8c60e0a` |
| module counter | `+0xC88` | `a280892915d436928a884de077547987` |
| module length | `+0xC98` | 65,817 |

## Layer 6 — aPLib decompression — **VALIDATED**

The embedded module (at instance offset `0x11C8`) is aPLib-compressed: **64,357 → 149,504 bytes**. The exact output-length match confirms the entire six-layer chain is correct end-to-end. The 149,504-byte result is the final PINHOLE RAT (`a7d3e902…`), analyzed in [internals](02-pinhole-internals.md) and [command protocol](03-pinhole-command-protocol.md).

## Post-unpack execution — **CORROBORATED**

After decompression the loader resolves syscalls via **Halo's Gate** (a Hell's Gate variant that walks neighbouring stubs when a target is hooked) and injects the RAT into a **suspended `ApplicationFrameHost.exe`** using **Early Bird APC injection**. This matches STRU's description; it was not independently re-derived here beyond confirming the injection target in behaviour, so it is carried as **CORROBORATED**, not VALIDATED.
