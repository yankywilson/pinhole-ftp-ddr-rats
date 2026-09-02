# Tools

Reproducible analysis tooling for PINHOLE. All scripts are standalone (Python 3.8+).
`pinhole_unpack.py` needs `capstone` (`pip install capstone`); the rest use only the
standard library.

| Tool | Purpose | Validation |
|------|---------|-----------|
| `pinhole_unpack.py` | Walk the loader chain (de-JPEG → locate stage → page cipher) | Byte-perfect stage reproduction (`--keys`); blind mode locates the offset and recovers the shared keystream tail |
| `pinhole_apihash.py` | Compute / resolve PINHOLE's API-name hashes | Self-test passes 15/15 known pairs (`--selftest`) |
| `pinhole_strings.py` | Decrypt the RAT's obfuscated string pool | Reproduces the documented cipher (see docs/02) |
| `pinhole_ads_config.py` | Decode base-41 + SplitMix64 ADS config blobs | Round-trips a synthetic config |

Reference cipher implementation for the loader's Donut fork is in
[`../analysis/donut_cipher_fork.py`](../analysis/donut_cipher_fork.py).

## Quick start

```bash
# API hashes
python3 pinhole_apihash.py --selftest
python3 pinhole_apihash.py --name CreateProcessW
python3 pinhole_apihash.py --resolve 0x494587AB      # -> wsprintfW

# Unpack a Layer-1 container to the loader stage
python3 pinhole_unpack.py bc_original.bin -o stage.bin
# guaranteed byte-perfect for the reference build:
python3 pinhole_unpack.py bc_original.bin \
    --keys d4bac3d1d219813f,d7bac3d1d219813f,d6bac3d1d219813f,d1bac3d1d219813f \
    -o stage.bin

# Decrypt the Donut instance carried in the stage
python3 ../analysis/donut_cipher_fork.py instance.bin -o payload.bin
```

## Note on blind unpacking

Blind byte-0 recovery for one interior page can be ambiguous where two candidate
keystream bytes differ only in a register-encoding nibble that linear disassembly
resynchronizes past. The tool reports this; supply the documented per-page
keystreams with `--keys` (see [docs/01](../docs/01-pinhole-loader-chain.md)) for a
guaranteed byte-perfect result. Every other layer and the shared keystream tail
recover unattended.
