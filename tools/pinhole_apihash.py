#!/usr/bin/env python3
"""
pinhole_apihash.py - PINHOLE API-hash resolver and name brute-forcer.

PINHOLE resolves every import at runtime by a 32-bit hash of the export name.
The algorithm (recovered from FUN_14000b1f0 and validated on 15/15 known pairs):

    h = 0x9E3779B9                       # seed (golden ratio)
    for each byte c in name (ASCII):
        h = (h * 0x85EBCA6B + rotl32(h, 13) + c) & 0xFFFFFFFF

0x85EBCA6B is a MurmurHash3 finalizer constant; 0x9E3779B9 is the golden-ratio
constant. The resolver also follows forwarder chains and supports ordinal imports
for hashes with the high bit set (>= 0x10000).

Uses:
  * hash a name:            pinhole_apihash.py --name RtlCopyMemory
  * identify a hash:        pinhole_apihash.py --resolve 0x494587AB [--wordlist api.txt]
  * dump a built-in map:    pinhole_apihash.py --selftest

MIT License. For defensive research.
"""
import argparse

M32 = 0xFFFFFFFF
SEED = 0x9E3779B9
MUL = 0x85EBCA6B


def rotl32(x, n): return ((x << n) | (x >> (32 - n))) & M32


def apihash(name: str) -> int:
    h = SEED
    for c in name.encode("ascii"):
        h = (h * MUL + rotl32(h, 13) + c) & M32
    return h


# Validated name -> hash pairs (subset used for self-test).
KNOWN = {
    "socket": 0xC60B4200, "getaddrinfo": 0xA03A564B, "connect": 0xE8AB725D,
    "send": 0x6ABFF9D0, "recv": 0x53CB4FE9, "GetLastError": 0x187ED739,
    "CreateFileW": 0xDBB813F5, "WriteFile": 0x35B28EF4, "CloseHandle": 0xB58D2A83,
    "CreateProcessW": 0xA2E9C2CC, "CreateProcessA": 0xA2E9C2B6,
    "GlobalLock": 0x51FCB7EE, "GlobalSize": 0xC4B808B4, "wsprintfW": 0x494587AB,
    "ShellExecuteW": 0x6A04525A,
}

# A small default wordlist for --resolve when none is supplied.
_DEFAULT_WORDS = [
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
    "VirtualProtect", "VirtualFree", "GetModuleHandleA", "GetModuleHandleW",
    "RtlCopyMemory", "memcpy", "malloc", "free", "WinExec", "CreateThread",
    "WaitForSingleObject", "ReadProcessMemory", "WriteProcessMemory",
    "NtCreateThreadEx", "QueueUserAPC", "ResumeThread", "OpenProcess",
    "TerminateProcess", "GetExitCodeProcess", "CreatePipe",
    "SetHandleInformation", "GlobalAlloc", "GlobalFree", "GlobalLock",
    "GlobalUnlock", "GlobalSize", "wsprintfW", "wsprintfA", "sprintf",
    "swprintf", "GetSystemMetrics", "GetDC", "ReleaseDC", "BitBlt",
    "CreateCompatibleDC", "CreateDIBSection", "SelectObject", "DeleteDC",
    "DeleteObject", "CoInitializeEx", "CoCreateInstance",
    "CreateStreamOnHGlobal", "GetHGlobalFromStream", "NtQuerySystemInformation",
]


def resolve(target: int, words):
    hits = []
    for w in words:
        if apihash(w) == target:
            hits.append(w)
    return hits


def main():
    ap = argparse.ArgumentParser(description="PINHOLE API-hash tool")
    ap.add_argument("--name", help="hash a single export name")
    ap.add_argument("--resolve", help="find a name for a hash (hex or dec)")
    ap.add_argument("--wordlist", help="newline-delimited candidate names for --resolve")
    ap.add_argument("--selftest", action="store_true", help="verify against known pairs")
    a = ap.parse_args()

    if a.selftest:
        ok = 0
        for name, h in KNOWN.items():
            got = apihash(name)
            flag = "OK" if got == h else "FAIL"
            ok += got == h
            print(f"  [{flag}] {name:<20} {got:08X} (expected {h:08X})")
        print(f"{ok}/{len(KNOWN)} passed")
        return

    if a.name:
        print(f"{apihash(a.name):08X}  {a.name}")
        return

    if a.resolve:
        target = int(a.resolve, 0) & M32
        words = _DEFAULT_WORDS
        if a.wordlist:
            words = [l.strip() for l in open(a.wordlist) if l.strip()]
        hits = resolve(target, words)
        if hits:
            for w in hits:
                print(f"{target:08X}  ->  {w}")
        else:
            print(f"{target:08X}  ->  (no match in {len(words)} candidates)")
        return

    ap.print_help()


if __name__ == "__main__":
    main()
