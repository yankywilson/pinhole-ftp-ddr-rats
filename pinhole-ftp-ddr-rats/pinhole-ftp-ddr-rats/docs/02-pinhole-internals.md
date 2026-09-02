# PINHOLE Internals — API Hashing, String Cipher, Struct Layout

**Reverse-engineering reference for the final-stage RAT** (`a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58`, 149,504 bytes, compiled 2026-08-29 19:21:13 UTC, MinGW-w64 x86-64).

## PE characteristics — **VALIDATED**

| Property | Value |
|----------|-------|
| Machine | x86-64, GUI subsystem |
| Image base | `0x140000000` |
| Entry point RVA | `0x211F7` |
| Static imports | **Zero** (`.idata` is 0x18 bytes, empty) |
| `.pdata` entries | 145 |

The RAT has **no static imports**; every API is resolved at runtime by hash via a PEB walk. Critically, the `.pdata` runtime-function table stops below `0x14000D000` — the entire command-handling region (`~0x14000F483`–`0x140020DDD`, ~70 KB) has **no exception-table coverage**. Any analysis driven off `.pdata` misses the command handlers entirely. This is worth stating because it likely explains why the public reporting enumerates no commands.

---

## 1. API-hashing algorithm — **NOVEL (high confidence, VALIDATED)**

The import resolver (`FUN_14000b5b8`) walks the PEB module list and matches export names by a 32-bit hash. The hash function (`FUN_14000b1f0`) was recovered directly from disassembly:

```c
uint32_t apihash(const char *name) {
    uint32_t h = 0x9E3779B9;              // seed = golden-ratio constant
    for (; *name; name++)
        h = (h * 0x85EBCA6B) + rotl32(h, 13) + (uint8_t)*name;
    return h;
}
```

Two recognizable fingerprints: the seed `0x9E3779B9` (golden ratio, as used in TEA/xxHash) and the multiplier `0x85EBCA6B` (a **MurmurHash3 finalizer constant**). The `div rax, rax`-on-a-nonzero-value trick in the prologue is junk obfuscation that simply yields `1`.

**Validation: 15 of 15** known name→hash pairs reproduce exactly. Implementation and a name brute-forcer are in [`tools/pinhole_apihash.py`](../tools/pinhole_apihash.py).

The resolver is more than a hashed `GetProcAddress`: it **follows forwarder chains** (parsing `dll.func` and `dll.#ordinal` forwards and re-resolving across DLLs) and supports **hash-based ordinal imports** for requests with the high bit set (`≥ 0x10000`).

### Resolved import set (34 of 36 named + validated)

All names below are **computed** from the validated algorithm, not guessed. Grouped by the handler that uses them.

| Hash | API | Module |
|------|-----|--------|
| `C60B4200` | socket | ws2_32 |
| `A03A564B` | getaddrinfo | ws2_32 |
| `53D9371D` | inet_pton | ws2_32 |
| `E8AB725D` | connect | ws2_32 |
| `6ABFF9D0` | send | ws2_32 |
| `53CB4FE9` | recv | ws2_32 |
| `2607C333` | AcquireCredentialsHandleA | secur32 |
| `06902222` | InitializeSecurityContextA | secur32 |
| `5CEEEBBE` | QueryContextAttributes | secur32 |
| `DFAD995A` | FreeContextBuffer | secur32 |
| `1FE9CDC4` | DeleteSecurityContext | secur32 |
| `D8439189` | FreeCredentialsHandle | secur32 |
| `187ED739` | GetLastError | kernel32 |
| `28BF17E6` | FormatMessageA | kernel32 |
| `D161AE82` | LocalFree | kernel32 |
| `21E15E16` | GetEnvironmentVariableW | kernel32 |
| `DBB813F5` | CreateFileW | kernel32 |
| `35B28EF4` | WriteFile | kernel32 |
| `B58D2A83` | CloseHandle | kernel32 |
| `A2E9C2CC` | CreateProcessW | kernel32 |
| `A2E9C2B6` | CreateProcessA | kernel32 |
| `D8767034` | MultiByteToWideChar | kernel32 |
| `923CBE3D` | WideCharToMultiByte | kernel32 |
| `99805030` | FindFirstFileW | kernel32 |
| `600D4D98` | FindNextFileW | kernel32 |
| `B9D5B589` | FindClose | kernel32 |
| `72FECCAC` | GetFileAttributesW | kernel32 |
| `2AD9768D` | DeleteFileW | kernel32 |
| `33245E17` | GetTempPathA | kernel32 |
| `7CF0CBA3` | OpenProcess | kernel32 |
| `2A32288F` | TerminateProcess | kernel32 |
| `FF06CEFD` | GetExitCodeProcess | kernel32 |
| `2E855D5A` | GetTickCount | kernel32 |
| `1A1EE056` | GetTickCount64 | kernel32 |
| `67CF2B14` | ReadFile | kernel32 |
| `A83C64BD` | Sleep | kernel32 |
| `4EA825DD` | CreatePipe | kernel32 |
| `836D1D5C` | SetHandleInformation | kernel32 |
| `C4B808B4` | **GlobalSize** | kernel32 |
| `51FCB7EE` | **GlobalLock** | kernel32 |
| `23DF7B14` | GlobalUnlock | kernel32 |
| `037EF3A2` | NtQuerySystemInformation | ntdll |
| `6A04525A` | ShellExecuteW | shell32 |
| `8F1227BC` | sprintf | msvcrt |
| `494587AB` | **wsprintfW** | user32 |
| `36AA273F` | GetSystemMetrics | user32 |
| `93BA59AF` | GetDC | gdi32 |
| `32677D92` | CreateCompatibleDC | gdi32 |
| `BBA2C9F9` | CreateDIBSection | gdi32 |
| `5E1476B2` | SelectObject | gdi32 |
| `D6F04002` | BitBlt | gdi32 |
| `105F1524` | DeleteDC | gdi32 |
| `FA50C9C3` | DeleteObject | gdi32 |
| `22DD2661` | ReleaseDC | gdi32 |
| `388BBD3A` | GetLogicalDriveStringsA | kernel32 |
| `E017F6E7` | GetDriveTypeA | kernel32 |
| `1FB97B2A` | CoInitializeEx | ole32 |
| `A6215111` | CoCreateInstance | ole32 |
| `6F70C117` | CreateStreamOnHGlobal | ole32 |
| `00658699` | GetHGlobalFromStream | ole32 |

**Two computed-but-unnamed hashes** (values certain, names pending a wordlist match): `0xAD4EADA5` (kernel32, 6-arg, signature `(handle, out_buffer[~0x100], 0, 0, 0, 0)`, reuses a cached global handle at `0x140027EC8`) and `0xBCB57F48` (kernel32, 3-arg, called as `(0,1,0)` and `(handle,0,0)`). These are footnotes, not gaps — the algorithm resolves them; only the human-readable name is open.

### CORRECTIONS to prior community understanding

- **`0x494587AB` is `wsprintfW` (user32), not `swprintf` (msvcrt).** Resolved from `user32.dll` at three independent call sites. *High confidence.*
- **`GlobalLock` and `GlobalSize` hashes were swapped** in prior reference material: `GlobalLock = 0x51FCB7EE`, `GlobalSize = 0xC4B808B4`. *High confidence — computed from the validated algorithm.*

---

## 2. String-obfuscation cipher — **NOVEL (VALIDATED)**

All sensitive strings (DLL names, API names, endpoints, format strings, error messages, DDR delimiters) are stored encrypted and decrypted on demand by `FUN_140021460` (135 bytes). It is called from **412 sites**; this analysis recovered **376 unique (pointer, key) pairs yielding 36 distinct plaintexts** (up from 22 in an earlier pass).

The per-byte decryption combines a golden-ratio mix, a PCG64 multiplier, and a bit-serial modular exponentiation:

```python
M32 = 0xFFFFFFFF; M64 = 0xFFFFFFFFFFFFFFFF
def dec_byte(c, key, idx):
    A  = (key + 0x3F2A1B8C + ((idx ^ 0xA5) * 0x9E3779B1)) & M32
    B  = (A * 0xAFEC16B1 + 0x3F8554AC) & M32
    u  = ((((B * 0x5851F42D4C957F2D) & M64) >> 33) & M32) | 1   # PCG64 multiplier
    r  = 0x4C957F01
    for bit in range(8):
        if (0x7F >> bit) & 1: r = (r * u) & M32
        u = (u * u) & M32
    D  = ((idx * 0x9E3779B1) + key) & M32
    E  = (D * 0xAFEC16B1 + 0x3F8554AC) & M32
    off = (((E * 0x5851F42D4C957F2D) & M64) >> 33) & M32
    return ((r * c - off) & M32) & 0xFF
```

Each call site passes a per-string 32-bit key in `edx`. Full extractor: [`tools/pinhole_strings.py`](../tools/pinhole_strings.py).

**Operationally important recovered strings:**

| Plaintext | Significance |
|-----------|--------------|
| `curl.exe -s -w "\n##STATUS##%{http_code}" -- "%s"` | The RAT's curl fallback command line — see [threat hunting](06-threat-hunting.md) |
| `\n##STATUS##` | Status delimiter marker — highest-value durable signature |
| `====D5===D6====` / `====D7===D8====` | DDR delimiter markers, recovered from the binary (previously only in STRU prose) |
| `/api/stlbrwsr`, `/api/vncpc` | Stealer + vnc endpoints |
| `Host: %s\r\nConnection: keep-alive\r\nAccept: */*\r\n` | Exact request header block (no User-Agent) |
| `Error al abrir el proceso vnc. Código: %lu` | Spanish internal error — see [attribution](07-attribution-and-assessment.md) |

Strings are decrypted once and cached in `.bss` behind one-byte sentinels, so **on a live host the `.bss` region holds the plaintext string pool** — a memory-forensics anchor. See the memory YARA in [`detections/yara/`](../detections/yara/).

---

## 3. Client struct & request path — **partially resolved (moderate confidence)**

The HTTP request core is reached through two thin wrappers:

```
FUN_140005225(out, client+0xA0, endpoint_str, client+0x43F8, body, body_len)   // 6-arg thunk
  └─ FUN_140005177(...)          // builds request line (128B) + header block (256B)
       ├─ FUN_1400386e(endpoint, client+0x43F8, out_reqline, out_headers)
       └─ FUN_1400039e3(out, client+0xA0, &{template, body, body_len, reqline, headers})  // chunked HTTP engine
```

What this data-flow establishes:

- **`client+0xA0`** is passed to the chunked engine **unformatted**, bypassing the request formatter entirely — consistent with it being the **live socket / TLS context or host descriptor**, not a URL string. *Moderate-to-high confidence.*
- **`client+0x43F8`** is fed into the formatter alongside the endpoint and emerges inside the request line/headers — consistent with it being the **session key** (matches the `?...&key=%s` query parameter and the `"key":"%s"` task-envelope field). *Moderate confidence.*
- **`body` / `body_len`** (params 5–6) are both `0` in the stealer and vnc fetches, confirming those two endpoints are **GET** requests. A caller passing non-zero here is doing a POST.

`FUN_140005177` has **four xrefs**: the stealer/vnc fetch wrapper, its `.pdata` entry, and **two unmapped callers** (`FUN_1400090C1`, `FUN_1400094D1`) that are almost certainly the **registration** (`POST /api/client`) and **beacon/task-poll** loop. That beacon loop is the one remaining un-decompiled region of the RAT; every command handler is mapped. See [command protocol](03-pinhole-command-protocol.md).
