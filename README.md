# PINHOLE & E4del — Independent Reverse Engineering, Detection & Threat Intelligence

**A complete, sample-driven teardown of two FTP-banner dead-drop-resolver RATs — going far past the only public report on them.**

> **What this is.** In August 2026 the SOCRadar Threat Research Unit (STRU) named two malware families — **PINHOLE** and **E4del** — that pull their next-stage command server out of **FTP server greeting banners** used as dead-drop resolvers (DDR). That report, and the dozen news rewrites downstream of it, establish *that* the families exist and roughly *what* they do. **None of it publishes the internals a defender actually needs** — no command protocol, no cryptography, no import-resolution scheme, and not one detection artifact.
>
> This repository reconstructs all of it **from the samples up**, corrects the public record where it is wrong, and ships **detection content and tooling that were validated against the samples before release**. This page is the full account. The `docs/` files are deeper cuts of each section.
>
> **Status:** Active research · **Last updated:** 2026-09-01 · **Not affiliated with SOCRadar.**

---

## Table of contents

1. [At a glance](#at-a-glance)
2. [What is genuinely new here](#what-is-genuinely-new-here) — the 12 novel findings, each explained
3. [PINHOLE loader chain — six layers](#pinhole-loader-chain--six-layers)
4. [PINHOLE cryptography (all three ciphers, with constants)](#pinhole-cryptography)
5. [PINHOLE command protocol — all 16 opcodes](#pinhole-command-protocol--all-16-opcodes)
6. [PINHOLE network & C2](#pinhole-network--c2)
7. [E4del RAT](#e4del-rat)
8. [Detection — the highest-value signatures](#detection--the-highest-value-signatures)
9. [Threat hunting](#threat-hunting)
10. [Attribution & assessment](#attribution--assessment)
11. [Corrections to the public record](#corrections-to-the-public-record)
12. [Key indicators](#key-indicators)
13. [Tooling](#tooling)
14. [Evidence standard](#evidence-standard)
15. [Samples analyzed](#samples-analyzed)
16. [Repository layout](#repository-layout)
17. [Responsible use & license](#responsible-use--license)

---

## At a glance

| | PINHOLE | E4del |
|---|---|---|
| **Type** | Multi-stage x64 native RAT (MinGW-w64) | Node.js RAT inside a trojanized signed Discord Electron bundle |
| **Delivery** | Phishing ZIP → LNK → PowerShell reads an **FTP banner** → Cloudflare Worker serves stages | Same FTP-banner delivery → expands Discord bundle to `%LOCALAPPDATA%` |
| **C2 resolution** | **DDR**: Pinterest pins + SurveyMonkey survey → Cloudflare Worker proxy | Hardcoded C2 per build (custom WebSocket) |
| **Transport** | **Custom Schannel HTTP** (no WinINet/WinHTTP; bypasses EDR hooks & proxy logs) | Custom WebSocket over raw socket, AES-256-CBC |
| **Commands** | **16 operator opcodes** (public reporting: "14") | **11 handlers** (public reporting: "8") |
| **Standout capability** | Browser stealer + remote-desktop (`vnc`) + persistent PowerShell | Desktop streaming + native priv-esc addon + package runner |
| **Best detection** | `##STATUS##` curl marker (host, rotation-proof) | `--init` Run-key persistence + `/ws/ds` WebSocket |
| **Attribution signal** | **Spanish developer strings inside the compiled binary** | Per-host builds, each with its own C2 |

**The single most important operational fact:** because C2 is resolved through a dead-drop chain, **blocking C2 IPs accomplishes almost nothing** — the malware just re-reads a Pinterest pin for the next one. Detection has to sit on **host behaviour and the delivery chain**, both of which this repo covers with tested rules.

---

## What is genuinely new here

Everything in this section is absent from the SOCRadar report and every downstream source, verified by search at time of writing. Each item is graded (see [evidence standard](#evidence-standard)). Where a claim in prior reporting is wrong, it is corrected in [§11](#corrections-to-the-public-record).

### 1. The complete 16-opcode command protocol — **NOVEL, VALIDATED**
Public reporting says PINHOLE has "14 commands" and lists none. The real dispatcher (`0x140020C91`) bounds-checks the opcode `≤ 0xF` and indexes a **16-entry jump table** at `0x140023BCC`. Commands are **integers, not strings**, which is why a string scan never reveals them. Full table with handlers, arguments, and wire format in [§5](#pinhole-command-protocol--all-16-opcodes). This includes a **7th network endpoint and a remote-desktop module nobody documented** (items 5–6 below).

### 2. The API-hashing algorithm, fully recovered — **NOVEL, VALIDATED 15/15**
PINHOLE has **zero static imports**; every API is resolved at runtime by a 32-bit hash of the export name. The algorithm (from `FUN_14000b1f0`):
```
h = 0x9E3779B9                                  # seed (golden ratio)
for each byte c of name:  h = (h * 0x85EBCA6B + rotl32(h,13) + c) & 0xFFFFFFFF
```
`0x85EBCA6B` is a **MurmurHash3 finalizer constant**; `0x9E3779B9` is the golden-ratio constant. **Validated on 15/15 known name→hash pairs.** The resolver also **follows forwarder chains** and supports **hash-based ordinal imports** (high bit set). This single result resolves the entire 60-name import set — the full table is in [`docs/02`](docs/02-pinhole-internals.md). Runnable: [`tools/pinhole_apihash.py`](tools/pinhole_apihash.py) (`--selftest` passes 15/15).

### 3. The Donut cipher fork — **NOVEL, high confidence**
This is why **every public Donut unpacker fails on this sample.** The loader carries a Donut instance encrypted not with stock Donut's 16-round Chaskey but with a **fork: 24 rounds and different rotation constants**.

| | Stock Donut Chaskey | This fork |
|---|---|---|
| Rounds | 16 | **24** |
| Rotations | 5, 16, 8, 13, 7, 16 | **14, 5, 4, 15, 9, 14** |

CTR-mode wrapper whose counter **increments from the last byte backward**. Decrypting with these parameters yields a coherent instance whose DLL list reads `ole32;oleaut32;wininet;mscoree;shell32` — the validation that the parameters are correct. Reference implementation: [`analysis/donut_cipher_fork.py`](analysis/donut_cipher_fork.py). Detail in [§3](#pinhole-loader-chain--six-layers) and [`docs/01`](docs/01-pinhole-loader-chain.md).

### 4. The string-obfuscation cipher — **NOVEL, VALIDATED**
Every sensitive string is stored encrypted and decrypted on demand by `FUN_140021460` (called from **412 sites → 376 unique (pointer,key) pairs → 36 plaintexts**). The per-byte routine mixes a golden-ratio constant, the **PCG64 multiplier** `0x5851F42D4C957F2D`, and a bit-serial modular exponentiation. Full algorithm and recovered strings in [§4](#pinhole-cryptography). Runnable: [`tools/pinhole_strings.py`](tools/pinhole_strings.py).

### 5. `/api/vncpc` — an undocumented 7th endpoint and remote-desktop module — **NOVEL, VALIDATED**
Opcode 14 (`vncpc`) fetches `/api/vncpc`, writes it to `%LOCALAPPDATA%\<pseudoword>.exe`, and launches it with a **`room_id` as its sole argument** — a session identifier for a remote-desktop ("vnc") channel. The internal error string `Error al abrir el proceso vnc` is the operator's own name for it. **This endpoint and capability appear in no public source.**

### 6. The `##STATUS##` curl marker — **NOVEL, VALIDATED, highest detection value**
PINHOLE carries a hardcoded fallback command line:
```
curl.exe -s -w "\n##STATUS##%{http_code}" -- "<url>"
```
`##STATUS##` is the RAT's own HTTP-status delimiter — **not a normal curl token**, baked into the binary, and it **survives every infrastructure rotation**. It is the single most durable host signature for the family. Tested Sigma rule: [`detections/sigma/pinhole_curl_status_marker.yml`](detections/sigma/pinhole_curl_status_marker.yml).

### 7. The developer is a Spanish speaker at the code level — **NOVEL, moderate-high confidence**
Public reporting notes Spanish in the **lures**. This analysis finds Spanish in the **compiled RAT's own internal, developer-facing error strings** — e.g. `Error al obtener LOCALAPPDATA. Código: %lu`, `Error al crear archivo. Código: %lu`, `Error al abrir el proceso vnc. Código: %lu`. Localization targets victims; **internal diagnostics are how the developer talks to themselves.** See [§10](#attribution--assessment).

### 8. E4del per-host build separation — **NOVEL, high confidence**
Each E4del payload host serves a **distinct `app.asar`** — different SHA256, different size, **different hardcoded C2** — while the Discord runtime is byte-identical across builds. TLSH distance between two builds on ~90 MB files is **27** (unrelated files score in the hundreds): same builder, different per-host payload. See [§7](#e4del-rat).

### 9. A new E4del C2, `51.89.199.118` — **NOVEL, high confidence**
Recovered by diffing the plaintext `index.js` of a build (`51.89.199.125/i`) the original reporting never analyzed. Its reconnect list is `WS_ENDPOINTS = ['ws://51.89.199.118', …]`. **Not present in any public source.**

### 10. Validated ADS config-extractor spec — **NOVEL**
Some builds stage config in an NTFS Alternate Data Stream, **base-41 encoded then XORed with a SplitMix64 keystream** seeded from the first 8 bytes. Reversed and round-tripped: [`tools/pinhole_ads_config.py`](tools/pinhole_ads_config.py).

### 11. Two concrete corrections to the community's understanding — **CORRECTION, high confidence**
`0x494587AB` = **`wsprintfW`** (user32), *not* `swprintf`; and the **`GlobalLock` / `GlobalSize` hashes were swapped** in prior reference material (`GlobalLock = 0x51FCB7EE`, `GlobalSize = 0xC4B808B4`). Both computed from the validated algorithm. See [§11](#corrections-to-the-public-record).

### 12. A working, round-trip-validated unpacker — **NOVEL, VALIDATED byte-perfect**
[`tools/pinhole_unpack.py`](tools/pinhole_unpack.py) walks the loader chain and reproduces the loader stage **byte-for-byte** (SHA-256 `89495a1b…`). It recovers the stage offset and the page-cipher keystream **blind** (no reference needed) by disassembly scoring; one interior keystream byte is honestly flagged as ambiguous and resolved by the documented `--keys`.

---

## PINHOLE loader chain — six layers

The second stage arrives from the Cloudflare Worker (`/api/bc`) as a **93,380-byte blob disguised as a JPEG** and is unpacked through six layers. **Every offset below is per-build randomized**; the one cross-build constant is the decoded-stage size, **15,552 bytes**. Deep dive: [`docs/01`](docs/01-pinhole-loader-chain.md).

| Layer | Mechanism | Transform | Status |
|---|---|---|---|
| 1 | Fake JPEG (`FF D8 FF E0`, no `JFIF`) + global byte-decrement | 93,380 → 93,376 | CORROBORATED + detail |
| 2 | Junk-prologue container with self-referential offsets | — | NOVEL (build deltas) |
| 3 | Stage extraction at a fixed offset (`0x13000` this build) | → 15,552 | VALIDATED |
| 4 | **8-byte page cipher** — per-4KB-page XOR; bytes 1-7 constant, byte 0 varies | 15,552 → 15,552 | **VALIDATED byte-perfect** |
| 5 | **Donut instance — cipher fork** (24-round Chaskey, see [§4](#pinhole-cryptography)) | decrypts instance | NOVEL |
| 6 | aPLib decompression | 64,357 → 149,504 | VALIDATED (exact size match) |

Then: **Halo's Gate** syscall resolution → **Early Bird APC injection** into a suspended `ApplicationFrameHost.exe`.

**Page-cipher keystreams (analyzed build), recovered three independent ways:**

| Page | Offset | Keystream |
|---|---|---|
| 0 | `0x13000` | `d4 ba c3 d1 d2 19 81 3f` |
| 1 | `0x14000` | `d7 ba c3 d1 d2 19 81 3f` |
| 2 | `0x15000` | `d6 ba c3 d1 d2 19 81 3f` |
| 3 | `0x16000` | `d1 ba c3 d1 d2 19 81 3f` |

Byte-0 sequence `D4 D7 D6 D1`; the shared 7-byte tail `ba c3 d1 d2 19 81 3f` is invariant. Decoded stage begins with the MinGW prologue `41 55 41 54 55 57 56 53` (`push r13/r12/rbp/rdi/rsi/rbx`).

**Build tracking (useful deltas between the STRU build and the analyzed build):**

| Element | STRU (2026-08-21) | Analyzed (2026-08-31) |
|---|---|---|
| Junk prologue length | 56 B | **38 B** |
| Config length | 60,131 | **70,575** |
| Stage offset | `0x10000` | **`0x13000`** |
| **Stage size** | **15,552** | **15,552 — unchanged** |

> **Indicator hygiene:** the loader XOR key and page-cipher keys are **per-build** — never use them as cross-build IOCs. Only the 15,552-byte stage size is stable.

---

## PINHOLE cryptography

Three separate custom cryptosystems, all reversed and reproduced in code.

### API-name hash (import resolution)
Seed `0x9E3779B9`, per byte `h = h*0x85EBCA6B + rotl32(h,13) + c`. MurmurHash3 finalizer multiplier. **Validated 15/15.** Follows forwarder chains; ordinal imports for hashes `≥ 0x10000`. → [`tools/pinhole_apihash.py`](tools/pinhole_apihash.py)

### String cipher (per-byte, keyed)
```python
M32=0xFFFFFFFF; M64=0xFFFFFFFFFFFFFFFF
def dec_byte(c, key, idx):
    A = (key + 0x3F2A1B8C + ((idx ^ 0xA5) * 0x9E3779B1)) & M32
    B = (A * 0xAFEC16B1 + 0x3F8554AC) & M32
    u = ((((B * 0x5851F42D4C957F2D) & M64) >> 33) & M32) | 1   # PCG64 multiplier
    r = 0x4C957F01
    for bit in range(8):
        if (0x7F >> bit) & 1: r = (r * u) & M32
        u = (u * u) & M32
    D = ((idx * 0x9E3779B1) + key) & M32
    E = (D * 0xAFEC16B1 + 0x3F8554AC) & M32
    off = (((E * 0x5851F42D4C957F2D) & M64) >> 33) & M32
    return ((r * c - off) & M32) & 0xFF
```
**Operationally important recovered plaintexts:** the `curl … ##STATUS##` command line; the DDR delimiters `====D5===D6====` / `====D7===D8====`; `/api/vncpc`, `/api/stlbrwsr`; the exact header block `Host: %s\r\nConnection: keep-alive\r\nAccept: */*\r\n` (**no User-Agent**); and the Spanish error strings. Strings are decrypted once and cached in `.bss` — so **on a live host the plaintext string pool sits in process memory** (a memory-forensics anchor; see the in-memory YARA rule). → [`tools/pinhole_strings.py`](tools/pinhole_strings.py)

### Donut cipher fork (loader Layer 5)
24-round modified Chaskey, rotations `14,5,4,15,9,14`, pre/post key whitening, CTR counter incrementing backward from the last byte. Key material is cleartext in the instance header: master key `19d01baf70ed8e9cc7abbf3ba27af957`, counter `2c48a8d90b846dcb8f7e54ceecfabf99`. Decrypts to DLL list `ole32;oleaut32;wininet;mscoree;shell32`. → [`analysis/donut_cipher_fork.py`](analysis/donut_cipher_fork.py)

---

## PINHOLE command protocol — all 16 opcodes

**Task structure:** opcode is a `uint32` at `task+4`; arguments JSON pointer at `task+8`. **Result envelope:** `{"type":2,"key":"%s","task_id":%d,"success":%s,"result_type":%d,"result":"%s"}`. **Registration** (`POST /api/client`) sends a **19-field** JSON object; note `sleep_time` and `jitter_time` are **server-controlled** — beacon cadence is operator-tunable per host. Deep dive: [`docs/03`](docs/03-pinhole-command-protocol.md).

| Op | Command | Handler | Notes |
|---|---|---|---|
| 0 | `ls` | `0x1400172DB` | `[D]`/`[F]` prefixed listing |
| 1 | `cd` | `0x1400181B2` | changes cached CWD |
| 2 | `pwd` | `0x14000E5BE` | reads cached CWD global |
| 3 | `upload` | `0x140013A21` | multipart POST → `/api/fls` |
| 4 | `download` | `0x140016C53` | `GET /api/fls?type=1&file_id=…&key=…` |
| 5 | `exec` | `0x140016965` | ShellExecuteW |
| 6 | `delete` | `0x1400163DF` | DeleteFileW |
| 7 | `find` | `0x140019263` | recursive, **walks all drives** |
| 8 | `processes` | `0x140018D69` | NtQuerySystemInformation |
| 9 | `kill` | `0x140018687` | OpenProcess + TerminateProcess |
| 10 | `screenshot` | `0x14000F483` | GDI+WIC → JPEG → `/api/fls` |
| 11 | **stealer** | `0x1400208A4` | fetches `/api/stlbrwsr` — **server-delivered module** |
| 12 | `powershell` init | `0x140014E78` | spawns **one** persistent PS child via pipes |
| 13 | `powershell` exec | `0x1400140CD` | writes to that child's stdin; sentinel `___PWSH_END_%08X___` |
| 14 | **vncpc** | `0x14001ED56` | **NOVEL** — fetches `/api/vncpc`, drops `%LOCALAPPDATA%\<pseudoword>.exe`, launches with `room_id` |
| 15 | **fallback** | `0x140020AE0` | operator-driven **on-demand C2 rotation** |

**Detection-relevant behaviours:** the persistent-PowerShell design means you see **one** `powershell.exe` creation (parented to a pseudoword binary, redirected stdio), **not** repeated spawns. The stealer (op 11) and vnc (op 14) modules are **fetched from the server** — which is exactly why STRU couldn't recover them, and why they can't be obtained without the C2 serving them.

**Two developer bugs (authorship texture):** op 14 emits `exec: path required` (op 5's string) on a missing arg; op 15 emits `download: args required` (op 4's string). Copy-paste artifacts.

**Pseudoword generator (shared with E4del stage 1 — a code-lineage link):** length 10–15, vowel-initial, strictly alternating consonant/vowel. Observed: `ofozuharasukizo`, `iloporafefon`, `izapukecoga`, `urutucucemel`, `erikituvicaba`. Regex: `%LOCALAPPDATA%\[a-z]{10,15}(\[a-z]{10,15})?\.exe`.

---

## PINHOLE network & C2

**DDR chain (three hops, so blocking one C2 does nothing):**
1. **FTP banner** (port 21) returns a PowerShell one-liner that fetches the next stage.
2. **Dead-drop resolvers** — real C2 sits between `====D5===D6====` / `====D7===D8====` markers on legitimate pages:
   `hxxps://mx.pinterest[.]com/pin/1128292512937332995`, `…/1128292512937332894/`, and tertiary `hxxps://www.surveymonkey[.]com/r/WW5NVT6`.
3. **Cloudflare Worker** fronts the real origin: `worker-1785198984-xsekhi.api-62c3cac6.workers.dev` (the epoch in the name decodes to **2026-07-28** — a *candidate* provisioning-timestamp pattern, **OPEN**).

**Custom TLS/HTTP stack — why the RAT is quiet on the wire (NOVEL, high confidence):** the network layer (`FUN_14000230D`) is **raw Winsock + Schannel SSPI** — **no WinINet, no WinHTTP**. Consequence:

| Control | Effect |
|---|---|
| EDR hooks on WinINet/WinHTTP | **Never fire** — libraries unused |
| System/corporate proxy | **Ignored** — proxy logs blank |
| Request shape | `Host / Connection: keep-alive / Accept: */*` — **no User-Agent** |

**Endpoints:** `/api/health`, `/api/client`, `/api/tsk`, `/api/bc`, `/api/fls`, `/api/stlbrwsr`, **`/api/vncpc`** (novel). Deep dive: [`docs/04`](docs/04-network-and-c2.md).

---

## E4del RAT

Node.js RAT inside a **trojanized, signed Discord Electron bundle** — only `app.asar → app_bootstrap/index.js` is swapped; the Discord runtime is genuine. Analysis primarily from plaintext **Build B** (`4712f482…`). Deep dive: [`docs/08`](docs/08-e4del-analysis.md).

- **Anti-sandbox gate:** `os.userInfo().username` compared (loosely, `!=`) to the `--init` argument → implies the operator knew the victim username at delivery (**targeted**, candidate).
- **Persistence:** HKCU Run key with args `['--init','<username>']`; drops a Zone.Identifier ADS (`HostUrl=http://51.89.199.125/i`).
- **Transport:** custom WebSocket over raw socket `ws://[C2]/ws/ds?hostId=&hwid=`; **AES-256-CBC**, key = `SHA256("protected!")`; delimiter `%e4del%`.
- **11 handlers** (public: "8"): `startcmd`, `runcmd`, `screenshot`, `streamstart <ip>`, `streamstop`, `plugin`, `filedownload`, `runpackage`, `elevate` (loads native `crypto32.node` priv-esc addon), `disconnect`, default.
- **Streaming gap:** `streamstart` opens a **second, unencrypted** WebSocket `/ws/agent` (raw JPEG every 2 s) that can target a **different IP** than the command C2 — defenders watching the C2 address see no video.
- **AV-aware:** WMI `SecurityCenter2` **plus** a registry fallback specifically to catch **CrowdStrike Falcon** (which doesn't register with SecurityCenter2); the detected AV rides in every heartbeat as an operator decision point.

| Build | Host | C2 | index.js |
|---|---|---|---|
| A | `54.37.237.164` | **Unknown** (VM-obfuscated) | 168,394 B |
| B | `51.89.199.125` | **`51.89.199.118`** (new) | 30,212 B plaintext |
| Public | `157.254.194.31` | `157.254.194.31` | STRU |

---

## Detection — the highest-value signatures

Full guide with tiers and tuning: [`docs/05`](docs/05-detection-guide.md). All rules were validated/linted against the samples before release.

**Tier A — deploy as alerts (near-zero FP, rotation-proof):**
- **`##STATUS##` curl marker** — [`detections/sigma/pinhole_curl_status_marker.yml`](detections/sigma/pinhole_curl_status_marker.yml). `curl.exe` with `##STATUS##` in the command line.
- **On-disk RAT YARA** — [`detections/yara/pinhole_rat.yar`](detections/yara/pinhole_rat.yar), rule `PINHOLE_RAT_on_disk` (plaintext `/api/client`+`/api/tsk`+`/api/fls?…`+`___PWSH_END_`). *Tested: fires on the RAT, clean on stage/instance/real-JPEG.*
- **In-memory YARA** — rule `PINHOLE_RAT_in_memory` (decrypted pool: `##STATUS##`, `/api/vncpc`, DDR delimiters, Spanish vnc error). Scan process memory / an image — **won't match the on-disk file by design**.
- **Fake-JPEG loader YARA** — rule `PINHOLE_loader_container` (valid SOI/APP0, **no `JFIF`** at offset 6). Structural, build-agnostic.

**Tier B — deploy with tuning:**
- Persistent PowerShell child parented to a pseudoword `%LOCALAPPDATA%` binary — [`pinhole_persistent_powershell.yml`](detections/sigma/pinhole_persistent_powershell.yml).
- Pseudoword drop (single + nested package path) — [`pinhole_pseudoword_drop.yml`](detections/sigma/pinhole_pseudoword_drop.yml).
- Outbound FTP (port 21) from a script host — [`pinhole_ftp_banner_delivery.yml`](detections/sigma/pinhole_ftp_banner_delivery.yml) + Suricata.

**Network (Suricata, 9 rules, SIDs 2810001-9):** [`detections/suricata/pinhole_e4del.rules`](detections/suricata/pinhole_e4del.rules) — FTP banner LOLbin primitives, Pinterest/SurveyMonkey resolver fetches, no-UA workers.dev flows, E4del `/ws/ds` + `/ws/agent`, and the new C2. **Do not blocklist Cloudflare anycast or the resolver platforms.**

---

## Threat hunting

Full hypotheses with queries and confidences: [`docs/06`](docs/06-threat-hunting.md). Start here:

1. **`##STATUS##` process marker** *(high)* — `curl.exe` cmdline contains `##STATUS##`. If you hunt one thing, hunt this.
2. **Memory string pool** *(high)* — `##STATUS##`, `/api/vncpc`, DDR delimiters, `Error al abrir el proceso vnc` co-occurring in one process's memory is definitive.
3. **Outbound FTP from a script host** *(mod-high)* — port 21 from `wscript`/`powershell`/`mshta` to a non-corporate IP; catches delivery early.
4. **Persistent PowerShell + pseudoword drop** *(mod-high combined)*.
5. **Infrastructure pivots** *(mod)* — FTP Stats Panel on **port 5000** (Censys/Shodan sibling hunt); enumerate the operator's other Pinterest pins; the FOFA/Censys banner-abuse query for the DDR technique class.

---

## Attribution & assessment

Full graded assessment: [`docs/07`](docs/07-attribution-and-assessment.md).

- **No actor attribution** — evidence is insufficient (consistent with STRU).
- **Developer language:** **Spanish** — multiple internal, non-victim-facing error strings in the compiled RAT. *Moderate-high confidence.*
- **Targeting:** **LATAM lean** — Spanish lures, `mx.pinterest.com`, `farolesa[.]mx`, internal Spanish strings; but the technique is fully portable, so treat as a capability concern for any region. *Moderate confidence on the lean.*
- **Code lineage:** the **shared pseudoword generator** links E4del stage 1 and the PINHOLE RAT, families STRU tracks separately — consistent with a shared developer/toolkit. *Moderate confidence a relationship exists; does not establish common operation.*
- **Ransomware:** no evidence — no encryptor, note, or leak site. *Watch-item only.*

---

## Corrections to the public record

| # | Prior reporting | Corrected finding | Confidence |
|---|---|---|---|
| 1 | "14 commands" | **16 opcodes**, fully enumerated | high (VALIDATED) |
| 2 | `0x494587AB = swprintf` | **`wsprintfW`** (user32), 3 call sites | high |
| 3 | `GlobalLock`/`GlobalSize` hashes | **Swapped**: `GlobalLock=0x51FCB7EE`, `GlobalSize=0xC4B808B4` | high |
| 4 | build constants treated as durable IOCs | **Per-build**; only 15,552-B stage size is stable | high |
| 5 | vnc drop = nested package path | **Also** single-level `%LOCALAPPDATA%\<pseudoword>.exe` (op 14) | high |
| 6 | ETag `"6a809184-59e6f0f"` → PINHOLE Worker | Belongs to **E4del Build A** (`54.37.237.164`) | high |
| 7 | E4del "8 commands" | **11 handlers** + default | high |

---

## Key indicators

Full machine-readable set (50 entries, confidence-graded): [`ioc/indicators.csv`](ioc/indicators.csv) · human-readable: [`ioc/indicators.md`](ioc/indicators.md).

**Highest value:**

| Indicator | Type | Note |
|---|---|---|
| `##STATUS##` | in-memory string | rotation-proof host signature |
| `___PWSH_END_%08X___` | on-disk string | plaintext in the RAT PE |
| `/api/vncpc` | URI | **novel** endpoint |
| `51.89.199.118` | IPv4 | **new** E4del C2 |
| `%e4del%` | string | E4del delimiter |

**PINHOLE RAT:** `a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58`
**E4del Build B bundle:** `4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1`

**Do NOT blocklist:** Cloudflare anycast (`104.21.x.x`, `172.67.x.x`) or the resolver platforms (Pinterest, SurveyMonkey, workers.dev).

---

## Tooling

All standalone (Python 3.8+). `pinhole_unpack.py` needs `capstone`; the rest are stdlib-only. Details: [`tools/README.md`](tools/README.md).

| Tool | Purpose | Validation |
|---|---|---|
| [`pinhole_unpack.py`](tools/pinhole_unpack.py) | Walk the loader chain to the stage | **Byte-perfect** stage repro (`--keys`); blind offset + tail recovery |
| [`pinhole_apihash.py`](tools/pinhole_apihash.py) | Compute / resolve API-name hashes | **15/15** self-test |
| [`pinhole_strings.py`](tools/pinhole_strings.py) | Decrypt the string pool | reproduces documented cipher |
| [`pinhole_ads_config.py`](tools/pinhole_ads_config.py) | Decode base-41 + SplitMix64 ADS config | round-trips |
| [`analysis/donut_cipher_fork.py`](analysis/donut_cipher_fork.py) | Reference impl of the cipher fork | decrypts to known DLL list |

---

## Evidence standard

Every material claim is tagged, using ICD-203 estimative language:

- **VALIDATED** — reproduced from the sample by code in this repo (output hashes to a known value).
- **CORROBORATED** — independently confirmed a prior-reporting claim against the sample.
- **NOVEL** — absent from every public source at time of writing; graded high/moderate/low.
- **CORRECTION** — an evidenced fix to prior reporting.
- **OPEN / UNVERIFIED** — stated or inferred, not yet confirmed against a sample (e.g. the Worker epoch pattern; the interior page-cipher byte-0 derivation; the resolver pins' post-disclosure liveness).

**Analytical line-of-sight:** all prior public work derives from a single originating source (STRU, 2026-08-21). This repo treats that report as one source to be corroborated, not as ground truth, and anchors every finding to the samples.

---

## Samples analyzed

| Role | SHA256 |
|---|---|
| PINHOLE final-stage RAT (x64) | `a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58` |
| PINHOLE `/api/bc` container | `78cd264a29e21b79035772faa4615e2bb1d795d15983ab1a3bc4e25d262e3840` |
| PINHOLE loader stage (decoded) | `89495a1b14cf37d1824af6937956efdc748ea3edb0e84c1e82d89b60cba451b1` |
| E4del bundle (Build B) | `4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1` |

**No live malware binaries are hosted in this repository** — analysis, detection logic, and tooling only.

---

## Repository layout

```
README.md                     ← this page (the full account)
docs/
  00-executive-summary.md     Leadership / IR-lead summary
  01-pinhole-loader-chain.md  Six-layer unpacking, cipher fork, page cipher
  02-pinhole-internals.md     API hashing (full 60-name table), string cipher, struct
  03-pinhole-command-protocol.md  All 16 opcodes, wire format, endpoints
  04-network-and-c2.md        DDR chain, Cloudflare Worker, custom TLS
  05-detection-guide.md       Tiered deployment & tuning
  06-threat-hunting.md        Hunt hypotheses w/ queries & confidence
  07-attribution-and-assessment.md  Graded, ICD-203
  08-e4del-analysis.md        E4del, per-host builds, new C2
detections/
  yara/pinhole_rat.yar        3 rules (on-disk, in-memory, loader) — tested
  sigma/*.yml                 4 rules — parsed & regex-validated
  suricata/pinhole_e4del.rules  9 rules — linted, unique SIDs
tools/                        4 validated Python tools + README
analysis/donut_cipher_fork.py Reference cipher implementation
ioc/                          indicators.csv (50, graded) + indicators.md
LICENSE                       MIT (code) + CC-BY-4.0 (docs)
```

---

## Responsible use & license

Published for defenders — detection engineering, threat hunting, incident response. The infrastructure described was live at analysis time; some indicators may since be rotated or down. **Validate every detection in your own environment before production.** Original discovery credit for the FTP-banner DDR technique and the family names belongs to MalwareHunterTeam (technique, July 2026) and the SOCRadar Threat Research Unit (families, August 2026); this project builds on that public disclosure.

Docs, IOCs, and detection content: **CC BY 4.0.** Code under `tools/` and `analysis/`: **MIT.** See [`LICENSE`](LICENSE).
