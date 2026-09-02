# PINHOLE Command Protocol — All 16 Opcodes

**NOVEL (high confidence, VALIDATED from the dispatcher).** Public reporting states PINHOLE has "14 commands" and enumerates none. This is the complete, reverse-engineered command set — **16 handlers**, every one reached by the dispatcher, with wire format, arguments, and per-handler API usage.

## Wire format

**Task structure** (received from C2, pointer in `r8` at dispatch):
- `+4` — opcode (uint32)
- `+8` — pointer to arguments JSON

**Dispatcher** at `0x140020C91`: bounds-checks the opcode `≤ 0xF`, then indexes a 16-entry `rel32` jump table at `0x140023BCC`. Commands are **integers, not strings** — there are no command-name literals anywhere in the binary, which is why a string scan never reveals the command set.

**Result envelope** returned to C2:
```json
{"type":2,"key":"%s","task_id":%d,"success":%s,"result_type":%d,"result":"%s"}
```

**Registration** (`POST /api/client`) sends a 19-field JSON object:
```
type, key, client_id, user_id, sleep_time, jitter_time, private_ip,
build_token, username, workstation, version, build, cpu, gpu, ram,
disk, drives, privileges, path
```
Note `sleep_time` and `jitter_time` are **server-controlled** — beacon cadence is operator-tunable per host, a detail absent from public reporting.

---

## The 16 handlers

| Op | Command | Handler | Body | JSON args | Notes |
|----|---------|---------|------|-----------|-------|
| 0 | `ls` | `0x1400172DB` | 3,799 | `path` | `[D]`/`[F]` prefixed listing |
| 1 | `cd` | `0x1400181B2` | 1,237 | `path` | changes cached CWD |
| 2 | `pwd` | `0x14000E5BE` | 635 | — | reads cached CWD global |
| 3 | `upload` | `0x140013A21` | 1,708 | `path` | multipart POST to `/api/fls` |
| 4 | `download` | `0x140016C53` | 1,672 | `file_id`, `dest` | `GET /api/fls?type=1&file_id=…&key=…` |
| 5 | `exec` | `0x140016965` | 750 | `path`, `verb` | ShellExecuteW |
| 6 | `delete` | `0x1400163DF` | 1,414 | `path` | DeleteFileW |
| 7 | `find` | `0x140019263` | 1,494 | `query` | recursive, **walks all drives** |
| 8 | `processes` | `0x140018D69` | 1,274 | — | NtQuerySystemInformation |
| 9 | `kill` | `0x140018687` | 1,762 | `pid` | OpenProcess+TerminateProcess |
| 10 | `screenshot` | `0x14000F483` | 17,822 | — | GDI+WIC → JPEG → `/api/fls` |
| 11 | **stealer** | `0x1400208A4` | 154 | — | fetches `/api/stlbrwsr` module |
| 12 | `powershell` init | `0x140014E78` | 5,479 | — | spawns persistent PS child |
| 13 | `powershell` exec | `0x1400140CD` | 3,499 | `command` | runs in the persistent child |
| 14 | **vncpc** | `0x14001ED56` | 5,074 | `room_id` | fetches `/api/vncpc`, drops & launches |
| 15 | **fallback** | `0x140020AE0` | 433 | `fallback_id`, `fallback_host` | rotates C2 on demand |

### Filesystem & search (0, 1, 2, 6, 7)

- **`ls`** emits `[D] name` / `[F] name (N bytes)` per entry, with `...(truncated)` and `(empty directory)` sentinels. Uses `FindFirstFileW`/`FindNextFileW`.
- **`pwd`** reads a `.bss` global (`0x140028D40`); the working directory set by `cd` **persists across tasks**.
- **`find`** resolves `GetLogicalDriveStringsA` + `GetDriveTypeA` — it enumerates **every drive letter** and searches recursively, not within a single path.

### File transfer (3, 4)

Both use the `/api/fls` file service. `upload` builds a `multipart/form-data` POST (fields `type`, `key`, `task_id`, `file`; content-type `application/octet-stream`) and parses a `file_id` from the response. `download` issues `GET /api/fls?type=1&file_id=%lld&key=%s`; with no `dest` it writes to `%s\dl_%lld`.

### Execution (5, 8, 9)

- **`exec`** → `ShellExecuteW`, `verb` defaults to `open`.
- **`processes`** → `NtQuerySystemInformation`; row format `%lu|%s|%.1f|%.1f|%s|%s` (pid, name, two floats, status).
- **`kill`** → `OpenProcess` + `TerminateProcess` by `pid`.

### Persistent PowerShell (12, 13) — detection-relevant

`powershell`-init (op 12) is a **separate setup command** that spawns `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` **once**, wired to anonymous pipes (`CreatePipe` + `SetHandleInformation`), using **`CreateProcessA`**. Every subsequent `powershell` command (op 13) runs **inside that same long-lived process** by writing to its stdin, appending `\r\necho ___PWSH_END_%08X___` (randomized per command) as an output sentinel.

**Detection consequence:** you will see **one** `powershell.exe` creation, parented to a pseudoword-named binary, with redirected stdio — not repeated PowerShell spawns. Enforced limits: command > 1 MB rejected, execution > 30 s timeout.

### Capture (10)

The largest handler (17,822 bytes). GDI path (`GetDC`→`CreateCompatibleDC`→`CreateDIBSection`→`BitBlt`→`GdiFlush`) into a WIC JPEG encoder (`CreateStreamOnHGlobal`→`GetHGlobalFromStream`), uploaded as **`screenshot.jpg`** via multipart POST to `/api/fls` (content-type `image/jpeg`).

### Server-delivered modules (11, 14) — the two most significant

Both handlers share an identical fetch prologue: decrypt the endpoint string, call the HTTP core with `client+0xA0` and `client+0x43F8`, then act on the returned binary.

- **Op 11 — stealer.** 154 bytes, **no error strings.** Fetches `/api/stlbrwsr`, sleeps 3 s, and launches. The browser-stealer logic is a **server-delivered second stage**, not code inside this RAT — which is exactly why STRU could not recover it, and why it cannot be obtained without the C2 serving it. *Moderate-to-high confidence, from structural identity with the fully-traced op 14 path.*
- **Op 14 — vncpc.** **NOVEL 7th endpoint, absent from all public reporting.** Requires a `room_id` argument. Fetches `/api/vncpc`, writes it to `%LOCALAPPDATA%\<pseudoword>.exe` (`CreateFileW` GENERIC_WRITE / CREATE_ALWAYS), then launches it as `"<path> <room_id>"` via `CreateProcessW` with `CREATE_NO_WINDOW`. The dropped binary receives `room_id` as its **sole command-line argument** — the session identifier for a remote-desktop ("vnc") channel. Internal error string `Error al abrir el proceso vnc` confirms the operator's own name for it.

> **Drop-path correction:** op 14 writes to `%LOCALAPPDATA%\<pseudoword>.exe` (format `L"%s\\%s.exe"`, one pseudoword). The **nested** `AppData\Local\Packages\{random}\{random}.exe` pattern seen elsewhere is a *different* code path. Both are real; a detection regex must cover both. See [threat hunting](06-threat-hunting.md).

### C2 control (15)

**`fallback`** (433 bytes, one `sprintf`) sets a global from `fallback_id`/`fallback_host` and returns `Fallback rotated`. **C2 rotation is operator-driven and on-demand, not automatic** — relevant when reasoning about infrastructure churn.

---

## Two developer bugs (authorship signal)

Both are copy-paste artifacts useful for code-lineage analysis:

- Op 14 (`vncpc`), on missing `room_id`, emits **`exec: path required`** — the error string belonging to op 5.
- Op 15 (`fallback`), on missing args, emits **`download: args required`** / **`download: invalid args`** — strings belonging to op 4.

## Pseudoword generator — **NOVEL, shared across stages**

Drop filenames are generated by an alternating consonant/vowel scheme, length 10–15:

```c
len = (rand % 6) + 10;
for (i = 0; i < len; i++)
    name[i] = (i & 1) == 0 ? "aeiou"[rand % 5]
                           : "bcdfghjklmnpqrstvwxyz"[rand % 21];
```

Every name **starts with a vowel and strictly alternates**. Observed: `ofozuharasukizo`, `iloporafefon`, `izapukecoga`, `urutucucemel`, `erikituvicaba`. The **same generator appears in E4del's first stage and in the PINHOLE RAT**, a code-lineage link between the two families STRU tracks separately. *Moderate confidence, single shared-artifact data point.* Detection regex: `%LOCALAPPDATA%\\[a-z]{10,15}(\\[a-z]{10,15})?\.exe`.
