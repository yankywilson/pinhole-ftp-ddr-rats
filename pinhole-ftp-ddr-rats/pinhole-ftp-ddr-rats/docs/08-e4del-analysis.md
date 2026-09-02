# E4del RAT — Analysis, Per-Host Builds, New C2

E4del is the second family in the campaign: a **Node.js RAT running inside a trojanized, signed Discord Electron bundle**. The Discord runtime is genuine and unmodified; only `discord/resources/app.asar` → `app_bootstrap/index.js` is replaced. Analysis below is primarily from **Build B** (`4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1`, from `51.89.199.125/i`), whose `index.js` is plaintext.

## Delivery & anti-sandbox — **CORROBORATED + detail**

Delivery: FTP banner (port 21) carries a PowerShell one-liner → downloads the bundle → expands to `%LOCALAPPDATA%\discord\` → runs `discord.exe --init <username>`.

**Anti-sandbox gate:** `os.userInfo().username` is compared to the `--init` argument. The comparison uses loose equality (`!=`, not `!==`). On mismatch the process exits. **Implication:** the operator supplied the victim's username at delivery time, implying **targeted delivery rather than spray-and-pray**. *Candidate finding, uncorroborated, single sample.*

## Execution modes — **NOVEL detail (from Build B source)**

| Arg | Behaviour |
|-----|-----------|
| `--e` | Loads `crypto32.node` in-process (privilege escalation), exits |
| `--a` | Sets `isAdmin = true` |
| `--init <user>` | Normal operation, username gate |
| anything else | `process.exit(0)` |

## Persistence — **CORROBORATED**

`app.setLoginItemSettings({openAtLogin:true})` → `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` with args `['--init','<username>']` and the full path to `discord.exe`. The download leaves a **Zone.Identifier ADS (MOTW)** on the payload:
```
[ZoneTransfer]
ZoneId=3
HostUrl=http://51.89.199.125/i
```
Recover with `Get-Content "$env:USERPROFILE\Downloads\i" -Stream Zone.Identifier`.

## Transport & crypto — **NOVEL detail**

- Custom WebSocket over a **raw `net.Socket`** (not the `ws` library, not browser WebSocket): `ws://[C2]/ws/ds?hostId=<user-hostname>&hwid=<hash>`.
- **AES-256-CBC** both directions, key = `SHA256("protected!")`, random 16-byte IV prepended per message.
- Field/pipe delimiter `%e4del%`.
- HWID = `sha256(all_MACs)[:8] + "-" + sha256(cpu_model_alnum[:20])[:8]` (`+ "-admin"` when `--a`); hostId = `<username>-<hostname>`.

**Beacon jitter ladder** (matches STRU): active <20 s → 200–2000 ms; semi-active 20–40 s → 2000–5000 ms; inactive >40 s → 5000–9000 ms; all ±20%. Emits V8 memory-pressure every 3 s to evict the heap (anti-forensics).

> **Discrepancy (OPEN):** public reporting describes E4del C2 as `POST /beacon` heartbeats. Build B source shows WebSocket `/ws/ds`. This is either build divergence or a correction to the reporting; it is flagged, not resolved.

## AV detection — **NOVEL detail**

Two-stage AV enumeration: WMI `root\SecurityCenter2 AntivirusProduct`, **plus** a registry uninstall-key scan (`findstr` over `avast|kaspersky|eset|symantec|crowdstrike|defender|mcafee|sophos`). The registry fallback exists specifically because **CrowdStrike Falcon does not register with `SecurityCenter2`**. The detected AV name rides in **every heartbeat** as an operator decision point — against a Falcon host the operator can suppress the child-process-spawning commands and keep only the safe ones (`screenshot`, `streamstart`). See the defensive note in [detection guide](05-detection-guide.md).

## Command set — **11 handlers, fully reversed (Build B)**

| Command | Action |
|---------|--------|
| `startcmd` | persistent `cmd.exe`, stdout+stderr → buffer |
| `runcmd%e4del%<cmd>` | write to the shell's stdin |
| `screenshot` | 1920×1080 JPEG q30 via desktopCapturer, base64 in next heartbeat |
| `streamstart <ip>` | **second unencrypted WS** to `/ws/agent?hostId=<hwid>`, JPEG every 2 s; `<ip>` may differ from C2 |
| `streamstop` | close stream socket |
| `plugin%e4del%<file>%e4del%<b64>` | write blob to `resourcesPath` |
| `filedownload%e4del%<token>` | `GET /api/download?token=&clientId=` → save |
| `runpackage%e4del%<token>` | download zip → `%LOCALAPPDATA%\Packages\<token>\` → Expand-Archive → run `config.json` entrypoint (then delete config), fully orphaned (`detached`, `unref`) |
| `elevate` | `exec("discord.exe --e discord.exe --a")` — self-re-exec loading `crypto32.node` |
| `disconnect` | `process.exit(0)` |
| *default* | `exec(<task>, timeout 15000)` |

STRU reports "eight commands"; Build B source exposes eleven handlers plus the default. The **streaming channel** (`/ws/agent`, raw unencrypted JPEG, can target a different IP than the command C2) is a notable detection gap — defenders watching the C2 address see no video.

## Per-host build separation — **NOVEL (high confidence)**

Each E4del payload host serves a **distinct `app.asar`** — different SHA256, different size, different hardcoded C2 — while the Discord runtime is byte-identical across builds.

| Build | Host | Bundle SHA256 | Size | index.js | C2 |
|-------|------|---------------|------|----------|-----|
| A | `54.37.237.164` | `2cb20f04…5851d` | 94,269,199 | 168,394 B, VM-obfuscated | **Unknown** (behind `vmm_46e43a`) |
| B | `51.89.199.125` | `4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1` | 94,226,860 | 30,212 B, plaintext | **`51.89.199.118`** |
| Public | `157.254.194.31` | `117b2b7e…d731c` (d.zip) | 89.86 MB | `e0c41dc4…320ddb` | `157.254.194.31` (STRU) |

**TLSH** Build A `T1462833253601EA17EDD3C17B0FEFF996BE179DE3AE2058D829213933B613889AC1D154`, Build B `T1102833642606E617EDD3C17B0BDFB996BD27DCE79E206CD829223A33B543988BC0D154` — **distance 27** on ~90 MB files (unrelated files score in the hundreds). Same builder, same base bundle, different payload build; Build A is newer. *Moderate-high confidence.*

**Key result:** Build B's C2 is **`51.89.199.118`**, delivered from `51.89.199.125/i` — a **new indicator not in public reporting**, recovered by diffing this build's plaintext `index.js` (reconnect list `WS_ENDPOINTS = ['ws://51.89.199.118', ...]`).

## Reconnect logic

`BASE_DELAY 5000 ms`, exponential backoff `min(5000 * 2^attempt, 60000)`, and **after 5 failures the malware rotates to the next entry in `WS_ENDPOINTS`** (only one live entry in Build B; the others are commented-out placeholders).

## `crypto32.node` — **unrecovered (by STRU and here)**

The privilege-escalation module is a native PE addon (`crypto32.node`) loaded in-process via `require(...).start(file, params)` — **no `CreateProcess` telemetry**. Its mechanism (token impersonation / UAC bypass / kernel exploit) is unknown; it was absent from every sandbox run and every artifact. **OPEN.**
