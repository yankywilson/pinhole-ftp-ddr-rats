# Threat Hunting Guide

Hunt hypotheses for PINHOLE and E4del, each with a rationale, a query sketch, and a stated confidence. Queries are written generically (KQL-ish / EDR-agnostic); adapt field names to your platform.

---

## Host artifacts to hunt (PINHOLE)

### H1. The `##STATUS##` process marker — **highest value**
**Hypothesis:** any `curl.exe` invocation containing `##STATUS##` on the command line is PINHOLE. Baked into the binary; rotation-proof.

```
process where process.name == "curl.exe"
  and process.command_line contains "##STATUS##"
```
**Confidence: high.** Near-zero false positives. If you hunt one thing from this repo, hunt this.

### H2. Persistent PowerShell child, redirected stdio
**Hypothesis:** a single `powershell.exe` parented to a pseudoword-named `%LOCALAPPDATA%` binary, with redirected stdin/stdout, is the PINHOLE PowerShell channel (opcodes 12/13).

```
process where process.name == "powershell.exe"
  and process.parent.executable matches "\\Users\\[^\\]+\\AppData\\Local\\[a-z]{10,15}\.exe"
  and process.command_line == "" /* driven via stdin, not args */
```
**Confidence: moderate-high.** Correlate with H1 for near-certainty.

### H3. Pseudoword drop binaries
**Hypothesis:** executables in `%LOCALAPPDATA%` whose names are 10–15 lowercase letters that **start with a vowel and alternate consonant/vowel** are PINHOLE drops (vnc/stealer modules, opcode 14/11).

```
file where file.path matches
  "\\Users\\[^\\]+\\AppData\\Local\\([a-z]{10,15}\\)?[a-z]{10,15}\.exe"
  /* then post-filter: name matches ^[aeiou](.[aeiou])*$ style alternation */
```
Observed names: `ofozuharasukizo`, `iloporafefon`, `izapukecoga`, `urutucucemel`, `erikituvicaba`, `esifubulereyog`, `eyojehiwamefotu`.
**Confidence: moderate.** The alternation pattern is distinctive but not unique; correlate with network or parent-process context.

### H4. Screenshot staging filename
**Hypothesis:** creation of a file literally named `screenshot.jpg` in a temp/appdata path by a pseudoword binary corresponds to opcode 10.
**Confidence: low-moderate** on its own; good as a correlation signal.

### H5. Working-directory + registry persistence (E4del)
E4del persists via `HKCU\...\CurrentVersion\Run` with args `['--init','<username>']`, and drops a MOTW/Zone.Identifier ADS on its payload:
```
[ZoneTransfer]
ZoneId=3
HostUrl=http://<C2>/i
```
Hunt Run-key values whose command line contains `--init` and a username matching the current user. **Confidence: moderate-high** for E4del specifically.

---

## Memory hunting (PINHOLE) — **high value**

The RAT decrypts its string pool once and caches it in `.bss`. On a live host or memory image, the plaintext constants are present even though they are encrypted on disk. Scan process memory with the memory YARA in [`detections/yara/pinhole_rat.yar`](../detections/yara/pinhole_rat.yar), or grep a memory capture for:
`##STATUS##`, `___PWSH_END_`, `/api/vncpc`, `/api/stlbrwsr`, `====D5===D6====`, `Error al abrir el proceso vnc`.
**Confidence: high.** These co-occurring in one process's memory is definitive.

---

## Network hunting

### N1. Outbound FTP to untrusted hosts
**Hypothesis:** the delivery chain reads an FTP banner from an untrusted host on port 21, launched from a script host.
```
network where destination.port == 21
  and process.name in ("wscript.exe","powershell.exe","cscript.exe","mshta.exe")
  and not destination.ip in (corporate_ftp_allowlist)
```
**Confidence: moderate-high.** Outbound FTP from a script host is rare and suspicious in most enterprises.

### N2. DDR-then-Worker sequence
**Hypothesis:** a host that fetches one of the known Pinterest pins or the SurveyMonkey survey and *then* connects to a `*.workers.dev` host is resolving PINHOLE C2.
Hunt the ordered pair within a short window. **Do not block the platforms.** **Confidence: moderate** (behavioural, correlation-only).

### N3. No-User-Agent keep-alive to workers.dev
Flows to `*.workers.dev` with `Connection: keep-alive`, `Accept: */*`, and **no `User-Agent`** match PINHOLE's direct-to-Worker requests. **Confidence: low alone; enrichment only.**

---

## Infrastructure pivots (proactive)

### P1. FTP Stats Panel siblings
The operators run an "FTP Stats Panel" on **port 5000** that tracks executions, total connections, and unique active/blocked IPs. Pivot on that HTML field-set to find sibling panels:
```
Censys:  services.port: 5000 and services.http.response.body: /* stats-panel field fingerprint */
Shodan:  port:5000 <panel-specific string>
```
Seed hosts observed alongside the campaign: `209.99.185.38`, `69.48.228.126`. **Confidence: moderate** — a distinctive field-set makes this a productive hunt.

### P2. FTP banner-abuse scan (the original technique)
STRU's published FOFA query, generalized:
```
FOFA:    (banner="conhost.exe --headless" || banner="bitsadmin" || banner="powershell"
          || banner="System.Net.WebClient") && port="21"
Censys:  services.port: 21 and services.banner: {"powershell","bitsadmin","System.Net.WebClient","conhost.exe --headless"}
Shodan:  port:21 "System.Net.WebClient"   (run each banner string separately)
```
**Confidence: high** for finding banner-DDR infrastructure of this class (not PINHOLE-exclusive).

### P3. DDR family enumeration
The two Pinterest pins differ only in trailing digits; the operator account likely holds more, and SurveyMonkey short-codes are enumerable. Enumerating the account's other pins can surface additional C2 pointers and new Worker domains. **Confidence: moderate.**

### P4. Cloudflare Worker epoch-name pattern — **OPEN, investigate don't alert**
If the `worker-<epoch>-<rand>.api-<hex>.workers.dev` naming holds (see [network](04-network-and-c2.md)), collect the family's Workers and test the epoch decode for timeline anchoring. **Confidence: low — hypothesis under test.**

---

## E4del-specific hunts

- **Per-host build separation:** each E4del payload host serves a distinct build with a distinct hardcoded C2. Retro-hunt any `discord.exe` running from `%LOCALAPPDATA%\discord\` launched with a `--init` argument. See [E4del analysis](08-e4del-analysis.md).
- **New C2 `51.89.199.118`** (extracted here, not in public reporting) — retro-hunt outbound `ws://51.89.199.118/ws/ds?...` and `/ws/agent?...`.
- **Second unencrypted WebSocket** for desktop streaming (`/ws/agent`, raw JPEG every 2 s) can point at a **different IP** than the command C2 — hunt for the stream endpoint independently of the C2 address.

---

## Prioritization for a first hunt

1. **H1** (`##STATUS##`) and the **memory YARA** — definitive, cheap.
2. **N1** (outbound FTP from script host) — catches delivery early.
3. **H2 + H3** (persistent PowerShell + pseudoword drop) — correlate for the RAT itself.
4. **P2/P1** — proactive infrastructure discovery if you have Censys/Shodan.
