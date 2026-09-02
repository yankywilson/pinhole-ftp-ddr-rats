# Network & C2 — DDR Chain, Cloudflare Worker, Custom TLS

## The dead-drop-resolver chain — **CORROBORATED + detail**

PINHOLE never carries a C2 address in the clear. It resolves one through a three-hop chain:

1. **FTP banner** (port 21) on a delivery host returns a PowerShell one-liner that fetches the next stage. The stager reads the C2 pointer out of the banner text itself.
2. **Dead-drop resolvers** — the second-stage config points at legitimate high-reputation platforms whose page HTML carries the real C2 between delimiter markers:
   - `hxxps://mx.pinterest[.]com/pin/1128292512937332995`
   - `hxxps://mx.pinterest[.]com/pin/1128292512937332894/`
   - `hxxps://www.surveymonkey[.]com/r/WW5NVT6` (tertiary; not queried in observed runs)
3. **Cloudflare Worker proxy** — traffic to the real C2 is fronted by a `*.workers.dev` subdomain so the origin is never contacted directly.

The C2 address is embedded in the resolver page between the markers `====D5===D6====` and `====D7===D8====`. **These delimiters were recovered directly from the RAT binary** (encrypted string pool) — see [internals](02-pinhole-internals.md). The two Pinterest pin IDs differ only in their final digits, so the operator account almost certainly holds more pins; SurveyMonkey short-codes are similarly enumerable. This is a **DDR-enumeration hunting surface** — see [threat hunting](06-threat-hunting.md).

## Cloudflare Worker naming — **NOVEL candidate (low-moderate confidence)**

One observed Worker: `worker-1785198984-xsekhi.api-62c3cac6.workers.dev`. The 10-digit numeric field decodes as a Unix epoch:

```
1785198984 → 2026-07-28 00:36:24 UTC
```

This lands squarely inside the campaign window and looks like a provisioning timestamp baked into the Worker name. **This is a single decode landing in a plausible range — suggestive, not confirmed.** Corroboration path: collect other `worker-<10 digits>-<6 chars>.api-<8 hex>.workers.dev` subdomains and test whether the numeric field consistently resolves to sane dates. If it holds, it yields free timeline anchoring on every Worker in the family. **Status: OPEN — do not publish as fact.**

## Custom TLS / HTTP stack — **NOVEL (high confidence)**

PINHOLE's network layer (`FUN_14000230D`) is built on **raw Winsock + Schannel SSPI**. It uses **no WinINet, no WinHTTP, and no Windows HTTP API** — it performs its own TLS handshake via `AcquireCredentialsHandleA` / `InitializeSecurityContextA` and speaks HTTP/1.1 with chunked transfer-encoding directly over the socket. Port is hardcoded `htons(0x1BB)` = 443. The Schannel package string is `Microsoft Unified Security Protocol Provider`.

**Defensive consequences — this is why the RAT is quiet on the network:**

| Control | Effect |
|---------|--------|
| EDR hooks on WinINet/WinHTTP | **Never fire** — those libraries are not used |
| System/corporate proxy | **Ignored** — no proxy artifacts, proxy logs are blank |
| WinHTTP session artifacts | **None** to find |
| JA3/JA3S | Looks like a native Windows app, not a browser |

The exact request shape (recovered from the string pool): request line `%s %s HTTP/1.1\r\n`, then `Host: %s\r\nConnection: keep-alive\r\nAccept: */*\r\n` — **no `User-Agent` header at all**, which is itself a weak network tell for the direct-to-Worker path.

### curl fallback path — **NOVEL (high confidence)**

Alongside the Schannel stack, the RAT carries a hardcoded `curl.exe` command line (recovered from the string pool):

```
curl.exe -s -w "\n##STATUS##%{http_code}" -- "<url>"
```

The `##STATUS##` marker is the RAT's own HTTP-status delimiter and `--` is curl's argument terminator. This is the **single most durable signature** for the family — it is baked into the binary and survives every infrastructure rotation. Detection detail in [threat hunting](06-threat-hunting.md).

## Endpoints — **CORROBORATED + 1 NOVEL**

Confirmed C2 endpoints (all reached via the custom stack):

| Endpoint | Purpose |
|----------|---------|
| `/api/health` | liveness / heartbeat |
| `/api/client` | registration (19-field JSON) |
| `/api/tsk` | task polling |
| `/api/bc` | second-stage container delivery |
| `/api/fls` | file service (upload/download/screenshot) |
| `/api/stlbrwsr` | browser-stealer module delivery |
| **`/api/vncpc`** | **NOVEL — remote-desktop module delivery** |

## E4del network behaviour — **see dedicated doc**

E4del uses a different transport (custom WebSocket on a raw socket, AES-256-CBC) and exhibits per-host build separation with distinct C2s. Covered in [E4del analysis](08-e4del-analysis.md).

## Infrastructure note & caveat

The banner-server and resolver indicators in [`ioc/`](../ioc/) were current at time of analysis. Because the DDR design decouples the implant from any single C2, **blocking C2 IPs is low-value**; prioritize the delivery chain and host behaviour. STRU published on 2026-08-21, giving operators lead time — the FTP servers and the two Pinterest pins are the indicators most likely to have rotated. **Liveness of the resolver pins was not re-confirmed in this analysis and is carried as OPEN.**
