# Indicators of Compromise

Machine-readable version with confidence and notes: [`indicators.csv`](indicators.csv).

**Confidence** reflects evidence strength (see [evidence standard](../README.md#evidence-standard)). **Do not blocklist Cloudflare anycast IPs** (`104.21.x.x`, `172.67.x.x`) — they front many benign sites. Because this is a DDR family, C2 IPs rotate; prioritize host detections and the delivery chain over IP blocking.

## Highest-value indicators

| Indicator | Type | Why it matters |
|-----------|------|----------------|
| `##STATUS##` | in-memory string | PINHOLE curl marker; rotation-proof host signature. Encrypted on disk, plaintext in process memory. |
| `___PWSH_END_%08X___` | on-disk string | PINHOLE persistent-PowerShell sentinel; plaintext in the RAT PE. |
| `/api/vncpc` | URI | **NOVEL** PINHOLE endpoint (vnc module), not in public reporting. |
| `51.89.199.118` | IPv4 | **NEW** E4del C2 (Build B), recovered here, not in public reporting. |
| `%e4del%` | string | E4del message delimiter. |

## Hashes

**PINHOLE**

- RAT (x64): `a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58` (MD5 `f96b4ee5565377a3caf9cc39f386160f`)
- Layer-1 container (`/api/bc`): `78cd264a29e21b79035772faa4615e2bb1d795d15983ab1a3bc4e25d262e3840`
- Loader stage (decoded, 15,552 B): `89495a1b14cf37d1824af6937956efdc748ea3edb0e84c1e82d89b60cba451b1`
- STRU-reported second stage (unconfirmed, not on VT/MB/Triage): `af769f3bff848bac7b73bf749769424b3df6c9175388980d99e0d6d0193237ba`

**E4del**

- Bundle Build B (from `51.89.199.125/i`): `4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1`
- Build B `app.asar`: `c25fd7e24d2e59cd23901585a0d856ff3e0aece91298975b9f22d210a677afb7`
- Bundle Build A (from `54.37.237.164`, VM-obfuscated): `2cb20f04bef481b0b77f32f5cf592caacfb721656da21ba2b64315941575851d`
- Bundle (STRU published): `117b2b7e7c0deee1f7bf0f154babc09738eac18e810625fab4f54dc8088d731c`

## Network

**C2 / delivery (actionable)**

- E4del C2 (Build B, new): `51.89.199.118`
- E4del delivery hosts: `51.89.199.125` (`/i`), `54.37.237.164`
- E4del C2 (STRU): `157.254.194.31`; host `167.148.41.164`
- PINHOLE delivery + FTP banner + stats panel: `209.99.185.38`; stats host `69.48.228.126`

**Cloudflare anycast (enrichment only — do NOT block):** `104.21.44.124`, `104.21.85.250`, `172.67.199.190`, `172.67.212.254`

**Domains**

- `farolesa.mx` (registered 2024-07-05, live at analysis), `www.farolesa.mx`, `verificar.farolesa.mx` (WebDAV `\\verificar.farolesa.mx@80\pub\Verificar.js` — DNS not re-confirmed)
- `nokierojotiarmx.com` (C2 behind Worker)
- `worker-1785198984-xsekhi.api-62c3cac6.workers.dev` (epoch-in-name → 2026-07-28, candidate)

**DDR resolver pages** (liveness not re-confirmed after 2026-08-21 disclosure)

- `https://mx.pinterest.com/pin/1128292512937332995`
- `https://mx.pinterest.com/pin/1128292512937332894`
- `https://www.surveymonkey.com/r/WW5NVT6` (tertiary, never queried in observed runs)

## Endpoints & host artifacts

- PINHOLE C2 URIs: `/api/health`, `/api/client`, `/api/tsk`, `/api/bc`, `/api/fls`, `/api/stlbrwsr`, **`/api/vncpc`**
- E4del WebSocket URIs: `/ws/ds` (command), `/ws/agent` (unencrypted stream)
- Pseudoword drop path: `%LOCALAPPDATA%\<pseudoword>.exe` or `%LOCALAPPDATA%\Packages\<x>\<x>.exe` — names 10–15 lowercase, vowel-initial, alternating consonant/vowel. Observed: `ofozuharasukizo`, `iloporafefon`, `izapukecoga`, `urutucucemel`, `erikituvicaba`, `esifubulereyog`, `eyojehiwamefotu`
- E4del persistence: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value with args `['--init','<username>']`
- FTP stats panel: port `5000`

## Correction notice (indicator hygiene)

The ETag `"6a809184-59e6f0f"` belongs to **E4del Build A** (`54.37.237.164`), not the PINHOLE Cloudflare Worker; earlier handoff material misattributed it. Per-build loader XOR keys and page-cipher keys are **build-specific** and must not be used as cross-build indicators — only the 15,552-byte decoded-stage size is stable across builds.
