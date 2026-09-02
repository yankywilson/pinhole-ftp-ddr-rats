# Attribution & Assessment

All judgements use ICD-203 estimative language. Confidence reflects evidence strength, not certainty. Where prior public reporting and this analysis diverge, both are stated.

## Attribution posture

**No actor attribution.** STRU stated the evidence is insufficient to attribute these clusters to a named actor, and this analysis found nothing to change that. What the samples *do* support is a language and regional assessment, below. E4del and PINHOLE are tracked as **separate clusters sharing a delivery technique**, consistent with STRU; this analysis adds a **code-lineage link** (shared pseudoword generator) that slightly raises the possibility of a shared developer or toolkit — see below.

## Language / developer assessment — **NOVEL, moderate-high confidence**

The PINHOLE final stage contains **developer-facing error strings in Spanish**, stored in its encrypted string pool (i.e. internal diagnostics, not user-visible localization):

- `Error al obtener LOCALAPPDATA. Código: %lu`
- `Error al crear archivo. Código: %lu`
- `Error al escribir. Código: %lu`
- `Error al abrir el proceso vnc. Código: %lu`

Public reporting notes Spanish in the **dropper lures**. This analysis finds Spanish in the **compiled RAT's own internal error handling**, which is a stronger signal: localization targets victims, but internal diagnostics are how the developer talks to themselves.

**Assessment:** the PINHOLE developer is a **Spanish speaker**. *Moderate-high confidence*, based on multiple internal (non-victim-facing) Spanish strings in the compiled binary.

## Targeting / victimology — **moderate confidence (LATAM lean)**

Consistent indicators pointing to Latin America / Spanish-language targeting: Spanish voucher-style lures, `mx.pinterest.com` resolver subdomain, a Mexican-TLD staging domain (`farolesa[.]mx`), an `mx`-suffixed C2 domain, and the internal Spanish strings above. Observed victim geography in public reporting also leans LATAM (a minority of claimed victims are US).

**Caveat:** the DDR technique and the implant are fully portable. This is best framed as a **capability-based concern for any region**, defensible for non-LATAM defenders on portability grounds rather than observed victimology. *Moderate confidence on the LATAM lean; low confidence that targeting is LATAM-exclusive.*

## Code-lineage between E4del and PINHOLE — **moderate confidence**

The **same pseudoword filename generator** (alternating consonant/vowel, length 10–15, vowel-initial) appears in **E4del's first stage and in the PINHOLE RAT**. STRU tracks the two as separate clusters. A shared, non-trivial code artifact is consistent with either a shared developer, a shared toolkit, or code copying. *Moderate confidence that a code relationship exists; this does not establish common operation.* Two copy-paste error-string bugs in PINHOLE (opcodes 14 and 15 emitting other handlers' error strings) are additional authorship texture but do not bear on the E4del link.

## Capability / intent assessment

| Assessment | Confidence | Basis |
|------------|-----------|-------|
| Goal is credential theft, data theft, durable remote access | Moderate | Browser-stealer module (op 11), file up/download (op 3/4), persistent PowerShell (op 12/13), vnc module (op 14), registry persistence |
| Actively maintained tooling | Moderate-high | RAT compiled ~48 h before collection; loader constants and payload sizes drift build-to-build; per-host E4del builds |
| Operator practises target selection | Low-moderate | E4del's `--init` username gate implies the operator knew the victim username pre-delivery (single-sample, **candidate** finding) |
| Ransomware capability | **Low / watch-item** | No encryptor, ransom note, or leak site observed in any sample or in public reporting |
| Well-resourced network tradecraft | Moderate-high | Custom Schannel HTTP stack bypassing WinINet/WinHTTP hooks and proxies; DDR + Cloudflare Worker fronting; on-demand C2 rotation |

## Corroboration vs. prior reporting

**Confirmed from the sample (CORROBORATED):** FTP-banner DDR delivery; Pinterest/SurveyMonkey resolvers behind Cloudflare Workers; Halo's Gate + Early Bird APC into `ApplicationFrameHost.exe`; tiered jitter beaconing (E4del); shellcode fluctuation keeping one 4 KB page decrypted; FTP Stats Panel on port 5000; browser-stealer capability (documented from the command path, module server-side).

**Extended beyond reporting (NOVEL):** full 16-opcode command set; API-hash algorithm; Donut cipher fork; string cipher; `/api/vncpc`; `##STATUS##` marker in-binary; Spanish developer strings; E4del per-host builds and new C2; validated tooling.

**Corrected (CORRECTION):** command count 14 → 16; `swprintf` → `wsprintf​W`; `GlobalLock`/`GlobalSize` hash swap; build-specific loader constants must not be used as cross-build IOCs; vnc drop path is `%LOCALAPPDATA%\<pseudoword>.exe` (single-level) in addition to the nested package path.

## Open items (explicitly unverified)

- Cloudflare Worker epoch-name hypothesis (P4) — **OPEN.**
- Page-cipher byte-0 derivation formula — **OPEN** (needs a second build; operationally irrelevant).
- Two API-hash values (`0xAD4EADA5`, `0xBCB57F48`) — computed, **names pending**.
- Liveness of the resolver pins post-2026-08-21 disclosure — **not re-confirmed.**
- `crypto32.node` (E4del privilege-escalation native addon), `/api/stlbrwsr` and `/api/vncpc` payloads — **server-side only, never recovered** (by STRU or here).
- Build A E4del C2 — behind a VM-obfuscated `index.js` (`vmm_46e43a`), **unrecovered.**
