# Detection Guide — Deploying & Tuning the Rules

This guide explains what each detection in [`detections/`](../detections/) catches, its expected fidelity, and how to tune it. **Validate everything in your own environment before production.** Rules are ordered by fidelity — deploy top-down.

## Fidelity tiers

| Tier | Meaning | Deploy as |
|------|---------|-----------|
| **A — High** | Anchored to a hardcoded, build-stable artifact unique to the malware | Alert |
| **B — Medium** | Behavioural pattern strongly associated with the family, some FP surface | Alert with tuning / hunt |
| **C — Contextual** | Weak on its own, valuable in correlation | Hunt / enrichment |

---

## Tier A — deploy as alerts

### A1. `##STATUS##` curl marker (host/process) — Sigma
**File:** [`detections/sigma/pinhole_curl_status_marker.yml`](../detections/sigma/pinhole_curl_status_marker.yml)

Matches process creation of `curl.exe` with the literal `##STATUS##` in the command line. This string is baked into the RAT (recovered from its encrypted string pool) and is the family's most durable signature — it survives every infrastructure rotation. Expected FP rate near zero; `##STATUS##` is not a normal curl format token.

### A2. RAT string-pool constants (memory/on-disk) — YARA
**File:** [`detections/yara/pinhole_rat.yar`](../detections/yara/pinhole_rat.yar)

Two rules: one keyed on the plaintext string pool as it exists **in memory** on a running host (`##STATUS##`, `___PWSH_END_`, `/api/vncpc`, `/api/stlbrwsr`, the DDR delimiters, the Spanish vnc error), and one keyed on the fake-JPEG **loader container** on disk. The memory rule is high-fidelity because these strings are decrypted and cached in `.bss` at runtime; scan process memory or a memory image.

### A3. Loader container fake-JPEG header (on-disk) — YARA
Included in A2's file. Matches the invalid `FF D8 FF E0 … 67 10` header with no `JFIF` marker. Because the loader constants are per-build, this rule keys on the **structural** invariant (malformed APP0), not build-specific bytes.

---

## Tier B — deploy with tuning

### B1. Persistent PowerShell child with redirected stdio — Sigma
**File:** [`detections/sigma/pinhole_persistent_powershell.yml`](../detections/sigma/pinhole_persistent_powershell.yml)

PINHOLE spawns `powershell.exe` **once**, parented to a pseudoword-named binary in `%LOCALAPPDATA%`, wired to anonymous pipes. Tune the parent-image regex to your environment; legitimate automation can parent PowerShell, but rarely from a random-named LOCALAPPDATA binary with the alternating-consonant/vowel pattern.

### B2. Pseudoword binary in LOCALAPPDATA — Sigma
**File:** [`detections/sigma/pinhole_pseudoword_drop.yml`](../detections/sigma/pinhole_pseudoword_drop.yml)

Process creation or file creation matching `%LOCALAPPDATA%\<10-15 lowercase>.exe` **or** `%LOCALAPPDATA%\Packages\<10-15 lowercase>\<10-15 lowercase>.exe`, where the name is all lowercase and alternates consonant/vowel. Covers both the vnc drop path and the nested package path. FP surface: some legitimate apps use random names — correlate with B1 or network activity.

### B3. FTP banner retrieval via LNK/PowerShell (delivery) — Sigma + Suricata
**Files:** [`detections/sigma/pinhole_ftp_banner_delivery.yml`](../detections/sigma/pinhole_ftp_banner_delivery.yml), [`detections/suricata/pinhole_e4del.rules`](../detections/suricata/pinhole_e4del.rules)

The delivery chain makes an outbound **FTP connection (port 21) to an untrusted host** to read the banner, typically launched from a script host (`wscript`/`powershell`) spawned by an LNK. Outbound FTP to non-corporate hosts is anomalous in most enterprises. Tune the Suricata rule's `$FTP_SERVERS`/`$HOME_NET` to exclude your legitimate FTP.

### B4. DDR resolution to Pinterest/SurveyMonkey followed by Cloudflare Worker — Suricata
**File:** included in `pinhole_e4del.rules`

Flags the *sequence* of a host fetching a specific Pinterest pin / SurveyMonkey survey and then connecting to a `*.workers.dev` host. Neither leg is malicious alone — this is a correlation/hunt rule, not a standalone block. **Do not block Pinterest, SurveyMonkey, or workers.dev wholesale.**

---

## Tier C — correlation / enrichment

### C1. FTP Stats Panel fingerprint (infrastructure hunting) — Suricata/Censys
The operators expose an "FTP Stats Panel" on port 5000 tracking executions and connected IPs. Use the field-set fingerprint in [threat hunting](06-threat-hunting.md) to find sibling panels via Censys/Shodan; not an endpoint-detection rule.

### C2. No-User-Agent HTTP with keep-alive to Worker hosts — Suricata
The direct-to-Worker request omits `User-Agent` and sends `Connection: keep-alive`, `Accept: */*`. Extremely weak alone; useful only as an enrichment tag on flows already suspect from B3/B4.

---

## What intentionally has **no** network-IP rule

The DDR design means C2 IPs rotate freely and blocking them is low-value. IP indicators are provided in [`ioc/`](../ioc/) for retro-hunting and enrichment, **not** as recommended blocklist entries. Prioritize the host-level Tier A/B detections.

## Tuning checklist

1. Deploy A1–A3 first; they are the safest.
2. Baseline B1/B2 against 30 days of normal LOCALAPPDATA execution before alerting.
3. Set Suricata `$HOME_NET`, `$FTP_SERVERS`, and any legitimate `workers.dev` usage before enabling B3/B4.
4. Wire A1 (`##STATUS##`) and B1 (persistent PowerShell) into a correlation rule — co-occurrence is near-certain PINHOLE.
5. Re-baseline after any AV/EDR change; the RAT's AV-detection logic (below) changes its own behaviour based on what it finds.

## Note on the RAT's AV-awareness

E4del enumerates installed AV (WMI `SecurityCenter2` **plus** a registry-uninstall-key fallback specifically to catch CrowdStrike Falcon, which does not register with `SecurityCenter2`) and reports it in every heartbeat as an operator decision point. Against a Falcon host, operators can suppress the noisier commands. This means **absence of loud behaviour does not mean absence of infection** — lean on the memory YARA (A2) and the delivery-chain rules (B3) which the operator cannot selectively disable.
