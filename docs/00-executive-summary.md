# Executive Summary

**Audience:** IR leads, SOC managers, CTI leadership. For technical depth, follow the links.

## The short version

E4del and PINHOLE are two remote-access trojans that share one novel delivery trick: they read their next-stage commands out of **FTP server greeting banners** used as dead-drop resolvers. The technique was first spotted by MalwareHunterTeam in July 2026 and the two RAT families were named and documented by the SOCRadar Threat Research Unit (STRU) on 2026-08-21.

This repository is an **independent, sample-driven teardown** that goes substantially further than the public reporting. It reconstructs the full command protocol, breaks the malware's cryptography and API-hiding, documents a previously-unreported module, and ships **validated detection content and tooling** — none of which exists in any public source today.

## What a defender needs to know

- **PINHOLE is the more dangerous of the two.** It is a multi-stage, heavily-obfuscated x64 implant with **16 operator commands** (not 14 as reported), including a browser-credential stealer and a remote-desktop ("vnc") module. It resolves its command server from **Pinterest pins and a SurveyMonkey survey**, proxies through **Cloudflare Workers**, and speaks a **custom TLS stack** that bypasses WinINet/WinHTTP hooks and corporate proxy logging.
- **The single best detection is host/process-level, not network.** PINHOLE shells out through a hardcoded `curl.exe` command line containing the literal marker **`##STATUS##`**. This string is baked into the binary, survives every infrastructure change, and is trivial to alert on. See [threat hunting](06-threat-hunting.md).
- **Network blocking alone will not contain this.** The DDR design means blocking one C2 IP accomplishes nothing — the malware simply re-reads a Pinterest pin for the next one. Detection has to sit on the host behaviour and the delivery chain, not on C2 addresses.
- **The delivery chain is loud in one specific way.** Infection begins with a phishing ZIP → LNK → PowerShell that makes an **FTP connection to an untrusted server on port 21** to read the banner. Outbound FTP to unknown hosts is anomalous in most enterprises and is a strong early-stage signal.

## What is genuinely new in this analysis

1. **The complete command set** — all 16 opcodes reverse-engineered from the dispatcher, versus "14 commands, unenumerated" in public reporting.
2. **The cryptography is broken** — the loader's custom Donut cipher fork, the RAT's string cipher, and the API-hash algorithm are all recovered and reproduced in code.
3. **A module nobody documented** — `/api/vncpc`, a remote-desktop capability keyed by a `room_id` session argument.
4. **Attribution signal** — internal, developer-facing error strings are in **Spanish**, indicating a Spanish-speaking developer rather than merely a localized lure.
5. **E4del infrastructure expansion** — each E4del payload host serves a *different* build pointing at a *different* C2; this analysis recovered a **new C2 (`51.89.199.118`)** from a build the original reporting never touched.

## Risk framing (graded)

- **End goal:** credential theft, data theft, and durable remote access. *Moderate confidence*, based on the stealer module, file up/download, persistent PowerShell, and the vnc module.
- **Ransomware:** no evidence. No encryptor, ransom note, or leak site observed. *Low confidence / watch-item only.*
- **Targeting:** lures and infrastructure lean **Latin America / Spanish-language** (Spanish voucher lures, `mx.pinterest.com` resolvers, a Mexican-TLD domain, Spanish internal strings). The technique is fully portable, so this is a defensible concern for any region on capability grounds rather than observed victimology. *Moderate confidence on the LATAM lean.*

## Bottom line

The DDR delivery technique is the headline, but the operationally important fact is that **PINHOLE is a capable, well-engineered implant with a stealthy custom network stack, and the public reporting under-describes it.** The detection and hunting content in this repository is designed to catch it on the host, where it is most exposed, rather than chasing rotating infrastructure.
