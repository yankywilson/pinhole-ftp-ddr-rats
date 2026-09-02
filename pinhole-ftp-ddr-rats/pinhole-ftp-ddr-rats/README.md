# PINHOLE & E4del — Independent Reverse Engineering, Detection & Threat-Hunting Reference

**A verification-first teardown of two FTP-banner dead-drop-resolver RATs, going well past the original public reporting.**

> **Status:** Active research · **Last updated:** 2026-09-01
> **Scope:** Independent analysis of the PINHOLE multi-stage RAT and the E4del Electron RAT, the two malware families first disclosed by the SOCRadar Threat Research Unit (STRU) on 2026-08-21. This repository is **not** affiliated with SOCRadar. It corroborates their work where the evidence supports it, corrects it where it does not, and adds a large body of new reverse-engineering, detection content, and tooling that has not been published anywhere else.

---

## Why this repository exists

The public reporting on E4del and PINHOLE — one STRU blog and roughly a dozen downstream news rewrites — establishes *that* these families exist and *what they do at a high level*. None of it publishes the internals a defender actually needs: the command protocol, the cryptography, the API-resolution scheme, or a single detection artifact. As of this writing there is **zero** published YARA, Sigma, Suricata, or config-extraction tooling for either family, and three of PINHOLE's modules were left explicitly unrecovered.

This project fills that gap from the samples up. Every claim here is graded, every novel finding is separated from corroboration of prior work, and every piece of tooling is **round-trip validated against the samples** before it ships. Where a finding could not be verified, it is labelled as such rather than omitted or overstated.

### What is new here (not in any public source)

| # | Finding | Section |
|---|---------|---------|
| 1 | **Complete 16-opcode command dispatcher** reconstructed from the binary (public reporting says "14 commands", enumerates none) | [Command protocol](docs/03-pinhole-command-protocol.md) |
| 2 | **API-hashing algorithm fully recovered and validated** (seed `0x9E3779B9`, MurmurHash3 finalizer constant) — resolves the entire import set from a 4-line function | [Internals](docs/02-pinhole-internals.md) |
| 3 | **Custom Donut cipher fork** (24-round modified Chaskey, not stock) — explains why every public Donut unpacker fails on this sample | [Loader chain](docs/01-pinhole-loader-chain.md) |
| 4 | **String-obfuscation cipher** (PCG-derived per-byte keystream) cracked — 36 plaintexts recovered | [Internals](docs/02-pinhole-internals.md) |
| 5 | **Undocumented 7th endpoint `/api/vncpc`** and its full drop-and-launch protocol with `room_id` session argument | [Command protocol](docs/03-pinhole-command-protocol.md) |
| 6 | **`##STATUS##` curl marker recovered from the binary** — the single most durable host/process signature, survives all infrastructure rotation | [Threat hunting](docs/06-threat-hunting.md) |
| 7 | **Developer is a Spanish speaker at the code level** — internal error strings, not just lure localization | [Attribution notes](docs/07-attribution-and-assessment.md) |
| 8 | **E4del per-host build separation** — each payload host serves a distinct payload with a distinct C2 (TLSH distance 27) | [E4del analysis](docs/08-e4del-analysis.md) |
| 9 | **New E4del C2 `51.89.199.118`** extracted from a build the original reporting never analyzed | [E4del analysis](docs/08-e4del-analysis.md) |
| 10 | **Validated ADS config-extractor spec** (base-41 → SplitMix64 keystream) | [tools/](tools/) |
| 11 | **Two errors corrected in the community's understanding** — `wsprintfW`≠`swprintf`, and `GlobalLock`/`GlobalSize` hashes were swapped | [Internals](docs/02-pinhole-internals.md) |
| 12 | **Working, round-trip-validated multi-stage unpacker** (byte-perfect stage reproduction) | [tools/](tools/) |

Full detail, with confidence gradings, in the linked docs below.

---

## Repository layout

```
.
├── README.md                       ← you are here
├── docs/
│   ├── 00-executive-summary.md     Executive summary for leadership / IR leads
│   ├── 01-pinhole-loader-chain.md  Six-layer unpacking, cipher fork, page cipher
│   ├── 02-pinhole-internals.md     API hashing, string cipher, struct layout
│   ├── 03-pinhole-command-protocol.md  All 16 opcodes, wire format, endpoints
│   ├── 04-network-and-c2.md        DDR chain, Cloudflare Worker, TLS stack
│   ├── 05-detection-guide.md       How to deploy and tune the rules
│   ├── 06-threat-hunting.md        Hunt hypotheses, queries, host & net artifacts
│   ├── 07-attribution-and-assessment.md  Graded assessments, ICD-203 language
│   └── 08-e4del-analysis.md        E4del RAT, per-host builds, new C2
├── detections/
│   ├── yara/                       Host & memory YARA (validated against samples)
│   ├── sigma/                      Sigma rules for the process/registry/network TTPs
│   └── suricata/                   Network rules for the DDR + C2 patterns
├── tools/
│   ├── pinhole_unpack.py           Multi-stage unpacker (round-trip validated)
│   ├── pinhole_strings.py          String-cipher decryptor
│   ├── pinhole_apihash.py          API-hash resolver + name brute-forcer
│   └── pinhole_ads_config.py       ADS config extractor (base-41 + SplitMix64)
├── ioc/
│   ├── indicators.csv              Machine-readable IOC table w/ confidence
│   └── indicators.md               Human-readable IOC reference
└── analysis/
    └── donut_cipher_fork.py        Standalone reference impl of the cipher fork
```

---

## How to read this, by role

- **SOC analyst / detection engineer** → [Detection guide](docs/05-detection-guide.md) + [`detections/`](detections/). Start with the process-level Sigma and the `##STATUS##` signature; they are the highest-fidelity, lowest-maintenance artifacts here.
- **Threat hunter** → [Threat hunting](docs/06-threat-hunting.md). Host-artifact and infrastructure-pivot hypotheses, each with a query and a stated confidence.
- **Malware analyst / RE** → [Loader chain](docs/01-pinhole-loader-chain.md) → [Internals](docs/02-pinhole-internals.md) → [Command protocol](docs/03-pinhole-command-protocol.md), then the [`tools/`](tools/) and [`analysis/`](analysis/) for reproducible artifacts.
- **CTI / leadership** → [Executive summary](docs/00-executive-summary.md) and [Attribution & assessment](docs/07-attribution-and-assessment.md).

---

## Evidence standard

This repository uses ICD-203 estimative language throughout and tags every material claim:

- **VALIDATED** — reproduced from the sample by code in this repo (e.g. a decryptor whose output hashes to a known value).
- **CORROBORATED** — independently confirmed a claim from prior public reporting against the sample.
- **NOVEL** — not present in any public source at time of writing; graded by confidence (high / moderate / low).
- **CORRECTION** — a specific, evidenced fix to prior public reporting.
- **UNVERIFIED / OPEN** — stated in reporting or inferred here, but not yet confirmed against a sample.

Confidence terms (*high / moderate / low*) follow ICD-203. A finding being "high confidence" is a statement about the strength of the evidence, not a guarantee.

### Analytical line-of-sight

Prior public work on these families derives, directly or indirectly, from a single originating source (STRU, 2026-08-21). Downstream news coverage repeats it without independent sample analysis. This repository treats the STRU report as one source to be corroborated, not as ground truth, and every finding below is anchored to the samples themselves.

---

## Samples

Analysis was performed on the following (hashes in [`ioc/indicators.csv`](ioc/indicators.csv)):

| Role | SHA256 | Notes |
|------|--------|-------|
| PINHOLE final-stage RAT (x64) | `a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58` | Compiled 2026-08-29; primary RE target |
| PINHOLE `/api/bc` container | `78cd264a29e21b79035772faa4615e2bb1d795d15983ab1a3bc4e25d262e3840` | Layer-1 fake-JPEG container |
| E4del bundle (Build B) | `4712f4825169bbe8dc718cb97e8680192775e935b341d6650c7863038a77d8d1` | From `51.89.199.125/i`; plaintext `index.js` |

**No live malware samples or payload binaries are hosted in this repository.** It contains analysis, detection logic, and tooling only.

---

## Responsible use & disclosure

This material is published for defenders — detection engineering, threat hunting, and incident response. The infrastructure described was live at time of analysis; some indicators may since have been rotated or taken down. Nothing here is a substitute for validating detections in your own environment before production deployment.

The original discovery credit for the FTP-banner DDR technique and for naming these families belongs to MalwareHunterTeam (technique, July 2026) and the SOCRadar Threat Research Unit (families, August 2026). This project builds on that public disclosure.

## License

Analysis, documentation, and detection content are released under **CC BY 4.0**. Code under [`tools/`](tools/) and [`analysis/`](analysis/) is released under the **MIT License**. See [`LICENSE`](LICENSE).
