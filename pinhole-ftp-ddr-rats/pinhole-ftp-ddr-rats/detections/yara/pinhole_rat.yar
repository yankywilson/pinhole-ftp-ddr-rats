/*
    PINHOLE RAT - YARA detection rules
    Independent analysis. See docs/ for the reverse-engineering behind each string.

    IMPORTANT - three distinct rules for three distinct artifacts:

      1. PINHOLE_RAT_on_disk       -> the unpacked RAT PE as it sits on disk.
                                      Keys on the PLAINTEXT strings that are NOT
                                      encrypted in the binary (endpoints + the
                                      PowerShell sentinel). Tested to fire on the
                                      reference sample.

      2. PINHOLE_loader_container  -> the fake-JPEG Layer-1 container from /api/bc.
                                      Keys on the malformed APP0 header (valid SOI
                                      + APP0 marker, missing JFIF identifier).
                                      Build-agnostic (structural, not key-based).

      3. PINHOLE_RAT_in_memory     -> a RUNNING PINHOLE process or a memory image.
                                      Keys on the DECRYPTED string pool cached in
                                      .bss at runtime (##STATUS##, /api/vncpc, the
                                      DDR delimiters, the Spanish vnc error). These
                                      strings are encrypted on disk, so this rule
                                      will NOT match the on-disk sample by design -
                                      scan process memory / a memory dump with it.

    Validated with yara-python 4.5 against:
      RAT  a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58
      cont 78cd264a29e21b79035772faa4615e2bb1d795d15983ab1a3bc4e25d262e3840
*/

import "pe"

rule PINHOLE_RAT_on_disk
{
    meta:
        author        = "independent analysis"
        description   = "PINHOLE RAT (unpacked PE, on disk) - plaintext endpoints + PowerShell sentinel"
        reference     = "docs/03-pinhole-command-protocol.md"
        sha256        = "a7d3e9020e4b978183a0652027a63dc0181c77a16e41279a22c07fbc93c3bc58"
        fidelity      = "high"
        tlp           = "clear"

    strings:
        $ep_client = "/api/client" ascii
        $ep_tsk    = "/api/tsk" ascii
        $ep_fls    = "/api/fls?type=1&file_id=%lld&key=%s" ascii
        $pwsh      = "___PWSH_END_%08X___" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $pwsh and 2 of ($ep_*)
}

rule PINHOLE_loader_container
{
    meta:
        author        = "independent analysis"
        description   = "PINHOLE Layer-1 loader container - fake JPEG (valid SOI/APP0, no JFIF)"
        reference     = "docs/01-pinhole-loader-chain.md"
        sha256        = "78cd264a29e21b79035772faa4615e2bb1d795d15983ab1a3bc4e25d262e3840"
        fidelity      = "medium"
        note          = "structural; independent of per-build cipher keys"
        tlp           = "clear"

    strings:
        // valid SOI + APP0 marker immediately followed by a 2-byte length and
        // (crucially) NOT the ASCII 'JFIF' identifier that a real APP0 carries.
        $soi_app0 = { FF D8 FF E0 }

    condition:
        $soi_app0 at 0 and
        // real JFIF APP0 has "JFIF\0" at offset 6; this container does not
        uint32(6) != 0x4649464A and     // 'JFIF' little-endian
        filesize > 40KB and filesize < 512KB
}

rule PINHOLE_RAT_in_memory
{
    meta:
        author        = "independent analysis"
        description   = "PINHOLE RAT decrypted string pool (RUNNING process / memory image only)"
        reference     = "docs/02-pinhole-internals.md"
        fidelity      = "high"
        scan_target   = "process memory or memory dump - NOT the on-disk file"
        tlp           = "clear"

    strings:
        $status   = "##STATUS##" ascii
        $curl     = "curl.exe -s -w" ascii
        $vncpc    = "/api/vncpc" ascii
        $stlbrwsr = "/api/stlbrwsr" ascii
        $ddr1     = "====D5===D6====" ascii
        $ddr2     = "====D7===D8====" ascii
        $es_vnc   = "Error al abrir el proceso vnc" ascii
        $pwsh     = "___PWSH_END_" ascii

    condition:
        3 of them
}
