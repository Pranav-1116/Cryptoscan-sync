"""ISO 9564 PIN-block format analysis.

What this does and does not do
------------------------------
This classifies a PIN-block **format declaration** — the format a system says
it uses, as read from HSM configuration, a switch's interface spec or scanned
source — and reports what that choice implies for PCI PIN and for a
post-quantum/AES migration. It is metadata analysis.

It deliberately does **not** parse, encipher, decipher, translate or otherwise
touch a PIN block. A clear PIN never enters this process, and the functions
here take a format name, not PIN data. :func:`looks_like_pin_material` exists
so callers can *refuse* input that appears to be a real block rather than
analyse it.

The formats (ISO 9564-1:2017)
-----------------------------
====== ============ ========================================================
format PAN-bound?   summary
====== ============ ========================================================
0      yes          PIN XOR PAN. ANSI X9.8. The long-standing default.
1      **no**       PIN + random fill. For use only where no PAN exists.
2      **no**       PIN + 'F' fill. Offline IC-card verification **only**.
3      yes          PIN XOR PAN with random fill; strengthens format 0.
4      yes          AES-only, 16-byte block, with a random-filled second half.
====== ============ ========================================================

Formats 0–3 are defined over a 64-bit block and are therefore bound to DES /
TDES. Format 4 is the AES format, and the only one with a path past TDES: PCI
PIN requires format 4 wherever AES keys are used, and the wider industry
deadline for retiring TDES PIN encryption makes "still on format 0" a dated,
scheduled migration rather than an abstract risk.

Formats 1 and 2 carry no PAN binding, so a PIN block captured for one account
can be replayed against another — the reason format 2 is confined to offline
IC-card use and format 1 to the narrow no-PAN case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Canonical ISO 9564-1 formats.
ISO_FORMATS = ("0", "1", "2", "3", "4")

#: Spellings seen in HSM config, switch specs and source code -> ISO format.
_ALIASES: dict[str, str] = {
    "0": "0", "iso0": "0", "iso-0": "0", "format0": "0", "fmt0": "0",
    # Whitespace and underscores are stripped before lookup, so both the
    # dotted and undotted spellings of X9.8 need an entry.
    "ansix98": "0", "ansix9.8": "0", "x98": "0", "x9.8": "0",
    "iso9564-0": "0", "iso9564-1format0": "0",
    "1": "1", "iso1": "1", "iso-1": "1", "format1": "1", "fmt1": "1", "iso9564-1": "1",
    "2": "2", "iso2": "2", "iso-2": "2", "format2": "2", "fmt2": "2", "iso9564-2": "2",
    "3": "3", "iso3": "3", "iso-3": "3", "format3": "3", "fmt3": "3", "iso9564-3": "3",
    "4": "4", "iso4": "4", "iso-4": "4", "format4": "4", "fmt4": "4", "iso9564-4": "4",
}

#: Proprietary / pre-ISO formats. Still deployed on older estates; none of them
#: is an ISO format and none is acceptable for new work.
_PROPRIETARY: dict[str, str] = {
    "ibm3624": "IBM 3624",
    "ibm 3624": "IBM 3624",
    "3624": "IBM 3624",
    "docutel": "Docutel",
    "diebold": "Diebold",
    "ncr": "NCR",
    "visa1": "Visa format 1",
    "visa2": "Visa format 2",
    "visa3": "Visa format 3",
    "visa4": "Visa format 4",
    "eci1": "ECI-1",
    "eci2": "ECI-2",
    "eci3": "ECI-3",
    "eci4": "ECI-4",
    "burroughs": "Burroughs",
}

_PAN_BOUND = {"0": True, "1": False, "2": False, "3": True, "4": True}
_BLOCK_CIPHER = {"0": "TDES", "1": "TDES", "2": "TDES", "3": "TDES", "4": "AES"}
_BLOCK_BITS = {"0": 64, "1": 64, "2": 64, "3": 64, "4": 128}

_SUMMARY = {
    "0": "PIN XOR PAN (ANSI X9.8)",
    "1": "PIN with random fill, no PAN binding",
    "2": "PIN with 'F' fill, offline IC-card verification only",
    "3": "PIN XOR PAN with random fill",
    "4": "AES PIN block with random fill",
}


@dataclass
class PinBlockFormat:
    """The verdict for one declared PIN-block format."""

    declared: str
    valid: bool
    iso_format: str | None = None          # "0".."4" for ISO formats
    proprietary: str | None = None         # name, when it is a pre-ISO format
    summary: str = ""
    pan_bound: bool | None = None
    block_cipher: str | None = None        # TDES / AES
    block_bits: int | None = None
    online_use_permitted: bool | None = None
    pci_pin_compliant: bool | None = None
    issues: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def requires_tdes_migration(self) -> bool:
        """True when the format itself pins the estate to TDES."""
        return self.valid and self.block_cipher == "TDES"


def _normalise(declared: str) -> str:
    return re.sub(r"[\s_]+", "", str(declared or "")).strip().lower()


def looks_like_pin_material(value: str) -> bool:
    """True when ``value`` looks like an actual PIN block rather than a format name.

    A caller that accepts user input should check this and refuse, rather than
    pass the value on: an enciphered PIN block is 16 or 32 hex digits, and this
    module must never be handed one.
    """
    text = re.sub(r"[\s:-]+", "", str(value or ""))
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{16}|[0-9A-Fa-f]{32})", text))


def analyse_pin_block_format(declared: str, *, online: bool = True,
                             key_algorithm: str | None = None) -> PinBlockFormat:
    """Classify a declared PIN-block format and report its implications.

    ``online`` marks an interchange/acquiring path (the usual case). ``format 2``
    is legitimate offline and a finding online, so the caller's context decides.
    ``key_algorithm`` ("TDES" / "AES"), when known, is cross-checked against the
    format: an AES key cannot carry a 64-bit PIN block.
    """
    result = PinBlockFormat(declared=str(declared or ""), valid=False)
    norm = _normalise(declared)

    if not norm:
        result.errors.append("no PIN-block format declared")
        return result
    if looks_like_pin_material(declared):
        # Refuse rather than analyse: this is data, not a format name.
        result.errors.append("value looks like PIN-block data, not a format name; refused")
        return result

    if norm in _PROPRIETARY:
        result.valid = True
        result.proprietary = _PROPRIETARY[norm]
        result.summary = f"{result.proprietary} proprietary PIN block (pre-ISO)"
        result.pan_bound = None
        result.block_cipher = "TDES"
        result.block_bits = 64
        result.online_use_permitted = False
        result.pci_pin_compliant = False
        result.issues.append({
            "severity": "HIGH", "code": "PROPRIETARY_PIN_BLOCK",
            "detail": f"{result.proprietary} is not an ISO 9564 format; migrate to ISO format 4",
        })
        return result

    iso = _ALIASES.get(norm)
    if iso is None:
        result.errors.append(f"unrecognised PIN-block format {declared!r}")
        return result

    result.valid = True
    result.iso_format = iso
    result.summary = _SUMMARY[iso]
    result.pan_bound = _PAN_BOUND[iso]
    result.block_cipher = _BLOCK_CIPHER[iso]
    result.block_bits = _BLOCK_BITS[iso]
    result.online_use_permitted = iso != "2"

    if not result.pan_bound:
        result.issues.append({
            "severity": "HIGH", "code": "PIN_BLOCK_NOT_PAN_BOUND",
            "detail": f"ISO format {iso} does not bind the PAN, so a captured block "
                      "can be replayed against another account",
        })
    if iso == "2" and online:
        result.issues.append({
            "severity": "CRITICAL", "code": "OFFLINE_FORMAT_USED_ONLINE",
            "detail": "ISO format 2 is for offline IC-card verification only and "
                      "must not appear on an online/interchange path",
        })
    if result.block_cipher == "TDES":
        result.issues.append({
            "severity": "MEDIUM", "code": "TDES_PIN_BLOCK",
            "detail": f"ISO format {iso} is a 64-bit block format and therefore TDES-bound; "
                      "ISO format 4 is the AES format required for AES PIN keys",
        })

    if key_algorithm:
        alg = key_algorithm.strip().upper().replace("3DES", "TDES").replace("TRIPLE_DES", "TDES")
        if alg == "AES" and iso != "4":
            result.issues.append({
                "severity": "HIGH", "code": "PIN_FORMAT_KEY_MISMATCH",
                "detail": f"an AES PIN key cannot carry a 64-bit ISO format {iso} block; "
                          "ISO format 4 is required",
            })
        elif alg == "TDES" and iso == "4":
            result.issues.append({
                "severity": "HIGH", "code": "PIN_FORMAT_KEY_MISMATCH",
                "detail": "ISO format 4 is a 128-bit AES block and cannot be carried by a TDES key",
            })

    # PCI PIN: format 4 is the compliant target; 0/1/3 remain permitted with
    # TDES today but are scheduled migrations; 2 online and proprietary are not.
    if iso == "4":
        result.pci_pin_compliant = True
    elif iso == "2" and online:
        result.pci_pin_compliant = False
    else:
        result.pci_pin_compliant = not any(i["severity"] in ("HIGH", "CRITICAL") for i in result.issues)

    return result


def summarise_estate(declarations: list[dict]) -> dict:
    """Roll up many declarations: ``[{"system": ..., "format": ..., "online": ...}]``.

    Returns per-format counts and the migration backlog, which is the number a
    payments programme actually tracks.
    """
    results: list[dict] = []
    by_format: dict[str, int] = {}
    for spec in declarations:
        verdict = analyse_pin_block_format(
            spec.get("format", ""),
            online=bool(spec.get("online", True)),
            key_algorithm=spec.get("key_algorithm"),
        )
        label = (f"ISO-{verdict.iso_format}" if verdict.iso_format
                 else verdict.proprietary or "UNKNOWN")
        by_format[label] = by_format.get(label, 0) + 1
        results.append({
            "system": spec.get("system"),
            "format": verdict.declared,
            "iso_format": verdict.iso_format,
            "pci_pin_compliant": verdict.pci_pin_compliant,
            "requires_tdes_migration": verdict.requires_tdes_migration,
            "issues": verdict.issues,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "by_format": dict(sorted(by_format.items())),
        "aes_ready": sum(1 for r in results if r["iso_format"] == "4"),
        "tdes_bound": sum(1 for r in results if r["requires_tdes_migration"]),
        "non_compliant": sum(1 for r in results if r["pci_pin_compliant"] is False),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
