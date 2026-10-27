"""EMV application-cryptogram (ARQC/ARPC) key lifecycle analysis.

The EMV key hierarchy an issuer runs is three deep:

    IMK   Issuer Master Key, per application, held in the HSM
     |    diversified by PAN + PSN
    ICC   card master key, personalised into the chip
     |    diversified per transaction by ATC (session key derivation)
    SK    session key, used for the ARQC and the ARPC response

What determines the strength of that chain is the **Cryptogram Version
Number**. The CVN fixes the session-key derivation method and the cryptogram
algorithm, so it — not a free-text algorithm field — is what has to be read to
know whether an issuer is on TDES or AES, and whether session keys are
genuinely per-transaction.

This analyses that configuration. It performs no key derivation and computes
no cryptogram: deriving a session key would require the IMK, and an IMK must
never leave the HSM. The inputs here are configuration values (CVN, key
algorithm, key length, ATC handling), not key material —
:func:`looks_like_key_material` lets a caller refuse anything that looks like
a key rather than accept it.

Cryptogram Version Numbers
--------------------------
==== ============== ================================================
CVN  derivation     notes
==== ============== ================================================
10   Visa CVN 10    TDES, **no ATC in session-key derivation** — the
                    "session key" is the ICC master key, so it does
                    not vary per transaction.
14   Visa CVN 14    TDES with ATC-based derivation (EMV CSK).
18   Visa CVN 18    AES-based CSK derivation.
22   Visa CVN 22    AES, current Visa target.
'A'  M/Chip 4       TDES, ATC-based.
'B'  M/Chip Adv     TDES, ATC-based, extended data.
'C'  M/Chip Adv     AES-based.
==== ============== ================================================

CVN 10 is the one worth naming: because the ATC is not an input, every
transaction on a card uses the same key, so a captured cryptogram set is far
more useful to an attacker than under CVN 14/18. It is still deployed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: cvn (normalised) -> (scheme, cipher, atc_diversified, description)
CRYPTOGRAM_VERSIONS: dict[str, tuple[str, str, bool, str]] = {
    "10": ("Visa", "TDES", False, "Visa CVN 10 — no ATC in session-key derivation"),
    "14": ("Visa", "TDES", True, "Visa CVN 14 — TDES common session key"),
    "16": ("Visa", "TDES", True, "Visa CVN 16 — TDES common session key"),
    "17": ("Visa", "TDES", True, "Visa CVN 17 — TDES common session key"),
    "18": ("Visa", "AES", True, "Visa CVN 18 — AES common session key"),
    "20": ("Visa", "AES", True, "Visa CVN 20 — AES"),
    "22": ("Visa", "AES", True, "Visa CVN 22 — AES"),
    "A": ("Mastercard", "TDES", True, "M/Chip 4 — TDES session keys"),
    "B": ("Mastercard", "TDES", True, "M/Chip Advance — TDES session keys"),
    "C": ("Mastercard", "AES", True, "M/Chip Advance — AES session keys"),
    "D": ("Mastercard", "AES", True, "M/Chip Advance — AES session keys"),
}

#: Minimum key lengths, in bits, that are not a finding.
_MIN_BITS = {"TDES": 112, "AES": 128}

_CRYPTOGRAM_TYPES = {
    "ARQC": "authorisation request cryptogram (online authorisation)",
    "ARPC": "authorisation response cryptogram (issuer response)",
    "TC": "transaction certificate (approved offline)",
    "AAC": "application authentication cryptogram (declined)",
}


def looks_like_key_material(value: str) -> bool:
    """True when ``value`` looks like a key or key component rather than a setting.

    An EMV key is 16/32/48 hex digits (double or triple-length TDES, or AES).
    A caller taking operator input should refuse on this rather than pass it on.
    """
    text = re.sub(r"[\s:-]+", "", str(value or ""))
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{48}|[0-9A-Fa-f]{64})", text))


@dataclass
class EmvKeyConfig:
    """The verdict for one issuer application's cryptogram configuration."""

    declared_cvn: str
    valid: bool = False
    scheme: str | None = None
    cipher: str | None = None
    atc_diversified: bool | None = None
    description: str = ""
    key_bits: int | None = None
    issues: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def quantum_vulnerable(self) -> bool:
        """EMV cryptograms are symmetric; Grover halves the effective strength.

        TDES at 112 bits drops to ~56 and is not survivable; AES-128 drops to
        ~64, which is why AES-192/256 is the durable target for long-lived IMKs.
        """
        return self.valid and (self.cipher == "TDES" or (self.key_bits or 0) < 192)


def _normalise_cvn(cvn: str) -> str:
    text = str(cvn or "").strip().upper()
    text = re.sub(r"^(?:CVN|CVR)\s*", "", text)
    text = text.lstrip("0") or "0" if text.isdigit() else text
    # "1" from "01" would be wrong: CVNs are two-digit numerics or a letter.
    if text.isdigit() and len(text) == 1:
        text = text.zfill(2)
    return text


def analyse_cryptogram_config(cvn: str, *, key_algorithm: str | None = None,
                              key_bits: int | None = None,
                              application: str | None = None) -> EmvKeyConfig:
    """Classify an issuer application's CVN and cross-check its declared key."""
    result = EmvKeyConfig(declared_cvn=str(cvn or ""))

    if looks_like_key_material(cvn):
        result.errors.append("value looks like key material, not a CVN; refused")
        return result

    norm = _normalise_cvn(cvn)
    if not norm:
        result.errors.append("no cryptogram version number declared")
        return result

    spec = CRYPTOGRAM_VERSIONS.get(norm)
    if spec is None:
        result.errors.append(f"unrecognised cryptogram version number {cvn!r}")
        return result

    scheme, cipher, atc, description = spec
    result.valid = True
    result.scheme = scheme
    result.cipher = cipher
    result.atc_diversified = atc
    result.description = description
    result.key_bits = key_bits

    if not atc:
        result.issues.append({
            "severity": "HIGH", "code": "SESSION_KEY_NOT_DIVERSIFIED",
            "detail": f"{description}: the ATC is not an input to session-key derivation, "
                      "so every transaction on a card uses the same key",
        })
    if cipher == "TDES":
        result.issues.append({
            "severity": "MEDIUM", "code": "TDES_CRYPTOGRAM",
            "detail": f"{description} derives {cipher} session keys; the AES CVN for "
                      f"{scheme} is the migration target",
        })

    if key_algorithm:
        declared = key_algorithm.strip().upper().replace("3DES", "TDES").replace("TRIPLE_DES", "TDES")
        if declared != cipher:
            result.issues.append({
                "severity": "HIGH", "code": "CVN_KEY_ALGORITHM_MISMATCH",
                "detail": f"CVN {norm} defines {cipher} cryptograms but the IMK is "
                          f"declared as {key_algorithm!r}",
            })
    if key_bits is not None:
        floor = _MIN_BITS.get(cipher)
        if floor and key_bits < floor:
            result.issues.append({
                "severity": "HIGH", "code": "IMK_TOO_SHORT",
                "detail": f"IMK is {key_bits} bits; {cipher} requires at least {floor}",
            })
        if key_bits == 112 and cipher == "TDES":
            result.issues.append({
                "severity": "MEDIUM", "code": "TWO_KEY_TDES",
                "detail": "double-length (2-key) TDES gives ~112 bits classically and "
                          "is withdrawn for new work",
            })

    if application:
        result.issues = [{**i, "application": application} for i in result.issues]
    return result


def cryptogram_type(value: str) -> dict:
    """Describe an ARQC/ARPC/TC/AAC label. Unknown values are surfaced, not guessed."""
    key = str(value or "").strip().upper()
    if key in _CRYPTOGRAM_TYPES:
        return {"type": key, "description": _CRYPTOGRAM_TYPES[key], "known": True}
    return {"type": key, "description": f"UNKNOWN({value})", "known": False}


def summarise_portfolio(applications: list[dict]) -> dict:
    """Roll up an issuer portfolio.

    ``[{"application": "VISA-DEBIT", "cvn": "10", "key_algorithm": "TDES", "key_bits": 112}]``
    """
    results = []
    by_cvn: dict[str, int] = {}
    for spec in applications:
        verdict = analyse_cryptogram_config(
            spec.get("cvn", ""),
            key_algorithm=spec.get("key_algorithm"),
            key_bits=spec.get("key_bits"),
            application=spec.get("application"),
        )
        label = _normalise_cvn(spec.get("cvn", "")) or "UNKNOWN"
        by_cvn[label] = by_cvn.get(label, 0) + 1
        results.append({
            "application": spec.get("application"),
            "cvn": verdict.declared_cvn,
            "scheme": verdict.scheme,
            "cipher": verdict.cipher,
            "atc_diversified": verdict.atc_diversified,
            "quantum_vulnerable": verdict.quantum_vulnerable,
            "issues": verdict.issues,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "by_cvn": dict(sorted(by_cvn.items())),
        "aes_applications": sum(1 for r in results if r["cipher"] == "AES"),
        "tdes_applications": sum(1 for r in results if r["cipher"] == "TDES"),
        "undiversified_session_keys": sum(1 for r in results if r["atc_diversified"] is False),
        "quantum_vulnerable": sum(1 for r in results if r["quantum_vulnerable"]),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
