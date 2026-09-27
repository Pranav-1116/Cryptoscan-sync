"""SUPI concealment (SUCI) analysis — 3GPP TS 33.501 Annex C.

The control this covers
-----------------------
In 2G/3G/4G the permanent subscriber identity (IMSI) is sent over the air in
clear during initial attach, which is what an IMSI catcher exploits. 5G fixes
this: the UE encrypts the SUPI into a SUCI with the home network's public key
before it ever leaves the device, so only the home network's SIDF can recover
it.

That fix is optional in configuration. TS 33.501 defines protection scheme 0
as the **null-scheme**, which sends the SUPI unconcealed, and it remains
legal — it exists for emergency registration and for operators that have not
deployed home-network keys. An operator running the null-scheme in production
has 5G radio with 4G privacy, and nothing in the air interface reveals that:
the attach succeeds normally. It is invisible unless someone reads the UDM/SIDF
configuration, which is what this module does.

Schemes (TS 33.501 Annex C.3):

==== ================= =================================================
 id  scheme            note
==== ================= =================================================
 0   null-scheme       SUPI in clear. Emergency-only, never routine.
 1   Profile A         ECIES over Curve25519 (X25519) + AES-128-CTR + HMAC-SHA-256
 2   Profile B         ECIES over secp256r1 (P-256), same AEAD construction
3-11 reserved          not assigned by 3GPP
12-15 operator-specific proprietary; unverifiable from outside
==== ================= =================================================

Both standardised profiles are ECIES, so both are Shor-vulnerable. That is
worth recording rather than alarming about: a SUCI is decrypted immediately
and not stored, so the harvest-now-decrypt-later exposure is the *subscriber
identity* of traffic an adversary recorded today — a real but bounded privacy
risk, and one 3GPP has not yet published a PQC profile for.

This reads configuration. It performs no concealment or de-concealment, holds
no home-network private key, and :func:`looks_like_key_material` lets a caller
refuse input that looks like one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_REF = "3GPP TS 33.501 Annex C"

#: scheme id -> (name, conceals_supi, curve, quantum_vulnerable)
PROTECTION_SCHEMES: dict[int, tuple[str, bool, str | None, bool]] = {
    0: ("null-scheme", False, None, False),
    1: ("ECIES Profile A", True, "Curve25519", True),
    2: ("ECIES Profile B", True, "secp256r1", True),
}

_ALIASES: dict[str, int] = {
    "0": 0, "null": 0, "nullscheme": 0, "null-scheme": 0, "none": 0, "clear": 0,
    "1": 1, "profilea": 1, "profile-a": 1, "ecies-profile-a": 1, "a": 1,
    "curve25519": 1, "x25519": 1,
    "2": 2, "profileb": 2, "profile-b": 2, "ecies-profile-b": 2, "b": 2,
    "secp256r1": 2, "p-256": 2, "prime256v1": 2,
}


def looks_like_key_material(value: str) -> bool:
    """True when ``value`` looks like a home-network key rather than a setting.

    A home-network private key is 32 bytes (Profile A/B); the public key is 32
    or 33. A caller taking operator input should refuse on this, not analyse it.
    """
    text = re.sub(r"[\s:-]+", "", str(value or ""))
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{66})", text))


@dataclass
class SuciConfig:
    """Verdict for one PLMN's / UDM's concealment configuration."""

    declared: str
    valid: bool = False
    scheme_id: int | None = None
    scheme: str = ""
    conceals_supi: bool | None = None
    curve: str | None = None
    home_network_public_key_id: int | None = None
    quantum_vulnerable: bool = False
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def imsi_catcher_exposed(self) -> bool:
        """True when the permanent identity goes over the air unconcealed."""
        return self.valid and self.conceals_supi is False


def _finding(code: str, severity: str, message: str, ref: str = _REF) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _normalise(value: Any) -> str:
    return re.sub(r"[\s_]+", "", str(value if value is not None else "")).strip().lower()


def analyse_concealment(
    protection_scheme: Any,
    *,
    home_network_public_key_id: int | None = None,
    emergency_only: bool = False,
    plmn: str | None = None,
) -> SuciConfig:
    """Classify a declared SUPI protection scheme.

    ``emergency_only`` marks a configuration that applies solely to emergency
    registration, where TS 33.501 does permit the null-scheme — the same value
    is a finding on a commercial profile and correct on an emergency one, so
    the caller's context decides rather than this function guessing.
    """
    result = SuciConfig(declared=str(protection_scheme if protection_scheme is not None else ""))

    if looks_like_key_material(protection_scheme):
        result.errors.append("value looks like key material, not a protection scheme; refused")
        return result

    norm = _normalise(protection_scheme)
    if not norm:
        result.errors.append("no SUPI protection scheme declared")
        return result

    scheme_id = _ALIASES.get(norm)
    if scheme_id is None:
        if norm.isdigit() and 3 <= int(norm) <= 11:
            result.errors.append(f"protection scheme {norm} is reserved and unassigned by 3GPP")
            return result
        if norm.isdigit() and 12 <= int(norm) <= 15:
            # Operator-specific schemes are legal but opaque; an unverifiable
            # scheme is not a pass and not a failure.
            result.valid = True
            result.scheme_id = int(norm)
            result.scheme = f"operator-specific ({norm})"
            result.conceals_supi = None
            result.findings.append(_finding(
                "suci.operator_specific_scheme", "medium",
                f"protection scheme {norm} is operator-specific: concealment cannot be "
                "verified from configuration and needs the operator's own assurance"))
            return result
        result.errors.append(f"unrecognised SUPI protection scheme {protection_scheme!r}")
        return result

    name, conceals, curve, pq = PROTECTION_SCHEMES[scheme_id]
    result.valid = True
    result.scheme_id = scheme_id
    result.scheme = name
    result.conceals_supi = conceals
    result.curve = curve
    result.quantum_vulnerable = pq
    result.home_network_public_key_id = home_network_public_key_id

    if not conceals:
        if emergency_only:
            result.findings.append(_finding(
                "suci.null_scheme_emergency", "info",
                "null-scheme on an emergency-registration profile — permitted by TS 33.501"))
        else:
            result.findings.append(_finding(
                "suci.null_scheme", "critical",
                "SUPI protection is the null-scheme: the permanent subscriber identity is "
                "sent over the air unconcealed on every initial registration, which is the "
                "exposure 5G SUCI exists to close (IMSI-catcher / subscriber tracking)"))
    else:
        if home_network_public_key_id is None:
            result.findings.append(_finding(
                "suci.no_key_identifier", "low",
                "no home-network public key identifier declared: without one the key cannot "
                "be rotated without breaking attach for provisioned USIMs"))
        if pq:
            result.findings.append(_finding(
                "suci.shor_vulnerable_profile", "info",
                f"{name} conceals the SUPI with ECIES over {curve}, which a cryptographically "
                "relevant quantum computer breaks. 3GPP has published no PQC concealment "
                "profile yet; recorded as an inventory fact, not a misconfiguration",
                "NIST IR 8547"))

    if plmn:
        result.findings = [{**f, "plmn": plmn} for f in result.findings]
    return result


def summarise_estate(profiles: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll up many PLMN / UDM profiles.

    ``[{"plmn": "424-02", "protection_scheme": 0, "emergency_only": False}]``
    """
    results: list[dict[str, Any]] = []
    by_scheme: dict[str, int] = {}
    for spec in profiles:
        verdict = analyse_concealment(
            spec.get("protection_scheme"),
            home_network_public_key_id=spec.get("home_network_public_key_id"),
            emergency_only=bool(spec.get("emergency_only", False)),
            plmn=spec.get("plmn"),
        )
        label = verdict.scheme or "UNKNOWN"
        by_scheme[label] = by_scheme.get(label, 0) + 1
        results.append({
            "plmn": spec.get("plmn"),
            "protection_scheme": verdict.declared,
            "scheme": verdict.scheme,
            "conceals_supi": verdict.conceals_supi,
            "imsi_catcher_exposed": verdict.imsi_catcher_exposed,
            "quantum_vulnerable": verdict.quantum_vulnerable,
            "findings": verdict.findings,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "by_scheme": dict(sorted(by_scheme.items())),
        "concealed": sum(1 for r in results if r["conceals_supi"] is True),
        "exposed": sum(1 for r in results if r["imsi_catcher_exposed"]),
        "unverifiable": sum(1 for r in results if r["conceals_supi"] is None and not r["errors"]),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
