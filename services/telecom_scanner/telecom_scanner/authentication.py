"""Subscriber authentication algorithm sets — MILENAGE, TUAK, and what must not be there.

The f-functions
---------------
The USIM and the operator's AuC/UDM share a long-term key K and run the same
algorithm set over it (TS 33.102 §6.3):

    f1  network authentication (MAC-A)      f1* resync (MAC-S)
    f2  user authentication (RES / XRES)    f5  anonymity key (AK)
    f3  cipher key CK                       f5* resync AK
    f4  integrity key IK

3GPP standardises two example sets, and both are examples — an operator may
substitute its own, which is why what is actually deployed has to be read
rather than assumed:

* **MILENAGE** (TS 35.205-208) — built on AES-128. K is 128 bits.
* **TUAK** (TS 35.231) — built on the Keccak-f[1600] permutation, the SHA-3
  core. K may be 128 **or 256** bits.

OP and OPc, which is where deployments go wrong
-----------------------------------------------
Both sets take an operator configuration field: OP for MILENAGE, TOP for TUAK.
The value provisioned onto a USIM must be the *derived, per-subscriber* OPc
(``OPc = OP XOR AES_K(OP)``), never OP itself.

The distinction is the whole security argument. OPc is specific to one
subscriber's K, so extracting it from one card yields one card. OP is the same
across the operator's entire fleet, so a single extracted USIM — and USIM key
extraction is a demonstrated attack — yields the operator configuration field
for every subscriber ever issued. It cannot be rotated without reissuing every
card. Provisioning OP instead of OPc is a real and recurring deployment error,
and nothing about it is visible in service: authentication succeeds either way.

Algorithms that must never be in production
-------------------------------------------
* **XOR** (TS 34.108 §8) is a *test* algorithm for conformance rigs. It offers
  no security whatsoever and exists so a lab can predict the outputs. Finding
  it in a live HSS/UDM means test provisioning reached production.
* **COMP128-1** is the GSM A3/A8 algorithm broken in 1998; it enables SIM
  cloning. COMP128-2/3 close that specific attack but remain 2G-era and have
  no place on a 5G subscriber record.

This reads configuration. It computes no f-function, derives no key, and
:func:`looks_like_key_material` lets a caller refuse a K, OP or OPc rather
than analyse it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_REF_MILENAGE = "3GPP TS 35.205-208"
_REF_TUAK = "3GPP TS 35.231"
_REF_33501 = "3GPP TS 33.501 §6.1"

#: name -> (primitive, permitted_key_bits, production_safe, reference)
ALGORITHM_SETS: dict[str, tuple[str, tuple[int, ...], bool, str]] = {
    "milenage": ("AES-128", (128,), True, _REF_MILENAGE),
    "tuak": ("Keccak-f[1600]", (128, 256), True, _REF_TUAK),
    "xor": ("none (test vector)", (128,), False, "3GPP TS 34.108 §8"),
    "comp128-1": ("COMP128-1", (128,), False, "GSM 03.20"),
    "comp128-2": ("COMP128-2", (128,), False, "GSM 03.20"),
    "comp128-3": ("COMP128-3", (128,), False, "GSM 03.20"),
}

_ALIASES: dict[str, str] = {
    "milenage": "milenage", "milenage-1": "milenage", "f1f5": "milenage",
    "tuak": "tuak", "tuak-256": "tuak", "keccak": "tuak",
    "xor": "xor", "xor-test": "xor", "test": "xor", "dummy": "xor",
    "comp128": "comp128-1", "comp1281": "comp128-1", "comp128v1": "comp128-1",
    "comp1282": "comp128-2", "comp128v2": "comp128-2",
    "comp1283": "comp128-3", "comp128v3": "comp128-3",
}

#: Authentication methods defined for 5G (TS 33.501 §6.1.3).
AUTH_METHODS = {
    "5g-aka": "5G-AKA",
    "5gaka": "5G-AKA",
    "eap-aka'": "EAP-AKA'",
    "eap-aka": "EAP-AKA'",
    "eapaka": "EAP-AKA'",
    "eap-tls": "EAP-TLS",
    "eaptls": "EAP-TLS",
}


def looks_like_key_material(value: str) -> bool:
    """True when ``value`` looks like K / OP / OPc rather than a setting.

    All three are 128 or 256 bits, i.e. 32 or 64 hex digits. A caller taking
    operator input should refuse on this rather than pass it on.
    """
    text = re.sub(r"[\s:-]+", "", str(value or ""))
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64})", text))


def _finding(code: str, severity: str, message: str, ref: str) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _norm(value: Any) -> str:
    return re.sub(r"[\s_]+", "", str(value if value is not None else "")).strip().lower()


@dataclass
class AuthAlgorithmConfig:
    """Verdict for one subscriber profile's authentication configuration."""

    declared: str
    valid: bool = False
    algorithm: str = ""
    primitive: str | None = None
    key_bits: int | None = None
    method: str | None = None
    production_safe: bool | None = None
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def quantum_vulnerable(self) -> bool:
        """Grover halves a symmetric key; 128-bit K gives ~64 bits of margin.

        TUAK with a 256-bit K is the only configuration here that survives
        that reduction with a conventional 128-bit security target.
        """
        return self.valid and (self.key_bits or 0) < 256


def analyse_algorithm_set(
    algorithm: Any,
    *,
    key_bits: int | None = None,
    op_provisioned: bool | None = None,
    opc_per_subscriber: bool | None = None,
    method: Any = None,
    profile: str | None = None,
) -> AuthAlgorithmConfig:
    """Classify a declared authentication algorithm set.

    ``op_provisioned`` is True when the *un-derived* OP/TOP is written to the
    USIM — the fleet-wide failure described in the module docstring.
    ``opc_per_subscriber`` states whether OPc is diversified per subscriber.
    """
    result = AuthAlgorithmConfig(declared=str(algorithm if algorithm is not None else ""))

    if looks_like_key_material(algorithm):
        result.errors.append("value looks like key material, not an algorithm name; refused")
        return result

    norm = _norm(algorithm).replace("_", "-")
    canonical = _ALIASES.get(norm) or _ALIASES.get(norm.replace("-", ""))
    if canonical is None:
        if not norm:
            result.errors.append("no authentication algorithm declared")
        else:
            # An operator-proprietary set is legal (the standard ones are
            # examples), but it cannot be judged from a name.
            result.valid = True
            result.algorithm = f"proprietary ({algorithm})"
            result.production_safe = None
            result.findings.append(_finding(
                "auth.proprietary_algorithm_set", "medium",
                f"authentication set {algorithm!r} is not a 3GPP example set. Operator sets are "
                "permitted, but the f1-f5 construction cannot be assessed from configuration "
                "and needs the operator's own cryptographic assurance",
                _REF_33501))
        return result

    primitive, permitted, safe, ref = ALGORITHM_SETS[canonical]
    result.valid = True
    result.algorithm = canonical
    result.primitive = primitive
    result.production_safe = safe
    result.key_bits = key_bits

    if canonical == "xor":
        result.findings.append(_finding(
            "auth.test_algorithm_in_use", "critical",
            "the XOR test algorithm is configured. It is a conformance-test vector with no "
            "security property at all — authentication can be forged by anyone who knows the "
            "scheme. Its presence means test provisioning reached a live subscriber record",
            ref))
    elif canonical.startswith("comp128"):
        detail = ("COMP128-1 is broken and enables SIM cloning"
                  if canonical == "comp128-1"
                  else f"{canonical} is a 2G-era A3/A8 algorithm")
        result.findings.append(_finding(
            "auth.legacy_2g_algorithm", "critical",
            f"{detail}; it has no place on a subscriber record used for 4G/5G authentication",
            ref))

    if key_bits is not None:
        if key_bits not in permitted:
            result.findings.append(_finding(
                "auth.invalid_key_length", "high",
                f"K is {key_bits} bits; {canonical} permits "
                f"{' or '.join(str(b) for b in permitted)}",
                ref))
        elif canonical == "tuak" and key_bits == 128:
            result.findings.append(_finding(
                "auth.tuak_128_bit_key", "medium",
                "TUAK is deployed with a 128-bit K. TUAK's advantage over MILENAGE is support "
                "for a 256-bit K, which is what keeps ~128 bits of margin under Grover; at 128 "
                "bits it carries the migration cost without the benefit",
                "NIST IR 8547"))
        elif key_bits == 128 and canonical == "milenage":
            result.findings.append(_finding(
                "auth.128_bit_long_term_key", "info",
                "K is 128 bits (~64-bit effective under Grover). MILENAGE defines no longer key; "
                "TUAK with a 256-bit K is the standardised path. Long-term subscriber keys live "
                "for the life of the USIM, so this is a harvest-now-decrypt-later exposure",
                "NIST IR 8547"))

    if op_provisioned:
        result.findings.append(_finding(
            "auth.op_provisioned_to_usim", "critical",
            "the un-derived OP/TOP is provisioned to the USIM instead of the per-subscriber "
            "OPc. OP is identical across the whole fleet, so extracting it from any single card "
            "yields the operator configuration field for every subscriber, and it cannot be "
            "rotated without reissuing every USIM",
            _REF_MILENAGE if canonical == "milenage" else _REF_TUAK))
    elif opc_per_subscriber is False:
        result.findings.append(_finding(
            "auth.opc_not_diversified", "high",
            "OPc is not diversified per subscriber: a shared OPc gives an attacker who "
            "recovers it the same fleet-wide advantage OP would have",
            _REF_MILENAGE))

    if method is not None:
        key = _norm(method).replace("_", "-")
        resolved = AUTH_METHODS.get(key) or AUTH_METHODS.get(key.replace("-", ""))
        if resolved is None:
            result.errors.append(f"unrecognised authentication method {method!r}")
        else:
            result.method = resolved

    if profile:
        result.findings = [{**f, "profile": profile} for f in result.findings]
    return result


def summarise_estate(profiles: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll up subscriber-profile authentication configuration."""
    results: list[dict[str, Any]] = []
    by_algorithm: dict[str, int] = {}
    for spec in profiles:
        verdict = analyse_algorithm_set(
            spec.get("algorithm"),
            key_bits=spec.get("key_bits"),
            op_provisioned=spec.get("op_provisioned"),
            opc_per_subscriber=spec.get("opc_per_subscriber"),
            method=spec.get("method"),
            profile=spec.get("profile"),
        )
        label = verdict.algorithm or "UNKNOWN"
        by_algorithm[label] = by_algorithm.get(label, 0) + 1
        results.append({
            "profile": spec.get("profile"),
            "algorithm": verdict.algorithm,
            "primitive": verdict.primitive,
            "key_bits": verdict.key_bits,
            "method": verdict.method,
            "production_safe": verdict.production_safe,
            "quantum_vulnerable": verdict.quantum_vulnerable,
            "findings": verdict.findings,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "unsafe_in_production": sum(1 for r in results if r["production_safe"] is False),
        "quantum_vulnerable": sum(1 for r in results if r["quantum_vulnerable"]),
        "profiles_with_critical": sum(
            1 for r in results if any(f["severity"] == "critical" for f in r["findings"])),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
