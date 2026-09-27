"""5G air-interface ciphering and integrity algorithms — 3GPP TS 33.501 §5.

What this covers
----------------
5G protects the radio link with an ordered list of algorithms the gNB and UE
negotiate: NEA* for confidentiality, NIA* for integrity. The list is operator
configuration, and two entries in it are null.

===== ============== ======================================================
 id   confidentiality integrity
===== ============== ======================================================
 0    NEA0 — null     NIA0 — null
 1    NEA1 — SNOW 3G  NIA1 — SNOW 3G
 2    NEA2 — AES-128  NIA2 — AES-128-CMAC
 3    NEA3 — ZUC      NIA3 — ZUC
===== ============== ======================================================

**NEA0 and NIA0 are the finding.** They exist for a narrow reason —
TS 33.501 permits NIA0 for unauthenticated emergency calls, where there is no
key to integrity-protect with — and they are legal entries in the list. An
operator that leaves NEA0 enabled on a commercial profile is running 5G with
an unencrypted radio link, and nothing observable from the UE says so: the
call connects, the bars are full.

Order matters as much as membership. The gNB picks the highest-priority
algorithm the UE also supports, so NEA0 sitting *above* NEA2 in the list means
every capable UE negotiates null ciphering even though AES is configured and
present. A membership-only check reports that configuration as healthy.

All four standardised algorithms use 128-bit keys. Grover halves that to ~64
bits of effective security, which is why 3GPP is specifying 256-bit successors;
that is recorded as an inventory fact for migration planning, not as a
misconfiguration today.

This reads configuration. It performs no ciphering and handles no keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_REF = "3GPP TS 33.501 §5.11"

#: id -> (name, algorithm, is_null, key_bits)
CIPHERING: dict[int, tuple[str, str, bool, int]] = {
    0: ("NEA0", "null", True, 0),
    1: ("NEA1", "SNOW 3G", False, 128),
    2: ("NEA2", "AES-128-CTR", False, 128),
    3: ("NEA3", "ZUC", False, 128),
}

INTEGRITY: dict[int, tuple[str, str, bool, int]] = {
    0: ("NIA0", "null", True, 0),
    1: ("NIA1", "SNOW 3G", False, 128),
    2: ("NIA2", "AES-128-CMAC", False, 128),
    3: ("NIA3", "ZUC", False, 128),
}


def _finding(code: str, severity: str, message: str, ref: str = _REF) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _parse_ids(values: Any, prefix: str) -> tuple[list[int], list[str]]:
    """Accept [0,2], ["NEA0","NEA2"], "NEA2,NEA0" — order is preserved."""
    errors: list[str] = []
    if values is None:
        return [], ["no algorithm list declared"]
    if isinstance(values, str):
        items: list[Any] = [v for v in re.split(r"[,\s]+", values) if v]
    elif isinstance(values, (list, tuple)):
        items = list(values)
    else:
        return [], [f"cannot read an algorithm list from {type(values).__name__}"]

    out: list[int] = []
    for item in items:
        token = str(item).strip().upper()
        token = token[len(prefix):] if token.startswith(prefix) else token
        if not token.isdigit():
            errors.append(f"not an algorithm id: {item!r}")
            continue
        num = int(token)
        if num not in CIPHERING:
            errors.append(f"{prefix}{num} is not a defined algorithm (0-3)")
            continue
        if num in out:
            errors.append(f"{prefix}{num} appears more than once")
            continue
        out.append(num)
    return out, errors


@dataclass
class AirInterfaceProfile:
    """Verdict for one gNB / AMF algorithm profile."""

    ciphering: list[str] = field(default_factory=list)
    integrity: list[str] = field(default_factory=list)
    null_ciphering_enabled: bool = False
    null_integrity_enabled: bool = False
    null_ciphering_preferred: bool = False
    null_integrity_preferred: bool = False
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def radio_confidentiality_at_risk(self) -> bool:
        """True when a capable UE will actually negotiate null ciphering."""
        return self.null_ciphering_preferred


def analyse_profile(
    ciphering: Any,
    integrity: Any,
    *,
    emergency_only: bool = False,
    node: str | None = None,
) -> AirInterfaceProfile:
    """Classify an ordered NEA/NIA algorithm profile.

    Both lists are **priority-ordered, highest first** — that is how the gNB
    selects, so it is how this reads them.
    """
    enc_ids, enc_err = _parse_ids(ciphering, "NEA")
    int_ids, int_err = _parse_ids(integrity, "NIA")
    result = AirInterfaceProfile(
        ciphering=[CIPHERING[i][0] for i in enc_ids],
        integrity=[INTEGRITY[i][0] for i in int_ids],
        errors=[f"ciphering: {e}" for e in enc_err] + [f"integrity: {e}" for e in int_err],
    )

    result.null_ciphering_enabled = 0 in enc_ids
    result.null_integrity_enabled = 0 in int_ids
    # "Preferred" means nothing stronger outranks it: a capable UE lands here.
    result.null_ciphering_preferred = bool(enc_ids) and enc_ids[0] == 0
    result.null_integrity_preferred = bool(int_ids) and int_ids[0] == 0

    if enc_ids and not any(i != 0 for i in enc_ids):
        result.findings.append(_finding(
            "air.no_ciphering_available", "critical",
            "NEA0 is the only configured ciphering algorithm: the radio link carries "
            "user plane and signalling in clear with no negotiable alternative"))
    elif result.null_ciphering_preferred:
        stronger = [CIPHERING[i][0] for i in enc_ids if i != 0]
        result.findings.append(_finding(
            "air.null_ciphering_preferred", "critical",
            f"NEA0 (null ciphering) is first in the priority list, ahead of {', '.join(stronger)}: "
            "the gNB selects the highest-priority algorithm the UE supports, so every capable "
            "UE negotiates an unencrypted radio link even though real ciphering is configured"))
    elif result.null_ciphering_enabled and not emergency_only:
        result.findings.append(_finding(
            "air.null_ciphering_enabled", "high",
            "NEA0 (null ciphering) is offered on a commercial profile: a UE that claims to "
            "support nothing stronger will be served unencrypted"))

    if int_ids and not any(i != 0 for i in int_ids):
        result.findings.append(_finding(
            "air.no_integrity_available", "critical",
            "NIA0 is the only configured integrity algorithm: signalling cannot be "
            "integrity-protected, so messages can be forged or modified in transit"))
    elif result.null_integrity_preferred:
        result.findings.append(_finding(
            "air.null_integrity_preferred", "critical",
            "NIA0 (null integrity) is first in the priority list: signalling will be "
            "accepted unauthenticated on every capable UE"))
    elif result.null_integrity_enabled and not emergency_only:
        result.findings.append(_finding(
            "air.null_integrity_enabled", "high",
            "NIA0 (null integrity) is offered outside emergency registration; TS 33.501 "
            "permits it only for unauthenticated emergency calls"))

    if not enc_ids and not enc_err:
        result.errors.append("ciphering: empty algorithm list")
    if not int_ids and not int_err:
        result.errors.append("integrity: empty algorithm list")

    real = [i for i in enc_ids if i != 0]
    if real:
        result.findings.append(_finding(
            "air.128_bit_keys", "info",
            f"{', '.join(CIPHERING[i][0] for i in real)} use 128-bit keys (~64-bit effective "
            "under Grover). 3GPP is specifying 256-bit successors; recorded for migration "
            "planning, not a misconfiguration today", "NIST IR 8547"))

    if node:
        result.findings = [{**f, "node": node} for f in result.findings]
    return result


def summarise_estate(nodes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll up many gNB / AMF profiles."""
    results: list[dict[str, Any]] = []
    for spec in nodes:
        verdict = analyse_profile(
            spec.get("ciphering"),
            spec.get("integrity"),
            emergency_only=bool(spec.get("emergency_only", False)),
            node=spec.get("node"),
        )
        results.append({
            "node": spec.get("node"),
            "ciphering": verdict.ciphering,
            "integrity": verdict.integrity,
            "null_ciphering_enabled": verdict.null_ciphering_enabled,
            "null_integrity_enabled": verdict.null_integrity_enabled,
            "radio_confidentiality_at_risk": verdict.radio_confidentiality_at_risk,
            "findings": verdict.findings,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "null_ciphering_enabled": sum(1 for r in results if r["null_ciphering_enabled"]),
        "null_integrity_enabled": sum(1 for r in results if r["null_integrity_enabled"]),
        "radio_confidentiality_at_risk": sum(1 for r in results if r["radio_confidentiality_at_risk"]),
        "nodes_with_critical": sum(
            1 for r in results if any(f["severity"] == "critical" for f in r["findings"])),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
