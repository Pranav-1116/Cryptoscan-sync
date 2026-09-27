"""N32 inter-PLMN roaming security — 3GPP TS 33.501 §13.

The interface
-------------
N32 is the link between two operators' SEPPs, and it is the one 5G interface
that routinely crosses infrastructure neither operator owns: IPX carriers sit
in the middle and, for commercial reasons, sometimes need to read or rewrite
parts of the signalling. TS 33.501 defines two protection modes because of
that conflict:

* **TLS** — end-to-end between the SEPPs. Confidential and integrity-protected,
  but opaque to the IPX, so an intermediary that must modify a message cannot.
* **PRINS** — application-layer JOSE protection (JWE for confidentiality, JWS
  for integrity) applied per information element, so an authorised IPX can
  modify the elements a policy permits while everything else stays protected
  and every modification is signed and attributable.

The mistake this module looks for is not "no encryption". It is the mismatch
between the mode and the topology:

* PRINS with **no IPX in the path** takes on per-element JOSE complexity and a
  weaker end-to-end guarantee for no reason — TLS is the better choice there.
* TLS with an IPX that is **contracted to modify** messages cannot work as
  described; in practice something terminates the TLS at the IPX, which means
  the "end-to-end" protection ends at a third party, usually without either
  operator's security team having been told.
* PRINS with an **unrestricted modification policy** lets an intermediary
  rewrite anything, which is the whole control surrendered.

Roaming is also where legacy signalling lives. An operator that still carries
SS7/MAP or Diameter for 2G/3G/4G roaming has an unprotected path alongside its
protected 5G one, and an attacker picks the weak one — so a declared fallback
is reported rather than ignored.

Configuration analysis. No handshake is performed and no key is handled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_REF = "3GPP TS 33.501 §13.2"

PROTECTION_MODES = ("tls", "prins")

#: Legacy roaming signalling that carries no protection of its own.
_LEGACY_SIGNALLING = {
    "ss7": "SS7/MAP has no authentication or confidentiality; location and "
           "interception attacks against it are well documented",
    "map": "SS7/MAP has no authentication or confidentiality",
    "sigtran": "SIGTRAN carries SS7 over IP without adding cryptographic protection",
    "diameter": "Diameter without DTLS/IPsec is unprotected; TS 33.210 requires NDS/IP",
    "gtp": "GTP-C/GTP-U carry no protection of their own and need IPsec on inter-PLMN paths",
}

_JOSE_WEAK = {
    "none": "critical",      # unsigned JWS — the classic JOSE failure
    "hs1": "high",
    "rs1": "high",
    "es1": "high",
}


def _finding(code: str, severity: str, message: str, ref: str = _REF) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _norm(value: Any) -> str:
    return re.sub(r"[\s_-]+", "", str(value if value is not None else "")).strip().lower()


@dataclass
class N32Link:
    """Verdict for one roaming partner's N32 configuration."""

    partner_plmn: str | None = None
    mode: str | None = None
    valid: bool = False
    ipx_in_path: bool = False
    end_to_end_confidential: bool | None = None
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def protected(self) -> bool:
        return self.valid and not any(f["severity"] in ("critical", "high") for f in self.findings)


def analyse_link(
    protection_mode: Any,
    *,
    partner_plmn: str | None = None,
    ipx_providers: Iterable[str] | None = None,
    ipx_may_modify: bool | None = None,
    modification_policy: Iterable[str] | None = None,
    jose_algorithms: Iterable[str] | None = None,
    tls_version: str | None = None,
    legacy_fallback: Iterable[str] | None = None,
) -> N32Link:
    """Classify one SEPP-to-SEPP roaming link."""
    ipx = [str(p) for p in (ipx_providers or []) if str(p).strip()]
    result = N32Link(partner_plmn=partner_plmn, ipx_in_path=bool(ipx))

    mode = _norm(protection_mode)
    if not mode:
        result.errors.append("no N32 protection mode declared")
        return result
    if mode not in PROTECTION_MODES:
        result.errors.append(
            f"unrecognised N32 protection mode {protection_mode!r}; expected tls or prins")
        return result

    result.valid = True
    result.mode = mode

    if mode == "tls":
        result.end_to_end_confidential = True
        # Dots too: "1.0", "TLSv1.0" and "tls10" all name the same version.
        version = _norm(tls_version).replace(".", "")
        if version and version in {"tls10", "tls11", "tlsv10", "tlsv11", "10", "11",
                                   "ssl30", "sslv30", "ssl3", "sslv3"}:
            result.findings.append(_finding(
                "n32.tls_version_disallowed", "critical",
                f"N32 is protected with TLS {tls_version}, which TS 33.210 and NIST SP 800-52r2 "
                "both disallow", "3GPP TS 33.210"))
        elif not version:
            result.findings.append(_finding(
                "n32.tls_version_undeclared", "low",
                "N32 uses TLS but the minimum version is not declared"))
        if ipx and ipx_may_modify:
            result.findings.append(_finding(
                "n32.tls_with_modifying_ipx", "high",
                f"N32 is declared end-to-end TLS while {len(ipx)} IPX provider(s) are contracted "
                "to modify signalling. Those are incompatible: in practice the TLS is being "
                "terminated at the intermediary, so protection ends at a third party rather "
                "than at the partner SEPP. Use PRINS, which authorises and signs specific "
                "modifications, or remove the modification right"))
        elif ipx:
            result.findings.append(_finding(
                "n32.tls_through_ipx", "info",
                f"{len(ipx)} IPX provider(s) in path with end-to-end TLS — they relay only, "
                "which is the stronger arrangement"))

    else:  # prins
        # PRINS protects per information element, so the end-to-end guarantee
        # is conditional on the modification policy rather than absolute.
        result.end_to_end_confidential = False
        if not ipx:
            result.findings.append(_finding(
                "n32.prins_without_ipx", "medium",
                "PRINS is configured with no IPX in the path. PRINS exists to let an "
                "intermediary modify authorised elements; with no intermediary it adds "
                "per-element JOSE handling and a weaker guarantee than plain TLS would give"))
        policy = [str(p) for p in (modification_policy or []) if str(p).strip()]
        if ipx and not policy:
            result.findings.append(_finding(
                "n32.no_modification_policy", "critical",
                "PRINS is in use with IPX providers but no modification policy is declared: "
                "an intermediary that may rewrite any information element has the whole "
                "control surrendered to it"))
        elif policy and any(_norm(p) in {"*", "all", "any"} for p in policy):
            result.findings.append(_finding(
                "n32.unrestricted_modification_policy", "critical",
                "the PRINS modification policy permits every information element; restrict it "
                "to the elements the IPX contract actually requires"))

        algs = [_norm(a) for a in (jose_algorithms or []) if str(a).strip()]
        for alg in algs:
            severity = _JOSE_WEAK.get(alg)
            if severity:
                result.findings.append(_finding(
                    "n32.weak_jose_algorithm", severity,
                    f"JOSE algorithm {alg!r} is accepted on N32"
                    + (": an unsigned JWS means any party in the path can forge signalling"
                       if alg == "none" else " and is a SHA-1-family construction"),
                    "RFC 7518"))
        if not algs:
            result.findings.append(_finding(
                "n32.jose_algorithms_undeclared", "low",
                "PRINS is in use but the accepted JOSE algorithm set is not declared"))

    for legacy in (legacy_fallback or []):
        key = _norm(legacy)
        note = next((v for k, v in _LEGACY_SIGNALLING.items() if k in key), None)
        if note:
            result.findings.append(_finding(
                "n32.legacy_signalling_fallback", "high",
                f"roaming also runs over {legacy}: {note}. A protected N32 does not help while "
                "an unprotected path to the same subscriber data stays reachable",
                "3GPP TS 33.210"))

    if partner_plmn:
        result.findings = [{**f, "partner_plmn": partner_plmn} for f in result.findings]
    return result


def summarise_partners(links: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll up a roaming partner matrix."""
    results: list[dict[str, Any]] = []
    by_mode: dict[str, int] = {}
    for spec in links:
        verdict = analyse_link(
            spec.get("protection_mode"),
            partner_plmn=spec.get("partner_plmn"),
            ipx_providers=spec.get("ipx_providers"),
            ipx_may_modify=spec.get("ipx_may_modify"),
            modification_policy=spec.get("modification_policy"),
            jose_algorithms=spec.get("jose_algorithms"),
            tls_version=spec.get("tls_version"),
            legacy_fallback=spec.get("legacy_fallback"),
        )
        label = verdict.mode or "UNKNOWN"
        by_mode[label] = by_mode.get(label, 0) + 1
        results.append({
            "partner_plmn": spec.get("partner_plmn"),
            "mode": verdict.mode,
            "ipx_in_path": verdict.ipx_in_path,
            "protected": verdict.protected,
            "findings": verdict.findings,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "by_mode": dict(sorted(by_mode.items())),
        "protected": sum(1 for r in results if r["protected"]),
        "with_ipx": sum(1 for r in results if r["ipx_in_path"]),
        "partners_with_critical": sum(
            1 for r in results if any(f["severity"] == "critical" for f in r["findings"])),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
