"""The 5G key hierarchy — TS 33.501 §6.2, Annex A.

Every key protecting a 5G subscriber descends from one long-term key K on the
USIM:

    K  (USIM / UDM-ARPF, 128 or 256 bits)
     └─ CK, IK           f3 / f4                          128 each
         └─ K_AUSF        at the AUSF                      256
             └─ K_SEAF    anchor key, bound to the serving network   256
                 └─ K_AMF                                  256
                     ├─ K_NASenc, K_NASint   NAS security  256 → **128 used**
                     └─ K_gNB / K_N3IWF                     256
                         ├─ K_RRCenc, K_RRCint  RRC        256 → **128 used**
                         └─ K_UPenc, K_UPint    user plane 256 → **128 used**

Two properties of that chain are worth checking, and neither is visible from
a probe.

**Effective strength is set at both ends, not in the middle.** The derivations
are HMAC-SHA-256 (TS 33.220 Annex B) and carry 256 bits, but the leaf keys are
truncated to 128 bits because NEA/NIA take 128-bit keys. So the chain is
bounded above by K and below by that truncation: deploying a 256-bit K with
TUAK does *not* make the radio link 256-bit strong, and a 256-bit K is
nonetheless the thing that protects the subscriber for the life of the card.
Both facts are reported, because operators routinely believe the first
purchase bought the second.

**K_SEAF must be bound to the serving network.** TS 33.501 derives it with the
serving network name as an input, which is what stops a visited network
reusing the keys it was given for one subscriber's roaming session in another
network — the anti-bidding-down property that separates 5G from earlier
generations. An implementation that omits the binding authenticates fine and
fails silently.

This analyses declared configuration. No key is derived and none is handled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

_REF = "3GPP TS 33.501 Annex A"

#: level -> (name, where it lives, nominal bits, note)
HIERARCHY: tuple[tuple[str, str, int, str], ...] = (
    ("K", "USIM / UDM-ARPF", 0, "long-term subscriber key; 128 (MILENAGE) or 256 (TUAK)"),
    ("CK/IK", "USIM / UDM-ARPF", 128, "cipher and integrity keys from f3/f4"),
    ("K_AUSF", "AUSF", 256, "home-network authentication anchor"),
    ("K_SEAF", "SEAF (in AMF)", 256, "serving-network anchor; bound to the SN name"),
    ("K_AMF", "AMF", 256, "access and mobility anchor"),
    ("K_NASenc/K_NASint", "AMF / UE", 256, "NAS signalling; truncated to 128 for NEA/NIA"),
    ("K_gNB", "gNB", 256, "radio anchor, derived per connection"),
    ("K_RRCenc/K_RRCint", "gNB / UE", 256, "RRC signalling; truncated to 128"),
    ("K_UPenc/K_UPint", "gNB / UE", 256, "user plane; truncated to 128"),
)

#: The air-interface algorithms take 128-bit keys, so every leaf is truncated.
AIR_INTERFACE_KEY_BITS = 128

_VALID_KDF = {"hmac-sha-256", "hmacsha256", "sha256", "hmac-sha256"}


def _finding(code: str, severity: str, message: str, ref: str = _REF) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _norm(value: Any) -> str:
    return str(value if value is not None else "").strip().lower().replace("_", "-")


@dataclass
class KeyHierarchy:
    """Verdict for one PLMN's key-hierarchy configuration."""

    long_term_key_bits: int | None = None
    kdf: str | None = None
    serving_network_binding: bool | None = None
    valid: bool = False
    effective_bits_air_interface: int = AIR_INTERFACE_KEY_BITS
    effective_bits_long_term: int | None = None
    levels: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def grover_margin_air_interface(self) -> int:
        """Effective bits against a quantum search of the air-interface key."""
        return self.effective_bits_air_interface // 2

    @property
    def grover_margin_long_term(self) -> int | None:
        if self.effective_bits_long_term is None:
            return None
        return self.effective_bits_long_term // 2


def analyse_hierarchy(
    *,
    long_term_key_bits: int | None = None,
    kdf: Any = None,
    serving_network_binding: bool | None = None,
    horizontal_key_derivation: bool | None = None,
    plmn: str | None = None,
) -> KeyHierarchy:
    """Assess a declared 5G key hierarchy.

    ``horizontal_key_derivation`` is the gNB-to-gNB key refresh on handover
    (TS 33.501 §6.9.4). Without it, a compromised gNB keeps deriving usable
    keys for the UE's subsequent cells.
    """
    result = KeyHierarchy(
        long_term_key_bits=long_term_key_bits,
        serving_network_binding=serving_network_binding,
    )
    result.levels = [
        {"key": name, "location": where, "bits": bits or long_term_key_bits, "note": note}
        for name, where, bits, note in HIERARCHY
    ]

    if long_term_key_bits is None:
        result.errors.append("long-term key length (K) not declared")
    elif long_term_key_bits not in (128, 256):
        result.errors.append(f"K of {long_term_key_bits} bits is not a defined length (128 or 256)")
    else:
        result.valid = True
        result.effective_bits_long_term = long_term_key_bits

    if kdf is not None:
        key = _norm(kdf)
        result.kdf = str(kdf)
        if key not in _VALID_KDF:
            result.findings.append(_finding(
                "keys.non_standard_kdf", "high",
                f"key derivation is declared as {kdf!r}; TS 33.220 Annex B specifies "
                "HMAC-SHA-256 for the 5G hierarchy. A substituted KDF breaks the key "
                "separation the hierarchy depends on",
                "3GPP TS 33.220 Annex B"))

    if serving_network_binding is False:
        result.findings.append(_finding(
            "keys.no_serving_network_binding", "critical",
            "K_SEAF is derived without the serving-network name. That binding is what stops a "
            "visited network reusing a roaming subscriber's keys in another network — the "
            "anti-bidding-down property 5G introduced. Authentication still succeeds, so this "
            "fails silently"))
    elif serving_network_binding is None:
        result.findings.append(_finding(
            "keys.serving_network_binding_undeclared", "low",
            "serving-network binding of K_SEAF is not declared; it is the property that makes "
            "roaming keys non-reusable and should be stated explicitly"))

    if horizontal_key_derivation is False:
        result.findings.append(_finding(
            "keys.no_horizontal_derivation", "medium",
            "horizontal key derivation on handover is disabled: a compromised gNB continues to "
            "hold material usable for the UE's subsequent cells instead of the chain being "
            "refreshed",
            "3GPP TS 33.501 §6.9.4"))

    # The truncation is not a defect — it is what NEA/NIA accept — but it is
    # the number that actually bounds the radio link, and it is routinely
    # confused with the length of K.
    if result.valid:
        if long_term_key_bits == 256:
            result.findings.append(_finding(
                "keys.air_interface_truncation", "info",
                "K is 256 bits, but every leaf key is truncated to 128 bits because NEA/NIA "
                f"take 128-bit keys — so the radio link carries ~{AIR_INTERFACE_KEY_BITS // 2} "
                "bits of margin under Grover regardless of K. The 256-bit K protects the "
                "subscriber identity and the authentication chain, not the air interface",
                "NIST IR 8547"))
        else:
            result.findings.append(_finding(
                "keys.long_term_key_128", "medium",
                "K is 128 bits, so the whole hierarchy is bounded at ~64 bits under Grover, "
                "including the long-term key that lives for the life of the USIM. TUAK with a "
                "256-bit K raises the ceiling; the air interface stays at 128 until 3GPP's "
                "256-bit NEA/NIA successors ship",
                "NIST IR 8547"))

    if plmn:
        result.findings = [{**f, "plmn": plmn} for f in result.findings]
    return result


def summarise_estate(networks: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll up key-hierarchy configuration across PLMNs."""
    results: list[dict[str, Any]] = []
    for spec in networks:
        verdict = analyse_hierarchy(
            long_term_key_bits=spec.get("long_term_key_bits"),
            kdf=spec.get("kdf"),
            serving_network_binding=spec.get("serving_network_binding"),
            horizontal_key_derivation=spec.get("horizontal_key_derivation"),
            plmn=spec.get("plmn"),
        )
        results.append({
            "plmn": spec.get("plmn"),
            "long_term_key_bits": verdict.long_term_key_bits,
            "kdf": verdict.kdf,
            "serving_network_binding": verdict.serving_network_binding,
            "grover_margin_long_term": verdict.grover_margin_long_term,
            "grover_margin_air_interface": verdict.grover_margin_air_interface,
            "findings": verdict.findings,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "k_256": sum(1 for r in results if r["long_term_key_bits"] == 256),
        "k_128": sum(1 for r in results if r["long_term_key_bits"] == 128),
        "missing_sn_binding": sum(1 for r in results if r["serving_network_binding"] is False),
        "networks_with_critical": sum(
            1 for r in results if any(f["severity"] == "critical" for f in r["findings"])),
        "unparsed": sum(1 for r in results if r["errors"]),
        "results": results,
    }
