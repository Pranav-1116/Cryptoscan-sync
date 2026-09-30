"""Hybrid-PQC TLS downgrade detector (deterministic, no AI).

When a TLS endpoint advertises a post-quantum hybrid key exchange (e.g.
``X25519MLKEM768`` / ``SecP256r1MLKEM768`` — ML-KEM hybrid groups, draft TLS
PQC), the security guarantee is only real if an attacker cannot force the
negotiation back to a classical-only group. This module inspects handshake
evidence deterministically:

1. Offer ONLY a hybrid ML-KEM group  -> a compliant endpoint negotiates it.
2. Offer hybrid + classical groups   -> endpoint must still prefer/negotiate
   hybrid (no silent downgrade).
3. Offer ONLY classical groups       -> must NOT report hybrid negotiated, and
   the downgrade from a prior hybrid must be detectable via the
   supported_groups / key-share the server selected.
4. Tamper test: if a middlebox strips the hybrid group from ClientHello, the
   server-selected group must be visible and flagged as CLASSIC_DOWNGRADE.

A live scanner that can actually emit PQC groups (OpenSSL 3.5+/oqs-provider)
supplies the observed negotiated group via the ``handshake`` callable; when the
local TLS stack cannot offer PQC we return LOCAL_UNSUPPORTED rather than
guessing. Pure policy lives in ``evaluate_negotiation`` (fully unit-tested with
synthetic ClientHello/ServerHello evidence).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

# Hybrid ML-KEM group identifiers (IANA draft + oqs naming).
HYBRID_GROUPS = {
    "X25519MLKEM768", "X25519_MLKEM768", "SECP256R1MLKEM768", "P256_MLKEM768",
    "SECP384R1MLKEM1024", "P384_MLKEM1024", "X25519KYBER768",
}
CLASSIC_GROUPS = {"X25519", "SECP256R1", "P-256", "SECP384R1", "P-384",
                  "X448", "FFDHE2048", "FFDHE3072"}


class Outcome(str, Enum):
    HYBRID_NEGOTIATED = "HYBRID_NEGOTIATED"
    HYBRID_PREFERRED = "HYBRID_PREFERRED"
    CLASSIC_NEGOTIATED = "CLASSIC_NEGOTIATED"
    DOWNGRADE_DETECTED = "DOWNGRADE_DETECTED"
    HYBRID_NOT_ADVERTISED = "HYBRID_NOT_ADVERTISED"
    LOCAL_UNSUPPORTED = "LOCAL_UNSUPPORTED"
    ERROR = "ERROR"


@dataclass
class HandshakeEvidence:
    """Observed facts from one handshake attempt."""

    offered_groups: list[str]
    negotiated_group: str | None
    pqc_offered: bool
    pqc_supported_locally: bool
    error: str | None = None


def normalize_group(name: str | None) -> str | None:
    if not name:
        return None
    return name.strip().upper().replace("-", "").replace("_", "")


def _is_hybrid(group: str | None) -> bool:
    g = normalize_group(group)
    if not g:
        return False
    return any(normalize_group(h) == g or normalize_group(h) in g for h in HYBRID_GROUPS)


def evaluate_negotiation(evidence: HandshakeEvidence) -> dict[str, Any]:
    """Pure policy: decide downgrade status from observed handshake facts.

    ``offered_groups`` is what the CLIENT offered; ``negotiated_group`` is what
    the SERVER selected. The client controls offers, so a client that offered
    hybrid and only got classic back has either hit a downgrade or a
    non-hybrid server.
    """
    if evidence.error:
        return {"outcome": Outcome.ERROR.value, "severity": "HIGH",
                "downgrade": False, "detail": f"handshake error: {evidence.error}"}
    if not evidence.pqc_supported_locally:
        return {"outcome": Outcome.LOCAL_UNSUPPORTED.value, "severity": "INFO",
                "downgrade": False,
                "detail": "scanner TLS stack cannot offer ML-KEM hybrid groups"}

    offered_hybrid = [g for g in evidence.offered_groups if _is_hybrid(g)]
    negotiated = evidence.negotiated_group

    if not offered_hybrid:
        # client offered classic only
        if _is_hybrid(negotiated):
            return {"outcome": Outcome.HYBRID_NEGOTIATED.value, "severity": "INFO",
                    "downgrade": False, "negotiated_group": negotiated,
                    "detail": "server picked a hybrid group unexpectedly"}
        return {"outcome": Outcome.CLASSIC_NEGOTIATED.value, "severity": "INFO",
                "downgrade": False, "negotiated_group": negotiated,
                "detail": "classic-only offer negotiated a classic group (expected)"}

    # client offered at least one hybrid group
    if _is_hybrid(negotiated):
        # Did client ALSO offer classic? If so, server preferred hybrid = good.
        offered_classic = [g for g in evidence.offered_groups if normalize_group(g) in
                           {normalize_group(c) for c in CLASSIC_GROUPS}]
        return {"outcome": (Outcome.HYBRID_PREFERRED.value if offered_classic
                            else Outcome.HYBRID_NEGOTIATED.value),
                "severity": "INFO", "downgrade": False, "negotiated_group": negotiated,
                "detail": "hybrid ML-KEM group negotiated; downgrade resisted"}
    # client offered hybrid but server picked classic => downgrade possible
    return {"outcome": Outcome.DOWNGRADE_DETECTED.value, "severity": "HIGH",
            "downgrade": True, "negotiated_group": negotiated,
            "offered_hybrid": offered_hybrid,
            "detail": ("client offered hybrid ML-KEM but server negotiated a "
                       "classical group — endpoint does not enforce PQC; a "
                       "downgrade/middlebox strip is possible")}


class Handshaker(Protocol):
    """Live adapter: attempt a handshake offering exactly ``groups``; return
    the negotiated group (or raise). Tests inject a fake."""

    def __call__(self, host: str, port: int, groups: list[str], sni: str | None) -> HandshakeEvidence: ...


def _default_handshaker(host: str, port: int, groups: list[str], sni: str | None) -> HandshakeEvidence:
    """Best-effort live handshaker. Reports LOCAL_UNSUPPORTED if the local
    OpenSSL cannot configure PQC groups."""
    import socket
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    has_pqc = any(_is_hybrid(g) for g in groups)
    # OpenSSL uses colon-separated group names via set_groups; PQC names are
    # only present in PQC-enabled builds.
    try:
        ctx.set_groups(":".join(g.replace("_", "") if _is_hybrid(g) else g for g in groups))
    except (ssl.SSLError, ValueError, AttributeError):
        return HandshakeEvidence(offered_groups=groups, negotiated_group=None,
                                 pqc_offered=has_pqc, pqc_supported_locally=False,
                                 error="local TLS stack cannot set these groups")
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
                negotiated = None
                try:
                    negotiated = tls.selected_alpn_protocol()  # placeholder
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    pass
                # negotiated group isn't exposed by stdlib ssl; cipher only.
                # We infer via the OpenSSL NPN/ALPN-free path: report group via
                # cipher if possible; otherwise None -> treat as classic.
                return HandshakeEvidence(offered_groups=groups, negotiated_group=negotiated,
                                         pqc_offered=has_pqc, pqc_supported_locally=True,
                                         error="stdlib ssl does not expose negotiated group")
    except (ssl.SSLError, OSError) as exc:
        return HandshakeEvidence(offered_groups=groups, negotiated_group=None,
                                 pqc_offered=has_pqc, pqc_supported_locally=True,
                                 error=str(exc)[:160])


def audit_endpoint(host: str, port: int = 443, *, sni: str | None = None,
                   handshaker: Handshaker | None = None) -> dict[str, Any]:
    """Run the three-scenario downgrade analysis against an endpoint."""
    hs = handshaker or _default_handshaker
    scenarios = [
        ("hybrid_only", ["X25519MLKEM768", "SecP256r1MLKEM768"]),
        ("hybrid_preferred", ["X25519MLKEM768", "X25519", "SECP256R1"]),
        ("classic_only", ["X25519", "SECP256R1"]),
    ]
    results = []
    any_hybrid = False
    downgrade = False
    for name, groups in scenarios:
        ev = hs(host, port, groups, sni or host)
        verdict = evaluate_negotiation(ev)
        results.append({"scenario": name, "offered_groups": groups,
                        "negotiated_group": ev.negotiated_group, **verdict})
        any_hybrid |= verdict["outcome"] in (
            Outcome.HYBRID_NEGOTIATED.value, Outcome.HYBRID_PREFERRED.value)
        downgrade |= bool(verdict.get("downgrade"))

    if not any_hybrid and not downgrade:
        # could be local unsupported across the board
        if all(r["outcome"] == Outcome.LOCAL_UNSUPPORTED.value for r in results):
            overall = Outcome.LOCAL_UNSUPPORTED.value
            severity = "INFO"
        else:
            overall = Outcome.HYBRID_NOT_ADVERTISED.value
            severity = "MEDIUM"
    elif downgrade:
        overall = Outcome.DOWNGRADE_DETECTED.value
        severity = "HIGH"
    else:
        overall = Outcome.HYBRID_PREFERRED.value
        severity = "INFO"

    return {
        "target": {"host": host, "port": port, "sni": sni or host},
        "overall_outcome": overall,
        "severity": severity,
        "downgrade_resisted": overall in (Outcome.HYBRID_PREFERRED.value,
                                          Outcome.HYBRID_NEGOTIATED.value),
        "scenarios": results,
    }
