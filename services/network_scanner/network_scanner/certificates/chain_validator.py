"""Best-effort X.509 chain checks (expiry, hostname, issuer links)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from network_scanner.certificates.cert_parser import hostname_matches, normalize_dn


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_chain(
    certs: Iterable[dict[str, Any]],
    *,
    hostname: str | None = None,
) -> dict[str, Any]:
    chain = [dict(item) for item in certs if item]
    if not chain:
        return {
            "is_valid": False,
            "structural_valid": False,
            "structural_status": "INVALID",
            "errors": ["EMPTY_CHAIN"],
            "chain_length": 0,
            "chain_completeness": "EMPTY",
            "trust_status": "NOT_VERIFIED",
            "trust_verification": {"status": "NOT_PERFORMED", "reason": "trust_store_not_loaded"},
        }
    errors: list[str] = []
    leaf = chain[0]
    if leaf.get("expiry_status") == "EXPIRED":
        errors.append("CERT_EXPIRED")
    if leaf.get("expiry_status") == "NOT_YET_VALID":
        errors.append("CERT_NOT_YET_VALID")
    not_before = _parse_iso(leaf.get("not_before"))
    if not_before and not_before > datetime.now(timezone.utc) and "CERT_NOT_YET_VALID" not in errors:
        errors.append("CERT_NOT_YET_VALID")
    if hostname and not hostname_matches(hostname, leaf):
        errors.append("HOSTNAME_MISMATCH")
    leaf_issuer = normalize_dn(str(leaf.get("issuer") or ""))
    leaf_subject = normalize_dn(str(leaf.get("subject") or ""))
    inferred_self_signed = bool(leaf_issuer and leaf_subject and leaf_issuer == leaf_subject)
    if leaf.get("is_self_signed") or inferred_self_signed:
        errors.append("SELF_SIGNED")
    elif len(chain) == 1:
        # A peer certificate alone cannot prove issuer linkage or trust. Do
        # not report it as a healthy chain merely because no broken pair was
        # available to inspect. A self-signed certificate is handled above;
        # all other leaf-only observations are explicitly incomplete.
        if not leaf_issuer or leaf_issuer != leaf_subject:
            errors.append("CHAIN_INCOMPLETE")
    for index in range(len(chain) - 1):
        issuer = normalize_dn(str(chain[index].get("issuer") or ""))
        subject = normalize_dn(str(chain[index + 1].get("subject") or ""))
        if issuer and subject and issuer != subject:
            errors.append("CHAIN_ISSUER_MISMATCH")
        if chain[index + 1].get("expiry_status") == "EXPIRED":
            errors.append("INTERMEDIATE_EXPIRED")
    structural_valid = not errors
    terminal = chain[-1]
    terminal_issuer = normalize_dn(str(terminal.get("issuer") or ""))
    terminal_subject = normalize_dn(str(terminal.get("subject") or ""))
    terminal_self_signed = bool(terminal.get("is_self_signed") or (
        terminal_issuer and terminal_subject and terminal_issuer == terminal_subject
    ))
    if len(chain) == 1 and not terminal_self_signed:
        chain_completeness = "INCOMPLETE"
    elif terminal_self_signed:
        chain_completeness = "COMPLETE"
    else:
        chain_completeness = "NOT_ESTABLISHED"
    return {
        "is_valid": structural_valid,  # backwards-compatible structural verdict
        "structural_valid": structural_valid,
        "structural_status": "VALID" if structural_valid else "INVALID",
        "errors": errors,
        "chain_length": len(chain),
        "chain_completeness": chain_completeness,
        # This scanner does not build a platform trust-store path. Keeping
        # this separate prevents structural validity from being mistaken for
        # proof that a root is trusted by an operating system or browser.
        "trust_status": "NOT_VERIFIED",
        "trust_verification": {
            "status": "NOT_PERFORMED",
            "reason": "trust_store_not_loaded",
        },
    }
