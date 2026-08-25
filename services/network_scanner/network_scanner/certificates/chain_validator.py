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
        return {"is_valid": False, "errors": ["EMPTY_CHAIN"], "chain_length": 0}
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
    if leaf.get("is_self_signed"):
        errors.append("SELF_SIGNED")
    for index in range(len(chain) - 1):
        issuer = normalize_dn(str(chain[index].get("issuer") or ""))
        subject = normalize_dn(str(chain[index + 1].get("subject") or ""))
        if issuer and subject and issuer != subject:
            errors.append("CHAIN_ISSUER_MISMATCH")
        if chain[index + 1].get("expiry_status") == "EXPIRED":
            errors.append("INTERMEDIATE_EXPIRED")
    return {"is_valid": not errors, "errors": errors, "chain_length": len(chain)}
