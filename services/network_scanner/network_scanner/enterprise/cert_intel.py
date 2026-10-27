"""Certificate Intelligence — beyond inventory.

reuse detection, endpoint/application/device/cloud usage mapping, dependency
mapping, blast radius, CA hierarchy discovery, trust store discovery,
expiration forecasting, weak-signature detection, vulnerable public-key
identification and PQC migration candidates.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

WEAK_SIGNATURES = {"md5", "md5withrsa", "sha1", "sha1withrsa", "sha1withecdsa"}
MIN_RSA_BITS = 2048


def _fp(cert: dict[str, Any]) -> str:
    return str(cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint") or "").lower()


def _san(cert: dict[str, Any]) -> list[str]:
    sans = cert.get("sans") or cert.get("san") or []
    if isinstance(sans, str):
        return [s.strip() for s in sans.split(",") if s.strip()]
    return [str(s) for s in sans]


def usage_tags(cert: dict[str, Any]) -> dict[str, Any]:
    """Map a certificate into the usage taxonomy (endpoint/app/device/cloud)."""
    sans = _san(cert)
    subject = str(cert.get("subject") or "")
    usage = {
        "endpoint": bool(sans),
        "application": bool(cert.get("usages") or cert.get("extended_key_usage")),
        "device": "device" in subject.lower() or any("device" in s for s in sans),
        "cloud": any(token in s.lower() for s in sans for token in (".amazonaws.com", ".azurewebsites.net", ".cloud.google.com", ".elb.", ".azuredns.")),
    }
    return usage


def find_reuse(certificates: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """fingerprint -> list of subjects sharing it (reuse detection)."""
    by_fp: dict[str, list[str]] = defaultdict(list)
    for cert in certificates:
        fp = _fp(cert)
        if fp:
            by_fp[fp].append(str(cert.get("subject") or cert.get("common_name") or "?"))
    return {fp: subjects for fp, subjects in by_fp.items() if len(subjects) > 1}


def dependency_map(certificates: Iterable[dict[str, Any]], endpoints: Iterable[str]) -> dict[str, list[str]]:
    """fingerprint -> endpoints using it."""
    deps: dict[str, list[str]] = defaultdict(list)
    for cert in certificates:
        fp = _fp(cert)
        if not fp:
            continue
        for endpoint in cert.get("endpoints") or endpoints:
            deps[fp].append(str(endpoint))
    return {fp: sorted(set(endpoints_)) for fp, endpoints_ in deps.items()}


def blast_radius(certificates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """How many distinct endpoints/apps break if a certificate changes."""
    radius: dict[str, Any] = {}
    for cert in certificates:
        fp = _fp(cert)
        if not fp:
            continue
        endpoints = set(cert.get("endpoints") or [])
        radius[fp] = {
            "subject": cert.get("subject"),
            "endpoint_count": len(endpoints),
            "direct_impact": sorted(endpoints)[:50],
            "indirect_impact": len(cert.get("usages") or []),
            "san_count": len(_san(cert)),
        }
    return radius


def ca_hierarchy(certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """subject -> issuer chains; discovers the CA hierarchy (root/intermediate)."""
    certs = list(certificates)
    by_subject: dict[str, dict[str, Any]] = {}
    for cert in certs:
        subject = str(cert.get("subject") or "")
        if subject:
            by_subject[subject] = cert
    hierarchy: list[dict[str, Any]] = []
    for cert in certs:
        subject = str(cert.get("subject") or "")
        issuer = str(cert.get("issuer") or "")
        if subject == issuer:
            continue  # self-signed root, handled separately
        parent = by_subject.get(issuer)
        role = "INTERMEDIATE_CA" if parent and "CA" in str(parent.get("subject") or "").upper() else "SERVER_CERT"
        hierarchy.append({
            "subject": subject,
            "issuer": issuer,
            "role": role,
            "fingerprint_sha256": _fp(cert),
        })
    roots = [str(c.get("subject") or "") for c in certs if str(c.get("subject") or "") == str(c.get("issuer") or "")]
    return {"roots": sorted(set(roots)), "chain_entries": hierarchy}


def trust_store_discovery(certificates: Iterable[dict[str, Any]]) -> list[str]:
    """The set of root CAs the estate actually trusts."""
    roots: set[str] = set()
    for cert in certificates:
        subject = str(cert.get("subject") or "")
        issuer = str(cert.get("issuer") or "")
        if subject and subject == issuer:
            roots.add(subject)
    return sorted(roots)


def expiration_forecast(certificates: Iterable[dict[str, Any]], *, horizon_days: int = 365,
                        today: date | None = None) -> list[dict[str, Any]]:
    """Certificates expiring within the horizon, bucketed for forecasting."""
    today = today or datetime.now(timezone.utc).date()
    forecast: list[dict[str, Any]] = []
    for cert in certificates:
        raw = cert.get("not_after") or cert.get("valid_to") or cert.get("expires_at")
        if not raw:
            continue
        expires = _parse_date(raw)
        if expires is None:
            continue
        days_left = (expires - today).days
        if days_left <= horizon_days:
            forecast.append({
                "subject": cert.get("subject") or cert.get("common_name"),
                "fingerprint_sha256": _fp(cert),
                "expires_on": expires.isoformat(),
                "days_left": days_left,
                "bucket": "EXPIRED" if days_left < 0 else ("<30d" if days_left < 30 else "<90d" if days_left < 90 else "<1y"),
            })
    return sorted(forecast, key=lambda row: row["days_left"])


def _parse_date(raw: Any) -> date | None:
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    text = str(raw)
    for fmt in ("%Y-%m-%d", "%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y%m%d%H%M%SZ"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.date()
        except ValueError:
            continue
    return None


def weak_signature_detection(certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for cert in certificates:
        sig = str(cert.get("signature_algorithm") or cert.get("signatureAlgorithm") or "").lower()
        if any(token in sig for token in WEAK_SIGNATURES):
            out.append({"subject": cert.get("subject"), "fingerprint_sha256": _fp(cert),
                        "signature_algorithm": sig, "issue": "WEAK_CERT_SIGNATURE"})
    return out


def vulnerable_public_key_identification(certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for cert in certificates:
        algo = str(cert.get("public_key_algorithm") or cert.get("key_algorithm") or "").upper()
        bits = cert.get("public_key_size") or cert.get("key_size")
        if algo in ("RSA", "RSA-PSS", "RSAES") and bits and int(bits) < MIN_RSA_BITS:
            out.append({"subject": cert.get("subject"), "fingerprint_sha256": _fp(cert),
                        "algorithm": algo, "key_size": int(bits), "issue": "WEAK_PUBLIC_KEY"})
    return out


def migration_candidates(certificates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """PQC migration candidates: certs signed with / carrying pre-quantum
    algorithms (RSA/ECDSA/ECDH), regardless of key strength."""
    candidates = []
    for cert in certificates:
        algo = str(cert.get("public_key_algorithm") or cert.get("key_algorithm") or "").upper()
        sig = str(cert.get("signature_algorithm") or "").upper()
        if algo.startswith("RSA") or algo in ("ECDSA", "ECDH", "DSA", "DH") or "RSA" in sig or "ECDSA" in sig:
            candidates.append({
                "subject": cert.get("subject"),
                "fingerprint_sha256": _fp(cert),
                "public_key_algorithm": algo,
                "signature_algorithm": sig,
                "pqc_status": "MIGRATION_REQUIRED",
            })
    return candidates


def certificate_intelligence_report(certificates: Iterable[dict[str, Any]],
                                    endpoints: Iterable[str] = ()) -> dict[str, Any]:
    certs = list(certificates)
    return {
        "certificate_count": len(certs),
        "reuse": find_reuse(certs),
        "dependencies": dependency_map(certs, endpoints),
        "blast_radius": blast_radius(certs),
        "ca_hierarchy": ca_hierarchy(certs),
        "trust_store": trust_store_discovery(certs),
        "expiration_forecast": expiration_forecast(certs),
        "weak_signatures": weak_signature_detection(certs),
        "vulnerable_keys": vulnerable_public_key_identification(certs),
        "migration_candidates": migration_candidates(certs),
    }
