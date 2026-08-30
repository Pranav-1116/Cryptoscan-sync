"""DNS and PKI discovery.

DNS intelligence: DNS infrastructure (SOA/NS), DNSSEC metadata (reuses the
live dnssec_checker), certificate-related records (CAA, TLSA) and service
discovery (SRV). PKI intelligence: map the certificate estate into the
hierarchy Root CA → Intermediate CA → Issuing CA → Server Certificate and
export it for graph databases.
"""

from __future__ import annotations

from typing import Any, Iterable

# ------------------------------------------------------------------ DNS


def dns_infrastructure_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Group DNS records into infrastructure + crypto metadata."""
    zones: dict[str, dict[str, Any]] = {}
    for record in records:
        zone = str(record.get("zone") or record.get("name") or "")
        if not zone:
            continue
        entry = zones.setdefault(zone, {"nameservers": [], "soa": None, "caa": [], "tlsa": [], "srv": []})
        rtype = str(record.get("type") or record.get("rtype") or "").upper()
        if rtype == "NS":
            entry["nameservers"].append(record.get("target") or record.get("value"))
        elif rtype == "SOA":
            entry["soa"] = record.get("value") or record
        elif rtype == "CAA":
            entry["caa"].append(record.get("value"))
        elif rtype == "TLSA":
            entry["tlsa"].append(record.get("value"))
        elif rtype == "SRV":
            entry["srv"].append(record.get("value"))
    return zones


def dns_crypto_summary(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    zones = dns_infrastructure_records(records)
    return {
        "zone_count": len(zones),
        "zones_with_caa": sum(1 for z in zones.values() if z["caa"]),
        "zones_with_tlsa": sum(1 for z in zones.values() if z["tlsa"]),
        "zones_with_dnssec_meta": sum(1 for z in zones.values() if z.get("dnssec") or z.get("dnssec_enabled")),
        "dnssec_status": {zone: (z.get("dnssec") or z.get("dnssec_enabled") or "UNKNOWN") for zone, z in zones.items()},
    }


def dnssec_status_from_checker(zone_results: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize dnssec_checker.scan_dnssec() outputs into DNS intelligence."""
    out = []
    for result in zone_results:
        out.append({
            "zone": result.get("zone"),
            "status": result.get("status"),
            "signed": result.get("signed"),
            "algorithms": result.get("algorithms") or [],
            "dnskey_count": result.get("dnskey_count"),
            "ds_count": result.get("ds_count"),
            "transfer_exposed": result.get("transfer_exposed"),
            "issues": result.get("issues") or [],
        })
    return out


# ------------------------------------------------------------------ PKI


def pki_hierarchy(certificates: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Root CA → Intermediate CA → Issuing CA → Server certificate map."""
    certs = list(certificates)
    by_subject: dict[str, dict[str, Any]] = {}
    for cert in certs:
        subject = str(cert.get("subject") or "")
        if subject:
            by_subject.setdefault(subject, cert)

    def _role(subject: str, issuer: str, cert: dict[str, Any]) -> str:
        if subject and subject == issuer:
            return "ROOT_CA"
        if not _is_ca(cert):
            return "SERVER_CERTIFICATE"
        issuer_cert = by_subject.get(issuer)
        if issuer_cert and str(issuer_cert.get("issuer") or "") == str(issuer_cert.get("subject") or ""):
            return "ISSUING_CA"  # issued directly by a root
        return "INTERMEDIATE_CA"  # issued by another (non-root) CA

    def _is_ca(cert: dict[str, Any]) -> bool:
        basic = str(cert.get("basic_constraints") or cert.get("basicConstraints") or "")
        return "CA:TRUE" in basic.upper() or "CA:true" in basic or "CA" in str(cert.get("subject") or "").upper()

    hierarchy: dict[str, Any] = {"roots": [], "intermediates": [], "issuing": [], "server_certificates": []}
    for cert in certs:
        subject = str(cert.get("subject") or "")
        issuer = str(cert.get("issuer") or "")
        role = _role(subject, issuer, cert)
        entry = {
            "subject": subject,
            "issuer": issuer,
            "fingerprint_sha256": str(cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint") or "").lower(),
            "valid_to": cert.get("not_after"),
        }
        if role == "ROOT_CA":
            hierarchy["roots"].append(entry)
        elif role == "INTERMEDIATE_CA":
            hierarchy["intermediates"].append(entry)
        elif role == "ISSUING_CA":
            hierarchy["issuing"].append(entry)
        else:
            hierarchy["server_certificates"].append(entry)
    return hierarchy


def pki_cypher_export(hierarchy: dict[str, Any]) -> str:
    """Cypher to load the PKI hierarchy into Neo4j."""
    statements: list[str] = []
    for role in ("roots", "intermediates", "issuing", "server_certificates"):
        label = role.upper().replace("_", "_")
        for entry in hierarchy.get(role) or []:
            subject = entry["subject"].replace('"', '\\"')
            fp = entry["fingerprint_sha256"]
            statements.append(
                f'MERGE (c:CA {{subject: "{subject}"}}) SET c.role = "{label}"'
                + (f', c.fingerprint = "{fp}"' if fp else "")
                + ";"
            )
    for role in ("intermediates", "issuing", "server_certificates"):
        for entry in hierarchy.get(role) or []:
            subject = entry["subject"].replace('"', '\\"')
            issuer = (entry.get("issuer") or "").replace('"', '\\"')
            if not issuer:
                continue
            statements.append(
                f'MATCH (c:CA {{subject: "{subject}"}}), (p:CA {{subject: "{issuer}"}}) '
                f'MERGE (c)-[:ISSUED_BY]->(p);'
            )
    return "\n".join(statements)
