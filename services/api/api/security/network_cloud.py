"""Cloud network endpoint correlation (spec 67 §21).

A cloud API tells you what a load balancer's *listener policy* says. That is a
declaration: it does not prove which handshake a client actually completed.
This module therefore keeps the two apart and never promotes one to the other:

    cloud API metadata      → NETWORK_CONFIGURED candidate endpoint
    matched observation     → the observed handshake stays authoritative
    no observation          → UNKNOWN with the declaration attached

The module makes no cloud API calls. Metadata is supplied by the caller (an
export, a collector, or an approved read-only connector), so importing it
cannot open a connection or touch a cloud account.
"""

from __future__ import annotations

from typing import Any, Iterable

MODEL = "cryptoscan.cloud-endpoint-correlation/1"

PROVIDERS = ("AWS", "AZURE", "GCP", "OCI", "ALIBABA", "PRIVATE_CLOUD", "UNKNOWN")

#: listener/API-gateway combos that are internet-reachable by definition
PUBLIC_SCHEMES = {"internet-facing", "external", "public", "global"}

#: TLS policy names carrying an explicit version floor
POLICY_VERSION_TOKENS = (
    ("tls13", "TLSv1.3"),
    ("tls1-3", "TLSv1.3"),
    ("tls-1-3", "TLSv1.3"),
    ("tls12", "TLSv1.2"),
    ("tls1-2", "TLSv1.2"),
    ("tls-1-2", "TLSv1.2"),
    ("tls11", "TLSv1.1"),
    ("tls1-1", "TLSv1.1"),
    ("tls-1-1", "TLSv1.1"),
    ("tls10", "TLSv1.0"),
    ("tls1-0", "TLSv1.0"),
    ("tls-1-0", "TLSv1.0"),
    ("ssl", "SSLv3"),
)

LEGACY_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def policy_floor(policy_name: str | None) -> tuple[str | None, bool]:
    """Read the version floor out of a cloud TLS policy name.

    Returns ``(version, deprecated)``. A policy name is a *label*, so the
    version it implies is reported as declared, and the deprecated flag only
    says the named policy admits legacy versions.
    """
    text = _norm(policy_name)
    if not text:
        return None, False
    for token, version in POLICY_VERSION_TOKENS:
        if token in text:
            return version, version in LEGACY_VERSIONS
    return None, False


def _observed_index(evidence: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for record in evidence:
        target = record.get("target") or {}
        for key in (target.get("endpoint"), target.get("host")):
            if key and str(key) not in index:
                index[str(key)] = record
    return index


def _endpoint(host: str, port: Any) -> str:
    return f"{host}:{port if port is not None else 443}"


def correlate(
    resources: Iterable[dict[str, Any]],
    evidence: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Correlate cloud network resources with observed crypto."""
    observed = _observed_index(evidence)
    endpoints: list[dict[str, Any]] = []
    gateways: list[dict[str, Any]] = []
    private_endpoints: list[dict[str, Any]] = []
    kms: list[dict[str, Any]] = []
    issues: list[str] = []

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        provider = str(resource.get("provider") or "UNKNOWN").upper()
        kind = str(resource.get("type") or resource.get("kind") or "").upper()
        name = resource.get("name") or resource.get("id")
        region = resource.get("region")
        scheme = _norm(resource.get("scheme") or resource.get("visibility"))

        if kind in {"LOAD_BALANCER", "ALB", "NLB", "APPLICATION_GATEWAY", "CDN"}:
            for listener in resource.get("listeners") or []:
                if not isinstance(listener, dict):
                    continue
                host = str(resource.get("dns_name") or resource.get("hostname") or name or "")
                port = listener.get("port")
                endpoint = _endpoint(host, port)
                version, deprecated = policy_floor(listener.get("tls_policy") or listener.get("ssl_policy"))
                record = observed.get(endpoint) or observed.get(host)
                item_issues: list[str] = []
                if deprecated:
                    item_issues.append("CLOUD_TLS_POLICY_ADMITS_LEGACY_TLS")
                if scheme in PUBLIC_SCHEMES:
                    item_issues.append("CLOUD_INTERNET_FACING_LISTENER")
                if not listener.get("certificate_arn") and not listener.get("certificate"):
                    item_issues.append("CLOUD_LISTENER_CERTIFICATE_NOT_DECLARED")
                if _norm(resource.get("backend_protocol")) in {"http", "tcp", "plaintext"}:
                    item_issues.append("CLOUD_ORIGIN_LEG_MAY_BE_PLAINTEXT")
                endpoints.append(
                    {
                        "endpoint": endpoint,
                        "provider": provider,
                        "kind": kind,
                        "name": name,
                        "region": region,
                        "port": port,
                        "scheme": resource.get("scheme"),
                        "declared": {
                            "protocol": listener.get("protocol"),
                            "tls_policy": listener.get("tls_policy") or listener.get("ssl_policy"),
                            "declared_floor": version,
                            "certificate_reference": listener.get("certificate_arn") or listener.get("certificate"),
                            "backend_protocol": resource.get("backend_protocol"),
                            "source": "CLOUD_API_METADATA",
                        },
                        "observed": bool(record),
                        "evidence_type": (record or {}).get("evidence_type") or "UNKNOWN",
                        "evidence_id": (record or {}).get("evidence_id"),
                        "observed_tls_version": (record or {}).get("tls_version"),
                        "observed_cipher_suite": (record or {}).get("cipher_suite"),
                        "drift": (
                            None
                            if not record or not version or not (record or {}).get("tls_version")
                            else "MATCH"
                            if _norm((record or {}).get("tls_version")) == _norm(version)
                            else "DIFFERS"
                        ),
                        "issues": item_issues,
                        "note": None
                        if record
                        else "cloud metadata declares this listener — no handshake observed, so its crypto is UNKNOWN",
                    }
                )
            continue

        if kind in {"API_GATEWAY", "API_MANAGEMENT", "EDGE_GATEWAY"}:
            host = str(resource.get("dns_name") or resource.get("hostname") or name or "")
            minimum = _norm(resource.get("minimum_tls_version") or resource.get("min_tls")).replace("_", "-")
            endpoints.append(
                {
                    "endpoint": _endpoint(host, 443),
                    "provider": provider,
                    "kind": "API_GATEWAY",
                    "name": name,
                    "region": region,
                    "port": 443,
                    "scheme": resource.get("endpoint_type") or resource.get("scheme"),
                    "declared": {
                        "minimum_tls_version": minimum or None,
                        "mutual_tls": resource.get("mutual_tls"),
                        "custom_domain": resource.get("custom_domain"),
                        "source": "CLOUD_API_METADATA",
                    },
                    "observed": bool(observed.get(_endpoint(host, 443)) or observed.get(host)),
                    "evidence_type": (observed.get(_endpoint(host, 443)) or observed.get(host) or {}).get("evidence_type")
                    or "UNKNOWN",
                    "issues": (
                        ["CLOUD_GATEWAY_MIN_TLS_LEGACY"] if minimum in {"tls-1-0", "tls1-0", "tls-1-1", "tls1-1"} else []
                    ),
                    "note": "gateway TLS configuration is declared by the cloud API, not observed by a handshake",
                }
            )
            gateways.append({"name": name, "provider": provider, "type": resource.get("gateway_type") or "REST"})
            continue

        if kind in {"PRIVATE_ENDPOINT", "SERVICE_ENDPOINT", "VPC_ENDPOINT", "PRIVATE_LINK"}:
            private_endpoints.append(
                {
                    "name": name,
                    "provider": provider,
                    "service": resource.get("service") or resource.get("service_name"),
                    "endpoint": resource.get("endpoint") or resource.get("dns_name"),
                    "subnets": list(resource.get("subnets") or [])[:50],
                    "note": "private endpoints carry provider-managed crypto — their parameters are not observable from the tenant side",
                }
            )
            continue

        if kind in {"VPN_GATEWAY", "VPN_CONNECTION", "EXPRESS_ROUTE", "INTERCONNECT"}:
            gateways.append(
                {
                    "name": name,
                    "provider": provider,
                    "type": kind,
                    "tunnel_crypto": resource.get("tunnel_crypto") or "UNKNOWN",
                    "note": "tunnel crypto parameters are declared by the cloud API; the negotiated SA is not observable here",
                }
            )
            continue

        if kind in {"KMS", "KEY_MANAGEMENT", "HSM"}:
            kms.append(
                {
                    "name": name,
                    "provider": provider,
                    "type": kind,
                    "note": "KMS/HSM key material and algorithms are outside network observation entirely",
                }
            )

    for item in endpoints:
        issues.extend(item["issues"])
    observed_count = len([item for item in endpoints if item.get("observed")])
    drift = [item for item in endpoints if item.get("drift") == "DIFFERS"]
    return {
        "model": MODEL,
        "endpoints": endpoints,
        "gateways": gateways,
        "private_endpoints": private_endpoints,
        "kms": kms,
        "issues": sorted(set(issues)),
        "drift": [
            {
                "endpoint": item["endpoint"],
                "declared": item["declared"]["declared_floor"],
                "observed": item["observed_tls_version"],
                "note": "the declared policy floor and the negotiated version disagree — review, do not auto-correct",
            }
            for item in drift
        ],
        "summary": {
            "resources": len([item for item in endpoints]) + len(gateways) + len(private_endpoints) + len(kms),
            "endpoints": len(endpoints),
            "observed_endpoints": observed_count,
            "declared_only_endpoints": len(endpoints) - observed_count,
            "api_gateways": len(gateways),
            "private_endpoints": len(private_endpoints),
            "kms_services": len(kms),
            "drift": len(drift),
            "internet_facing": len([item for item in endpoints if "CLOUD_INTERNET_FACING_LISTENER" in item["issues"]]),
        },
        "governance": {
            "read_only": True,
            "cloud_api_calls": 0,
            "metadata_source": "caller_supplied",
            "write_operations": 0,
        },
        "limitations": [
            "cloud API metadata is a declaration: it is NETWORK_CONFIGURED, never an observed handshake",
            "provider-managed crypto (private link, managed KMS, CDN edge crypto) is not observable from the tenant side",
            "a declared TLS policy floor does not prove the listener refuses older versions",
            "nothing is corrected automatically: a declared/observed drift is a review item",
        ],
        "boundary": "cloud network metadata correlated with network observation; application and storage crypto stay separate",
    }
