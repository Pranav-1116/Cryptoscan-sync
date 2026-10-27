"""Evidence for SSH and database transport crypto (spec 67 §12, §18, §24).

Both protocols have the same trap as TLS: seeing an *offer* is not seeing a
*negotiation*, and seeing transport encryption is not seeing storage or
application encryption. The records below therefore keep those apart:

    SSH     algorithms the server offers  ≠  the algorithms a session negotiates
            (CryptoScan never authenticates, so nothing is negotiated)
    DB      transport TLS  ≠  TDE  ≠  column encryption  ≠  runtime queries

A database that answers "no TLS" is recorded with its refusal and a policy
issue; a database that completes a handshake gets real negotiated parameters.
Either way TDE and column encryption stay ``NOT_OBSERVED`` — they are invisible
from the network and belong to the database collector, not to this engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from network_scanner.inventory.network_evidence import (
    OBSERVED_EVIDENCE_TYPES,
    SCHEMA,
)

PROTOCOL_CBOM_MODEL = "cryptoscan.protocol-cbom/1"

#: longest service banner kept — identification only, never application content
BANNER_LIMIT_PROTOCOL = 120

#: SSH roles, distinct from TLS roles (§12, §28)
ROLE_SSH_KEX = "ssh-key-exchange"
ROLE_SSH_HOST_KEY = "ssh-host-key"
ROLE_SSH_CIPHER = "ssh-cipher"
ROLE_SSH_MAC = "ssh-mac"

#: database transport roles (§18)
ROLE_DB_TLS_BULK = "db-transport-encryption"
ROLE_DB_TLS_KEX = "db-transport-key-exchange"
ROLE_DB_TLS_AUTH = "db-transport-authentication"
ROLE_DB_CERT_SIGNATURE = "db-certificate-signature"

#: things the network cannot see, always reported (§18, §29)
DATABASE_OUT_OF_REACH = (
    "TDE (transparent data encryption) is a database feature — not visible on the wire",
    "column/field-level encryption is application behaviour — not visible on the wire",
    "query-level crypto operations require the runtime collector, not the network scanner",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _split_endpoint(endpoint: str | None) -> tuple[str | None, int | None]:
    host, _, port_text = str(endpoint or "").rpartition(":")
    if not host:
        return (endpoint or None), None
    return host.strip("[]") or None, int(port_text) if port_text.isdigit() else None


def _base_record(
    endpoint: str | None,
    *,
    protocol: str,
    evidence_type: str,
    observation_status: str,
    observed_at: str | None,
    scope_name: str | None,
    scope_revision: str | None,
    confidence: str,
) -> dict[str, Any]:
    host, port = _split_endpoint(endpoint)
    return {
        "schema": SCHEMA,
        "evidence_type": evidence_type,
        "evidence_id": f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": endpoint,
            "host": host,
            # an IP literal keeps the endpoint honest; a hostname is resolved by
            # the caller, the scanner never claims an address it did not observe
            "ip_address": host if host and host.replace(".", "").isdigit() else None,
            "port": port,
        },
        "protocol": protocol,
        "observation_status": observation_status,
        "tls_version": None,
        "cipher_suite": None,
        "decomposition": {
            "key_exchange": None,
            "authentication": None,
            "encryption": None,
            "mode": None,
            "mac_or_prf": None,
            "key_size_bits": None,
        },
        "certificate": {
            "fingerprint_sha256": None,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "public_key_algorithm": None,
            "public_key_bits": None,
            "curve": None,
            "signature_algorithm": None,
            "san_count": None,
        },
        "certificate_chain": {"length": None, "structural_status": None, "trust_status": None, "completeness": None},
        "mutual_tls": "NOT_APPLICABLE",
        "mtls_evidence": "NOT_APPLICABLE",
        "policy_issues": [],
        "algorithm_verdict": {},
        "observed_at": observed_at or _now(),
        "scanner_version": "network-protocol-scanner-v1.0",
        "scope_revision": scope_revision,
        "scope_name": scope_name,
        "confidence": confidence,
        "limitations": [],
    }


def build_ssh_evidence(
    *,
    endpoint: str,
    kex: dict[str, Any] | None = None,
    host_keys: dict[str, Any] | None = None,
    observed_at: str | None = None,
    scope_name: str | None = None,
    scope_revision: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """§12 evidence from an SSH KEXINIT offer and/or host-key observation."""
    kex = kex or {}
    host_keys = host_keys or {}
    offered = str(kex.get("status") or "").upper() == "OK"
    keys_observed = str(host_keys.get("status") or "").upper() == "OK" and bool(host_keys.get("keys"))
    observed = offered or keys_observed

    record = _base_record(
        endpoint,
        protocol="SSH",
        evidence_type="NETWORK_ACTIVE_OBSERVED" if observed else "UNKNOWN",
        observation_status="ALGORITHMS_OFFERED" if observed else (kex.get("status") or host_keys.get("status") or "NO_RESPONSE"),
        observed_at=observed_at,
        scope_name=scope_name,
        scope_revision=scope_revision,
        confidence="HIGH" if offered else "MEDIUM",
    )

    kex_algorithms = list(kex.get("kex_algorithms") or [])
    host_key_algorithms = list(kex.get("host_key_algorithms") or [])
    ciphers = list(kex.get("ciphers") or [])
    macs = list(kex.get("macs") or [])
    compression = list(kex.get("compression") or [])
    keys = list(host_keys.get("keys") or [])

    # The `decomposition` block is a summary of the *offer*; it is populated so
    # the shared summary/CBOM code paths work, and every field is re-labelled as
    # an offer rather than a negotiated value below.
    if kex_algorithms:
        record["decomposition"]["key_exchange"] = kex_algorithms[0]
    if host_key_algorithms:
        record["decomposition"]["authentication"] = host_key_algorithms[0]
    elif keys:
        record["decomposition"]["authentication"] = keys[0].get("key_type")
    if ciphers:
        record["decomposition"]["encryption"] = ciphers[0]
    if macs:
        record["decomposition"]["mac_or_prf"] = macs[0]
    if keys:
        record["certificate"]["public_key_algorithm"] = keys[0].get("key_type")
        record["certificate"]["public_key_bits"] = keys[0].get("bits")
        record["certificate"]["fingerprint_sha256"] = keys[0].get("fingerprint_sha256")

    record["ssh"] = {
        "server_banner": (kex.get("server_banner") or "")[:BANNER_LIMIT_PROTOCOL] or None,
        "version": _ssh_version(kex.get("server_banner")),
        "algorithms_offered": {
            "kex": kex_algorithms,
            "host_key": host_key_algorithms,
            "cipher": ciphers,
            "mac": macs,
            "compression": compression,
        },
        # nothing is negotiated: CryptoScan sends no user auth and completes no
        # key exchange, so the session suite is genuinely unknown (§12, §29)
        "negotiated": None,
        "negotiation_status": "NOT_NEGOTIATED" if observed else "NOT_OBSERVED",
        "host_keys": [
            {
                "key_type": key.get("key_type"),
                "bits": key.get("bits"),
                "fingerprint_sha256": key.get("fingerprint_sha256"),
                "verdict": (key.get("verdict") or {}).get("status"),
            }
            for key in keys
        ],
        "weak_offers": (kex.get("weak") or {}),
        "legacy_offers": (kex.get("legacy") or {}),
    }

    issues = sorted(set(list(kex.get("policy_issues") or []) + list(host_keys.get("policy_issues") or [])))
    record["policy_issues"] = issues

    if not observed:
        record["limitations"].append(
            "no SSH KEXINIT/host key was obtained — reachability failure is not proof of weak crypto"
        )
    else:
        record["limitations"].append(
            "algorithms_offered is the server's offer; no session was negotiated, so the algorithms "
            "actually used in production are NOT_OBSERVED"
        )
    record["limitations"].append(
        "SSH user authentication, authorized_keys and per-user differences are out of network reach"
    )
    if extra:
        record["context"] = dict(extra)
    return record


def _ssh_version(banner: str | None) -> str | None:
    text = str(banner or "").strip()
    if not text.startswith("SSH-"):
        return None
    return text.split("-")[1] if len(text.split("-")) > 1 else None


def build_database_evidence(
    *,
    endpoint: str,
    engine: str,
    detection: dict[str, Any] | None = None,
    tls: dict[str, Any] | None = None,
    observed_at: str | None = None,
    scope_name: str | None = None,
    scope_revision: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """§18 evidence: database *transport* crypto, with TDE kept out of reach."""
    detection = detection or {}
    details = detection.get("details") or {}
    postgres = details.get("postgres") or {}
    mysql = details.get("mysql") or {}
    handshake = tls or detection.get("tls") or None
    ssl_supported = postgres.get("ssl_supported")
    ssl_capable = mysql.get("ssl_capable")
    handshake_done = bool(handshake)

    record = _base_record(
        endpoint,
        protocol=str(engine or detection.get("detected") or "DATABASE").upper(),
        evidence_type="NETWORK_ACTIVE_OBSERVED" if handshake_done else "UNKNOWN",
        observation_status="TLS_HANDSHAKE" if handshake_done else ("TLS_REFUSED" if ssl_supported is False else "TLS_NOT_NEGOTIATED"),
        observed_at=observed_at,
        scope_name=scope_name,
        scope_revision=scope_revision,
        confidence="HIGH" if handshake_done else "MEDIUM",
    )

    if handshake_done:
        record["tls_version"] = handshake.get("tls_version")
        record["cipher_suite"] = handshake.get("cipher_suite")
        pair = _split_bundle(handshake.get("cipher_suite"), handshake.get("tls_version"))
        record["decomposition"].update(pair)

    record["database"] = {
        "engine": str(engine or "").upper() or None,
        "server_version": mysql.get("server_version"),
        "transport": {
            "tls_negotiated": handshake_done,
            "tls_version": handshake.get("tls_version") if handshake_done else None,
            "cipher_suite": handshake.get("cipher_suite") if handshake_done else None,
            "ssl_request_answer": postgres.get("answer"),
            "ssl_supported": ssl_supported if ssl_supported is not None else ssl_capable,
        },
        # Explicit, so nobody reads a TLS observation as a storage-crypto fact.
        "tde": "NOT_OBSERVED",
        "column_encryption": "NOT_OBSERVED",
        "runtime_operations": "NOT_OBSERVED",
        "out_of_reach": list(DATABASE_OUT_OF_REACH),
    }

    issues: list[str] = []
    if ssl_supported is False:
        issues.append("DB_TRANSPORT_TLS_NOT_OFFERED")
    if ssl_capable is False:
        issues.append("DB_CLIENT_SSL_UNSUPPORTED")
    if handshake_done and str(handshake.get("tls_version") or "") in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
        issues.append(f"DB_LEGACY_TLS:{handshake.get('tls_version')}")
    record["policy_issues"] = issues

    if not handshake_done:
        record["limitations"].append(
            "no TLS handshake completed on this database port — transport crypto is NOT_OBSERVED"
            if ssl_supported is not False
            else "the server answered that it does not offer TLS on this connection — recorded as a refusal, "
            "not as an absence of crypto in the database"
        )
    record["limitations"].extend(DATABASE_OUT_OF_REACH)
    if extra:
        record["context"] = dict(extra)
    return record


def _split_bundle(name: str | None, version: str | None) -> dict[str, Any]:
    from network_scanner.probing.cipher_suite_parser import parse_cipher_suite

    parsed = parse_cipher_suite(name, tls_version=version)
    return {
        "key_exchange": parsed.get("key_exchange"),
        "authentication": parsed.get("authentication"),
        "encryption": parsed.get("encryption"),
        "mode": parsed.get("mode"),
        "mac_or_prf": parsed.get("mac"),
        "key_size_bits": parsed.get("key_size"),
    }


def build_protocol_evidence(
    detection: dict[str, Any],
    *,
    observed_at: str | None = None,
    scope_name: str | None = None,
    scope_revision: str | None = None,
) -> dict[str, Any]:
    """An evidence record for an endpoint whose protocol carries no crypto.

    Keeping an ``UNKNOWN`` record for a detected plaintext/unknown service is
    the point: the estate view must show the endpoint and its evidence gap
    instead of silently omitting it (§23, §29).
    """
    detected = str(detection.get("detected") or "UNKNOWN").upper()
    endpoint = f"{detection.get('host')}:{detection.get('port')}"
    record = _base_record(
        endpoint,
        protocol=detected,
        evidence_type="UNKNOWN",
        observation_status=f"PROTOCOL_{detected}",
        observed_at=observed_at,
        scope_name=scope_name,
        scope_revision=scope_revision,
        confidence="LOW",
    )
    record["detection"] = {
        "method": detection.get("detection_method"),
        "confidence": detection.get("confidence"),
        "service_guess": detection.get("service_guess"),
        "port_matches_protocol": detection.get("port_matches_protocol"),
        "tls_capable": detection.get("tls_capable"),
        "attempts": detection.get("attempts") or [],
    }
    record["limitations"].append(
        f"detected protocol {detected} exposes no cryptographic parameters on this port — UNKNOWN, not SAFE"
        if detected != "UNKNOWN"
        else "no protocol identified — UNKNOWN is the result, not a clean verdict"
    )
    return record


# --------------------------------------------------------------------------- #
# §28 — SSH / database crypto assets
# --------------------------------------------------------------------------- #


def _asset(
    record: dict[str, Any],
    *,
    algorithm: str | None,
    role: str,
    observation_mode: str = "ACTIVE",
    key_size: int | None = None,
    note: str | None = None,
) -> dict[str, Any] | None:
    if not algorithm:
        return None
    target = record.get("target") or {}
    return {
        "asset_id": f"{target.get('endpoint') or 'unknown'}:{role}:{algorithm}",
        "algorithm": algorithm,
        "role": role,
        "key_size": key_size,
        "curve": None,
        "mode": None,
        "layer": "NETWORK_TRANSPORT",
        "protocol": record.get("protocol"),
        "observation_mode": observation_mode,
        "context": {
            "endpoint": target.get("endpoint"),
            "host": target.get("host"),
            "port": target.get("port"),
            "protocol": record.get("protocol"),
            "tls_version": record.get("tls_version"),
            "cipher_suite": record.get("cipher_suite"),
            "note": note,
        },
        "evidence": {
            "evidence_id": record.get("evidence_id"),
            "evidence_type": record.get("evidence_type"),
            "observed_at": record.get("observed_at"),
            "confidence": record.get("confidence"),
            "scope_name": record.get("scope_name"),
        },
        "policy_issues": list(record.get("policy_issues") or []),
        "quantum_impact": None,
    }


def to_protocol_cbom_assets(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Project SSH/database evidence into CBOM assets (§12, §18, §28).

    SSH assets describe the *offer* (the session is never negotiated), and the
    database assets describe *transport only* — TDE and column encryption never
    become assets here because nothing observed them.
    """
    assets: list[dict[str, Any]] = []
    not_observed: list[str] = []
    for record in records:
        protocol = str(record.get("protocol") or "").upper()
        endpoint = (record.get("target") or {}).get("endpoint") or "unknown"
        if record.get("evidence_type") not in OBSERVED_EVIDENCE_TYPES:
            not_observed.append(endpoint)
            continue
        if protocol == "SSH":
            ssh = record.get("ssh") or {}
            offered = ssh.get("algorithms_offered") or {}
            candidates = [
                _asset(record, algorithm=(offered.get("kex") or [None])[0], role=ROLE_SSH_KEX, note="offered, not negotiated"),
                _asset(record, algorithm=(offered.get("host_key") or [None])[0], role=ROLE_SSH_HOST_KEY, note="offered, not negotiated"),
                _asset(record, algorithm=(offered.get("cipher") or [None])[0], role=ROLE_SSH_CIPHER, note="offered, not negotiated"),
                _asset(record, algorithm=(offered.get("mac") or [None])[0], role=ROLE_SSH_MAC, note="offered, not negotiated"),
            ]
            assets.extend(item for item in candidates if item)
            continue
        if protocol in {"POSTGRESQL", "POSTGRES", "MYSQL", "MARIADB", "DATABASE"}:
            decomposition = record.get("decomposition") or {}
            certificate = record.get("certificate") or {}
            candidates = [
                _asset(record, algorithm=decomposition.get("encryption"), role=ROLE_DB_TLS_BULK, key_size=decomposition.get("key_size_bits")),
                _asset(record, algorithm=decomposition.get("key_exchange"), role=ROLE_DB_TLS_KEX),
                _asset(record, algorithm=decomposition.get("authentication"), role=ROLE_DB_TLS_AUTH),
                _asset(record, algorithm=certificate.get("signature_algorithm"), role=ROLE_DB_CERT_SIGNATURE),
            ]
            assets.extend(item for item in candidates if item)

    algorithms: dict[str, int] = {}
    roles: dict[str, int] = {}
    protocols: dict[str, int] = {}
    for asset in assets:
        algorithms[asset["algorithm"]] = algorithms.get(asset["algorithm"], 0) + 1
        roles[asset["role"]] = roles.get(asset["role"], 0) + 1
        protocols[str(asset.get("protocol"))] = protocols.get(str(asset.get("protocol")), 0) + 1
    return {
        "model": PROTOCOL_CBOM_MODEL,
        "layer": "NETWORK_TRANSPORT",
        "asset_count": len(assets),
        "assets": assets,
        "algorithms": algorithms,
        "roles": roles,
        "protocols": protocols,
        "not_observed": sorted(not_observed),
        "boundary": (
            "SSH entries are algorithm offers (no session negotiated); database entries are transport "
            "TLS only — TDE, column encryption and runtime operations are separate layers"
        ),
    }
