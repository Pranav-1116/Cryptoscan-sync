"""Normalize network observations into Cryptographic Network Intelligence evidence.

Design spec: ``docs/bank-environment/67-network-crypto-discovery-engine.md`` §24.

An evidence record states only what the observation actually produced. Anything
the probe could not determine — mutual TLS, private-key size, application-layer
crypto, HSM/KMS internals — stays ``UNKNOWN``; it is never rendered as "safe"
or as "no crypto" (§29). Records are plain dictionaries so the API, CBOM/NBOM
builders and the graph can consume the same object.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

#: §23 evidence taxonomy. A record carries exactly one of these.
EVIDENCE_TYPES = (
    "NETWORK_ACTIVE_OBSERVED",
    "NETWORK_PASSIVE_OBSERVED",
    "NETWORK_CONFIGURED",
    "CERTIFICATE_OBSERVED",
    "VENDOR_DECLARED",
    "IMPORTED",
    "UNKNOWN",
)

#: Outcomes that prove the endpoint answered a handshake we initiated.
_OBSERVED_STATUSES = {"OK"}

#: Outcomes that prove reachability but not cryptographic parameters.
_REACHABILITY_STATUSES = {"PORT_CLOSED", "TIMEOUT", "CONNECT_ERROR", "DNS_FAILED", "STARTTLS_REFUSED"}

SCHEMA = "cryptoscan.network-evidence/1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_type_for(finding: dict[str, Any]) -> str:
    """Classify one probe finding without upgrading inference into observation."""
    if not finding:
        return "UNKNOWN"
    status = str(finding.get("status") or "").upper()
    if status in _OBSERVED_STATUSES and (finding.get("crypto") or {}).get("cipher_suite"):
        return "NETWORK_ACTIVE_OBSERVED"
    if finding.get("certificates"):
        return "CERTIFICATE_OBSERVED"
    return "UNKNOWN"


def _leaf(finding: dict[str, Any]) -> dict[str, Any]:
    certs = finding.get("certificates") or []
    return certs[0] if certs and isinstance(certs[0], dict) else {}


def build_evidence(
    finding: dict[str, Any],
    *,
    scanner_version: str = "network-tls-scanner-v1.0",
    scope_revision: str | None = None,
    observed_at: str | None = None,
    scope_name: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one §24 evidence record from one active-probe finding.

    The record never contains payload, credentials, private keys or customer
    data — only negotiated parameters and public certificate metadata.
    """
    crypto = finding.get("crypto") or {}
    leaf = _leaf(finding)
    chain = finding.get("chain_validation") or {}
    status = str(finding.get("status") or "UNKNOWN").upper()
    evidence_type = evidence_type_for(finding)

    public_key_algorithm = leaf.get("public_key_algorithm") or leaf.get("public_key_type")
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "evidence_type": evidence_type,
        "evidence_id": finding.get("finding_id") or f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": finding.get("endpoint"),
            "host": finding.get("metadata", {}).get("endpoint_hostname") or finding.get("endpoint", "").rsplit(":", 1)[0],
            "port": int(str(finding.get("endpoint", ":0")).rsplit(":", 1)[-1] or 0),
            "ip_address": finding.get("ip_address"),
        },
        "protocol": "TLS",
        "observation_status": status,
        "tls_version": crypto.get("tls_version"),
        "cipher_suite": crypto.get("cipher_suite"),
        # §7/§8 decomposition — never store only the OpenSSL suite name
        "decomposition": {
            "key_exchange": crypto.get("key_exchange_algorithm"),
            "authentication": crypto.get("authentication_algorithm"),
            "encryption": crypto.get("encryption_algorithm"),
            "mode": crypto.get("encryption_mode"),
            "mac_or_prf": crypto.get("mac_algorithm"),
            "key_size_bits": crypto.get("key_size"),
        },
        "certificate": {
            "fingerprint_sha256": leaf.get("fingerprint_sha256"),
            "subject": leaf.get("subject"),
            "issuer": leaf.get("issuer"),
            "not_before": leaf.get("not_before"),
            "not_after": leaf.get("not_after"),
            "public_key_algorithm": public_key_algorithm,
            "public_key_bits": leaf.get("public_key_bits") or leaf.get("key_size"),
            "curve": leaf.get("curve") or leaf.get("ec_curve"),
            "signature_algorithm": leaf.get("signature_algorithm"),
            "san_count": len(leaf.get("san") or []),
        },
        "certificate_chain": {
            "length": len(finding.get("certificates") or []),
            "structural_status": chain.get("structural_status"),
            "trust_status": chain.get("trust_status"),
            "completeness": chain.get("chain_completeness"),
        },
        # A handshake that completed with no client certificate proves the
        # server did not *require* one on this path. Whether it *offers*
        # optional mTLS is not visible to a server-only handshake, so the
        # record says NOT_REQUIRED (observed) rather than "mTLS disabled".
        "mutual_tls": finding.get("mutual_tls")
        or ("NOT_REQUIRED" if evidence_type == "NETWORK_ACTIVE_OBSERVED" else "UNKNOWN"),
        "mtls_evidence": "CLIENT_CERT_REQUESTED"
        if finding.get("client_cert_requested")
        else ("HANDSHAKE_WITHOUT_CLIENT_CERT" if evidence_type == "NETWORK_ACTIVE_OBSERVED" else "NOT_PROBED"),
        "policy_issues": list(finding.get("policy_issues") or []),
        "algorithm_verdict": finding.get("algorithm_verdict") or {},
        "observed_at": observed_at or _now(),
        "scanner_version": scanner_version,
        "scope_revision": scope_revision,
        "scope_name": scope_name,
        "confidence": (finding.get("metadata") or {}).get("confidence", "LOW"),
        "limitations": [],
    }

    if evidence_type != "NETWORK_ACTIVE_OBSERVED":
        record["limitations"].append(
            "no cryptographic parameters observed — reachability/refusal is not proof of absence"
        )
    if record["mutual_tls"] == "NOT_REQUIRED":
        record["limitations"].append(
            "handshake completed without a client certificate: mTLS was not required here; "
            "optional client-certificate requests are not distinguishable"
        )
    elif record["mutual_tls"] == "UNKNOWN":
        record["limitations"].append("mutual TLS requirement is not determinable without a completed handshake")
    record["limitations"].append("application-layer, storage and HSM/KMS crypto are out of network reach")

    if extra:
        record["context"] = dict(extra)
    return record


#: §13 — IPsec roles, kept distinct from TLS roles in the CBOM
ROLE_IKE_KEX = "ike-key-exchange"
ROLE_IKE_ENC = "ike-encryption"
ROLE_IKE_INTEG = "ike-integrity"
ROLE_ESP_ENC = "esp-encryption"
ROLE_ESP_INTEG = "esp-integrity"


def build_ipsec_evidence(
    probe: dict[str, Any],
    *,
    scanner_version: str = "network-ipsec-scanner-v1.0",
    scope_revision: str | None = None,
    observed_at: str | None = None,
    scope_name: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One §13/§24 evidence record from an IKE SA proposal observation.

    Both versions are covered: an IKEv2 SA_INIT reply and an IKEv1 Main Mode
    reply carry the same readable phase-1 suite, and ``ike.version`` reports
    which one answered. ``IKE_AUTH``/Quick Mode is never attempted, so the
    authentication method, peer identity and the ESP transform set remain
    ``UNKNOWN``/``NOT_OBSERVED``, each with the basis it rests on. A responder
    that refused the proposal is reported as a refusal with its notify reason —
    that is still not evidence that the gateway has no crypto.
    """
    status = str(probe.get("status") or "UNKNOWN").upper()
    ike = probe.get("ike") or None
    esp = probe.get("esp") or {"status": "NOT_OBSERVED"}
    endpoint = str(probe.get("endpoint") or "")
    host, _, port_text = endpoint.rpartition(":")
    observed = status == "OK" and bool(ike)
    evidence_type = "NETWORK_ACTIVE_OBSERVED" if observed else "UNKNOWN"

    record: dict[str, Any] = {
        "schema": SCHEMA,
        "evidence_type": evidence_type,
        # assigned at build time so the response, the stored run and the hash
        # chain all reference the same identity
        "evidence_id": f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": endpoint or None,
            "host": host or None,
            "port": int(port_text) if port_text.isdigit() else None,
            "ip_address": host if host and host[0].isdigit() else None,
        },
        "protocol": "IPsec",
        "observation_status": status,
        # IKE decomposition in the shared shape so the summary/CBOM builders do
        # not need a second code path; ESP stays separately labelled.
        "decomposition": {
            "key_exchange": (ike or {}).get("dh_group"),
            "authentication": None,  # IKE_AUTH not attempted
            "encryption": (ike or {}).get("encryption"),
            "mode": "AEAD" if (ike or {}).get("integrity") == "AEAD" else None,
            "mac_or_prf": (ike or {}).get("prf") or (ike or {}).get("integrity"),
            "key_size_bits": None,
        },
        "ike": {
            # the version the responder actually spoke, from its own header
            "version": (probe.get("header") or {}).get("version") or probe.get("ike_version") or None,
            "encryption": (ike or {}).get("encryption"),
            "prf": (ike or {}).get("prf"),
            "integrity": (ike or {}).get("integrity"),
            "dh_group": (ike or {}).get("dh_group"),
            "esn": (ike or {}).get("esn"),
            # Certificate vs PSK vs EAP is only visible in IKE_AUTH. IKEv1 does
            # *offer* its method in the phase-1 proposal — recorded as offered.
            "authentication": "UNKNOWN",
            "auth_methods_offered": (ike or {}).get("auth_methods_offered"),
        },
        "esp": {
            "status": esp.get("status") or "NOT_OBSERVED",
            # what the ESP claim rests on: RESPONDER_OFFERED, CONFIGURATION or
            # NOT_OBSERVED — never a bare assertion that ESP is "in use"
            "basis": esp.get("basis") or "NOT_OBSERVED",
            "encryption": esp.get("encryption"),
            "integrity": esp.get("integrity"),
            "dh_group": esp.get("dh_group"),
            # PFS applies to the CHILD_SA. Without an ESP proposal (or a
            # configured suite) it is UNKNOWN, and pfs_state says so once.
            "pfs": esp.get("pfs") or "UNKNOWN",
            "pfs_state": esp.get("pfs_state") or "UNKNOWN",
            "pfs_basis": esp.get("pfs_basis") or "NOT_OBSERVED",
            "reason": esp.get("reason"),
        },
        "ke": probe.get("ke"),
        "header": probe.get("header"),
        "notifies": list(probe.get("notifies") or []),
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
        # Gateway identity is authenticated in IKE_AUTH; a SA_INIT reply proves
        # the responder speaks IKE, not who it is.
        "mutual_tls": "NOT_APPLICABLE",
        "mtls_evidence": "NOT_APPLICABLE",
        "policy_issues": list(probe.get("issues") or []),
        "algorithm_verdict": {},
        "observed_at": observed_at or _now(),
        "scanner_version": scanner_version,
        "scope_revision": scope_revision,
        "scope_name": scope_name,
        "confidence": "MEDIUM" if observed else "LOW",
        "limitations": [],
    }

    if not observed:
        record["limitations"].append(
            "no IKE SA accepted: reachability/refusal is not proof that the gateway has no crypto"
            if status in {"NO_PROPOSAL_CHOSEN", "INVALID_KE", "NO_PROPOSAL"}
            else "gateway did not answer IKE on the probed UDP port — NOT_OBSERVED, not NO_CRYPTO"
        )
    else:
        record["limitations"].append(
            "IKE_AUTH was not attempted: peer authentication (certificate/PSK/EAP) and identity are UNKNOWN"
        )
    record["limitations"].append(
        "ESP/CHILD_SA transforms are negotiated inside IKE_AUTH and are NOT_OBSERVED here"
    )
    record["limitations"].append(
        "an IKE proposal is the responder's offer, not a VPN policy verdict — tunnel selectors and traffic are out of scope"
    )

    if extra:
        record["context"] = dict(extra)
    return record


def summarize(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic counts for the dashboard; unobserved stays UNKNOWN."""
    records = list(records)
    versions: dict[str, int] = {}
    ciphers: dict[str, int] = {}
    key_exchange: dict[str, int] = {}
    signatures: dict[str, int] = {}
    evidence_types: dict[str, int] = {}
    issue_counts: dict[str, int] = {}
    observed = 0
    active = 0
    passive = 0
    for record in records:
        evidence_types[record.get("evidence_type") or "UNKNOWN"] = (
            evidence_types.get(record.get("evidence_type") or "UNKNOWN", 0) + 1
        )
        if record.get("evidence_type") not in OBSERVED_EVIDENCE_TYPES:
            continue
        observed += 1
        if record.get("evidence_type") == "NETWORK_PASSIVE_OBSERVED":
            passive += 1
        else:
            active += 1
        for key, bucket in (
            (record.get("tls_version") or "UNKNOWN", versions),
            (record.get("cipher_suite") or "UNKNOWN", ciphers),
            ((record.get("decomposition") or {}).get("key_exchange") or "UNKNOWN", key_exchange),
            ((record.get("certificate") or {}).get("signature_algorithm") or "UNKNOWN", signatures),
        ):
            bucket[key] = bucket.get(key, 0) + 1
        for issue in record.get("policy_issues") or []:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    return {
        "schema": "cryptoscan.network-evidence-summary/1",
        "records": len(records),
        "observed": observed,
        "observed_active": active,
        "observed_passive": passive,
        "not_observed": len(records) - observed,
        "evidence_types": evidence_types,
        "tls_versions": versions,
        "cipher_suites": ciphers,
        "key_exchange": key_exchange,
        "signature_algorithms": signatures,
        "policy_issues": issue_counts,
        "unknown_note": "endpoints without an observed handshake are NOT_OBSERVED, not NO_CRYPTO",
    }


# --------------------------------------------------------------------------- #
# §28 — network evidence → CBOM crypto assets
# --------------------------------------------------------------------------- #

#: roles a network observation can contribute to a CBOM
ROLE_TLS_BULK = "tls-bulk-encryption"
ROLE_TLS_KEX = "tls-key-exchange"
ROLE_TLS_AUTH = "tls-authentication"
ROLE_TLS_MAC = "tls-mac-or-prf"
ROLE_CERT_SIGNATURE = "certificate-signature"


#: evidence types that carry observed parameters (active handshake or sensor)
OBSERVED_EVIDENCE_TYPES = frozenset({"NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED"})


def _asset(
    record: dict[str, Any],
    *,
    algorithm: str | None,
    role: str,
    key_size: int | None = None,
    curve: str | None = None,
    mode: str | None = None,
) -> dict[str, Any] | None:
    if not algorithm:
        return None
    target = record.get("target") or {}
    certificate = record.get("certificate") or {}
    return {
        "asset_id": f"{target.get('endpoint') or 'unknown'}:{role}:{algorithm}",
        "algorithm": algorithm,
        "role": role,
        "key_size": key_size,
        "curve": curve,
        "mode": mode,
        # §27 — transport crypto is not application crypto
        "layer": "NETWORK_TRANSPORT",
        # active handshake vs passive sensor: the same algorithm, two different
        # strengths of evidence — never collapsed into one confidence.
        "observation_mode": "PASSIVE" if record.get("evidence_type") == "NETWORK_PASSIVE_OBSERVED" else "ACTIVE",
        "context": {
            "host": target.get("host"),
            "port": target.get("port"),
            "ip_address": target.get("ip_address"),
            "endpoint": target.get("endpoint"),
            "protocol": record.get("protocol"),
            "tls_version": record.get("tls_version"),
            "cipher_suite": record.get("cipher_suite"),
            "certificate_fingerprint_sha256": certificate.get("fingerprint_sha256"),
        },
        "evidence": {
            "evidence_id": record.get("evidence_id"),
            "evidence_type": record.get("evidence_type"),
            "observed_at": record.get("observed_at"),
            "confidence": record.get("confidence"),
            "scope_name": record.get("scope_name"),
        },
        "policy_issues": list(record.get("policy_issues") or []),
        "quantum_impact": (record.get("algorithm_verdict") or {}).get("quantum_impact"),
    }


def to_cbom_assets(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Project observed network evidence into CBOM-shaped crypto assets (§28).

    Both active handshake and passive sensor records contribute assets (each
    asset states which). A record with no observed parameters contributes
    nothing: it is counted as ``not_observed`` instead of being given a
    placeholder asset (§29).
    """
    assets: list[dict[str, Any]] = []
    not_observed: list[str] = []
    for record in records:
        if record.get("evidence_type") not in OBSERVED_EVIDENCE_TYPES:
            target = record.get("target") or {}
            not_observed.append(str(target.get("endpoint") or "unknown"))
            continue
        decomposition = record.get("decomposition") or {}
        certificate = record.get("certificate") or {}
        if str(record.get("protocol") or "").upper() == "IPSEC":
            ike = record.get("ike") or {}
            esp = record.get("esp") or {}
            assets.extend(
                item
                for item in (
                    _asset(record, algorithm=ike.get("dh_group"), role=ROLE_IKE_KEX),
                    _asset(record, algorithm=ike.get("encryption"), role=ROLE_IKE_ENC),
                    _asset(record, algorithm=ike.get("integrity"), role=ROLE_IKE_INTEG),
                    # only emit ESP assets when the responder actually proposed them
                    _asset(record, algorithm=esp.get("encryption"), role=ROLE_ESP_ENC)
                    if esp.get("status") == "DECLARED_IN_SA_INIT"
                    else None,
                    _asset(record, algorithm=esp.get("integrity"), role=ROLE_ESP_INTEG)
                    if esp.get("status") == "DECLARED_IN_SA_INIT"
                    else None,
                )
                if item
            )
            continue
        candidates = [
            _asset(
                record,
                algorithm=decomposition.get("encryption"),
                role=ROLE_TLS_BULK,
                key_size=decomposition.get("key_size_bits"),
                mode=decomposition.get("mode"),
            ),
            _asset(record, algorithm=decomposition.get("key_exchange"), role=ROLE_TLS_KEX),
            _asset(record, algorithm=decomposition.get("authentication"), role=ROLE_TLS_AUTH),
            _asset(record, algorithm=decomposition.get("mac_or_prf"), role=ROLE_TLS_MAC),
            _asset(
                record,
                algorithm=certificate.get("public_key_algorithm"),
                role=ROLE_TLS_AUTH,
                key_size=certificate.get("public_key_bits"),
                curve=certificate.get("curve"),
            ),
            _asset(record, algorithm=certificate.get("signature_algorithm"), role=ROLE_CERT_SIGNATURE),
        ]
        assets.extend([item for item in candidates if item])

    algorithms: dict[str, int] = {}
    roles: dict[str, int] = {}
    for asset in assets:
        algorithms[asset["algorithm"]] = algorithms.get(asset["algorithm"], 0) + 1
        roles[asset["role"]] = roles.get(asset["role"], 0) + 1
    return {
        "model": "cryptoscan.network-cbom/1",
        "layer": "NETWORK_TRANSPORT",
        "asset_count": len(assets),
        "assets": assets,
        "algorithms": algorithms,
        "roles": roles,
        "not_observed": sorted(not_observed),
        "boundary": (
            "network transport crypto only — application, storage, HSM/KMS and "
            "message-layer crypto are separate layers and are not inferred from transport"
        ),
    }


# --------------------------------------------------------------------------- #
# §25 — network crypto path (hop graph)
# --------------------------------------------------------------------------- #


def build_crypto_path(
    records: Iterable[dict[str, Any]],
    hops: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Annotate a declared hop chain with observed crypto (§15–§17, §25).

    Hops are supplied by the operator (or imported from the reviewed network
    inventory). CryptoScan never invents a hop: a hop with no matching
    observation is returned with ``evidence_type: UNKNOWN`` and is excluded
    from the "observed chain" count.
    """
    by_endpoint: dict[str, dict[str, Any]] = {}
    for record in records:
        endpoint = str((record.get("target") or {}).get("endpoint") or "")
        if endpoint and endpoint not in by_endpoint:
            by_endpoint[endpoint] = record

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for hop in hops:
        source = str(hop.get("from") or "").strip()
        target = str(hop.get("to") or "").strip()
        if not source or not target:
            continue
        for name in (source, target):
            if name not in nodes:
                record = by_endpoint.get(name)
                nodes[name] = {
                    "id": name,
                    "label": (hop.get("label") if name == source else None) or name,
                    "observed": bool(record),
                    "evidence_type": (record or {}).get("evidence_type") or "UNKNOWN",
                }
        record = by_endpoint.get(source)
        edges.append(
            {
                "from": source,
                "to": target,
                "layer": "NETWORK_TRANSPORT",
                "evidence_type": (record or {}).get("evidence_type") or "UNKNOWN",
                # passive hop crypto is still observed crypto, but weaker
                # evidence than a handshake we performed — never conflated.
                "evidence_mode": "PASSIVE"
                if (record or {}).get("evidence_type") == "NETWORK_PASSIVE_OBSERVED"
                else ("ACTIVE" if record else None),
                "evidence_id": (record or {}).get("evidence_id"),
                "tls_version": (record or {}).get("tls_version"),
                "cipher_suite": (record or {}).get("cipher_suite"),
                "decomposition": (record or {}).get("decomposition") or {},
                "mutual_tls": (record or {}).get("mutual_tls"),
                "observed_at": (record or {}).get("observed_at"),
                "note": None
                if record
                else "no observation for this hop — transport crypto is UNKNOWN, not absent",
                "confidence": (record or {}).get("confidence"),
            }
        )

    observed_edges = sum(1 for edge in edges if edge["evidence_type"] in OBSERVED_EVIDENCE_TYPES)
    return {
        "model": "cryptoscan.network-crypto-path/1",
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "observed_edges": observed_edges,
        "unknown_edges": len(edges) - observed_edges,
        "complete": bool(edges) and observed_edges == len(edges),
        "boundary": "hops are declared; only the annotated crypto is observed",
    }


# --------------------------------------------------------------------------- #
# §22 — passive observation (metadata only, never payload)
# --------------------------------------------------------------------------- #

#: the only fields a passive sensor may submit. Everything else is refused so a
#: sensor cannot turn CryptoScan into a packet archive.
PASSIVE_ALLOWED_FIELDS = frozenset(
    {
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "server_name",
        "tls_version",
        "cipher_suite",
        "certificate_fingerprint_sha256",
        "certificate_subject",
        "certificate_issuer",
        "certificate_public_key_algorithm",
        "certificate_curve",
        "certificate_signature_algorithm",
        "sni_present",
        "mtls",
        "ja3",
        "ja4",
        "alpn",
        "bytes",
        "sensor_id",
        "capture_point",
        "direction",
    }
)

#: substrings that must never appear in a passive observation field name
FORBIDDEN_FIELD_TOKENS = (
    "payload",
    "plaintext",
    "password",
    "secret",
    "private_key",
    "privkey",
    "session_key",
    "premaster",
    "master_secret",
    "certificate_body",
    "http_body",
    "body",
    "cookie",
    "authorization",
    "token",
)


class PassiveObservationRejected(ValueError):
    """A passive observation carried content the platform must not store."""


def _split_bundle(name: str | None, version: str | None) -> dict[str, Any]:
    """Reuse the TLS decomposition for a passively supplied cipher name."""
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


def validate_passive_observation(observation: dict[str, Any]) -> None:
    """Reject unknown or content-bearing fields before anything is stored."""
    if not isinstance(observation, dict):
        raise PassiveObservationRejected("observation must be an object")
    for field in observation:
        lowered = str(field).lower()
        if any(token in lowered for token in FORBIDDEN_FIELD_TOKENS):
            raise PassiveObservationRejected(
                f"field '{field}' looks like captured content — passive mode stores handshake metadata only"
            )
        if lowered not in PASSIVE_ALLOWED_FIELDS:
            raise PassiveObservationRejected(
                f"field '{field}' is not an allowed passive metadata field"
            )


def build_passive_evidence(
    observation: dict[str, Any],
    *,
    scanner_version: str = "network-passive-sensor-v1.0",
    scope_revision: str | None = None,
    scope_name: str | None = None,
    received_at: str | None = None,
) -> dict[str, Any]:
    """One §22/§24 evidence record from a metadata-only sensor observation.

    Anything the sensor did not report stays ``None`` — a passive sensor proves
    only the traffic it actually saw (§22: *no observed traffic ≠ no crypto*).
    """
    validate_passive_observation(observation)
    dst = str(observation.get("dst_ip") or "")
    port = observation.get("dst_port")
    endpoint = f"{dst}:{port}" if dst and port is not None else None
    version = observation.get("tls_version")
    suite = observation.get("cipher_suite")
    observed_at = str(observation.get("timestamp") or received_at or _now())

    record = {
        "schema": SCHEMA,
        "evidence_type": "NETWORK_PASSIVE_OBSERVED",
        "evidence_id": f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": endpoint,
            "host": observation.get("server_name") or dst or None,
            "port": int(port) if isinstance(port, int) or (isinstance(port, str) and str(port).isdigit()) else None,
            "ip_address": dst or None,
        },
        "protocol": str(observation.get("protocol") or "TLS").upper(),
        "observation_status": "PASSIVE_SEEN",
        "tls_version": version,
        "cipher_suite": suite,
        "decomposition": _split_bundle(suite, version),
        "certificate": {
            "fingerprint_sha256": observation.get("certificate_fingerprint_sha256"),
            "subject": observation.get("certificate_subject"),
            "issuer": observation.get("certificate_issuer"),
            "not_before": None,
            "not_after": None,
            "public_key_algorithm": observation.get("certificate_public_key_algorithm"),
            "public_key_bits": None,
            "curve": observation.get("certificate_curve"),
            "signature_algorithm": observation.get("certificate_signature_algorithm"),
            "san_count": None,
        },
        "certificate_chain": {"length": None, "structural_status": None, "trust_status": None, "completeness": None},
        "mutual_tls": observation.get("mtls") if observation.get("mtls") is not None else "UNKNOWN",
        "mtls_evidence": "PASSIVE_CLIENT_CERT_SEEN" if observation.get("mtls") else "NOT_OBSERVED",
        "policy_issues": [],
        "algorithm_verdict": {},
        "observed_at": observed_at,
        "scanner_version": scanner_version,
        "scope_revision": scope_revision,
        "scope_name": scope_name,
        "confidence": "MEDIUM",
        "limitations": [
            "passive observation proves only the traffic this sensor saw",
            "unobserved endpoints are NOT_OBSERVED, not free of crypto",
            "certificate chain validation and mTLS requirement are not determinable passively",
        ],
        "passive": {
            "sensor_id": observation.get("sensor_id"),
            "capture_point": observation.get("capture_point"),
            "direction": observation.get("direction"),
            "src_ip": observation.get("src_ip"),
            "src_port": observation.get("src_port"),
            "ja3": observation.get("ja3"),
            "ja4": observation.get("ja4"),
            "alpn": observation.get("alpn"),
            "sni_present": observation.get("sni_present"),
            "bytes": observation.get("bytes"),
            "received_at": received_at or _now(),
        },
    }
    return record
