"""Message-layer crypto evidence for brokers and queues (spec 67 §19, §27).

A bank's Kafka/IBM MQ/AMQP/NATS estate has two crypto questions that look
alike and are not:

    transport   — how does a client reach the broker? (TLS version, cipher,
                  certificate, client certificate / mTLS, SASL mechanism)
    payload     — are the *messages* encrypted before they are handed to the
                  broker, so the broker itself cannot read them?

Network telemetry can answer the first and cannot answer the second. This
module therefore keeps the two in different blocks and refuses to promote a
declaration into an observation:

* transport facts are ``NETWORK_CONFIGURED`` when they come from broker
  configuration (``listener_security``) and ``NETWORK_ACTIVE_OBSERVED`` only
  when a caller states the TLS handshake was actually performed;
* payload facts are ``DECLARED`` (with the declaring source) or ``UNKNOWN``,
  never ``OBSERVED``;
* SASL is authentication to the broker, not message encryption (§27), so a
  SASL mechanism is emitted as an authentication asset and never as a bulk
  cipher.

No payload, credential, JAAS configuration or private key is ever accepted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from network_scanner.inventory.network_evidence import (
    FORBIDDEN_FIELD_TOKENS,
    OBSERVED_EVIDENCE_TYPES,
)

SCHEMA = "cryptoscan.message-layer-evidence/1"
CBOM_MODEL = "cryptoscan.message-layer-cbom/1"

#: transport vs payload — two layers that must never be merged (§19, §27)
LAYERS = ("MESSAGE_TRANSPORT", "MESSAGE_PAYLOAD")

MESSAGE_PROTOCOLS = ("KAFKA", "AMQP", "IBM_MQ", "NATS", "PULSAR", "RABBITMQ", "MQ")

#: broker listener security settings as they appear in broker configuration
LISTENER_SECURITY = ("PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL", "UNKNOWN")
ENCRYPTED_LISTENERS = frozenset({"SSL", "SASL_SSL"})
SASL_LISTENERS = frozenset({"SASL_PLAINTEXT", "SASL_SSL"})

SASL_MECHANISMS = (
    "PLAIN",
    "SCRAM-SHA-256",
    "SCRAM-SHA-512",
    "GSSAPI",
    "OAUTHBEARER",
    "AWS_MSK_IAM",
    "EXTERNAL",
    "NONE",
    "UNKNOWN",
)

#: SASL mechanisms that carry a reusable password to the broker in the clear
#: unless the listener is encrypted
PLAINTEXT_CREDENTIAL_MECHANISMS = frozenset({"PLAIN"})

CLIENT_AUTHENTICATION = ("NONE", "mTLS", "SASL", "SASL_MTLS", "UNKNOWN")

PAYLOAD_ENCRYPTION_STATES = ("DECLARED", "UNKNOWN", "NOT_DECLARED")

#: where a payload-encryption claim may come from; nothing else is accepted
PAYLOAD_SOURCES = (
    "BANK_DECLARATION",
    "VENDOR_DOCUMENTATION",
    "APPLICATION_DESIGN",
    "UNKNOWN",
)

#: fields a broker observation may carry. Everything else is refused so the
#: endpoint cannot become a place to park credentials or message content.
ALLOWED_FIELDS = frozenset(
    {
        "endpoint",
        "broker",
        "protocol",
        "service",
        "owner",
        "environment",
        "listener_security",
        "listener_name",
        "sasl_mechanism",
        "client_authentication",
        # 'authorization' alone is refused by the credential-token guard, so the
        # ACL/RBAC model arrives as an explicitly named field
        "authorization_model",
        "tls_version",
        "cipher_suite",
        "certificate_fingerprint_sha256",
        "certificate_public_key_algorithm",
        "certificate_signature_algorithm",
        "certificate_expires_at",
        "observed",
        "observed_at",
        "payload_encryption",
        "payload_encryption_source",
        "source",
        "evidence_source",
        "notes",
    }
)

#: extra content-bearing names we refuse even though the base list is broad
EXTRA_FORBIDDEN = ("sasl_password", "sasl_jaas_config", "jaas", "credential", "keytab")


class MessageLayerRejected(ValueError):
    """A broker observation carried fields the platform must not store."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _split_endpoint(entry: dict[str, Any]) -> tuple[str | None, str | None, int | None]:
    raw = str(entry.get("endpoint") or entry.get("broker") or "").strip()
    if not raw:
        return None, None, None
    host, _, port_text = raw.rpartition(":")
    if not host:  # no port supplied
        return raw, raw, None
    port = int(port_text) if port_text.isdigit() else None
    return raw, host.strip("[]") or None, port


def validate_message_observation(entry: dict[str, Any]) -> None:
    """Fail closed on unknown or credential-bearing fields."""
    if not isinstance(entry, dict):
        raise MessageLayerRejected("observation must be an object")
    for field in entry:
        lowered = str(field).lower()
        # the allow-list is authoritative; a name that is not on it is then
        # screened for content-bearing words before being refused outright
        if lowered in ALLOWED_FIELDS:
            continue
        if any(token in lowered for token in FORBIDDEN_FIELD_TOKENS + EXTRA_FORBIDDEN):
            raise MessageLayerRejected(
                f"field '{field}' looks like credential or message content — "
                "message-layer observation stores handshake/config metadata only"
            )
        raise MessageLayerRejected(f"field '{field}' is not an allowed message-layer field")


def _issues(entry: dict[str, Any], *, encrypted: bool, observed: bool) -> list[str]:
    issues: list[str] = []
    listener = str(entry.get("listener_security") or "UNKNOWN").upper()
    mechanism = str(entry.get("sasl_mechanism") or "UNKNOWN").upper()
    version = str(entry.get("tls_version") or "")

    if listener == "PLAINTEXT" or (observed and not encrypted and not version):
        issues.append("MESSAGE_TRANSPORT_UNENCRYPTED")
    if listener == "SASL_PLAINTEXT":
        issues.append("MESSAGE_SASL_OVER_PLAINTEXT")
    if mechanism in PLAINTEXT_CREDENTIAL_MECHANISMS and not encrypted:
        issues.append("MESSAGE_SASL_PLAIN_WITHOUT_TLS")
    if version in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}:
        issues.append(f"MESSAGE_LEGACY_TLS:{version}")
    if encrypted and str(entry.get("client_authentication") or "UNKNOWN").upper() == "NONE":
        issues.append("MESSAGE_NO_CLIENT_AUTHENTICATION")
    if str(entry.get("payload_encryption") or "").strip() and not observed:
        issues.append("MESSAGE_PAYLOAD_ENCRYPTION_UNVERIFIED")
    return sorted(set(issues))


def build_message_evidence(
    entry: dict[str, Any],
    *,
    scanner_version: str = "network-message-layer-v1.0",
    scope_revision: str | None = None,
    scope_name: str | None = None,
    received_at: str | None = None,
) -> dict[str, Any]:
    """One §19 evidence record for a broker listener.

    ``evidence_type`` is ``NETWORK_ACTIVE_OBSERVED`` only when the caller states
    the TLS handshake was performed and supplies negotiated parameters;
    otherwise the listener configuration is ``NETWORK_CONFIGURED`` — a
    declaration, and it says so.
    """
    validate_message_observation(entry)
    endpoint, host, port = _split_endpoint(entry)
    if not endpoint:
        raise MessageLayerRejected("observation must name an endpoint or broker")

    protocol = str(entry.get("protocol") or "KAFKA").upper()
    if protocol not in MESSAGE_PROTOCOLS:
        raise MessageLayerRejected(f"unsupported message protocol '{protocol}'")

    listener = str(entry.get("listener_security") or "UNKNOWN").upper()
    if listener not in LISTENER_SECURITY:
        raise MessageLayerRejected(f"unknown listener_security '{listener}'")
    encrypted = listener in ENCRYPTED_LISTENERS
    observed = bool(entry.get("observed"))
    tls_version = entry.get("tls_version")
    cipher_suite = entry.get("cipher_suite")
    if observed and not (tls_version or cipher_suite):
        raise MessageLayerRejected(
            "observed=true requires negotiated tls_version or cipher_suite — "
            "otherwise the listener is a configuration claim, not an observation"
        )

    mechanism = str(entry.get("sasl_mechanism") or "UNKNOWN").upper()
    if mechanism not in SASL_MECHANISMS:
        raise MessageLayerRejected(f"unknown sasl_mechanism '{mechanism}'")
    if mechanism not in {"UNKNOWN", "NONE"} and listener not in SASL_LISTENERS:
        raise MessageLayerRejected(
            f"SASL mechanism '{mechanism}' declared on a non-SASL listener '{listener}' — "
            "the listener configuration and the mechanism contradict each other"
        )

    if observed:
        evidence_type = "NETWORK_ACTIVE_OBSERVED"
    elif listener == "UNKNOWN" and mechanism == "UNKNOWN" and not entry.get("authorization_model"):
        evidence_type = "UNKNOWN"
    else:
        evidence_type = "NETWORK_CONFIGURED"

    payload_value = entry.get("payload_encryption")
    payload_source = str(entry.get("payload_encryption_source") or "UNKNOWN").upper()
    if payload_source not in PAYLOAD_SOURCES:
        raise MessageLayerRejected(f"unknown payload_encryption_source '{payload_source}'")
    if payload_value:
        payload = {
            "status": "DECLARED",
            "algorithm": str(payload_value),
            "source": payload_source,
            "observed": False,
            "note": "declared by the bank/vendor — network telemetry cannot see message encryption",
        }
    else:
        payload = {
            "status": "UNKNOWN",
            "algorithm": None,
            "source": payload_source,
            "observed": False,
            "note": "no declaration and no observation — message encryption is UNKNOWN, not absent",
        }

    issues = _issues(entry, encrypted=encrypted, observed=observed)
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "layer": "MESSAGE_TRANSPORT",
        "evidence_type": evidence_type,
        "evidence_id": f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": endpoint,
            "host": host,
            "port": port,
            "broker": entry.get("broker"),
            "service": entry.get("service"),
            "owner": entry.get("owner"),
            "environment": entry.get("environment"),
        },
        "protocol": protocol,
        "observation_status": "TLS_HANDSHAKE"
        if observed
        else ("CONFIG_READ" if evidence_type == "NETWORK_CONFIGURED" else "UNKNOWN"),
        "listener": {
            "security": listener,
            "name": entry.get("listener_name"),
            "transport_encrypted": bool(encrypted) if listener != "UNKNOWN" else None,
        },
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "certificate": {
            "fingerprint_sha256": entry.get("certificate_fingerprint_sha256"),
            "public_key_algorithm": entry.get("certificate_public_key_algorithm"),
            "signature_algorithm": entry.get("certificate_signature_algorithm"),
            "not_after": entry.get("certificate_expires_at"),
        },
        # SASL authenticates the client to the broker. It is authentication to a
        # service, not encryption of the message.
        "sasl": {
            "mechanism": mechanism,
            "authenticates": "CLIENT_TO_BROKER",
            "encrypts_messages": False,
            "mechanism_is_crypto": mechanism in {"SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI", "EXTERNAL"},
        },
        "client_authentication": str(entry.get("client_authentication") or "UNKNOWN").upper(),
        "authorization": entry.get("authorization_model"),
        "payload_encryption": payload,
        "policy_issues": issues,
        "evidence_source": str(entry.get("evidence_source") or entry.get("source") or "BROKER_CONFIG").upper(),
        "observed_at": str(entry.get("observed_at") or received_at or _now()),
        "scanner_version": scanner_version,
        "scope_revision": scope_revision,
        "scope_name": scope_name,
        "confidence": "HIGH" if observed else "MEDIUM",
        "limitations": [],
    }

    if not observed:
        record["limitations"].append(
            "listener configuration is declared, not observed — no broker handshake was performed"
        )
    record["limitations"].append(
        "message/payload encryption is not observable from network telemetry; it stays DECLARED or UNKNOWN"
    )
    record["limitations"].append(
        "broker authorization (ACL/RBAC) is an access-control control, not a cryptographic one"
    )
    if entry.get("notes"):
        record["context"] = {"notes": str(entry["notes"])[:500]}
    return record


def summarize(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Counts for the dashboard; nothing unobserved is counted as observed."""
    records = list(records)
    protocols: dict[str, int] = {}
    listeners: dict[str, int] = {}
    mechanisms: dict[str, int] = {}
    evidence_types: dict[str, int] = {}
    issues: dict[str, int] = {}
    payload_states: dict[str, int] = {}
    encrypted = 0
    observed = 0
    mtls = 0
    for record in records:
        protocols[record.get("protocol") or "UNKNOWN"] = protocols.get(record.get("protocol") or "UNKNOWN", 0) + 1
        listener = str((record.get("listener") or {}).get("security") or "UNKNOWN")
        listeners[listener] = listeners.get(listener, 0) + 1
        mechanism = str((record.get("sasl") or {}).get("mechanism") or "UNKNOWN")
        mechanisms[mechanism] = mechanisms.get(mechanism, 0) + 1
        evidence_type = record.get("evidence_type") or "UNKNOWN"
        evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
        payload_state = str((record.get("payload_encryption") or {}).get("status") or "UNKNOWN")
        payload_states[payload_state] = payload_states.get(payload_state, 0) + 1
        if evidence_type in OBSERVED_EVIDENCE_TYPES:
            observed += 1
        if (record.get("listener") or {}).get("transport_encrypted"):
            encrypted += 1
        if record.get("client_authentication") in {"mTLS", "SASL_MTLS"}:
            mtls += 1
        for issue in record.get("policy_issues") or []:
            issues[issue] = issues.get(issue, 0) + 1
    return {
        "schema": "cryptoscan.message-layer-summary/1",
        "records": len(records),
        "observed": observed,
        "configured": evidence_types.get("NETWORK_CONFIGURED", 0),
        "unknown": evidence_types.get("UNKNOWN", 0),
        "transport_encrypted": encrypted,
        "transport_plaintext": sum(
            1
            for record in records
            if (record.get("listener") or {}).get("security") in {"PLAINTEXT", "SASL_PLAINTEXT"}
        ),
        "client_authenticated": mtls,
        "protocols": protocols,
        "listeners": listeners,
        "sasl_mechanisms": mechanisms,
        "evidence_types": evidence_types,
        "payload_encryption_states": payload_states,
        "policy_issues": issues,
        "boundary": "transport encryption and SASL are not message encryption",
        "unknown_note": "a listener with no declaration is UNKNOWN, not unencrypted",
    }


# --------------------------------------------------------------------------- #
# §19/§28 — message-layer crypto assets
# --------------------------------------------------------------------------- #

ROLE_MESSAGE_TLS_BULK = "message-transport-encryption"
ROLE_MESSAGE_SASL_AUTH = "message-client-authentication"
ROLE_MESSAGE_CERT = "message-certificate-signature"
ROLE_MESSAGE_PAYLOAD = "message-payload-encryption"


def _asset(
    record: dict[str, Any],
    *,
    algorithm: str | None,
    role: str,
    layer: str,
    observation_mode: str,
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
        "layer": layer,
        "protocol": record.get("protocol"),
        "observation_mode": observation_mode,
        "context": {
            "host": target.get("host"),
            "port": target.get("port"),
            "endpoint": target.get("endpoint"),
            "broker": target.get("broker"),
            "service": target.get("service"),
            "listener_security": (record.get("listener") or {}).get("security"),
            "tls_version": record.get("tls_version"),
            "cipher_suite": record.get("cipher_suite"),
            "sasl_mechanism": (record.get("sasl") or {}).get("mechanism"),
            "note": note,
        },
        "evidence": {
            "evidence_id": record.get("evidence_id"),
            "evidence_type": record.get("evidence_type"),
            "observed_at": record.get("observed_at"),
            "confidence": record.get("confidence"),
            "source": record.get("evidence_source"),
        },
        "policy_issues": list(record.get("policy_issues") or []),
        "quantum_impact": None,
    }


def to_cbom_assets(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Project message-layer evidence into CBOM assets (§19, §28).

    Transport assets are emitted for configured *and* observed listeners (each
    labelled with its evidence type). Payload assets are emitted only for a
    declaration and are labelled ``DECLARED`` — never ``ACTIVE``/``PASSIVE``,
    because nothing observed them.
    """
    assets: list[dict[str, Any]] = []
    unknown: list[str] = []
    for record in records:
        if record.get("evidence_type") not in OBSERVED_EVIDENCE_TYPES | {"NETWORK_CONFIGURED"}:
            unknown.append(str((record.get("target") or {}).get("endpoint") or "unknown"))
            continue
        mode = "ACTIVE" if record.get("evidence_type") == "NETWORK_ACTIVE_OBSERVED" else "CONFIGURED"
        certificate = record.get("certificate") or {}
        sasl = record.get("sasl") or {}
        payload = record.get("payload_encryption") or {}
        candidates = [
            _asset(
                record,
                algorithm=record.get("cipher_suite"),
                role=ROLE_MESSAGE_TLS_BULK,
                layer="MESSAGE_TRANSPORT",
                observation_mode=mode,
            ),
            _asset(
                record,
                algorithm=certificate.get("public_key_algorithm"),
                role=ROLE_MESSAGE_CERT,
                layer="MESSAGE_TRANSPORT",
                observation_mode=mode,
            ),
            # SASL is an authentication mechanism: it is emitted as authentication,
            # explicitly never as a bulk cipher (§27).
            _asset(
                record,
                algorithm=sasl.get("mechanism") if sasl.get("mechanism_is_crypto") else None,
                role=ROLE_MESSAGE_SASL_AUTH,
                layer="MESSAGE_TRANSPORT",
                observation_mode=mode,
                note="SASL authenticates the client to the broker; it does not encrypt messages",
            ),
            _asset(
                record,
                algorithm=payload.get("algorithm") if payload.get("status") == "DECLARED" else None,
                role=ROLE_MESSAGE_PAYLOAD,
                layer="MESSAGE_PAYLOAD",
                observation_mode="DECLARED",
                note=f"declared source: {payload.get('source')}; never observed by network telemetry",
            ),
        ]
        assets.extend(item for item in candidates if item)

    algorithms: dict[str, int] = {}
    roles: dict[str, int] = {}
    layers: dict[str, int] = {}
    for asset in assets:
        algorithms[asset["algorithm"]] = algorithms.get(asset["algorithm"], 0) + 1
        roles[asset["role"]] = roles.get(asset["role"], 0) + 1
        layers[asset["layer"]] = layers.get(asset["layer"], 0) + 1
    return {
        "model": CBOM_MODEL,
        "asset_count": len(assets),
        "assets": assets,
        "algorithms": algorithms,
        "roles": roles,
        "layers": layers,
        "not_observed": sorted(unknown),
        "boundary": (
            "MESSAGE_TRANSPORT and MESSAGE_PAYLOAD are separate layers: a TLS listener on the "
            "broker says nothing about whether message payloads are encrypted, and a declared "
            "payload encryption is not an observation"
        ),
    }
