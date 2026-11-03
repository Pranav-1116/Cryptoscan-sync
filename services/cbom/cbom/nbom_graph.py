"""NBOM as a network projection: endpoints, dependencies and the TLS that joins them.

The estate already has a network layer — endpoints, WAFs, load balancers, API gateways,
service meshes, certificates — and :mod:`cbom.techbom` already refuses an edge without a
basis. What neither answers is the question this module exists for:

    what is behind ``10.10.10.20:443``, how does traffic get from a client to a database,
    where is TLS terminated and re-encrypted, and what cryptographic material does each
    hop actually depend on?

The review's twenty-two points reduce to four rules, and each is a rule here rather than
a paragraph:

* **an address is not an identity.** ``10.10.10.20:443`` is a *location*. The same address
  hosts several virtual hosts, several certificates and several applications, so the
  endpoint is a node and the thing behind it is reached by a claim with a named basis —
  DNS, SNI, a Kubernetes ingress rule, an API gateway route, a load balancer backend, a
  service registry, or a runtime observation. Name similarity is not among them;
* **supported is not negotiated, and negotiated is not used.** Three relations, three
  evidence classes: ``SUPPORTS`` (what a listener will accept), ``NEGOTIATES`` (what a
  handshake actually chose — it has an evidence floor, so a config file cannot claim it),
  ``USES_CRYPTO`` (what the process did). A cipher suite is decomposed into its key
  exchange, authentication, bulk cipher and hash, because a suite is four crypto
  dependencies wearing one name;
* **termination is a topology, not a flag.** ``TERMINATES_TLS``, ``RE_ENCRYPTS`` and
  ``PASSTHROUGH`` are three different cryptographic graphs between the same two boxes,
  and a passthrough that presents a certificate is refused rather than drawn;
* **every edge carries its own record.** Source, target, relationship, protocol, port,
  evidence id, basis, confidence, first and last seen. An edge without them is a drawing.

Like the TechBOM, this is a projection: :func:`build` takes a canonical estate and
:func:`from_document` refuses an NBOM as input, so the projection can never become the
source of the next one.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from . import techbom as tb

SCHEMA = "cryptoscan.nbom/1"

#: the kinds a network projection reports. The graph itself is shared — this is the
#: subset a network reviewer asked to see, not a separate store.
NBOM_KINDS: tuple[str, ...] = (
    "NETWORK_ENDPOINT", "WAF", "LOAD_BALANCER", "API_GATEWAY", "SERVICE_MESH",
    "CIPHER_SUITE", "SSH_SERVICE", "VPN_GATEWAY", "IPSEC_TUNNEL", "DATABASE",
    "NETWORK_SEGMENT", "FIREWALL", "SECURITY_APPLIANCE", "IDS", "IPS", "RATE_LIMIT",
    "CERTIFICATE", "CERTIFICATE_AUTHORITY", "PUBLIC_KEY", "ALGORITHM",
    "SERVICE", "APPLICATION", "BUSINESS_SYSTEM", "PROCESS", "CONTAINER", "POD",
    "HOST", "VM", "PHYSICAL_SERVER", "CLOUD_INSTANCE", "KUBERNETES_NODE", "OS",
    "HSM", "KMS", "KEY_REFERENCE", "CRYPTO_ASSET", "CRYPTO_LIBRARY", "CRYPTO_OPERATION",
    "VENDOR", "VENDOR_PRODUCT", "FIRMWARE", "NIC", "EVIDENCE",
)

#: what every edge must be able to answer (review nbom 15–16). Checked, not documented.
EDGE_FIELDS: tuple[str, ...] = ("source", "target", "relationship", "basis", "confidence",
                                "evidence_id", "observed_at", "first_seen", "last_seen")

#: the three ways TLS crosses an intermediary. They are not three flags on one box; they
#: are three graphs, and the model refuses to draw two of them at once (review nbom 3).
TLS_MODES: dict[str, str] = {
    "TERMINATE": "TERMINATES_TLS",
    "RE_ENCRYPT": "RE_ENCRYPTS",
    "PASSTHROUGH": "PASSTHROUGH",
}

#: relationship lifecycle (review nbom 17)
LIFECYCLE: tuple[str, ...] = ("FIRST_SEEN", "ACTIVE", "CHANGED", "SUPERSEDED", "REMOVED",
                              "UNKNOWN")

#: bases that may tie an endpoint to what is behind it. A name match is deliberately
#: absent: `payments.bank.example` and an application called `payments` are two strings.
ROUTING_BASES: tuple[str, ...] = ("dns-resolution", "sni-header", "deployment-metadata",
                                  "kubernetes-ingress", "api-gateway-config",
                                  "load-balancer-config", "service-registry", "mesh-config",
                                  "database-config", "vpn-config", "runtime-observation",
                                  "agent-inventory", "config-parse")

#: bases that can say what a *session* negotiated. A configuration file can say what a
#: listener will accept; only a handshake or a capture says what it chose (review nbom 6).
HANDSHAKE_BASES: tuple[str, ...] = ("tls-handshake", "packet-capture", "passive-capture")

#: dependency relations, in the order the review's chain reads (nbom 22)
SPINE: tuple[str, ...] = (
    "CONTAINS", "PROVIDES", "RUNS", "RUNS_PROCESS", "RUNS_APPLICATION", "EXPOSES",
    "LISTENS_ON", "ROUTES_TO",
    "FORWARDS_TO", "FRONTED_BY", "TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH", "PROTECTS",
    "INVOKES",
    "AUTHENTICATES", "PROXY_FOR", "CONNECTS_TO", "TUNNELS_TO", "STORES_IN", "USES_HSM",
    "USES_KMS", "USES_KEY", "USES_CERTIFICATE", "PRESENTS", "CONTAINS_KEY",
    "USES_ALGORITHM", "SIGNED_WITH", "ISSUED_BY", "SIGNED_BY", "NEGOTIATES",
    "USES_CRYPTO", "SUPPORTS", "HAS_MODEL", "SUPPLIED_BY", "RUNS_FIRMWARE", "RUNS_ON",
    "SCHEDULED_ON", "LOADS", "PROVIDES_ALGORITHM",
)

NOT_PROVEN = [
    "that an endpoint's backend is the application the name suggests: the edge cites a "
    "DNS record, an SNI value, an ingress rule, a gateway route or a runtime observation, "
    "and each of those is printed beside it",
    "that a supported algorithm is in use: supported, negotiated and used are three "
    "relations with three evidence classes, and only NEGOTIATES and USES_CRYPTO count as "
    "what a session or a process did",
    "that a network observation is the application's cryptography: a TLS handshake on port "
    "443 says nothing about what the process does internally, and RUNTIME_OBSERVED is kept "
    "apart from NETWORK_OBSERVED for exactly that reason",
    "that an unavailable endpoint does not exist: coverage is a denominator, and the "
    "endpoints nobody could reach are reported as unavailable, never dropped",
    "that traffic follows one path: a graph holds every edge that was evidenced, and a "
    "request takes one of them at a time",
]


# --------------------------------------------------------------------------- #
# Rows and parts
# --------------------------------------------------------------------------- #

def part(*assets: Any, claims: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """A bundle of assets and claims, ready to be handed to :func:`estate`.

    A nested part is flattened *with its claims*: an asset that arrives with the edge that
    put it there and loses the edge has been counted and not recorded.
    """
    flat: list[dict[str, Any]] = []
    flat_claims: list[dict[str, Any]] = [dict(row) for row in claims]
    for item in assets:
        if item is None:
            continue
        if isinstance(item, Mapping) and "assets" in item:
            flat.extend(item["assets"])
            flat_claims.extend(dict(row) for row in item.get("claims") or [])
            continue
        flat.append(dict(item))  # type: ignore[arg-type]
    return {"assets": flat, "claims": flat_claims}


def merge(*parts: Any) -> dict[str, Any]:
    """Concatenate parts. Identical rows collapse; anything else is left for build().

    A part may carry a *section* beside its assets and claims — the at-rest block of a
    database, for instance. Those are merged one level deep and carried to the projection,
    because a builder that returns a fact and has it dropped on the way to the BOM has
    measured nothing.
    """
    assets: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    sections: dict[str, Any] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for item in parts:
        if isinstance(item, Mapping):
            for key, value in item.items():
                if key in ("assets", "claims"):
                    continue
                if isinstance(value, Mapping) and isinstance(sections.get(key), Mapping):
                    sections[key] = {**sections[key], **value}
                else:
                    sections[key] = value
        # a part is {assets, claims}; a bare row is one asset and is accepted too, so a
        # caller never loses an asset to the shape of the bundle it arrived in
        rows = ([item] if isinstance(item, Mapping)
                and "kind" in item and "name" in item
                else (item or {}).get("assets") or [])
        for raw in rows:
            row = tb.asset(
                raw.get("kind"), raw.get("name"),
                environment=raw.get("environment") or "PRODUCTION",
                version=raw.get("version"), owner=raw.get("owner"),
                location=raw.get("location"), status=raw.get("status"),
                first_seen=raw.get("first_seen"), last_seen=raw.get("last_seen"),
                source=raw.get("source"), evidence_ids=raw.get("evidence_ids"),
                **(raw.get("attributes") or {}),
            )
            fingerprint = (row["key"], str(sorted(row["attributes"].items())))
            if (row["key"], fingerprint[1], row["evidence_ids"][0],
                    row["environment"]) in seen:
                continue
            seen.add((row["key"], fingerprint[1], row["evidence_ids"][0],
                      row["environment"]))
            assets.append(row)
        claims.extend((item or {}).get("claims") or [])
    return {"assets": assets, "claims": claims, "sections": sections}


def estate(*parts: Any, estate_id: str = "estate", environment: str = "PRODUCTION",
           expected: Mapping[str, Any] | None = None,
           gaps: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    body = merge(*parts)
    return {
        "schema": tb.ESTATE_SCHEMA,
        "estate_id": estate_id,
        "environment": environment,
        "assets": body["assets"],
        "claims": body["claims"],
        "sections": body["sections"],
        "expected": dict(expected or {}),
        "gaps": list(gaps or []),
    }


# --------------------------------------------------------------------------- #
# 1–2. An address is a location; the endpoint and what is behind it are identity
# --------------------------------------------------------------------------- #

def endpoint(*, host: Any, port: Any, protocol: Any = "TCP", transport: Any = "TLS",
             name: Any = None, sni: Iterable[Any] = (), alpn: Iterable[Any] = (),
             tls: Mapping[str, Any] | None = None, service: Any = None,
             environment: Any = "PRODUCTION", owner: Any = None, location: Any = None,
             evidence_ids: Iterable[Any] | None = None,
             **attributes: Any) -> dict[str, Any]:
    """One ``host:port`` listener — many of which may share an address.

    The name is ``host:port`` because that is what was observed; the *identity* is the
    node, and two virtual hosts on one address are two endpoints with two names. A bare IP
    is refused: an IP with no port is not a service, it is an address.
    """
    host_text = str(host or "").strip()
    port_text = str(port or "").strip()
    if not host_text or not port_text:
        raise tb.ClaimRefused("ENDPOINT_WITHOUT_HOST_OR_PORT",
                              "an endpoint is host:port; an IP with no port is an address, "
                              "not a service")
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise tb.ClaimRefused("ENDPOINT_PORT_NOT_A_PORT",
                              f"{port_text} is not a port number")
    label = str(name or f"{host_text}:{port_text}")
    body = {
        "host": host_text,
        "port": int(port_text),
        "protocol": str(protocol or "TCP").upper(),
        "transport": str(transport or "TLS").upper(),
        "sni": [str(value) for value in sni],
        "alpn": [str(value).upper() for value in alpn],
        "tls": dict(tls or {}),
        **attributes,
    }
    row = tb.asset("NETWORK_ENDPOINT", label, environment=environment, owner=owner,
                   location=location, evidence_ids=evidence_ids, **body)
    if service is not None:
        row["_service"] = str(service)
    return row


def service_of(*, name: Any, application: Any = None, systems: Iterable[Any] = (),
               environment: Any = "PRODUCTION", port: Any = None, protocol: Any = "TCP",
               kind: Any = "SERVICE", owner: Any = None, version: Any = None,
               evidence_ids: Iterable[Any] | None = None,
               **attributes: Any) -> dict[str, Any]:
    """A service — or with ``kind="APPLICATION"`` an application, or a business system.

    The three levels the review insists on (`SERVICE`, `APPLICATION`, `BUSINESS_SYSTEM`)
    are separate nodes because they have separate lifecycles: a service is a listener with
    a port, an application is a program, a system is a thing the bank owns.
    """
    return tb.asset(kind, name, environment=environment, owner=owner, version=version,
                    evidence_ids=evidence_ids, port=port,
                    protocol=str(protocol).upper() if port else None, **attributes)


def routed(*, endpoint_row: Mapping[str, Any], service_row: Mapping[str, Any],
           basis: Any = "dns-resolution", evidence_ids: Iterable[Any] | None = None,
           observed_at: Any = None, rule: Any = None, note: Any = None,
           **facts: Any) -> dict[str, Any]:
    """``endpoint → ROUTES_TO → service``, with the record that says so.

    ``basis`` must be one of :data:`ROUTING_BASES`. A name comparison is refused by name,
    because two strings matching is how a network graph invents an application.
    """
    basis_text = str(basis or "").strip().lower()
    if basis_text not in ROUTING_BASES:
        raise tb.ClaimRefused(
            "ROUTING_BASIS_NOT_EVIDENCE",
            f"{basis_text or '(none)'} is not a routing basis: an endpoint is tied to what "
            f"is behind it by {', '.join(ROUTING_BASES)} — a matching name is not one")
    claim = tb.claim(endpoint_row["name"], "ROUTES_TO", service_row["name"],
                     basis=basis_text, evidence_ids=evidence_ids, observed_at=observed_at,
                     rule=rule, note=note, **facts)
    return part(endpoint_row, service_row, claims=[claim])


def serves(*, application_row: Mapping[str, Any], service_row: Mapping[str, Any],
           system_row: Mapping[str, Any] | None = None, basis: Any = "service-registry",
           evidence_ids: Iterable[Any] | None = None, **facts: Any) -> dict[str, Any]:
    """Application → service, and optionally system → application."""
    claims = [tb.claim(application_row["name"], "PROVIDES", service_row["name"],
                       basis=basis, evidence_ids=evidence_ids, **facts)]
    assets = [application_row, service_row]
    if system_row is not None:
        assets.append(system_row)
        claims.append(tb.claim(system_row["name"], "CONTAINS", application_row["name"],
                               basis="cmdb-import", evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 3. TLS at an intermediary: terminate, re-encrypt, passthrough
# --------------------------------------------------------------------------- #

def tls_hop(*, frontend: Mapping[str, Any], backend: Mapping[str, Any], mode: Any,
            basis: Any = "load-balancer-config", evidence_ids: Iterable[Any] | None = None,
            certificate: Mapping[str, Any] | None = None,
            observed_at: Any = None, protocol: Any = None,
            **facts: Any) -> dict[str, Any]:
    """The TLS boundary between two listeners, in one of three modes.

    ``TERMINATE`` — the frontend holds the certificate and the backend is plaintext.
    ``RE_ENCRYPT`` — both sides carry TLS, and the two cipher suites are recorded
    separately, because they are two dependencies rather than one.
    ``PASSTHROUGH`` — the handshake crosses the intermediary untouched, so it can present
    no certificate of its own; asking it to is refused rather than drawn.
    """
    mode_text = str(mode or "").strip().upper().replace("-", "_")
    if mode_text not in TLS_MODES:
        raise tb.ClaimRefused("UNKNOWN_TLS_MODE",
                              f"{mode or '(none)'} is not a TLS boundary; it is one of "
                              f"{', '.join(TLS_MODES)}")
    relation = TLS_MODES[mode_text]
    front_tls = dict(frontend["attributes"].get("tls") or {})
    back_tls = dict(backend["attributes"].get("tls") or {})
    if mode_text == "TERMINATE" and back_tls:
        raise tb.ClaimRefused(
            "TERMINATION_WITH_TLS_UPSTREAM",
            f"{frontend['name']} terminates TLS and {backend['name']} carries TLS too; that "
            "is a re-encrypting hop, and calling it termination hides a dependency")
    if mode_text == "RE_ENCRYPT" and not back_tls:
        raise tb.ClaimRefused(
            "RE_ENCRYPT_WITHOUT_UPSTREAM_TLS",
            f"{backend['name']} has no TLS parameters, so there is nothing to re-encrypt")
    if mode_text == "PASSTHROUGH" and (certificate is not None or front_tls.get("certificate")):
        raise tb.ClaimRefused(
            "PASSTHROUGH_WITH_CERTIFICATE",
            "a passthrough never presents a certificate: the handshake belongs to the "
            "backend, and a certificate here would be a termination")
    assets = [frontend, backend]
    claims = []
    if certificate is not None:
        assets.append(certificate)
        claims.append(tb.claim(frontend["name"], "PRESENTS", certificate["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               observed_at=observed_at))
    claims.append(tb.claim(frontend["name"], relation, backend["name"], basis=basis,
                           evidence_ids=evidence_ids, observed_at=observed_at,
                           mode=mode_text, protocol=protocol or "TLS",
                           **facts))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 4. Certificates are a chain, not a blob
# --------------------------------------------------------------------------- #

def algorithm(*, name: Any, family: Any, key_size: Any = None, curve: Any = None,
              mode: Any = None, hash_name: Any = None, quantum_sensitive: Any = None,
              environment: Any = "PRODUCTION",
              evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """An algorithm as a node: ``ECDSA P-256`` is a different dependency from ``RSA-2048``."""
    attributes = {"family": str(family).upper(), "key_size": key_size, "curve": curve,
                  "mode": str(mode).upper() if mode else None,
                  "hash": str(hash_name).upper() if hash_name else None,
                  "quantum_sensitive": bool(quantum_sensitive) if quantum_sensitive is not None
                  else any(token in str(name).upper() for token in tb.QUANTUM_SENSITIVE)}
    row = tb.asset("ALGORITHM", name, environment=environment,
                   evidence_ids=evidence_ids, **attributes)
    return row


def public_key(*, name: Any, key_algorithm_row: Mapping[str, Any],
               key_size: Any = None, curve: Any = None, environment: Any = "PRODUCTION",
               evidence_ids: Iterable[Any] | None = None,
               **attributes: Any) -> dict[str, Any]:
    return tb.asset("PUBLIC_KEY", name, environment=environment, evidence_ids=evidence_ids,
                    key_size=key_size, curve=curve,
                    algorithm=key_algorithm_row["name"], **attributes)


def certificate(*, name: Any, subject: Any, issuer: Any = None, serial: Any = None,
                not_before: Any = None, not_after: Any = None,
                signature_algorithm: Any = None, environment: Any = "PRODUCTION",
                evidence_ids: Iterable[Any] | None = None,
                **attributes: Any) -> dict[str, Any]:
    """A certificate row. No private key, no key material — by refusal, not by habit."""
    return tb.asset("CERTIFICATE", name, environment=environment,
                    evidence_ids=evidence_ids, subject=subject, issuer=issuer,
                    serial=serial, not_before=not_before, not_after=not_after,
                    signature_algorithm=signature_algorithm, **attributes)


def authority(*, name: Any, kind: Any = "INTERMEDIATE", environment: Any = "PRODUCTION",
              evidence_ids: Iterable[Any] | None = None,
              **attributes: Any) -> dict[str, Any]:
    return tb.asset("CERTIFICATE_AUTHORITY", name, environment=environment,
                    evidence_ids=evidence_ids, ca_kind=str(kind).upper(), **attributes)


def certificate_chain(*, certificate_row: Mapping[str, Any],
                      key_row: Mapping[str, Any], key_algorithm_row: Mapping[str, Any],
                      signature_algorithm_row: Mapping[str, Any],
                      issuer_row: Mapping[str, Any],
                      root_row: Mapping[str, Any] | None = None,
                      basis: Any = "packet-capture",
                      evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """``certificate → public key → algorithm → signature algorithm → issuer → root``.

    The chain is five edges, not one row, so "which certificates rest on RSA" and "which
    signature algorithm signs them" are two different questions with two answers.
    """
    assets: list[Mapping[str, Any]] = [certificate_row, key_row, key_algorithm_row,
                                       signature_algorithm_row, issuer_row]
    claims = [
        tb.claim(certificate_row["name"], "CONTAINS_KEY", key_row["name"], basis=basis,
                 evidence_ids=evidence_ids),
        tb.claim(key_row["name"], "USES_ALGORITHM", key_algorithm_row["name"], basis=basis,
                 evidence_ids=evidence_ids),
        tb.claim(certificate_row["name"], "SIGNED_WITH", signature_algorithm_row["name"],
                 basis=basis, evidence_ids=evidence_ids),
        tb.claim(certificate_row["name"], "ISSUED_BY", issuer_row["name"], basis=basis,
                 evidence_ids=evidence_ids),
    ]
    if root_row is not None:
        assets.append(root_row)
        claims.append(tb.claim(issuer_row["name"], "SIGNED_BY", root_row["name"],
                               basis=basis, evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 5–6. A cipher suite is four dependencies; supported is not negotiated
# --------------------------------------------------------------------------- #

def cipher_suite(*, name: Any, tls_version: Any, kex: Any = None, auth: Any = None,
                 bulk: Any = None, mac: Any = None, pqc: Any = None,
                 environment: Any = "PRODUCTION",
                 evidence_ids: Iterable[Any] | None = None,
                 **attributes: Any) -> dict[str, Any]:
    """A suite as a node, with its parts named — never one opaque crypto asset."""
    return tb.asset("CIPHER_SUITE", name, environment=environment,
                    evidence_ids=evidence_ids,
                    tls_version=str(tls_version), kex=kex, auth=auth, bulk=bulk, mac=mac,
                    pqc=pqc, **attributes)


def suite_parts(*, suite_row: Mapping[str, Any], parts: Mapping[str, Mapping[str, Any]],
                basis: Any = "tls-handshake",
                evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """``suite → USES_CRYPTO → {bulk, mac, kex, auth}``, so CBOM sees four assets."""
    assets: list[Mapping[str, Any]] = [suite_row]
    claims = []
    for role, asset in parts.items():
        assets.append(asset)
        claims.append(tb.claim(suite_row["name"], "USES_CRYPTO", asset["name"],
                               basis=basis, evidence_ids=evidence_ids, role=str(role)))
    return part(*assets, claims=claims)


def negotiated(*, endpoint_row: Mapping[str, Any], suite_row: Mapping[str, Any],
               basis: Any = "tls-handshake", evidence_ids: Iterable[Any] | None = None,
               observed_at: Any = None, port: Any = None) -> dict[str, Any]:
    """``endpoint → NEGOTIATES → suite``: only a handshake, or a capture, can say this."""
    basis_text = str(basis or "").strip().lower()
    if basis_text not in HANDSHAKE_BASES:
        raise tb.ClaimRefused(
            "NEGOTIATION_NEEDS_A_HANDSHAKE",
            f"{basis_text or '(none)'} says what a listener will accept; a session was "
            f"negotiated by {' or '.join(HANDSHAKE_BASES)}, and a policy claim belongs on "
            "SUPPORTS")
    claim = tb.claim(endpoint_row["name"], "NEGOTIATES", suite_row["name"], basis=basis,
                     evidence_ids=evidence_ids, observed_at=observed_at,
                     port=port if port is not None else endpoint_row["attributes"].get("port"),
                     protocol=endpoint_row["attributes"].get("protocol") or "TCP")
    return part(endpoint_row, suite_row, claims=[claim])


def supported(*, endpoint_row: Mapping[str, Any], suite_rows: Iterable[Mapping[str, Any]],
              basis: Any = "config-parse", evidence_ids: Iterable[Any] | None = None,
              observed_at: Any = None) -> dict[str, Any]:
    """``endpoint → SUPPORTS → suite``: what the listener would accept, not what it chose."""
    rows = list(suite_rows)
    claims = [tb.claim(endpoint_row["name"], "SUPPORTS", row["name"], basis=basis,
                       evidence_ids=evidence_ids, observed_at=observed_at,
                       port=endpoint_row["attributes"].get("port"))
              for row in rows]
    return part(endpoint_row, *rows, claims=claims)


def negotiated_crypto(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """The crypto a session actually used — and nothing it merely could have used.

    This is the review's AES-128 trap as a function: a suite that appears only under
    ``SUPPORTS`` is reported in ``supported_only`` and never in ``negotiated``, so a
    dependency report cannot say "the application uses AES-128" because a policy allowed
    it.
    """
    keys = _endpoint_keys(bom, query)
    negotiated_suites: dict[str, dict[str, Any]] = {}
    supported_suites: dict[str, dict[str, Any]] = {}
    for claim in bom["claims"]:
        if claim["from_key"] not in keys:
            continue
        target = bom["by_key"][claim["to_key"]]
        if claim["relation"] == "NEGOTIATES":
            negotiated_suites[claim["to_key"]] = target
        elif claim["relation"] == "SUPPORTS" and target["kind"] == "CIPHER_SUITE":
            supported_suites[claim["to_key"]] = target
    crypto: dict[str, dict[str, Any]] = {}
    for key in negotiated_suites:
        for claim in bom["claims"]:
            if claim["from_key"] == key and claim["relation"] == "USES_CRYPTO":
                crypto[claim["to_key"]] = bom["by_key"][claim["to_key"]]
    used_elsewhere = {claim["to_key"] for claim in bom["claims"]
                      if claim["relation"] == "USES_CRYPTO"
                      and bom["by_key"][claim["from_key"]]["kind"] in
                      ("APPLICATION", "SERVICE", "PROCESS")}
    supported_only = {key: row for key, row in supported_suites.items()
                      if key not in negotiated_suites}
    return {
        "query": str(query),
        "negotiated": [_summary(row) for row in negotiated_suites.values()],
        "supported_only": [_summary(row) for row in supported_only.values()],
        "crypto": [_summary(row) for row in crypto.values()],
        "runtime_crypto": [_summary(bom["by_key"][key]) for key in sorted(used_elsewhere)],
        "statement": (
            f"{len(negotiated_suites)} suite(s) negotiated, {len(supported_only)} supported "
            f"but never negotiated, {len(crypto)} crypto asset(s) behind the session, "
            f"{len(used_elsewhere)} used inside a process"),
        "not_proven": [
            "that the negotiated suite is what the application uses internally: the "
            "handshake belongs to the listener, and the process's own crypto is only "
            "known from RUNTIME_OBSERVED evidence",
        ],
    }


# --------------------------------------------------------------------------- #
# 7. Network → runtime: the process, not the socket
# --------------------------------------------------------------------------- #

def runtime(*, process_row: Mapping[str, Any], application_row: Mapping[str, Any],
            library_row: Mapping[str, Any] | None = None,
            crypto_rows: Iterable[Mapping[str, Any]] = (),
            evidence_ids: Iterable[Any] | None = None,
            basis: Any = "runtime-observation", pid: Any = None,
            **facts: Any) -> dict[str, Any]:
    """``application → RUNS → process → LOADS → library → USES_CRYPTO → asset``.

    Every edge here is ``RUNTIME_OBSERVED``, which is a different class from the
    ``NETWORK_OBSERVED`` handshake on the socket: a process that links OpenSSL and uses
    AES-256-GCM internally is not the same claim as a TLS listener negotiating it.
    """
    assets: list[Mapping[str, Any]] = [process_row, application_row]
    claims = [tb.claim(process_row["name"], "RUNS_APPLICATION", application_row["name"],
                       basis=basis, evidence_ids=evidence_ids, pid=pid, **facts)]
    if library_row is not None:
        assets.append(library_row)
        claims.append(tb.claim(process_row["name"], "LOADS", library_row["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
    for crypto_row in crypto_rows:
        assets.append(crypto_row)
        claims.append(tb.claim(process_row["name"], "USES_CRYPTO", crypto_row["name"],
                               basis=basis, evidence_ids=evidence_ids, **facts))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 8. Network → HSM/KMS, metadata only
# --------------------------------------------------------------------------- #

#: attribute names that would mean the model collected a secret. The list is deliberately
#: short and explicit, and the refusal quotes the field.
KEY_MATERIAL_FIELDS: tuple[str, ...] = (
    "private_key", "privatekey", "private_key_pem", "key_material", "keymaterial",
    "secret", "shared_secret", "session_key", "plaintext", "password", "passphrase",
    "key_bytes", "raw_key", "wrapped_key", "master_key", "pin", "psk",
)
KEY_MATERIAL_MARKERS: tuple[str, ...] = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                                         "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY",
                                         "BEGIN PGP PRIVATE KEY")


def _forbid_key_material(fields: Mapping[str, Any], *, where: str) -> None:
    for name, value in fields.items():
        lowered = str(name).lower()
        if lowered in KEY_MATERIAL_FIELDS and "reference" not in lowered \
                and not lowered.endswith(("_ref", "_id")):
            raise tb.ClaimRefused(
                "KEY_MATERIAL_REFUSED",
                f"{where}: {name} is key material, and this model holds references only — "
                "a key reference, its algorithm, size, purpose and status, never the key")
        text = str(value or "")
        if any(marker in text for marker in KEY_MATERIAL_MARKERS):
            raise tb.ClaimRefused(
                "KEY_MATERIAL_REFUSED",
                f"{where}: {name} contains a private key. Collect the reference and the "
                "metadata; the material never enters the graph")


def key_reference(*, name: Any, key_ref: Any, purpose: Any, algorithm: Any,
                  key_size: Any = None, holder: Any = None, status: Any = "ACTIVE",
                  environment: Any = "PRODUCTION",
                  evidence_ids: Iterable[Any] | None = None,
                  **metadata: Any) -> dict[str, Any]:
    """A key the application uses, as metadata: reference, algorithm, size, purpose."""
    _forbid_key_material(dict(metadata), where=f"key reference {name}")
    return tb.asset("KEY_REFERENCE", name, environment=environment,
                    evidence_ids=evidence_ids, key_ref=key_ref, purpose=purpose,
                    algorithm=algorithm, key_size=key_size, holder=holder,
                    status=str(status).upper(), **metadata)


def key_use(*, application_row: Mapping[str, Any], hsm_row: Mapping[str, Any],
            key_row: Mapping[str, Any], capability_row: Mapping[str, Any] | None = None,
            operation: Any = None, basis: Any = "api-poll",
            evidence_ids: Iterable[Any] | None = None) -> dict[str, Any]:
    """``application → USES_HSM → HSM → HOLDS_KEY → key reference`` (and the operation)."""
    assets: list[Mapping[str, Any]] = [application_row, hsm_row, key_row]
    claims = [
        tb.claim(application_row["name"], "USES_HSM", hsm_row["name"], basis=basis,
                 evidence_ids=evidence_ids, operation=operation),
        tb.claim(hsm_row["name"], "HOLDS_KEY", key_row["name"], basis=basis,
                 evidence_ids=evidence_ids),
    ]
    if capability_row is not None:
        assets.append(capability_row)
        claims.append(tb.claim(application_row["name"], "USES_KEY", key_row["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               operation=operation))
        claims.append(tb.claim(hsm_row["name"], "PERFORMS", capability_row["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               operation=operation))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 9. The database: TLS on the wire is not encryption at rest
# --------------------------------------------------------------------------- #

def database_dependency(*, application_row: Mapping[str, Any],
                        database_row: Mapping[str, Any],
                        endpoint_row: Mapping[str, Any],
                        tls_suite: Mapping[str, Any] | None = None,
                        tde: Mapping[str, Any] | None = None,
                        basis: Any = "database-config",
                        evidence_ids: Iterable[Any] | None = None,
                        **facts: Any) -> dict[str, Any]:
    """``application → STORES_IN → database → LISTENS_ON → endpoint`` and its two cryptos.

    ``tls`` and ``tde`` are reported as two independent dependencies: a database can be
    encrypted in transit and in the clear at rest, and collapsing them is how a report
    says a database is encrypted when only the socket was.
    """
    assets: list[Mapping[str, Any]] = [application_row, database_row, endpoint_row]
    claims = [
        tb.claim(application_row["name"], "STORES_IN", database_row["name"], basis=basis,
                 evidence_ids=evidence_ids, **facts),
        tb.claim(database_row["name"], "LISTENS_ON", endpoint_row["name"], basis=basis,
                 evidence_ids=evidence_ids, port=endpoint_row["attributes"].get("port")),
    ]
    if tls_suite is not None:
        assets.append(tls_suite)
        claims.append(tb.claim(endpoint_row["name"], "NEGOTIATES", tls_suite["name"],
                               basis="tls-handshake", evidence_ids=evidence_ids,
                               port=endpoint_row["attributes"].get("port")))
    block = {
        "in_transit": dict(endpoint_row["attributes"].get("tls") or {}),
        "at_rest": dict(tde or {}),
        "distinct": True,
    }
    return {**part(*assets, claims=claims),
            "database_crypto": {database_row["name"]: block}}


# --------------------------------------------------------------------------- #
# 10–12. Mesh, gateway, WAF, and who actually holds the key
# --------------------------------------------------------------------------- #

def mesh(*, mesh_row: Any, trust_domain: Any,
         sidecars: Iterable[Mapping[str, Any]] = (),
         proxied: Iterable[Mapping[str, Any]] = (),
         basis: Any = "mesh-config", evidence_ids: Iterable[Any] | None = None,
         certificate_row: Mapping[str, Any] | None = None,
         **attributes: Any) -> dict[str, Any]:
    """The mesh, its sidecars, and the fact that the *sidecar* does the TLS.

    ``PROXY_FOR`` is the edge that keeps this honest: the handshake belongs to the proxy,
    so an mTLS certificate is attached to the proxy process and not to the application
    behind it.

    ``mesh_row`` may be the device row or the part ``network_device()`` returned.
    """
    mesh_row = (mesh_row["assets"][0] if isinstance(mesh_row, Mapping)
                and "assets" in mesh_row else mesh_row)
    assets: list[Mapping[str, Any]] = [mesh_row, *sidecars, *proxied]
    claims = []
    for sidecar, application in zip(list(sidecars), list(proxied), strict=False):
        claims.append(tb.claim(sidecar["name"], "PROXY_FOR", application["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               trust_domain=trust_domain))
        claims.append(tb.claim(mesh_row["name"], "AUTHENTICATES", application["name"],
                               basis=basis, evidence_ids=evidence_ids,
                               trust_domain=trust_domain,
                               mtls=attributes.get("mtls", True)))
    if certificate_row is not None:
        assets.append(certificate_row)
        for sidecar in sidecars:
            claims.append(tb.claim(sidecar["name"], "USES_CERTIFICATE",
                                   certificate_row["name"], basis=basis,
                                   evidence_ids=evidence_ids, trust_domain=trust_domain))
    return part(*assets, claims=claims)


def tls_terminator(bom: Mapping[str, Any], *, endpoint_query: Any) -> dict[str, Any]:
    """Who performed the handshake on this endpoint — the proxy, not automatically the app.

    Reads ``PRESENTS`` / ``USES_CERTIFICATE`` / ``NEGOTIATES`` edges; if the only thing
    behind the endpoint is a sidecar, the answer says so instead of crediting the
    application with TLS it never ran.
    """
    keys = _endpoint_keys(bom, endpoint_query)
    holders: list[dict[str, Any]] = []
    for claim in bom["claims"]:
        # a holder presents a certificate, or owns the listener the certificate is on
        if claim["relation"] == "PRESENTS" and claim["from_key"] in keys:
            holders.append(_summary(bom["by_key"][claim["from_key"]]))
        elif claim["relation"] == "USES_CERTIFICATE" and claim["from_key"] in keys:
            holders.append(_summary(bom["by_key"][claim["from_key"]]))
        elif claim["relation"] == "LISTENS_ON" and claim["to_key"] in keys:
            holders.append(_summary(bom["by_key"][claim["from_key"]]))
    proxies = [claim for claim in bom["claims"] if claim["relation"] == "PROXY_FOR"
               and bom["by_key"][claim["from_key"]]["kind"] in ("PROCESS", "CONTAINER",
                                                                "SERVICE")]
    proxied_upto = {claim["to_key"]: bom["by_key"][claim["from_key"]]["name"]
                    for claim in proxies}
    return {
        "endpoints": [_summary(bom["by_key"][key]) for key in sorted(keys)],
        "holders": holders,
        "proxied_by": proxied_upto,
        "statement": (f"{len(holders)} certificate holder(s) on {len(keys)} endpoint(s); "
                      f"{len(proxied_upto)} application(s) are proxied"),
    }


# --------------------------------------------------------------------------- #
# 13–14. SSH and IPsec: negotiated parameters, not a version string
# --------------------------------------------------------------------------- #

def ssh_service(*, name: Any, host_row: Mapping[str, Any],
                endpoint_row: Mapping[str, Any], kex: Mapping[str, Any] | None = None,
                host_key: Mapping[str, Any] | None = None,
                cipher: Mapping[str, Any] | None = None,
                mac: Mapping[str, Any] | None = None, version: Any = None,
                basis: Any = "ssh-banner", evidence_ids: Iterable[Any] | None = None,
                **attributes: Any) -> dict[str, Any]:
    """``endpoint → LISTENS_ON ← SSH service → NEGOTIATES → kex, host key, cipher, MAC``."""
    row = tb.asset("SSH_SERVICE", name, version=version, evidence_ids=evidence_ids,
                   **attributes)
    assets: list[Mapping[str, Any]] = [row, host_row, endpoint_row]
    claims = [
        # the port is inventory; only the algorithms came out of the banner
        tb.claim(row["name"], "LISTENS_ON", endpoint_row["name"],
                 basis="agent-inventory", evidence_ids=evidence_ids,
                 port=endpoint_row["attributes"].get("port")),
        tb.claim(row["name"], "RUNS_ON", host_row["name"], basis="agent-inventory",
                 evidence_ids=evidence_ids),
    ]
    for role, asset in (("kex", kex), ("host-key", host_key), ("cipher", cipher),
                        ("mac", mac)):
        if asset is None:
            continue
        assets.append(asset)
        claims.append(tb.claim(row["name"], "NEGOTIATES", asset["name"], basis=basis,
                               evidence_ids=evidence_ids, role=role,
                               port=endpoint_row["attributes"].get("port")))
    return part(*assets, claims=claims)


def ipsec_tunnel(*, name: Any, gateway_row: Mapping[str, Any], peer_row: Mapping[str, Any],
                 zone_row: Mapping[str, Any] | None = None, ike_version: Any = "IKEv2",
                 encryption: Mapping[str, Any] | None = None,
                 integrity: Mapping[str, Any] | None = None,
                 dh_group: Mapping[str, Any] | None = None,
                 authentication: Mapping[str, Any] | None = None,
                 proposals: Iterable[Mapping[str, Any]] = (),
                 basis: Any = "vpn-config", evidence_ids: Iterable[Any] | None = None,
                 status: Any = "UP", **attributes: Any) -> dict[str, Any]:
    """A tunnel: IKE version, encryption, integrity, DH group, and how it authenticates.

    ``proposals`` are what the gateways *would* accept (``SUPPORTS``); the four chosen
    parameters are what the tunnel *negotiated* (``NEGOTIATES``), and the two are never
    merged into one list.
    """
    status_text = str(status or "UP").strip().upper()
    if status_text not in ("UP", "DOWN", "UNKNOWN"):
        raise tb.ClaimRefused("UNKNOWN_TUNNEL_STATUS",
                              f"{status} is not a tunnel state; a tunnel is UP, DOWN or "
                              "UNKNOWN, and only one of those carries traffic")
    # a pre-shared key is key material: the reference is collected, the secret is not
    _forbid_key_material(dict(attributes), where=f"tunnel {name}")
    row = tb.asset("IPSEC_TUNNEL", name, evidence_ids=evidence_ids, ike_version=ike_version,
                   tunnel_state=status_text, **attributes)
    assets: list[Mapping[str, Any]] = [row, gateway_row, peer_row]
    claims = [
        tb.claim(gateway_row["name"], "TUNNELS_TO", peer_row["name"], basis=basis,
                 evidence_ids=evidence_ids, ike_version=ike_version),
    ]
    if zone_row is not None:
        assets.append(zone_row)
        claims.append(tb.claim(row["name"], "TUNNELS_TO", zone_row["name"], basis=basis,
                               evidence_ids=evidence_ids, ike_version=ike_version))
    for role, asset in (("encryption", encryption), ("integrity", integrity),
                        ("dh-group", dh_group), ("authentication", authentication)):
        if asset is None:
            continue
        assets.append(asset)
        claims.append(tb.claim(row["name"], "NEGOTIATES", asset["name"], basis=basis,
                               evidence_ids=evidence_ids, role=role, protocol="UDP",
                               port=attributes.get("port", 500)))
    for proposal in proposals:
        assets.append(proposal)
        claims.append(tb.claim(row["name"], "SUPPORTS", proposal["name"], basis=basis,
                               evidence_ids=evidence_ids, role="proposal"))
    return part(*assets, claims=claims)


# --------------------------------------------------------------------------- #
# 19–20. Vendor and hardware behind a network device
# --------------------------------------------------------------------------- #

def network_device(*, kind: Any, name: Any, vendor: Any, product: Any, model: Any = None,
                   firmware_version: Any = None, ha_role: Any = None,
                   tenant: Any = None, environment: Any = "PRODUCTION",
                   evidence_ids: Iterable[Any] | None = None,
                   **attributes: Any) -> dict[str, Any]:
    """A network device with its vendor chain and firmware, so NBOM joins VBOM and HBOM."""
    kind_text = str(kind or "").upper()
    if kind_text not in ("LOAD_BALANCER", "WAF", "API_GATEWAY", "SERVICE_MESH",
                         "FIREWALL", "VPN_GATEWAY", "DATABASE"):
        raise tb.ClaimRefused("NOT_A_NETWORK_DEVICE",
                              f"{kind_text or '(none)'} is not a network device this model "
                              "builds; a switch is a NIC and a port, not a guess")
    device = tb.asset(kind_text, name, environment=environment, evidence_ids=evidence_ids,
                      vendor=vendor, product=product, model=model,
                      firmware_version=firmware_version, ha_role=ha_role,
                      tenant=tenant, **attributes)
    product_name = f"{vendor} {product}"
    product_row = tb.asset("VENDOR_PRODUCT", product_name, environment=environment,
                           vendor=vendor, product=product, model=model,
                           evidence_ids=evidence_ids)
    vendor_row = tb.asset("VENDOR", vendor, environment=environment,
                          evidence_ids=evidence_ids)
    claims = [
        tb.claim(name, "HAS_MODEL", product_name, basis="vendor-datasheet",
                 evidence_ids=evidence_ids),
        tb.claim(product_name, "SUPPLIED_BY", str(vendor), basis="vendor-datasheet",
                 evidence_ids=evidence_ids),
    ]
    assets: list[Mapping[str, Any]] = [device, product_row, vendor_row]
    if firmware_version:
        firmware_row = tb.asset("FIRMWARE", f"{product} {firmware_version}",
                                version=str(firmware_version), environment=environment,
                                evidence_ids=evidence_ids, vendor=str(vendor))
        assets.append(firmware_row)
        claims.append(tb.claim(name, "RUNS_FIRMWARE", firmware_row["name"],
                               basis="api-poll", evidence_ids=evidence_ids))
    return part(*assets, claims=claims)


def on_hardware(*, device_row: Mapping[str, Any], hardware_row: Mapping[str, Any],
                basis: Any = "agent-inventory",
                evidence_ids: Iterable[Any] | None = None,
                **facts: Any) -> dict[str, Any]:
    """``endpoint → device → hardware``: the network edge that ends in a physical bay."""
    return part(device_row, hardware_row,
                claims=[tb.claim(device_row["name"], "RUNS_ON", hardware_row["name"],
                                 basis=basis, evidence_ids=evidence_ids, **facts)])


# --------------------------------------------------------------------------- #
# 15–16. The graph and its edge record
# --------------------------------------------------------------------------- #

def edge_record(bom: Mapping[str, Any], claim: Mapping[str, Any]) -> dict[str, Any]:
    """One edge, in the shape the review asks every edge to carry."""
    source = bom["by_key"][claim["from_key"]]
    target = bom["by_key"][claim["to_key"]]
    facts = claim.get("facts") or {}
    evidence = _collector_for(bom, (claim.get("evidence_ids") or [None])[0])
    body = {
        "id": claim["id"],
        "source": claim["from"],
        "source_kind": source["kind"],
        "source_id": source["id"],
        "target": claim["to"],
        "target_kind": target["kind"],
        "target_id": target["id"],
        "relationship": claim["relation"],
        "protocol": facts.get("protocol") or _attribute("protocol", target, source),
        "port": facts.get("port") or _attribute("port", target, source),
        "evidence_id": (claim.get("evidence_ids") or [None])[0],
        "evidence_ids": list(claim.get("evidence_ids") or []),
        "evidence_type": evidence.get("evidence_type") or claim["confidence"],
        "collector": evidence.get("collector"),
        "collector_version": evidence.get("collector_version"),
        "basis": claim["basis"],
        "confidence": claim["confidence"],
        "observed_at": claim.get("observed_at") or evidence.get("observed_at"),
        "first_seen": claim.get("first_seen"),
        "last_seen": claim.get("last_seen"),
        "facts": facts,
    }
    return body


def _resolve_one(bom: Mapping[str, Any], query: Any) -> str:
    """Any reference to one node: key, id, name or stable id — and never a guess."""
    text = str(query or "").strip().lower()
    matches = [row["key"] for row in bom["assets"]
               if row["key"].lower() == text or str(row["id"]).lower() == text
               or row["name"].lower() == text or stable_id(row).lower() == text]
    if not matches:
        raise tb.ClaimRefused("UNKNOWN_NODE", f"{query} is not a node in this projection")
    if len(matches) > 1:
        raise tb.ClaimRefused("AMBIGUOUS_NODE",
                              f"{query} names {len(matches)} nodes; qualify it by kind")
    return matches[0]


def _matches(row: Mapping[str, Any], query: Any) -> bool:
    text = str(query or "").strip().lower()
    return text in (row["key"].lower(), str(row["id"]).lower(), row["name"].lower(),
                    stable_id(row).lower())


def _attribute(name: str, *rows: Mapping[str, Any]) -> Any:
    for row in rows:
        value = (row.get("attributes") or {}).get(name)
        if value not in (None, ""):
            return value
    return None


def graph(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Nodes and edges of the network projection, each edge a full record."""
    nodes = [_summary(row) for row in bom["assets"] if row["kind"] in NBOM_KINDS]
    edges = [edge_record(bom, claim) for claim in bom["claims"]]
    missing = [edge["id"] for edge in edges
               if not edge["relationship"] or not edge["basis"] or not edge["confidence"]
               or not edge["evidence_id"]]
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "edges_missing_a_record": missing,
        "adjacency": _adjacency(bom),
    }


def _adjacency(bom: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for claim in bom["claims"]:
        out.setdefault(claim["from"], []).append(
            {"relationship": claim["relation"], "to": claim["to"],
             "confidence": claim["confidence"], "basis": claim["basis"]})
    return dict(sorted(out.items()))


# --------------------------------------------------------------------------- #
# 1–2, 18, 22. The chain: endpoint → service → application → system
# --------------------------------------------------------------------------- #

def dependency_chain(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """Walk from an endpoint up to the business system and down to the crypto.

    The walk follows :data:`SPINE` only, so it answers "what does this endpoint depend on"
    rather than "what is connected to it in any direction".
    """
    keys = _endpoint_keys(bom, query)
    levels: dict[str, list[dict[str, Any]]] = {
        "endpoint": [], "service": [], "process": [], "application": [], "system": [],
        "device": [], "control": [], "database": [], "keys": [], "crypto": [], "vendor": [],
    }
    seen: set[str] = set(keys)
    queue: deque[str] = deque(sorted(keys))
    spine = {relation for relation in SPINE}
    while queue:
        key = queue.popleft()
        for claim in bom["claims"]:
            if claim["relation"] not in spine:
                continue
            # walk both ways: forward is "what this depends on", and the reverse is
            # "what depends on this" — a service is reached from its application by
            # walking PROVIDES backwards, which is what makes the chain reach a system
            if claim["from_key"] == key:
                neighbour = claim["to_key"]
            elif claim["to_key"] == key:
                neighbour = claim["from_key"]
            else:
                continue
            if neighbour in seen:
                continue
            seen.add(neighbour)
            target = bom["by_key"][neighbour]
            bucket = _bucket(target["kind"])
            if bucket and bucket != "endpoint":
                levels[bucket].append(_summary(target))
            queue.append(neighbour)
    for name, rows in levels.items():
        levels[name] = sorted({row["key"]: row for row in rows}.values(),
                              key=lambda row: row["id"])
    return {
        "query": str(query),
        "levels": levels,
        "statement": _chain_statement(levels),
        "not_proven": list(NOT_PROVEN[:2]),
    }


def _bucket(kind: str) -> str | None:
    return {
        "NETWORK_ENDPOINT": "endpoint", "SERVICE": "service", "APPLICATION": "application",
        "BUSINESS_SYSTEM": "system", "PROCESS": "process", "LOAD_BALANCER": "device",
        "WAF": "device",
        "API_GATEWAY": "device", "SERVICE_MESH": "device", "DATABASE": "database",
        "HSM": "keys", "KMS": "keys", "KEY_REFERENCE": "keys",
        "CRYPTO_ASSET": "crypto", "CIPHER_SUITE": "crypto", "VENDOR": "vendor",
        "VENDOR_PRODUCT": "vendor", "IDS": "control", "IPS": "control",
        "RATE_LIMIT": "control", "FIREWALL": "control",
    }.get(kind)


def _chain_statement(levels: Mapping[str, Sequence[Mapping[str, Any]]]) -> str:
    parts = [f"{len(rows)} {name}" for name, rows in levels.items() if rows]
    return " → ".join(parts) if parts else "nothing behind this endpoint was evidenced"


# --------------------------------------------------------------------------- #
# 17. Lifecycle and drift
# --------------------------------------------------------------------------- #

def lifecycle(bom: Mapping[str, Any], *, reference: Any = None) -> dict[str, Any]:
    """Per-edge state: FIRST_SEEN, ACTIVE, CHANGED, SUPERSEDED, REMOVED, UNKNOWN.

    The state is derived from the edge's own record, not from a mutable flag: an edge seen
    once is ``FIRST_SEEN``, an edge with a last_seen older than the reference is
    ``CHANGED``, and an edge with no timestamps at all is ``UNKNOWN`` — which is not the
    same as active.
    """
    reference_text = str(reference or "").strip() or None
    states: dict[str, str] = {}
    for claim in bom["claims"]:
        first = claim.get("first_seen")
        last = claim.get("last_seen") or claim.get("observed_at")
        if not first and not last:
            states[claim["id"]] = "UNKNOWN"
        elif first and last and first == last:
            states[claim["id"]] = "FIRST_SEEN"
        elif reference_text and last and last < reference_text:
            states[claim["id"]] = "CHANGED"
        else:
            states[claim["id"]] = "ACTIVE"
    counts: dict[str, int] = {}
    for state in states.values():
        counts[state] = counts.get(state, 0) + 1
    return {"states": states, "counts": dict(sorted(counts.items())),
            "reference": reference_text}


def drift(previous: Mapping[str, Any], current: Mapping[str, Any], *,
          reference: Any = None) -> dict[str, Any]:
    """What changed in the network between two projections.

    An edge that now points somewhere else is ``SUPERSEDED`` on the old target and
    ``ACTIVE`` on the new one — the review's "was active yesterday, points elsewhere
    today" — rather than one removal plus one addition that lose the history.
    """
    before = {claim["id"]: claim for claim in previous["claims"]}
    after = {claim["id"]: claim for claim in current["claims"]}
    events: list[dict[str, Any]] = []
    by_source_relation: dict[tuple[str, str], dict[str, Any]] = {}
    for claim in current["claims"]:
        by_source_relation[(claim["from_key"], claim["relation"])] = claim
    for identifier, old in before.items():
        if identifier in after:
            new = after[identifier]
            changed = {name: {"from": old.get("facts", {}).get(name),
                              "to": new.get("facts", {}).get(name)}
                       for name in set(old.get("facts") or {}) | set(new.get("facts") or {})
                       if (old.get("facts") or {}).get(name) !=
                       (new.get("facts") or {}).get(name)}
            if changed:
                events.append({"change": "EDGE_CHANGED", "edge": identifier,
                               "relationship": old["relation"], "source": old["from"],
                               "target": old["to"], "facts": changed,
                               "crypto_impact": _crypto_impact(current, new["to_key"])})
            continue
        replacement = by_source_relation.get((old["from_key"], old["relation"]))
        if replacement is not None and replacement["to_key"] != old["to_key"]:
            events.append({"change": "EDGE_SUPERSEDED", "edge": identifier,
                           "relationship": old["relation"], "source": old["from"],
                           "previous_target": old["to"],
                           "target": replacement["to"],
                           "crypto_impact": _crypto_impact(current, replacement["to_key"])})
            continue
        events.append({"change": "EDGE_REMOVED", "edge": identifier,
                       "relationship": old["relation"], "source": old["from"],
                       "target": old["to"],
                       "crypto_impact": _crypto_impact(previous, old["to_key"])})
    for identifier, new in after.items():
        if identifier in before:
            continue
        if any(event["change"] == "EDGE_SUPERSEDED" and event["target"] == new["to"]
               for event in events):
            continue
        events.append({"change": "EDGE_ADDED", "edge": identifier,
                       "relationship": new["relation"], "source": new["from"],
                       "target": new["to"],
                       "crypto_impact": _crypto_impact(current, new["to_key"])})
    counts: dict[str, int] = {}
    for event in events:
        counts[event["change"]] = counts.get(event["change"], 0) + 1
    return {
        "schema": "cryptoscan.nbom-drift/1",
        "reference": str(reference or "").strip() or None,
        "events": sorted(events, key=lambda row: (row["change"], row["edge"])),
        "by_change": dict(sorted(counts.items())),
        "statement": (f"{len(events)} network change(s): " +
                      (", ".join(f"{count} {name}" for name, count in
                                 sorted(counts.items())) or "none")),
        "not_proven": ["that a superseded edge stopped working: what is recorded is that "
                       "the configuration now names a different target"],
    }


def _crypto_impact(bom: Mapping[str, Any], key: str) -> dict[str, Any]:
    """What cryptography sits behind a node — the per-change block of the review."""
    counts: dict[str, int] = {}
    seen: set[str] = set()
    frontier = [key]
    while frontier:
        nxt: list[str] = []
        for current in frontier:
            for claim in bom["claims"]:
                if claim["from_key"] != current or claim["to_key"] in seen:
                    continue
                target = bom["by_key"][claim["to_key"]]
                if target["kind"] in ("CIPHER_SUITE", "CRYPTO_ASSET", "CERTIFICATE",
                                      "ALGORITHM", "APPLICATION", "BUSINESS_SYSTEM",
                                      "HSM", "KMS", "DATABASE"):
                    counts[target["kind"]] = counts.get(target["kind"], 0) + 1
                    seen.add(claim["to_key"])
                    nxt.append(claim["to_key"])
        frontier = nxt
    return {"counts": dict(sorted(counts.items())),
            "total": sum(counts.values())}


# --------------------------------------------------------------------------- #
# 21. Coverage, and what it makes partial
# --------------------------------------------------------------------------- #

def coverage(*, expected: int, observed: int, unavailable: int = 0, unknown: int = 0,
             permission_denied: int = 0, forbidden: int = 0) -> dict[str, Any]:
    """The denominator, with the bucket rule that makes it worth anything.

    Buckets must account for the denominator; if they do not, the coverage is refused
    rather than reported, because a percentage that does not add up is worse than none.
    """
    accounted = observed + unavailable + unknown + permission_denied + forbidden
    if expected < 0 or accounted > expected:
        raise tb.ClaimRefused(
            "COVERAGE_DOES_NOT_RECONCILE",
            f"{accounted} endpoint(s) accounted for out of {expected}; coverage cannot "
            "claim more endpoints than the estate expected")
    missing = expected - accounted
    verdict = "COMPLETE" if expected and missing == 0 and unavailable == 0 \
        and permission_denied == 0 and forbidden == 0 else "PARTIAL"
    return {
        "expected": expected, "observed": observed, "unavailable": unavailable,
        "unknown": unknown, "permission_denied": permission_denied, "forbidden": forbidden,
        "unaccounted": missing, "verdict": verdict,
        "propagates": {"nbom": verdict, "cbom_network_evidence": verdict,
                       "digital_twin_network": verdict},
        "statement": (f"expected {expected} endpoint(s): observed {observed}, unavailable "
                      f"{unavailable}, unknown {unknown}, permission denied "
                      f"{permission_denied} — coverage {verdict}"),
        "rule": ("an unavailable endpoint is not an absent endpoint: it is counted in the "
                 "denominator and reported as unseen, and every view that reads this "
                 "projection inherits PARTIAL until it is accounted for"),
    }


# --------------------------------------------------------------------------- #
# 18. The projection
# --------------------------------------------------------------------------- #

def build(estate_doc: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical estate → NBOM. One graph, network subset, coverage carried through."""
    if not isinstance(estate_doc, Mapping) or estate_doc.get("schema") != tb.ESTATE_SCHEMA:
        raise ValueError(f"build() takes a {tb.ESTATE_SCHEMA} document, not a projection; "
                         "an NBOM is never its own input")
    bom = tb.build(estate_doc)
    endpoints = {row["key"]: row for row in bom["assets"]
                 if row["kind"] == "NETWORK_ENDPOINT"}
    chains = {row["name"]: dependency_chain(bom, query=row["key"])
              for row in endpoints.values()}
    modes: dict[str, int] = {}
    for claim in bom["claims"]:
        if claim["relation"] in ("TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH"):
            modes[claim["relation"]] = modes.get(claim["relation"], 0) + 1
    networks = graph(bom)
    gaps = itertools_gaps(estate_doc)
    coverage_block = gaps.get("coverage")
    segments = gaps.get("segments")
    routes: dict[str, Any] = {}
    for row in endpoints.values():
        try:
            routes[row["name"]] = paths(bom, source=row["key"])
        except tb.ClaimRefused:  # pragma: no cover - an endpoint is its own source
            continue
    policy: dict[str, Any] = {}
    for row in endpoints.values():
        try:
            finding = policy_gap(bom, query=row["key"])
        except tb.ClaimRefused:  # pragma: no cover - endpoint keys always resolve
            continue
        if finding["findings"]:
            policy[row["name"]] = finding
    sections = dict(estate_doc.get("sections") or {})
    inspection: dict[str, Any] = {}
    for row in endpoints.values():
        try:
            found = inspection_gap(bom, source=row["key"])
        except tb.ClaimRefused:  # pragma: no cover - an endpoint is its own source
            continue
        if found["routes"]:
            inspection[row["name"]] = found
    return {
        "schema": SCHEMA,
        "projection": True,
        "source_of_truth": "CANONICAL_ESTATE",
        "derived_from": bom["derived_from"],
        "environment": bom["environment"],
        "assets": [row for row in bom["assets"] if row["kind"] in NBOM_KINDS],
        "by_key": bom["by_key"],
        "claims": bom["claims"],
        "refusals": bom["refusals"],
        "counts": bom["counts"],
        "ids": nbom_ids(bom),
        "endpoints": [_summary(row) for row in endpoints.values()],
        "chains": chains,
        "routes": routes,
        "policy_findings": policy,
        "sensors": [_sensor_row(row) for row in bom["assets"]
                    if row["kind"] in SENSOR_KINDS],
        "inspection": inspection,
        "rate_limits": rate_limit_gap(bom),
        "sections": sections,
        "exposure": pqc_exposure(bom),
        "graph": networks,
        "tls_modes": dict(sorted(modes.items())),
        "lifecycle": lifecycle(bom),
        "coverage": coverage_block,
        "coverage_by_segment": (coverage_by_segment(segments) if segments else None),
        "statement": (
            f"{len(endpoints)} network endpoint(s), {networks['edge_count']} evidenced "
            f"edge(s), {len(modes)} TLS boundary mode(s) in use, "
            f"{sum(row['proven'] for row in routes.values())} proven route(s); "
            f"{len(bom['refusals'])} claim(s) refused"),
        "not_proven": list(NOT_PROVEN),
    }


def itertools_gaps(estate_doc: Mapping[str, Any]) -> dict[str, Any]:
    """The gaps block an estate carries: coverage, and coverage per segment."""
    merged: dict[str, Any] = {}
    for gap in estate_doc.get("gaps") or []:
        if isinstance(gap, Mapping):
            merged.update({key: value for key, value in gap.items()
                           if key in ("coverage", "segments", "reason")})
    return merged


def twin(bom: Mapping[str, Any]) -> dict[str, Any]:
    """The digital twin's network view: who connects to whom, how, and with what."""
    edges = [edge_record(bom, claim) for claim in bom["claims"]]
    return {
        "schema": "cryptoscan.nbom-twin/1",
        "who_connects_to_whom": sorted({(edge["source"], edge["target"]) for edge in edges}),
        "how": sorted({(edge["relationship"], edge["protocol"] or "-") for edge in edges}),
        "tls": [edge for edge in edges if edge["relationship"] == "NEGOTIATES"],
        "certificates": [edge for edge in edges if edge["relationship"] in
                         ("PRESENTS", "USES_CERTIFICATE", "CONTAINS_KEY", "SIGNED_WITH")],
        "applications": sorted({edge["target"] for edge in edges
                                if edge["target_kind"] == "APPLICATION"}),
        "systems": sorted({edge["source"] for edge in edges
                           if edge["source_kind"] == "BUSINESS_SYSTEM"}),
        "keys": sorted({edge["target"] for edge in edges if edge["target_kind"] in
                        ("HSM", "KMS", "KEY_REFERENCE")}),
        "edge_count": len(edges),
        "statement": (f"{len(edges)} edge(s) into the twin — one graph, read as the "
                      "network projection rather than stored as a second database"),
    }


def from_document(document: Mapping[str, Any] | Any) -> None:
    """An NBOM or a TechBOM is a projection and can never be an input."""
    schema = ""
    if isinstance(document, Mapping):
        schema = str(document.get("schema") or "")
    if schema in (SCHEMA, "cryptoscan.nbom-twin/1", tb.SCHEMA):
        raise tb.ClaimRefused(
            "PROJECTION_AS_SOURCE",
            f"{schema} is a projection; the network projection reads a "
            f"{tb.ESTATE_SCHEMA} estate, not another projection")
    raise tb.ClaimRefused(
        "UNKNOWN_DOCUMENT",
        f"{schema or 'that document'} is not a canonical estate; NBOM is built from "
        f"{tb.ESTATE_SCHEMA}")



# --------------------------------------------------------------------------- #
# The review's ids, and the path it draws
# --------------------------------------------------------------------------- #

#: the readable prefix the review asks for, per kind. `TECH-EP-001` is the graph's id and
#: `SERVICE-9281` is the content-addressed one; these are the per-kind numbers a bank's
#: change record uses, and the three are the same node.
ID_PREFIX: dict[str, str] = {
    "NETWORK_ENDPOINT": "NET-ENDPOINT", "SERVICE": "SERVICE",
    "APPLICATION": "APPLICATION", "BUSINESS_SYSTEM": "SYSTEM",
    "LOAD_BALANCER": "LOAD-BALANCER", "API_GATEWAY": "API-GATEWAY", "WAF": "WAF",
    "SERVICE_MESH": "SERVICE-MESH", "DATABASE": "DATABASE",
    "CIPHER_SUITE": "CIPHER-SUITE", "CERTIFICATE": "CERTIFICATE",
    "SSH_SERVICE": "SSH-SERVICE", "IPSEC_TUNNEL": "IPSEC-TUNNEL",
    "IDS": "IDS", "IPS": "IPS", "RATE_LIMIT": "RATE-LIMIT", "FIREWALL": "FIREWALL",
    "CRYPTO_OPERATION": "CRYPTO-OP", "VENDOR": "VENDOR", "HOST": "HOST", "VM": "VM",
}


def nbom_ids(bom: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """``NET-ENDPOINT-001``, ``SERVICE-002`` — the review's ids, one per node.

    Numbering is per kind and ordered by key, so it is stable for a stable estate and it
    never collides across kinds. ``stable_id`` (``SERVICE-9281``) is the one to key on.
    """
    counters: dict[str, int] = {}
    out: dict[str, dict[str, str]] = {}
    for row in sorted(bom["assets"], key=lambda item: (item["kind"], item["key"])):
        if row["kind"] not in NBOM_KINDS:
            continue
        prefix = ID_PREFIX.get(row["kind"], row["kind"].replace("_", "-"))
        counters[prefix] = counters.get(prefix, 0) + 1
        out.setdefault(row["kind"], {})[row["name"]] = f"{prefix}-{counters[prefix]:03d}"
    return out


#: relations a request can travel along. The spine plus the hops a packet actually takes.
PATH_RELATIONS: frozenset[str] = frozenset({
    "ROUTES_TO", "FORWARDS_TO", "TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH",
    "PROXY_FOR", "LISTENS_ON", "RUNS_APPLICATION", "TUNNELS_TO", "CONNECTS_TO",
})

#: walked backwards: an application *provides* a service, so a request that reached the
#: service is served by the application. The edge points the other way on purpose.
REVERSE_PATH_RELATIONS: frozenset[str] = frozenset({"PROVIDES"})

#: where a path stops: something that terminates a request rather than passing it on
PATH_ENDS: tuple[str, ...] = ("APPLICATION", "DATABASE", "HSM", "KMS")


def paths(bom: Mapping[str, Any], *, source: Any, target: Any = None,
          max_hops: int = 8, limit: int = 12,
          include_declared: bool = True) -> dict[str, Any]:
    """Every evidenced route from one node to an application, with its TLS profile.

    A path is *proven* only when every edge on it is: a route that depends on one
    ``IMPORTED`` hop is reported as declared, because that is what it is. A tunnel whose
    recorded status is not ``UP`` carries no traffic and is not a path at all.
    """
    start = _resolve_one(bom, source)
    findings: list[dict[str, Any]] = []
    walked: list[list[dict[str, Any]]] = []

    def walk(key: str, trail: list[dict[str, Any]], seen: set[str]) -> None:
        if len(findings) >= limit or len(trail) > max_hops:
            return
        row = bom["by_key"][key]
        if trail and (row["kind"] in PATH_ENDS or
                      (target is not None and _matches(row, target))):
            findings.append(list(trail))
            return
        for claim in bom["claims"]:
            if claim["relation"] in REVERSE_PATH_RELATIONS:
                if claim["to_key"] != key:
                    continue
                step = claim["from_key"]
            elif claim["relation"] in PATH_RELATIONS:
                if claim["from_key"] != key:
                    continue
                step = claim["to_key"]
            else:
                continue
            if step in seen:
                continue
            if claim["relation"] == "TUNNELS_TO" and not _tunnel_up(bom["by_key"][claim["from_key"]]):
                continue
            if not include_declared and claim["confidence"] not in tb.PROVEN:
                continue
            walk(step, [*trail, claim], seen | {step})

    walk(start, [], {start})
    for trail in findings:
        walked.append(trail)
    routes = [_route(bom, trail) for trail in walked]
    proven = [route for route in routes if route["proven"]]
    return {
        "source": _summary(bom["by_key"][start]),
        "target": str(target) if target is not None else None,
        "routes": sorted(routes, key=lambda route: route["path"]),
        "proven": len(proven),
        "declared": len(routes) - len(proven),
        "statement": (
            f"{len(routes)} route(s) from {bom['by_key'][start]['name']}: "
            f"{len(proven)} proven, {len(routes) - len(proven)} declared"),
        "not_proven": ["that a request takes this route now: a graph holds every route "
                       "that was evidenced, and a request takes one of them at a time"],
    }


def _route(bom: Mapping[str, Any], trail: list[Mapping[str, Any]]) -> dict[str, Any]:
    # a step is named by the node it *arrives* at: the target for a forward relation and
    # the source for the one that is walked backwards
    keys = [trail[0]["from_key"]]
    for claim in trail:
        keys.append(claim["to_key"] if claim["to_key"] != keys[-1] else claim["from_key"])
    names = [bom["by_key"][key]["name"] for key in keys]
    modes = [claim["relation"] for claim in trail
             if claim["relation"] in ("TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH")]
    suites = [_suite_at(bom, claim) for claim in trail
              if claim["relation"] in ("TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH")]
    return {
        "path": " → ".join(names),
        "nodes": names,
        "relationships": [claim["relation"] for claim in trail],
        "tls_modes": modes,
        "suites": [suite for suite in suites if suite],
        "proven": all(claim["confidence"] in tb.PROVEN for claim in trail),
        "weakest": min((claim["confidence"] for claim in trail),
                       key=lambda name: tb.CONFIDENCE[name]),
        "statement": (
            f"{' → '.join(names)} ({', '.join(modes) or 'no TLS boundary'}"
            + (f"; {', '.join(filter(None, suites))}" if suites else "") + ")"),
    }


def _suite_at(bom: Mapping[str, Any], claim: Mapping[str, Any]) -> str | None:
    for other in bom["claims"]:
        if other["relation"] == "NEGOTIATES" and other["from_key"] == claim["from_key"]:
            return bom["by_key"][other["to_key"]]["name"]
    row = bom["by_key"][claim["from_key"]]
    return (row["attributes"].get("tls") or {}).get("suite")


def _tunnel_up(row: Mapping[str, Any]) -> bool:
    state = str(row["attributes"].get("tunnel_state") or "UP").upper()
    return state == "UP"


# --------------------------------------------------------------------------- #
# Configured, supported, negotiated — the fourth state the review asks for
# --------------------------------------------------------------------------- #

def configured(*, endpoint_row: Mapping[str, Any], min_version: Any = None,
               max_version: Any = None, suites: Iterable[Any] = (),
               sni_required: Any = None, alpn: Iterable[Any] = (),
               client_auth: Any = None, evidence_ids: Iterable[Any] | None = None,
               ) -> dict[str, Any]:
    """The listener's *policy*: what it will accept, as distinct from what it chose.

    The review asks for ``SUPPORTED``, ``CONFIGURED``, ``NEGOTIATED`` and ``OBSERVED`` to
    stay apart. A policy is a fact on the listener; the suites it enables are ``SUPPORTS``
    claims; the one it chose is ``NEGOTIATES``; what a capture saw is the evidence class.
    """
    if min_version and max_version and str(min_version) > str(max_version):
        raise tb.ClaimRefused(
            "TLS_POLICY_INVERTED",
            f"min {min_version} is newer than max {max_version}; a policy that accepts "
            "nothing is a mistake, not a configuration")
    row = dict(endpoint_row)
    attributes = dict(row.get("attributes") or {})
    attributes["tls_policy"] = {
        "min_version": str(min_version) if min_version else None,
        "max_version": str(max_version) if max_version else None,
        "suites": [str(name) for name in suites],
        "sni_required": sni_required,
        "alpn": [str(value).upper() for value in alpn],
        "client_auth": client_auth,
    }
    row["attributes"] = attributes
    row["evidence_ids"] = list(row.get("evidence_ids") or []) + [
        str(value) for value in (evidence_ids or [])]
    return row


def policy_gap(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """Configured policy versus the session that was observed — a downgrade is a finding.

    This is the review's point 6 as a measurement: a listener that may speak TLS 1.3 and
    negotiated TLS 1.2 is neither an error nor a success, it is a **finding** with two
    versions in it.
    """
    keys = _endpoint_keys(bom, query)
    findings: list[dict[str, Any]] = []
    for key in sorted(keys):
        row = bom["by_key"][key]
        policy = (row["attributes"].get("tls_policy") or {})
        negotiated = (row["attributes"].get("tls") or {})
        chosen_version = str(negotiated.get("version") or "")
        chosen_suite = str(negotiated.get("suite") or "")
        if policy:
            if policy.get("max_version") and chosen_version and                     chosen_version < str(policy["max_version"]):
                findings.append({"code": "TLS_DOWNGRADED", "endpoint": row["name"],
                                 "policy": policy["max_version"],
                                 "negotiated": chosen_version,
                                 "reason": "the listener could have gone higher"})
            if policy.get("min_version") and chosen_version and                     chosen_version < str(policy["min_version"]):
                findings.append({"code": "BELOW_CONFIGURED_FLOOR", "endpoint": row["name"],
                                 "policy": policy["min_version"],
                                 "negotiated": chosen_version,
                                 "reason": "the session is weaker than the policy allows"})
            allowed = [str(name) for name in policy.get("suites") or []]
            if allowed and chosen_suite and chosen_suite not in allowed:
                findings.append({"code": "SUITE_NOT_IN_POLICY", "endpoint": row["name"],
                                 "negotiated": chosen_suite,
                                 "policy": allowed,
                                 "reason": "the suite was not on the list"})
        if not policy:
            findings.append({"code": "NO_POLICY_RECORDED", "endpoint": row["name"],
                             "negotiated": chosen_version or "unknown",
                             "reason": "no configuration was read for this listener"})
    return {
        "query": str(query),
        "findings": findings,
        "counts": {code: sum(1 for row in findings if row["code"] == code)
                   for code in sorted({row["code"] for row in findings})},
        "statement": (f"{len(findings)} policy finding(s) on {len(keys)} endpoint(s): "
                      + (", ".join(sorted({row["code"] for row in findings})) or "none")),
    }


# --------------------------------------------------------------------------- #
# Runtime and network, side by side
# --------------------------------------------------------------------------- #

def runtime_vs_network(bom: Mapping[str, Any], *, query: Any) -> dict[str, Any]:
    """Which algorithms the wire chose, which the process used, and which are both.

    Two observations of two different things. An intersection is evidence that the
    process that serves the endpoint is the process that links the library; the
    difference is what a report must not blend.
    """
    keys = _endpoint_keys(bom, query)
    on_the_wire: dict[str, dict[str, Any]] = {}
    for claim in bom["claims"]:
        if claim["from_key"] in keys and claim["relation"] == "NEGOTIATES":
            suite_key = claim["to_key"]
            on_the_wire[suite_key] = bom["by_key"][suite_key]
            for inner in bom["claims"]:
                if inner["from_key"] == suite_key and inner["relation"] == "USES_CRYPTO":
                    on_the_wire[inner["to_key"]] = bom["by_key"][inner["to_key"]]
    in_the_process = {claim["to_key"]: bom["by_key"][claim["to_key"]]
                      for claim in bom["claims"]
                      if claim["relation"] == "USES_CRYPTO"
                      and bom["by_key"][claim["from_key"]]["kind"] == "PROCESS"}
    both = sorted(set(on_the_wire) & set(in_the_process))
    return {
        "query": str(query),
        "network": [_summary(row) for key, row in sorted(on_the_wire.items())],
        "runtime": [_summary(row) for key, row in sorted(in_the_process.items())],
        "both": [_summary(bom["by_key"][key]) for key in both],
        "network_only": [_summary(row) for key, row in sorted(on_the_wire.items())
                         if key not in in_the_process],
        "runtime_only": [_summary(row) for key, row in sorted(in_the_process.items())
                         if key not in on_the_wire],
        "statement": (f"{len(on_the_wire)} on the wire, {len(in_the_process)} in the "
                      f"process, {len(both)} in both"),
        "not_proven": ["that an algorithm in both places is the same dependency: the "
                       "handshake belongs to the listener and the library to the process"],
    }


# --------------------------------------------------------------------------- #
# Evidence on a network edge
# --------------------------------------------------------------------------- #

def evidence_record(evidence_id: Any, *, collector: Any, collector_version: Any = None,
                    target_id: Any = None, observed_at: Any = None, source: Any = None,
                    evidence_type: Any = "OBSERVED", raw_reference: Any = None,
                    normalized_fact: Any = None, hash: Any = None,
                    confidence: Any = "HIGH") -> dict[str, Any]:
    """One collector read, as a record. No hash, no record: it could not be re-checked."""
    identifier = str(evidence_id or "").strip()
    if not identifier:
        raise tb.ClaimRefused("EVIDENCE_WITHOUT_ID", "an evidence record needs an id")
    if not str(collector or "").strip():
        raise tb.ClaimRefused("EVIDENCE_WITHOUT_COLLECTOR",
                              f"{identifier}: an observation with no collector behind it "
                              "cannot be argued with")
    if not str(hash or "").strip():
        raise tb.ClaimRefused("EVIDENCE_WITHOUT_HASH",
                              f"{identifier}: a record with no content hash cannot be "
                              "re-checked, so it is a note rather than evidence")
    return {
        "evidence_id": identifier, "collector": str(collector),
        "collector_version": str(collector_version) if collector_version else None,
        "target_id": str(target_id) if target_id else None,
        "observed_at": str(observed_at) if observed_at else None,
        "source": str(source) if source else None,
        "evidence_type": str(evidence_type).upper(),
        "raw_reference": str(raw_reference) if raw_reference else None,
        "normalized_fact": str(normalized_fact) if normalized_fact else None,
        "hash": str(hash), "confidence": str(confidence).upper(),
    }


def evidence_node(record: Mapping[str, Any], *, environment: Any = "PRODUCTION"):
    """An evidence record as a node, so an edge can point at it and a reader can walk it."""
    return tb.asset("EVIDENCE", record["evidence_id"], environment=environment,
                    evidence_ids=[record["evidence_id"]],
                    collector=record.get("collector"),
                    collector_version=record.get("collector_version"),
                    observed_at=record.get("observed_at"),
                    source=record.get("source"),
                    evidence_type=record.get("evidence_type"),
                    raw_reference=record.get("raw_reference"),
                    normalized_fact=record.get("normalized_fact"),
                    hash=record.get("hash"),
                    confidence=record.get("confidence"))


def attach_evidence(*, row: Mapping[str, Any], record: Mapping[str, Any],
                    basis: Any = "config-parse") -> dict[str, Any]:
    """``asset → EVIDENCED_BY → EVIDENCE``: how this node is known at all."""
    node = evidence_node(record)
    claim = tb.claim(row["name"], "EVIDENCED_BY", node["name"], basis=basis,
                     evidence_ids=[record["evidence_id"]])
    return part(row, node, claims=[claim])


def _collector_for(bom: Mapping[str, Any], evidence_id: Any) -> dict[str, Any]:
    if not evidence_id:
        return {"collector": None, "evidence_type": None, "observed_at": None}
    for row in bom["assets"]:
        if row["kind"] == "EVIDENCE" and row["name"] == str(evidence_id):
            attributes = row["attributes"]
            return {"collector": attributes.get("collector"),
                    "collector_version": attributes.get("collector_version"),
                    "evidence_type": attributes.get("evidence_type"),
                    "observed_at": attributes.get("observed_at")}
    return {"collector": None, "evidence_type": None, "observed_at": None}


# --------------------------------------------------------------------------- #
# What the wire leaves exposed to a quantum computer
# --------------------------------------------------------------------------- #

def pqc_exposure(bom: Mapping[str, Any], *, query: Any = None) -> dict[str, Any]:
    """Quantum-sensitive algorithms a session actually negotiated, per endpoint.

    Capability is not exposure: an HSM that *supports* RSA is a migration question, but a
    session that *negotiated* ECDSA is an exposure, and the two are counted apart.
    """
    keys = _endpoint_keys(bom, query) if query is not None else         {row["key"] for row in bom["assets"] if row["kind"] == "NETWORK_ENDPOINT"}
    findings: list[dict[str, Any]] = []
    for key in sorted(keys):
        endpoint = bom["by_key"][key]
        exposed: list[str] = []
        for claim in bom["claims"]:
            if claim["from_key"] != key or claim["relation"] != "NEGOTIATES":
                continue
            suite = bom["by_key"][claim["to_key"]]
            for inner in bom["claims"]:
                if inner["from_key"] != suite["key"] or inner["relation"] != "USES_CRYPTO":
                    continue
                asset = bom["by_key"][inner["to_key"]]
                name = asset["name"].upper()
                if any(token in name for token in tb.QUANTUM_SENSITIVE) or \
                        asset["attributes"].get("quantum_sensitive"):
                    exposed.append(asset["name"])
        blockers = sorted({row["name"] for row in bom["assets"]
                           if row["kind"] in tb.PQC_BLOCKER_KINDS
                           and row["key"] not in keys})
        if exposed:
            findings.append({"endpoint": endpoint["name"], "exposed": sorted(set(exposed)),
                             "blockers": blockers})
    return {
        "endpoints": findings,
        "statement": (f"{len(findings)} endpoint(s) negotiate quantum-sensitive "
                      f"cryptography: " + ", ".join(
                          f"{row['endpoint']} ({', '.join(row['exposed'])})"
                          for row in findings) if findings else
                      "no endpoint negotiates a quantum-sensitive algorithm"),
        "not_proven": ["that a quantum computer is available: this is exposure, and the "
                       "migration judgement belongs to the PQC engine"],
    }


# --------------------------------------------------------------------------- #
# Vendor capability, and a lifecycle timeline
# --------------------------------------------------------------------------- #

def product_capability(*, product_row: Mapping[str, Any],
                       capability_row: Mapping[str, Any], basis: Any = "vendor-datasheet",
                       evidence_ids: Iterable[Any] | None = None,
                       **facts: Any) -> dict[str, Any]:
    """``VENDOR_PRODUCT → SUPPORTS → CRYPTO_CAPABILITY``: VBOM joined to CBOM.

    A datasheet claiming a product speaks TLS 1.3 is exactly the class that claim
    deserves, and it is a different statement from the product's firmware in the field.
    """
    return part(product_row, capability_row,
                claims=[tb.claim(product_row["name"], "SUPPORTS", capability_row["name"],
                                 basis=basis, evidence_ids=evidence_ids, **facts)])


def timeline(bom: Mapping[str, Any], *, previous: Mapping[str, Any] | None = None,
             reference: Any = None) -> dict[str, Any]:
    """Each edge's life: first seen, last seen, and whether it is still active.

    The drift feed says what changed; this says what an edge's history is, which is the
    question an investigator asks after the change.
    """
    states = lifecycle(bom, reference=reference)["states"]
    rows: list[dict[str, Any]] = []
    for claim in bom["claims"]:
        rows.append({
            "edge": claim["id"], "relationship": claim["relation"],
            "source": claim["from"], "target": claim["to"],
            "state": states.get(claim["id"], "UNKNOWN"),
            "first_seen": claim.get("first_seen"), "last_seen": claim.get("last_seen"),
            "observed_at": claim.get("observed_at"),
        })
    changes = drift(previous, bom, reference=reference) if previous is not None else None
    return {
        "edges": sorted(rows, key=lambda row: (row["state"], row["edge"])),
        "counts": dict(sorted(
            {state: sum(1 for row in rows if row["state"] == state)
             for state in {row["state"] for row in rows}}.items())),
        "drift": changes,
        "statement": (f"{len(rows)} edge(s) with history; "
                      f"{'no previous projection was supplied' if previous is None else changes['statement']}"),
    }


def coverage_by_segment(segments: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Coverage per network segment, with the worst segment deciding the whole.

    A bank's DMZ at 100% and its cardholder zone at 60% is not a 90% estate.
    """
    per_segment: dict[str, dict[str, Any]] = {}
    for name, counts in sorted(segments.items()):
        per_segment[name] = coverage(**counts)
    verdicts = [row["verdict"] for row in per_segment.values()]
    overall = "COMPLETE" if verdicts and all(v == "COMPLETE" for v in verdicts) else \
        ("PARTIAL" if per_segment else "UNKNOWN")
    return {
        "segments": per_segment,
        "verdict": overall,
        "weakest": sorted(per_segment, key=lambda name: per_segment[name]["observed"]
                          / max(per_segment[name]["expected"], 1))[:1],
        "statement": (f"{len(per_segment)} segment(s), overall {overall}: " +
                      ", ".join(f"{name} {row['verdict']}"
                                for name, row in per_segment.items())),
    }


# --------------------------------------------------------------------------- #
# Controls: what sees the traffic, what limits it, and what we may send
# --------------------------------------------------------------------------- #

#: the two intrusion controls, kept apart because they do different jobs. An IPS is in the
#: path and can drop a packet; an IDS sees a copy and can only say what it saw.
SENSOR_KINDS: tuple[str, ...] = ("IDS", "IPS")

#: how a sensor is deployed. Only INLINE puts it on the route; the rest see a copy.
SENSOR_MODES: dict[str, str] = {"INLINE": "INLINE", "TAP": "TAP", "SPAN": "SPAN",
                                "MIRROR": "SPAN", "OUT_OF_PATH": "TAP"}

#: the modes a route can pass *through*. A tap is not one of them, and that is the point.
IN_PATH_MODES: frozenset[str] = frozenset({"INLINE"})

#: what a control can be. A route crosses one of these or it does not.
CONTROL_KINDS: tuple[str, ...] = ("IDS", "IPS", "FIREWALL", "WAF", "SECURITY_APPLIANCE",
                                 "SERVICE_MESH")

FILTER_ACTIONS: dict[str, str] = {"ALLOW": "ALLOW", "PERMIT": "ALLOW", "ACCEPT": "ALLOW",
                                  "DENY": "DENY", "DROP": "DENY", "REJECT": "DENY",
                                  "BLOCK": "DENY"}

RATE_SCOPES: tuple[str, ...] = ("CLIENT", "IP", "KEY", "TENANT", "GLOBAL")

RATE_ACTIONS: dict[str, str] = {"REJECT": "REJECT", "429": "REJECT", "SEND_429": "REJECT",
                                "DROP": "DROP", "SHAPE": "SHAPE", "LOG_ONLY": "LOG_ONLY"}

#: methods a scanner may send without being told twice. Everything else can change state,
#: and a bank's gateway is not a test bed.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def _sensor_row(row: Mapping[str, Any]) -> dict[str, Any]:
    attributes = row.get("attributes") or {}
    return {"name": row["name"], "kind": row["kind"],
            "mode": attributes.get("mode"), "blocking": bool(attributes.get("blocking")),
            "fail_open": bool(attributes.get("fail_open")),
            "inspects": list(attributes.get("inspects") or [])}


def intrusion_sensor(*, name: Any, kind: Any = "IDS", mode: Any = "INLINE",
                     segments: Iterable[Any] = (), endpoints: Iterable[Any] = (),
                     forwards_to: Any = None, fail_open: Any = False, blocks: Any = None,
                     engine: Any = None, inspection: Iterable[Any] = ("HEADERS", "PAYLOAD"),
                     environment: Any = "PRODUCTION", evidence_ids: Iterable[Any] | None = None,
                     basis: Any = "config-parse", **attributes: Any) -> dict[str, Any]:
    """An IDS or an IPS, with the deployment that decides whether it can stop anything.

    The single most expensive mistake in this area is a diagram that puts an IDS on the
    path. The model refuses it three ways: an off-path sensor may not be ``blocking``
    (``SENSOR_CANNOT_BLOCK_OFF_PATH``), an IDS may never block (``IDS_CANNOT_BLOCK``), and
    an inline sensor with nothing behind it is an outage, not a control
    (``INLINE_WITHOUT_DOWNSTREAM``). An IPS deployed as a tap is *allowed* — it is a real
    and common misconfiguration — and reported by :func:`inspection_gap` as
    ``IPS_NOT_INLINE`` instead of being quietly drawn as protection.
    """
    kind_text = str(kind or "").strip().upper()
    if kind_text not in SENSOR_KINDS:
        raise tb.ClaimRefused(
            "NOT_A_SENSOR",
            f"{kind_text or '(none)'} is not an intrusion sensor; a firewall filters, a WAF "
            "terminates, and only an IDS or an IPS inspect for intrusions")
    mode_text = SENSOR_MODES.get(str(mode or "").strip().upper())
    if not mode_text:
        raise tb.ClaimRefused(
            "UNKNOWN_SENSOR_MODE",
            f"{mode or '(none)'} is not a deployment mode; a sensor is either in the path "
            "or it sees a copy of it")
    blocking = (kind_text == "IPS" and mode_text in IN_PATH_MODES) if blocks is None \
        else bool(blocks)
    if blocking and mode_text not in IN_PATH_MODES:
        raise tb.ClaimRefused(
            "SENSOR_CANNOT_BLOCK_OFF_PATH",
            f"{name} is deployed {mode_text}: it inspects a copy of the traffic and cannot "
            "drop a packet it never carried")
    if kind_text == "IDS" and blocking:
        raise tb.ClaimRefused(
            "IDS_CANNOT_BLOCK",
            f"{name} is an IDS: it alerts, and dropping a packet is an IPS or a firewall's "
            "job — an IDS that claims to block is a false sense of control")
    if mode_text in IN_PATH_MODES and not forwards_to:
        raise tb.ClaimRefused(
            "INLINE_WITHOUT_DOWNSTREAM",
            f"{name} is inline with nothing behind it; a control in the path that forwards "
            "nowhere is an outage")
    watch = [str(value) for value in [*(segments or ()), *(endpoints or ())]]
    sensor = tb.asset(kind_text, name, environment=environment, evidence_ids=evidence_ids,
                      mode=mode_text, blocking=blocking, fail_open=bool(fail_open),
                      engine=engine, inspects=watch,
                      inspection=[str(value).upper() for value in inspection], **attributes)
    claims: list[dict[str, Any]] = [
        tb.claim(name, "INSPECTS", target, basis=basis, evidence_ids=evidence_ids)
        for target in watch]
    if forwards_to:
        claims.append(tb.claim(name, "FORWARDS_TO", str(forwards_to), basis=basis,
                               evidence_ids=evidence_ids, protocol="TCP"))
    if blocking:
        claims.extend(tb.claim(name, "PROTECTS", target, basis=basis,
                               evidence_ids=evidence_ids)
                      for target in watch)
    return part(sensor, claims=claims)


def filters(*, firewall_row: Mapping[str, Any], default_action: Any = "DENY",
            rules: Iterable[Mapping[str, Any]] = (), logged: Any = True,
            evidence_ids: Iterable[Any] | None = None, **attributes: Any) -> dict[str, Any]:
    """A firewall's rule set, as configuration — evaluated in order, first match wins.

    A rule that names no port is refused (``RULE_WITHOUT_SERVICE``): "allow the payments
    subnet" is a sentence, and a rule that does not say which service is not one.
    """
    action = FILTER_ACTIONS.get(str(default_action or "").strip().upper())
    if not action:
        raise tb.ClaimRefused(
            "UNKNOWN_FILTER_ACTION",
            f"{default_action or '(none)'} is not a filter action; a policy either allows "
            "or denies by default")
    normalised: list[dict[str, Any]] = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, Mapping):
            raise tb.ClaimRefused("MALFORMED_RULE", f"rule {index} is not a mapping")
        rule_action = FILTER_ACTIONS.get(str(rule.get("action") or "").strip().upper())
        if not rule_action:
            raise tb.ClaimRefused(
                "UNKNOWN_FILTER_ACTION",
                f"rule {index}: {rule.get('action') or '(none)'} is not a filter action")
        port = rule.get("port") if rule.get("port") is not None else rule.get("service")
        if port is None:
            raise tb.ClaimRefused(
                "RULE_WITHOUT_SERVICE",
                f"rule {index} names no port; a rule about nothing matches everything")
        normalised.append({
            "order": index, "action": rule_action,
            "direction": str(rule.get("direction") or "INBOUND").upper(),
            "source": str(rule.get("source") or "ANY"),
            "destination": str(rule.get("destination") or "ANY"),
            "port": port, "protocol": str(rule.get("protocol") or "TCP").upper(),
            "logged": bool(rule.get("logged", logged)),
        })
    row = dict(firewall_row)
    body = dict(row.get("attributes") or {})
    body["filter_policy"] = {"default_action": action, "rules": normalised,
                             "logged": bool(logged)}
    row["attributes"] = body
    row["evidence_ids"] = list(row.get("evidence_ids") or []) + [
        str(value) for value in (evidence_ids or [])]
    return row


def filter_verdict(bom: Mapping[str, Any], *, source: Any, target: Any, port: Any = None,
                   protocol: Any = "TCP") -> dict[str, Any]:
    """Would the configured policy let this flow through? Configuration, never a packet.

    The answer is deliberately one class below an observation: a rule that matches is
    ``CONFIGURED``, and a packet that was refused is ``NETWORK_OBSERVED``. Claiming the
    second from the first is how a firewall review ends up meaningless.
    """
    host = str(target)
    wanted = None if port is None else str(port)
    for row in bom.get("assets") or []:
        if row["kind"] not in ("FIREWALL", "SECURITY_APPLIANCE", "WAF", "IPS"):
            continue
        policy = (row["attributes"] or {}).get("filter_policy") or {}
        if not policy:
            continue
        for rule in policy.get("rules") or []:
            if not _destination_matches(str(rule.get("destination") or "ANY"), host):
                continue
            if wanted is not None and str(rule.get("port")) not in ("ANY", wanted):
                continue
            if rule.get("direction") not in (None, "INBOUND", "BOTH"):
                continue
            return {
                "decision": rule["action"], "firewall": row["name"],
                "matched_rule": rule.get("order"), "rule": rule,
                "source": str(source), "target": host, "port": _port_value(wanted),
                "confidence": "CONFIGURED",
                "statement": (f"{row['name']} rule {rule.get('order')} "
                              f"{'allows' if rule['action'] == 'ALLOW' else 'denies'} "
                              f"{str(protocol).upper()}:{wanted or 'any'} to {host} — a "
                              "matching rule, not an observed packet"),
                "not_proven": ["that the packet was refused: a rule that matches is a "
                               "policy, and only a capture or a probe says what happened"],
            }
        return {
            "decision": policy.get("default_action") or "DENY", "firewall": row["name"],
            "matched_rule": None, "source": str(source), "target": host,
            "port": _port_value(wanted), "confidence": "CONFIGURED",
            "statement": (f"no rule matched; {row['name']} falls to its default "
                          f"{str(policy.get('default_action')).lower()}"),
            "not_proven": ["that the default was exercised: an unmatched flow is a "
                           "configuration path, not a measurement"],
        }
    raise tb.ClaimRefused(
        "NO_FILTER_POLICY",
        f"no firewall policy was read for {host}; an unread rule set is not an open one, "
        "and it is not a closed one either")


def _destination_matches(destination: str, host: str) -> bool:
    """``10.0.2.5`` matches ``app:8443`` when that is the address the name resolves to."""
    if destination in ("ANY", "*"):
        return True
    if destination.startswith("*."):
        return host.lower().endswith(destination[1:].lower())
    address = host.split(":")[0].lower()
    return destination.lower() in (host.lower(), address)


def _port_value(value: Any) -> Any:
    """``'443'`` and ``443`` are the same port; keeping them apart invents findings."""
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def rate_limit(*, name: Any, enforcer_row: Mapping[str, Any], limit: Any,
               window_seconds: Any = 1, scope: Any = "CLIENT", burst: Any = None,
               on_exceed: Any = "REJECT", fail_open: Any = False,
               observed: Mapping[str, Any] | None = None, targets: Iterable[Any] = (),
               evidence_ids: Iterable[Any] | None = None, basis: Any = "config-parse",
               **attributes: Any) -> dict[str, Any]:
    """A rate limit as a policy node: what is limited, how, and what happens at the edge.

    A limit is a *number and a behaviour*, and the behaviour is where they fail: a policy
    that is configured to reject but deployed ``fail_open``, or set to ``LOG_ONLY``, is a
    limit on paper. Both are findings in :func:`rate_limit_gap`, not refusals here — the
    configuration is legal and wrong, which is exactly what a review is for.
    """
    try:
        limit_value = int(limit)
        window_value = int(window_seconds)
    except (TypeError, ValueError) as exc:
        raise tb.ClaimRefused(
            "INVALID_RATE_LIMIT",
            f"{limit!r}/{window_seconds!r} is not a rate; a limit is a count over a window"
        ) from exc
    if limit_value <= 0 or window_value <= 0:
        raise tb.ClaimRefused(
            "INVALID_RATE_LIMIT",
            f"{limit_value} request(s) per {window_value}s cannot be enforced; a limit of "
            "zero is an outage and a window of zero is a division")
    scope_text = str(scope or "").strip().upper()
    if scope_text not in RATE_SCOPES:
        raise tb.ClaimRefused(
            "UNKNOWN_RATE_SCOPE",
            f"{scope or '(none)'} is not a scope; a limit applies to a client, an address, "
            "a key, a tenant, or everyone")
    action_text = RATE_ACTIONS.get(str(on_exceed or "").strip().upper())
    if not action_text:
        raise tb.ClaimRefused(
            "UNKNOWN_RATE_ACTION",
            f"{on_exceed or '(none)'} is not something a limiter can do at the edge")
    policy = tb.asset("RATE_LIMIT", name, evidence_ids=evidence_ids,
                      limit=limit_value, window_seconds=window_value, scope=scope_text,
                      burst=burst, on_exceed=action_text, fail_open=bool(fail_open),
                      applies_to=[str(value) for value in targets],
                      observed=dict(observed or {}), **attributes)
    claims = [tb.claim(enforcer_row["name"], "ENFORCES", name, basis=basis,
                       evidence_ids=evidence_ids)]
    claims.extend(tb.claim(name, "LIMITS", str(target), basis=basis,
                           evidence_ids=evidence_ids) for target in targets)
    return part(enforcer_row, policy, claims=claims)


def rate_limit_gap(bom: Mapping[str, Any]) -> dict[str, Any]:
    """Every way a configured limit fails to be a limit, measured rather than asserted."""
    findings: list[dict[str, Any]] = []
    policies = {row["name"]: row for row in bom.get("assets") or []
                if row["kind"] == "RATE_LIMIT"}
    enforced_by: dict[str, list[str]] = {}
    limited: dict[str, list[str]] = {}
    for claim in bom.get("claims") or []:
        if claim["relation"] == "ENFORCES":
            enforced_by.setdefault(claim["to"], []).append(claim["from"])
        elif claim["relation"] == "LIMITS":
            limited.setdefault(claim["to"], []).append(claim["from"])
    for name, row in sorted(policies.items()):
        attributes = row["attributes"] or {}
        limit = _port_value(attributes.get("limit"))
        observed = attributes.get("observed") or {}
        if attributes.get("fail_open"):
            findings.append({"code": "LIMIT_FAIL_OPEN", "policy": name,
                             "reason": "when the limiter cannot decide, traffic passes"})
        if str(attributes.get("on_exceed")) == "LOG_ONLY":
            findings.append({"code": "LIMIT_LOG_ONLY", "policy": name,
                             "reason": "the count is recorded and nothing is refused"})
        if not enforced_by.get(name):
            findings.append({"code": "LIMIT_ENFORCER_MISSING", "policy": name,
                             "reason": "a policy nobody enforces is a document"})
        rate = observed.get("rate")
        rejected = observed.get("rejected")
        if rate is not None and rejected is not None and limit is not None:
            if float(rate) > float(limit) and int(rejected) == 0:
                findings.append({"code": "LIMIT_NOT_ENFORCED", "policy": name,
                                 "observed_rate": rate, "limit": limit,
                                 "reason": "traffic above the limit was never refused"})
    for endpoint in [row for row in bom.get("assets") or []
                     if row["kind"] == "NETWORK_ENDPOINT"]:
        covered = limited.get(endpoint["name"]) or [
            name for name, targets in limited.items() if endpoint["name"] in targets]
        if covered:
            continue
        enforcers = [claim["from"] for claim in bom.get("claims") or []
                     if claim["relation"] in ("FORWARDS_TO", "ROUTES_TO", "FRONTED_BY")
                     and claim["to"] == endpoint["name"]]
        if enforcers:
            findings.append({"code": "NO_LIMIT_RECORDED", "endpoint": endpoint["name"],
                             "enforcer": sorted(set(enforcers)),
                             "reason": "the endpoint is reachable through a device and no "
                                       "limit was read for it"})
    return {
        "findings": findings,
        "counts": {code: sum(1 for row in findings if row["code"] == code)
                   for code in sorted({row["code"] for row in findings})},
        "statement": (f"{len(findings)} rate-limit finding(s) on {len(policies)} policy "
                      "row(s): "
                      + (", ".join(sorted({row["code"] for row in findings})) or "none")),
        "not_proven": ["that a limit protected anything: a configured limit is "
                       "CONFIGURED, and only a rejected request is NETWORK_OBSERVED"],
    }


def inspection_gap(bom: Mapping[str, Any], *, source: Any, target: Any = None,
                   max_hops: int = 8) -> dict[str, Any]:
    """Which routes actually cross a control that can stop something.

    For every evidenced route out of ``source`` the answer is one of three, and they are
    not interchangeable: ``INSPECTED_INLINE`` (a blocking control is on the route),
    ``TAP_ONLY`` (a sensor watches a node on it, from off the path), or ``NOT_INSPECTED``
    (nothing evidenced sees it at all). An inline control deployed ``fail_open`` is
    ``FAIL_OPEN_INLINE``: present, and passing traffic when it fails.
    """
    walk = paths(bom, source=source, target=target, max_hops=max_hops)
    controls = {row["name"]: row for row in bom.get("assets") or []
                if row["kind"] in CONTROL_KINDS}
    taps: dict[str, list[str]] = {}
    for claim in bom.get("claims") or []:
        if claim["relation"] != "INSPECTS":
            continue
        sensor = controls.get(claim["from"])
        if sensor and str((sensor["attributes"] or {}).get("mode")) in ("TAP", "SPAN"):
            taps.setdefault(claim["to"], []).append(claim["from"])
    rows: list[dict[str, Any]] = []
    for route in walk["routes"]:
        on_path = [name for name in route["nodes"]
                   if name in controls and (controls[name]["attributes"] or {}).get("mode")
                   in IN_PATH_MODES]
        blocking = [name for name in on_path
                    if (controls[name]["attributes"] or {}).get("blocking")]
        fail_open = [name for name in on_path
                     if (controls[name]["attributes"] or {}).get("fail_open")]
        off_path = sorted({sensor for name in route["nodes"]
                           for sensor in taps.get(name, [])})
        codes: list[str] = []
        if blocking and fail_open:
            codes.append("FAIL_OPEN_INLINE")
        elif blocking:
            codes.append("INSPECTED_INLINE")
        elif off_path:
            codes.append("TAP_ONLY")
        else:
            codes.append("NOT_INSPECTED")
        rows.append({**route, "inline": on_path, "blocking": blocking,
                     "fail_open": fail_open, "tap_only": off_path,
                     "codes": codes,
                     "inspected": bool(blocking) and not fail_open})
    bypass = [row for row in rows if not row["inspected"]]
    sensor_findings: list[dict[str, Any]] = []
    for name, row in sorted(controls.items()):
        attributes = row["attributes"] or {}
        mode = str(attributes.get("mode") or "")
        if row["kind"] == "IPS" and mode not in IN_PATH_MODES:
            sensor_findings.append({
                "code": "IPS_NOT_INLINE", "sensor": name, "mode": mode,
                "reason": "an IPS deployed off the path detects and never blocks; the "
                          "prevention it was bought for is not deployed"})
        if attributes.get("blocking") and attributes.get("fail_open"):
            sensor_findings.append({
                "code": "FAIL_OPEN_SENSOR", "sensor": name,
                "reason": "when the sensor fails, the traffic it was stopping passes"})
    return {
        "source": walk["source"], "target": str(target) if target is not None else None,
        "routes": rows,
        "inspected": sum(1 for row in rows if row["inspected"]),
        "bypass": [row["path"] for row in bypass],
        "sensor_findings": sensor_findings,
        "codes": {code: sum(1 for row in rows if code in row["codes"])
                  for code in sorted({code for row in rows for code in row["codes"]})},
        "statement": (f"{len(rows)} route(s) from {walk['source']['name']}: "
                      f"{sum(1 for row in rows if row['inspected'])} cross a control that "
                      f"can block, {len(bypass)} do not"),
        "not_proven": ["that the control would have matched: an inline sensor on the path "
                       "is where the traffic goes, not a rule that fires",
                       "that a tap sees this route's traffic: a tap is evidenced against a "
                       "node, and what it captured is the capture's claim, not this one"],
    }


# --------------------------------------------------------------------------- #
# Request sending: a budget, an allowlist, and a record of every request not sent
# --------------------------------------------------------------------------- #

def _allowlist_entry(entry: Any) -> dict[str, Any]:
    text = str(entry or "").strip()
    if not text:
        raise tb.ClaimRefused("ALLOWLIST_INVALID", "an empty allowlist entry allows nothing")
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise tb.ClaimRefused(
                "ALLOWLIST_INVALID",
                f"{text} looks like a CIDR range and is not one; an allowlist that does not "
                "parse is a scan of the internet") from exc
        return {"kind": "CIDR", "value": text, "network": network}
    if text.startswith("*."):
        if len(text) <= 2:
            raise tb.ClaimRefused("ALLOWLIST_INVALID",
                                  f"{text} is a wildcard with no domain under it")
        return {"kind": "SUFFIX", "value": text, "suffix": text[1:].lower()}
    host, _, port_text = text.partition(":")
    if port_text and not port_text.isdigit():
        raise tb.ClaimRefused("ALLOWLIST_INVALID", f"{text}: {port_text} is not a port")
    return {"kind": "HOST", "value": text, "host": host.lower(),
            "port": int(port_text) if port_text else None}


def _parse_target(target: Any) -> dict[str, Any]:
    if isinstance(target, Mapping):
        host = str(target.get("host") or "").strip()
        port = target.get("port")
    else:
        text = str(target or "").strip()
        host, _, port_text = text.partition(":")
        port = int(port_text) if port_text.isdigit() else None
    if not host:
        raise tb.ClaimRefused("TARGET_WITHOUT_HOST", "a request needs a host")
    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    return {"host": host.lower(), "port": port, "address": address,
            "name": f"{host}:{port}" if port else host}


def _allowlisted(entry: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    if entry["kind"] == "CIDR":
        return target["address"] is not None and target["address"] in entry["network"]
    if entry["kind"] == "SUFFIX":
        if target["address"] is not None:
            return False
        host = f".{target['host']}"
        return host.endswith(entry["suffix"])
    if entry["host"] != target["host"]:
        if not (target["address"] is not None and entry["host"] == str(target["address"])):
            return False
    return entry["port"] in (None, target["port"])


def probe_policy(*, allowlist: Iterable[Any] = (), max_requests_per_target: Any = 50,
                 max_concurrency: Any = 4, min_interval_ms: Any = 200,
                 stop_after_errors: Any = 3, allow_unsafe_methods: Any = False,
                 dry_run: Any = False, collector: Any = "probe-gate",
                 collector_version: Any = "1.0.0") -> dict[str, Any]:
    """What a scanner is allowed to send, before it sends anything.

    An empty allowlist is refused (``EMPTY_ALLOWLIST``): "scan whatever resolves" is not a
    policy, it is an incident. The budget, the concurrency and the backoff are part of the
    same object because a limit that can be raised by the caller is a suggestion.
    """
    entries = [_allowlist_entry(entry) for entry in (allowlist or ())]
    if not entries:
        raise tb.ClaimRefused(
            "EMPTY_ALLOWLIST",
            "a probe with no allowlist is a scan of the internet; the targets are named "
            "before the first packet")
    numbers: dict[str, int] = {}
    for field, value in (("max_requests_per_target", max_requests_per_target),
                         ("max_concurrency", max_concurrency),
                         ("min_interval_ms", min_interval_ms),
                         ("stop_after_errors", stop_after_errors)):
        try:
            numbers[field] = int(value)
        except (TypeError, ValueError) as exc:
            raise tb.ClaimRefused("INVALID_PROBE_BUDGET",
                                  f"{field}={value!r} is not a number") from exc
        if numbers[field] < 0:
            raise tb.ClaimRefused("INVALID_PROBE_BUDGET",
                                  f"{field} cannot be negative")
    if numbers["max_requests_per_target"] == 0 or numbers["max_concurrency"] == 0:
        raise tb.ClaimRefused(
            "INVALID_PROBE_BUDGET",
            "a budget of zero and a concurrency of zero cannot send the one request a "
            "probe is for")
    return {
        "allowlist": [{"kind": entry["kind"], "value": entry["value"],
                       "port": entry.get("port")} for entry in entries],
        "_entries": entries,
        "max_requests_per_target": numbers["max_requests_per_target"],
        "max_concurrency": numbers["max_concurrency"],
        "min_interval_ms": numbers["min_interval_ms"],
        "stop_after_errors": numbers["stop_after_errors"],
        "allow_unsafe_methods": bool(allow_unsafe_methods),
        "dry_run": bool(dry_run),
        "collector": str(collector), "collector_version": str(collector_version),
    }


def probe_gate(policy: Mapping[str, Any], *, target: Any, method: Any = "GET",
               sent: Any = 0, in_flight: Any = 0, recent_errors: Any = 0,
               last_sent_at: Any = None, now: Any = None) -> dict[str, Any]:
    """One decision per request: send it, or refuse it and say why.

    The order is deliberate — *may we touch this target at all* comes before *do we have
    budget*, because a budget is not permission. The refusal codes are the product: a
    scanner that silently declines to probe a segment is indistinguishable from one that
    found nothing there.
    """
    target_row = _parse_target(target)
    entries = policy.get("_entries") or [_allowlist_entry(row["value"])
                                         for row in policy.get("allowlist") or []]

    def decision(code: str, reason: str, **extra: Any) -> dict[str, Any]:
        return {"decision": "SEND" if code == "SEND" else "REFUSE", "code": code,
                "target": target_row["name"], "method": str(method).upper(),
                "reason": reason, **extra}

    if str(method).upper() not in SAFE_METHODS and not policy.get("allow_unsafe_methods"):
        return decision("METHOD_NOT_SAFE",
                        f"{str(method).upper()} can change state; a probe is not a "
                        "transaction")
    if not any(_allowlisted(entry, target_row) for entry in entries):
        return decision("TARGET_NOT_ALLOWED",
                        f"{target_row['name']} is not in the allowlist; nothing is probed "
                        "off-list, however interesting it looks")
    if int(sent) >= int(policy.get("max_requests_per_target") or 0):
        return decision("BUDGET_EXHAUSTED",
                        f"{int(sent)} request(s) already sent to {target_row['name']}; the "
                        "budget is a stop, not a target")
    if int(in_flight) >= int(policy.get("max_concurrency") or 0):
        return decision("CONCURRENCY_EXHAUSTED",
                        f"{int(in_flight)} request(s) in flight; a scanner that opens "
                        "everything at once is a load test")
    if int(recent_errors) >= int(policy.get("stop_after_errors") or 0):
        return decision("BACKOFF_REQUIRED",
                        f"{int(recent_errors)} consecutive error(s); the target is having a "
                        "worse day than the scan")
    if last_sent_at is not None and now is not None:
        elapsed_ms = (float(now) - float(last_sent_at)) * 1000
        if elapsed_ms < float(policy.get("min_interval_ms") or 0):
            return decision("INTERVAL_NOT_ELAPSED",
                            f"{elapsed_ms:.0f}ms since the last request; the floor is "
                            f"{policy.get('min_interval_ms')}ms")
    if policy.get("dry_run"):
        return decision("DRY_RUN", "the policy is in dry-run: the decision is recorded and "
                                   "nothing is sent")
    return decision("SEND", f"{target_row['name']} is allowlisted and within budget")


def probe_ledger(decisions: Iterable[Mapping[str, Any]], *,
                 collector: Any = "probe-gate", collector_version: Any = "1.0.0",
                 evidence_prefix: Any = "EVID-PROBE",
                 observed_at: Any = None) -> dict[str, Any]:
    """Every decision as an evidence record — including, and especially, the refusals.

    A sent request is ``NETWORK_OBSERVED``; a refused one is ``CONFIGURED``, because a
    decision is not an observation. Both get a collector and a hash, so "we did not probe
    that segment" is a checkable fact rather than an omission.
    """
    records: list[dict[str, Any]] = []
    by_code: dict[str, int] = {}
    for index, decision in enumerate(decisions, start=1):
        code = str(decision.get("code") or "UNKNOWN")
        by_code[code] = by_code.get(code, 0) + 1
        digest = hashlib.sha256(
            json.dumps(decision, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        records.append(evidence_record(
            f"{evidence_prefix}-{index:03d}", collector=collector,
            collector_version=collector_version, target_id=decision.get("target"),
            observed_at=observed_at,
            evidence_type="NETWORK_OBSERVED" if code == "SEND" else "CONFIGURED",
            source=str(decision.get("decision") or "REFUSE"),
            normalized_fact=f"{code} {decision.get('method')} {decision.get('target')}",
            raw_reference=str(decision.get("reason")), hash=f"sha256:{digest[:16]}"))
    sent = by_code.get("SEND", 0)
    refused = len(records) - sent
    reasons = ", ".join(f"{code} {count}" for code, count in sorted(by_code.items())
                        if code != "SEND")
    return {
        "records": records,
        "sent": sent, "refused": refused, "by_code": dict(sorted(by_code.items())),
        "statement": (f"{len(records)} decision(s): {sent} sent, {refused} refused"
                      + (f" ({reasons})" if reasons else "")),
        "not_proven": ["that a sent request reached the service: the record says it was "
                       "allowed, and the response is a separate observation"],
    }


# --------------------------------------------------------------------------- #
# The dependencies under the ones already drawn
# --------------------------------------------------------------------------- #

#: a named certificate on a listener is a fact; without an edge it is a dangling string.
#: The review asks for the chain to be *reached* from the endpoint, not merely stored.
CERTIFICATE_LINK: tuple[str, ...] = ("PRESENTS", "USES_CERTIFICATE")

#: a chain that ends in an intermediate has been parsed, not validated.
PUBLIC_SUFFIX_MARKERS: tuple[str, ...] = ("ROOT", "SELF_SIGNED")

#: below these a key is not "legacy", it is broken. Refused by the numbers rather than
#: described as "weak" and left to the reader.
MINIMUM_KEY_SIZE: dict[str, int] = {"RSA": 2048, "DSA": 2048, "DH": 2048, "ECDSA": 256,
                                    "EDDSA": 256}

WEAK_CURVES: frozenset[str] = frozenset({"P-192", "SECP192R1", "P-224", "SECP224R1"})

WEAK_SIGNATURES: tuple[str, ...] = ("MD2", "MD4", "MD5", "SHA1", "SHA-1")

#: the operations a bank's key inventory is actually about
CRYPTO_OPERATIONS: tuple[str, ...] = ("SIGN", "VERIFY", "ENCRYPT", "DECRYPT", "WRAP",
                                      "UNWRAP", "DERIVE", "MAC", "RANDOM", "HASH",
                                      "GENERATE_KEY")


def presents_certificate(*, endpoint_row: Mapping[str, Any],
                         certificate_row: Mapping[str, Any],
                         basis: Any = "tls-handshake", evidence_ids: Iterable[Any] | None = None,
                         **facts: Any) -> dict[str, Any]:
    """``endpoint → PRESENTS → certificate``: the edge the listener's configuration implies.

    A listener that names ``certificate: CERT-001`` and draws no edge is a dangling
    reference, and a graph full of them is a certificate inventory with a picture on top.
    """
    if endpoint_row.get("kind") not in ("NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY",
                                        "WAF", "SERVICE_MESH", "DATABASE"):
        raise tb.ClaimRefused(
            "NOT_A_TLS_PRESENTER",
            f"{endpoint_row.get('kind')} does not present a certificate; a listener, a "
            "gateway or a terminator does")
    return part(endpoint_row, certificate_row,
                claims=[tb.claim(endpoint_row["name"], "PRESENTS", certificate_row["name"],
                                 basis=basis, evidence_ids=evidence_ids, **facts)])


def certificate_depth(bom: Mapping[str, Any], *, query: Any,
                      max_depth: int = 8) -> dict[str, Any]:
    """Every certificate an endpoint presents, walked to the weakest link.

    ``endpoint → certificate → public key → algorithm → signature algorithm → issuer →
    root`` is five questions with five answers, and the answer a review needs is which of
    them is the weak one. An endpoint that names a certificate the estate does not hold is
    reported as ``CERTIFICATE_UNRESOLVED`` rather than silently skipped: the reference is
    real, the object behind it is missing.
    """
    keys = _endpoint_keys(bom, query)
    findings: list[dict[str, Any]] = []
    certificates: list[dict[str, Any]] = []
    for key in sorted(keys):
        row = bom["by_key"][key]
        named = str((row["attributes"].get("tls") or {}).get("certificate") or "")
        links = [claim for claim in bom["claims"]
                 if claim["from_key"] == key and claim["relation"] in CERTIFICATE_LINK]
        if not links and named:
            findings.append({"code": "CERTIFICATE_UNRESOLVED", "endpoint": row["name"],
                             "certificate": named,
                             "reason": "the listener names a certificate and no edge "
                                       "reaches it; the reference is real and the object "
                                       "is missing"})
            continue
        for link in links:
            certificates.append(_certificate_walk(bom, link["to_key"], findings))
    chain_complete = [row for row in certificates if row["rooted"]]
    return {
        "query": str(query),
        "certificates": certificates,
        "findings": findings,
        "counts": {code: sum(1 for row in findings if row["code"] == code)
                   for code in sorted({row["code"] for row in findings})},
        "rooted": len(chain_complete),
        "statement": (f"{len(certificates)} certificate(s) presented on {len(keys)} "
                      f"endpoint(s); {len(chain_complete)} reach a root, "
                      f"{len(findings)} finding(s): "
                      + (", ".join(sorted({row["code"] for row in findings})) or "none")),
        "not_proven": ["that the certificate is currently served: the chain is what the "
                       "estate holds and what the handshake presented, and revocation is "
                       "a separate question",
                       "that a weak algorithm is exploitable: this names the link and the "
                       "size, and the risk judgement belongs to the assurance engine"],
    }


def _certificate_walk(bom: Mapping[str, Any], cert_key: str,
                      findings: list[dict[str, Any]]) -> dict[str, Any]:
    certificate = bom["by_key"][cert_key]
    chain: list[dict[str, Any]] = [_link_row(bom, certificate, "delivers")]
    seen: set[str] = {cert_key}
    frontier = [cert_key]
    stage = 0
    rooted = False
    while frontier and stage < 8:
        stage += 1
        following: list[str] = []
        for key in frontier:
            for claim in bom["claims"]:
                if claim["from_key"] != key:
                    continue
                if claim["relation"] not in ("CONTAINS_KEY", "USES_ALGORITHM", "SIGNED_WITH",
                                             "ISSUED_BY", "SIGNED_BY", "USES_CERTIFICATE"):
                    continue
                if claim["to_key"] in seen:
                    continue
                seen.add(claim["to_key"])
                node = bom["by_key"][claim["to_key"]]
                chain.append(_link_row(bom, node, claim["relation"], claim["confidence"]))
                if node["kind"] == "CERTIFICATE_AUTHORITY" and \
                        str((node["attributes"] or {}).get("ca_kind")) in \
                        PUBLIC_SUFFIX_MARKERS:
                    rooted = True
                following.append(claim["to_key"])
        frontier = following

    for row in chain:
        attributes = row["attributes"]
        if row["kind"] == "ALGORITHM":
            name = str(row["name"]).upper()
            if any(token in name for token in WEAK_SIGNATURES):
                findings.append({
                    "code": "WEAK_SIGNATURE", "certificate": certificate["name"],
                    "algorithm": row["name"],
                    "reason": "the certificate is signed with a broken hash"})
            family = str(attributes.get("family") or "").upper()
            minimum = MINIMUM_KEY_SIZE.get(family)
            size = attributes.get("key_size")
            curve = str(attributes.get("curve") or "").upper()
            if minimum and isinstance(size, int) and size < minimum:
                findings.append({
                    "code": "WEAK_KEY", "certificate": certificate["name"],
                    "algorithm": row["name"], "key_size": size, "minimum": minimum,
                    "reason": f"{size} bits is below the {minimum}-bit floor for {family}"})
            elif curve in WEAK_CURVES:
                findings.append({
                    "code": "WEAK_KEY", "certificate": certificate["name"],
                    "algorithm": row["name"], "curve": row["attributes"].get("curve"),
                    "reason": "the curve is below the 256-bit floor"})
    if not rooted:
        findings.append({
            "code": "CHAIN_NOT_ROOTED", "certificate": certificate["name"],
            "reason": "the chain ends at an intermediate; a chain that never reaches a "
                      "root authority is a parsed file, not a trust path"})
    return {
        "certificate": {"name": certificate["name"], "id": certificate.get("id"),
                        "subject": (certificate["attributes"] or {}).get("subject"),
                        "serial": (certificate["attributes"] or {}).get("serial")},
        "links": chain, "rooted": rooted, "depth": len(chain),
        "weakest": next((row for row in chain if row["kind"] == "ALGORITHM"), None),
    }


def _link_row(bom: Mapping[str, Any], node: Mapping[str, Any], relation: str,
              confidence: Any = "CONFIGURED") -> dict[str, Any]:
    return {"relation": relation, "kind": node["kind"], "name": node["name"],
            "id": node.get("id"), "confidence": str(confidence).upper(),
            "attributes": dict(node.get("attributes") or {})}


def crypto_operation(*, name: Any, application_row: Mapping[str, Any],
                     operation: Any, key_row: Mapping[str, Any] | None = None,
                     provider_row: Mapping[str, Any] | None = None,
                     algorithm_row: Mapping[str, Any] | None = None,
                     purpose: Any = None, basis: Any = "api-poll",
                     evidence_ids: Iterable[Any] | None = None,
                     **metadata: Any) -> dict[str, Any]:
    """``application → INVOKES → operation → key / provider / algorithm``.

    The review's point 8 is a level, not a verb: *who asked for RSA signing, on which key,
    and did the HSM do it or the application?* A key reference and an operation are both
    metadata; no key material is accepted here, at all.
    """
    operation_text = str(operation or "").strip().upper()
    if operation_text not in CRYPTO_OPERATIONS:
        raise tb.ClaimRefused(
            "UNKNOWN_CRYPTO_OPERATION",
            f"{operation or '(none)'} is not a crypto operation this model names; "
            "'uses crypto' is not an operation")
    _forbid_key_material(dict(metadata), where=f"crypto operation {name}")
    if provider_row is not None and provider_row.get("kind") not in ("HSM", "KMS", "TPM"):
        raise tb.ClaimRefused(
            "NOT_A_KEY_PROVIDER",
            f"{provider_row.get('name')} ({provider_row.get('kind')}) is not a key "
            "provider; doing the operation in the application is a different claim")
    row = tb.asset("CRYPTO_OPERATION", name, operation=operation_text,
                   purpose=purpose, key_ref=key_row["name"] if key_row else None,
                   provider=provider_row["name"] if provider_row else None,
                   algorithm=algorithm_row["name"] if algorithm_row else None,
                   runs_in=str((provider_row or {}).get("kind") or "APPLICATION"),
                   evidence_ids=evidence_ids, **metadata)
    assets: list[Mapping[str, Any]] = [row, application_row]
    claims = [tb.claim(application_row["name"], "INVOKES", name, basis=basis,
                       evidence_ids=evidence_ids, operation=operation_text)]
    if key_row is not None:
        assets.append(key_row)
        claims.append(tb.claim(name, "USES_KEY", key_row["name"], basis=basis,
                               evidence_ids=evidence_ids, operation=operation_text))
    if provider_row is not None:
        assets.append(provider_row)
        claims.append(tb.claim(name, "USES_HSM", provider_row["name"], basis=basis,
                               evidence_ids=evidence_ids, operation=operation_text))
    if algorithm_row is not None:
        assets.append(algorithm_row)
        claims.append(tb.claim(name, "USES_ALGORITHM", algorithm_row["name"], basis=basis,
                               evidence_ids=evidence_ids, operation=operation_text))
    return part(*assets, claims=claims)


def operations(bom: Mapping[str, Any], *, query: Any = None) -> dict[str, Any]:
    """Every crypto operation, with the key it used and where it ran.

    The two findings that matter are the ones a key inventory exists to catch: an
    operation whose key is unnamed (so the key inventory is incomplete) and an operation
    performed in the application when an HSM was available (so the key is in the process).
    """
    # the filter is "operations this node invokes", so the query is a node, not a listener
    wanted = {_resolve_one(bom, query)} if query is not None else set()
    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for row in bom.get("assets") or []:
        if row["kind"] != "CRYPTO_OPERATION":
            continue
        incoming = [claim for claim in bom["claims"] if claim["to_key"] == row["key"]]
        applications = [bom["by_key"][claim["from_key"]]["name"] for claim in incoming
                        if claim["relation"] == "INVOKES"]
        if wanted and not any(claim["from_key"] in wanted for claim in incoming):
            continue
        outgoing = [claim for claim in bom["claims"] if claim["from_key"] == row["key"]]
        key = next((bom["by_key"][claim["to_key"]]["name"] for claim in outgoing
                    if claim["relation"] == "USES_KEY"), None)
        provider = next((bom["by_key"][claim["to_key"]]["name"] for claim in outgoing
                         if claim["relation"] == "USES_HSM"), None)
        algorithm = next((bom["by_key"][claim["to_key"]]["name"] for claim in outgoing
                          if claim["relation"] == "USES_ALGORITHM"), None)
        attributes = row["attributes"] or {}
        rows.append({"name": row["name"], "id": row.get("id"),
                     "operation": attributes.get("operation"),
                     "applications": sorted(set(applications)), "key": key,
                     "provider": provider, "algorithm": algorithm,
                     "runs_in": attributes.get("runs_in"),
                     "purpose": attributes.get("purpose")})
        if key is None:
            findings.append({"code": "OPERATION_WITHOUT_KEY", "operation": row["name"],
                             "reason": "the operation names no key, so the key inventory "
                                       "cannot be complete"})
        if provider is None:
            findings.append({"code": "OPERATION_WITHOUT_PROVIDER",
                             "operation": row["name"], "application": applications[0]
                             if applications else None,
                             "reason": "the operation runs in the application; the key it "
                                       "uses is in the process, not in the HSM"})
    return {
        "query": str(query) if query is not None else None,
        "operations": rows,
        "findings": findings,
        "counts": {code: sum(1 for row in findings if row["code"] == code)
                   for code in sorted({row["code"] for row in findings})},
        "statement": (f"{len(rows)} crypto operation(s), "
                      f"{sum(1 for row in rows if row['provider'])} in an HSM/KMS, "
                      f"{len(findings)} finding(s)"),
        "not_proven": ["that the key is the one that produced the signature: the "
                       "operation names a key reference, and the reference is metadata"],
    }


# --------------------------------------------------------------------------- #
# At rest and in transit: two dependencies, not one
# --------------------------------------------------------------------------- #

def database_crypto_gap(bom: Mapping[str, Any]) -> dict[str, Any]:
    """A database encrypted on the socket and in the clear on the disk.

    ``in_transit`` and ``at_rest`` are separate blocks in the estate and separate findings
    here, because collapsing them is how a report says "encrypted" about a database whose
    only encryption is the connection.
    """
    block = (bom.get("sections") or {}).get("database_crypto") or {}
    findings: list[dict[str, Any]] = []
    for name, row in sorted(block.items()):
        transit = dict(row.get("in_transit") or {})
        at_rest = dict(row.get("at_rest") or {})
        if not transit:
            findings.append({"code": "TLS_NOT_OBSERVED", "database": name,
                             "reason": "no TLS parameters were recorded on the database "
                                       "endpoint, so the wire is not evidenced"})
        if not at_rest:
            findings.append({"code": "TDE_NOT_RECORDED", "database": name,
                             "reason": "nothing was read about encryption at rest; a "
                                       "record is not the same as no encryption, and it "
                                       "is not the same as encryption either"})
        elif str(at_rest.get("enabled")).lower() in ("false", "no", "0", "off", "none"):
            findings.append({"code": "AT_REST_UNENCRYPTED", "database": name,
                             "in_transit": bool(transit),
                             "reason": "the database is encrypted in transit and not at "
                                       "rest — two different dependencies, one of them "
                                       "missing"})
        if transit and at_rest and transit.get("suite") == at_rest.get("algorithm"):
            findings.append({"code": "AT_REST_MIRRORS_TRANSIT", "database": name,
                             "algorithm": transit.get("suite"),
                             "reason": "the same algorithm on the wire and on the disk is "
                                       "one key decision applied twice, not two "
                                       "independent ones"})
    return {
        "databases": block,
        "findings": findings,
        "counts": {code: sum(1 for row in findings if row["code"] == code)
                   for code in sorted({row["code"] for row in findings})},
        "statement": (f"{len(block)} database(s) with a crypto record; "
                      f"{len(findings)} finding(s): "
                      + (", ".join(sorted({row['code'] for row in findings})) or "none")),
        "rule": "in transit and at rest are two dependencies: a TLS-only database is "
                "encrypted on the wire and readable on the disk",
    }


# --------------------------------------------------------------------------- #
# Coverage propagates, and never improves downstream
# --------------------------------------------------------------------------- #

#: a worse verdict can never be averaged away by a better one
SEVERITY: dict[str, int] = {"COMPLETE": 0, "PARTIAL": 1, "UNKNOWN": 2}


def propagate_coverage(coverage_block: Mapping[str, Any],
                       segments: Mapping[str, Mapping[str, Any]] | None = None,
                       consumers: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The network's coverage, inherited by every view that reads it.

    ``consumers`` is what each downstream view *claims*: ``COMPLETE``, ``PARTIAL`` or
    ``UNKNOWN``. The result is the worse of the two, always — a CBOM that says
    ``COMPLETE`` while 50 endpoints were unreachable is refused as
    ``COVERAGE_LAUNDERED``, because coverage is a denominator and a denominator cannot be
    improved by being re-told.
    """
    network = str(coverage_block.get("verdict") or "UNKNOWN").upper()
    if network not in SEVERITY:
        raise tb.ClaimRefused("UNKNOWN_COVERAGE_VERDICT",
                              f"{network} is not a coverage verdict")
    scope = {"network": network}
    if segments:
        segments = {name: (dict(row) if "verdict" in row else coverage(**row))
                    for name, row in segments.items()}
        weakest = max((str(row.get("verdict") or "UNKNOWN").upper()
                       for row in segments.values()), key=lambda name: SEVERITY[name],
                      default="COMPLETE")
        scope["segments"] = {name: str(row.get("verdict") or "UNKNOWN").upper()
                             for name, row in sorted(segments.items())}
        scope["weakest_segment"] = [name for name, row in sorted(segments.items())
                                    if str(row.get("verdict")).upper()
                                    == weakest][:1]
        if SEVERITY[weakest] > SEVERITY[network]:
            network = weakest
            scope["network"] = network
    downstream: dict[str, str] = {}
    findings: list[dict[str, Any]] = []
    for name, claimed in sorted((consumers or {}).items()):
        claim_text = str(claimed or "UNKNOWN").upper()
        if claim_text not in SEVERITY:
            raise tb.ClaimRefused("UNKNOWN_COVERAGE_VERDICT",
                                  f"{name} claims {claim_text}, which is not a verdict")
        if SEVERITY[claim_text] < SEVERITY[network]:
            findings.append({
                "code": "COVERAGE_LAUNDERED", "consumer": name, "claimed": claim_text,
                "inherited": network,
                "reason": f"{name} reports {claim_text} while the network it reads is "
                          f"{network}; coverage cannot improve downstream"})
        downstream[name] = max((claim_text, network), key=lambda value: SEVERITY[value])
    return {
        "network": network,
        "segments": scope.get("segments"),
        "weakest_segment": scope.get("weakest_segment"),
        "consumers": downstream,
        "findings": findings,
        "statement": (f"network coverage {network} propagates to "
                      + (", ".join(f"{name} {verdict}"
                                   for name, verdict in downstream.items()) or "no consumer")
                      + (f"; {len(findings)} laundered" if findings else "")),
        "rule": "a downstream view inherits the worse of its own claim and the network's "
                "coverage; unavailable is not absent, and it does not round up",
    }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _summary(row: Mapping[str, Any]) -> dict[str, Any]:
    attributes = dict(row.get("attributes") or {})
    return {
        "key": row["key"],
        "id": row.get("id"),
        "kind": row["kind"],
        "name": row["name"],
        "stable_id": stable_id(row),
        "environment": row.get("environment"),
        "version": row.get("version"),
        "attributes": attributes,
    }


def stable_id(row: Mapping[str, Any]) -> str:
    """``SERVICE-9281``: the readable id renumbers, this one does not."""
    digest = hashlib.sha256(str(row.get("key")).encode("utf-8")).hexdigest()
    number = int(digest[:8], 16) % 10000
    return f"{row['kind']}-{number:04d}"


def _endpoint_keys(bom: Mapping[str, Any], query: Any) -> set[str]:
    text = str(query or "").strip().lower()
    keys = {row["key"] for row in bom["assets"]
            if row["kind"] == "NETWORK_ENDPOINT" and
            (row["key"].lower() == text or row["id"].lower() == text
             or row["name"].lower() == text or stable_id(row).lower() == text)}
    if not keys:
        keys = {row["key"] for row in bom["assets"] if row["kind"] == "NETWORK_ENDPOINT"
                and text and text in row["name"].lower()}
    if not keys:
        raise tb.ClaimRefused("UNKNOWN_ENDPOINT",
                              f"{query} is not an endpoint in this projection")
    return keys


__all__ = [
    "SCHEMA", "NBOM_KINDS", "EDGE_FIELDS", "TLS_MODES", "LIFECYCLE", "ROUTING_BASES",
    "SPINE", "NOT_PROVEN", "KEY_MATERIAL_FIELDS", "KEY_MATERIAL_MARKERS",
    "part", "merge", "estate", "endpoint", "service_of", "routed", "serves",
    "tls_hop", "algorithm", "public_key", "certificate", "authority", "certificate_chain",
    "cipher_suite", "suite_parts", "negotiated", "supported", "negotiated_crypto",
    "runtime", "key_reference", "key_use", "database_dependency", "mesh", "tls_terminator",
    "ssh_service", "ipsec_tunnel", "network_device", "on_hardware", "edge_record", "graph",
    "dependency_chain", "lifecycle", "drift", "coverage", "build", "twin", "from_document",
    "stable_id",
]
