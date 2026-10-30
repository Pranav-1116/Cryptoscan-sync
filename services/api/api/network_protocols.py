"""Network protocol coverage — which protocols this build can actually read.

The protocol-aware model is the right shape, but "we read the network" is only
true one protocol at a time. TLS is the strongest path; SSH is real; IPsec is a
proposal reader; and several protocols a bank certainly runs (MQ, Oracle TNS,
LDAP, proprietary gateways, service-mesh control planes) have **no reader at
all** in this build.

This module states that per protocol, in the same shape as the surface registry
so a screen can render both without learning a second vocabulary:

``strength``
    how much a positive read proves:

    ``NEGOTIATED``      a completed handshake: what *this* connection agreed
    ``OFFERED``         what the peer offers/accepts before a session exists
    ``SESSION_CONFIG``  keys and policy read from a session's own record
    ``PASSIVE``         a sensor's report; no handshake was driven
    ``ABSENT``          no reader in this build

``producers`` / ``ingest_only`` are the same distinction as the runtime matrix:
a path the platform accepts data for is not a path it can collect.

``coverage`` is measured, not asserted: for each protocol the registry names the
inventory target classes that would have to carry it, and the measured half (in
the router) compares against what the estate's assets actually contain. A
protocol with no assets is ``NOT_OBSERVED`` — never 0% covered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from api.estate_surfaces import resolve_detector

SCHEMA = "cryptoscan.network-protocols/1"

NEGOTIATED = "NEGOTIATED"
OFFERED = "OFFERED"
SESSION_CONFIG = "SESSION_CONFIG"
PASSIVE = "PASSIVE"
ABSENT = "ABSENT"

STRENGTHS: tuple[str, ...] = (NEGOTIATED, OFFERED, SESSION_CONFIG, PASSIVE, ABSENT)

STRENGTH_MEANING: dict[str, str] = {
    NEGOTIATED: "a completed handshake — this connection's cipher, version and key exchange",
    OFFERED: "what the peer offers or accepts before any session exists",
    SESSION_CONFIG: "keys and policy read from the session's own configuration record",
    PASSIVE: "a sensor saw the traffic; no handshake was driven by us",
    ABSENT: "no reader for this protocol in this build",
}


@dataclass(frozen=True)
class Protocol:
    """One network protocol and how much a positive read of it proves."""

    id: str
    label: str
    layer: str
    strength: str
    producers: tuple[str, ...]
    reads: str
    cannot_claim: str
    ingest_only: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    #: inventory target classes that would carry this protocol
    targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.strength not in STRENGTHS:
            raise ValueError(f"unknown strength {self.strength!r}")


PROTOCOLS: tuple[Protocol, ...] = (
    Protocol(
        id="tls",
        label="TLS / SSL (all versions, SNI and ALPN aware)",
        layer="NETWORK_TRANSPORT",
        strength=NEGOTIATED,
        producers=(
            "network_scanner.probing.tls_handshaker:handshake",
            "network_scanner.probing.active_prober:probe_endpoint",
            "network_scanner.probing.version_floor:probe_version_floor",
            "network_scanner.probing.cipher_probe:probe_weak_ciphers",
            "network_scanner.probing.renegotiation:probe_renegotiation",
            "network_scanner.probing.http_headers:check_http_headers",
        ),
        reads=(
            "protocol version actually negotiated, cipher suite and key exchange, certificate "
            "chain, version floor (which legacy versions the peer still accepts), renegotiation "
            "and HSTS"
        ),
        cannot_claim=(
            "a negotiated suite is what this connection agreed. It is not the application's own "
            "crypto, not what the peer's other listeners do, and not evidence about a listener "
            "outside the approved scope"
        ),
        gaps=(
            "no TLS 1.3 Encrypted ClientHello (ECH) inspection",
            "no QUIC/HTTP-3 crypto read (QUIC initial packets are not handshaken here)",
        ),
        targets=("NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY"),
    ),
    Protocol(
        id="starttls",
        label="STARTTLS upgrades (SMTP, IMAP, POP3, LDAP, FTP, XMPP)",
        layer="NETWORK_TRANSPORT",
        strength=NEGOTIATED,
        producers=(
            "network_scanner.probing.starttls:negotiate_starttls",
            "network_scanner.probing.starttls:protocol_for_port",
        ),
        reads=(
            "the plaintext greeting, the STARTTLS acceptance and then the negotiated TLS version "
            "and suite on the upgraded channel"
        ),
        cannot_claim=(
            "an upgrade that the server refuses is reported as a refusal, which says nothing about "
            "the suites it would accept on a port that does offer TLS"
        ),
        gaps=("no XMPP or LDAP extended-operation STARTTLS variants beyond the shipped set",),
        targets=("NETWORK_ENDPOINT",),
    ),
    Protocol(
        id="ssh",
        label="SSH (KEX, host keys, MACs)",
        layer="NETWORK_TRANSPORT",
        strength=OFFERED,
        producers=(
            "network_scanner.probing.ssh_kex:probe_ssh_kex_offer",
            "network_scanner.probing.ssh_kex:analyze_ssh_kex_offer",
            "network_scanner.probing.ssh_keyscan:scan_ssh_host_keys",
            "network_scanner.probing.ssh_keyscan:classify_host_key",
        ),
        reads=(
            "the server's KEXINIT: key-exchange algorithms, host-key algorithms, ciphers, MACs and "
            "compression — plus the host key type and size actually presented"
        ),
        cannot_claim=(
            "KEXINIT is an offer list. Which algorithm a given session used needs packet capture or "
            "server-side logs, neither of which this reader has"
        ),
        gaps=(
            "no SSH-2 user-authentication method enumeration",
            "no per-session negotiated-algorithm capture",
        ),
        targets=("HOST", "NETWORK_ENDPOINT", "NETWORK_DEVICE"),
    ),
    Protocol(
        id="ipsec",
        label="IPsec / IKE (IKEv1 and IKEv2)",
        layer="NETWORK_TRANSPORT",
        strength=OFFERED,
        producers=(
            "network_scanner.probing.ipsec_probe:probe_ike",
            "network_scanner.probing.ipsec_probe:summarize_proposals",
            "network_scanner.probing.ipsec_probe:classify_esp",
        ),
        reads=(
            "the SA proposals a gateway answers with: encryption, PRF, integrity, DH group, and the "
            "ESP proposals, classified for post-quantum exposure"
        ),
        cannot_claim=(
            "a proposal set is not a tunnel. No established-SA read, no PSK/certificate identity and "
            "no traffic-selector knowledge — an idle gateway tells us what it would accept"
        ),
        gaps=(
            "no established-SA or SPD read (needs device access, not a probe)",
            "no IKE identity / auth-method enumeration",
            "no IKEv2 fragmentation or MOBIKE handling",
        ),
        targets=("NETWORK_ENDPOINT", "NETWORK_DEVICE"),
    ),
    Protocol(
        id="database",
        label="Database wire protocols (PostgreSQL, MySQL/MariaDB)",
        layer="NETWORK_TRANSPORT",
        strength=NEGOTIATED,
        producers=(
            "network_scanner.probing.db_probe:probe_database",
            "network_scanner.probing.db_probe:probe_postgres_tls",
            "network_scanner.probing.db_probe:probe_mysql_tls",
            "network_scanner.probing.db_probe:parse_mysql_handshake",
        ),
        reads=(
            "SSLRequest acceptance and the resulting TLS session on PostgreSQL and MySQL/MariaDB, "
            "including the engine's own version banner"
        ),
        cannot_claim=(
            "a TLS-capable listener is not evidence that storage is encrypted: TDE, tablespace "
            "encryption and per-column crypto are invisible to a wire probe"
        ),
        gaps=(
            "no Oracle TNS or TDS message-layer reader (both are reachable at the TLS layer via "
            "app_tls_ports, which cannot speak the protocol)",
            "no MongoDB / Redis / Cassandra / DB2 LUW reader beyond transport TLS",
            "no TDE or tablespace encryption read",
        ),
        targets=("DATABASE",),
    ),
    Protocol(
        id="app_tls_ports",
        label="TLS on application ports (brokers, directories, databases)",
        layer="NETWORK_TRANSPORT",
        strength=NEGOTIATED,
        producers=(
            "network_scanner.probing.port_protocols:plan_probes",
            "network_scanner.probing.port_protocols:interpret",
            "network_scanner.probing.tls_handshaker:handshake",
        ),
        reads=(
            "a TLS handshake on the ports brokers, directories and databases actually listen on "
            "(5671 AMQPS, 8883 MQTT/TLS, 9093 Kafka SSL, 636 LDAPS, 27017 MongoDB, 1433 TDS, "
            "1521 TNS, 6380 Redis TLS, 9200 Elastic): version, suite and certificate"
        ),
        cannot_claim=(
            "the protocol named for a port is the one that normally sits there, from IANA "
            "registration or vendor convention. The probe speaks TLS and nothing else, so channel "
            "encryption, client-certificate requirements and message-level crypto stay NOT_OBSERVED"
        ),
        gaps=(
            "no AMQP/MQTT/Kafka/TDS/TNS message-layer reader",
            "no in-protocol TLS upgrade capture (MongoDB, TDS and TNS negotiate TLS inside the "
            "application conversation)",
        ),
        targets=("MESSAGE_BROKER", "DATABASE", "SERVICE"),
    ),
    Protocol(
        id="service_mesh",
        label="Service mesh mTLS (Istio, Linkerd, Consul)",
        layer="NETWORK_TRANSPORT",
        strength=OFFERED,
        producers=(),  # filled below by the honest answer: none
        reads=(
            "nothing directly. A sidecar-held mTLS session is visible only as a TLS handshake on the "
            "sidecar's port if it is in scope, and the workload identity behind it is not read"
        ),
        cannot_claim=(
            "the mesh's own control plane is the source of truth for mTLS policy and identity, and "
            "this build does not read it. Mesh traffic is therefore NOT_OBSERVED at the workload "
            "level even when the sidecar port answers a probe"
        ),
        gaps=(
            "no Istio PeerAuthentication/DestinationRule read",
            "no SPIFFE identity extraction from the handshake",
            "no Linkerd or Consul mTLS policy read",
        ),
        targets=("POD", "SERVICE"),
    ),
    Protocol(
        id="messaging",
        label="Message brokers (AMQP, MQTT, Kafka, IBM MQ, JMS)",
        layer="APPLICATION",
        strength=ABSENT,
        producers=(),
        reads=(
            "nothing. Broker endpoints are inventoried as MESSAGE_BROKER assets by the attribution "
            "rules, but no protocol reader exists to say what a broker negotiated"
        ),
        cannot_claim=(
            "a broker on a TLS port is inferred from port and banner only. Channel encryption, "
            "client-certificate requirements and message-level crypto are NOT_OBSERVED"
        ),
        gaps=(
            "no AMQP/MQTT/Kafka message-layer reader (transport TLS on those ports is read by the "
            "app_tls_ports path, which says so)",
            "no IBM MQ channel definition read",
        ),
        targets=("MESSAGE_BROKER",),
    ),
    Protocol(
        id="directory",
        label="Directory and authentication protocols (LDAP/LDAPS, Kerberos, RADIUS)",
        layer="NETWORK_TRANSPORT",
        strength=SESSION_CONFIG,
        producers=("universal_vendor.plugins.identity:OktaPlugin",),
        reads=(
            "identity-provider configuration asserted by the IdP plugin: signing algorithms and "
            "assertion crypto as the provider declares them"
        ),
        cannot_claim=(
            "a directory's own TLS and Kerberos enctypes are not read. On-prem AD/Kerberos crypto "
            "is the Windows gap, not covered here"
        ),
        gaps=(
            "no LDAP rootDSE / supportedSASLMechanisms read (LDAPS 636 is read at the TLS layer by "
            "the app_tls_ports path)",
            "no Kerberos etype enumeration",
            "no RADIUS/EAP method read",
        ),
        targets=("SERVICE", "HOST"),
    ),
    Protocol(
        id="passive",
        label="Passive network observation",
        layer="NETWORK_TRANSPORT",
        strength=PASSIVE,
        producers=(
            "network_scanner.inventory.network_evidence:build_passive_evidence",
            "network_scanner.inventory.network_evidence:validate_passive_observation",
            "runtime.agent.tls_tap:TLSTap",
        ),
        reads=(
            "session records a sensor supplies (or the on-host TLS tap produces): versions, suites, "
            "SNI and certificate metadata, tagged as passive so they never rank as a handshake"
        ),
        cannot_claim=(
            "passive coverage is a sensor-placement question, not a software question. With no "
            "sensor deployed, nothing is observed, and the platform reports that rather than 0% "
            "coverage of the estate"
        ),
        gaps=(
            "no bundled sensor appliance",
            "no flow-table (NetFlow/IPFIX) ingestion",
        ),
        targets=("NETWORK_ENDPOINT",),
    ),
    Protocol(
        id="multi_hop",
        label="Multi-hop and path correlation",
        layer="NETWORK_TRANSPORT",
        strength=SESSION_CONFIG,
        producers=(
            "network_scanner.inventory.network_evidence:build_crypto_path",
            "api.estate_trust:survey",
            "shared_models.estate_twin:crypto_graph",
        ),
        reads=(
            "a declared hop chain annotated with the crypto observed at each hop, and trust paths "
            "walked over the estate graph — each hop either carries evidence or is marked UNKNOWN "
            "and excluded from the observed chain count"
        ),
        cannot_claim=(
            "hops are supplied by the operator or a reviewed inventory; the platform does not "
            "discover network topology. An unannotated hop is UNKNOWN, so a 'fully observed path' "
            "only ever means 'every hop on the list I gave it was observed'"
        ),
        gaps=(
            "no automatic topology discovery (LLDP/CDP/SNMP)",
            "no routing-path correlation from traceroute",
            "no per-hop re-key or key-lifetime correlation",
        ),
        targets=("NETWORK_ENDPOINT", "SERVICE"),
    ),
    Protocol(
        id="proprietary",
        label="Proprietary and financial protocols (SWIFT, ISO 8583, FIX, TIBCO EMS)",
        layer="APPLICATION",
        strength=ABSENT,
        producers=(),
        reads=(
            "nothing at the protocol level. These endpoints appear in the inventory from CMDB and "
            "vendor records, and their crypto is whatever TLS they sit behind"
        ),
        cannot_claim=(
            "SWIFT CSP, ISO 8583 and FIX message-level crypto is not read. A TLS read of the front "
            "door says nothing about the payload crypto behind it"
        ),
        gaps=(
            "no SWIFT/ISO 8583/FIX protocol reader",
            "no TIBCO/HF message-layer inspection",
        ),
        targets=("APPLICATION", "MESSAGE_BROKER"),
    ),
)

PROTOCOL_INDEX = {protocol.id: protocol for protocol in PROTOCOLS}


def _row(protocol: Protocol) -> dict[str, Any]:
    producers = [{"ref": ref, **resolve_detector(ref)} for ref in protocol.producers]
    present = [item for item in producers if item["present"]]
    strength = protocol.strength
    notes: list[str] = []
    if strength != ABSENT and not present:
        # A reader that is not in the build cannot read: say ABSENT, not "partial".
        strength = ABSENT
        notes.append("no declared producer of this protocol is present in this build")
    return {
        "id": protocol.id,
        "label": protocol.label,
        "layer": protocol.layer,
        "strength": strength,
        "declared_strength": protocol.strength,
        "strength_meaning": STRENGTH_MEANING[strength],
        "producers": producers,
        "producers_present": len(present),
        "ingest_only": list(protocol.ingest_only),
        "reads": protocol.reads,
        "cannot_claim": protocol.cannot_claim,
        "gaps": list(protocol.gaps),
        "targets": list(protocol.targets),
        "notes": notes,
    }


def registry(measured: Mapping[str, Any] | None = None) -> dict[str, Any]:
    rows = [_row(protocol) for protocol in PROTOCOLS]
    by_strength: dict[str, int] = {strength: 0 for strength in STRENGTHS}
    for row in rows:
        by_strength[row["strength"]] = by_strength.get(row["strength"], 0) + 1
    return {
        "schema": SCHEMA,
        "protocols": rows,
        "strengths": list(STRENGTHS),
        "strength_meaning": STRENGTH_MEANING,
        "rollup": {
            "protocols": len(rows),
            "by_strength": by_strength,
            "negotiated": by_strength.get(NEGOTIATED, 0),
            "offered_only": by_strength.get(OFFERED, 0),
            "absent": by_strength.get(ABSENT, 0),
        },
        "measured": dict(measured) if measured is not None else None,
        "claim": (
            "TLS is a completed-handshake reader; SSH and IPsec are offer readers, not session "
            "readers; messaging and proprietary financial protocols have no reader at all in this "
            "build. Coverage is per protocol, never an estate-wide network number"
        ),
        "note": (
            "an absent reader is listed as ABSENT rather than omitted: a protocol the platform "
            "cannot see is part of the answer, not a silence"
        ),
    }


__all__ = [
    "ABSENT",
    "NEGOTIATED",
    "OFFERED",
    "PASSIVE",
    "PROTOCOLS",
    "PROTOCOL_INDEX",
    "SCHEMA",
    "SESSION_CONFIG",
    "STRENGTHS",
    "STRENGTH_MEANING",
    "registry",
]
