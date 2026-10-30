"""TLS on the ports application protocols actually listen on.

The protocol matrix is honest about what it cannot read: Kafka, AMQP, MQTT,
LDAP, MongoDB and friends have no **message-layer** reader here. But that is not
the same as "we learn nothing from those ports". Every one of them carries TLS in
production, and a TLS handshake is a TLS handshake wherever it happens — the same
handshaker that reads a web listener can read a broker, a directory or a
database, and report the version, the suite and the certificate it presented.

So this module does exactly two things, and refuses the third:

* it maps the well-known TLS-bearing ports to the protocol that normally sits
  there, with the source of that knowledge stated;
* it turns a successful handshake on such a port into evidence of *TLS on that
  port*, never into evidence about the protocol above it.

What it deliberately does **not** do is speak AMQP, MQTT, TDS, TNS or the LDAP
bind protocol. A probe that opened a Mongo wire conversation would need its own
parser, its own error model and its own tests; a probe that *claims* to have done
so is worse than one that does not. The label on a row from this module is
"TLS on 5671", and the broker behind it stays NOT_OBSERVED.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.port-protocols/1"

#: how the port mapping itself was established
CLASSIFICATION_IANA = "IANA_REGISTERED"
CLASSIFICATION_CONVENTION = "VENDOR_CONVENTION"

KNOWN_TLS_PORTS: tuple[dict[str, Any], ...] = (
    {
        "port": 5671,
        "protocol": "amqp",
        "label": "AMQP over TLS (RabbitMQ and compatible)",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: amqps 5671/tcp",
        "message_layer": "AMQP 0-9-1 / 1.0",
    },
    {
        "port": 8883,
        "protocol": "mqtt",
        "label": "MQTT over TLS",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: secure-mqtt 8883/tcp",
        "message_layer": "MQTT",
    },
    {
        "port": 9093,
        "protocol": "kafka",
        "label": "Kafka SSL listener",
        "classification": CLASSIFICATION_CONVENTION,
        "source": "Apache Kafka convention: SSL listener 9093/tcp",
        "message_layer": "Kafka wire protocol",
    },
    {
        "port": 636,
        "protocol": "ldaps",
        "label": "LDAPS (directory over TLS)",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: ldaps 636/tcp",
        "message_layer": "LDAP",
    },
    {
        "port": 3269,
        "protocol": "ldaps_gc",
        "label": "LDAPS Global Catalog (Active Directory)",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: msft-gc-ssl 3269/tcp",
        "message_layer": "LDAP",
    },
    {
        "port": 27017,
        "protocol": "mongodb",
        "label": "MongoDB with TLS",
        "classification": CLASSIFICATION_CONVENTION,
        "source": "MongoDB convention: 27017/tcp, TLS negotiated in-protocol",
        "message_layer": "MongoDB wire protocol",
    },
    {
        "port": 9200,
        "protocol": "elasticsearch",
        "label": "Elasticsearch HTTPS",
        "classification": CLASSIFICATION_CONVENTION,
        "source": "Elastic convention: REST/HTTPS 9200/tcp",
        "message_layer": "HTTP + Elasticsearch APIs",
    },
    {
        "port": 1433,
        "protocol": "mssql",
        "label": "Microsoft SQL Server (TDS), TLS negotiated in the pre-login",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: ms-sql-s 1433/tcp",
        "message_layer": "TDS",
    },
    {
        "port": 1521,
        "protocol": "oracle_tns",
        "label": "Oracle TNS listener, TLS negotiated by the connection string",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: oracle 1521/tcp",
        "message_layer": "TNS",
    },
    {
        "port": 6380,
        "protocol": "redis_tls",
        "label": "Redis over TLS",
        "classification": CLASSIFICATION_CONVENTION,
        "source": "Redis convention: TLS port is conventionally 6380/tcp",
        "message_layer": "RESP",
    },
    {
        "port": 5672,
        "protocol": "amqp_plain",
        "label": "AMQP plaintext port (TLS absent is a finding, not a failure)",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: amqp 5672/tcp",
        "message_layer": "AMQP 0-9-1 / 1.0",
    },
    {
        "port": 1883,
        "protocol": "mqtt_plain",
        "label": "MQTT plaintext port (TLS absent is a finding, not a failure)",
        "classification": CLASSIFICATION_IANA,
        "source": "IANA: mqtt 1883/tcp",
        "message_layer": "MQTT",
    },
)

PORT_INDEX: dict[int, dict[str, Any]] = {int(entry["port"]): entry for entry in KNOWN_TLS_PORTS}

#: ports where the plaintext variant is the expected one, so "no TLS here" is a
#: statement about the deployment rather than a probe failure
PLAINTEXT_PORTS: frozenset[int] = frozenset({5672, 1883})


def classify_port(port: int) -> dict[str, Any] | None:
    entry = PORT_INDEX.get(int(port))
    if entry is None:
        return None
    return {**entry, "plaintext_variant": int(port) in PLAINTEXT_PORTS}


def plan_probes(endpoints: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Turn candidate endpoints into TLS probes on the ports that carry crypto.

    ``endpoints`` are ``{"host": str, "port": int}`` mappings. An endpoint on a
    port this module does not know is returned in ``unclassified`` rather than
    being dropped — an unknown port is a question, not a no.
    """
    probes: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    for endpoint in endpoints:
        host = str(endpoint.get("host") or "").strip()
        try:
            port = int(endpoint.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not port:
            continue
        known = classify_port(port)
        if known is None:
            unclassified.append({"host": host, "port": port})
            continue
        probes.append(
            {
                "host": host,
                "port": port,
                "probe": "TLS_HANDSHAKE",
                "protocol": known["protocol"],
                "label": known["label"],
                "classification": known["classification"],
                "source": known["source"],
                "expect_tls": port not in PLAINTEXT_PORTS,
            }
        )
    return {
        "schema": SCHEMA,
        "probes": probes,
        "unclassified": unclassified,
        "counts": {"probes": len(probes), "unclassified": len(unclassified)},
        "note": (
            "every probe here is a TLS handshake. The protocol named is the one that normally sits "
            "on that port, from IANA registration or vendor convention — it is not a claim that the "
            "probe spoke that protocol"
        ),
    }


def interpret(port: int, handshake: Mapping[str, Any] | None) -> dict[str, Any]:
    """Attach a handshake result to a known port, without over-claiming.

    ``handshake`` is what the existing TLS prober returned (version, suite,
    certificate, error). ``None`` means the port answered nothing usable.
    """
    known = classify_port(port)
    if known is None:
        return {
            "schema": SCHEMA,
            "port": int(port),
            "state": "UNCLASSIFIED",
            "reason": "this port is not in the well-known crypto-port table",
            "app_protocol_spoken": False,
        }
    if handshake is None:
        state = "NOT_ATTEMPTED"
        reason = "no handshake result was supplied for this port"
    elif handshake.get("error") or handshake.get("verdict") in {"REFUSED", "FAILED", "NO_TLS"}:
        state = "NO_TLS"
        reason = (
            "the port did not complete a TLS handshake. On a plaintext-convention port that is an "
            "observation about the deployment; on a TLS-convention port it means the listener is "
            "misconfigured, speaks something else, or is guarded"
        )
    else:
        state = "TLS_OBSERVED"
        reason = None
    return {
        "schema": SCHEMA,
        "port": int(port),
        "protocol": known["protocol"],
        "label": known["label"],
        "classification": known["classification"],
        "source": known["source"],
        "message_layer": known["message_layer"],
        "state": state,
        "reason": reason,
        "tls": dict(handshake) if handshake else None,
        "app_protocol_spoken": False,
        "cannot_claim": (
            "the handshake proves TLS on this port. It proves nothing about "
            + str(known["message_layer"])
            + ": channel encryption, client-certificate requirements and message-level crypto stay "
            "NOT_OBSERVED"
        ),
    }


def coverage() -> dict[str, Any]:
    """The port table itself, for a coverage screen."""
    return {
        "schema": SCHEMA,
        "ports": [dict(entry, plaintext_variant=int(entry["port"]) in PLAINTEXT_PORTS) for entry in KNOWN_TLS_PORTS],
        "counts": {
            "ports": len(KNOWN_TLS_PORTS),
            "iana": len([e for e in KNOWN_TLS_PORTS if e["classification"] == CLASSIFICATION_IANA]),
            "convention": len(
                [e for e in KNOWN_TLS_PORTS if e["classification"] == CLASSIFICATION_CONVENTION]
            ),
        },
        "claim": (
            "a TLS handshake can be read on every port in this table, which extends protocol "
            "coverage to brokers, directories and databases at the transport layer. No message-layer "
            "protocol is spoken, and every result says so"
        ),
    }


__all__ = [
    "CLASSIFICATION_CONVENTION",
    "CLASSIFICATION_IANA",
    "KNOWN_TLS_PORTS",
    "PLAINTEXT_PORTS",
    "PORT_INDEX",
    "SCHEMA",
    "classify_port",
    "coverage",
    "interpret",
    "plan_probes",
]
