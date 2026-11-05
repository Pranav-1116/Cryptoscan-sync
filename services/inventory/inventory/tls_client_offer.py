"""One bounded inbound observation window: the ClientHellos that arrive at an approved probe.

This is the collector that observes handshakes **client-side**. Where ``tls_session``
initiates a session and records what the server selected, this binds one approved numeric
endpoint and records what each connecting client *offers* — the runtime acceptance the
protocol floor could not see. It sends no ServerHello and completes no handshake: the
fact says what was offered on the wire, never what was used.

The window is bounded in every dimension the platform charges: seconds, connections,
offers (``MAX_OFFERS``) and wire bytes. A window in which no client offered anything is a
failed read (``UNAVAILABLE``/``TLS_TIMEOUT``) with no facts — never an estate whose
clients are all above the floor.
"""

from datetime import datetime, timezone
import hashlib
import json
import socket
import time

from shared_models.tls_client_offer import (
    HELLO_LIMIT,
    KIND,
    MAX_OFFERS,
    TlsClientOfferFact,
    WIRE_LIMIT,
    client_offer_resource,
    endpoint,
    parse_client_hello,
    seal_offer,
)

#: the probe declines to continue the handshake, politely and identically every time
ALERT_HANDSHAKE_FAILURE = bytes.fromhex("15030300020228")
WINDOW_SECONDS = 8
MAX_CLIENTS = 8


def _recv_exact(conn, count, timeout):
    """Read exactly ``count`` bytes or return ``None`` — a partial read is a refusal."""
    conn.settimeout(timeout)
    chunks, left = b"", count
    while left > 0:
        try:
            chunk = conn.recv(left)
        except (socket.timeout, ConnectionError, OSError):
            return None
        if not chunk:
            return None
        chunks += chunk
        left -= len(chunk)
    return chunks


def probe_client_offers(item, limit, charge, expires_at, *, reviewed_target_sha256):
    from inventory.host import Refused

    bind_address, bind_port = client_offer_resource(item.path)
    budget = min(limit, WIRE_LIMIT)
    if budget < 8192:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    deadline = time.monotonic() + WINDOW_SECONDS
    used = 0

    def timeout():
        left = (expires_at - datetime.now(timezone.utc)).total_seconds()
        if left <= 0:
            raise Refused("DENIED", "EXPIRED")
        left = min(left, deadline - time.monotonic())
        if left <= 0:
            return None
        return min(2.0, left)

    listener = socket.socket(socket.AF_INET6 if ":" in bind_address else socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_address, bind_port))
    except PermissionError:
        raise Refused("DENIED", "ACCESS_DENIED") from None
    except OSError:
        raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None
    listener.listen(MAX_CLIENTS)
    offers: list[TlsClientOfferFact] = []
    refused_connections = 0
    try:
        while len(offers) < MAX_OFFERS:
            left = timeout()
            if left is None:
                break
            listener.settimeout(left)
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                # once something has been observed, a quiet accept window closes the
                # observation: the probe reports what arrived, it does not wait out the
                # clock hoping for more
                if offers:
                    break
                continue
            except OSError:
                raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE") from None
            try:
                # one TLS record carrying one handshake message, bounded twice over
                head = _recv_exact(conn, 5, timeout() or 1.0)
                size = int.from_bytes(head[3:5], "big") if head and len(head) == 5 else 0
                if not head or head[0] != 22 or not 4 <= size <= HELLO_LIMIT:
                    refused_connections += 1
                    continue
                payload = _recv_exact(conn, size, timeout() or 1.0)
                if payload is None or len(payload) < 4 or payload[0] != 1:
                    refused_connections += 1
                    continue
                message_len = int.from_bytes(payload[1:4], "big")
                if 4 + message_len > len(payload):
                    refused_connections += 1
                    continue
                data = head + payload
                charge(len(data))
                used += len(data)
                if used > budget:
                    raise Refused("BUDGET_EXCEEDED", "LIMIT")
                parsed = parse_client_hello(payload[: 4 + message_len])
                client_address = peer[0]
                client_port = peer[1]
                offers.append(
                    seal_offer(
                        reviewed_target_sha256=reviewed_target_sha256,
                        bind_address=bind_address,
                        bind_port=bind_port,
                        client_address=client_address,
                        client_port=client_port,
                        sni=parsed["sni"],
                        offered_versions=parsed["offered_versions"],
                        offered_cipher_suites=parsed["offered_cipher_suites"],
                        offered_groups=parsed["offered_groups"],
                        offered_signature_algorithms=parsed["offered_signature_algorithms"],
                        alpn=parsed["alpn"],
                        grease_values_seen=parsed["grease_values_seen"],
                        versions_field=parsed["versions_field"],
                        wire_bytes_received=len(data),
                        identity_key=(
                            "tls-client-endpoint:" + endpoint(bind_address, bind_port)
                            + ":client:" + endpoint(client_address, client_port)
                        ),
                    )
                )
            except ValueError:
                refused_connections += 1
            finally:
                try:
                    conn.sendall(ALERT_HANDSHAKE_FAILURE)
                except OSError:
                    pass
                conn.close()
    finally:
        listener.close()

    if offers:
        data = json.dumps(
            {
                "client_offers": [fact.model_dump(mode="json") for fact in offers],
                "refused_connections": refused_connections,
                "window_seconds": WINDOW_SECONDS,
                "note": (
                    "offers observed at one approved probe endpoint during one bounded window; a "
                    "client that never connected here is not covered and is not assumed compliant"
                ),
            },
            sort_keys=True,
        ).encode()
        if used + len(data) > budget:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(len(data))
        return data, offers
    if refused_connections:
        raise Refused("INVALID", "INVALID_FORMAT")
    # the probe was bound for the whole window and nothing offered anything: a failed
    # read. No facts and no zeros — an unobserved client is not an unbroken one
    raise Refused("UNAVAILABLE", "TLS_TIMEOUT")
