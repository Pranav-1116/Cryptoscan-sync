"""One bounded active TLS handshake to an approved numeric endpoint. No DNS."""

from datetime import datetime, timezone
import hashlib
import socket
import ssl
import time
from shared_models.tls_session import (
    PEER_LIMIT,
    WIRE_LIMIT,
    TlsPeerCertificate,
    client_session,
    endpoint,
    seal_session,
    selected_bytes,
    tls_resource,
)


def probe_session(item, limit, charge, expires_at, *, reviewed_target_sha256):
    from inventory.host import Refused, _certificate

    from shared_models.tls_key_share import (
        KIND,
        ServerHelloReader,
        TlsKeyShareFact,
        key_share_resource,
        parse_hello,
        GROUPS,
        group_classification,
    )

    from shared_models.tls_hybrid import KIND as HYBRID_KIND, hybrid_resource, TlsHybridFact

    hybrid = item.kind == HYBRID_KIND
    detailed = item.kind == KIND or hybrid
    address, port, sni, version, pin = (
        hybrid_resource if hybrid else key_share_resource if detailed else tls_resource
    )(item.path)
    reader = ServerHelloReader() if detailed else None
    budget = min(limit, WIRE_LIMIT)
    if budget < 8192:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    deadline = time.monotonic() + 8
    used, sent, received = 0, 0, 0

    def timeout():
        left = (expires_at - datetime.now(timezone.utc)).total_seconds()
        if left <= 0:
            raise Refused("DENIED", "EXPIRED")
        left = min(left, deadline - time.monotonic())
        if left <= 0:
            raise Refused("UNAVAILABLE", "TLS_TIMEOUT")
        return min(2.0, left)

    def counted(data):
        nonlocal used
        n = min(len(data), max(0, budget - used))
        charge(n)
        used += n
        if n != len(data):
            raise Refused("BUDGET_EXCEEDED", "LIMIT")

    # socket.socket + literal sockaddr avoids getaddrinfo, DNS, proxies and retries.
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    timeout()  # Refuse expiry before even allocating/connecting a socket.
    try:
        if hybrid:
            from inventory.tls_hybrid import hybrid_engine

            obj, incoming, outgoing = hybrid_engine(sni, version)
        else:
            obj, incoming, outgoing = client_session(sni, version)
        with socket.socket(family, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(timeout())
            try:
                tcp.connect((address, port, 0, 0) if family == socket.AF_INET6 else (address, port))
            except TimeoutError:
                raise Refused("UNAVAILABLE", "TLS_TIMEOUT") from None
            except OSError:
                raise Refused("UNAVAILABLE", "TLS_CONNECT_FAILED") from None
            for _ in range(512):
                timeout()
                complete, need_read = False, False
                try:
                    obj.do_handshake()
                    complete = True
                except ssl.SSLWantReadError:
                    need_read = True
                except ssl.SSLWantWriteError:
                    pass
                while outgoing.pending:
                    pending = outgoing.read(min(16384, outgoing.pending))
                    if len(pending) > budget - used:
                        raise Refused("BUDGET_EXCEEDED", "LIMIT")
                    while pending:
                        tcp.settimeout(timeout())
                        n = tcp.send(pending)
                        if n <= 0:
                            raise Refused("UNAVAILABLE", "TLS_HANDSHAKE_FAILED")
                        counted(pending[:n])
                        sent += n
                        pending = pending[n:]
                if complete:
                    break
                if need_read:
                    if budget - used <= 0:
                        raise Refused("BUDGET_EXCEEDED", "LIMIT")
                    tcp.settimeout(timeout())
                    data = tcp.recv(min(16384, budget - used))
                    if not data:
                        raise Refused("UNAVAILABLE", "TLS_HANDSHAKE_FAILED")
                    counted(data)
                    received += len(data)
                    if reader is not None:
                        reader.feed(data)
                    incoming.write(data)
            else:
                raise Refused("BUDGET_EXCEEDED", "LIMIT")
            der = obj.getpeercert(binary_form=True)
            if not der:
                raise Refused("UNAVAILABLE", "TLS_HANDSHAKE_FAILED")
            if len(der) > PEER_LIMIT:
                raise Refused("BUDGET_EXCEEDED", "LIMIT")
            counted(der)
            if hashlib.sha256(der).hexdigest() != pin:
                raise Refused("INVALID", "TLS_PEER_PIN_MISMATCH")
            certificate = _certificate(der)[0]
            public = TlsPeerCertificate(**{k: getattr(certificate, k) for k in TlsPeerCertificate.model_fields})
            cipher = obj.cipher()
            if obj.version() != version or not cipher:
                raise Refused("UNAVAILABLE", "TLS_HANDSHAKE_FAILED")
            detail = {}
            if reader is not None:
                if reader.final is None:
                    raise Refused("INVALID", "INVALID_FORMAT")
                counted(reader.final)
                _, group_id, _ = parse_hello(reader.final)
                detail = {
                    "fact_model": TlsKeyShareFact,
                    "selected_group_id": group_id,
                    "key_exchange_group": GROUPS.get(group_id, "UNKNOWN"),
                    "group_classification": group_classification(group_id),
                    "server_hello_hex": reader.final.hex(),
                    "server_hello_sha256": hashlib.sha256(reader.final).hexdigest(),
                    "hello_retry_request_seen": bool(reader.retries),
                }
            if hybrid:
                if group_id != 4588:
                    raise Refused("UNAVAILABLE", "TLS_REQUIRED_GROUP_NOT_SELECTED")
                detail.update(fact_model=TlsHybridFact, **obj.provider_metadata)
            fact = seal_session(
                **detail,
                on_selected=counted,
                reviewed_target_sha256=reviewed_target_sha256,
                address=address,
                port=port,
                sni=sni,
                tls_version=obj.version(),
                cipher_suite=cipher[0],
                cipher_bits=cipher[2],
                certificate=public,
                peer_der_bytes=len(der),
                wire_bytes_sent=sent,
                wire_bytes_received=received,
                identity_key="tls-endpoint:" + endpoint(address, port) + ":sni:" + sni,
            )
            data = selected_bytes(fact)
            timeout()
            return data, [fact]
    except TimeoutError:
        raise Refused("UNAVAILABLE", "TLS_TIMEOUT") from None
    except (ssl.SSLError, OSError):
        raise Refused("UNAVAILABLE", "TLS_HANDSHAKE_FAILED") from None
