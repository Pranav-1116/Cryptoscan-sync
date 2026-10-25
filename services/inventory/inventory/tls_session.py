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

    address, port, sni, version, pin = tls_resource(item.path)
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
            fact = seal_session(
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
