"""Passive TLS tap — an observing forward proxy for production traffic.

Sits between clients and a TLS endpoint (load balancer, service, database):

    client -> [tap: listen_port] -> upstream host:port

The tap reads only the *handshake* records as they flow past — ClientHello
(offered suites, SNI, ALPN, versions) and ServerHello/Certificate
(negotiated suite, version, cert chain fingerprints) — then splices both
directions untouched. TLS is never terminated and no key material is ever
seen. Each connection produces a session record suitable for the runtime
crypto collector.

Usage (ops):

    cryptoscan-runtime tap --listen 0.0.0.0:8443 --upstream payments.internal:443 \
        --jsonl /var/log/tls-sessions.jsonl
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Any, Callable

class TLSTap:
    """Observing TCP forwarder that records TLS handshake metadata."""

    def __init__(
        self,
        *,
        upstream_host: str,
        upstream_port: int,
        on_session: Callable[[dict[str, Any]], None] | None = None,
        session_jsonl: str | None = None,
        connect_timeout: float = 5.0,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.on_session = on_session
        self.session_jsonl = session_jsonl
        self.connect_timeout = connect_timeout
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self.sessions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        """Start listening; returns the bound port (useful for port=0)."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        listener.settimeout(0.5)
        self._listener = listener
        bound_port = listener.getsockname()[1]
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        return bound_port

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                assert self._listener is not None
                client, addr = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    # ------------------------------------------------------------------ #
    def _handle(self, client: socket.socket, addr: tuple[str, int]) -> None:
        from runtime.agent.tls_record_parser import (
            CT_HANDSHAKE,
            HT_CERTIFICATE,
            HT_CLIENT_HELLO,
            HT_SERVER_HELLO,
            RecordBuffer,
            handshake_messages,
            parse_certificate,
            parse_client_hello,
            parse_server_hello,
        )

        session: dict[str, Any] = {
            "ts": time.time(),
            "client": f"{addr[0]}:{addr[1]}",
            "sni": None,
            "alpn": None,
            "offered_suites": [],
            "supported_versions": [],
            "negotiated": None,
            "certificate": None,
            "bytes_up": 0,
            "bytes_down": 0,
            "error": None,
        }

        upstream: socket.socket | None = None
        try:
            # 1) read the client's ClientHello (first handshake flight)
            client_hello: dict[str, Any] | None = None
            hello_buffer = RecordBuffer()
            client.settimeout(self.connect_timeout)
            while client_hello is None:
                chunk = client.recv(65536)
                if not chunk:
                    raise ConnectionError("client closed before ClientHello")
                hello_buffer.track_raw(chunk)
                for _ctype, payload in hello_buffer.feed(chunk):
                    if _ctype != CT_HANDSHAKE:
                        continue
                    for htype, body in handshake_messages(payload):
                        if htype == HT_CLIENT_HELLO and client_hello is None:
                            client_hello = parse_client_hello(body)
                if not chunk:
                    break
            if client_hello is None:
                raise ConnectionError("no ClientHello observed")
            session["sni"] = client_hello.get("sni")
            session["alpn"] = (client_hello.get("alpn") or [None])[0]
            session["offered_suites"] = client_hello.get("cipher_suites") or []
            session["supported_versions"] = client_hello.get("supported_versions") or []

            # 2) connect upstream and replay the exact bytes already read
            upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=self.connect_timeout)
            upstream.sendall(hello_buffer.raw_consumed)

            # 3) splice both directions, parsing server handshake records

            def pump(reader: socket.socket, writer: socket.socket, is_downstream: bool) -> None:
                server_buffer = RecordBuffer()
                handshake_done = False
                while not self._stop.is_set():
                    try:
                        chunk = reader.recv(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    if is_downstream:
                        session["bytes_down"] += len(chunk)
                        if not handshake_done:
                            for _ctype, payload in server_buffer.feed(chunk):
                                if _ctype != CT_HANDSHAKE:
                                    # first non-handshake record ends the handshake flight
                                    if session["negotiated"] is not None:
                                        handshake_done = True
                                    continue
                                for htype, body in handshake_messages(payload):
                                    if htype == HT_SERVER_HELLO and session["negotiated"] is None:
                                        session["negotiated"] = parse_server_hello(body)
                                    elif htype == HT_CERTIFICATE and session["certificate"] is None:
                                        session["certificate"] = parse_certificate(body)
                                if session["negotiated"] is not None and session["certificate"] is not None:
                                    handshake_done = True
                    else:
                        session["bytes_up"] += len(chunk)
                    try:
                        writer.sendall(chunk)
                    except OSError:
                        break
                try:
                    writer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            up_thread = threading.Thread(target=pump, args=(client, upstream, False), daemon=True)
            down_thread = threading.Thread(target=pump, args=(upstream, client, True), daemon=True)
            up_thread.start()
            down_thread.start()
            up_thread.join()
            down_thread.join()
        except Exception as exc:  # noqa: BLE001 — tap must never crash on bad traffic
            session["error"] = f"{type(exc).__name__}: {exc}"[:300]
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            with self._lock:
                self.sessions.append(session)
            if self.on_session is not None:
                try:
                    self.on_session(session)
                except Exception:  # noqa: BLE001 — observer errors must not kill taps
                    pass
            if self.session_jsonl:
                try:
                    _append_jsonl(self.session_jsonl, session)
                except OSError:
                    pass

    # ------------------------------------------------------------------ #
    def summary(self) -> dict[str, Any]:
        with self._lock:
            sessions = list(self.sessions)
        negotiated = [s["negotiated"] for s in sessions if s.get("negotiated")]
        suites: dict[str, int] = {}
        versions: dict[str, int] = {}
        for n in negotiated:
            suites[n.get("cipher_suite") or "unknown"] = suites.get(n.get("cipher_suite") or "unknown", 0) + 1
            versions[n.get("negotiated_version") or "unknown"] = versions.get(n.get("negotiated_version") or "unknown", 0) + 1
        return {
            "sessions": len(sessions),
            "handshakes_observed": len(negotiated),
            "errors": sum(1 for s in sessions if s.get("error")),
            "cipher_suites": suites,
            "tls_versions": versions,
        }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _append_jsonl(path: str, session: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(session, default=str) + "\n")
