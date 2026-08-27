"""End-to-end TLS tap test: scripted client + upstream, real sockets."""

from __future__ import annotations

import socket
import threading
import time

from runtime.agent.tls_tap import TLSTap

from test_tls_record_parser import build_certificate, build_client_hello, build_server_hello


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_tap_records_handshake_and_forwards_bytes_untouched():
    upstream_port = _free_port()
    received_upstream = bytearray()

    # scripted "TLS server": expects the ClientHello, replies ServerHello+Cert, then app data
    def upstream_server():
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", upstream_port))
        server.listen(1)
        server.settimeout(5)
        try:
            conn, _ = server.accept()
            hello = conn.recv(65536)
            received_upstream.extend(hello)
            conn.sendall(build_server_hello(suite=0xC02F) + build_certificate(b"payments.internal"))
            # echo any app data back
            conn.settimeout(2)
            try:
                data = conn.recv(65536)
                received_upstream.extend(data)
                if data:
                    conn.sendall(b"pong:" + data)
            except socket.timeout:
                pass
            conn.close()
        finally:
            server.close()

    server_thread = threading.Thread(target=upstream_server, daemon=True)
    server_thread.start()

    sessions: list[dict] = []
    tap = TLSTap(upstream_host="127.0.0.1", upstream_port=upstream_port, on_session=sessions.append)
    tap_port = tap.start("127.0.0.1", 0)
    try:
        client_hello = build_client_hello(sni=b"payments.internal")
        client = socket.create_connection(("127.0.0.1", tap_port), timeout=5)
        client.sendall(client_hello)
        client.settimeout(3)
        response = b""
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
            if len(response) >= len(build_server_hello(suite=0xC02F) + build_certificate(b"payments.internal")):
                break
        # send app data through the tap after the handshake
        client.sendall(b"ping")
        try:
            while len(response) < 4096:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
                if b"pong:ping" in response:
                    break
        except socket.timeout:
            pass
        client.close()

        # wait for the session record
        deadline = time.time() + 3
        while not sessions and time.time() < deadline:
            time.sleep(0.05)
    finally:
        tap.stop()

    assert sessions, "tap must record the session"
    session = sessions[0]
    assert session["sni"] == "payments.internal"
    assert session["negotiated"]["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert session["negotiated"]["negotiated_version"] == "TLSv1.3"
    chain = session["certificate"]["chain"]
    assert chain and "payments.internal" in chain[0]["common_names"]
    assert len(chain[0]["sha256_fingerprint"]) == 64
    # the ClientHello bytes reached upstream EXACTLY as sent
    assert bytes(received_upstream).startswith(client_hello[:5])
    assert bytes(received_upstream)[: len(client_hello)] == client_hello
    # app data flowed both ways through the tap untouched
    assert b"pong:ping" in response
    assert session["bytes_up"] > 0 and session["bytes_down"] > 0


def test_tap_summary_counts():
    sessions = [
        {"negotiated": {"cipher_suite": "TLS_AES_128_GCM_SHA256", "negotiated_version": "TLSv1.3"}},
        {"negotiated": {"cipher_suite": "TLS_AES_128_GCM_SHA256", "negotiated_version": "TLSv1.3"}},
        {"negotiated": {"cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "negotiated_version": "TLSv1.0"}, "error": None},
        {"error": "ConnectionError: client closed"},
    ]
    tap = TLSTap(upstream_host="x", upstream_port=1)
    tap.sessions.extend(sessions)
    summary = tap.summary()
    assert summary["sessions"] == 4
    assert summary["handshakes_observed"] == 3
    assert summary["errors"] == 1
    assert summary["cipher_suites"]["TLS_AES_128_GCM_SHA256"] == 2
    assert summary["tls_versions"]["TLSv1.0"] == 1
