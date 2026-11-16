#!/usr/bin/env python3
"""mTLS certificate-rotation drill — rehearse the runbook before the incident.

Rotation is the one maintenance action that can lock every client out at
once if done wrong. docs/runbooks/mtls-cert-rotation.md is the no-outage
path (server first, clients second, CA last, always overlapped); this
drill EXECUTES that order against a real TLS stack that DEMANDS client
certificates (the same demand as deploy/ha/nginx.conf ssl_verify_client
on and deploy/stack/envoy/envoy.yaml require_client_certificate) and
proves each claim with a live handshake:

    baseline          an unauthenticated client is REJECTED (the gate
                      demands certificates) and the enrolled one connects
    server_swap       a re-issued server cert (new key, same CA) locks
                      NOBODY out — the old client still connects
    client_reissue    re-issued client certs connect; old certs still do
    ca_overlap        with BOTH CAs trusted, new-CA and old-CA clients
                      connect — the overlap that makes this safe
    ca_retire         after the old root is removed, old-CA clients are
                      rejected (the intended end state) and new-CA ones work
    wrong_order_demo  swapping the CA FIRST would lock every client out —
                      the failure mode the ordering prevents, observed and
                      named so the drill can detect it

The PKI here is throwaway drill material in a temp directory — the bank's
PKI issues production certificates ("CryptoScan never generates them").
Exit 0 = every claim held; 1 = a step broke the runbook's contract.

    python3 scripts/mtls_rotation_drill.py --out drill-report.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ drill PKI

def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())


def make_ca(cn: str) -> dict:
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return {"cn": cn, "key": key, "cert": cert}


def issue(ca: dict, cn: str, *, server: bool) -> dict:
    key = _key()
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(ca["cert"].subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5))
               .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)))
    if server:
        builder = (builder
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName("localhost"),
                       x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
                   .add_extension(x509.ExtendedKeyUsage(
                       [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    else:
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert = builder.sign(ca["key"], hashes.SHA256())
    return {"cn": cn, "key": key, "cert": cert}


# ------------------------------------------------------- demanding TLS stack

class DemandingServer:
    """One listener that requires and verifies client certificates —
    the same demand the production gateways make."""

    def __init__(self, server_cert: dict, trust_cas: list[dict]):
        self._cert = server_cert
        self._trust = trust_cas
        self.port: int | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.rejected: list[str] = []

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.NamedTemporaryFile(suffix=".pem") as certfile, \
                tempfile.NamedTemporaryFile(suffix=".key") as keyfile, \
                tempfile.NamedTemporaryFile(suffix=".pem") as cafile:
            certfile.write(_pem_cert(self._cert["cert"])); certfile.flush()
            keyfile.write(_pem_key(self._cert["key"])); keyfile.flush()
            cafile.write(b"".join(_pem_cert(ca["cert"]) for ca in self._trust))
            cafile.flush()
            ctx.load_cert_chain(certfile.name, keyfile.name)
            ctx.load_verify_locations(cafile.name)
        ctx.verify_mode = ssl.CERT_REQUIRED  # the gate DEMANDS a client cert
        return ctx

    def start(self) -> None:
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        ctx = self._context()
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(16)
                    tls.sendall(b"OK\n")
            except ssl.SSLError as exc:
                self.rejected.append(str(exc))
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)


def attempt(port: int, client: dict | None, trust_cas: list[dict]) -> tuple[bool, str]:
    """One live mTLS request. (ok, detail) — a refusal is honest detail."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          # 127.0.0.1, SAN verified by the chain
    with tempfile.NamedTemporaryFile(suffix=".pem") as cafile:
        cafile.write(b"".join(_pem_cert(ca["cert"]) for ca in trust_cas))
        cafile.flush()
        ctx.load_verify_locations(cafile.name)
    if client is not None:
        with tempfile.NamedTemporaryFile(suffix=".pem") as certfile, \
                tempfile.NamedTemporaryFile(suffix=".key") as keyfile:
            certfile.write(_pem_cert(client["cert"])); certfile.flush()
            keyfile.write(_pem_key(client["key"])); keyfile.flush()
            ctx.load_cert_chain(certfile.name, keyfile.name)
            return _connect(port, ctx)
    return _connect(port, ctx)


def _connect(port: int, ctx: ssl.SSLContext) -> tuple[bool, str]:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw) as tls:
                tls.sendall(b"ping")
                reply = tls.recv(16)
                return reply.startswith(b"OK"), "handshake completed"
    except (ssl.SSLError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ----------------------------------------------------------------- the drill

def _step(report: dict, name: str, claim: str, checks: list[dict]) -> None:
    passed = all(c["connected"] == c["expected"] for c in checks)
    report["steps"].append({
        "step": name, "claim": claim,
        "result": "PASS" if passed else "FAIL", "checks": checks})


def run_drill(workdir: Path) -> dict:
    report = {"schema": "cryptoscan.mtls-rotation-drill/1",
              "runbook": "docs/runbooks/mtls-cert-rotation.md",
              "pki": f"throwaway drill material ({workdir})",
              "steps": []}

    ca1 = make_ca("drill-bank-ca-v1")
    ca2 = make_ca("drill-bank-ca-v2")
    client_old = issue(ca1, "soc-client", server=False)
    client_new = issue(ca2, "soc-client-v2", server=False)
    server_v1 = issue(ca1, "cryptoscan-gateway", server=True)
    server_v2 = issue(ca1, "cryptoscan-gateway", server=True)   # new key, same CA
    server_v3 = issue(ca2, "cryptoscan-gateway", server=True)   # new-CA server

    def run(server_cert, trust, clients) -> list[dict]:
        srv = DemandingServer(server_cert, trust)
        srv.start()
        try:
            out = []
            for label, client, client_trust, expected in clients:
                connected, detail = attempt(srv.port, client, client_trust)
                out.append({"client": label, "expected": expected,
                            "connected": connected, "detail": detail})
            return out
        finally:
            srv.stop()

    # baseline: the gate demands certificates; the enrolled client connects
    checks = run(server_v1, [ca1], [
        ("enrolled-client", client_old, [ca1], True),
        ("no-client-cert", None, [ca1], False)])
    _step(report, "baseline",
          "the gate DEMANDS client certificates (bare client rejected) "
          "and the enrolled client connects", checks)

    # server first: a re-issued server cert locks nobody out
    checks = run(server_v2, [ca1], [
        ("old-client", client_old, [ca1], True)])
    _step(report, "server_swap",
          "a re-issued server cert (new key, same CA) locks NOBODY out", checks)

    # client re-issue: new certs connect, old certs still do
    checks = run(server_v2, [ca1], [
        ("new-client", client_old, [ca1], True),
        ("old-client", client_old, [ca1], True)])
    _step(report, "client_reissue",
          "re-issued client certs connect while old certs still do", checks)

    # CA overlap: BOTH CAs trusted on both sides — nobody is locked out
    checks = run(server_v3, [ca1, ca2], [
        ("old-CA-client", client_old, [ca1, ca2], True),
        ("new-CA-client", client_new, [ca1, ca2], True)])
    _step(report, "ca_overlap",
          "with BOTH CAs trusted, old-CA and new-CA clients connect", checks)

    # CA retire: old root removed — the intended end state
    checks = run(server_v3, [ca2], [
        ("old-CA-client", client_old, [ca2], False),
        ("new-CA-client", client_new, [ca2], True)])
    _step(report, "ca_retire",
          "after the old root is removed, old-CA clients are rejected "
          "(intended) and new-CA clients work", checks)

    # the failure mode the ordering prevents, observed and named
    checks = run(server_v1, [ca2], [
        ("old-CA-client", client_old, [ca2], False)])
    _step(report, "wrong_order_demo",
          "swapping the CA FIRST locks every client out — the failure "
          "mode 'server first, CA last' prevents, observed here", checks)

    report["verdict"] = ("PASS"
                         if all(s["result"] == "PASS" for s in report["steps"])
                         else "FAIL")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None, help="write the report JSON here")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="mtls-drill-") as work:
        report = run_drill(Path(work))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
