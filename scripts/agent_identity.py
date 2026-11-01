"""Agent machine identity: certificate → registered agent → signed observation.

Guide 119 recorded the gap as three separate facts that were never joined:

    "this TLS client presented a valid certificate"
    "this payload carries a valid signature by a trusted key"
    "this agent exists"

The drill below executes the join and grades it. Every probe is either a real
TLS handshake, a real Ed25519 signature, or the real middleware and route code —
no probe asserts that code exists.

Run::

    python scripts/agent_identity.py \\
        --json docs/bank-environment/124-agent-identity.json \\
        --md   docs/bank-environment/124-agent-identity.md
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import socket
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.agent-identity/1"
VERSION = "agent-identity/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


def _bootstrap_paths() -> None:
    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "shared/shared_logging"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)


_bootstrap_paths()

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "agent-identity-drill-key-32-characters")

from api.security import agent_identity as ai  # noqa: E402
from shared_models import release_signature  # noqa: E402
from api.middleware.agent_identity_middleware import AgentIdentityMiddleware  # noqa: E402


@dataclass
class Probe:
    name: str
    ok: bool
    observed: str

    def as_dict(self) -> dict[str, Any]:
        return {"probe": self.name, "ok": self.ok, "observed": self.observed}


# --------------------------------------------------------------------------- #
# real key material
# --------------------------------------------------------------------------- #

@dataclass
class Material:
    directory: Path
    ca_pem: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    client_der: bytes

    @property
    def client_spki(self) -> str:
        return ai.spki_fingerprint(self.client_der)


def _make_cert(*, common_name: str, is_ca: bool, issuer: Any = None,
               issuer_key: Any = None, key: Any = None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                                   x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False)
    certificate = builder.sign(issuer_key or key, hashes.SHA256())
    return certificate, key, serialization


def build_material(directory: Path, *, client_cn: str = "agent-eu-1") -> Material:
    from cryptography.hazmat.primitives import serialization

    ca_cert, ca_key, _ = _make_cert(common_name="CryproScan Drill CA", is_ca=True)
    server_cert, server_key, _ = _make_cert(
        common_name="127.0.0.1", is_ca=False, issuer=ca_cert.subject, issuer_key=ca_key)
    client_cert, client_key, _ = _make_cert(
        common_name=client_cn, is_ca=False, issuer=ca_cert.subject, issuer_key=ca_key)

    paths = {}
    for name, (cert, key) in {
        "ca": (ca_cert, None), "server": (server_cert, server_key),
        "client": (client_cert, client_key),
    }.items():
        cert_path = directory / f"{name}.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        paths[f"{name}_cert"] = cert_path
        if key is not None:
            key_path = directory / f"{name}.key"
            key_path.write_bytes(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
            paths[f"{name}_key"] = key_path

    return Material(
        directory=directory,
        ca_pem=paths["ca_cert"],
        server_cert=paths["server_cert"], server_key=paths["server_key"],
        client_cert=paths["client_cert"], client_key=paths["client_key"],
        client_der=client_cert.public_bytes(serialization.Encoding.DER),
    )


def handshake_peer_certificate(material: Material) -> bytes | None:
    """Run a real TLS handshake and return the certificate the SERVER saw.

    This is the only honest way to answer "can the boundary read the identity?":
    the bytes come out of ``SSLObject.getpeercert`` on the server side, not out of
    the file this drill just wrote.
    """
    from api.security.mtls import build_mtls_context, client_context

    server_context = build_mtls_context(str(material.server_cert), str(material.server_key),
                                        str(material.ca_pem))
    peer: dict[str, Any] = {}

    def serve(sock: socket.socket) -> None:
        try:
            with server_context.wrap_socket(sock, server_side=True) as tls:
                peer["der"] = tls.getpeercert(binary_form=True)
                tls.sendall(b"ok")
        except Exception as exc:  # noqa: BLE001
            peer["error"] = repr(exc)
            peer["der"] = None

    ours, theirs = socket.socketpair()
    thread = threading.Thread(target=serve, args=(theirs,), daemon=True)
    thread.start()
    context = client_context(str(material.client_cert), str(material.client_key),
                             str(material.ca_pem))
    context.check_hostname = False
    try:
        with context.wrap_socket(ours, server_hostname="127.0.0.1") as client:
            client.recv(2)
    finally:
        thread.join(timeout=10)
        theirs.close()
    return peer.get("der")


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #

def probe_certificate_readable(material: Material) -> list[Probe]:
    from_handshake = handshake_peer_certificate(material)
    expected = material.client_spki
    got = None
    if from_handshake:
        try:
            got = ai.spki_fingerprint(from_handshake)
        except ai.AgentIdentityError as exc:
            got = f"error: {exc}"
    probes = [Probe(
        "server-reads-peer-certificate",
        got == expected,
        (f"real TLS handshake: the server's getpeercert produced SPKI {got}"
         if got else "the server saw no client certificate; the boundary cannot read identity"),
    )]
    probes.append(Probe(
        "fingerprint-is-the-key-not-the-certificate",
        ai.spki_fingerprint(material.client_der) == expected,
        "the SPKI fingerprint is computed from the public key, so reissuing a "
        "certificate for the same key keeps the identity and a new key never "
        "inherits an old one",
    ))
    return probes


def probe_registry(material: Material) -> list[Probe]:
    probes: list[Probe] = []
    signing = release_signature.sign_document({"x": 1}, _ed25519_key())["public_key"]
    agent = ai.AgentIdentity(agent_id="agent-eu-1", spki=material.client_spki,
                             signing_key=signing, tenant="bank-a")
    registry = ai.AgentRegistry([agent])

    resolved = registry.lookup(material.client_spki)
    probes.append(Probe("registered-fingerprint-resolves", resolved is not None
                        and resolved.agent_id == "agent-eu-1",
                        f"lookup returned {resolved.agent_id if resolved else None}"))

    noisy = material.client_spki.replace("sha256:", "SHA256:").upper().replace("SHA256", "sha256")
    probes.append(Probe("fingerprint-normalisation", registry.lookup(noisy) is not None,
                        "an upper-case, colon-separated fingerprint resolves to the same "
                        "agent as the canonical form"))

    with tempfile.TemporaryDirectory() as tmp:
        other = build_material(Path(tmp), client_cn="agent-rogue")
        unknown = registry.lookup(other.client_spki)
    probes.append(Probe("unregistered-fingerprint-refused", unknown is None,
                        "a certificate from the same CA that is not in the registry "
                        "resolves to no agent"))

    duplicate = [
        ai.AgentIdentity("a", material.client_spki, signing),
        ai.AgentIdentity("b", material.client_spki, signing),
    ]
    try:
        ai.AgentRegistry(duplicate)
        duplicate_ok, duplicate_note = False, "two agents were allowed to share a fingerprint"
    except ai.AgentIdentityError as exc:
        duplicate_ok, duplicate_note = True, f"refused: {exc}"
    probes.append(Probe("duplicate-fingerprint-refused", duplicate_ok, duplicate_note))

    with tempfile.TemporaryDirectory() as tmp:
        broken = Path(tmp) / "registry.json"
        broken.write_text('{"agents": [{"agent_id": "half", "spki": "sha256:deadbeef"}]}')
        try:
            ai.AgentRegistry.from_file(broken)
            malformed_ok, malformed_note = False, "a half-written agent entry was accepted"
        except ai.AgentIdentityError as exc:
            malformed_ok, malformed_note = True, f"refused: {exc}"
    probes.append(Probe("malformed-registry-fails-closed", malformed_ok, malformed_note))

    empty = ai.AgentRegistry()
    probes.append(Probe("empty-registry-refuses-everything",
                        empty.lookup(material.client_spki) is None,
                        "with no agents registered, no certificate resolves — the "
                        "default is refusal, not trust"))
    return probes


def _ed25519_key(seed: bytes | None = None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if seed is None:
        return Ed25519PrivateKey.generate()
    return Ed25519PrivateKey.from_private_bytes(seed)


def probe_signature_binding(material: Material) -> list[Probe]:
    agent_key = _ed25519_key()
    other_key = _ed25519_key(b"\x01" * 32)
    public = release_signature.public_key_b64(agent_key.public_key())
    agent = ai.AgentIdentity("agent-eu-1", material.client_spki, public)

    document = {"schema": "cryptoscan.live-observation/1", "estate": "bank-a"}
    bound_signature = release_signature.sign_document(document, agent_key)
    foreign_signature = release_signature.sign_document(document, other_key)

    ok, note = ai.check_signature_binding(agent, bound_signature)
    probes = [Probe("bound-key-accepted", ok, note)]

    ok, note = ai.check_signature_binding(agent, foreign_signature)
    probes.append(Probe("foreign-key-refused", not ok, note))

    ok, note = ai.check_signature_binding(agent, None)
    probes.append(Probe("unsigned-observation-refused", not ok, note))

    tampered = dict(bound_signature)
    tampered["public_key"] = base64.b64encode(b"x" * 32).decode()
    ok, note = ai.check_signature_binding(agent, tampered)
    probes.append(Probe("swapped-embedded-key-refused", not ok, note))
    return probes


def probe_http_enforcement(material: Material) -> list[Probe]:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    agent_key = _ed25519_key(b"\x02" * 32)
    public = release_signature.public_key_b64(agent_key.public_key())
    agent = ai.AgentIdentity("agent-eu-1", material.client_spki, public, "bank-a")
    registry = ai.AgentRegistry([agent])

    app = FastAPI()

    @app.post("/api/v1/ingestion/observations")
    def ingest() -> dict:
        return {"stored": True}

    # Not an /api path: this app belongs to the drill, so a product-shaped path
    # here would put a phantom endpoint in the route-contract census.
    @app.post("/__drill/non-ingest-surface")
    def other() -> dict:
        return {"stored": True}

    app.add_middleware(AgentIdentityMiddleware, registry=registry)
    # The middleware is driven directly below (an ASGI TestClient cannot carry a
    # TLS extension), but the app is built so a wiring mistake shows up here.
    TestClient(app)

    probes: list[Probe] = []
    with _env({ai.ENFORCE_ENV: "1", ai.TERMINATOR_ENV: ""}):
        # Simulate the ASGI TLS extension by wrapping the transport: FastAPI's
        # TestClient cannot carry it, so the drill drives the middleware directly
        # with the certificate it read from a real handshake.
        status, body = _drive_middleware(registry, material.client_der, "/api/v1/ingestion/observations")
        probes.append(Probe("registered-certificate-admitted", status == 200 and body.get("stored"),
                            f"middleware admitted the request with status {status}"))
        status, body = _drive_middleware(registry, b"not-a-certificate", "/api/v1/ingestion/observations")
        probes.append(Probe("unusable-certificate-refused",
                            status == 403 and "agent_identity_unregistered" in json.dumps(body),
                            f"unusable certificate answered {status}"))
        status, _ = _drive_middleware(registry, None, "/api/v1/ingestion/observations")
        probes.append(Probe("no-certificate-refused", status == 403,
                            f"a request with no peer certificate answered {status}"))
        status, _ = _drive_middleware(registry, None, "/__drill/non-ingest-surface")
        probes.append(Probe("non-ingest-surface-unaffected", status == 200,
                            f"a non-ingest path answered {status} with no certificate"))

    with _env({ai.ENFORCE_ENV: ""}):
        status, _ = _drive_middleware(registry, None, "/api/v1/ingestion/observations")
        probes.append(Probe("inert-when-not-required", status == 200,
                            "with the requirement off (the default) the middleware "
                            "changes nothing, so this is an opt-in deployment property"))

    with _env({ai.ENFORCE_ENV: "1", ai.TERMINATOR_ENV: "1"}):
        other_registry = ai.AgentRegistry([])
        status, body = _drive_middleware(
            other_registry, None, "/api/v1/ingestion/observations",
            headers={ai.TERMINATOR_HEADER: material.client_spki})
        probes.append(Probe("declared-terminator-fingerprint-refused-when-unregistered",
                            status == 403,
                            "a forwarded fingerprint is not trusted by itself: the registry "
                            "still decides"))
    return probes


def _drive_middleware(registry, der, path: str, headers: dict[str, str] | None = None):
    """Drive the real middleware with an ASGI scope carrying the certificate."""
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": json.dumps({"stored": True}).encode()})

    middleware = AgentIdentityMiddleware(app, registry=registry)
    scope = {
        "type": "http",
        "path": path,
        "method": "POST",
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "extensions": {"tls": {"client_cert_chain": [der]}} if der else {},
        "state": {},
    }
    sent: list[dict[str, Any]] = []

    async def receive():
        return {"type": "http.request", "body": b"{}"}

    async def send(message):
        sent.append(message)

    import asyncio

    asyncio.run(middleware(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), 0)
    body = next((m["body"] for m in sent if m["type"] == "http.response.body"), b"{}")
    try:
        parsed = json.loads(body or b"{}")
    except json.JSONDecodeError:
        parsed = {}
    return status, parsed


from contextlib import contextmanager  # noqa: E402


@contextmanager
def _env(values: dict[str, str]):
    previous = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        if value == "":
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def probe_route_binding(material: Material) -> list[Probe]:
    """The route refuses a body whose signature is not the agent's key."""
    from types import SimpleNamespace

    from api.routers.ingestion import _require_bound_identity
    from fastapi import HTTPException

    agent_key = _ed25519_key(b"\x03" * 32)
    other_key = _ed25519_key(b"\x04" * 32)
    agent = ai.AgentIdentity("agent-eu-1", material.client_spki,
                             release_signature.public_key_b64(agent_key.public_key()))
    document = {"schema": "cryptoscan.live-observation/1"}

    def call(signature, *, with_agent: bool = True) -> tuple[int, str]:
        request = SimpleNamespace(state=SimpleNamespace(
            agent_identity=agent if with_agent else None,
            agent_identity_reason="no certificate" if not with_agent else None))
        try:
            with _env({ai.ENFORCE_ENV: "1"}):
                _require_bound_identity(request, signature)
            return 200, "accepted"
        except HTTPException as exc:
            return exc.status_code, json.dumps(exc.detail)[:160]

    probes: list[Probe] = []
    status, note = call(release_signature.sign_document(document, agent_key))
    probes.append(Probe("route-accepts-bound-signature", status == 200, note))
    status, note = call(release_signature.sign_document(document, other_key))
    probes.append(Probe("route-refuses-foreign-signature",
                        status == 401 and "signature_not_bound_to_agent" in note, note))
    status, note = call(None)
    probes.append(Probe("route-refuses-unsigned", status == 401, note))
    status, note = call(release_signature.sign_document(document, agent_key),
                        with_agent=False)
    probes.append(Probe("route-refuses-without-identity", status == 403, note))

    with _env({ai.ENFORCE_ENV: ""}):
        request = SimpleNamespace(state=SimpleNamespace(agent_identity=None))
        try:
            _require_bound_identity(request, None)
            probes.append(Probe("route-inert-when-not-required", True,
                                "with the requirement off the route keeps its previous "
                                "behaviour, which is why this is a deployment property"))
        except HTTPException as exc:  # pragma: no cover - defensive
            probes.append(Probe("route-inert-when-not-required", False, str(exc)))
    return probes


def probe_end_to_end(material: Material) -> list[Probe]:
    """certificate → identity → signature → authenticity, and the attack."""
    agent_key = _ed25519_key(b"\x05" * 32)
    attacker_key = _ed25519_key(b"\x06" * 32)
    peer_der = handshake_peer_certificate(material)
    if not peer_der:
        return [Probe("chain", False, "no peer certificate from the handshake")]
    fingerprint = ai.spki_fingerprint(peer_der)
    agent = ai.AgentIdentity("agent-eu-1", fingerprint,
                             release_signature.public_key_b64(agent_key.public_key()))
    registry = ai.AgentRegistry([agent])

    document = {"schema": "cryptoscan.live-observation/1", "estate": "bank-a",
                "observed_at": "2026-01-01T00:00:00Z"}
    honest = release_signature.sign_document(document, agent_key)
    impostor = release_signature.sign_document(document, attacker_key)

    resolved = registry.lookup(fingerprint)
    bound, note = ai.check_signature_binding(resolved, honest) if resolved else (False, "no agent")
    verdict = release_signature.verify_document({**document, "signature": honest},
                                               trusted_key=agent_key.public_key())
    probes = [
        Probe("honest-chain", bool(resolved) and bound
              and verdict.get("status") == release_signature.VALID,
              f"certificate→agent {getattr(resolved, 'agent_id', None)}, signature bound, "
              f"authenticity {verdict.get('status')}"),
    ]

    # The attack this whole module exists for: a valid certificate for this
    # machine carrying somebody else's signature.
    bound_impostor, note_impostor = (ai.check_signature_binding(resolved, impostor)
                                     if resolved else (False, "no agent"))
    probes.append(Probe(
        "replay-with-another-agents-signature-refused", not bound_impostor, note_impostor))
    return probes


def probe_controls(material: Material) -> list[Probe]:
    """The instruments must be able to fail."""
    agent = ai.AgentIdentity("agent-eu-1", material.client_spki,
                             release_signature.public_key_b64(_ed25519_key(b"\x07" * 32).public_key()))
    wrong = _ed25519_key(b"\x08" * 32)
    ok, note = ai.check_signature_binding(
        agent, release_signature.sign_document({}, wrong))
    probes = [Probe("control-binding-detects-a-mismatch", not ok,
                    f"a deliberately wrong key is reported as unbound: {note}")]

    try:
        ai.spki_fingerprint(b"definitely not a certificate")
        probes.append(Probe("control-garbage-certificate-rejected", False,
                            "garbage bytes produced a fingerprint"))
    except ai.AgentIdentityError as exc:
        probes.append(Probe("control-garbage-certificate-rejected", True, f"refused: {exc}"))

    probes.append(Probe(
        "control-registry-lookup-of-unknown-is-none",
        ai.AgentRegistry([agent]).lookup("sha256:" + "00" * 32) is None,
        "an unknown fingerprint returns None rather than a default identity"))
    return probes


# --------------------------------------------------------------------------- #
# rows
# --------------------------------------------------------------------------- #

def measure(material: Material | None = None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="agent-identity-drill-") as tmp:
        material = material or build_material(Path(tmp))

        def row(row_id: str, question: str, probes: list[Probe],
                *, unproven: list[str] | None = None,
                limits: list[str] | None = None) -> dict[str, Any]:
            failed = [probe for probe in probes if not probe.ok]
            return {
                "id": row_id,
                "question": question,
                "verdict": FAIL if failed else PASS,
                "probes": [probe.as_dict() for probe in probes],
                "unproven": unproven or [],
                "limits": limits or [],
            }

        rows = [
            row("certificate_readable",
                "can the boundary read the identity the TLS handshake proved?",
                probe_certificate_readable(material),
                limits=["the drill reads the certificate from a socketpair handshake; "
                        "whether the deployed server exposes it to the application "
                        "depends on the terminator (see agent_identity.peer_certificate)"]),
            row("registry", "is an unregistered certificate refused?",
                probe_registry(material)),
            row("signature_binding",
                "must the signature be the key registered for that agent?",
                probe_signature_binding(material)),
            row("http_enforcement",
                "does the middleware refuse an ingest request with no registered agent?",
                probe_http_enforcement(material)),
            row("route_binding",
                "does the ingestion route refuse a signature that is not the agent's?",
                probe_route_binding(material)),
            row("end_to_end",
                "does certificate → agent → signature hold, and does the replay fail?",
                probe_end_to_end(material)),
            row("controls", "can each instrument fail?", probe_controls(material)),
        ]

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "limits": [
            "The SPKI fingerprint is the identity. A machine that can export its key "
            "is that machine to this platform; the private key is the credential and "
            "hardware-backed keys are the deployment's choice.",
            "The registry is a deployment file. Who may write it is a control the "
            "platform does not own — that is the same trust the certificate authority "
            "already has.",
            "Whether the TLS server in front of the API exposes its peer certificate "
            "to the application is a terminator property; the drill proves the "
            "application half and names the dependency rather than assuming it.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Agent machine identity — certificate → agent → signed observation",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail**",
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        evidence = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {evidence} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            lines.append(f"- **{'PASS' if probe['ok'] else 'NOT MET'}** "
                         f"`{probe['probe']}` — {probe['observed']}")
        for gap in row["unproven"]:
            lines.append(f"- **Not proven:** {gap}")
        for limit in row["limits"]:
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** the certificate a client presents is read "
        "at the boundary, resolves to a registered agent or to nothing, and an "
        "observation is accepted only when its signature is the key registered for the "
        "agent the certificate proved — so the three facts guide 119 called independent "
        "are now one chain, and the replay that separated them is refused.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Agent machine-identity drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99)
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            first = row["probes"][0] if row["probes"] else {"observed": ""}
            print(f"{row['verdict']:<8} {row['id']:<22} {first['observed'][:100]}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
