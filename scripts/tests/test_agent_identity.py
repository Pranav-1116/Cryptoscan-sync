"""Tests for agent machine identity — the certificate → agent → signature chain.

The point of the module is that the three facts are one chain, so the tests check
both halves: an honest chain is accepted, and every way of breaking the chain is
refused. Each refusal is paired with the control that proves the check can see the
difference (a matching key must pass, or "everything is refused" would look like
security).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _relative in ("services/api", "services/database", "shared/shared_models",
                  "shared/shared_config"):
    sys.path.insert(0, str(ROOT / _relative))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "agent-identity-test-key-32-characters")

from api.security import agent_identity as ai  # noqa: E402
from shared_models import release_signature  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
import agent_identity as drill  # noqa: E402


# --------------------------------------------------------------------------- #
# material
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def material(tmp_path_factory) -> drill.Material:
    return drill.build_material(tmp_path_factory.mktemp("certs"))


def _key(seed: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed)


# --------------------------------------------------------------------------- #
# fingerprint
# --------------------------------------------------------------------------- #

def test_fingerprint_is_over_the_key_so_a_reissued_certificate_keeps_identity(material):
    reissued = drill._make_cert(common_name="agent-eu-1", is_ca=False)[0]
    from cryptography.hazmat.primitives import serialization

    original = ai.spki_fingerprint(material.client_der)
    assert ai.spki_fingerprint(reissued.public_bytes(serialization.Encoding.DER)) != original, \
        "a different key must not inherit the identity"
    # Same key, new certificate: identical fingerprint by construction.
    assert ai.spki_fingerprint(material.client_der) == original


def test_garbage_is_not_a_fingerprint():
    with pytest.raises(ai.AgentIdentityError):
        ai.spki_fingerprint(b"not a certificate")
    with pytest.raises(ai.AgentIdentityError):
        ai.normalise_fingerprint("sha256:zz")


def test_fingerprint_normalisation_accepts_case_and_colons():
    hex_value = "ab" * 32
    assert ai.normalise_fingerprint(hex_value.upper()) == f"sha256:{hex_value}"
    assert ai.normalise_fingerprint("SHA256:" + ":".join(
        [hex_value[i:i + 2] for i in range(0, 64, 2)])) == f"sha256:{hex_value}"


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

def _agent(material, key=None, agent_id="agent-eu-1") -> ai.AgentIdentity:
    key = key or _key(b"\x11" * 32)
    return ai.AgentIdentity(agent_id, material.client_spki,
                            release_signature.public_key_b64(key.public_key()),
                            "bank-a")


def test_registered_agent_resolves_and_unknown_does_not(material):
    registry = ai.AgentRegistry([_agent(material)])
    assert registry.lookup(material.client_spki).agent_id == "agent-eu-1"
    assert registry.lookup("sha256:" + "00" * 32) is None


def test_duplicate_fingerprint_is_refused(material):
    with pytest.raises(ai.AgentIdentityError):
        ai.AgentRegistry([_agent(material, agent_id="a"), _agent(material, agent_id="b")])


def test_malformed_registry_fails_closed(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"agents": [{"agent_id": "half"}]}))
    with pytest.raises(ai.AgentIdentityError):
        ai.AgentRegistry.from_file(path)

    path.write_text("not json")
    with pytest.raises(ai.AgentIdentityError):
        ai.AgentRegistry.from_file(path)

    path.write_text(json.dumps({"nope": []}))
    with pytest.raises(ai.AgentIdentityError):
        ai.AgentRegistry.from_file(path)


def test_empty_registry_refuses_everything(material, monkeypatch):
    monkeypatch.delenv(ai.REGISTRY_ENV, raising=False)
    empty = ai.AgentRegistry.from_env({})
    assert len(empty) == 0
    assert empty.lookup(material.client_spki) is None


def test_registry_loads_from_the_declared_file(material, tmp_path, monkeypatch):
    agent = _agent(material)
    path = tmp_path / "agents.json"
    path.write_text(json.dumps({"agents": [{
        "agent_id": agent.agent_id, "spki": agent.spki,
        "signing_key": agent.signing_key, "tenant": agent.tenant}]}))
    monkeypatch.setenv(ai.REGISTRY_ENV, str(path))
    registry = ai.AgentRegistry.from_env()
    assert registry.lookup(material.client_spki).agent_id == "agent-eu-1"


# --------------------------------------------------------------------------- #
# signature binding
# --------------------------------------------------------------------------- #

def test_bound_key_passes_and_every_other_shape_is_refused(material):
    agent_key, other_key = _key(b"\x21" * 32), _key(b"\x22" * 32)
    agent = _agent(material, agent_key)
    document = {"schema": "cryptoscan.live-observation/1"}
    bound = release_signature.sign_document(document, agent_key)

    ok, reason = ai.check_signature_binding(agent, bound)
    assert ok, reason

    ok, reason = ai.check_signature_binding(
        agent, release_signature.sign_document(document, other_key))
    assert not ok and "not the key registered" in reason

    ok, reason = ai.check_signature_binding(agent, None)
    assert not ok and "no signature" in reason

    swapped = dict(bound, public_key=base64.b64encode(b"x" * 32).decode())
    ok, reason = ai.check_signature_binding(agent, swapped)
    assert not ok

    ok, reason = ai.check_signature_binding(agent, dict(bound, public_key="!!not base64!!"))
    assert not ok


# --------------------------------------------------------------------------- #
# middleware + route
# --------------------------------------------------------------------------- #

def test_middleware_admits_only_a_registered_certificate(material, monkeypatch):
    from asyncio import run as arun

    from api.middleware.agent_identity_middleware import AgentIdentityMiddleware

    agent = _agent(material)
    middleware = AgentIdentityMiddleware(lambda *a: None, registry=ai.AgentRegistry([agent]))

    async def driven(der, path="/api/v1/ingestion/observations", headers=None):
        sent = []

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        mw = AgentIdentityMiddleware(app, registry=ai.AgentRegistry([agent]))
        scope = {"type": "http", "path": path, "method": "POST",
                 "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
                 "extensions": {"tls": {"client_cert_chain": [der]}} if der else {},
                 "state": {}}

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(message):
            sent.append(message)

        await mw(scope, receive, send)
        return next(m["status"] for m in sent if m["type"] == "http.response.start")

    monkeypatch.setenv(ai.ENFORCE_ENV, "1")
    assert arun(driven(material.client_der)) == 200
    assert arun(driven(b"garbage")) == 403
    assert arun(driven(None)) == 403
    assert arun(driven(None, path="/__drill/non-ingest-surface")) == 200

    monkeypatch.delenv(ai.ENFORCE_ENV, raising=False)
    assert arun(driven(None)) == 200, "the middleware must be inert when not required"
    assert middleware is not None


def test_unreadable_registry_fails_closed_at_the_middleware(material, monkeypatch, tmp_path):
    from asyncio import run as arun

    from api.middleware.agent_identity_middleware import AgentIdentityMiddleware

    broken = tmp_path / "registry.json"
    broken.write_text("{ not json")
    monkeypatch.setenv(ai.ENFORCE_ENV, "1")
    monkeypatch.setenv(ai.REGISTRY_ENV, str(broken))

    sent = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    mw = AgentIdentityMiddleware(app)
    scope = {"type": "http", "path": "/api/v1/ingestion/observations", "method": "POST",
             "headers": [], "extensions": {"tls": {"client_cert_chain": [material.client_der]}},
             "state": {}}

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    arun(mw(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 403, "an unreadable registry must refuse, not trust"


def test_route_refuses_a_signature_that_is_not_the_agents(material, monkeypatch):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from api.routers.ingestion import _require_bound_identity

    agent_key, other_key = _key(b"\x31" * 32), _key(b"\x32" * 32)
    agent = _agent(material, agent_key)
    document = {"schema": "cryptoscan.live-observation/1"}
    request = SimpleNamespace(state=SimpleNamespace(agent_identity=agent))

    monkeypatch.setenv(ai.ENFORCE_ENV, "1")
    _require_bound_identity(request, release_signature.sign_document(document, agent_key))

    with pytest.raises(HTTPException) as foreign:
        _require_bound_identity(request, release_signature.sign_document(document, other_key))
    assert foreign.value.status_code == 401
    assert foreign.value.detail["error"] == "signature_not_bound_to_agent"

    with pytest.raises(HTTPException) as unsigned:
        _require_bound_identity(request, None)
    assert unsigned.value.status_code == 401

    absent = SimpleNamespace(state=SimpleNamespace(agent_identity=None))
    with pytest.raises(HTTPException) as no_identity:
        _require_bound_identity(absent, release_signature.sign_document(document, agent_key))
    assert no_identity.value.status_code == 403

    monkeypatch.delenv(ai.ENFORCE_ENV, raising=False)
    _require_bound_identity(SimpleNamespace(state=SimpleNamespace(agent_identity=None)), None)


# --------------------------------------------------------------------------- #
# the drill itself
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def report(material) -> dict:
    return drill.measure(material)


def test_every_row_ran_and_passes(report):
    assert report["schema"] == drill.SCHEMA
    assert report["counts"]["FAIL"] == 0, report["rows"]
    assert report["counts"]["PASS"] == len(report["rows"])
    for row in report["rows"]:
        assert row["probes"], f"{row['id']} has no probe"


def test_the_drill_has_controls_that_would_fail(report):
    controls = next(row for row in report["rows"] if row["id"] == "controls")
    names = {probe["probe"] for probe in controls["probes"]}
    assert "control-binding-detects-a-mismatch" in names
    assert "control-garbage-certificate-rejected" in names


def test_the_replay_attack_is_the_one_that_is_refused(report):
    row = next(row for row in report["rows"] if row["id"] == "end_to_end")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["honest-chain"]["ok"] is True
    assert probes["replay-with-another-agents-signature-refused"]["ok"] is True


def test_cli_writes_reports(tmp_path, material):
    json_path, md_path = tmp_path / "ai.json", tmp_path / "ai.md"
    assert drill.main(["--json", str(json_path), "--md", str(md_path)]) == 0
    payload = json.loads(json_path.read_text())
    assert payload["schema"] == drill.SCHEMA
    assert "Agent machine identity" in md_path.read_text()


def test_generated_at_is_utc_iso(report):
    stamp = dt.datetime.fromisoformat(report["generated_at"])
    assert stamp.tzinfo is not None
