"""Integration: deterministic short-lived vault leasing (no AI; reference-only).

Verifies the lease policy gate over the real API + sqlite: scoped TTL leases are
issued and persisted, out-of-scope requests are denied 403, over-long TTLs are
denied, and released leases are tracked. No secret value ever transits the API.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "vault_lease_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


def _make_credential(client, name="ro-cloud", scope="assets:read,findings:read"):
    r = client.post(f"{API}/control/credentials", json={
        "name": name, "kind": "cloud", "vault_provider": "aws_secretsmanager",
        "secret_ref": "arn:aws:secretsmanager:us-east-1:123:secret:zelnx-ro-AbCd",
        "least_privilege_scope": scope, "status": "active", "health_ok": True,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"] if "id" in r.json() else _cred_id(client, name)


def _cred_id(client, name):
    rows = client.get(f"{API}/control/credentials").json()["credentials"]
    return [c for c in rows if c["name"] == name][0]["id"]


class TestVaultLease:
    def test_lease_issued_scoped_and_persisted(self, client):
        cid = _make_credential(client, "ro-cloud-1")
        r = client.post(f"{API}/control/credentials/{cid}/lease", json={
            "component": "cloud_scanner", "scope": ["assets:read"], "ttl_seconds": 300,
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["leased"] is True
        lease = body["lease"]
        assert lease["ttl_seconds"] == 300
        assert lease["status"] == "ACTIVE"
        assert lease["component"] == "cloud_scanner"
        # reference only — no secret value field, locator present
        assert "secret" not in lease or lease["secret_ref"].startswith("arn:")
        assert "value" not in lease

    def test_out_of_scope_lease_denied(self, client):
        cid = _make_credential(client, "ro-cloud-2")
        r = client.post(f"{API}/control/credentials/{cid}/lease", json={
            "component": "cloud_scanner", "scope": ["secrets:write"], "ttl_seconds": 300,
        })
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "SCOPE_EXCEEDED"

    def test_overlong_ttl_denied(self, client):
        cid = _make_credential(client, "ro-cloud-3")
        r = client.post(f"{API}/control/credentials/{cid}/lease", json={
            "component": "cloud_scanner", "scope": ["assets:read"], "ttl_seconds": 100_000,
        })
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "TTL_TOO_LONG"

    def test_inline_secret_material_rejected_at_credential_create(self, client):
        r = client.post(f"{API}/control/credentials", json={
            "name": "evil", "kind": "cloud",
            "secret_ref": "password=hunter2",
        })
        # the credential create endpoint rejects secret-bearing fields; a raw
        # password in secret_ref must not produce a usable credential
        assert r.status_code in (422, 400)

    def test_release_lease(self, client):
        cid = _make_credential(client, "ro-cloud-4")
        lease = client.post(f"{API}/control/credentials/{cid}/lease", json={
            "component": "cloud_scanner", "scope": ["assets:read"], "ttl_seconds": 300,
        }).json()["lease"]
        r = client.post(f"{API}/control/credential-leases/{lease['handle']}/release")
        assert r.status_code == 200 and r.json()["status"] == "RELEASED"
        # double release -> 409
        r2 = client.post(f"{API}/control/credential-leases/{lease['handle']}/release")
        assert r2.status_code == 409

    def test_leases_listed(self, client):
        r = client.get(f"{API}/control/credential-leases")
        assert r.status_code == 200
        assert r.json()["total_count"] >= 1
        assert all("value" not in l for l in r.json()["leases"])
