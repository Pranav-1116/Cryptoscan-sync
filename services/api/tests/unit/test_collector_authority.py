"""Collector authority: the six questions answered by one code path, per plane.

Guide 116 graded ten of eleven collector planes GAP because the questions were
answered by different mechanisms in different places. These tests pin the build
that closed it: every plane declares its authority, every collection answers all
six questions, and each refusal names the question that failed. Every control has
a negative next to it — an approval that is revoked, a revision that has moved on,
a target that is a subnet — because a matrix that only ever sees valid input
proves nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

P = "/api/v1"
ALL = ("NETWORK", "RUNTIME", "STATIC", "PKI", "CLOUD", "KUBERNETES", "CMDB", "KMS",
       "HSM", "HARDWARE", "VENDOR")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/authority.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as built:
        from api.security.passwords import hash_password
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        with SessionLocal() as s:
            repo = UserRepository(s)
            repo.create_user("chief", hash_password("Chief-Password-2026!"),
                             roles=["superadmin"])
            repo.create_user("builder", hash_password("Builder-Password-2026!"),
                             roles=["developer"])
            # A tenant member, because the tenancy middleware refuses an
            # authenticated principal with no estate — that is guide 121's
            # boundary, not this one, and it would mask the permission refusal
            # this file is measuring.
            from db.repositories.tenant_repository import TenantRepository

            tenants = TenantRepository(s)
            bank = tenants.create(name="Drill Bank", slug="drill-bank")
            tenants.add_member(bank.id, "builder", "member")
            s.commit()
        yield built
    get_settings.cache_clear()


def token_for(username: str) -> str:
    from api.security.session_manager import SessionManager

    roles = ["superadmin"] if username == "chief" else ["developer"]
    return SessionManager().create_session(username, roles=roles)


def headers(username: str = "chief") -> dict[str, str]:
    return {"Authorization": f"Bearer {token_for(username)}"}


def approve(client, plane: str = "NETWORK", **body) -> dict:
    response = client.post(f"{P}/collectors/authority/{plane}", json=body, headers=headers())
    assert response.status_code == 200, response.text
    return response.json()


def authorize(client, **body):
    payload = {"plane": "NETWORK", "target": "bank.example:443", "requests": 1}
    payload.update(body)
    return client.post(f"{P}/collectors/authorize", json=payload, headers=headers())


# --------------------------------------------------------------------- matrix --- #


def test_every_plane_is_named_and_none_starts_approved(client):
    """No defaults: an approval nobody signed is not an approval."""
    body = client.get(f"{P}/collectors/authority", headers=headers()).json()

    assert [row["plane"] for row in body["planes"]] == list(ALL)
    assert body["counts"] == {"planes": 11, "approved": 0, "unapproved": 11}
    assert all(row["gaps"] == ["NO_APPROVAL"] for row in body["planes"])
    assert all(row["permission"] and row["target_kind"] for row in body["planes"])
    assert body["questions"].keys() == {"who", "what_target", "which_revision",
                                        "when", "how_long", "permission"}


def test_the_matrix_needs_a_governance_reader(client):
    assert client.get(f"{P}/collectors/authority").status_code == 401
    assert client.get(f"{P}/collectors/authority",
                      headers=headers("builder")).status_code == 403


# ------------------------------------------------------------------- decision --- #


def test_without_an_approval_every_question_is_still_answered(client):
    decision = authorize(client).json()

    assert decision["allowed"] is False
    assert sorted(decision["answers"]) == sorted(
        ["who", "what_target", "which_revision", "when", "how_long", "permission"])
    assert [refusal["code"] for refusal in decision["refusals"]] == ["NO_APPROVAL"]
    assert decision["refusals"][0]["question"] == "which_revision"


def test_who_is_answered_by_the_session_gate(client):
    """An authorize call with no session is not a decision, it is a 401."""
    assert client.post(f"{P}/collectors/authorize", json={
        "plane": "NETWORK", "target": "bank.example:443"}).status_code == 401


def test_permission_is_the_planes_not_the_routes(client):
    """A developer may trigger scans; that does not make them a runtime ingester."""
    approve(client, "RUNTIME", valid_days=30)
    decision = client.post(f"{P}/collectors/authorize", headers=headers("builder"),
                           json={"plane": "RUNTIME", "target": "app01",
                                 "revision": 1, "requests": 1}).json()

    assert decision["allowed"] is False
    assert [refusal["code"] for refusal in decision["refusals"]] == ["PERMISSION_DENIED"]
    assert decision["refusals"][0]["question"] == "permission"


def test_a_named_target_is_accepted_and_a_wildcard_is_not(client):
    approval = approve(client, "NETWORK", valid_days=30)
    ok = authorize(client, revision=approval["revision"]).json()
    wildcard = authorize(client, target="*", revision=approval["revision"]).json()
    subnet = authorize(client, target="10.0.0.0/8", revision=approval["revision"]).json()
    wrong_plane = authorize(client, target="app01", revision=approval["revision"]).json()

    assert ok["allowed"] is True, ok
    for refused in (wildcard, subnet, wrong_plane):
        assert refused["allowed"] is False
        assert refused["refusals"][0]["code"] == "TARGET_REFUSED"
        assert refused["refusals"][0]["question"] == "what_target"


def test_the_revision_is_pinned_and_a_reaapproval_makes_the_old_one_stale(client):
    first = approve(client, "NETWORK", valid_days=30)
    second = approve(client, "NETWORK", valid_days=30, max_requests=10)

    assert second["revision"] == first["revision"] + 1
    stale = authorize(client, revision=first["revision"]).json()
    unnamed = authorize(client).json()

    assert stale["refusals"][0]["code"] == "STALE_REVISION"
    assert unnamed["refusals"][0]["code"] == "STALE_REVISION"
    assert authorize(client, revision=second["revision"]).json()["allowed"] is True


def test_the_approval_window_expires(client):
    from api.security import collector_authority as authority
    from db.connection.session import SessionLocal
    from db.models.collector_authority import CollectorAuthority

    approve(client, "NETWORK", valid_days=1)
    with SessionLocal() as s:
        row = s.query(CollectorAuthority).filter_by(plane="NETWORK").one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        s.commit()
        decision = authority.evaluate(s, plane="NETWORK", principal="chief",
                                      roles=["superadmin"], target="bank.example:443",
                                      revision=row.revision)
    assert decision.allowed is False
    assert [refusal["code"] for refusal in decision.refusals] == ["OUTSIDE_WINDOW"]


def test_the_budget_is_spent_and_refuses_the_request_that_would_exceed_it(client):
    approval = approve(client, "NETWORK", valid_days=30, max_requests=2)
    revision = approval["revision"]

    first = authorize(client, revision=revision).json()
    second = authorize(client, revision=revision).json()
    third = authorize(client, revision=revision).json()

    assert (first["allowed"], first["remaining_requests"]) == (True, 1)
    assert (second["allowed"], second["remaining_requests"]) == (True, 0)
    assert third["allowed"] is False
    assert third["refusals"][0] == {**third["refusals"][0], "code": "EXHAUSTED",
                                    "question": "how_long"}


def test_the_runtime_budget_is_a_second_limit(client):
    approval = approve(client, "NETWORK", valid_days=30, max_runtime_seconds=60)
    revision = approval["revision"]

    assert authorize(client, revision=revision,
                     runtime_seconds=60).json()["allowed"] is True
    refused = authorize(client, revision=revision, runtime_seconds=1).json()

    assert refused["allowed"] is False
    assert refused["refusals"][0]["code"] == "EXHAUSTED"


def test_revocation_stops_collection_and_keeps_the_row(client):
    approval = approve(client, "KMS", valid_days=30)
    revoked = client.post(f"{P}/collectors/authority/KMS/revoke", json={"reason": "rotated"},
                          headers=headers())
    assert revoked.status_code == 200
    decision = authorize(client, plane="KMS", target="kms:arn:aws:kms:eu-west-1:1:key/abc",
                         revision=approval["revision"]).json()
    matrix = {row["plane"]: row for row in
              client.get(f"{P}/collectors/authority", headers=headers()).json()["planes"]}

    assert decision["allowed"] is False
    assert decision["refusals"][0]["code"] == "REVOKED"
    assert matrix["KMS"]["approved"] is False
    assert matrix["KMS"]["gaps"] == ["REVOKED"]
    # the row survives the revocation: "who withdrew what, when" is a fact
    assert matrix["KMS"]["revision"] == approval["revision"]


def test_an_approval_against_a_permission_nothing_checks_is_refused(client):
    response = client.post(f"{P}/collectors/authority/NETWORK",
                           json={"permission": "made.up.permission"}, headers=headers())
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "PERMISSION_DENIED"


def test_approving_is_platform_work_not_collector_work(client):
    response = client.post(f"{P}/collectors/authority/NETWORK", json={},
                           headers=headers("builder"))
    assert response.status_code == 403
    assert client.post(f"{P}/collectors/authority/NOT_A_PLANE", json={},
                       headers=headers()).status_code == 422
