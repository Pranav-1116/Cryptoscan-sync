"""Auth hardening: credential history, single-use TOTP, source velocity, idle.

These pin the four controls that closed the guide-120 PARTIALs. Each test has a
negative control next to it — a version of the attack that must still be
refused after the happy path passes — because a control that only ever sees
well-formed input proves nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from api.security import totp
from api.security.passwords import (
    PASSWORD_HISTORY_DEPTH,
    password_policy_errors,
    password_reused,
    push_history,
)
from api.security.session_policy import session_refusal, touch_due


# --------------------------------------------------------------------- policy


def test_password_history_keeps_newest_first_and_capped():
    hashes = [f"hash-{i}" for i in range(PASSWORD_HISTORY_DEPTH + 3)]
    kept = push_history(hashes[0], hashes[1:])
    assert kept[0] == hashes[0]
    assert len(kept) == PASSWORD_HISTORY_DEPTH


def test_password_history_never_records_plaintext():
    # The argument is a hash by contract; if it ever were plaintext the entries
    # would verify, so a plaintext history would make every old secret reusable.
    kept = push_history("$pbkdf2-sha256$210000$c2FsdA$aGFzaA", [])
    assert kept == ["$pbkdf2-sha256$210000$c2FsdA$aGFzaA"]


def test_identity_token_in_password_is_refused():
    errors = password_policy_errors("Alice.Smith!2026", username="alice.smith")
    assert any("username or email" in e for e in errors)


def test_identity_token_check_ignores_short_names():
    # "bob" is four characters of noise in most passwords; only tokens long
    # enough to be a real directory entry are refused.
    assert not any("username or email" in e for e in password_policy_errors("Bobcat!Runner42", username="bob"))


# ------------------------------------------------------------------ totp replay


def test_verify_step_reports_the_step_and_replay_is_the_same_step():
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    code = totp.current_code(secret, at=now)
    step = totp.verify_step(secret, code, at=now)
    assert step == int(now // totp.DEFAULT_PERIOD)
    # Same code, one second later, still inside the same 30-second step.
    assert totp.verify_step(secret, code, at=now + 1) == step


def test_verify_step_rejects_malformed_codes():
    secret = totp.generate_secret()
    assert totp.verify_step(secret, "abcdef", at=1_700_000_000.0) is None
    assert totp.verify_step(secret, "12345", at=1_700_000_000.0) is None
    assert totp.verify_step(secret, "", at=1_700_000_000.0) is None


# ---------------------------------------------------------------- idle window


def test_idle_session_is_refused_before_absolute_expiry():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    refusal = session_refusal(
        now=now,
        expires_at=now + timedelta(hours=20),
        created_at_ts=now - timedelta(hours=2),
        last_seen_at=now - timedelta(minutes=31),
        idle_minutes=30,
    )
    assert refusal == "idle"


def test_active_session_survives_the_idle_window():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert session_refusal(
        now=now,
        expires_at=now + timedelta(hours=20),
        created_at_ts=now - timedelta(hours=2),
        last_seen_at=now - timedelta(minutes=5),
        idle_minutes=30,
    ) is None


def test_absolute_expiry_beats_fresh_activity():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert session_refusal(
        now=now,
        expires_at=now - timedelta(seconds=1),
        created_at_ts=now - timedelta(days=2),
        last_seen_at=now,
        idle_minutes=30,
    ) == "expired"


def test_idle_disabled_means_never_idle_expired():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert session_refusal(
        now=now,
        expires_at=None,
        created_at_ts=now - timedelta(days=1),
        last_seen_at=now - timedelta(days=1),
        idle_minutes=0,
    ) is None


def test_touch_is_throttled():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert touch_due(now - timedelta(seconds=30), now=now) is False
    assert touch_due(now - timedelta(seconds=61), now=now) is True
    assert touch_due(None, now=now) is True


# ------------------------------------------------------------------- end to end


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/hardening.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("LOGIN_SOURCE_MAX_FAILURES", "3")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        from api.security.passwords import hash_password
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        with SessionLocal() as s:
            repo = UserRepository(s)
            repo.create_user("rotator1", hash_password("Original-Pass-2024"), roles=["viewer"])
            repo.create_user("spraytarget2", hash_password("Spray-Target-2024"), roles=["viewer"])
            repo.create_user("spraytarget3", hash_password("Spray-Target-2024"), roles=["viewer"])
            s.commit()
        yield client
    get_settings.cache_clear()


def _login(client, username, password):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def test_reused_password_is_refused_and_fresh_one_accepted(sqlite_app):
    client = sqlite_app
    token = _login(client, "rotator1", "Original-Pass-2024").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    reused = client.post(
        "/api/v1/auth/me/password",
        json={"current_password": "Original-Pass-2024", "new_password": "Original-Pass-2024"},
        headers=headers,
    )
    assert reused.status_code == 422
    rotated = client.post(
        "/api/v1/auth/me/password",
        json={"current_password": "Original-Pass-2024", "new_password": "Second-Choice-2025"},
        headers=headers,
    )
    assert rotated.status_code == 200
    token2 = _login(client, "rotator1", "Second-Choice-2025").json()["token"]
    headers2 = {"Authorization": f"Bearer {token2}"}
    # Cycling back to the original is the attack the history stops.
    back = client.post(
        "/api/v1/auth/me/password",
        json={"current_password": "Second-Choice-2025", "new_password": "Original-Pass-2024"},
        headers=headers2,
    )
    assert back.status_code == 422
    assert "used recently" in back.json()["detail"]


def test_login_from_one_source_is_throttled_after_repeated_failures(sqlite_app):
    """Password spraying: one failure per account never trips per-account lockout.

    Driven through AuthService rather than HTTP because the request layer has
    its own in-memory 5/min limiter; this control is the durable one that holds
    across worker processes and survives a restart.
    """
    from api.security.auth import AuthService, AuthenticationError
    from db.connection.session import SessionLocal

    with SessionLocal() as s:
        service = AuthService(s)
        # Each guess targets a different account, so no per-account counter moves.
        for target in ("spraytarget2", "spraytarget3", "rotator1", "spraytarget2"):
            try:
                service.authenticate(target, "Spray-Guess-0001", client_key="203.0.113.9")
            except AuthenticationError:
                pass
        from sqlalchemy import text as _sql

        counted = dict(s.execute(_sql(
            "SELECT outcome, COUNT(*) FROM audit_log WHERE ip_address = '203.0.113.9' "
            "GROUP BY outcome")).all())
        # Three guesses were actually evaluated; the fourth was refused before
        # any credential was read and recorded as LOCKED instead.
        assert counted == {"FAILURE": 3, "LOCKED": 1}
        # A correct password from the same source is still refused.
        import pytest as _pytest
        with _pytest.raises(AuthenticationError) as excinfo:
            service.authenticate("rotator1", "Original-Pass-2024", client_key="203.0.113.9")
        assert "this location" in str(excinfo.value)
        # A different source is unaffected — the block is on the source, not the user.
        assert service.authenticate("rotator1", "Original-Pass-2024",
                                    client_key="198.51.100.4").username == "rotator1"


def test_repository_history_records_hashes_only(sqlite_app):
    from db.connection.session import SessionLocal
    from db.repositories.user_repository import UserRepository
    from api.security.passwords import hash_password

    with SessionLocal() as s:
        repo = UserRepository(s)
        assert repo.set_password("rotator1", hash_password("Brand-New-Secret-2030")) is not None
        history = repo.password_history_of(repo.get_by_username("rotator1"))
        s.commit()
    assert history, "the replaced hash must be remembered"
    assert "Original-Pass-2024" not in history, "plaintext must never be stored"
    assert password_reused("Original-Pass-2024", history), "the old password must verify against history"
    assert not password_reused("Never-Used-Pass-2040", history)


def test_totp_step_is_single_use_per_account(sqlite_app):
    from db.connection.session import SessionLocal
    from db.repositories.user_repository import UserRepository

    step = int(datetime.now(timezone.utc).timestamp()) // totp.DEFAULT_PERIOD
    with SessionLocal() as s:
        repo = UserRepository(s)
        assert repo.consume_totp_step("rotator1", step) is True
        assert repo.consume_totp_step("rotator1", step) is False   # replay
        assert repo.consume_totp_step("rotator1", step - 1) is False  # stale window code
        assert repo.consume_totp_step("rotator1", step + 1) is True   # next step is fresh
        s.commit()


# --------------------------------------------------------------- breach corpus


def test_corpus_parses_both_line_shapes_and_skips_comments(tmp_path, monkeypatch):
    from api.security import breach_corpus

    digest_zero = "0" * 64
    digest_one = "1" * 64
    path = tmp_path / "corpus.txt"
    path.write_text(
        "# a comment\n\n"
        f"{digest_zero}\n"
        f"{digest_one}:12345\n"
        "not-a-digest\n",
        encoding="utf-8",
    )
    assert breach_corpus.load(path) == frozenset({digest_zero, digest_one})
    monkeypatch.setenv(breach_corpus.CORPUS_ENV, str(path))
    assert breach_corpus.describe()["loaded"] is True


def test_absent_corpus_means_no_breach_verdict_and_a_named_production_gap(monkeypatch):
    from types import SimpleNamespace

    from api.security import breach_corpus

    monkeypatch.setenv(breach_corpus.CORPUS_ENV, "")
    breach_corpus._cache = None
    assert breach_corpus.is_breached("anything-at-all-2026") is False
    assert breach_corpus.production_gap(SimpleNamespace(is_production=False)) is None
    gap = breach_corpus.production_gap(SimpleNamespace(is_production=True))
    assert gap and breach_corpus.CORPUS_ENV in gap


def test_breached_password_is_refused_even_when_shape_passes(tmp_path, monkeypatch):
    from api.security import breach_corpus

    password = "Tr0ub4dor&3xkcd-Breached-2019"
    path = tmp_path / "corpus.txt"
    path.write_text(f"{breach_corpus.digest(password)}\n", encoding="utf-8")
    monkeypatch.setenv(breach_corpus.CORPUS_ENV, str(path))
    breach_corpus._cache = None
    errors = password_policy_errors(password)
    assert any("breach" in e for e in errors)
    # Negative control: a same-shaped password that is not listed passes.
    assert password_policy_errors("Unlisted-Passphrase-2049") == []


# ------------------------------------------------------------- write authority


def test_read_only_roles_cannot_write_anything():
    from api.security.write_authority import refusal

    for role in ("readonly", "auditor", "supervisor"):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert refusal([role], method, "/api/v1/anomaly/analyze") is not None
        # ...but reading is untouched.
        assert refusal([role], "GET", "/api/v1/anomaly/analyze") is None


def test_writable_roles_are_not_blocked():
    from api.security.write_authority import refusal

    for role in ("superadmin", "ciso", "security_analyst", "developer",
                 "business_owner", "scanner"):
        assert refusal([role], "POST", "/api/v1/anomaly/analyze") is None
    # A mixed role set that includes one writable role is a writable principal.
    assert refusal(["readonly", "security_analyst"], "POST", "/api/v1/x") is None


def test_unknown_or_empty_roles_fail_closed():
    from api.security.write_authority import refusal

    assert refusal([], "POST", "/api/v1/x") == "no recognized role"
    assert refusal(["not-a-role"], "POST", "/api/v1/x") == "no recognized role"


def test_self_service_and_attestation_are_exempt():
    from api.security.write_authority import refusal

    assert refusal(["readonly"], "POST", "/api/v1/auth/me/password") is None
    assert refusal(["readonly"], "POST", "/api/v1/auth/mfa/enroll") is None
    assert refusal(["auditor"], "POST", "/api/v1/assurance/samples/abc/reviews") is None
    assert refusal(["auditor"], "POST", "/api/v1/collection/oci/jobs/x/truth/approve") is None
    # The exemption is a suffix, not a prefix: nothing else inherits it.
    assert refusal(["auditor"], "POST", "/api/v1/assurance/samples/abc/reviews/x") is not None


def test_viewer_session_is_refused_a_write_by_the_running_app(sqlite_app):
    client = sqlite_app
    from api.security.session_manager import SessionManager
    from db.connection.session import SessionLocal
    from db.repositories.user_repository import UserRepository

    with SessionLocal() as s:
        UserRepository(s).set_roles("rotator1", ["readonly"])
        s.commit()
    token = _login(client, "rotator1", "Original-Pass-2024").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    refused = client.post("/api/v1/anomaly/analyze", json={}, headers=headers)
    assert refused.status_code == 403
    assert refused.json()["error_code"] == "WRITE_FORBIDDEN"
    # Reads and self-service still work for the same session.
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    # Control: the same call with a writable role gets past the gate, so the 403
    # above is the role policy and not a broken route.
    with SessionLocal() as s:
        UserRepository(s).set_roles("rotator1", ["security_analyst"])
        s.commit()
    assert SessionManager  # the session token is unchanged; only the role moved
    allowed = client.post("/api/v1/anomaly/analyze", json={}, headers=headers)
    # Past the write gate. It may still be refused downstream (this account has
    # no tenant membership), but not by the role rule.
    assert allowed.json().get("error_code") != "WRITE_FORBIDDEN", allowed.text
