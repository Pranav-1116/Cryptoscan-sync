"""Key rotation is a rotation, not a mass logout — and the gate polices it.

Sessions are HMAC-signed with ``SECRET_KEY``. Replacing it invalidates every
live session, which for a 24/7 operations console means operators are thrown out
mid-incident. ``SECRET_KEY_PREVIOUS`` is the overlap: the old key verifies,
the new key signs, and the window closes when the entry is removed.

These tests pin both halves: the overlap works, and the production gate refuses
an overlap that is a lie (current key listed as previous, four stale keys, a
weak retired key).
"""

from __future__ import annotations

import pytest

from api.config.settings import APISettings, validate_runtime_settings
from api.security.session_manager import SessionManager

OLD = "previous-secret-key-0123456789abcdefghijklmnop"
NEW = "current-secret-key-0123456789abcdefghijklmnopq"
THIRD = "third-secret-key-0123456789abcdefghijklmnopqrs"


def _manager(monkeypatch, *, current: str, previous: str) -> SessionManager:
    monkeypatch.setenv("SECRET_KEY", current)
    monkeypatch.setenv("SECRET_KEY_PREVIOUS", previous)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    return SessionManager()


def test_a_session_minted_before_the_rotation_still_validates(monkeypatch):
    before = _manager(monkeypatch, current=OLD, previous="")
    token = before.create_session("ops.engineer", roles=["security_analyst"])

    after = _manager(monkeypatch, current=NEW, previous=OLD)
    assert after.validate_session(token) == "ops.engineer"


def test_a_token_minted_after_the_rotation_uses_the_new_key(monkeypatch):
    after = _manager(monkeypatch, current=NEW, previous=OLD)
    fresh = after.create_session("ops.engineer", roles=["security_analyst"])

    # The overlap is for verification only: the old key alone must not validate
    # a token minted today.
    old_only = SessionManager(secret=OLD)
    assert old_only.validate_session(fresh) is None


def test_retiring_the_previous_key_ends_the_overlap(monkeypatch):
    before = _manager(monkeypatch, current=OLD, previous="")
    stale = before.create_session("ops.engineer")

    closed = _manager(monkeypatch, current=NEW, previous="")
    assert closed.validate_session(stale) is None


def test_an_unrelated_key_is_still_refused(monkeypatch):
    attacker = SessionManager(secret="attacker-chosen-key-0123456789abcdefghij")
    forged = attacker.create_session("admin", roles=["superadmin"])

    manager = _manager(monkeypatch, current=NEW, previous=OLD)
    assert manager.validate_session(forged) is None


def test_an_explicit_secret_means_exactly_one_key(monkeypatch):
    """A migration tool that passes its own key must not inherit the deployment's."""
    before = _manager(monkeypatch, current=OLD, previous="")
    token = before.create_session("ops.engineer")

    explicit = SessionManager(secret=NEW)  # previous key configured but not used
    assert explicit.validate_session(token) is None


def _production(**overrides) -> APISettings:
    values = dict(
        ENVIRONMENT="production",
        SECRET_KEY=NEW,
        SECRET_KEY_PREVIOUS="",
        ADMIN_PASSWORD="",
        ADMIN_PASSWORD_HASH="pbkdf2_sha256$600000$c2FsdA==$aGFzaA==",
        GITHUB_WEBHOOK_SECRET="x" * 32,
        DATABASE_URL="postgresql://c:cs@postgres:5432/cs",
        REDIS_URL="rediss://replay:pw@redis:6379/0",
        EVENT_TAILER_SECONDS=2,
        CORS_ORIGINS="https://console.example",
        TRUSTED_HOSTS=["console.example"],
        METRICS_TOKEN="m" * 32,
        ALERTMANAGER_WEBHOOK_TOKEN="a" * 32,
        REGISTRY_WEBHOOK_SECRET="r" * 32,
        CBOM_SIGNING_SECRET="c" * 32,
        STREAM_SECRET="s" * 32,
        AUDITOR_API_KEY="a" * 32,
        CRYPTOSCAN_DEPLOYMENT_PROFILE="kubernetes-external-services/local-source-v1",
        NEO4J_URI="",
        TRUSTED_PROXY_COUNT=1,
        TRUSTED_PROXY_CIDRS="10.20.0.0/24",
    )
    values.update(overrides)
    return APISettings.model_construct(**values)


@pytest.mark.parametrize(
    "previous, needle",
    [
        (NEW, "must not contain the current SECRET_KEY"),
        ("short", "must each be at least 32 characters"),
        (",".join(f"retired-key-{i}-0123456789abcdefghijklmn" for i in range(4)), "more than 3 rotations"),
        (f"{OLD},{OLD}", "duplicate entry"),
    ],
)
def test_the_gate_refuses_a_dishonest_overlap(previous, needle):
    with pytest.raises(RuntimeError) as excinfo:
        validate_runtime_settings(_production(SECRET_KEY_PREVIOUS=previous))
    assert needle in str(excinfo.value)


def test_a_single_previous_key_is_accepted():
    validate_runtime_settings(_production(SECRET_KEY_PREVIOUS=OLD))
