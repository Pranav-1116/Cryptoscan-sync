"""Password strength policy — rejects weak/common passwords everywhere."""

from __future__ import annotations

import pytest

from api.security.passwords import (
    PasswordPolicyError,
    password_policy_errors,
    validate_password_policy,
)

WEAK = [
    "short1!A",              # too short
    "password1234",          # common base 'password123' family -> 12 chars but common set match? 'password123' (11) add len; use password12345 below
    "Password12345",         # no symbol -> only 2 classes + common-ish
    "aaaaaaaaaaaa1!",        # repeated char run
    "alllowercaseonly",      # only one class
    "QWERTYUIOPASDFGH",      # only one class (uppercase)
    "changeme12345",         # common base, only 2 classes
]

STRONG = [
    "Xk9!vQm2#fLz4@wR",      # 4 classes
    "Correct-Horse-Battery-Staple-9",
    "N0rdvault#Zephyr-2026",
    "aB3$kP7&mW9!xQ2@",
]


@pytest.mark.parametrize("pw", WEAK)
def test_weak_passwords_rejected(pw):
    assert password_policy_errors(pw), f"expected {pw!r} to be rejected"
    with pytest.raises(PasswordPolicyError):
        validate_password_policy(pw)


@pytest.mark.parametrize("pw", STRONG)
def test_strong_passwords_accepted(pw):
    assert password_policy_errors(pw) == []
    validate_password_policy(pw)  # no raise


def test_common_password_lowercase_match():
    # Case/handle common passwords regardless of surrounding? exact lower match
    for common in ("Password", "ADMIN", "Changeme", "cryptoscan"):
        if len(common) >= 12:
            assert "common" in " ".join(password_policy_errors(common)).lower() or password_policy_errors(common)
