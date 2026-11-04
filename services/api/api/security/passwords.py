"""Password hashing (PBKDF2-SHA256) with a plaintext fallback for local development.

The plaintext fallback is refused outright when ENVIRONMENT=production.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import logging
import os

logger = logging.getLogger(__name__)

SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 210_000


def _plaintext_fallback_forbidden() -> bool:
    """True in production, where a non-hashed stored credential must not verify."""
    try:
        from api.config.settings import get_settings

        return bool(get_settings().is_production)
    except Exception:  # settings unavailable -> assume production, fail closed
        from shared_config import environment as platform_environment

        return platform_environment.is_production()


def _iterations() -> int:
    """PBKDF2 work factor for *new* hashes.

    Verification always reads the count from the stored hash, so this only
    changes how expensive hashing is going forward. Under pytest the suite
    hashes and verifies passwords thousands of times per run; a low count there
    keeps it fast without weakening anything a real install writes — production
    ignores the override unless it is set explicitly (and never below the floor).
    """
    import os
    import sys

    raw = os.environ.get("CRYPTOSCAN_PBKDF2_ITERATIONS", "")
    if raw.isdigit():
        return max(int(raw), 1 if "pytest" in sys.modules else 100_000)
    if "pytest" in sys.modules:
        return 1_000
    return DEFAULT_ITERATIONS

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 200

# Common / breached-shaped passwords that are never accepted even if they
# meet the length rule. Kept small and dependency-free (extend as needed).
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "qwerty", "qwerty123",
    "12345678", "123456789", "1234567890", "changeme", "admin", "administrator",
    "cryptoscan", "zelinx", "welcome", "welcome1", "letmein", "iloveyou",
    "abc12345", "football", "monkey123", "dragon123", "master123",
    "p@ssw0rd", "p@ssword", "passw0rd!", "qazwsx123",
})

# Core dictionary words that are weak even when padded with digits/symbols
# (e.g. "Password12345!", "Qwerty-2026"). Matched on leetspeak-normalized stem.
_COMMON_STEMS = frozenset({
    "password", "passw0rd", "qwerty", "changeme", "admin", "administrator",
    "welcome", "letmein", "iloveyou", "football", "monkey", "dragon",
    "master", "cryptoscan", "zelinx", "secret",
})


def _normalized_stem(pw: str) -> str:
    """Lowercase, map symbol-only leet (@→a, $→s), drop digits/other symbols."""
    table = str.maketrans({"@": "a", "$": "s"})
    stem = pw.lower().translate(table)
    return "".join(c for c in stem if c.isalpha())


class PasswordPolicyError(ValueError):
    """Raised when a candidate password fails the strength policy."""


def password_policy_errors(password: str, *, username: str | None = None,
                           email: str | None = None) -> list[str]:
    """Return a list of human-readable policy problems (empty list == OK).

    Policy: 12+ chars; not a common/breached-shaped password; must contain
    at least three of {lowercase, uppercase, digit, symbol}; must not repeat
    a single character more than 3 times in a row; must not contain the
    account's own username or email local-part, which is the first thing an
    attacker who has seen a directory entry tries.
    """
    errors: list[str] = []
    pw = str(password or "")
    if len(pw) < MIN_PASSWORD_LENGTH:
        errors.append(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(pw) > MAX_PASSWORD_LENGTH:
        errors.append(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    from api.security.breach_corpus import is_breached

    if is_breached(pw):
        # Checked before shape rules: a breached password is refused even when
        # it is long and mixed-class, which is exactly the case shape rules miss.
        errors.append("password appears in the configured breach corpus")
    elif pw.lower() in _COMMON_PASSWORDS:
        errors.append("password is too common")
    else:
        stem = _normalized_stem(pw)
        if stem in _COMMON_STEMS or any(
            len(s) >= 5 and s in stem for s in _COMMON_STEMS
        ):
            errors.append("password is based on a common word and too easy to guess")
    identity_tokens = [token for token in (
        (username or "").strip().lower(),
        (email or "").split("@")[0].strip().lower(),
    ) if len(token) >= 4]
    lowered = pw.lower()
    for token in identity_tokens:
        if token in lowered:
            errors.append("password must not contain your username or email address")
            break
    classes = 0
    if any(c.islower() for c in pw):
        classes += 1
    if any(c.isupper() for c in pw):
        classes += 1
    if any(c.isdigit() for c in pw):
        classes += 1
    if any((not c.isalnum()) for c in pw):
        classes += 1
    if classes < 3 and len(pw) >= MIN_PASSWORD_LENGTH:
        errors.append("password must contain at least three of: lowercase, uppercase, digit, symbol")
    # reject long runs of the same character
    run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            run += 1
            if run >= 4:
                errors.append("password must not repeat a character 4+ times")
                break
        else:
            run = 1
    return errors


def validate_password_policy(
    password: str, *, username: str | None = None, email: str | None = None
) -> None:
    """Raise PasswordPolicyError if the password is unacceptable."""
    errors = password_policy_errors(password, username=username, email=email)
    if errors:
        raise PasswordPolicyError("; ".join(errors))


#: How many previous passwords are remembered for the re-use check.
PASSWORD_HISTORY_DEPTH = 5


def password_reused(password: str, history: list[str] | None) -> bool:
    """True when ``password`` still verifies against one of the kept hashes."""
    for previous in history or []:
        # ``verify_password`` never raises on a malformed stored value; a
        # non-string entry is a corrupt row, which is simply not a match.
        if isinstance(previous, str) and previous and verify_password(password, previous):
            return True
    return False


def push_history(current_hash: str | None, history: list[str] | None,
                 *, depth: int = PASSWORD_HISTORY_DEPTH) -> list[str]:
    """Newest-first history with the just-replaced hash at the front, capped."""
    kept = [entry for entry in (history or []) if entry]
    if current_hash:
        kept.insert(0, current_hash)
    return kept[:depth]


def hash_password(password: str, *, iterations: int | None = None) -> str:
    iterations = iterations or _iterations()
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"{SCHEME}${iterations}$"
        f"{binascii.hexlify(salt).decode('ascii')}$"
        f"{binascii.hexlify(digest).decode('ascii')}"
    )


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith(f"{SCHEME}$"):
        try:
            _, iter_s, salt_hex, digest_hex = stored.split("$", 3)
            iterations = int(iter_s)
            salt = binascii.unhexlify(salt_hex)
            expected = binascii.unhexlify(digest_hex)
        except (ValueError, binascii.Error):
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    # Legacy/dev fallback: the stored value is not a PBKDF2 hash, so the only
    # thing we can do is compare it literally. That is never acceptable in
    # production -- accepting it there would let a plaintext ADMIN_PASSWORD (or
    # an un-migrated row) authenticate against an unhashed secret.
    if _plaintext_fallback_forbidden():
        logger.error(
            "rejected login against a non-PBKDF2 stored credential; "
            "re-hash it with hash_password() (scripts/hash_admin_password.py)"
        )
        return False
    left = password.encode("utf-8")
    right = stored.encode("utf-8")
    if len(left) != len(right):
        hmac.compare_digest(left, left)
        return False
    return hmac.compare_digest(left, right)
