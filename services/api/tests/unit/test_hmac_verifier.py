import hashlib
import hmac

from api.security.hmac_verifier import HMACVerifier


def test_valid_signature():
    body = b'{"ok":true}'
    secret = "super-secret"
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert HMACVerifier(secret).verify(body, f"sha256={sig}")


def test_invalid_signature():
    assert not HMACVerifier("secret").verify(b"{}", "sha256=deadbeef")
