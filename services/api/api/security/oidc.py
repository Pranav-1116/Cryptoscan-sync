"""OIDC single sign-on — the verification side, bring your own identity provider.

What this module does: validate an RS256-signed JWT (ID or access token)
presented by a user against the issuer's published JWKS, enforce issuer /
audience / expiry, and map the subject to a local account. Federation means
the IdP owns the credential (and its MFA); CryptoScan mints its usual session
only after the token verifies.

Configuration (all optional — SSO is off until OIDC_ISSUER is set):

    OIDC_ISSUER            e.g. https://sso.corp.example.com/realms/main
    OIDC_CLIENT_ID         expected `aud` (audience) of the token
    OIDC_JWKS_FILE         air-gap mode: path to a saved JWKS JSON document
    OIDC_JWKS_URL          override the discovery-derived JWKS location
    OIDC_AUTO_PROVISION    create a local viewer account on first login
    OIDC_CLOCK_LEEWAY      seconds of exp/iat tolerance (default 60)

Key material is discovered at ``<issuer>/.well-known/openid-configuration``
unless a URL/file is given. Verification is RS256 (the universal IdP default)
via the same backends as report signing — the ``cryptography`` package when
installed, otherwise the ``openssl`` CLI. No network calls happen at import
time; discovery failures are honest errors, never skipped checks.

Not claimed: SAML, ES256, IdP-initiated logout, automatic role mapping —
roles stay assigned locally in CryptoScan.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import base64
import json
import time
import urllib.request
from typing import Any

__all__ = ["OidcError", "discover_jwks_url", "load_jwks", "verify_id_token"]


class OidcError(Exception):
    """Token rejected — message is safe to return to the caller."""


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _unverified(token: str) -> tuple[dict[str, Any], dict[str, Any], str, bytes]:
    parts = str(token).split(".")
    if len(parts) != 3:
        raise OidcError("malformed token: expected header.payload.signature")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise OidcError(f"malformed token JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("malformed token: header and payload must be JSON objects")
    return header, claims, sig_b64, f"{header_b64}.{payload_b64}".encode("ascii")


# --------------------------------------------------------------------- JWKS

_JWKS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_JWKS_TTL_SECONDS = 300.0


def discover_jwks_url(issuer: str, *, timeout: float = 5.0) -> str:
    """Standard OpenID discovery: read the JWKS location from the issuer's metadata."""
    issuer = issuer.rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            document = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OidcError(f"OIDC discovery failed for {issuer}: {exc}") from exc
    jwks_uri = (document or {}).get("jwks_uri")
    if not jwks_uri:
        raise OidcError(f"OIDC discovery document at {url} has no jwks_uri")
    _validate_jwks_uri(str(jwks_uri), issuer)
    return str(jwks_uri)


def _validate_jwks_uri(jwks_uri: str, issuer: str) -> None:
    """Defense-in-depth SSRF guard for the discovered JWKS endpoint.

    A compromised/hostile discovery document must not point the verifier at an
    internal address or a non-TLS URL. Only http(s) is allowed, production
    issuers must use https, and the JWKS host must match the issuer host (an
    IdP never legitimately serves keys from a different origin).
    """
    try:
        from urllib.parse import urlparse

        parsed = urlparse(jwks_uri)
        if parsed.scheme not in {"http", "https"}:
            raise OidcError(f"jwks_uri uses disallowed scheme {parsed.scheme!r}")
        if not parsed.hostname:
            raise OidcError("jwks_uri has no host")
        # Block literal local/metadata targets outright.
        if parsed.hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or parsed.hostname.startswith("169.254."):
            raise OidcError("jwks_uri points to a loopback/metadata address")
        issuer_parsed = urlparse(issuer)
        if issuer_parsed.hostname and parsed.hostname.lower() != issuer_parsed.hostname.lower():
            raise OidcError(
                f"jwks_uri host {parsed.hostname!r} does not match issuer host {issuer_parsed.hostname!r}"
            )
        if issuer.startswith("https://") and parsed.scheme != "https":
            raise OidcError("jwks_uri must use https for an https issuer")
    except OidcError:
        raise
    except Exception as exc:
        raise OidcError(f"unvalidatable jwks_uri: {exc}") from exc


def load_jwks(*, url: str | None = None, path: str | None = None, issuer: str | None = None) -> dict[str, Any]:
    """Fetch (with a small TTL cache) or read the JWKS document."""
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            raise OidcError(f"cannot read OIDC_JWKS_FILE {path}: {exc}") from exc
    if not url and issuer:
        url = discover_jwks_url(issuer)
    if not url:
        raise OidcError("no JWKS source configured (set OIDC_JWKS_URL, OIDC_JWKS_FILE or OIDC_ISSUER)")
    # Validate an explicitly-configured JWKS URL the same way as a discovered one.
    if url and not issuer:
        _validate_jwks_uri(url, url.split("/.well-known/")[0])
    now = time.monotonic()
    cached = _JWKS_CACHE.get(url)
    if cached and now - cached[0] < _JWKS_TTL_SECONDS:
        return cached[1]
    try:
        with urllib.request.urlopen(url, timeout=5.0) as response:
            document = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OidcError(f"cannot fetch JWKS from {url}: {exc}") from exc
    if not isinstance(document.get("keys"), list):
        raise OidcError(f"JWKS at {url} has no keys array")
    _JWKS_CACHE[url] = (now, document)
    return document


# ------------------------------------------------------- RSA key from JWKS

def _int_to_der(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")  # keep sign bit positive
    if raw[0] & 0x80:
        return b"\x00" + raw
    return raw


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_length(len(body)) + body


def _rsa_public_key_pem(jwk: dict[str, Any]) -> bytes:
    """PEM SubjectPublicKeyInfo for the JWKS RSA key (n, e).

    Pure-DER assembly for the openssl-CLI backend; the ``cryptography``
    backend builds the key object directly instead.
    """
    n = int.from_bytes(_b64url_decode(str(jwk["n"])), "big")
    e = int.from_bytes(_b64url_decode(str(jwk["e"])), "big")
    pkcs1 = _der_sequence(
        b"\x02" + _der_length(len(_int_to_der(n))) + _int_to_der(n),
        b"\x02" + _der_length(len(_int_to_der(e))) + _int_to_der(e),
    )
    # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier(rsaEncryption), BIT STRING { pkcs1 } }
    algorithm = _der_sequence(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", b"\x05\x00")
    bit_string = b"\x03" + _der_length(len(pkcs1) + 1) + b"\x00" + pkcs1
    spki = _der_sequence(algorithm, bit_string)
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        + base64.encodebytes(spki).strip()
        + b"\n-----END PUBLIC KEY-----\n"
    )


# ------------------------------------------------------------- verification

def _verify_rs256(signing_input: bytes, signature: bytes, public_pem: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_public_key(public_pem)
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except ImportError:
        pass
    except Exception:
        return False
    # openssl CLI fallback
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pem") as key_file, tempfile.NamedTemporaryFile(
        suffix=".sig"
    ) as sig_file:
        key_file.write(public_pem)
        key_file.flush()
        sig_file.write(signature)
        sig_file.flush()
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", key_file.name, "-signature", sig_file.name],
            input=signing_input, capture_output=True, check=False, timeout=30,
        )
        return proc.returncode == 0


def verify_id_token(
    token: str,
    *,
    issuer: str,
    audience: str | None = None,
    jwks_url: str | None = None,
    jwks_file: str | None = None,
    clock_leeway: int = 60,
) -> dict[str, Any]:
    """Full validation. Returns the claims; raises OidcError on any failure."""
    header, claims, sig_b64, signing_input = _unverified(token)

    alg = str(header.get("alg") or "")
    if alg != "RS256":
        raise OidcError(f"unsupported token algorithm '{alg}' — only RS256 is accepted")
    if alg.lower() == "none" or str(header.get("alg")) == "none":  # explicit, belt and braces
        raise OidcError("unsecured tokens are rejected")

    jwks = load_jwks(url=jwks_url, path=jwks_file, issuer=issuer if not jwks_url else None)
    kid = header.get("kid")
    candidates = [k for k in jwks["keys"] if k.get("kty") == "RSA"]
    if kid:
        matching = [k for k in candidates if k.get("kid") == kid]
        if not matching:
            raise OidcError(f"unknown signing key id '{kid}' (JWKS rotated?)")
        candidates = matching
    if not candidates:
        raise OidcError("JWKS contains no RSA signing keys")

    signature = _b64url_decode(sig_b64)
    if not any(_verify_rs256(signing_input, signature, _rsa_public_key_pem(jwk)) for jwk in candidates):
        raise OidcError("signature verification failed")

    now = int(time.time())
    token_issuer = str(claims.get("iss") or "")
    if token_issuer.rstrip("/") != issuer.rstrip("/"):
        raise OidcError(f"issuer mismatch: token says '{token_issuer}', configured '{issuer}'")
    if audience is not None:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if audience not in audiences:
            raise OidcError("audience mismatch: token is not for this client")
    exp = claims.get("exp")
    if exp is None or now > int(exp) + clock_leeway:
        raise OidcError("token expired")
    iat = claims.get("iat")
    if iat is not None and int(iat) > now + clock_leeway:
        raise OidcError("token issued in the future (clock skew?)")
    return claims


# ------------------------------------------------- authorization-code flow
#
# The token-relay endpoint (POST /auth/oidc) trusts the caller to hand over an
# IdP-issued id_token. Enterprises usually want the classic redirect flow:
# the browser is sent to the IdP, CryptoScan receives the code server-side and
# exchanges it confidentially. Once the id_token exists, the SAME verification
# rules apply — signature, issuer, audience, expiry — plus the nonce bound at
# authorization time.


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _default_fetch(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def _default_post(url: str, data: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def discover_oidc_endpoints(issuer: str, *, timeout: float = 5.0, fetch=None) -> dict[str, str]:
    """Read authorization/token endpoints from the issuer's discovery document.

    Same SSRF discipline as JWKS discovery: a hostile document must not point
    us at a different host, a loopback/metadata address or a non-TLS URL.
    """
    reader = fetch or _default_fetch
    base = issuer.rstrip("/")
    url = f"{base}/.well-known/openid-configuration"
    try:
        document = json.loads(reader(url, timeout).decode("utf-8"))
    except Exception as exc:
        raise OidcError(f"OIDC discovery failed for {issuer}: {exc}") from exc
    out: dict[str, str] = {}
    for field in ("authorization_endpoint", "token_endpoint"):
        value = str((document or {}).get(field) or "").strip()
        if not value:
            continue
        _validate_jwks_uri(value, base)  # shared guard: same host, https for https issuers
        out[field] = value
    if "token_endpoint" not in out:
        raise OidcError(f"discovery document at {url} has no token_endpoint")
    return out


def make_authorize_url(authorization_endpoint: str, *, client_id: str,
                       redirect_uri: str, scope: str, state: str, nonce: str,
                       code_challenge: str = "") -> str:
    from urllib.parse import urlencode

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope or "openid",
        "state": state,
        "nonce": nonce,
    }
    if code_challenge:
        # RFC 7636 PKCE, S256 — used whenever no client secret is configured
        # (public client); the verifier itself never travels the front channel.
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    params = urlencode(params)
    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{params}"


def make_pkce() -> tuple[str, str]:
    """RFC 7636 PKCE pair: (code_verifier, S256 code_challenge).

    Verifier is 64 base64url characters (within the required 43..128);
    challenge is base64url(SHA256(verifier)) with no padding.
    """
    import hashlib
    import secrets as _secrets

    verifier = _b64url_encode(_secrets.token_bytes(48))
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def exchange_code(token_endpoint: str, *, code: str, client_id: str, redirect_uri: str,
                  client_secret: str = "", timeout: float = 5.0, poster=None,
                  code_verifier: str = "") -> dict[str, Any]:
    """Confidential-client code exchange (RFC 6749 §4.1.3).

    Returns the raw token response; the caller verifies the contained
    id_token. When no client secret is configured the parameter is simply
    omitted (public client) — honest, not silently substituted. A PKCE
    code_verifier is included when provided (RFC 7636 §4.5).
    """
    from urllib.parse import urlencode

    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if client_secret:
        form["client_secret"] = client_secret
    if code_verifier:
        form["code_verifier"] = code_verifier
    poster_fn = poster or _default_post
    try:
        raw = poster_fn(token_endpoint, urlencode(form).encode("utf-8"), timeout)
    except OidcError:
        raise
    except Exception as exc:
        raise OidcError(f"code exchange failed: {exc}") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise OidcError(f"token endpoint returned non-JSON: {exc}") from exc
    if isinstance(document, dict) and document.get("error"):
        raise OidcError(f"token endpoint error: {document.get('error')}")
    return document


def make_state(secret: str, nonce: str, *, now: float | None = None) -> str:
    """Signed, self-contained OAuth state: base64url(payload).base64url(HMAC).

    Carries the nonce and issue time so the callback needs no server-side
    session store. The HMAC key is the platform SECRET_KEY.
    """
    import hashlib
    import hmac

    payload = _b64url_encode(json.dumps(
        {"nonce": nonce, "iat": int(now if now is not None else time.time())}).encode("utf-8"))
    signature = _b64url_encode(
        hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def read_state(secret: str, state: str, *, now: float | None = None, max_age: int = 600) -> str | None:
    """Return the nonce iff the signature verifies and the state is fresh."""
    import hashlib
    import hmac

    try:
        payload, signature = state.split(".", 1)
    except ValueError:
        return None
    expected = _b64url_encode(
        hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        data = json.loads(_b64url_decode(payload).decode("utf-8"))
        issued = int(data.get("iat") or 0)
        current = int(now if now is not None else time.time())
        nonce = str(data.get("nonce") or "")
        if not nonce or issued > current + 60 or current - issued > max_age:
            return None
        return nonce
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
