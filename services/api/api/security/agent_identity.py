"""Agent machine identity: bind the mTLS peer certificate to the agent that signs.

The gap this closes
-------------------
Guide 119 recorded it plainly: the platform could prove *two independent facts* —
"this TLS client presented a certificate signed by the site CA" and "this payload
carries a valid Ed25519 signature" — but not that they belonged to the same
machine. An attacker who held **any** valid client certificate could replay
another agent's signed observation, and an observation signed by a trusted key
from an unregistered host was indistinguishable from one produced by the agent it
named.

The chain this module builds:

    peer certificate ──SPKI fingerprint──▶ registered agent identity
                                              │
                              registered signing key ──▶ observation signature

Three properties, each refusable:

1. **The certificate is read at the boundary.** :func:`peer_certificate` takes the
   peer certificate the TLS stack actually saw (``SSLObject.getpeercert``), not a
   header someone can invent. A terminator that fronts the API can forward the
   fingerprint, but only when the deployment declares it
   (``CRYPTOSCAN_TRUST_MTLS_TERMINATOR=1``) — and then the *terminator* is the
   trust boundary, stated rather than assumed.

2. **The fingerprint must be registered.** :class:`AgentRegistry` maps
   ``sha256:<spki>`` to an agent id and that agent's Ed25519 signing key. An
   unregistered certificate is refused; a malformed registry fails closed with a
   readable error instead of becoming a trust-everything default.

3. **The signer must be the agent.** When an observation carries a signature, the
   signing key must be the key registered for the identity the certificate
   proved. Otherwise a certificate for host A can carry a signature from host B.

The SPKI fingerprint (SHA-256 over the DER-encoded SubjectPublicKeyInfo) is used
rather than a whole-certificate hash so that reissuing a certificate for the same
key — same machine, new expiry — does not silently break identity, while a new key
never inherits an old identity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

#: "1"/"true" turns the identity requirement on for ingestion.
ENFORCE_ENV = "CRYPTOSCAN_REQUIRE_AGENT_IDENTITY"

#: Path to the registry JSON (see :class:`AgentRegistry`).
REGISTRY_ENV = "CRYPTOSCAN_AGENT_REGISTRY"

#: "1" means the TLS handshake happens in a terminator that forwards the peer
#: certificate fingerprint in ``X-Client-Cert-SPKI``. The terminator, not this
#: process, is then the trust boundary — and that is written down, not implied.
TERMINATOR_ENV = "CRYPTOSCAN_TRUST_MTLS_TERMINATOR"

#: Header a terminator sets. Only honoured when :data:`TERMINATOR_ENV` is on.
TERMINATOR_HEADER = "x-client-cert-spki"

#: Scope key a TLS server may populate with the verified chain (ASGI extension).
TLS_EXTENSION = "tls"

FINGERPRINT_PREFIX = "sha256:"


class AgentIdentityError(Exception):
    """An identity could not be established — always refuse, never guess."""


def spki_fingerprint(certificate_der: bytes) -> str:
    """``sha256:<hex>`` over the certificate's SubjectPublicKeyInfo.

    Raises :class:`AgentIdentityError` when the bytes are not a certificate, so a
    garbage value cannot become a fingerprint that accidentally matches.
    """
    if not certificate_der:
        raise AgentIdentityError("empty certificate")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_der_x509_certificate

        certificate = load_der_x509_certificate(certificate_der)
        spki = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:  # noqa: BLE001 — any parse failure is a refusal
        raise AgentIdentityError(f"not a usable certificate: {exc}") from exc
    return FINGERPRINT_PREFIX + hashlib.sha256(spki).hexdigest()


def normalise_fingerprint(value: str) -> str:
    """Accept ``sha256:AB:CD`` / ``SHA256:abcd`` / bare hex and return the canonical form."""
    text = str(value or "").strip().lower().replace(":", "")
    if text.startswith("sha256"):
        text = text[len("sha256"):]
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise AgentIdentityError(f"not a sha256 fingerprint: {value!r}")
    return FINGERPRINT_PREFIX + text


@dataclass(frozen=True)
class AgentIdentity:
    """One registered machine: a certificate key, an agent, a signing key."""

    agent_id: str
    spki: str
    signing_key: str  # base64 Ed25519 raw public key, as release_signature uses
    tenant: str | None = None

    @property
    def key_id(self) -> str:
        from shared_models import release_signature

        return release_signature.key_id(self.signing_key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "spki": self.spki,
            "signing_key_id": self.key_id,
            "tenant": self.tenant,
        }


class AgentRegistry:
    """Registered machine identities, keyed by SPKI fingerprint.

    Loaded from JSON::

        {"agents": [{"agent_id": "agent-eu-1",
                     "spki": "sha256:…",
                     "signing_key": "<base64 raw ed25519 public key>",
                     "tenant": "bank-a"}]}

    Bad entries raise rather than being skipped: a registry that silently drops a
    line is a registry that silently trusts nothing — or, worse, that an operator
    believes is populated when it is not.
    """

    def __init__(self, agents: Iterable[AgentIdentity] = ()):
        self._by_spki: dict[str, AgentIdentity] = {}
        for agent in agents:
            spki = normalise_fingerprint(agent.spki)
            if spki in self._by_spki:
                raise AgentIdentityError(f"two agents share the fingerprint {spki}")
            self._by_spki[spki] = AgentIdentity(agent.agent_id, spki, agent.signing_key,
                                                agent.tenant)

    def __len__(self) -> int:
        return len(self._by_spki)

    def lookup(self, fingerprint: str) -> AgentIdentity | None:
        try:
            return self._by_spki.get(normalise_fingerprint(fingerprint))
        except AgentIdentityError:
            return None

    def by_agent_id(self, agent_id: str) -> AgentIdentity | None:
        return next((agent for agent in self._by_spki.values()
                     if agent.agent_id == agent_id), None)

    # ------------------------------------------------------------------ loaders
    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> AgentRegistry:
        entries = payload.get("agents") if isinstance(payload, Mapping) else None
        if not isinstance(entries, list):
            raise AgentIdentityError("registry must contain an 'agents' list")
        agents: list[AgentIdentity] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                raise AgentIdentityError(f"agent entry {index} is not an object")
            missing = [field for field in ("agent_id", "spki", "signing_key")
                       if not str(entry.get(field) or "").strip()]
            if missing:
                raise AgentIdentityError(
                    f"agent entry {index} is missing {', '.join(missing)}")
            agents.append(AgentIdentity(
                agent_id=str(entry["agent_id"]).strip(),
                spki=str(entry["spki"]),
                signing_key=str(entry["signing_key"]).strip(),
                tenant=(str(entry["tenant"]).strip() if entry.get("tenant") else None),
            ))
        return cls(agents)

    @classmethod
    def from_file(cls, path: str | Path) -> AgentRegistry:
        data = Path(path).read_text(encoding="utf-8")
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise AgentIdentityError(f"registry is not JSON: {exc}") from exc
        return cls.from_mapping(payload)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AgentRegistry:
        source = env if env is not None else os.environ
        path = str(source.get(REGISTRY_ENV, "")).strip()
        if not path:
            # An empty registry is a legitimate state: nothing is registered, so
            # every certificate is unregistered and every request is refused.
            return cls()
        return cls.from_file(path)


# --------------------------------------------------------------------------- #
# reading the peer certificate
# --------------------------------------------------------------------------- #

def peer_certificate(scope: Mapping[str, Any]) -> bytes | None:
    """The peer certificate the TLS stack verified, or None.

    Two sources, in order:

    * the ASGI TLS extension (``scope["extensions"]["tls"]["client_cert_chain"]``),
      which a server that terminates TLS itself may populate;
    * the fingerprint header from a declared terminator
      (:data:`TERMINATOR_ENV`), which is a *different trust boundary* and is
      therefore opt-in.
    """
    extension = (scope.get("extensions") or {}).get(TLS_EXTENSION) or {}
    chain = extension.get("client_cert_chain") if isinstance(extension, Mapping) else None
    if chain:
        first = chain[0]
        return first if isinstance(first, bytes) else str(first).encode("latin-1")
    return None


def forwarded_fingerprint(scope: Mapping[str, Any]) -> str | None:
    """The terminator's fingerprint header, honoured only when declared."""
    if str(os.getenv(TERMINATOR_ENV, "")).strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    headers = {key.decode("latin-1").lower(): value.decode("latin-1")
               for key, value in (scope.get("headers") or [])}
    return (headers.get(TERMINATOR_HEADER) or "").strip() or None


def resolve_identity(scope: Mapping[str, Any],
                     registry: AgentRegistry) -> tuple[AgentIdentity | None, str]:
    """(identity, reason) for one request.

    ``reason`` is an operator-readable sentence for the audit line: it says which
    evidence was present and why it did or did not resolve to an agent.
    """
    certificate = peer_certificate(scope)
    if certificate:
        try:
            fingerprint = spki_fingerprint(certificate)
        except AgentIdentityError as exc:
            return None, f"peer certificate unusable: {exc}"
    else:
        fingerprint = forwarded_fingerprint(scope)
        if not fingerprint:
            return None, ("no peer certificate on the connection and no declared "
                          "terminator fingerprint")
        try:
            fingerprint = normalise_fingerprint(fingerprint)
        except AgentIdentityError as exc:
            return None, f"terminator forwarded an unusable fingerprint: {exc}"
    agent = registry.lookup(fingerprint)
    if agent is None:
        return None, (f"certificate {fingerprint} is not registered to any agent "
                      f"({len(registry)} registered)")
    return agent, f"certificate {fingerprint} belongs to agent {agent.agent_id}"


def enforcement_enabled(env: Mapping[str, str] | None = None) -> bool:
    source = env if env is not None else os.environ
    return str(source.get(ENFORCE_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def check_signature_binding(agent: AgentIdentity,
                            signature: Mapping[str, Any] | None) -> tuple[bool, str]:
    """Does this signature belong to the agent the certificate proved?"""
    if not signature:
        return False, (f"agent {agent.agent_id} presented the certificate but the "
                       "observation carries no signature, so nothing binds the "
                       "payload to that machine")
    embedded = str(signature.get("public_key") or "").strip()
    if not embedded:
        return False, "signature block carries no public key"
    try:
        decoded = base64.b64decode(embedded, validate=True)
    except Exception:  # noqa: BLE001
        return False, "signature block's public key is not base64"
    try:
        registered = base64.b64decode(agent.signing_key, validate=True)
    except Exception:  # noqa: BLE001
        return False, f"agent {agent.agent_id}'s registered key is not base64"
    if decoded != registered:
        presented = hashlib.sha256(decoded).hexdigest()[:16]
        return False, (f"signature key {presented}… is not the key registered for "
                       f"agent {agent.agent_id}")
    return True, f"signature key matches the key registered for agent {agent.agent_id}"
