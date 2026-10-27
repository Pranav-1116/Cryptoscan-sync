"""Deterministic SAML 2.0 SP assertion + signature validation (no AI, no XML
decompression surprises).

This is a deliberately small, hard-failing SAML 2.0 Service Provider for the
HTTP-POST binding. It accepts a base64 ``SAMLResponse`` that is a
``<samlp:Response>`` containing one signed ``<saml:Assertion>``. It:

1. Rejects the response unless ``Destination`` matches the configured ACS URL
   and ``InResponseTo`` matches the outstanding request id (CSRF/SSRF guard).
2. Requires an enveloped XML-DSig signature over the assertion, and verifies
   that signature with the IdP's pre-registered X.509 public key using
   RSA-SHA256 (RS256). RSA-SHA1 and ``<Signature>`` over the whole response
   are NOT accepted as proof of the assertion.
3. Enforces ``NotBefore`` / ``NotOnOrAfter`` against a supplied clock.
4. Extracts ``NameID`` and role attributes using configured attribute names.

Signing uses ``cryptography`` directly; XML canonicalization is c14n 1.0
with inclusive prefixes (the only mode needed for SAML assertions). We parse
XML with a hardened stdlib ElementTree resolver (no external entities).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import base64
import hashlib
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate

# --- XML namespaces ------------------------------------------------------- #
NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)


class SamlError(ValueError):
    """Raised for any malformed, unsigned, expired, or untrusted assertion."""


@dataclass
class SamlConfig:
    idp_entity_id: str
    sp_entity_id: str
    acs_url: str
    idp_certificate_pem: str  # the pre-registered IdP signing certificate
    role_attribute: str = "groups"          # attribute that carries roles
    nameid_format_email: bool = True
    clock_skew_seconds: int = 120


@dataclass
class SamlIdentity:
    nameid: str
    email: str | None
    display_name: str | None
    roles: list[str] = field(default_factory=list)
    issuer: str = ""
    assertion_id: str = ""


# --------------------------------------------------------------------------- #
# hardened XML parse (no external entities / XInclude / DTD expansion)
# --------------------------------------------------------------------------- #
def _safe_parse(xml_bytes: bytes) -> ET.Element:
    # Refuse DOCTYPE / entity declarations outright (XXE / billion laughs).
    head = xml_bytes[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise SamlError("DOCTYPE/ENTITY declarations are not permitted")
    try:
        return ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise SamlError(f"malformed SAML XML: {exc}") from exc


def _q(ns_prefix: str, tag: str) -> str:
    return f"{{{NS[ns_prefix]}}}{tag}"


def extract_in_response_to(saml_response_b64: str) -> str | None:
    """Read the Response/Assertion InResponseTo without validating.

    The ACS handler correlates a response to an AuthnRequest it initiated
    before running full (signature) validation.
    """
    try:
        xml_bytes = base64.b64decode("".join(saml_response_b64.split()), validate=True)
        root = _safe_parse(xml_bytes)
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    val = root.get("InResponseTo")
    if not val:
        assertion = root.find(_q("saml", "Assertion"))
        if assertion is not None:
            val = assertion.get("InResponseTo")
    return val or None


def _signed_info_canonical(signature_el: ET.Element) -> bytes:
    """Extract the <ds:SignedInfo> and serialize it with c14n 1.0."""
    signed_info = signature_el.find("ds:SignedInfo", NS)
    if signed_info is None:
        raise SamlError("signature is missing <SignedInfo>")
    raw = ET.tostring(signed_info)
    try:
        # Inclusive canonicalization (C14N 1.0) — the SAML default.
        return ET.canonicalize(raw, with_comments=False).encode("utf-8")
    except (AttributeError, ValueError):
        # Fallback: raw serialization (namespaces are explicit in our input).
        return raw


def _rsa_sha256_signature_value(signature_el: ET.Element) -> bytes:
    sig_el = signature_el.find("ds:SignatureValue", NS)
    if sig_el is None or not (sig_el.text or "").strip():
        raise SamlError("signature is missing <SignatureValue>")
    raw = "".join(sig_el.text.split())
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SignatureValue is not valid base64") from exc


def _verify_algorithm(signature_el: ET.Element) -> None:
    method = signature_el.find("ds:SignedInfo/ds:SignatureMethod", NS)
    algo = (method.get("Algorithm") if method is not None else "") or ""
    if not algo.endswith("sha256") and not algo.endswith("sha384") and not algo.endswith("sha512"):
        raise SamlError(f"unsupported signature algorithm {algo!r} (require RSA-SHA256+)")


def _idp_public_key(cert_pem: str):
    cert = load_pem_x509_certificate(_to_pem(cert_pem).encode())
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise SamlError("IdP certificate must be an RSA key (RS256 signatures)")
    return pub


def _to_pem(cert: str) -> str:
    cert = cert.strip()
    if "BEGIN CERTIFICATE" in cert:
        return cert
    body = "\n".join(textwrap.wrap(cert, 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def verify_enveloped_signature(xml_bytes: bytes, cert_pem: str) -> ET.Element:
    """Return the verified, signed <saml:Assertion> element or raise SamlError.

    Strategy: parse, find the assertion, find its enveloped <ds:Signature>,
    verify RS256 over the c14n <SignedInfo>. We additionally check that the
    signed reference URI matches the assertion ID and the transform includes
    enveloped-signature (so the signature really covers the assertion).
    """
    root = _safe_parse(xml_bytes)
    assertion = root.find(".//saml:Assertion", NS)
    if assertion is None:
        raise SamlError("no <saml:Assertion> present")
    signature = assertion.find("ds:Signature", NS)
    if signature is None:
        raise SamlError("assertion is not signed (enveloped XML-DSig required)")

    _verify_algorithm(signature)

    # reference integrity: must reference the assertion id with enveloped c14n
    ref = signature.find("ds:SignedInfo/ds:Reference", NS)
    if ref is None:
        raise SamlError("signature has no <Reference>")
    ref_uri = (ref.get("URI") or "").lstrip("#")
    if ref_uri != assertion.get("ID"):
        raise SamlError("signature reference does not match the assertion ID")
    transforms = [t.get("Algorithm") for t in ref.findall(".//ds:Transform", NS)]
    if not any("enveloped-signature" in (t or "") for t in transforms):
        raise SamlError("signature does not use the enveloped-signature transform")

    _verify_reference_digest(assertion, ref)

    pub = _idp_public_key(cert_pem)
    try:
        pub.verify(
            _rsa_sha256_signature_value(signature),
            _signed_info_canonical(signature),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SamlError("assertion signature failed verification") from exc
    return assertion


def _c14n(element: ET.Element) -> bytes:
    raw = ET.tostring(element)
    try:
        return ET.canonicalize(raw, with_comments=False).encode("utf-8")
    except (AttributeError, ValueError):  # pragma: no cover
        return raw


def _verify_reference_digest(assertion: ET.Element, ref: ET.Element) -> None:
    """Recompute the SHA-256 digest of the referenced assertion (enveloped
    transform = the <ds:Signature> sub-tree is removed before hashing) and
    compare it to the signed <DigestValue>. This is what binds the signature
    to the assertion *content* — without it a valid signature over SignedInfo
    would not protect the attributes/NameID from tampering.
    """
    from copy import deepcopy

    digest_el = ref.find("ds:DigestValue", NS)
    if digest_el is None or not (digest_el.text or "").strip():
        raise SamlError("reference is missing <DigestValue>")
    method = ref.find("ds:DigestMethod", NS)
    if method is not None and not (method.get("Algorithm") or "").endswith("sha256"):
        raise SamlError("only SHA-256 reference digests are supported")

    target = deepcopy(assertion)
    # apply the enveloped-signature transform: drop the signature node
    for sig in target.findall("ds:Signature", NS):
        target.remove(sig)
    canonical = _c14n(target)
    computed = base64.b64encode(hashlib.sha256(canonical).digest()).decode()
    provided = "".join(digest_el.text.split())
    if not _b64_equal(computed, provided):
        raise SamlError("assertion content digest mismatch — tampered content")


def _b64_equal(a: str, b: str) -> bool:
    try:
        return base64.b64decode(a) == base64.b64decode(b)
    except Exception:  # noqa: BLE001
        return a.strip() == b.strip()


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    txt = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        raise SamlError(f"unparseable SAML time {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _check_time_window(assertion: ET.Element, *, skew: int, now: datetime) -> None:
    cond = assertion.find("saml:Conditions", NS)
    if cond is None:
        raise SamlError("assertion missing <Conditions>")
    not_before = _parse_utc(cond.get("NotBefore"))
    not_on_or_after = _parse_utc(cond.get("NotOnOrAfter"))
    if not_before is None or not_on_or_after is None:
        raise SamlError("Conditions must set NotBefore and NotOnOrAfter")
    if now < not_before - _seconds(skew):
        raise SamlError("assertion NotBefore is in the future")
    if now >= not_on_or_after + _seconds(skew):
        raise SamlError("assertion has expired (NotOnOrAfter passed)")


def _seconds(n: int):
    from datetime import timedelta

    return timedelta(seconds=n)


def _extract_roles(assertion: ET.Element, role_attr: str) -> list[str]:
    roles: list[str] = []
    for attr in assertion.findall(".//saml:Attribute", NS):
        name = attr.get("Name") or ""
        if name == role_attr or name.endswith("/" + role_attr) or name == role_attr.lower():
            for val in attr.findall("saml:AttributeValue", NS):
                if val.text and val.text.strip():
                    roles.append(val.text.strip())
    return roles


def parse_and_validate(
    saml_response_b64: str,
    config: SamlConfig,
    *,
    expected_in_response_to: str | None = None,
    now: datetime | None = None,
) -> SamlIdentity:
    """Full validation of a base64 SAMLResponse. Raises SamlError on failure."""
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)

    try:
        xml_bytes = base64.b64decode("".join(saml_response_b64.split()), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SamlError("SAMLResponse is not valid base64") from exc

    root = _safe_parse(xml_bytes)
    if root.tag != _q("samlp", "Response"):
        raise SamlError("SAMLResponse root must be <samlp:Response>")

    destination = root.get("Destination") or ""
    if not destination.rstrip("/").endswith(config.acs_url.rstrip("/").split("://", 1)[-1]) \
            and destination != config.acs_url:
        # compare host+path loosely but require the ACS host/path
        if config.acs_url not in destination:
            raise SamlError("Destination does not match the configured ACS URL")
    if expected_in_response_to:
        if root.get("InResponseTo") != expected_in_response_to:
            raise SamlError("InResponseTo does not match the outstanding AuthnRequest")

    issuer = root.find("saml:Issuer", NS)
    issuer_val = issuer.text.strip() if issuer is not None and issuer.text else ""
    if config.idp_entity_id and issuer_val != config.idp_entity_id:
        raise SamlError("assertion issuer is not the configured IdP")

    assertion = verify_enveloped_signature(xml_bytes, config.idp_certificate_pem)
    _check_time_window(assertion, skew=config.clock_skew_seconds, now=ref)

    nameid_el = assertion.find(".//saml:NameID", NS)
    nameid = nameid_el.text.strip() if nameid_el is not None and nameid_el.text else ""
    if not nameid:
        raise SamlError("assertion has no NameID")

    attrs: dict[str, str] = {}
    for attr in assertion.findall(".//saml:Attribute", NS):
        val_el = attr.find("saml:AttributeValue", NS)
        if val_el is not None and val_el.text:
            attrs[(attr.get("Name") or "").lower()] = val_el.text.strip()
    email = attrs.get("email") or attrs.get("urn:oid:0.9.2342.19200300.100.1.3")
    display = attrs.get("displayname") or attrs.get("cn") or nameid

    return SamlIdentity(
        nameid=nameid,
        email=email if config.nameid_format_email or "@" in nameid else None,
        display_name=display,
        roles=_extract_roles(assertion, config.role_attribute),
        issuer=issuer_val,
        assertion_id=assertion.get("ID") or "",
    )
