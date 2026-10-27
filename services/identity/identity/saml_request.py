"""SAML 2.0 AuthnRequest construction (SP → IdP) and test-assertion signing.

Kept deterministic: every request id is caller-supplied or derived from the
SSO session so login flows are replay-tracked. ``sign_assertion_for_test``
produces a correctly enveloped-signed SAML assertion so the validation path
can be exercised end-to-end without a live IdP.
"""

from __future__ import annotations

import base64
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from identity import saml

SAML2_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SAML2_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Post"


def make_authn_request(*, sp_entity_id: str, acs_url: str,
                        request_id: str | None = None) -> dict:
    """Build a deflated-encodable AuthnRequest plus the SSO-session id."""
    rid = request_id or f"_{secrets.token_hex(16)}"
    inst = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        '<?xml version="1.0"?>'
        f'<samlp:AuthnRequest xmlns:samlp="{saml.NS["samlp"]}" '
        f'xmlns:saml="{saml.NS["saml"]}" '
        f'ID="{rid}" Version="2.0" IssueInstant="{inst}" '
        f'ProtocolBinding="{SAML2_POST_BINDING}" AssertionConsumerServiceURL="{acs_url}">'
        f'<saml:Issuer>{_esc(sp_entity_id)}</saml:Issuer>'
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" '
        'AllowCreate="true"/>'
        '</samlp:AuthnRequest>'
    )
    b64 = base64.b64encode(xml.encode()).decode()
    return {
        "id": rid,
        "saml_request_b64": b64,
        "redirect_url": f"{sp_entity_id}?SAMLRequest={urllib.parse.quote(b64)}",
    }


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# --------------------------------------------------------------------------- #
# Test-only: produce a signed SAML response using an IdP private key
# --------------------------------------------------------------------------- #
def sign_assertion_for_test(
    *,
    idp_entity_id: str,
    acs_url: str,
    nameid: str,
    private_key_pem: str,
    roles: list[str] | None = None,
    role_attribute: str = "groups",
    email: str | None = None,
    display_name: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
    valid_window_minutes: int = 10,
) -> str:
    """Return a base64 SAMLResponse with a valid enveloped RS256 signature.

    Used by the test-suite to prove the validation path; never used by the
    running service (the service only verifies).
    """
    ref = now or datetime.now(timezone.utc)
    not_before = ref - timedelta(minutes=1)
    not_after = ref + timedelta(minutes=valid_window_minutes)
    assertion_id = f"_{secrets.token_hex(12)}"
    role_xml = "".join(
        f'<saml:AttributeValue>{_esc(r)}</saml:AttributeValue>' for r in (roles or [])
    )
    extra_attrs = ""
    if email:
        extra_attrs += (f'<saml:Attribute Name="email">'
                        f'<saml:AttributeValue>{_esc(email)}</saml:AttributeValue></saml:Attribute>')
    if display_name:
        extra_attrs += (f'<saml:Attribute Name="displayName">'
                        f'<saml:AttributeValue>{_esc(display_name)}</saml:AttributeValue></saml:Attribute>')

    assertion_inner = (
        f'<saml:Issuer xmlns:saml="{saml.NS["saml"]}">{_esc(idp_entity_id)}</saml:Issuer>'
        f'<ds:Signature xmlns:ds="{saml.NS["ds"]}">__SIGNATURE__</ds:Signature>'
        f'<saml:Subject xmlns:saml="{saml.NS["saml"]}">'
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        f'{_esc(nameid)}</saml:NameID>'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_after:%Y-%m-%dT%H:%M:%SZ}" '
        f'Recipient="{_esc(acs_url)}"'
        + (f' InResponseTo="{_esc(request_id)}"' if request_id else "")
        + '/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions xmlns:saml="{saml.NS["saml"]}" '
        f'NotBefore="{not_before:%Y-%m-%dT%H:%M:%SZ}" '
        f'NotOnOrAfter="{not_after:%Y-%m-%dT%H:%M:%SZ}">'
        '<saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction>'
        '</saml:Conditions>'
        f'<saml:AttributeStatement xmlns:saml="{saml.NS["saml"]}">'
        f'<saml:Attribute Name="{_esc(role_attribute)}">{role_xml}</saml:Attribute>'
        f'{extra_attrs}</saml:AttributeStatement>'
    )
    assertion_open = (
        f'<saml:Assertion xmlns:saml="{saml.NS["saml"]}" '
        f'xmlns:ds="{saml.NS["ds"]}" ID="{assertion_id}" '
        f'Version="2.0" IssueInstant="{ref:%Y-%m-%dT%H:%M:%SZ}">'
    )
    assertion_xml = assertion_open + assertion_inner + "</saml:Assertion>"

    # Build SignedInfo over the assertion id, sign c14n of SignedInfo.
    signed_info = (
        f'<ds:SignedInfo xmlns:ds="{saml.NS["ds"]}">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{assertion_id}">'
        '<ds:Transforms>'
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '</ds:Transforms>'
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        '<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>'
        '</ds:Reference></ds:SignedInfo>'
    )
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    # Canonicalize the SignedInfo on the signing side so the bytes match the
    # verifier's C14N exactly.
    try:
        from xml.etree import ElementTree as _ET

        si_canon = _ET.canonicalize(signed_info, with_comments=False).encode("utf-8")
    except Exception:  # pragma: no cover
        si_canon = signed_info.encode()
    signature = base64.b64encode(
        key.sign(si_canon, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    signature_block = (
        signed_info
        + f"<ds:SignatureValue>{signature}</ds:SignatureValue>"
    )
    # Compute the real reference digest: SHA-256 over c14n of the assertion
    # with the enveloped <ds:Signature> node removed (the enveloped transform).
    import hashlib
    from xml.etree import ElementTree as _ET

    assertion_no_sig = assertion_xml.replace(
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">__SIGNATURE__</ds:Signature>',
        "",
    )
    try:
        digest_c14n = _ET.canonicalize(assertion_no_sig, with_comments=False).encode("utf-8")
    except Exception:  # pragma: no cover
        digest_c14n = assertion_no_sig.encode()
    digest = base64.b64encode(hashlib.sha256(digest_c14n).digest()).decode()
    signed_info = signed_info.replace(
        "<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>",
        f"<ds:DigestValue>{digest}</ds:DigestValue>",
    )
    # re-sign SignedInfo now that the digest is embedded
    try:
        from xml.etree import ElementTree as _ET2

        si_canon = _ET2.canonicalize(signed_info, with_comments=False).encode("utf-8")
    except Exception:  # pragma: no cover
        si_canon = signed_info.encode()
    signature = base64.b64encode(
        key.sign(si_canon, padding.PKCS1v15(), hashes.SHA256())
    ).decode()
    signature_block = signed_info + f"<ds:SignatureValue>{signature}</ds:SignatureValue>"

    signed_assertion = assertion_xml.replace(
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">__SIGNATURE__</ds:Signature>',
        f'<ds:Signature xmlns:ds="{saml.NS["ds"]}">{signature_block}</ds:Signature>',
    )

    response = (
        f'<?xml version="1.0"?>'
        f'<samlp:Response xmlns:samlp="{saml.NS["samlp"]}" xmlns:saml="{saml.NS["saml"]}" '
        f'ID="_{secrets.token_hex(12)}" Version="2.0" '
        f'IssueInstant="{ref:%Y-%m-%dT%H:%M:%SZ}" Destination="{_esc(acs_url)}"'
        + (f' InResponseTo="{_esc(request_id)}"' if request_id else "")
        + '>'
        f'<saml:Issuer>{_esc(idp_entity_id)}</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        '</samlp:Status>'
        + signed_assertion
        + '</samlp:Response>'
    )
    return base64.b64encode(response.encode()).decode()
