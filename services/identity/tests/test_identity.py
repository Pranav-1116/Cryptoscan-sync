"""Deterministic tests for the identity package: API-key guard, SAML, LDAP,
SCIM mapping, and SPIFFE workload identity. No network, no live IdP/LDAP."""

from __future__ import annotations

import datetime as dt
from datetime import datetime, timedelta, timezone

import pytest

# ---- 4. API-key IP allowlist + rotation ---------------------------------- #
from identity.api_key_guard import ip_allowed, normalize_allowlist, rotation_status

NOW = datetime(2026, 9, 6, tzinfo=timezone.utc)


def test_empty_allowlist_allows():
    assert ip_allowed("10.0.0.1", None) is True
    assert ip_allowed("10.0.0.1", []) is True


def test_exact_ip_allowlist():
    assert ip_allowed("203.0.113.7", ["203.0.113.7"]) is True
    assert ip_allowed("203.0.113.8", ["203.0.113.7"]) is False


def test_cidr_allowlist():
    assert ip_allowed("10.20.30.40", ["10.0.0.0/8"]) is True
    assert ip_allowed("192.168.1.5", ["10.0.0.0/8"]) is False
    assert ip_allowed("8.8.8.8", "10.0.0.0/8, 192.168.0.0/16") is False
    assert ip_allowed("192.168.5.5", "10.0.0.0/8, 192.168.0.0/16") is True


def test_ipv6_and_malformed_client_fail_closed():
    assert ip_allowed("2001:db8::1", ["2001:db8::/32"]) is True
    assert ip_allowed("not-an-ip", ["10.0.0.0/8"]) is False
    assert ip_allowed(None, ["10.0.0.0/8"]) is False


def test_normalize_allowlist_rejects_junk():
    with pytest.raises(ValueError):
        normalize_allowlist(["not-an-ip"])
    assert normalize_allowlist("10.0.0.0/8; 203.0.113.4") == ["10.0.0.0/8", "203.0.113.4/32"]


def test_rotation_states():
    created = NOW - timedelta(days=100)
    r = rotation_status(created_at=created, rotate_after_days=90, now=NOW)
    assert r["state"] == "ROTATION_DUE"
    expiring = rotation_status(created_at=NOW - timedelta(days=10),
                               expires_at=NOW + timedelta(days=5), now=NOW)
    assert expiring["state"] == "EXPIRING_SOON"
    ok = rotation_status(created_at=NOW - timedelta(days=2), rotate_after_days=90, now=NOW)
    assert ok["state"] == "OK"
    revoked = rotation_status(created_at=created, revoked_at=NOW - timedelta(days=1), now=NOW)
    assert revoked["state"] == "REVOKED"


# ---- 1. SAML -------------------------------------------------------------- #
from identity.saml import SamlConfig, SamlError, parse_and_validate
from identity.saml_request import make_authn_request, sign_assertion_for_test


@pytest.fixture(scope="module")
def idp():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.test")])
    cert = (
        x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
        .public_key(key.public_key()).serial_number(7)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return {
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).decode(),
    }


@pytest.fixture(scope="module")
def saml_cfg(idp):
    return SamlConfig(
        idp_entity_id="https://idp.test", sp_entity_id="https://sp.test",
        acs_url="https://sp.test/api/v1/auth/saml/acs",
        idp_certificate_pem=idp["cert_pem"], role_attribute="groups",
    )


def _signed(idp, roles=("auditor",), request_id="_req", now=None):
    return sign_assertion_for_test(
        idp_entity_id="https://idp.test", acs_url="https://sp.test/api/v1/auth/saml/acs",
        nameid="alice@corp.example", private_key_pem=idp["key_pem"],
        roles=list(roles), email="alice@corp.example", display_name="Alice",
        request_id=request_id, now=now or NOW,
    )


def test_saml_valid_assertion(idp, saml_cfg):
    req = make_authn_request(sp_entity_id="https://sp.test", acs_url=saml_cfg.acs_url)
    ident = parse_and_validate(_signed(idp, request_id=req["id"]),
                               saml_cfg, expected_in_response_to=req["id"], now=NOW)
    assert ident.nameid == "alice@corp.example"
    assert "auditor" in ident.roles
    assert ident.email == "alice@corp.example"


def test_saml_tamper_rejected(idp, saml_cfg):
    import base64

    resp = _signed(idp)
    xml = base64.b64decode(resp).decode().replace("auditor", "superadmin")
    tampered = base64.b64encode(xml.encode()).decode()
    with pytest.raises(SamlError):
        parse_and_validate(tampered, saml_cfg, expected_in_response_to="_req", now=NOW)


def test_saml_csrf_inresponse_to_must_match(idp, saml_cfg):
    with pytest.raises(SamlError):
        parse_and_validate(_signed(idp), saml_cfg,
                           expected_in_response_to="bogus", now=NOW)


def test_saml_expired_assertion_rejected(idp, saml_cfg):
    old = _signed(idp, now=NOW - timedelta(hours=1))
    with pytest.raises(SamlError):
        parse_and_validate(old, saml_cfg, expected_in_response_to="_req", now=NOW)


def test_saml_wrong_idp_cert_rejected(idp, saml_cfg):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    s = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")])
    c2 = (x509.CertificateBuilder().subject_name(s).issuer_name(s).public_key(k2.public_key())
          .serial_number(8).not_valid_before(NOW - timedelta(days=1))
          .not_valid_after(NOW + timedelta(days=365)).sign(k2, hashes.SHA256()))
    other = SamlConfig(
        idp_entity_id="https://idp.test", sp_entity_id=saml_cfg.sp_entity_id,
        acs_url=saml_cfg.acs_url,
        idp_certificate_pem=c2.public_bytes(serialization.Encoding.PEM).decode(),
        role_attribute="groups")
    with pytest.raises(SamlError):
        parse_and_validate(_signed(idp), other, expected_in_response_to="_req", now=NOW)


def test_saml_doctype_rejected(saml_cfg):
    import base64

    evil = b'<samlp:Response xmlns:samlp="x"><!DOCTYPE foo [<!ENTITY x "y">]></samlp:Response>'
    with pytest.raises(SamlError):
        parse_and_validate(base64.b64encode(evil).decode(), saml_cfg, now=NOW)


# ---- 3. LDAP -------------------------------------------------------------- #
from identity.ldap_auth import (
    FakeLdapBackend,
    LdapError,
    apply_group_role_map,
    authenticate_with_backend,
)


def _fake_dir():
    return FakeLdapBackend({
        "alice": {
            "dn": "CN=Alice,OU=Eng,DC=corp,DC=example",
            "password": "S3cret!2026x",
            "attributes": {
                "mail": ["alice@corp.example"],
                "displayName": ["Alice"],
                "memberOf": ["CN=CryptoScan-Auditors,OU=Groups,DC=corp,DC=example"],
            },
        },
        "bob": {
            "dn": "CN=Bob,DC=corp,DC=example", "password": "b",
            "attributes": {"memberOf": ["CN=Random,DC=corp"]},
        },
    })


GMAP = {"cryptoscan-auditors": "auditor", "cryptoscan-admins": "superadmin"}


def test_ldap_group_to_role_by_cn():
    assert "auditor" in apply_group_role_map(
        ["CN=CryptoScan-Auditors,OU=Groups,DC=corp"], GMAP)
    assert apply_group_role_map(["CN=NoMatch"], GMAP) == ["readonly"]


def test_ldap_authenticate_and_roles():
    ident = authenticate_with_backend(
        _fake_dir(), username="alice", password="S3cret!2026x",
        user_search_base="DC=corp", user_search_filter="(sAMAccountName={username})",
        group_role_map=GMAP)
    assert ident.roles == ["auditor"]
    assert ident.email == "alice@corp.example"


def test_ldap_unmapped_group_is_readonly():
    ident = authenticate_with_backend(
        _fake_dir(), username="bob", password="b",
        user_search_base="DC=corp", user_search_filter="(sAMAccountName={username})",
        group_role_map=GMAP)
    assert ident.roles == ["readonly"]


def test_ldap_bad_password_and_injection_denied():
    for kw in (
        dict(username="alice", password="wrong"),
        dict(username="alice)(|(objectClass=*", password="x"),
        dict(username="ghost", password="x"),
    ):
        with pytest.raises(LdapError):
            authenticate_with_backend(
                _fake_dir(), user_search_base="DC=corp",
                user_search_filter="(sAMAccountName={username})",
                group_role_map=GMAP, **kw)


# ---- 2. SCIM -------------------------------------------------------------- #
from identity.scim import (
    ScimError,
    create_scim_user,
    deactivate_scim_user,
    list_scim_users,
    patch_scim_user,
)


class _Row:
    def __init__(self, username, roles, email=None, active=True, display=None):
        self.username = username
        self.role_list = roles
        self.email = email
        self.is_active = active
        self.display_name = display


class FakeUserStore:
    def __init__(self):
        self.users: dict[str, _Row] = {}

    def get_by_username(self, u):
        return self.users.get(u)

    def create_user(self, username, password_hash, *, roles, display_name=None,
                    email=None, active=True):
        row = _Row(username, list(roles), email=email, active=active, display=display_name)
        self.users[username] = row
        return row

    def set_roles(self, u, roles):
        self.users[u].role_list = list(roles)
        return self.users[u]

    def set_active(self, u, active):
        self.users[u].is_active = active
        return self.users[u]

    def soft_delete(self, u):
        self.users[u].is_active = False
        return self.users[u]

    def list_all(self):
        return list(self.users.values())


def test_scim_create_and_list():
    store = FakeUserStore()
    res = create_scim_user(store, {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "carol", "displayName": "Carol",
        "emails": [{"value": "carol@corp.example", "primary": True}],
        "active": True, "roles": [{"value": "auditor"}],
    })
    assert res["userName"] == "carol"
    assert res["roles"][0]["value"] == "auditor"
    listing = list_scim_users(store)
    assert listing["totalResults"] == 1
    # duplicate -> 409
    with pytest.raises(ScimError) as ei:
        create_scim_user(store, {"userName": "carol"})
    assert ei.value.status == 409


def test_scim_superadmin_not_minted():
    store = FakeUserStore()
    res = create_scim_user(store, {"userName": "eve", "roles": [{"value": "superadmin"}]})
    assert "superadmin" not in [r["value"] for r in res["roles"]]


def test_scim_patch_deactivate():
    store = FakeUserStore()
    create_scim_user(store, {"userName": "dan", "roles": [{"value": "developer"}]})
    patch_scim_user(store, "dan", [{"op": "replace", "path": "active", "value": False}])
    assert store.get_by_username("dan").is_active is False
    patch_scim_user(store, "dan", [{"op": "replace", "path": "roles",
                                    "value": [{"value": "auditor"}]}])
    assert store.get_by_username("dan").role_list == ["auditor"]


def test_scim_delete_deactivates():
    store = FakeUserStore()
    create_scim_user(store, {"userName": "frank"})
    deactivate_scim_user(store, "frank")
    assert store.get_by_username("frank").is_active is False


# ---- 5. Workload identity (SPIFFE mTLS SVID) ----------------------------- #
from identity.workload import (
    WorkloadIdentityError,
    generate_ca,
    issue_svid,
    spiffe_id,
    verify_peer,
)


def test_spiffe_id_format():
    assert spiffe_id("scanner/edge-1", "cs.example") == "spiffe://cs.example/scanner/edge-1"


def test_svid_issue_and_verify():
    ca = generate_ca(trust_domain="cs.example")
    svid = issue_svid(ca, "scanner/edge-1", ttl_minutes=60, now=NOW)
    result = verify_peer(svid["cert_pem"], ca,
                         allowed_workloads=["scanner/edge-1"], now=NOW)
    assert result["workload"] == "scanner/edge-1"


def test_svid_wrong_workload_denied():
    ca = generate_ca(trust_domain="cs.example")
    svid = issue_svid(ca, "scanner/edge-1", now=NOW)
    with pytest.raises(WorkloadIdentityError):
        verify_peer(svid["cert_pem"], ca, allowed_workloads=["api"], now=NOW)


def test_svid_forged_ca_denied():
    ca = generate_ca(trust_domain="cs.example")
    other = generate_ca(trust_domain="cs.example")
    forged = issue_svid(other, "scanner/edge-1", now=NOW)
    with pytest.raises(WorkloadIdentityError):
        verify_peer(forged["cert_pem"], ca,
                    allowed_workloads=["scanner/edge-1"], now=NOW)


def test_svid_expired_denied():
    ca = generate_ca(trust_domain="cs.example")
    past = NOW - timedelta(hours=3)
    svid = issue_svid(ca, "scanner/edge-1", ttl_minutes=60, now=past)
    with pytest.raises(WorkloadIdentityError):
        verify_peer(svid["cert_pem"], ca,
                    allowed_workloads=["scanner/edge-1"], now=NOW)
