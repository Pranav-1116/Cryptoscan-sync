"""Deterministic tests for the key/crypto assurance engines. No network:
live TLS/CT/HSM paths use injected fakes; policy logic is pure."""

from __future__ import annotations

import datetime as dt

import pytest

NOW = dt.datetime(2026, 9, 6, tzinfo=dt.timezone.utc)


# ---- 6. TLS protocol/cipher classification (pure policy) ----------------- #
from keyassure.cipher_policy import classify_cipher, classify_protocol, overall_grade


def test_protocol_tls10_11_downgrade_flagged():
    for v in ("TLSv1", "TLSv1.1", "TLS 1.0", "SSLv3"):
        r = classify_protocol(v)
        assert r["allowed"] is False and r["severity"] in ("HIGH", "CRITICAL"), v
    assert classify_protocol("TLSv1.3")["allowed"] is True
    assert classify_protocol(None)["allowed"] is False


def test_cipher_rc4_3des_null_disallowed():
    for name in ("RC4-SHA", "DES-CBC3-SHA", "NULL-SHA256", "ECDHE-RSA-RC4-SHA"):
        v = classify_cipher(name, protocol="TLSv1.2")
        assert v.allowed is False and v.severity in ("CRITICAL", "HIGH"), name


def test_cipher_static_rsa_no_forward_secrecy():
    v = classify_cipher("AES256-GCM-SHA384", protocol="TLSv1.2")  # static RSA kx
    assert v.forward_secrecy is False
    assert v.severity in ("MEDIUM", "LOW", "HIGH", "CRITICAL")


def test_cipher_ecdhe_gcm_is_strong():
    v = classify_cipher("ECDHE-RSA-AES256-GCM-SHA384")
    assert v.forward_secrecy is True and v.aead is True and v.allowed is True


def test_cipher_tls13_suites_strong():
    v = classify_cipher("TLS_AES_256_GCM_SHA384")
    assert v.allowed and v.aead and v.severity == "INFO"


def test_overall_grade():
    assert overall_grade([{"severity": "CRITICAL"}])["grade"] == "F"
    assert overall_grade([{"severity": "MEDIUM"}])["grade"] == "C"
    assert overall_grade([])["grade"] == "A"


# TLS cert analysis (pure, using synthetic cert)
def test_tls_cert_analysis_san_and_expiry():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from keyassure.tls_audit import _analyze_chain

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "good.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - dt.timedelta(days=30))
            .not_valid_after(NOW + dt.timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("good.example")]), critical=False)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    res = _analyze_chain(None, der, "good.example", NOW)
    codes = {i["code"] for i in res.issues}
    assert "SAN_MISMATCH" not in codes
    assert "CERT_EXPIRING" in codes  # 10 days
    res2 = _analyze_chain(None, der, "evil.example", NOW)
    assert "SAN_MISMATCH" in {i["code"] for i in res2.issues}


def test_tls_weak_rsa_key_flagged():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from keyassure.tls_audit import _analyze_chain

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(2)
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=400))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("weak.example")]), critical=False)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    res = _analyze_chain(None, der, "weak.example", NOW)
    assert "WEAK_KEY" in {i["code"] for i in res.issues}


# ---- 7. CT log monitoring -------------------------------------------------- #
from keyassure.ct_monitor import monitor_domain, summarize


CRTSH_FIXTURE = r'''[
 {"id":101,"common_name":"app.example.com","name_value":"app.example.com","issuer_name":"C=US,O=Let's Encrypt,CN=E5","not_before":"2026-08-01","not_after":"2026-11-01","serial_number":"abc"},
 {"id":102,"common_name":"rogue.example.com","name_value":"rogue.example.com","issuer_name":"CN=Sketchy CA","not_before":"2026-09-01","not_after":"2026-12-01","serial_number":"def"},
 {"id":103,"common_name":"other.xyz","name_value":"other.xyz","issuer_name":"CN=Good CA","not_before":"2026-09-01","not_after":"2026-12-01","serial_number":"ghi"}
]'''


def test_ct_flags_new_and_rogue():
    fetch = lambda url: CRTSH_FIXTURE  # noqa: E731
    rep = monitor_domain("example.com", fetcher=fetch,
                         known_serials=["abc"],
                         allowed_issuers=["e5", "good ca"])
    cn = {c["common_name"] for c in rep.observed}
    assert "app.example.com" in cn and "rogue.example.com" in cn
    assert "other.xyz" not in cn  # doesn't cover monitored domain
    # rogue = issuer (CN "Sketchy CA") not on allowlist
    assert any(c["common_name"] == "rogue.example.com" for c in rep.rogue_certs)
    # app cert serial is known -> counted known, not new
    assert rep.known_certs == 1
    assert not any(c["common_name"] == "app.example.com" for c in rep.new_certs)


def test_ct_new_cert_when_not_in_inventory():
    fetch = lambda url: CRTSH_FIXTURE  # noqa: E731
    rep = monitor_domain("example.com", fetcher=fetch,
                         allowed_issuers=["e5", "good ca", "sketchy ca"])
    # app + rogue both allowed issuers now, but neither serial known -> both NEW
    cns = {c["common_name"] for c in rep.new_certs}
    assert "app.example.com" in cns and "rogue.example.com" in cns
    s = summarize([rep])
    assert s["new_cert_alerts"] == 2 and s["rogue_cert_alerts"] == 0


def test_ct_invalid_domain():
    with pytest.raises(Exception):
        monitor_domain("notadomain", fetcher=lambda u: "[]")


# ---- 8. Expiry alerts + SLA ----------------------------------------------- #
from keyassure.expiry_alerts import run_expiry_campaign, rules_for_days, sla_state


def test_expiry_rules_fire_at_milestones():
    assert {r["code"] for r in rules_for_days(5)} == {"EXPIRY_7D", "EXPIRY_30D", "EXPIRY_60D", "EXPIRY_90D"}
    assert {r["code"] for r in rules_for_days(45)} == {"EXPIRY_60D", "EXPIRY_90D"}
    assert {r["code"] for r in rules_for_days(200)} == set()
    assert rules_for_days(-1)[0]["code"] == "EXPIRED"


def test_sla_breach_and_at_risk():
    assert sla_state(-5, {"sla_tier": "tier1"}, now=NOW)["status"] == "BREACHED"
    assert sla_state(20, {"sla_tier": "tier1"}, now=NOW)["status"] == "AT_RISK"  # lead 60
    assert sla_state(200, {"sla_tier": "tier1"}, now=NOW)["status"] == "ON_TRACK"
    assert sla_state(5, {"sla_tier": "tier1", "renewed": True}, now=NOW)["status"] == "MET"


def test_expiry_campaign_summary():
    assets = [
        {"id": "a1", "subject": "expired", "not_after": (NOW - dt.timedelta(days=2)).isoformat(), "sla_tier": "tier1"},
        {"id": "a2", "subject": "soon", "not_after": (NOW + dt.timedelta(days=5)).isoformat()},
        {"id": "a3", "subject": "fine", "not_after": (NOW + dt.timedelta(days=300)).isoformat()},
    ]
    camp = run_expiry_campaign(assets, now=NOW)
    assert camp["sla_breached"] == 1
    assert camp["alert_counts"]["EXPIRY_7D"] >= 1
    assert camp["total_assets"] == 3


# ---- 9. HSM/KMS key residence --------------------------------------------- #
from keyassure.hsm_connectivity import check_key


class FakeBackend:
    def __init__(self, desc, sig_ok=True):
        self._desc = desc
        self._sig_ok = sig_ok

    def describe(self, key_ref):
        if self._desc == "CONN_FAIL":
            raise RuntimeError("connection refused")
        return self._desc

    def sign_challenge(self, key_ref, nonce):
        if not self._sig_ok:
            raise RuntimeError("signing disabled")
        return {"signature": b"\x30" + b"\x00" * 64}


def test_hsm_backed_key_passes():
    desc = {"metadata": {"origin": "AWS_CLOUDHSM", "protection_level": "HARDWARE",
                         "algorithm": "RSA", "key_spec": "RSA_2048",
                         "key_usage": ["SIGN", "VERIFY"], "exportable": False}}
    r = check_key("key/1", provider="aws_kms", backend=FakeBackend(desc))
    assert r["hardware_backed"] is True
    assert r["connectivity"] == "OK" and r["sign_challenge"] == "OK"
    assert r["attributes"]["raw_key_material_present"] is False


def test_software_key_flagged():
    desc = {"metadata": {"origin": "AWS_KMS", "protection_level": "SOFTWARE",
                         "exportable": True}}
    r = check_key("key/2", provider="aws_kms", backend=FakeBackend(desc))
    assert r["key_residence"] == "SOFTWARE"
    assert any(i["code"] in ("NOT_HARDWARE_BACKED", "EXPORTABLE_KEY") for i in r["issues"])


def test_hsm_connectivity_failure_fail_closed():
    r = check_key("key/3", provider="aws_kms", backend=FakeBackend("CONN_FAIL"))
    assert r["connectivity"] == "FAIL"
    assert r["hardware_backed"] is False


def test_hsm_never_returns_key_material():
    desc = {"metadata": {"protection_level": "HARDWARE", "private_key": "x" * 200}}
    r = check_key("key/4", provider="pkcs11", backend=FakeBackend(desc))
    blob = str(r["attributes"])
    assert "x" * 200 not in blob  # material scrubbed


def test_hsm_unsupported_provider():
    with pytest.raises(Exception):
        check_key("k", provider="bitlocker", backend=FakeBackend({}))


# ---- 10. Trust-store inventory -------------------------------------------- #
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID as _OID

from keyassure.trust_store import audit, baseline_fingerprints, parse_pem_bundle


from cryptography.hazmat.primitives import serialization as _ser


def _root(cn, *, days=365, key=None, self_signed=True):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, cn)])
    issuer = subject
    sign_key = key
    if not self_signed:
        sign_key = ec.generate_private_key(ec.SECP256R1())
        issuer = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, "Real CA")])
    cert = (_x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(_x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=10))
            .not_valid_after(NOW + dt.timedelta(days=days))
            .sign(sign_key, _hashes.SHA256()))
    return cert.public_bytes(_ser.Encoding.PEM)


def test_trust_store_flags_rogue_and_expired():

    good = _root("Approved Root CA", days=2000)
    rogue = _root("Unknown Injected CA", days=2000)
    expired = _root("Expired Root", days=-10)
    bundle = good + rogue + expired
    anchors = parse_pem_bundle(bundle, source="ca-bundle.crt", now=NOW)
    assert len(anchors) == 3
    approved = baseline_fingerprints(good)
    rep = audit(anchors, approved_fingerprints=approved)
    rogue_subjects = [e["subject"] for e in rep["extra_or_rogue_roots"]]
    assert "Unknown Injected CA" in rogue_subjects
    assert len(rep["expired_roots"]) == 1
    assert rep["self_signed_roots"] == 3


def test_trust_store_flags_non_root_anchor():

    leaf = _root("not-a-root.example", days=100, self_signed=False)
    anchors = parse_pem_bundle(leaf, source="cacerts", now=NOW)
    rep = audit(anchors)
    assert any(i["code"] == "NON_ROOT_ANCHOR" for i in rep["other_issues"])


# ---- 11. Hybrid-PQC downgrade detector ------------------------------------ #
from keyassure.pqc_downgrade import HandshakeEvidence, audit_endpoint, evaluate_negotiation


def test_pqc_hybrid_negotiated_resists():
    ev = HandshakeEvidence(offered_groups=["X25519MLKEM768", "X25519"],
                           negotiated_group="X25519MLKEM768",
                           pqc_offered=True, pqc_supported_locally=True)
    v = evaluate_negotiation(ev)
    assert v["downgrade"] is False
    assert "HYBRID" in v["outcome"]


def test_pqc_downgrade_when_server_picks_classic():
    ev = HandshakeEvidence(offered_groups=["X25519MLKEM768", "X25519"],
                           negotiated_group="X25519",
                           pqc_offered=True, pqc_supported_locally=True)
    v = evaluate_negotiation(ev)
    assert v["downgrade"] is True and v["outcome"] == "DOWNGRADE_DETECTED"


def test_pqc_local_unsupported_honest():
    ev = HandshakeEvidence(offered_groups=["X25519MLKEM768"], negotiated_group=None,
                           pqc_offered=True, pqc_supported_locally=False)
    v = evaluate_negotiation(ev)
    assert v["outcome"] == "LOCAL_UNSUPPORTED"


def test_pqc_audit_endpoint_with_fake_handshaker():
    def fake_hs(host, port, groups, sni):
        pqc = any("MLKEM" in g.upper() or "KYBER" in g.upper() for g in groups)
        if not pqc:
            return HandshakeEvidence(groups, "X25519", False, True)
        # compliant server: negotiates hybrid whenever offered
        return HandshakeEvidence(groups, "X25519MLKEM768", True, True)

    rep = audit_endpoint("pqc.example", handshaker=fake_hs)
    assert rep["downgrade_resisted"] is True

    def downgrading(host, port, groups, sni):
        pqc = any("MLKEM" in g.upper() for g in groups)
        if pqc and any(g.upper().replace("-", "") in ("X25519", "SECP256R1") for g in groups):
            return HandshakeEvidence(groups, "X25519", True, True)  # strips hybrid
        if not pqc:
            return HandshakeEvidence(groups, "X25519", False, True)
        return HandshakeEvidence(groups, None, True, True, error="no shared group")

    rep2 = audit_endpoint("pqc.example", handshaker=downgrading)
    assert rep2["overall_outcome"] == "DOWNGRADE_DETECTED"


# ---- 12. Code-scanning rules ---------------------------------------------- #
from keyassure.code_rules import scan_python, _regex_scan, scan_paths


def test_code_python_md5_and_ecb():
    src = '''
import hashlib
from Crypto.Cipher import AES
def h(x):
    return hashlib.md5(x).hexdigest()
def enc(k, d):
    c = AES.new(k, AES.MODE_ECB)
    return c.encrypt(d)
'''
    findings = scan_python(src, "weak.py")
    rules = {f.rule_id for f in findings}
    assert "WP-MD5" in rules
    assert "WP-ECB" in rules


def test_code_python_des_and_short_rsa():
    src = '''
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
key = DES.new(b"8bytekey")
rsa_key = RSA.generate(1024)
'''
    rules = {f.rule_id for f in scan_python(src, "d.py")}
    assert "WP-DES" in rules
    assert "WP-RSA-SHORT" in rules


def test_code_hardcoded_key_and_static_iv():
    src = '''
API_KEY = "sk-live-abcdef1234567890"
iv = b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
'''
    rules = {f.rule_id for f in scan_python(src, "cfg.py")}
    assert "WP-HARDCODED-KEY" in rules
    assert "WP-STATIC-IV" in rules


def test_code_java_regex_rules():
    src = '''
MessageDigest md = MessageDigest.getInstance("MD5");
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
KeyGenerator kg = KeyGenerator.getInstance("DESede");
'''
    rules = {f.rule_id for f in _regex_scan(src, "Crypto.java")}
    assert {"WP-MD5", "WP-ECB", "WP-DES"} <= rules


def test_code_no_false_positive_on_strong_python():
    src = '''
import hashlib
from Crypto.Cipher import AES
def h(x): return hashlib.sha256(x).hexdigest()
def enc(k, iv, d): return AES.new(k, AES.MODE_GCM, nonce=iv).encrypt(d)
'''
    rules = {f.rule_id for f in scan_python(src, "strong.py")}
    assert "WP-MD5" not in rules and "WP-ECB" not in rules and "WP-DES" not in rules


def test_code_scan_paths(tmp_path):
    (tmp_path / "a.py").write_text('import hashlib\nhashlib.md5(b"x")\n')
    (tmp_path / "b.txt").write_text("nothing here")  # not scanned
    rep = scan_paths([tmp_path])
    assert rep["files_scanned"] == 1
    assert rep["by_rule"].get("WP-MD5") == 1
