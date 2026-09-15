"""Normalization to the canonical schema + deterministic dedup."""

from __future__ import annotations

from eventstream.stream.dedup import DedupIndex, dedup_key
from eventstream.stream.normalize import normalize


def test_tls_finding_normalizes():
    out = normalize({
        "endpoint": "api.bank.example:443",
        "status": "OK",
        "crypto": {"tls_version": "TLSv1.3", "key_size": 256},
        "policy_issues": ["WEAK_TLS_VERSION"],
        "fingerprint_sha256": "ab" * 32,
        "issuer": "CN=Test CA",
    }, source="network-scanner")
    assert out["kind"] == "tls_finding"
    assert out["host"] == "api.bank.example"
    assert out["tls_version"] == "TLSv1.3"
    assert out["cert_fingerprint"] == "ab" * 32
    assert out["extra"]["policy_issues"] == ["WEAK_TLS_VERSION"]


def test_unknown_kind_is_honestly_unmapped():
    out = normalize({"mystery": "payload"}, source="x")
    assert out["kind"] == "unknown"
    assert out["extra"]["unmapped"] is True


def test_normalize_is_deterministic():
    raw = {"kind": "telecom_nf", "nf_name": "amf-1", "endpoint": "amf:443",
           "crypto": {"kex": "ML-KEM-768"}}
    assert normalize(raw, source="t") == normalize(raw, source="t")


def test_dedup_merges_same_identity():
    ev = normalize({"endpoint": "e:443", "crypto": {"tls_version": "TLSv1.3"},
                    "kind": "tls_finding"}, source="s")
    idx = DedupIndex()
    is_new, first = idx.merge(ev)
    assert is_new and first["seen_count"] == 1
    is_new2, second = idx.merge(dict(ev))
    assert not is_new2 and second["seen_count"] == 2
    assert first["dedup_key"] == second["dedup_key"]
    assert len(idx) == 1


def test_dedup_key_changes_with_identity():
    a = normalize({"endpoint": "e:443", "kind": "tls_finding",
                   "crypto": {"tls_version": "TLSv1.3"}}, source="s")
    b = normalize({"endpoint": "e:8443", "kind": "tls_finding",
                   "crypto": {"tls_version": "TLSv1.3"}}, source="s")
    assert dedup_key(a) != dedup_key(b)
