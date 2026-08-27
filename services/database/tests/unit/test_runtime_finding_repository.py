"""Runtime finding persistence: upsert-merge, aggregation, weak filters."""

from __future__ import annotations


from db.repositories.runtime_finding_repository import RuntimeFindingRepository, dedup_key_for


def _row(**overrides):
    base = {
        "scanner_id": "tls-tap-agent-v1.0",
        "kind": "session",
        "hostname": "payments.internal",
        "process_name": "tls-tap",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "algorithm": "AES",
        "key_size": 256,
        "status": "ALLOWED",
        "quantum_impact": "grover",
        "weak_tls": False,
        "observation_count": 1,
        "extra": {"source": "tap"},
    }
    base.update(overrides)
    return base


def test_upsert_merges_repeated_observations(db_session):
    repo = RuntimeFindingRepository(db_session)
    result = repo.upsert_many([_row()])
    assert result == {"created": 1, "updated": 0}
    result2 = repo.upsert_many([_row(observation_count=3), _row(cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA", status="DISALLOWED", weak_tls=True, algorithm="3DES", key_size=168)])
    assert result2 == {"created": 1, "updated": 1}
    rows = repo.list_recent()
    assert len(rows) == 2
    repeated = next(r for r in rows if r.cipher_suite == "TLS_AES_256_GCM_SHA384")
    assert repeated.observation_count == 4  # 1 + 3


def test_summary_aggregates_hosts_weak_and_tops(db_session):
    repo = RuntimeFindingRepository(db_session)
    repo.upsert_many([
        _row(hostname="a.internal"),
        _row(hostname="b.internal", cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA", status="DISALLOWED", weak_tls=True, algorithm="3DES", key_size=168),
        _row(hostname="a.internal", kind="tls-library-risk", cipher_suite=None, algorithm="TLS", status="DISALLOWED", process_name="nginx", extra={"library": "openssl", "library_version": "1.0.2"}),
    ])
    summary = repo.summary()
    assert summary["total_findings"] == 3
    assert summary["weak_findings"] == 2
    assert summary["hosts"] == 2
    top_suite = summary["top_cipher_suites"][0]
    assert top_suite["cipher_suite"] in {"TLS_AES_256_GCM_SHA384", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}


def test_weak_only_filter(db_session):
    repo = RuntimeFindingRepository(db_session)
    repo.upsert_many([
        _row(),
        _row(cipher_suite="TLS_RSA_WITH_RC4_128_SHA", status="DISALLOWED", weak_tls=True, algorithm="RC4"),
    ])
    weak = repo.list_recent(weak_only=True)
    assert len(weak) == 1
    assert weak[0].cipher_suite == "TLS_RSA_WITH_RC4_128_SHA"
    assert repo.list_recent(kind="tls-library-risk") == []


def test_dedup_key_is_stable_and_bounded():
    a = _row()
    b = _row(extra={"source": "tap"})  # extras do not split the key
    assert dedup_key_for(a) == dedup_key_for(b)
    assert len(dedup_key_for(a)) <= 400
    assert dedup_key_for(_row(hostname="other")) != dedup_key_for(a)


def test_model_registered_in_metadata():
    from db.connection.session import Base

    assert "runtime_findings" in Base.metadata.tables
