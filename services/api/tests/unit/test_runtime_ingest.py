"""Runtime ingest endpoint: registry verdicts + persistence shape."""

from __future__ import annotations

from api.routers.runtime import RuntimeFinding, RuntimeFindingsBody, _verdict_rows


def _body(findings):
    return RuntimeFindingsBody(scanner_id="tls-tap-agent-v1.0", findings=[RuntimeFinding(**f) for f in findings])


def test_session_rows_carry_registry_verdicts():
    rows = _verdict_rows(_body([
        {"hostname": "payments.internal", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
        {"hostname": "legacy.internal", "tls_version": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    ]))
    modern, legacy = rows
    assert modern["algorithm"] == "AES-GCM" and modern["key_size"] == 256
    assert modern["status"] == "ALLOWED" and modern["weak_tls"] is False
    assert legacy["algorithm"] == "3DES" and legacy["key_size"] == 168
    assert legacy["status"] == "DISALLOWED"
    assert legacy["weak_tls"] is True  # weak version AND disallowed suite


def test_library_risk_rows_use_agent_verdict():
    rows = _verdict_rows(_body([
        {"hostname": "prod-web-1", "process_name": "nginx", "pid": 101,
         "extra": {"kind": "tls-library-risk", "library": "openssl", "library_version": "1.0.2", "library_status": "DISALLOWED"}},
    ]))
    row = rows[0]
    assert row["kind"] == "tls-library-risk"
    assert row["status"] == "DISALLOWED"
    assert row["weak_tls"] is True
    assert row["extra"]["library"] == "openssl"


def test_observation_counts_flow_through():
    rows = _verdict_rows(_body([{"hostname": "h", "cipher_suite": "TLS_AES_128_GCM_SHA256", "observation_count": 7}]))
    assert rows[0]["observation_count"] == 7
