"""Focused contracts for the operator-configured key-assurance live adapter."""

from keyassure import realtime_cli


def test_unconfigured_modes_are_explicitly_skipped():
    result = realtime_cli.run({})

    assert result["scan_status"] == "SKIP"
    assert result["modes"] == {"tls": "SKIP", "ct": "SKIP", "code": "SKIP"}
    assert result["observations"] == []
    assert result["findings"] == []


def test_code_mode_emits_findings_and_evidence(tmp_path):
    source = tmp_path / "crypto.py"
    source.write_text('import hashlib\npassword = "hardcoded-secret-value"\nhashlib.md5(b"x")\n', encoding="utf-8")

    result = realtime_cli.run({"code": [str(source)]})

    assert result["scan_status"] == "PASS"
    assert result["modes"] == {"tls": "SKIP", "ct": "SKIP", "code": "PASS"}
    assert result["findings"]
    assert all(item["evidence_reference"].startswith("sha256:") for item in result["findings"])
    assert result["observations"][0]["mode"] == "code"


def test_tls_failure_is_not_reported_as_success(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("operator endpoint refused connection")

    monkeypatch.setattr("keyassure.tls_audit.audit_tls_endpoint", fail)
    result = realtime_cli.run({"tls": [{"host": "operator.example"}]})

    assert result["scan_status"] == "FAIL"
    assert result["modes"]["tls"] == "FAIL"
    assert result["errors"][0]["mode"] == "tls"
    assert result["observations"] == []


def test_tls_observations_have_record_evidence(monkeypatch):
    monkeypatch.setattr(
        "keyassure.tls_audit.audit_tls_endpoint",
        lambda *args, **kwargs: {
            "target": {"host": "tls.example", "port": 443},
            "protocols": [{"version": "TLSv1.3", "status": "NEGOTIATED"}],
            "cipher_probes": [],
            "certificate": {"subject": "tls.example"},
            "findings": [],
        },
    )

    result = realtime_cli.run({"tls": [{"host": "tls.example"}]})
    observation = result["observations"][0]

    assert result["scan_status"] == "PASS"
    assert observation["evidence_reference"].startswith("sha256:")
    assert observation["protocols"][0]["evidence_reference"].startswith("sha256:")
    assert observation["certificate"]["evidence_reference"].startswith("sha256:")


def test_ct_monitor_failure_is_degraded_when_another_mode_passes(monkeypatch, tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("print('no crypto finding')\n", encoding="utf-8")

    def fail(*args, **kwargs):
        raise RuntimeError("CT endpoint unavailable")

    monkeypatch.setattr("keyassure.ct_monitor.monitor_domain", fail)
    result = realtime_cli.run({"ct": ["example.com"], "code": [str(source)]})

    assert result["scan_status"] == "DEGRADED"
    assert result["modes"] == {"tls": "SKIP", "ct": "FAIL", "code": "PASS"}
    assert result["errors"][0]["mode"] == "ct"
