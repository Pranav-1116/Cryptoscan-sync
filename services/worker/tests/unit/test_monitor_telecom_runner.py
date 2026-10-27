"""TELECOM monitor targets: continuous 3GPP NF posture from the daemon.

The runner must drive the SAME probe/classify engine as POST /telecom/scan,
mirror its pass into the API's telecom snapshot file (so /telecom/posture and
the exit report reflect monitor passes), classify issues honestly
(critical/high -> issues -> SCAN_DEGRADED), and BLOCK with the exact fix when
there is no estate — never a fabricated scan. Sockets are the thin edge and
are synthesized at the same boundary the telecom suite itself uses (probe
dicts into the real classify engine).
"""

from __future__ import annotations

import json

import pytest

from telecom_scanner.journey import pqc_adoption
from worker.monitor.runners import telecom_runner


def _probe_ok() -> dict:
    return {
        "status": "OK",
        "crypto": {"tls_version": "TLSv1.3",
                   "cipher_suite": "TLS_AES_256_GCM_SHA384",
                   "key_exchange": "X25519"},
        "certificates": [{"expiry_status": "VALID", "days_until_expiry": 200,
                          "is_self_signed": False, "key_size": 3072,
                          "key_type": "rsa",
                          "signature_algorithm": "sha256WithRSAEncryption",
                          "not_after": "2027-03-01T00:00:00+00:00"}],
        "chain_validation": {"is_valid": True, "errors": []},
    }


@pytest.fixture()
def estate(tmp_path, monkeypatch):
    """Two carriers, one NF each; the orange NF's endpoint refuses connections
    (a real production blind spot -> mission-plane CRITICAL)."""
    (tmp_path / "telecom_registry.json").write_text(json.dumps({
        "carriers": [
            {"code": "de-telekom", "name": "Deutsche Telekom", "country": "de", "plmn": "262-01"},
            {"code": "orange-fr", "name": "Orange France", "country": "fr", "plmn": "208-01"},
        ],
        "targets": [
            {"nf_id": "amf-de-01", "nf_type": "amf", "endpoint": "10.0.0.1:443",
             "carrier_code": "de-telekom", "environment": "production"},
            {"nf_id": "amf-fr-01", "nf_type": "amf", "endpoint": "10.0.1.1:443",
             "carrier_code": "orange-fr", "environment": "production"},
        ],
        "roaming_partners": [],
    }))
    monkeypatch.setenv("CRYPTOSCAN_TELECOM_REGISTRY", str(tmp_path / "telecom_registry.json"))
    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path / "snaps"))
    from telecom_scanner import main as telecom_main

    def fake_probe_one(endpoint, timeout=4.0, **_):
        if str(endpoint).startswith("10.0.0.1"):
            return _probe_ok()
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(telecom_main, "probe_one", fake_probe_one)
    return tmp_path


def test_telecom_runner_classifies_and_mirrors_snapshot(estate):
    result = telecom_runner({}, session=None)
    assert "blocked_reason" not in result, result
    summary = result["summary"]
    assert summary["nf_targets"] == 2
    assert summary["clean"] == 1
    assert summary["critical"] == 1  # unreachable AMF = mission-plane blind spot
    assert result["degraded"] is True
    assert "CRITICAL:amf-fr-01" in result["issues"]

    snapshot = json.loads((estate / "snaps" / "telecom_snapshot.json").read_text())
    assert snapshot["scanner"] == "telecom-monitor"
    assert snapshot["targets_registered"] == 2
    assert set(snapshot["state"]) == {"amf-de-01", "amf-fr-01"}
    # drift diffs need pqc_ready in the state (PQC transitions stream)
    assert snapshot["state"]["amf-de-01"]["pqc_ready"] is False
    assert snapshot["rollup"]  # same shape the API scan writes

    # the pass also folds into the PQC adoption journey (same file contract
    # as the API; pqc_ready derived from pqc_kex for classify rows)
    journey = json.loads((estate / "snaps" / "telecom_journey.json").read_text())
    assert journey["eras"]["amf-de-01"][0]["pqc_ready"] is False
    assert journey["eras"]["amf-de-01"][0]["passes"] == 1
    adoption = pqc_adoption(journey)
    assert adoption["nf_tracked"] == 2 and adoption["adoption_pct"] == 0.0


def test_telecom_runner_carrier_and_nf_filters(estate):
    only_de = telecom_runner({"carrier": "de-telekom"}, session=None)
    assert only_de["summary"]["nf_targets"] == 1
    assert only_de["summary"]["clean"] == 1
    assert only_de["degraded"] is False

    only_fr = telecom_runner({"nf_ids": ["amf-fr-01"]}, session=None)
    assert only_fr["summary"]["critical"] == 1
    assert "CRITICAL:amf-fr-01" in only_fr["issues"]

    blocked = telecom_runner({"carrier": "no-such-carrier"}, session=None)
    assert "no NF targets match" in blocked["blocked_reason"]
    assert "amf-de-01" in blocked["blocked_reason"]  # names what IS registered


def test_telecom_runner_blocks_without_estate(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_TELECOM_REGISTRY", str(tmp_path / "none.json"))
    blocked = telecom_runner({}, session=None)
    assert "no telecom estate registered" in blocked["blocked_reason"]
    assert "/telecom/targets" in blocked["blocked_reason"]  # the fix, not just the complaint


def test_telecom_target_type_is_wired_end_to_end():
    from db.models.monitor import TARGET_TYPES
    from worker.monitor.engine import DEFAULT_INTERVALS, _default_runners

    assert "TELECOM" in TARGET_TYPES
    assert DEFAULT_INTERVALS["TELECOM"] == 900
    assert callable(_default_runners()["TELECOM"])


def test_network_runner_refuses_ssrf_targets_at_execution(monkeypatch):
    """Defense in depth (OWASP A10): even a config that predates the API-side
    SSRF gate is filtered at probe time — metadata/loopback/URL targets are
    never probed by the daemon and surface as named issues."""
    from worker.monitor import runners as runner_mod

    probed: list[str] = []

    class _FakeScanner:
        def scan_hosts(self, endpoints, *a, **k):
            probed.extend(str(e) for e in endpoints)
            return {"findings": [{"endpoint": e, "status": "OK",
                                  "policy_issues": [], "crypto": {"tls_version": "TLSv1.3"}}
                                 for e in endpoints]}

        def discover_network(self, *a, **k):
            return {}

    monkeypatch.setattr(
        "network_scanner.core.scanner.NetworkTlsScanner",
        lambda live=True, timeout=5.0, workers=8: _FakeScanner(),
    )

    result = runner_mod.network_runner(
        {"endpoints": ["169.254.169.254:80", "127.0.0.1:8010",
                       "http://169.254.169.254/latest/meta-data/",
                       "api.bank.example:443"]},
        session=None,
    )
    assert "blocked_reason" not in result, result
    assert result["degraded"] is True
    blocked = [i for i in result["issues"] if i.startswith("SSRF_BLOCKED:")]
    assert len(blocked) == 3, result["issues"]
    assert probed == ["api.bank.example:443"], f"only the public endpoint may be probed, got {probed}"
