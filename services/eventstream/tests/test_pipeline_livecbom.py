"""End-to-end pipeline (ingest -> normalize -> dedup -> policy -> detect ->
fan-out -> evidence chain) and the Live CBOM service."""

from __future__ import annotations


from eventstream.bus import StreamBus
from eventstream.livecbom import CbomProjector, LiveCbomService, jws_verify
from eventstream.stream.pipeline import StreamProcessor

SECRET = "test-stream-secret-0123456789ab"


def _processor(tmp_path):
    return StreamProcessor(StreamBus(tmp_path / "logs", secret=SECRET))


def test_pipeline_end_to_end_downgrade(tmp_path):
    proc = _processor(tmp_path)
    proc.ingest({"kind": "tls_finding", "endpoint": "api.bank.example:443",
                 "crypto": {"tls_version": "TLSv1.3", "key_size": 256}},
                source="test")
    assert proc.drain() == 1
    # clean learning pass: at most the honest first-sighting note, never a downgrade
    first_rules = [e["payload"]["rule"] for e in proc.bus.latest("attack-detections")]
    assert "crypto_downgrade" not in first_rules
    assert "api.bank.example:443" in proc.detector.state.baselines

    # now the downgrade
    proc.ingest({"kind": "tls_finding", "endpoint": "api.bank.example:443",
                 "crypto": {"tls_version": "TLSv1.0"}}, source="test")
    proc.drain()
    det = [e["payload"] for e in proc.bus.latest("attack-detections")]
    assert any(d["rule"] == "crypto_downgrade" for d in det)
    # CRITICAL-ish fan-out: ALERT >= threshold lands on alerts topic too
    alerts = [e["payload"] for e in proc.bus.latest("alerts")]
    assert any(a["rule"] == "crypto_downgrade" for a in alerts)
    # audit chain advanced with per-event entries
    audit = proc.bus.latest("audit-log")
    assert len(audit) == 2 and len({a["payload"]["chain_hash"] for a in audit}) == 2


def test_pipeline_dedup_merges_and_policy_fails(tmp_path):
    proc = _processor(tmp_path)
    clean = {"kind": "tls_finding", "endpoint": "x:443",
             "crypto": {"tls_version": "TLSv1.3", "algorithm": "AES-256-GCM"}}
    proc.ingest(dict(clean), source="t")  # baseline learning pass
    dirty = {"kind": "tls_finding", "endpoint": "x:443",
             "crypto": {"tls_version": "TLSv1.2", "algorithm": "3DES"}}
    proc.ingest(dict(dirty), source="t")  # policy FAIL + algorithm downgrade
    proc.drain()
    pol = [e["payload"] for e in proc.bus.latest("policy-results")]
    assert any(p["fails"] >= 1 for p in pol)  # 3DES fails policy
    det = [e["payload"] for e in proc.bus.latest("attack-detections")]
    assert any(d["rule"] == "algorithm_downgrade" for d in det)
    assert any(d["severity"] == "CRITICAL"
               for d in det if d["rule"] == "algorithm_downgrade")

    # dedup: the same identity twice -> ONE dedup entry, seen_count 2
    proc.ingest(dict(dirty), source="t")
    proc.drain()
    dirty_entries = [v for v in proc.dedup.entries.values()
                     if v["current"].get("algorithm") == "3DES"]
    assert len(dirty_entries) == 1 and dirty_entries[0]["seen_count"] == 2


def test_livecbom_versions_sign_chain_and_diff(tmp_path):
    svc = LiveCbomService(tmp_path / "cbom", stale_after_seconds=3600)
    v1 = svc.update("sys-a", [{"kind": "tls_finding", "endpoint": "e:443",
                               "tls_version": "TLSv1.3"}])
    assert v1["version_no"] == 1 and jws_verify(v1["jws"], svc.secret)
    v2 = svc.update("sys-a", [
        {"kind": "tls_finding", "endpoint": "e:443", "tls_version": "TLSv1.3"},
        {"kind": "tls_finding", "endpoint": "g:443", "tls_version": "TLSv1.2"},
    ])
    assert v2["version_no"] == 2 and v2["prev_hash"] == v1["version_hash"]

    chain = svc.verify_chain("sys-a")
    assert chain["chain_valid"] is True and chain["versions"] == 2

    diff = svc.diff("sys-a", 1, 2)
    assert len(diff["added"]) == 1 and diff["added"][0]["endpoint"] == "g:443"
    assert diff["removed"] == [] and diff["changed"] == []

    cur = svc.current("sys-a")
    assert cur["version_no"] == 2
    assert cur["freshness"]["stale"] is False
    assert cur["freshness"]["seconds_since_update"] >= 0


def test_livecbom_detects_tampering(tmp_path):
    svc = LiveCbomService(tmp_path / "cbom")
    svc.update("sys-b", [{"kind": "tls_finding", "endpoint": "e:443"}])
    svc.update("sys-b", [{"kind": "tls_finding", "endpoint": "e:443"},
                         {"kind": "cert", "endpoint": "e:443"}])
    # tamper with version 1's asset in the log
    path = svc._path("sys-b")
    lines = path.read_text().splitlines()
    rec = __import__("json").loads(lines[0])
    rec["doc"]["assets"][0]["endpoint"] = "evil:443"
    lines[0] = __import__("json").dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    verdict = svc.verify_chain("sys-b")
    assert verdict["chain_valid"] is False and verdict["broke_at"] == 1


def test_projector_folds_normalized_events_into_versions(tmp_path):
    bus = StreamBus(tmp_path / "logs", secret=SECRET)
    svc = LiveCbomService(tmp_path / "cbom")
    proj = CbomProjector(bus, svc)
    proc = StreamProcessor(bus)
    proc.ingest({"kind": "tls_finding", "system": "web-1", "endpoint": "w:443",
                 "crypto": {"tls_version": "TLSv1.3"}}, source="t")
    proc.drain()
    proj.drain()
    cur = svc.current("web-1")
    assert cur is not None and cur["asset_count"] == 1
    # re-processing the same identity does not bump the version
    proc.ingest({"kind": "tls_finding", "system": "web-1", "endpoint": "w:443",
                 "crypto": {"tls_version": "TLSv1.3"}}, source="t")
    proc.drain()
    proj.drain()
    assert svc.current("web-1")["version_no"] == 1
