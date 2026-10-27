"""Tests for features 21 (signed PDF reports), 22 (encrypted backup/PITR/retention),
25 (audit attestation), 26 (airgap bundles). All deterministic, no network.

Note: compliance_pdf/backup/audit_attest/airgap are modules inside the existing
`governance` service package; this file is named distinctly to avoid colliding
with the pre-existing test_governance.py (approvals/migration-validation)."""
import datetime as dt

import pytest

from governance import compliance_pdf, backup, audit_attest, airgap


# ------------------------------------------------------------------ 21 PDF -- #
def test_framework_mapping_rolls_up_worst_status():
    tags = {
        "tls": [{"id": "tls-1", "title": "TLS audit", "status": "PASS"}],
        "audit": [{"id": "au-1", "title": "audit", "status": "FAIL"}],
        "cve": [{"id": "c-1", "title": "cve", "status": "PARTIAL"}],
    }
    m = compliance_pdf.map_evidence("NIST_SP_800_53", tags)
    statuses = {r["control"]: r["status"] for r in m["control_rows"]}
    assert statuses["SC-8"] == "PASS"
    assert statuses["AU-2"] == "FAIL"
    assert statuses["SI-2"] == "PARTIAL"
    assert statuses["AC-2"] == "NO_EVIDENCE"
    assert 0 <= m["compliance_pct"] <= 100


def test_all_frameworks_have_controls():
    for fw in ("NIST_SP_800_53", "PCI_DSS_4", "DORA", "UAE_PDPL"):
        m = compliance_pdf.map_evidence(fw, {})
        assert m["counts"]["NO_EVIDENCE"] == len(m["control_rows"]) > 3


def test_pdf_is_valid_deterministic_and_signed():
    tags = {"tls": [{"id": "x", "title": "tls", "status": "PASS"}]}
    m = compliance_pdf.map_evidence("PCI_DSS_4", tags)
    secret = "topsecret"
    canonical = compliance_pdf.canonical_summary("PCI_DSS_4", m, org="Acme", generated_at="2026-09-07T00:00:00Z")
    sig = compliance_pdf.sign_summary(canonical, secret)
    pdf = compliance_pdf.render_pdf(framework="PCI_DSS_4", org="Acme", generated_at="2026-09-07T00:00:00Z",
                                    mapping=m, signature=sig)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    pdf2 = compliance_pdf.render_pdf(framework="PCI_DSS_4", org="Acme", generated_at="2026-09-07T00:00:00Z",
                                     mapping=m, signature=sig)
    assert pdf == pdf2
    assert compliance_pdf.verify_summary(canonical, secret, sig)
    assert not compliance_pdf.verify_summary(canonical, "wrong", sig)


# -------------------------------------------------------------- 22 backup --- #
class FakePgBackend:
    name = "postgres"
    def __init__(self):
        self.restored = None
        self.replayed = None
    def dump(self, db):
        return f"PGDUMP:{db}:table1,table2".encode()
    def restore(self, db, payload):
        self.restored = (db, payload)
        return {"restored_tables": 2}
    def replay_wal(self, db, wal, pit):
        self.replayed = (db, wal, pit)
        return {"wal_records": 5, "pit": pit}


def test_backup_create_and_restore_roundtrip_and_pitr():
    key = backup.generate_encryption_key()
    be = FakePgBackend()
    res = backup.create_backup(backend=be, database_id="proddb", encryption_key=key,
                               signing_secret="s", now=dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc),
                               sequence=3, wal_tail=b"WALRECORD123")
    man = res["manifest"]
    assert man["engine"] == "postgres" and man["has_wal_tail"] is True
    out = backup.restore_backup(backend=be, database_id="proddb", ciphertext=res["ciphertext"],
                                manifest=man, encryption_key=key, signing_secret="s",
                                target_point_in_time="2026-09-07T12:00:00Z")
    assert out["restored"] is True and out["wal_applied"] is True and be.replayed is not None


def test_backup_tampered_ciphertext_fails_closed():
    key = backup.generate_encryption_key()
    be = FakePgBackend()
    res = backup.create_backup(backend=be, database_id="d", encryption_key=key, signing_secret="s")
    bad_man = dict(res["manifest"]); bad_man["size_bytes"] = 999
    with pytest.raises(backup.BackupError):
        backup.restore_backup(backend=be, database_id="d", ciphertext=res["ciphertext"],
                              manifest=bad_man, encryption_key=key, signing_secret="s")
    with pytest.raises(backup.BackupError):
        backup.restore_backup(backend=be, database_id="d", ciphertext=res["ciphertext"],
                              manifest=res["manifest"], encryption_key=backup.generate_encryption_key(),
                              signing_secret="s")


def test_retention_gfs_classification_and_purge():
    now = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
    backups = [
        {"backup_id": "daily-old", "created_at": (now - dt.timedelta(days=30)).isoformat()},
        {"backup_id": "weekly", "created_at": (now - dt.timedelta(days=21)).isoformat()},
        {"backup_id": "sunday", "created_at": (now - dt.timedelta(days=now.weekday() + 1 + 7)).isoformat()},
        {"backup_id": "fresh", "created_at": (now - dt.timedelta(days=2)).isoformat()},
    ]
    r = backup.apply_retention(backups, now=now)
    ids = {p["backup_id"] for p in r["purge"]}
    assert "daily-old" in ids and "fresh" not in ids
    assert r["kept"] + r["purged"] == len(backups)
    yr = {"backup_id": "yearly", "created_at": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc).isoformat()}
    r2 = backup.apply_retention([yr], now=dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc))
    assert r2["kept"] == 1


# ------------------------------------------------------- 25 attestation ---- #
def _chain(n):
    entries, prev = [], audit_attest.GENESIS_HASH
    base = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
    for i in range(n):
        e = {"actor": "admin", "action": f"login_{i}", "target_type": "session",
             "target_id": str(i), "detail": "ok", "ip_address": "10.0.0.1",
             "outcome": "success", "created_at": (base + dt.timedelta(seconds=i)).isoformat(),
             "chain_sequence": i, "previous_hash": prev}
        e["entry_hash"] = audit_attest.entry_hash(prev, e)
        prev = e["entry_hash"]; entries.append(e)
    return entries


def test_audit_chain_verifies_clean_and_detects_tamper():
    entries = _chain(5)
    r = audit_attest.verify_entries(entries)
    assert r["status"] == "VERIFIED" and r["entries_checked"] == 5
    entries[2]["action"] = "EVIL_ESCALATION"
    r2 = audit_attest.verify_entries(entries)
    assert r2["status"] == "TAMPERED"
    assert any(m["code"] == "ENTRY_HASH_MISMATCH" for m in r2["mismatches"])


def test_audit_chain_detects_deleted_entry_gap():
    entries = _chain(6)
    del entries[3]
    r = audit_attest.verify_entries(entries)
    assert r["status"] == "TAMPERED" and 3 in r["sequence_gaps"]


def test_attestation_signature_roundtrip():
    entries = _chain(3)
    rep = audit_attest.build_attestation(entries, org="Acme", signer="auditor", secret="s",
                                         now=dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc))
    assert rep["attestation"]["status"] == "VERIFIED"
    assert audit_attest.verify_attestation(rep, secret="s")
    rep["attestation"]["entries_checked"] = 999
    assert not audit_attest.verify_attestation(rep, secret="s")


# ------------------------------------------------------------- 26 airgap --- #
def test_airgap_blocks_external_allows_internal():
    pol = airgap.AirgapPolicy(airgap=True, allowlist=("mirror.internal.corp",))
    assert airgap.network_decision("https://services.nvd.nist.gov/rest/json/cves/2.0", pol)["action"] == "BLOCK"
    assert airgap.network_decision("https://mirror.internal.corp/feeds/cve.json", pol)["action"] == "ALLOW"
    off = airgap.AirgapPolicy(airgap=False)
    assert airgap.network_decision("https://services.nvd.nist.gov/x", off)["action"] == "ALLOW"


def test_signed_bundle_roundtrip_import():
    secret = "bundle-secret"
    entries = [
        {"feed": "nvd", "id": "CVE-2026-1111", "payload": {"cvss": 9.1, "desc": "rce"}},
        {"feed": "osv", "id": "GHSA-xxxx", "payload": {"pkg": "lodash"}},
    ]
    bundle = airgap.build_bundle(entries, secret=secret)
    sink = airgap.InMemoryFeedSink()
    out = airgap.import_bundle(bundle, secret=secret, sink=sink)
    assert out["imported"] == 2
    assert sink.feeds["nvd"]["CVE-2026-1111"]["cvss"] == 9.1


def test_bundle_bad_signature_rejected():
    bundle = airgap.build_bundle([{"feed": "nvd", "id": "X", "payload": {}}], secret="right")
    with pytest.raises(airgap.AirgapError):
        airgap.import_bundle(bundle, secret="wrong", sink=airgap.InMemoryFeedSink())


def test_bundle_tampered_entry_rejected():
    secret = "s"
    bundle = airgap.build_bundle([{"feed": "nvd", "id": "CVE-1", "payload": {"cvss": 1.0}}], secret=secret)
    bundle["manifest"]["entries"][0]["sha256"] = "0" * 64
    with pytest.raises(airgap.AirgapError):
        airgap.import_bundle(bundle, secret=secret, sink=airgap.InMemoryFeedSink())
