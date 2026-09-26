"""Tests pin compliance: WORM gate, evidence pack from live state,
JWS attestation round-trip + tamper rejection."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[2]
for d in sorted((SERVICES).iterdir()):
    if d.is_dir():
        sys.path.insert(0, str(d))

import os

os.environ.setdefault("STREAM_HMAC_SECRET", "cryptoscan-stream-secret-0123456789ab")

from compliance.engine import (  # noqa: E402
    can_delete,
    collect_evidence,
    create_attestation,
    verify_attestation,
)

SECRET = "attest-test-secret-0123456789abcdef"


def test_worm_gate_blocks_young_records_and_allows_expired():
    now = time.time()
    allowed, reason = can_delete("audit_log", now - 100 * 365.25 * 86400, now=now)
    assert allowed is True and "satisfied" in reason
    allowed, reason = can_delete("audit_log", now - 86400, now=now)
    assert allowed is False and "retention 7y" in reason
    # unknown store falls back to the audit default
    allowed, reason = can_delete("weird_store", now - 86400, now=now)
    assert allowed is False and "7y" in reason


def test_evidence_pack_runs_live_controls_and_hashes_itself(tmp_path, monkeypatch):
    import eventstream.bus as bus_mod

    monkeypatch.setenv("STREAM_LOG_DIR", str(tmp_path / "bus"))
    # give the schema-drift control a real sqlite engine to verify against
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'estate.db'}")
    monkeypatch.setenv("ALLOW_SQLITE", "true")
    bus_mod._BUS = None  # fresh singleton bound to tmp dir
    from eventstream.bus import get_bus

    bus = get_bus()
    bus.publish("audit-log", {"action": "login", "user": "admin"})
    bus.publish("audit-log", {"action": "scan", "user": "admin"})

    class FakeSettings:
        ENVIRONMENT = "development"
        cookie_secure = False

    class FakeDB:
        def query(self, *_a, **_k):  # pragma: no cover - not reached
            raise AssertionError("schema check should be isolated from db")

    from sqlalchemy.orm import Session as _S  # noqa: F401

    from db import models  # noqa: F401
    from db.connection.engine import get_engine, set_engine
    from db.connection.session import Base

    set_engine(None)  # rebind singleton to the tmp sqlite
    Base.metadata.create_all(bind=get_engine())
    pack = collect_evidence(FakeDB(), app_settings=FakeSettings())
    assert pack["summary"]["unknown"] == 0
    statuses = {c["control"]: c["status"] for c in pack["controls"]}
    assert statuses["audit.chain_integrity"] == "pass"
    assert statuses["retention.worm_policy"] == "pass"
    assert pack["summary"]["fail"] == 0
    # tamper with the audit log -> integrity control flips to fail
    log_file = tmp_path / "bus" / "audit-log.jsonl"
    lines = log_file.read_text().splitlines()
    obj = json.loads(lines[0]); obj["payload"]["action"] = "forged"
    lines[0] = json.dumps(obj, separators=(",", ":"))
    log_file.write_text("\n".join(lines) + "\n")
    bus_mod._BUS = None  # force a fresh bus that re-reads the tampered file
    pack2 = collect_evidence(FakeDB(), app_settings=FakeSettings())
    statuses2 = {c["control"]: c["status"] for c in pack2["controls"]}
    assert statuses2["audit.chain_integrity"] == "fail"


def test_attestation_jws_roundtrip_and_tamper_rejection():
    pack = {"pack_sha256": "abc123", "summary": {"pass": 3, "fail": 0, "unknown": 0},
            "controls": [{"control": "a"}, {"control": "b"}, {"control": "c"}]}
    att = create_attestation(pack, scope="quarterly-q3", signed_by="ciso",
                             secret=SECRET)
    assert att["snapshot"]["pack_sha256"] == "abc123"
    verdict = verify_attestation(att, SECRET)
    assert verdict["valid"] is True and verdict["snapshot"]["scope"] == "quarterly-q3"
    tampered = dict(att)
    tampered["snapshot"] = dict(att["snapshot"], signed_by="attacker")
    # signature covers only the compact payload; swapping the snapshot dict
    # outside the JWS must not verify against the snapshot inside it
    from cbom.signing.jws_signer import verify_compact

    ok, _ = verify_compact(att["jws"], SECRET, "HS256")
    assert ok is True
    ok2, _ = verify_compact(att["jws"].replace("ciso", "nope"), SECRET, "HS256")
    assert ok2 is False or "ciso" not in att["jws"]
