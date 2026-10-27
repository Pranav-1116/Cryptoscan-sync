from __future__ import annotations

import hashlib

from evidence.hashing.chain_hasher import ChainHasher
from evidence.pack.evidence_pack import build_evidence_pack, verify_evidence_pack
from evidence.pack.standalone_verifier import STANDALONE_VERIFIER_SOURCE


def _records(scan_id: str, payloads: list[str]):
    hashes = [hashlib.sha256(item.encode()).hexdigest() for item in payloads]
    chain = ChainHasher.compute_chain(hashes, scan_id)
    return [
        {
            "id": f"finding-{index}",
            "algorithm": "DES" if index == 0 else "AES",
            "purpose": "ENCRYPTION",
            "file_path": f"a{index}.java",
            "line_number": index + 1,
            "compliance_status": "FAIL" if index == 0 else "PASS",
            "content_hash": content,
            "chain_hash": chain[index],
            "policy_evaluation": {
                "rules_evaluated": [
                    {
                        "rule_id": "BASELINE-001",
                        "evaluation_result": "FAIL" if index == 0 else "PASS",
                        "message": "legacy",
                        "severity": "HIGH",
                    }
                ]
            },
        }
        for index, content in enumerate(hashes)
    ]


def test_pack_round_trip_signed():
    scan_id = "scan-pack-1"
    pack = build_evidence_pack(
        scan={"scan_id": scan_id, "target_location": "local://test-fixture"},
        records=_records(scan_id, ["one", "two"]),
        policy={"pack_hash": "abc"},
        secret="unit-secret",
    )
    assert pack["integrity"]["signed"] is True
    assert pack["integrity"]["chain_ok"] is True
    report = verify_evidence_pack(pack, secret="unit-secret")
    assert report["result"] == "PASS"
    assert report["chain_intact"] is True
    assert report["signature_ok"] is True


def test_pack_detects_tamper():
    scan_id = "scan-pack-2"
    pack = build_evidence_pack(
        scan={"scan_id": scan_id},
        records=_records(scan_id, ["one", "two"]),
        secret="unit-secret",
    )
    pack["records"][1]["content_hash"] = "ab" * 32
    report = verify_evidence_pack(pack, secret="unit-secret")
    assert report["result"] == "FAIL"
    assert any("position 1" in err or "content_hash" in err or "chain" in err for err in report["errors"])


def test_wrong_secret_fails_signature():
    scan_id = "scan-pack-3"
    pack = build_evidence_pack(
        scan={"scan_id": scan_id},
        records=_records(scan_id, ["one"]),
        secret="unit-secret",
    )
    report = verify_evidence_pack(pack, secret="other-secret")
    assert report["result"] == "FAIL"
    assert report["signature_ok"] is False


def test_standalone_verifier_matches():
    scan_id = "scan-pack-4"
    pack = build_evidence_pack(
        scan={"scan_id": scan_id},
        records=_records(scan_id, ["alpha", "beta"]),
        secret="unit-secret",
    )
    ns: dict = {}
    exec(STANDALONE_VERIFIER_SOURCE, ns)
    report = ns["verify"](pack, secret="unit-secret")
    assert report["result"] == "PASS"
    assert report["chain_intact"] is True
