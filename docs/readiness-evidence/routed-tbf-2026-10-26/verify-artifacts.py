"""Offline engineering closure, not independent review or physical-device identity."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.routed_tbf.runner import verify_receipt
from tools.routed_tbf.authority import verify
from tools.routed_tbf.report import GATES


def main():
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / "evidence-manifest.json").read_text())
    names = set()
    for record in manifest["files"]:
        p = Path(record["path"])
        assert not p.is_absolute() and ".." not in p.parts and str(p) not in names
        names.add(str(p))
        f = ROOT / p
        assert not f.is_symlink() and f.resolve().is_relative_to(ROOT)
        assert f.stat().st_size == record["bytes"]
        assert hashlib.sha256(f.read_bytes()).hexdigest() == record["sha256"], str(p)
    public_keys = json.loads((base / "public-keys.json").read_text())
    results = []
    for run in ("run-01", "run-02"):
        p = base / run / "result.json"
        results.append(verify_receipt(p, hashlib.sha256(p.read_bytes()).hexdigest(), public_keys["adapter"]))
    assert results == ["LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES"] * 2
    failed = json.loads((base / "failed-initial-profile/result.json").read_text())
    verify(public_keys["adapter"], failed["adapter_signature"], failed["payload"])
    old = failed["payload"]
    assert old["acceptance"] == GATES and old["verdict"] == "INCONCLUSIVE_OR_FAILED"
    for name in ("guest.py", "report.py"):
        f = base / "failed-initial-profile/source-snapshots" / name
        assert hashlib.sha256(f.read_bytes()).hexdigest() == old["sources"]["tools/routed_tbf/" + name]
    revocation = json.loads((base / "revocation-check.json").read_text())
    assert revocation["passed"] and revocation["response_seconds"] <= 5
    native_revocation = json.loads((base / "revocation/result.json").read_text())
    verify(public_keys["adapter"], native_revocation["adapter_signature"], native_revocation["payload"])
    p = native_revocation["payload"]
    assert p["failure"] == "LEASE_REVOKED_OR_EXPIRED_VM_TERMINATED" and p["verdict"] == "INCONCLUSIVE_OR_FAILED"
    assert p["parent_before"] == p["parent_after"] and p["parent_policy_before"] == p["parent_policy_after"]
    print(
        f"Verified {len(names)} file commitments, two source-bound routed runs, retained failed gates and native revocation."
    )
    print(
        "Expected identity/policy refusal cases are NOT recovered. Independent review, second environment and production remain pending."
    )


if __name__ == "__main__":
    main()
