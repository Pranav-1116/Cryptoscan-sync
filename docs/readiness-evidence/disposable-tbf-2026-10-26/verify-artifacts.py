"""Offline engineering closure; binary bytes/authenticity are NOT independently attested."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from jsonschema import Draft202012Validator
from tools.disposable_tbf import build
from tools.disposable_tbf.contracts import Scope, GuestCapture, RunReceipt, report
from tools.disposable_tbf.runner import digest, parse_capture, strict_json

HERE = Path(__file__).resolve().parent
for name, model in (("scope", Scope), ("guest", GuestCapture), ("run", RunReceipt)):
    schema = json.loads((ROOT / f"tools/disposable_tbf/schemas/{name}-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    assert {k: v for k, v in schema.items() if k != "$schema"} == model.model_json_schema()
bundle_path = HERE / "bundle-manifest.json"
bundle = strict_json(bundle_path.read_bytes())
for field, source in (
    ("assets_lock_sha256", "assets.lock.json"),
    ("guest_source_sha256", "guest.py"),
    ("probe_source_sha256", "probe.c"),
    ("launcher_source_sha256", "sandbox.c"),
    ("builder_source_sha256", "build.py"),
    ("kernel_profile_sha256", "kernel.config"),
):
    assert bundle[field] == build.sha(ROOT / "tools/disposable_tbf" / source)
assert build.sha(HERE / "kernel.config") == next(v["sha256"] for v in bundle["files"] if v["path"] == "kernel.config")
record = strict_json((HERE / "build-record.json").read_bytes())
assert record["build_exit_code"] == 0 and record["bundle_sha256"] == build.sha(bundle_path)
nonces = []
for index in (1, 2):
    folder = HERE / f"run-{index:02}"
    raw = (folder / "result.json").read_bytes()
    strict_json(raw)
    receipt = RunReceipt.model_validate_json(raw)
    schema = json.loads((ROOT / "tools/disposable_tbf/schemas/run-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(json.loads(raw))
    serial = (folder / "serial.log").read_bytes()
    assert hashlib.sha256(serial).hexdigest() == receipt.serial_sha256
    assert parse_capture(serial, receipt.scope.nonce) == receipt.guest
    assert receipt.scope == Scope.model_validate_json((folder / "scope.json").read_bytes())
    assert receipt.scope == Scope.model_validate_json((HERE / f"scope-{index:02}.json").read_bytes())
    assert receipt.bundle_sha256 == build.sha(bundle_path)
    assert receipt.verdict == "VERIFIED_IN_DISPOSABLE_VM" and receipt.report == report(receipt.guest)
    assert "RESULT_SHA256=" + digest(receipt) in (HERE / f"cli-{index:02}.txt").read_text()
    nonces.append(receipt.scope.nonce)
assert len(set(nonces)) == 2
assert (HERE / "parent-qdisc-before.json").read_bytes() == (HERE / "parent-qdisc-after.json").read_bytes()
manifest = strict_json((HERE / "evidence-manifest.json").read_bytes())
for item in manifest["files"]:
    assert build.sha(ROOT / item["path"]) == item["sha256"], item["path"]
print(
    f"Verified two distinct actual guest runs, three schemas, report/serial/source closure and {len(manifest['files'])} file hashes."
)
print(
    "Boot binary hashes are recorded, not rehashed here without the external bundle. Device authenticity and production qualification remain FALSE."
)
