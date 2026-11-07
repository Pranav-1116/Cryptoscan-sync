"""Fixed isolated-VM execution; no user target address, port or QEMU flags."""

import hashlib
import json
from pathlib import Path
import secrets
import time
from tools.disposable_tbf.runner import ordinary_parent, parent_context, bounded_vm
from tools.disposable_tbf.build import sha
from tools.banking_sandbox.common import dump
from tools.banking_sandbox.live_vm.build import HERE, PRODUCTION, ROOT


def run(bundle, expected, output):
    ordinary_parent()
    bundle = Path(bundle).resolve(strict=True)
    output = Path(output)
    if output.exists() or output.resolve().is_relative_to(bundle):
        raise ValueError("fresh independent output required")
    manifest = bundle / "bundle.json"
    if sha(manifest) != expected or manifest.is_symlink():
        raise ValueError("bundle commitment")
    v = json.loads(manifest.read_text())
    names = set()
    if v["profile"] != "SYNTHETIC_BANK_LIVE_NO_NIC_V1":
        raise ValueError("not bank lab profile")
    for source in PRODUCTION:
        if v["production_collector_sources"][str(source.relative_to(ROOT))] != sha(source):
            raise ValueError("production collector source changed")
    for name, key in [
        ("guest.py", "guest_source_sha256"),
        ("sandbox.c", "launcher_source_sha256"),
        ("build.py", "builder_source_sha256"),
    ]:
        if v[key] != sha(HERE / name):
            raise ValueError("live fixture source changed")
    for r in v["files"]:
        p = Path(r["path"])
        if p.is_absolute() or ".." in p.parts or str(p) in names:
            raise ValueError("unsafe bundle path")
        names.add(str(p))
        f = bundle / p
        if (
            f.is_symlink()
            or not f.resolve().is_relative_to(bundle)
            or f.stat().st_size != r["bytes"]
            or sha(f) != r["sha256"]
        ):
            raise ValueError("bundle altered")
    if names != {str(p.relative_to(bundle)) for p in bundle.rglob("*") if p.is_file() and p != manifest}:
        raise ValueError("bundle closure")
    nonce = secrets.token_hex(32)
    before = parent_context()
    start = time.monotonic()
    raw, failure = bounded_vm([str(bundle / "launcher"), str(bundle), nonce], timeout=90)
    lines = [x.split(b"=", 1)[1] for x in raw.splitlines() if x.startswith(b"CRYPTOSCAN_BANK_LIVE=")]
    capture = None
    if not failure:
        if len(lines) != 1 or b"CRYPTOSCAN_BANK_LIVE_FAILED=" in raw:
            failure = "GUEST_FAILED"
        else:
            capture = json.loads(lines[0])
            if capture["nonce"] != nonce or [r["protocol"] for r in capture["network"]] != ["TLSv1.2", "TLSv1.3"]:
                failure = "CAPTURE_INVALID"
    after = parent_context()
    if before != after:
        failure = "PARENT_CONTEXT_CHANGED"
    output.mkdir(mode=0o700)
    (output / "serial.log").write_bytes(raw)
    result = {
        "verdict": "MEASURED_ISOLATED_VM_SAMPLE" if failure is None else "FAILED_OR_UNKNOWN",
        "failure": failure,
        "wall_seconds": time.monotonic() - start,
        "nonce": nonce,
        "bundle_sha256": expected,
        "serial_sha256": hashlib.sha256(raw).hexdigest(),
        "parent_before": before,
        "parent_after": after,
        "capture": capture,
        "production_qualified": False,
    }
    dump(output / "result.json", result)
    return result
