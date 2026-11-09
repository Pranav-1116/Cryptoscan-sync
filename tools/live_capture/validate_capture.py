#!/usr/bin/env python3
"""Live-host capture validation harness
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §12, §15 step 9).

Feeds a capture directory produced by capture-windows.ps1 or
capture-macos.sh into the matching collector and the OS-CRYPTO rule
catalogue, and reports exactly what was validated.

Standing limits (§12): validating ONE capture validates THAT HOST'S
CAPTURE ONLY — it is never fleet qualification, and a successful
validation is never 'the platform is validated'. Denied or missing
sources are reported as unavailable — never as absence (§2.1).

Usage:
  validate_capture.py --platform windows <capture-dir>
  validate_capture.py --platform macos <capture-dir>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] /
                       "services" / "os_intelligence"))

from os_intelligence.macos import collect_macos  # noqa: E402
from os_intelligence.rules import evaluate  # noqa: E402
from os_intelligence.windows import collect_windows  # noqa: E402

WIN_FILES = {
    "systeminfo": "systeminfo.txt",
    "ver": "ver.txt",
    "certutil_csplist": "certutil_csplist.txt",
    "certutil_store": "certutil_store.txt",
    "reg_schannel_protocols": "reg_schannel.txt",
    "reg_cipher_order": "reg_cipher_order.txt",
    "manage_bde": "manage_bde.txt",
    "get_tpm": "get_tpm.txt",
    "confirm_secureboot": "confirm_secureboot.txt",
    "driverquery": "driverquery.txt",
}

MAC_FILES = {
    "sw_vers": "sw_vers.txt",
    "uname": "uname.txt",
    "csrutil": "csrutil.txt",
    "spctl": "spctl.txt",
    "fdesetup": "fdesetup.txt",
    "kmutil": "kmutil.txt",
    "certificate_metadata": "certificate_metadata.txt",
}


def load_capture(capture_dir: Path, files: dict) -> dict:
    captured: dict = {}
    for source, filename in files.items():
        path = capture_dir / filename
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if text.startswith("permission_denied or unavailable"):
            captured[source] = {"error": "permission_denied"}
        else:
            captured[source] = text
    return captured


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True,
                        choices=("windows", "macos"))
    parser.add_argument("capture_dir")
    args = parser.parse_args()
    capture_dir = Path(args.capture_dir)
    if not capture_dir.is_dir():
        print(f"refused: {capture_dir} is not a capture directory")
        return 2

    files = WIN_FILES if args.platform == "windows" else MAC_FILES
    captured = load_capture(capture_dir, files)
    manifest_path = capture_dir / "manifest.json"
    manifest = (json.loads(manifest_path.read_text())
                if manifest_path.exists() else {})
    host = str(manifest.get("host") or capture_dir.name)

    collector = (collect_windows if args.platform == "windows"
                 else collect_macos)
    inventory = collector(host, captured)
    report = evaluate(inventory)
    coverage = inventory["coverage"]

    print(f"live-host capture validation — platform={args.platform}")
    print(f"host: {host}  (this validates THIS HOST'S CAPTURE ONLY — "
          "never fleet qualification, §12)")
    print(f"manifest: {manifest.get('captured_at', 'absent')}")
    print(f"sources collected: "
          f"{len(coverage['sources_collected'])} "
          f"{coverage['sources_collected']}")
    for entry in coverage["sources_unavailable"]:
        print(f"source unavailable: {entry['source']} — "
              f"{entry['reason']} (never treated as absence, §2.1)")
    by_status: dict = {}
    for r in report.results:
        by_status.setdefault(r.status, []).append(r.rule_id)
    for status, ids in sorted(by_status.items()):
        print(f"rules {status}: {len(ids)}")
    findings = sum(len(r.findings) for r in report.results)
    print(f"findings raised: {findings} "
          "(detections, not verdicts — §1)")
    print("validation status: capture parsed and evaluated with the "
          "documented disciplines; this run performs NO external act "
          "and marks NO external act done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
