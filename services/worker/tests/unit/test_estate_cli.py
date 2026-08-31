"""Worker tests — full-estate one-command CLI (scripts/scan_estate.py).

Proves the end-to-end journey with the real pipeline: scan -> evidence
chain -> normalize -> policy -> CBOM -> PQC/gate -> report artifacts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = REPO_ROOT / "scripts" / "scan_estate.py"


def _write_target(root: Path) -> None:
    (root / "Pay.java").write_text(
        "import javax.crypto.Cipher;\n"
        "class Pay {\n"
        "  void go() {\n"
        "    Cipher c = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"
        "    javax.crypto.spec.SecretKeySpec k =\n"
        "        new javax.crypto.spec.SecretKeySpec(key, \"DES\");\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    # container manifest marker so the container stage runs too
    (root / "package.json").write_text(
        '{"name": "pay", "dependencies": {"crypto-js": "^4.0.0"}}',
        encoding="utf-8",
    )


@pytest.fixture
def target(tmp_path: Path) -> Path:
    _write_target(tmp_path)
    return tmp_path


def test_estate_cli_end_to_end(target: Path, tmp_path: Path):
    out = tmp_path / "out"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dir", str(target), "--out", str(out)],
        capture_output=True, text=True, timeout=300,
        env={**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
    )
    assert result.returncode == 0, result.stderr[-2000:]

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["findings"] >= 1
    assert summary["scan_id"]

    pack = json.loads((out / "evidence-pack.json").read_text(encoding="utf-8"))
    assert pack["pack_format"] == "cryptoscan-evidence-pack"
    assert len(pack["records"]) == summary["findings"]
    assert pack["integrity"]["chain_ok"] is True

    bom = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    assert bom.get("bomFormat") == "CycloneDX"
    assert len(bom.get("components") or []) >= 1

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["totals"]["findings"] == summary["findings"]
    assert "report_hash" in report

    pdf = (out / "report.pdf").read_bytes()
    assert pdf[:5] == b"%PDF-"

    transfer = json.loads((out / "transfer.json").read_text(encoding="utf-8"))
    assert transfer["transfer_format"].startswith("cryptoscan")
    assert transfer["digests"]["payload_digest"]


def test_estate_cli_rejects_missing_dir(tmp_path: Path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--dir", str(tmp_path / "nope")],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
    )
    assert result.returncode == 2
