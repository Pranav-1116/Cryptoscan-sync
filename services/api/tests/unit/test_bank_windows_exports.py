"""The Windows gap is closed by exports, and the collector says how far that goes.

The bank sandbox had no Windows host, so the `windows` maturity gap could only be
asserted, never exercised. ``tools.banking_sandbox.windows_exports`` writes a
bundle in the three formats Windows actually produces (``reg export``,
``Get-TlsCipherSuite``, ``Get-ChildItem Cert:``), derived from the bank's own
declared assets, so the collector has something real to parse.

The point of these tests is the *ceiling*: parsing policy is CONFIGURATION. An
enabled protocol is permitted, not negotiated; a certificate in a store is not
one that was presented. If the collector ever labels these facts anything
stronger, this file fails.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "scripts"))


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def estate(tmp_path: Path) -> Path:
    public = tmp_path / "public"
    (public / "banks").mkdir(parents=True)
    (public / "certificates").mkdir(parents=True)
    (public / "banks" / "bank-0001.json").write_text('{"bank_id": "bank-0001"}', encoding="utf-8")
    rows = [
        {
            "certificate_id": f"bank-0001-cert-{index}",
            "app_id": f"bank-0001-app-{index}",
            "issuer_ref": "bank-0001-issuing",
            "not_before": "2029-01-01T00:00:00+00:00",
            "not_after": "2030-01-01T00:00:00+00:00",
            "public_key_algorithm": "RSA-2048",
            "private_key_persisted": False,
        }
        for index in range(3)
    ]
    (public / "certificates" / "bank-0001.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return tmp_path


def test_the_bundle_is_written_in_the_formats_windows_writes(estate: Path, tmp_path: Path):
    from banking_sandbox import windows_exports

    out = tmp_path / "exports"
    summary = windows_exports.build_exports(estate, out, host="BANK-WIN-01")

    assert summary["synthetic"] is True
    assert summary["establishes"] == "CONFIGURATION"
    assert summary["files"] == ["SCHANNEL.reg", "machine-certificates.json", "tls-cipher-suites.json"]
    for name in summary["files"]:
        assert (out / name).is_file(), name
    # the marker is inside the artefact, not only in the summary
    assert windows_exports.SYNTHETIC_MARKER in (out / "SCHANNEL.reg").read_text(encoding="utf-8")


def test_every_artefact_parses_and_nothing_is_refused(estate: Path, tmp_path: Path):
    from banking_sandbox import windows_exports
    from api.windows_artifacts import parse_artifacts

    out = tmp_path / "exports"
    windows_exports.build_exports(estate, out)
    parsed = parse_artifacts(sorted(out.iterdir()))

    assert parsed["refused"] == []
    formats = {row["format"] for row in parsed["files"]}
    assert formats == {"schannel-registry", "cipher-suites-json", "certificate-store"}
    # three scopes per protocol: a server enabling TLS 1.0 is not a client enabling it
    assert len(parsed["protocols"]) == 3 * len(windows_exports.POLICY)
    assert {row["scope"] for row in parsed["protocols"]} == {"global", "client", "server"}
    assert len(parsed["suites"]) == len(windows_exports.SUITES)
    assert len(parsed["certificates"]) == 3


def test_the_collector_labels_export_evidence_as_configuration_only(estate: Path, tmp_path: Path):
    """No handshake, no execution: nothing here may claim OBSERVED or NEGOTIATED."""
    from banking_sandbox import windows_exports
    from api import host_collect

    out = tmp_path / "exports"
    windows_exports.build_exports(estate, out)
    package = host_collect.collect_windows(sorted(out.iterdir()), host="BANK-WIN-01")

    assert package["summary"]["establishes"] == "CONFIGURED"
    assert {row["evidence_type"] for row in package["evidence"]} == {"CONFIGURED"}
    states = {(row.get("facts") or {}).get("usage_state") for row in package["evidence"]}
    # a fact that carries a usage state carries CONFIGURED; none is silent about depth
    assert states - {None} == {"CONFIGURED"}, states
    assert "NEGOTIATED" not in json.dumps(package)
    # the host asset exists and says where the facts came from
    host = next(asset for asset in package["assets"] if asset["type"] == "HOST")
    assert host["identity"]["hostname"] == "BANK-WIN-01"
    assert host["attributes"]["source"] == "exported artefacts"


def test_a_directory_of_exports_expands_but_a_file_does_not(estate: Path, tmp_path: Path):
    from banking_sandbox import windows_exports

    script = _load_script("connect_bank_sandbox_maturity", ROOT / "scripts" / "connect_bank_sandbox.py")
    out = tmp_path / "exports"
    windows_exports.build_exports(estate, out)

    expanded = script._expand_artifacts([str(out)])
    assert sorted(Path(item).name for item in expanded) == [
        "SCHANNEL.reg", "machine-certificates.json", "tls-cipher-suites.json",
    ]
    single = script._expand_artifacts([str(out / "SCHANNEL.reg")])
    assert single == [str(out / "SCHANNEL.reg")]


def test_a_port_range_expands_and_a_single_target_survives():
    script = _load_script("connect_bank_sandbox_targets", ROOT / "scripts" / "connect_bank_sandbox.py")
    assert script._expand_targets(["127.0.0.1:21000-21003"]) == [
        "127.0.0.1:21000", "127.0.0.1:21001", "127.0.0.1:21002", "127.0.0.1:21003",
    ]
    assert script._expand_targets(["bank.example:443"]) == ["bank.example:443"]
    # a range that runs backwards is left alone rather than silently emptied
    assert script._expand_targets(["host:21003-21000"]) == ["host:21003-21000"]
