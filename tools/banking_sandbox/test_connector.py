"""The connected lab must not turn collector failure into an empty BOM success."""

import json
import re
from pathlib import Path

import pytest

from tools.banking_sandbox.connector import connector
from tools.banking_sandbox.connector.dashboard import TEMPLATE
from tools.banking_sandbox.generator import generate


def test_static_collector_failure_refuses_connected_output(tmp_path, monkeypatch):
    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")
    monkeypatch.setattr(
        "tools.banking_sandbox.harness.run_static",
        lambda *args, **kwargs: {"failure": "COLLECTOR_EXIT_1", "boundary_receipt": None},
    )

    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="Static collector failed"):
        connector.connect(estate, output)
    assert not (output / "boms").exists()
    assert not (estate / "scanner-inputs").exists()


def test_missing_isolation_proof_refuses_connected_output(tmp_path, monkeypatch):
    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")
    monkeypatch.setattr(
        "tools.banking_sandbox.harness.run_static",
        lambda *args, **kwargs: {"failure": None, "boundary_receipt": {"guard": {
            "oracle_read_denied": False, "socket_creation_denied": True,
            "seccomp": "ACTIVE_NETWORK_DENIED", "landlock_abi": 8,
        }}},
    )
    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="isolation proof is unavailable"):
        connector.connect(estate, output)
    assert not (output / "boms").exists()


def test_lb_collector_failure_refuses_connected_output(tmp_path, monkeypatch):
    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")

    def run_static(*args, mode="static", **kwargs):
        if mode == "lb-config":
            return {"failure": "COLLECTOR_EXIT_1"}
        return {"failure": None, "boundary_receipt": {"guard": {
            "oracle_read_denied": True, "socket_creation_denied": True,
            "seccomp": "ACTIVE_NETWORK_DENIED", "landlock_abi": 8,
        }}}

    monkeypatch.setattr("tools.banking_sandbox.harness.run_static", run_static)
    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="LB config collector failed"):
        connector.connect(estate, output)
    assert not (output / "boms").exists()


def test_invalid_bom_schema_refuses_connected_output(tmp_path, monkeypatch):
    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")
    monkeypatch.setattr(
        "tools.banking_sandbox.harness.run_static",
        lambda *args, **kwargs: {"failure": None, "boundary_receipt": {"guard": {
            "oracle_read_denied": True, "socket_creation_denied": True,
            "seccomp": "ACTIVE_NETWORK_DENIED", "landlock_abi": 8,
        }}},
    )
    monkeypatch.setattr(connector, "_findings_to_crypto", lambda *args: [])
    monkeypatch.setattr(connector, "_build_boms", lambda *args: {"cbom": {"components": 1}})
    monkeypatch.setattr(connector, "_validate", lambda *args: {"schema_checks": {"cbom": {"ok": False}, "sbom": {"ok": True}}})

    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="BOM schema validation failed"):
        connector.connect(estate, output)
    assert (output / "reports/validation.json").is_file()
    assert not (output / "dashboard/index.html").exists()


def test_connected_bom_exports_validate_without_dropping_vendor_only_rows(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    for group in ("services", "shared"):
        for package in (root / group).iterdir():
            if package.is_dir():
                monkeypatch.syspath_prepend(str(package))
    from cbom.cyclonedx16 import validate_cyclonedx16
    from tools.banking_sandbox.documents import validators

    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")
    inventory = connector._collect_inventory(estate, [])
    inventory["_vendors_raw"].append({
        "vendor_id": "fixture-vendor-without-crypto", "product": "Unobserved Vendor",
        "category": "service", "bank_id": "bank-0001", "declared_algorithms": [],
    })
    output = tmp_path / "output"
    output.mkdir()
    connector._build_boms(estate, inventory, output, {})
    boms = output / "boms"
    cdx, _ = validators()
    assert validate_cyclonedx16(json.loads((boms / "cbom.json").read_text()))["ok"]
    assert validate_cyclonedx16(json.loads((boms / "vbom.cyclonedx.json").read_text()))["ok"]
    for name in ("sbom.json", "hbom.cyclonedx.json"):
        cdx.validate(json.loads((boms / name).read_text()))
    native = json.loads((boms / "vbom.json").read_text())
    assert any(v["vendor_id"] == "fixture-vendor-without-crypto" for v in native["vendors"])
    qualified = json.loads((boms / "vbom.cyclonedx.json").read_text())
    assert {p["name"]: p["value"] for p in qualified["metadata"]["properties"]}[
        "cryptoscan:vendor_only_in_native_document"
    ] == "1"


def test_dashboard_links_resolve_outside_dashboard_directory():
    assert "fetch('../'+path" in TEMPLATE
    links = re.findall(r'href="([^"]+)"', TEMPLATE)
    assert all(link.startswith(("#", "../")) for link in links)
    assert {"../boms/cbom.json", "../boms/hbom.json", "../scan/static/metrics.json"} <= set(links)
