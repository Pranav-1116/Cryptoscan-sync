"""Literal bounded Debian status parsing; tests never execute dpkg or scripts."""

import pytest
from inventory.linux_packages import dpkg_status
from inventory.host import collect, Refused
from shared_models.host_collection import HostInput, MAX_FILE_BYTES
from services.inventory.tests.test_host import manifest


def entry(name="openssl", status="install ok installed", version="3.0.13-1"):
    return f"Package: {name}\nStatus: {status}\n" + (f"Version: {version}\n" if version is not None else "")


@pytest.mark.parametrize("selection", ["install", "hold", "deinstall", "purge", "unknown"])
def test_current_installed_record_is_not_dropped_by_selection(selection):
    fact = dpkg_status(entry(status=selection + " ok installed").encode())[0]
    assert fact.software_name == "openssl" and fact.software_version == "3.0.13-1"
    assert fact.algorithm == fact.runtime_use == "UNKNOWN"


def test_crlf_unknown_fields_and_descriptions_are_not_executed_or_emitted(tmp_path):
    sentinel = tmp_path / "must-not-exist"
    data = entry() + f"Description: metadata only\n $(touch {sentinel})\nPassword: never-export-this\n"
    fact = dpkg_status(data.replace("\n", "\r\n").encode())[0]
    assert not sentinel.exists() and "never-export" not in fact.model_dump_json()


def test_missing_version_is_unknown_and_noninstalled_is_not_absence():
    facts = dpkg_status((entry(version=None) + "\n" + entry("removed", "deinstall ok config-files")).encode())
    assert len(facts) == 1 and facts[0].software_version is None
    with pytest.raises(Refused):
        dpkg_status(entry(status="deinstall ok config-files").encode())


@pytest.mark.parametrize(
    "data",
    [
        entry() + "Package: alternate\n",
        entry() + "Version: 9\n",
        entry() + "sTaTuS: install ok installed\n",
        entry() + " Version: 9\n",
        entry() + "\n" + entry(version="9"),
        entry() + "Architecture: amd64\n\n" + entry() + "Architecture: arm64\n",
        " Package: openssl\n" + entry(),
        entry(status="install ok mystery"),
        entry(status="install installed"),
        "Status: install ok installed\nVersion: 1\n",
        entry(name="bad/name"),
        entry(version=""),
        entry() + "\x00",
        "Package: openssl\rStatus: install ok installed\n",
    ],
)
def test_ambiguous_malformed_or_multiarch_refuses_whole_input(data, tmp_path):
    path = tmp_path / "status"
    path.write_bytes(data.encode())
    snapshot = collect(manifest(tmp_path, [HostInput(input_id="packages", kind="DPKG_STATUS", path=str(path))]))
    assert snapshot.receipts[0].status == "INVALID" and not snapshot.receipts[0].facts
    assert not snapshot.whole_host_coverage_verified


def test_byte_and_fact_budgets():
    with pytest.raises(Refused):
        dpkg_status(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(Refused):
        dpkg_status(("\n".join(entry("p" + str(i)) for i in range(1001))).encode())
