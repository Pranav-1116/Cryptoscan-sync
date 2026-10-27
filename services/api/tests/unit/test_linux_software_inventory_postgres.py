"""Owned disposable PostgreSQL: software reads cannot change original evidence."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_linux_software_inventory as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_real_intake_software_keeps_packages_binary_and_unknowns_separate,
        contracts.test_ambiguous_package_input_is_explicit_gap_not_no_packages,
        contracts.test_duplicate_versions_preserved_without_selecting_winner,
    ],
)
def test_postgres_linux_software(assured, contract):
    contract(assured)


@pytest.mark.parametrize(
    "kind,manager,version", [("APK_INSTALLED", "apk", "3.3.2-r1"), ("RPM_SQLITE", "rpm", "1:3.2.2-5.el9")]
)
def test_postgres_linux_package_namespaces(assured, kind, manager, version):
    contracts.test_other_linux_package_namespaces_are_not_merged(assured, kind, manager, version)
