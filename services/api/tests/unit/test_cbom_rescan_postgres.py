"""Same inspection contracts on explicit owned disposable PostgreSQL."""
import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks,pytestmark as pytestmark
import test_cbom_rescan_inspection as contracts


@pytest.mark.parametrize('contract',[
    contracts.test_verified_rescan_is_scoped_not_automatic_clearance,
    contracts.test_retained_inventory_and_inspection_are_exact_estate,
    contracts.test_empty_manifest_is_not_absence_or_complete_inventory_proof,
    contracts.test_metadata_path_is_not_trusted_over_committed_content,
    contracts.test_actual_scanner_and_evidence_loader_to_scoped_inspection,
])
def test_postgres_rescan_contract(assured,contract):contract(assured)


@pytest.mark.parametrize('change',['wrong_system','foreign_job','null_tenant','wrong_target','old_scan','unfinished',
    'wrong_branch','requested_commit','nonlocal_type','future','no_receipts','all_unparsed',
    'content_tamper','manifest_tamper','unreceipted_finding','not_latest','oversize'])
def test_postgres_rescan_rejections(assured,change):
    contracts.test_unproven_or_changed_rescan_cannot_be_verified(assured,change)
