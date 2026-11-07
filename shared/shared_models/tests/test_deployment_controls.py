"""Deployment and operations controls — roadmap item 10 acceptance rows.

Standing rules: a backup is not a tested restore; an unattested control is never
drawn as OK; a stale drill cannot hold readiness; the bank keeps control of its
database, evidence and crypto metadata only when each is located and named;
air-gapped is claimed only where it is offered.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from shared_models.deployment_controls import (
    ATTESTED,
    CONTROLS,
    CORE_CONTROLS,
    FAILED,
    NOT_ATTESTED,
    STALE,
    attest,
    control_catalog,
    control_state,
    deployment_readiness,
)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def at(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def attestation(control="BACKUP", days_ago=6.0, status="OK"):
    return attest(control=control, evidence_ids=[f"E-{control}"],
                  observed_at=at(days_ago), actor="ops", status=status)


def full_attestations():
    return [attestation(control=name) for name in CORE_CONTROLS]


CLEAN_CUSTODY = {
    "database": {"controller": "BANK", "location": "bank-dc-1/postgres-primary"},
    "evidence": {"controller": "BANK", "location": "bank-dc-1/object-store"},
    "crypto_metadata": {"controller": "BANK", "location": "bank-dc-1/vault"},
}


class TestAttestationConstruction:

    def test_an_attestation_without_evidence_is_refused(self):
        with pytest.raises(ValueError, match="is a claim"):
            attest(control="BACKUP", evidence_ids=[], observed_at=at(1),
                   actor="ops")

    def test_an_attestation_without_a_clock_is_refused(self):
        with pytest.raises(ValueError, match="cannot age"):
            attest(control="BACKUP", evidence_ids=["E1"], observed_at="  ",
                   actor="ops")

    def test_an_unknown_control_is_refused(self):
        with pytest.raises(ValueError, match="unknown deployment control"):
            attest(control="VIBES", evidence_ids=["E1"], observed_at=at(1),
                   actor="ops")

    def test_a_failed_drill_is_fileable_and_visible(self):
        row = attestation(control="DR", status="FAILED")
        assert row["status"] == "FAILED"


class TestCatalogue:

    def test_every_item10_row_is_a_control_or_a_mode(self):
        catalog = control_catalog()
        ids = {row["id"] for row in catalog["controls"]}
        for name in ("HA", "BACKUP", "RESTORE_TESTED", "DR", "TENANT_ISOLATION",
                     "BANK_IAM", "MTLS", "KEY_ROTATION", "SIGNED_RELEASES",
                     "OWN_SBOM", "MIGRATION_VALIDATION", "MONITORING",
                     "DATA_CUSTODY"):
            assert name in ids, name
        assert catalog["modes"] == ["ON_PREM", "AIR_GAPPED"]
        assert set(CONTROLS) == set(CORE_CONTROLS)


class TestReadiness:

    def test_unattested_is_never_ready(self):
        result = deployment_readiness(attestations=[], custody=CLEAN_CUSTODY, now=NOW)
        assert result["verdict"] == "ATTESTATION_INCOMPLETE"
        assert all(g["is_clean_result"] is False for g in result["gaps"])
        assert result["controls"]["HA"]["state"] == NOT_ATTESTED
        assert "never drawn as OK" in result["controls"]["HA"]["reason"]

    def test_a_backup_is_not_a_tested_restore(self):
        result = deployment_readiness(attestations=[attestation("BACKUP")],
                                      custody=CLEAN_CUSTODY, now=NOW)
        assert result["verdict"] == "ATTESTATION_INCOMPLETE"
        gap = next(g for g in result["gaps"]
                   if "backup is not a tested restore" in g["detail"])
        assert gap["control"] == "RESTORE_TESTED"

    def test_a_tested_restore_covers_the_restore_control(self):
        rows = [attestation("BACKUP"), attestation("RESTORE_TESTED")]
        state = control_state("RESTORE_TESTED", rows, now=NOW)
        assert state["state"] == ATTESTED
        assert "validity window" in state["reason"]

    def test_a_stale_drill_cannot_hold_readiness(self):
        rows = [attestation("RESTORE_TESTED", days_ago=200)]
        state = control_state("RESTORE_TESTED", rows, now=NOW)
        assert state["state"] == STALE
        assert "cannot hold readiness" in state["reason"]

    def test_a_failed_drill_stays_failed_until_a_newer_pass_exists(self):
        rows = [attestation("DR", days_ago=30, status="FAILED")]
        assert control_state("DR", rows, now=NOW)["state"] == FAILED
        rows.append(attestation("DR", days_ago=3))
        assert control_state("DR", rows, now=NOW)["state"] == ATTESTED

    def test_full_attestation_and_clean_custody_is_ready(self):
        result = deployment_readiness(attestations=full_attestations(),
                                      custody=CLEAN_CUSTODY, now=NOW)
        assert result["verdict"] == "DEPLOYMENT_READY"
        assert result["gaps"] == []

    def test_the_verdict_is_reproducible(self):
        def run():
            return json.dumps(deployment_readiness(
                attestations=full_attestations(), custody=CLEAN_CUSTODY, now=NOW),
                sort_keys=True, default=str)
        assert run() == run()


class TestCustody:

    def test_unknown_location_is_not_bank_control(self):
        result = deployment_readiness(attestations=full_attestations(),
                                      custody={"database": {"controller": "BANK",
                                                            "location": "dc-1"},
                                               "evidence": {"controller": "BANK",
                                                            "location": "dc-1"}},
                                      now=NOW)
        gap = next(g for g in result["gaps"]
                   if "crypto_metadata" in g["detail"]
                   and "unknown location is not bank control" in g["detail"])
        assert gap["control"] == "DATA_CUSTODY"

    def test_a_third_party_controller_is_a_custody_failure(self):
        custody = {**CLEAN_CUSTODY,
                   "evidence": {"controller": "CLOUD_SAAS",
                                "location": "vendor-bucket"}}
        result = deployment_readiness(attestations=full_attestations(),
                                      custody=custody, now=NOW)
        gap = next(g for g in result["gaps"] if "not the bank" in g["detail"])
        assert gap["state"] == FAILED
        assert result["verdict"] == "ATTESTATION_INCOMPLETE"

    def test_no_custody_map_is_a_gap_not_a_pass(self):
        result = deployment_readiness(attestations=full_attestations(),
                                      custody=None, now=NOW)
        gap = next(g for g in result["gaps"] if g["control"] == "DATA_CUSTODY")
        assert "unknown location is not bank control" in gap["detail"]


class TestModes:

    def test_air_gapped_is_claimed_only_where_offered(self):
        result = deployment_readiness(attestations=full_attestations(),
                                      offered_modes=["ON_PREM"],
                                      custody=CLEAN_CUSTODY,
                                      mode="AIR_GAPPED", now=NOW)
        assert result["verdict"] == "MODE_NOT_OFFERED"
        assert result["controls"] == {}
        assert "never assumed" in result["reason"]

    def test_an_offered_air_gapped_mode_is_assessed_like_any_other(self):
        result = deployment_readiness(attestations=full_attestations(),
                                      offered_modes=["ON_PREM", "AIR_GAPPED"],
                                      custody=CLEAN_CUSTODY,
                                      mode="AIR_GAPPED", now=NOW)
        assert result["verdict"] == "DEPLOYMENT_READY"
        assert "AIR_GAPPED" in result["offered_modes"]

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(ValueError, match="unknown deployment mode"):
            deployment_readiness(attestations=[], mode="SPACE")
