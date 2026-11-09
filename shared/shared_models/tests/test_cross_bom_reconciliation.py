"""Cross-BOM reconciliation (gap analysis §E), as tests.

"The system must show where evidence agrees, conflicts or is missing. It must
not automatically assume that the OpenSSL library is responsible for every TLS
connection made by the application."
"""

from __future__ import annotations

import pytest

from shared_models.cross_bom_reconciliation import (
    CBOM,
    CONFLICTS,
    MISSING,
    NBOM,
    PRESENCE,
    RESPONSIBILITY,
    SBOM,
    UNATTRIBUTED,
    attribute_operation,
    bom_claim,
    reconcile,
)


def claim(bom, relationship, target, kind=PRESENCE, subject="app-1",
          evidence=("EV-1",)):
    return bom_claim(bom=bom, subject=subject, claim_kind=kind,
                     relationship=relationship, target=target,
                     evidence_ids=list(evidence))


class TestClaims:

    def test_a_claim_without_evidence_is_a_guess(self):
        with pytest.raises(ValueError, match="guess"):
            claim(SBOM, "contains", "openssl", evidence=())

    def test_a_responsibility_claim_without_evidence_is_refused(self):
        with pytest.raises(ValueError, match="guess"):
            bom_claim(bom=NBOM, subject="app-1", claim_kind=RESPONSIBILITY,
                      relationship="negotiated", target="tls-session-7",
                      evidence_ids=[])


class TestAttribution:

    def test_presence_is_never_responsibility(self):
        claims = [claim(SBOM, "contains", "openssl", evidence=("SBOM-9",))]
        verdict = attribute_operation(component="openssl",
                                      operation="tls-session-7", claims=claims)
        assert verdict["attribution"] == UNATTRIBUTED
        assert "presence is not responsibility" in verdict["reason"]
        assert "SBOM-9" in verdict["reason"]

    def test_responsibility_needs_evidence_linking_component_to_operation(self):
        claims = [
            claim(SBOM, "contains", "openssl", evidence=("SBOM-9",)),
            bom_claim(bom=NBOM, subject="app-1", claim_kind=RESPONSIBILITY,
                      relationship="negotiated", target="tls-session-7",
                      evidence_ids=["PCAP-1"]),
        ]
        # the responsibility claim is about app-1, not about openssl
        verdict = attribute_operation(component="openssl",
                                      operation="tls-session-7", claims=claims)
        assert verdict["attribution"] == UNATTRIBUTED

        linked = bom_claim(bom=NBOM, subject="openssl",
                           claim_kind=RESPONSIBILITY,
                           relationship="negotiated", target="tls-session-7",
                           evidence_ids=["PCAP-1"])
        verdict = attribute_operation(component="openssl",
                                      operation="tls-session-7",
                                      claims=[linked])
        assert verdict["attribution"] == "ATTRIBUTED"
        assert verdict["evidence_ids"] == ["PCAP-1"]


class TestReconciliation:

    def test_agreement_conflict_and_missing_are_shown_side_by_side(self):
        rows = [
            claim(SBOM, "uses-library", "openssl", evidence=("SBOM-1",)),
            claim(CBOM, "uses-library", "openssl", evidence=("CBOM-1",)),
            claim(CBOM, "uses-algorithm", "aes-256-gcm", evidence=("CBOM-2",)),
            claim(NBOM, "uses-algorithm", "aes-128-cbc", evidence=("NBOM-2",)),
        ]
        report = reconcile(subject="app-1", claims=rows)
        assert report["counts"]["AGREES"] >= 1  # sbom+cbom on openssl
        assert any(c["verdict"] == CONFLICTS for c in report["conflicts"])
        conflict = [c for c in report["conflicts"] if
                    c["relationship"] == "uses-algorithm"][0]
        assert set(conflict["target"]) == {"aes-256-gcm", "aes-128-cbc"}
        # both sides are kept — a conflict never deletes a claim
        assert len(conflict["claims"]) == 2
        assert any(m["verdict"] == MISSING for m in report["missing"])

    def test_a_silent_bom_is_missing_never_agreement(self):
        report = reconcile(subject="app-1",
                           claims=[claim(SBOM, "contains", "openssl")])
        silent = [m for m in report["missing"] if m["boms"] == ["HBOM"]]
        assert silent and "blind spot" in silent[0]["reason"]

    def test_a_single_source_edge_reads_as_uncorroborated(self):
        report = reconcile(subject="app-1",
                           claims=[claim(SBOM, "contains", "openssl")])
        entry = [m for m in report["missing"]
                 if m["relationship"] == "contains"][0]
        assert "missing is not agreement" in entry["reason"]
