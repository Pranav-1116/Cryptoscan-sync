"""Digital Twin investigation journeys (gap analysis §F), as tests.

"Can an investigator start with a certificate, find every asset using it, see
the evidence for each connection, and determine which business systems could
be affected by its expiry? That is a meaningful Digital Twin acceptance test."
"""

from __future__ import annotations

from shared_models.twin_investigation import investigate_certificate


def journey(**over):
    base = dict(
        certificate_id="cert-root-39",
        expiry="2026-12-01T00:00:00+00:00",
        usage_edges=[
            {"asset": "lb-1", "relationship": "presents", "target":
                "cert-root-39", "evidence_ids": ["PCAP-1"]},
            {"asset": "gw-2", "relationship": "presents", "target":
                "cert-root-39", "evidence_ids": []},
        ],
        dependency_edges=[
            {"system": "payments", "asset": "lb-1", "relationship":
                "depends_on", "evidence_ids": ["CMDB-1"]},
            {"system": "lending", "asset": "gw-2", "relationship":
                "depends_on", "evidence_ids": ["CMDB-2"]},
        ],
        ownership={"payments": "payments-team"},
    )
    base.update(over)
    return investigate_certificate(**base)


class TestCertificateJourney:

    def test_every_asset_using_the_certificate_is_found_with_its_evidence(self):
        report = journey()
        assert report["assets_using"] == ["lb-1"]
        proven = report["connections"]["proven"]
        assert proven[0]["evidence_ids"] == ["PCAP-1"]
        assert report["connections"]["unevidenced"][0]["asset"] == "gw-2"

    def test_impact_is_proven_only_through_evidenced_hops(self):
        report = journey()
        affected = report["business_systems"]["affected"]
        assert [s["system"] for s in affected] == ["payments"]
        assumed = report["business_systems"]["assumed"]
        assert [s["system"] for s in assumed] == ["lending"]
        assert assumed[0]["paths"][0]["path_provenance"] == "ASSUMED"

    def test_unknown_owners_stay_unknown_and_blind_spots_are_visible(self):
        report = journey(ownership={})
        assert report["unknown_owners"] == ["unknown"]
        kinds = {b["kind"] for b in report["blind_spots"]}
        assert "UNEVIDENCED_CONNECTION" in kinds
        assert "ASSUMED_PATH" in kinds
        assert all(b["is_clean_result"] is False for b in report["blind_spots"])

    def test_an_empty_journey_is_answerable_but_never_clean(self):
        report = journey(usage_edges=[], dependency_edges=[])
        assert report["answerable"] is False
        assert report["assets_using"] == []
        assert "blind spot" in report["note"]
