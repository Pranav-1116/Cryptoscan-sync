"""Relationship provenance, sightings and impact closure — roadmap item 1 rows.

Standing directive: "Every graph relationship should have evidence behind it."
These tests pin the display classes (proven / inferred / unknown), the sighting
window (evidence timestamps only), and impact propagation where a hypothetical is
always labelled a projection.
"""

from __future__ import annotations

from shared_models.relationship_provenance import (
    INFERRED,
    PROVEN,
    UNKNOWN,
    edge_sighting,
    impact_closure,
    provenance_of,
    sighting_window,
)


def ev(eid, kind, observed_at="2026-11-01T00:00:00+00:00"):
    return {"evidence_type": kind, "observed_at": observed_at}


class TestProvenanceClasses:

    def test_direct_evidence_makes_a_relationship_proven(self):
        edge = {"subject": "payments-api", "predicate": "uses",
                "object": "tls-cert-1", "basis": "CONFIGURATION",
                "evidence_ids": ["E1"]}
        lookup = {"E1": ev("E1", "RUNTIME_OBSERVED")}
        result = provenance_of(edge, lookup)
        assert result["provenance"] == PROVEN
        assert result["unresolved_evidence_ids"] == []

    def test_declarations_and_imports_make_it_inferred_never_proven(self):
        edge = {"subject": "payments-api", "predicate": "uses",
                "object": "hsm-1", "basis": "APPROVED_MAPPING",
                "evidence_ids": ["E1", "E2"]}
        lookup = {"E1": ev("E1", "VENDOR_DECLARED"),
                  "E2": ev("E2", "IMPORTED")}
        result = provenance_of(edge, lookup)
        assert result["provenance"] == INFERRED
        assert "must not be shown as proven" in result["reason"]

    def test_an_edge_without_evidence_is_unknown_never_proven(self):
        edge = {"subject": "a", "predicate": "uses", "object": "b",
                "basis": "CONFIGURATION", "evidence_ids": []}
        assert provenance_of(edge, {})["provenance"] == UNKNOWN

    def test_unresolved_evidence_ids_count_as_nothing(self):
        edge = {"subject": "a", "predicate": "uses", "object": "b",
                "basis": "CONFIGURATION", "evidence_ids": ["GONE"]}
        result = provenance_of(edge, {"OTHER": ev("OTHER", "RUNTIME_OBSERVED")})
        assert result["provenance"] == UNKNOWN
        assert result["unresolved_evidence_ids"] == ["GONE"]

    def test_one_direct_record_among_many_is_enough_to_prove(self):
        edge = {"subject": "a", "predicate": "uses", "object": "b",
                "basis": "CONFIGURATION", "evidence_ids": ["E1", "E2"]}
        lookup = {"E1": ev("E1", "VENDOR_DECLARED"),
                  "E2": ev("E2", "NETWORK_ACTIVE_OBSERVED")}
        assert provenance_of(edge, lookup)["provenance"] == PROVEN


class TestSightingWindow:

    def test_first_and_last_seen_come_from_evidence_timestamps(self):
        records = [
            {"observed_at": "2026-11-01T00:00:00+00:00"},
            {"observed_at": "2026-10-15T00:00:00+00:00"},
            {"observed_at": "2026-11-05T00:00:00+00:00"},
        ]
        window = sighting_window(records)
        assert window["first_seen"] == "2026-10-15T00:00:00+00:00"
        assert window["last_seen"] == "2026-11-05T00:00:00+00:00"
        assert window["sightings"] == 3

    def test_undated_records_extend_neither_bound(self):
        records = [{"observed_at": None}, {"observed_at": "  "}, {}]
        window = sighting_window(records)
        assert window["first_seen"] is None
        assert window["last_seen"] is None
        assert "never back-filled" in window["reason"]

    def test_mixed_records_use_only_the_datable_ones(self):
        records = [{"observed_at": None},
                   {"observed_at": "2026-11-02T00:00:00+00:00"}]
        window = sighting_window(records)
        assert window["first_seen"] == "2026-11-02T00:00:00+00:00"
        assert window["sightings"] == 1

    def test_edge_sighting_resolves_only_known_evidence(self):
        edge = {"evidence_ids": ["E1", "GONE"]}
        lookup = {"E1": ev("E1", "RUNTIME_OBSERVED",
                           "2026-11-03T00:00:00+00:00")}
        window = edge_sighting(edge, lookup)
        assert window["first_seen"] == "2026-11-03T00:00:00+00:00"
        assert window["sightings"] == 1


class TestImpactClosure:

    # payments-api → load-balancer → tls-cert → rsa-2048 → root-ca
    EDGES = [
        {"subject": "payments-api", "predicate": "uses", "object": "load-balancer",
         "basis": "CONFIGURATION", "evidence_ids": ["E1"]},
        {"subject": "load-balancer", "predicate": "uses", "object": "tls-cert",
         "basis": "CONFIGURATION", "evidence_ids": ["E2"]},
        {"subject": "tls-cert", "predicate": "depends_on", "object": "rsa-2048",
         "basis": "CONFIGURATION", "evidence_ids": ["E3"]},
        {"subject": "rsa-2048", "predicate": "signed_by", "object": "root-ca",
         "basis": "CONFIGURATION", "evidence_ids": ["E4"]},
    ]
    LOOKUP = {f"E{i}": ev(f"E{i}", "RUNTIME_OBSERVED") for i in range(1, 5)}

    def test_a_change_flows_up_the_dependency_chain(self):
        result = impact_closure(self.EDGES, "root-ca", evidence_by_id=self.LOOKUP)
        names = [row["asset"] for row in result["affected"]]
        # every dependent upstream is affected, in hop order
        assert names[0] == "root-ca"
        assert names[1] == "rsa-2048"
        assert "payments-api" in names
        assert result["counts"]["affected"] == 4

    def test_each_hop_carries_its_own_provenance(self):
        result = impact_closure(self.EDGES, "tls-cert", evidence_by_id=self.LOOKUP)
        payments = next(row for row in result["affected"]
                        if row["asset"] == "payments-api")
        assert payments["hops"] == 2
        assert payments["chain_provenance"] == PROVEN
        assert payments["chain"][0]["provenance"] == PROVEN

    def test_a_chain_with_an_unknown_hop_is_not_a_proven_chain(self):
        edges = [
            {"subject": "app", "predicate": "uses", "object": "svc",
             "basis": "CONFIGURATION", "evidence_ids": []},          # unknown hop
            {"subject": "svc", "predicate": "uses", "object": "host",
             "basis": "CONFIGURATION", "evidence_ids": ["E1"]},      # proven hop
        ]
        result = impact_closure(edges, "host", evidence_by_id={"E1": ev("E1", "RUNTIME_OBSERVED")})
        app = next(row for row in result["affected"] if row["asset"] == "app")
        assert app["chain_provenance"] == UNKNOWN  # weakest link labels the chain

    def test_the_result_is_always_labelled_a_projection(self):
        result = impact_closure(self.EDGES, "tls-cert", evidence_by_id=self.LOOKUP)
        assert result["result_kind"] == "IMPACT_PROJECTION"
        assert "not a production change" in result["note"]

    def test_an_unconnected_asset_affects_only_itself(self):
        result = impact_closure(self.EDGES, "unrelated-host")
        assert [row["asset"] for row in result["affected"]] == ["unrelated-host"]
        assert result["counts"]["affected"] == 0

    def test_predicate_filtering_limits_the_closure(self):
        result = impact_closure(self.EDGES, "root-ca",
                                evidence_by_id=self.LOOKUP,
                                predicates=["signed_by"])
        names = {row["asset"] for row in result["affected"]}
        # only the signed_by hop propagates; depends_on edges are filtered out
        assert names == {"root-ca", "rsa-2048"}
