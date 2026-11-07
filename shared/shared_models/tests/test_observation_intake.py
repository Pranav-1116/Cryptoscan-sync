"""Observation intake and projection rebuild (gap analysis §C), as tests.

"Duplicate observations do not create duplicate assets or relationships."
"Rebuilding Neo4j from authoritative records produces the same logical graph."
"""

from __future__ import annotations

import random

import pytest

from shared_models.observation_intake import (
    ingest_observations,
    rebuild_projection,
)


def obs(asset_id="lib-1", **over):
    base = {"plane": "linux", "asset_type": "crypto-library",
            "locator": "proc:1234", "evidence_ids": ["EV-1"]}
    base.update(over)
    if asset_id is not None:
        base["asset_id"] = asset_id
    return base


class TestDuplicateCollapse:

    def test_duplicate_observations_collapse_to_one_asset(self):
        intake = ingest_observations([obs(), obs(), obs(evidence_ids=["EV-2"])])
        assert len(intake["assets"]) == 1
        assert intake["duplicates_collapsed"] == 2
        # evidence is unioned, never lost
        assert intake["assets"][0]["evidence_ids"] == ["EV-1", "EV-2"]

    def test_duplicate_relationships_collapse_to_one_edge(self):
        edge = {"kind": "relationship", "subject": "app-1",
                "predicate": "uses", "object": "lib-1", "evidence_ids": ["E"]}
        intake = ingest_observations([edge, dict(edge)])
        assert len(intake["relationships"]) == 1
        assert intake["duplicates_collapsed"] == 1

    def test_content_identity_collapses_when_no_asset_id_is_named(self):
        intake = ingest_observations([obs(asset_id=None), obs(asset_id=None)])
        assert len(intake["assets"]) == 1

    def test_an_unplaceable_observation_is_refused(self):
        with pytest.raises(ValueError, match="unplaceable"):
            ingest_observations([obs(asset_id=None, locator="")])
        with pytest.raises(ValueError, match="not a relationship"):
            ingest_observations([{"kind": "relationship", "subject": "a",
                                  "predicate": "p", "object": ""}])


class TestRebuildDeterminism:

    def test_rebuilding_from_the_same_rows_gives_the_same_logical_graph(self):
        rows = [obs("a"), obs("b"), obs("a", evidence_ids=["EV-9"]),
                {"kind": "relationship", "subject": "app", "predicate": "uses",
                 "object": "a", "evidence_ids": ["E1"]}]
        first = rebuild_projection(ingest_observations(rows))
        shuffled = list(rows)
        random.Random(7).shuffle(shuffled)
        second = rebuild_projection(ingest_observations(shuffled))
        assert first["graph_digest"] == second["graph_digest"]
        assert first["vertex_count"] == second["vertex_count"] == 2

    def test_a_different_estate_gives_a_different_digest(self):
        one = rebuild_projection(ingest_observations([obs("a")]))
        two = rebuild_projection(ingest_observations([obs("b")]))
        assert one["graph_digest"] != two["graph_digest"]

    def test_the_digest_claims_reproducibility_not_truth(self):
        report = rebuild_projection(ingest_observations([obs("a")]))
        assert "does not prove the rows are true" in report["note"]
