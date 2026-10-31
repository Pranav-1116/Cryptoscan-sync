"""The 10/50/100/150 curve: a real measurement, and a corpus that can fail.

A scale benchmark is easy to fake in three ways, and each has a test here:

* a corpus with no ground truth — the answer key is what precision is measured
  against, so it is checked to contain the things that must NOT be found (dark
  assets), the edges that must be refused, and the conflicts that must be reported;
* a curve that only measures speed — every row must carry accuracy, refusals,
  coverage and reproducibility, and the artifact is refused without them;
* a report served from memory — the endpoint must serve the committed artifact,
  refuse one from another corpus, and refuse a curve missing a scale.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _extra in ("scripts", "services/api", "services/database", "shared/shared_models", "shared/shared_config"):
    _candidate = str(ROOT / _extra)
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from shared_models import synthetic_estate as G  # noqa: E402

ARTIFACT = ROOT / "docs" / "bank-environment" / "107-scale-curve.json"


# --------------------------------------------------------------------------- #
# the corpus — an answer key, not a fixture
# --------------------------------------------------------------------------- #


def test_the_same_seed_produces_the_same_estates():
    first, second = G.build(12, seed=7), G.build(12, seed=7)
    assert first.assets == second.assets
    assert first.evidence == second.evidence
    assert first.relationships == second.relationships
    assert first.summary() == second.summary()


def test_adding_banks_does_not_change_the_ones_before_them():
    """A per-bank seed, so a curve's earlier points stay comparable when it grows."""
    small, large = G.build(5, seed=7), G.build(9, seed=7)
    assert small.assets == large.assets[: len(small.assets)]
    assert [bank.planted_crypto for bank in small.banks] == [
        bank.planted_crypto for bank in large.banks[:5]
    ]


def test_the_corpus_contains_the_things_that_must_not_be_found():
    corpus = G.build(30, seed=7)
    summary = corpus.summary()
    # dark assets: no evidence, so a finding on one is an invention
    assert summary["unobserved_assets"] > 0
    for bank in corpus.banks:
        evidence_targets = {row["target"] for row in bank.evidence}
        for name in bank.unobserved_assets:
            assert name not in evidence_targets, name
            assert name not in {subject for _, subject, _ in bank.planted_edges}
    # refusals: co-location, inference, and evidence nobody recorded
    whys = {row["why"] for bank in corpus.banks for row in bank.refused_edges}
    bases = {row["basis"] for bank in corpus.banks for row in bank.refused_edges}
    assert len(whys) == 2
    assert "INFERRED" in bases
    # conflicts: two planes disagreeing about one asset
    assert summary["expected_conflicts"] > 0


def test_a_refused_edge_can_never_also_be_a_planted_edge():
    """The scorer counts 'wrongly accepted' by triple; a colliding triple would lie."""
    for bank in G.build(40, seed=7).banks:
        planted = {
            (subject, predicate, obj) for predicate, subject, obj in bank.planted_edges
        }
        for row in bank.refused_edges:
            assert (row["subject"], row["predicate"], row["object"]) not in planted, row


def test_every_bank_carries_a_correlation_probe():
    for bank in G.build(25, seed=7).banks:
        probe = bank.correlation_probe
        assert probe.get("subject"), bank.bank
        assert probe.get("expect_agreement") is True
        if probe.get("expect_contradiction"):
            assert probe.get("absent_plane")


# --------------------------------------------------------------------------- #
# the harness — accuracy at a small scale, end to end
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def small() -> dict:
    import scale_bank_curve

    # the smallest scale, with the persistence write: that write is what proves the row
    # projection is a measurement rather than a guess
    return scale_bank_curve.measure(10, seed=7, persist=True)


def test_accuracy_is_measured_against_the_key_not_the_graph(small):
    crypto = small["accuracy"]["crypto"]
    relationships = small["accuracy"]["relationships"]
    for block in (crypto, relationships):
        assert block["expected"] > 0
        assert block["true_positives"] + block["false_negatives"] == block["expected"]
        assert 0.0 <= block["precision"] <= 1.0
        assert 0.0 <= block["recall"] <= 1.0
    assert crypto["precision"] == 1.0, crypto["false_positive_examples"]
    assert relationships["precision"] == 1.0, relationships["false_positive_examples"]


def test_the_refusals_are_scored_separately_from_precision(small):
    refusals = small["accuracy"]["relationships"]["refusals"]
    assert refusals["expected"] > 0
    assert refusals["rate"] == 1.0, refusals["wrongly_accepted_examples"]


def test_correlation_is_measured_at_scale(small):
    correlation = small["accuracy"]["correlation"]
    assert correlation["agreement"]["expected"] > 0
    assert correlation["agreement"]["detected"] == correlation["agreement"]["expected"]
    assert correlation["contradiction"]["detected"] == correlation["contradiction"]["expected"]
    # nothing was merged into the wrong asset, or the agreement count would be wrong
    assert correlation["subjects"]["ambiguous"] == 0
    assert correlation["subjects"]["state"] == "RESOLVED"


def test_evidence_is_reproducible_and_complete(small):
    evidence = small["evidence"]
    assert evidence["arrived"] == evidence["planted"]
    assert evidence["missing"] == 0
    assert evidence["establishment_citations_absent"] == 0
    assert evidence["correct"] is True
    assert evidence["reproducible"] is True
    assert evidence["conflicts"]["agrees"] is True
    assert evidence["blind_spot"]["unobserved_assets"] > 0


def test_coverage_distinguishes_own_evidence_from_being_known(small):
    coverage = small["evidence"]["coverage"]
    # infrastructure carries no evidence of its own but is still known through its edges
    assert coverage["asset_coverage"] < coverage["graph_coverage"]
    assert coverage["graph_coverage"] > 0.5


def test_performance_and_database_growth_are_reported(small):
    assert small["performance"]["ingest_seconds"] > 0
    assert small["performance"]["assets_per_second"] > 0
    assert small["performance"]["peak_rss_mb"] > 0
    assert small["database"]["rows_projected"] > small["estate"]["evidence"]


def test_the_persistence_projection_is_validated_against_a_real_write(small):
    """Row counts are only a proxy for database growth until one write confirms them."""
    database = small["database"]
    assert database.get("observations_written") == database.get("observations_projected")
    assert database["matches_projection"] is True


# --------------------------------------------------------------------------- #
# the artifact and the endpoint
# --------------------------------------------------------------------------- #


def test_the_committed_curve_covers_the_four_scales_and_states_accuracy():
    assert ARTIFACT.is_file(), "run scripts/scale_bank_curve.py"
    document = json.loads(ARTIFACT.read_text())
    assert document["schema"] == "cryptoscan.scale-curve/1"
    assert [row["banks"] for row in document["rows"]] == [10, 50, 100, 150]
    for row in document["rows"]:
        assert row["estate"]["schema"] == "cryptoscan.synthetic-estate/1"
        assert row["accuracy"]["crypto"]["expected"] > 0
        assert row["accuracy"]["relationships"]["refusals"]["expected"] > 0
        assert row["accuracy"]["correlation"]["agreement"]["expected"] > 0
        assert row["evidence"]["reproducible"] is True
        assert row["database"]["rows_projected"] > 0


def test_the_curve_does_not_degrade_with_scale():
    document = json.loads(ARTIFACT.read_text())
    rows = document["rows"]
    for row in rows:
        assert row["accuracy"]["crypto"]["precision"] >= 0.99, row["banks"]
        assert row["accuracy"]["crypto"]["recall"] >= 0.99, row["banks"]
        assert row["accuracy"]["relationships"]["recall"] >= 0.99, row["banks"]
        assert row["accuracy"]["relationships"]["refusals"]["rate"] >= 0.99, row["banks"]
        assert row["accuracy"]["correlation"]["agreement"]["recall"] >= 0.99, row["banks"]
        assert row["evidence"]["correct"] is True, row["banks"]
    # ingest grows with the estate; it must not grow faster than the estate does
    first, last = rows[0], rows[-1]
    growth = last["performance"]["ingest_seconds"] / max(first["performance"]["ingest_seconds"], 1e-9)
    estate_growth = last["estate"]["assets"] / first["estate"]["assets"]
    assert growth <= estate_growth * 3, (growth, estate_growth)


def test_the_endpoint_serves_the_artifact_without_measuring_anything(monkeypatch):
    from api.routers import scale_validation

    def refuse(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("the endpoint ran the harness inside a request")

    monkeypatch.setattr("scale_bank_curve.measure", refuse, raising=False)
    curve = scale_validation.load()
    assert [point.banks for point in curve.points] == [10, 50, 100, 150]
    assert curve.points[-1].agreement.detected == curve.points[-1].agreement.expected


def test_an_artifact_from_another_corpus_is_refused(tmp_path):
    from api.routers import scale_validation

    document = json.loads(ARTIFACT.read_text())
    document["rows"][0]["estate"]["schema"] = "cryptoscan.synthetic-estate/0"
    target = tmp_path / "stale.json"
    target.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="corpus this endpoint does not recognise"):
        scale_validation.load(target)


def test_a_curve_missing_a_scale_is_refused(tmp_path):
    from api.routers import scale_validation

    document = json.loads(ARTIFACT.read_text())
    document["rows"] = [row for row in document["rows"] if row["banks"] != 100]
    target = tmp_path / "short.json"
    target.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="missing \\[100\\]"):
        scale_validation.load(target)


def test_a_curve_with_no_accuracy_is_refused(tmp_path):
    from api.routers import scale_validation

    document = json.loads(ARTIFACT.read_text())
    document["rows"][0].pop("accuracy")
    target = tmp_path / "timings.json"
    target.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="states no accuracy"):
        scale_validation.load(target)


def test_the_route_answers_with_the_checked_curve():
    """The route is the checked load plus serialisation — asserted on the payload it sends."""
    from api.routers import scale_validation

    payload = scale_validation.scale_curve(user="auditor").model_dump()
    assert [point["banks"] for point in payload["points"]] == [10, 50, 100, 150]
    assert payload["points"][-1]["crypto"]["precision"] >= 0.99
    assert payload["points"][-1]["reproducible"] is True
    assert payload["notes"], "a curve served without its caveats is a claim, not a measurement"
    assert "synthetic" in " ".join(payload["notes"])
