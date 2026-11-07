"""Phase-8 qualification suite tests (docs/cryptolog/01_PRODUCT_SPEC.md).

Every check passes against the SYNTHETIC corpus; the corpus is labelled
synthetic at the source; the external acts stay register-only — the
platform never marks them done from inside the repo.
"""

from __future__ import annotations

from cryptolog.qualification_suite import EXTERNAL_ACTS, run_suite
from shared_models.cryptolog_corpus import (
    SYNTHETIC_COLLECTOR, generate_corpus,
)


def test_the_corpus_is_deterministic_and_labelled_synthetic():
    assert generate_corpus(10) == generate_corpus(10)
    for event in generate_corpus(10):
        assert event["attributes"]["synthetic"] is True
        assert event["attributes"]["corpus"].startswith("cryptoscan.cryptolog-synthetic-corpus/")
        assert event["source"]["collector_id"] == SYNTHETIC_COLLECTOR, \
            "a synthetic result can never masquerade as an observation"


def test_every_qualification_check_passes():
    result = run_suite(corpus_size=30, volume_size=100)
    by_name = {c["check"]: c for c in result["checks"]}
    assert by_name["synthetic-corpus-contract"]["status"] == "PASS"
    assert by_name["event-ordering-verify"]["status"] == "PASS"
    assert "VERIFIED" in by_name["event-ordering-verify"]["detail"]
    assert by_name["event-ordering-tamper-named"]["status"] == "PASS"
    assert by_name["duplicate-idempotency"]["status"] == "PASS"
    assert by_name["tampering-detected"]["status"] == "PASS"
    assert "INVALID_HASH" in by_name["tampering-detected"]["detail"]
    assert by_name["deletion-detected"]["status"] == "PASS"
    assert "ARTIFACT_MISSING" in by_name["deletion-detected"]["detail"]
    assert by_name["synthetic-volume-run"]["status"] == "PASS"
    assert "never a real-estate claim" in by_name["synthetic-volume-run"]["detail"]
    assert result["timings"]["label"].startswith("SYNTHETIC")


def test_presence_in_the_registry_is_never_qualification():
    result = run_suite(corpus_size=10, volume_size=10)
    assert result["collector_qualification"], "adapters are recorded"
    assert all(row["status"] == "REGISTERED"
               for row in result["collector_qualification"]), \
        "a fixture is not support: nothing auto-qualifies"
    status = next(c for c in result["checks"]
                  if c["check"] == "collector-integration-status")
    assert status["status"] == "REGISTERED"


def test_external_acts_stay_register_only():
    result = run_suite(corpus_size=10, volume_size=10)
    assert len(result["external_acts"]) == len(EXTERNAL_ACTS)
    for row in result["external_acts"]:
        assert row["status"] == "EXTERNAL — NOT DONE (register only)"
        assert row["reason"]
    assert "never qualify a real-environment act" in result["note"]
