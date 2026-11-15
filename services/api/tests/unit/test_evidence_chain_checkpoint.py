"""Signed evidence-chain checkpoints — the external anchor a local chain
cannot provide for itself.

The chain is honestly ``anchoring: local-database-only``: it can prove its
own continuity but not that the database alone did not rewrite all of it.
A signed checkpoint — archived by the bank, keyed by an operator-held key
— binds the chain head, length and declared truncation at a moment in
time. These tests pin the anchor: signatures cover the whole body,
forged heads fail, drift is named, and there is NO default key.
"""
from __future__ import annotations


import pytest

from api.security import evidence_chain as ec


def _chain(*hashes: str) -> dict:
    entries = []
    running = ec.GENESIS
    for i, h in enumerate(hashes, start=1):
        entries.append({"seq": i, "record_hash": h, "prev_hash": running,
                        "recorded_at": "2026-10-16T00:00:00Z"})
        running = h
    return {"entries": entries}


SPEC = ec.ChainSpec(namespace="network", id_field="event_id",
                    chain_schema="s", verify_schema="v")
KEY = b"operator-held-key-material"


class TestTheAnchor:
    def test_sign_then_verify_round_trips(self):
        doc = ec.checkpoint(_chain("a" * 64, "b" * 64), spec=SPEC,
                            tenant_id="t1", signer_id="ops-1", key=KEY)
        assert doc["head_hash"] == "b" * 64
        assert doc["entry_count"] == 2 and doc["last_seq"] == 2
        assert ec.verify_checkpoint(doc, key=KEY)["valid"] is True

    def test_a_forged_head_breaks_the_signature(self):
        doc = ec.checkpoint(_chain("a" * 64), spec=SPEC,
                            tenant_id="t1", signer_id="ops-1", key=KEY)
        doc["head_hash"] = "f" * 64  # the database rewrote its own history
        result = ec.verify_checkpoint(doc, key=KEY)
        assert result["valid"] is False
        assert "signature" in result["reason"]

    def test_an_edited_truncation_window_breaks_the_signature(self):
        truncated = _chain("a" * 64)
        truncated["truncated_before_seq"] = 7  # an older window was dropped
        doc = ec.checkpoint(truncated, spec=SPEC,
                            tenant_id="t1", signer_id="ops-1", key=KEY)
        assert doc["truncated_before_seq"] == 7
        doc["truncated_before_seq"] = 0  # pretending no window was dropped
        assert ec.verify_checkpoint(doc, key=KEY)["valid"] is False

    def test_the_wrong_key_never_verifies(self):
        doc = ec.checkpoint(_chain("a" * 64), spec=SPEC,
                            tenant_id="t1", signer_id="ops-1", key=KEY)
        assert ec.verify_checkpoint(doc, key=b"different-key-material")["valid"] is False

    def test_drift_is_named_not_smoothed_over(self):
        chain = _chain("a" * 64)
        doc = ec.checkpoint(chain, spec=SPEC, tenant_id="t1",
                            signer_id="ops-1", key=KEY)
        chain["entries"].append({"seq": 2, "record_hash": "b" * 64,
                                 "prev_hash": "a" * 64, "recorded_at": "x"})
        result = ec.match_head(chain, doc)
        assert result["status"] == "DRIFT"
        assert result["live_head"] == "b" * 64
        assert "legitimate" in result["note"]
        assert ec.match_head(_chain("a" * 64), doc)["status"] == "MATCH"


class TestThereIsNoDefaultKey:
    def test_signing_without_an_operator_key_refuses_loudly(self, monkeypatch):
        monkeypatch.delenv("EVIDENCE_CHECKPOINT_KEY", raising=False)
        with pytest.raises(RuntimeError, match="refusing to sign"):
            ec.checkpoint(_chain("a" * 64), spec=SPEC, tenant_id="t1",
                          signer_id="ops-1")

    def test_a_short_key_is_refused_too(self, monkeypatch):
        monkeypatch.setenv("EVIDENCE_CHECKPOINT_KEY", "short")
        with pytest.raises(RuntimeError, match="refusing to sign"):
            ec.checkpoint(_chain("a" * 64), spec=SPEC, tenant_id="t1",
                          signer_id="ops-1")
