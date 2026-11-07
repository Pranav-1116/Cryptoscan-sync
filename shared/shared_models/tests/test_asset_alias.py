"""Asset-alias and duplicate-resolution tests (gap analysis Phase 2)."""

from __future__ import annotations

import pytest

from shared_models.asset_alias import (
    ALIAS_SCHEMA, CONFLICT, RESOLVED, UNALIASED,
    alias_record, merge_duplicates, resolve, resolve_all,
)


def _alias(alias_key, canonical_key="asset:web-1", **over):
    base = dict(alias_key=alias_key, canonical_key=canonical_key,
                actor="alice", reason="same host seen under two names",
                evidence_ref="ev-9")
    base.update(over)
    return alias_record(**base)


def test_an_alias_claim_is_attributed_and_evidence_backed():
    with pytest.raises(ValueError):
        _alias("ip:10.0.0.5", actor="")
    with pytest.raises(ValueError):
        _alias("ip:10.0.0.5", reason="")
    with pytest.raises(ValueError):
        _alias("ip:10.0.0.5", evidence_ref="")


def test_self_alias_is_refused():
    with pytest.raises(ValueError):
        _alias("asset:web-1", canonical_key="asset:web-1")


def test_resolve_follows_the_alias_to_the_canonical():
    out = resolve("ip:10.0.0.5", [_alias("ip:10.0.0.5")])
    assert out["state"] == RESOLVED
    assert out["canonical_key"] == "asset:web-1"
    assert out["chain"] == ["ip:10.0.0.5", "asset:web-1"]


def test_an_unaliased_key_resolves_to_itself_not_a_gap():
    out = resolve("asset:db-3", [])
    assert out["state"] == UNALIASED
    assert out["canonical_key"] == "asset:db-3"


def test_alias_chains_resolve_and_cycles_are_refused():
    chain = [_alias("ip:10.0.0.5", canonical_key="host:web-1"),
             _alias("host:web-1", canonical_key="asset:web-1")]
    out = resolve("ip:10.0.0.5", chain)
    assert out["canonical_key"] == "asset:web-1"
    with pytest.raises(ValueError):
        resolve("a", [_alias("a", canonical_key="b"),
                      _alias("b", canonical_key="a")])


def test_a_merge_preserves_every_original_key_as_an_alias():
    merge = merge_duplicates(keys=["host:web-1", "ip:10.0.0.5"],
                             canonical_key="asset:web-1", actor="alice",
                             reason="same physical host",
                             evidence_ref="ev-9")
    assert merge["kind"] == "merge"
    assert merge["original_keys"] == ["host:web-1", "ip:10.0.0.5"]
    assert {row["alias_key"] for row in merge["aliases"]} == {"host:web-1", "ip:10.0.0.5"}
    for row in merge["aliases"]:
        assert row["canonical_key"] == "asset:web-1"
        assert row["evidence_ref"] == "ev-9"
    assert "never deletes" in merge["note"]


def test_a_merge_without_evidence_or_with_one_key_is_refused():
    with pytest.raises(ValueError):
        merge_duplicates(keys=["a"], canonical_key="a", actor="x",
                         reason="r", evidence_ref="e")
    with pytest.raises(ValueError):
        merge_duplicates(keys=["a", "b"], canonical_key="asset:x", actor="x",
                         reason="r", evidence_ref="")


def test_a_conflicting_alias_is_kept_never_silently_resolved():
    aliases = [
        _alias("ip:10.0.0.5", canonical_key="asset:web-1"),
        _alias("ip:10.0.0.5", canonical_key="asset:web-2"),
    ]
    out = resolve("ip:10.0.0.5", aliases)
    assert out["state"] == CONFLICT
    assert out["canonical_key"] is None
    assert out["conflicting_targets"] == ["asset:web-1", "asset:web-2"]
    assert "never silently resolved" in out["note"]
    report = resolve_all(["ip:10.0.0.5"], aliases)
    assert report["conflicted"] == ["ip:10.0.0.5"]
    assert report["is_clean_result"] is False


def test_resolution_is_deterministic_and_order_insensitive():
    aliases = [_alias("ip:10.0.0.5", canonical_key="host:web-1"),
               _alias("host:web-1", canonical_key="asset:web-1")]
    a = resolve_all(["host:web-1", "ip:10.0.0.5", "asset:db-3"], aliases)
    b = resolve_all(["asset:db-3", "ip:10.0.0.5", "host:web-1"], list(reversed(aliases)))
    assert a == b
    assert a["is_clean_result"] is True
