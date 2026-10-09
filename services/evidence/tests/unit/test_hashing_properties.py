"""Property-based tests for the evidence hashing core (round 17 — report 11).

Hypothesis explores the input space; the example-based suites pin individual
behaviors. Properties that MUST hold for the chain to be trustworthy:

* canonical serialization is deterministic and order-insensitive;
* hashing is stable (equal content ⇒ equal digest) and 64-hex;
* runtime-only fields (evidence_id, timestamps) never affect a digest;
* a chain verifies iff nothing was tampered, reordered, removed, or appended;
* verify_single agrees with verify_chain link by link.
"""

from __future__ import annotations

import string

from hypothesis import given, settings, strategies as st

from evidence.hashing.canonical_serializer import CanonicalSerializer
from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

MAX_EXAMPLES = 50

# JSON-shaped data: nested dicts/lists over text, ints, bools, None
json_values = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**31), max_value=2**31)
    | st.text(alphabet=string.printable, max_size=24),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(min_size=1, max_size=12, alphabet=string.ascii_letters), children, max_size=4),
    max_leaves=12,
)
findings = st.dictionaries(
    st.text(min_size=1, max_size=12, alphabet=string.ascii_letters + "_-"),
    json_values,
    min_size=1,
    max_size=6,
)
hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@settings(max_examples=MAX_EXAMPLES)
@given(data=findings)
def test_serialize_is_deterministic_and_round_trips(data):
    import json

    once = CanonicalSerializer.serialize(data)
    twice = CanonicalSerializer.serialize(data)
    assert once == twice
    assert CanonicalSerializer.serialize_to_bytes(data) == (
        once if isinstance(once, bytes) else once.encode("utf-8")
    )
    # round trip: the canonical form parses back to the cleaned content
    assert json.loads(CanonicalSerializer.serialize_to_bytes(data)) == CanonicalSerializer._clean_data(data)


@settings(max_examples=MAX_EXAMPLES)
@given(data=findings)
def test_key_order_never_changes_the_serialization(data):
    shuffled = dict(reversed(list(data.items())))
    assert CanonicalSerializer.serialize(data) == CanonicalSerializer.serialize(shuffled)


@settings(max_examples=MAX_EXAMPLES)
@given(data=findings)
def test_content_hash_stable_and_wellformed(data):
    h1 = ContentHasher.compute_hash(data)
    h2 = ContentHasher.compute_hash(dict(data))
    assert h1 == h2
    assert len(h1) == 64
    int(h1, 16)  # hex
    assert ContentHasher.verify_hash(data, h1) is True
    assert ContentHasher.verify_hash(data, h1.replace(h1[0], "0" if h1[0] != "0" else "1", 1)) is False


@settings(max_examples=MAX_EXAMPLES)
@given(data=findings, evidence_id=st.uuids(), created_at=st.text(max_size=8))
def test_runtime_fields_are_excluded_from_digests(data, evidence_id, created_at):
    base = ContentHasher.compute_hash(data)
    decorated = {
        **data,
        "evidence_id": str(evidence_id),
        "created_at": created_at,
        "scan_timestamp": created_at,
        "finding_id": str(evidence_id),
    }
    assert ContentHasher.compute_hash(decorated) == base


@settings(max_examples=MAX_EXAMPLES)
@given(hashes=st.lists(hex64, min_size=1, max_size=8), session=st.text(min_size=1, max_size=16))
def test_chain_verifies_untampered_and_detects_any_mutation(hashes, session):
    chain = ChainHasher.compute_chain(hashes, session)
    assert len(chain) == len(hashes)
    assert ChainHasher.verify_chain(hashes, chain, session) is True

    if len(hashes) == 1:
        return  # mutation strategies below need at least one editable slot

    # mutate one content hash -> chain must fail (guaranteed value change)
    mutated = list(hashes)
    idx = len(hashes) // 2
    old = mutated[idx]
    mutated[idx] = ("f" if old[0] != "f" else "0") + old[1:]
    assert mutated != hashes
    assert ChainHasher.verify_chain(mutated, chain, session) is False

    # reorder -> fail
    reordered = list(hashes)
    reordered[0], reordered[-1] = reordered[-1], reordered[0]
    if reordered != hashes:
        assert ChainHasher.verify_chain(reordered, chain, session) is False

    # delete a middle link -> length mismatch -> fail
    assert ChainHasher.verify_chain(hashes[1:], chain, session) is False
    # append a link -> length mismatch -> fail
    assert ChainHasher.verify_chain(hashes + [hashes[0]], chain, session) is False


@settings(max_examples=MAX_EXAMPLES)
@given(hashes=st.lists(hex64, min_size=1, max_size=8), session=st.text(min_size=1, max_size=16))
def test_verify_single_agrees_with_the_chain(hashes, session):
    chain = ChainHasher.compute_chain(hashes, session)
    for i, link in enumerate(chain):
        previous = chain[i - 1] if i > 0 else None
        assert ChainHasher.verify_single(hashes[i], link, previous, session if i == 0 else None) is True
        bad = ("f" if link[0] != "f" else "0") + link[1:]  # guaranteed-different digest
        assert ChainHasher.verify_single(hashes[i], bad, previous, session if i == 0 else None) is False


@settings(max_examples=MAX_EXAMPLES)
@given(data=findings, session=st.text(min_size=1, max_size=16))
def test_end_to_end_content_then_chain_round_trip(data, session):
    """ContentHasher + ChainHasher compose: same findings -> same chain, always."""
    content = ContentHasher.compute_hash(data)
    link = ChainHasher.compute_chain_hash(content, scan_session_id=session)
    assert ChainHasher.verify_single(content, link, None, session) is True
    # different session id binds the first link to its scan
    other = ChainHasher.compute_chain_hash(content, scan_session_id=session + "x")
    assert other != link
