from evidence.hashing.chain_hasher import ChainHasher


def test_reorder_is_detected():
    hashes = ["a" * 64, "b" * 64]
    chain = ChainHasher.compute_chain(hashes, "s")
    assert not ChainHasher.verify_chain(list(reversed(hashes)), chain, "s")
