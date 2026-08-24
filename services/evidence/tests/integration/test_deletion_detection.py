from evidence.hashing.chain_hasher import ChainHasher


def test_deletion_is_detected():
    hashes = ["a" * 64, "b" * 64, "c" * 64]
    chain = ChainHasher.compute_chain(hashes, "s")
    assert not ChainHasher.verify_chain(hashes[:2], chain, "s")
