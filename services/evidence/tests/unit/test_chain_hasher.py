from evidence.hashing.chain_hasher import ChainHasher


def test_chain_length_matches_input():
    hashes = ["a" * 64, "b" * 64, "c" * 64]
    chain = ChainHasher.compute_chain(hashes, "scan-1")
    assert len(chain) == 3
    assert all(len(h) == 64 for h in chain)


def test_tamper_breaks_chain():
    hashes = ["a" * 64, "b" * 64]
    chain = ChainHasher.compute_chain(hashes, "scan-1")
    tampered = ["a" * 64, "d" * 64]
    assert not ChainHasher.verify_chain(tampered, chain, "scan-1")


def test_intact_chain_verifies():
    hashes = ["a" * 64, "b" * 64]
    chain = ChainHasher.compute_chain(hashes, "scan-1")
    assert ChainHasher.verify_chain(hashes, chain, "scan-1")
