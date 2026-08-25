from container_scanner.fingerprints.repository import FingerprintRepository


def test_seed_hashes_are_loadable():
    repo = FingerprintRepository()
    hit = repo.lookup_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert hit is not None
    assert hit["library"] == "OpenSSL"
    assert repo.lookup_hash("missing") is None
