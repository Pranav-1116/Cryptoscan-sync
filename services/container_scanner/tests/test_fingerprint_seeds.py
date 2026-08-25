from container_scanner.fingerprints.repository import FingerprintRepository


def test_seed_hashes_are_loadable():
    repo = FingerprintRepository()
    hit = repo.lookup_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert hit is not None
    assert hit["library"] == "OpenSSL"
    assert repo.lookup_hash("missing") is None
    sodium = repo.lookup_hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    assert sodium is not None
    assert sodium["library"] == "libsodium"
    mbedtls = repo.match_binary("libmbedtls.so.21")
    assert mbedtls is not None
    assert "AES" in (mbedtls.get("algorithms") or [])
    assert repo.match_binary("libgnutls.so.30")["vendor"] == "GnuTLS"
    assert repo.match_binary("libwolfssl.so.37")["vendor"] == "wolfSSL"
    assert repo.match_binary("libboringssl.so")["vendor"] == "Google"
    assert "TLS" in (repo.lookup("nss") or {}).get("algorithms", [])
