from evidence.hashing.content_hasher import ContentHasher


def test_hash_is_64_hex():
    digest = ContentHasher.compute_hash({"algorithm": "AES"})
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_same_content_same_hash():
    a = ContentHasher.compute_hash({"b": 1, "a": 2})
    b = ContentHasher.compute_hash({"a": 2, "b": 1})
    assert a == b


def test_verify_hash():
    data = {"x": "y"}
    digest = ContentHasher.compute_hash(data)
    assert ContentHasher.verify_hash(data, digest)
    assert not ContentHasher.verify_hash({"x": "z"}, digest)
