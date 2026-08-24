from evidence.hashing.content_hasher import ContentHasher


def verify_content(data: dict, expected: str) -> bool:
    return ContentHasher.verify_hash(data, expected)
