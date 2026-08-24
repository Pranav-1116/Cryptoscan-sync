from evidence.hashing.chain_hasher import ChainHasher


def verify_chain(content_hashes: list[str], stored: list[str], scan_id: str) -> bool:
    return ChainHasher.verify_chain(content_hashes, stored, scan_id)
