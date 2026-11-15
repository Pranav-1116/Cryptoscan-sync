"""Zstandard compression for evidence content (spec 2.1/7).

Compress-then-encrypt, never the other way around. Compression is applied
where it helps — the codec is recorded per object and ``none`` is recorded
when compression did not shrink the payload, so monitoring reports real
savings instead of claims.
"""

from __future__ import annotations

import zstandard

#: Compression level. 9 is zstd's documented sweet spot for JSON/structured
#: evidence: near-maximal ratio at a fraction of maximal's CPU cost.
LEVEL = 9

#: Skip compression when the payload is smaller than this — the framing
#: overhead is not worth it and small rows dominate row-count, not bytes.
MIN_COMPRESS_BYTES = 256


def compress(data: bytes, *, enabled: bool = True) -> tuple[bytes, str]:
    """Return ``(stored, codec)`` — zstd when it helps, ``none`` otherwise."""
    if not enabled or len(data) < MIN_COMPRESS_BYTES:
        return data, "none"
    compressor = zstandard.ZstdCompressor(level=LEVEL)
    stored = compressor.compress(data)
    if len(stored) >= len(data):
        # Incompressible (already-compressed uploads, random bytes): store
        # as-is and say so. A codec claim without savings is a lie.
        return data, "none"
    return stored, "zstd"


def decompress(stored: bytes, codec: str) -> bytes:
    """Reverse :func:`compress`. Unknown codecs are a corruption error."""
    if codec == "none":
        return stored
    if codec == "zstd":
        return zstandard.ZstdDecompressor().decompress(stored)
    raise ValueError(f"unknown storage codec: {codec!r}")
