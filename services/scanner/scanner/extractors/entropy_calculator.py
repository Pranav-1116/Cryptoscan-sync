"""Shannon entropy helper for hardcoded-secret heuristics."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str | bytes) -> float:
    if not value:
        return 0.0
    data = value if isinstance(value, (bytes, bytearray)) else value.encode("utf-8", errors="replace")
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_secret(value: str, threshold: float = 3.5, min_length: int = 12) -> bool:
    if len(value) < min_length:
        return False
    return shannon_entropy(value) >= threshold
