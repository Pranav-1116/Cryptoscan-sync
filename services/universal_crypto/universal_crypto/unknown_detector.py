"""§31 False-negative detection — the unknown crypto detector.

If the application performs cryptographic-looking operations but the engine
cannot identify the primitive, it is queued as UNKNOWN_CRYPTO_OPERATION and
sent to deep analysis:

    Deep Binary Analysis → AST Analysis → Runtime Observation →
    Human Review

(No AI step: the spec's AI-assisted classification is excluded by the
product constraint — deep analysis here is deterministic and the review
queue is a human work queue.)
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Iterable

from universal_crypto.models import FindingStatus

#: crypto-looking operation patterns (functions the AST engine refuses to
#: auto-classify per §5 — here they become *unknown* candidates, §31)
_CRYPTO_LOOKING = re.compile(
    r"(?:def|func|function|public\s+\w+|private\s+\w+|static\s+\w+|"
    r"let\s+\w+\s*=\s*)\s*"
    r"(?:my_|our_|custom_|own_|proprietary_)?"
    r"(?:encrypt|decrypt|hash|digest|sign|verify|mac|prng|kdf|keygen|derive)"
    r"\s*\(", re.IGNORECASE)

#: unknown-looking binary imports/symbols (crypto-adjacent names)
_BINARY_CRYPTO_LOOKING = re.compile(
    r"(?:encrypt|decrypt|hash|digest|sign|verify|mac|prng|cipher|keygen|derive)",
    re.IGNORECASE)

DEEP_ANALYSIS_STEPS = [
    "deep_binary_analysis",
    "ast_analysis",
    "runtime_observation",
    "human_review",
]


class UnknownCryptoQueue:
    """§31 queue of UNKNOWN_CRYPTO_OPERATION items with review workflow."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def pending(self) -> list[dict[str, Any]]:
        return [i for i in self._items.values() if i["status"] == FindingStatus.OPEN.value]

    def all(self) -> list[dict[str, Any]]:
        return list(self._items.values())

    def enqueue(self, *, item_id: str = "", asset_id: str = "default",
                location: str = "", snippet: str = "",
                kind: str = "source") -> dict[str, Any]:
        entry = {
            "unknown_id": item_id or uuid.uuid4().hex[:16],
            "asset_id": asset_id,
            "location": location,
            "snippet": snippet[:200],
            "kind": kind,
            "status": FindingStatus.OPEN.value,
            "deep_analysis": DEEP_ANALYSIS_STEPS,
            "analysis_result": "",
            "review_decision": "",
            "review_note": "",
        }
        self._items[entry["unknown_id"]] = entry
        return entry

    def analyze(self, unknown_id: str, *, result: str) -> dict[str, Any]:
        """Deterministic deep-analysis result recorded by an analyzer."""
        entry = self._items[unknown_id]
        entry["analysis_result"] = result
        return entry

    def review(self, unknown_id: str, *, decision: str, note: str = "") -> dict[str, Any]:
        """Human review: 'crypto' | 'not_crypto' | 'needs_more_evidence'."""
        entry = self._items[unknown_id]
        entry["status"] = FindingStatus.REVIEWED.value
        entry["review_decision"] = decision
        entry["review_note"] = note
        return entry


class UnknownCryptoDetector:
    """§31 finds crypto-looking operations the engine could not classify."""

    def __init__(self) -> None:
        self.queue = UnknownCryptoQueue()

    def scan_source(self, lines: Iterable[str], *, asset_id: str = "default",
                    location: str = "") -> list[dict[str, Any]]:
        found = []
        for lineno, line in enumerate(lines, start=1):
            if _CRYPTO_LOOKING.search(line):
                entry = self.queue.enqueue(
                    asset_id=asset_id,
                    location=f"{location}:{lineno}" if location else str(lineno),
                    snippet=line.strip()[:200], kind="source")
                found.append(entry)
        return found

    def scan_binary(self, names: Iterable[str], *, asset_id: str = "default",
                    location: str = "") -> list[dict[str, Any]]:
        found = []
        for name in names:
            if _BINARY_CRYPTO_LOOKING.search(name) and not _KNOWN_BINARY_SYMBOL(name):
                entry = self.queue.enqueue(
                    asset_id=asset_id, location=location,
                    snippet=name, kind="binary")
                found.append(entry)
        return found


def _KNOWN_BINARY_SYMBOL(name: str) -> bool:
    """Symbols the deterministic catalogs already classify are not unknown."""
    from universal_crypto.binary_engine import SYMBOL_ALGORITHMS
    return name in SYMBOL_ALGORITHMS
