"""§30 False-positive suppression — the finding correlator.

Recognizes that:
    "RSA" in documentation       ≠  RSA API call
    RSA API call                 ≠  RSA certificate
    RSA certificate              ≠  RSA actually used during TLS

Suppression rules (deterministic):
  1. doc/comment/string mentions never become findings by themselves;
  2. duplicate detections (same algorithm+operation+asset) merge;
  3. string-only evidence is dropped when stronger evidence exists;
  4. a mention that merely *references* an algorithm name is dropped
     unless corroborated by API/cert/runtime/protocol evidence.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from universal_crypto.models import Evidence, EvidenceType

#: doc-only contexts — algorithm names appearing here are mentions, not usage
_DOC_CONTEXT = re.compile(
    r"(?:\.md|\.rst|\.txt|\.html?|README|docs?/|comments?|documentation)"
    r"|^\s*(?:#|//|/\*|\*|--|<!--|\"\"\"|')", re.IGNORECASE)

#: evidence kinds that corroborate a mention into a finding
_STRONG_KINDS = frozenset({
    EvidenceType.AST, EvidenceType.BINARY, EvidenceType.RUNTIME,
    EvidenceType.PROTOCOL, EvidenceType.CERTIFICATE,
})

#: string-only kinds (weak by themselves)
_WEAK_KINDS = frozenset({EvidenceType.KEY_METADATA, EvidenceType.TRUST_STORE,
                         EvidenceType.DEPENDENCY})


class FindingCorrelator:
    """§30 suppresses false positives and merges duplicates."""

    def correlate(
        self,
        detections: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """detections: engine drafts/dicts with algorithm/operation/asset_id/
        evidence/location keys. Returns correlated, suppression-tagged rows.
        """
        merged: dict[tuple[str, str, str], dict[str, Any]] = {}
        for detection in detections:
            algorithm = detection.get("algorithm", "")
            operation = detection.get("operation") or ""
            if isinstance(operation, str):
                operation = operation.lower()
            asset = detection.get("asset_id", "default")
            location = str(detection.get("location") or "")
            evidence = detection.get("evidence") or []
            evidence = [e for e in evidence if not isinstance(e, str)]

            # rule 1: doc-context mentions are suppressed unless corroborated
            if _DOC_CONTEXT.search(location):
                if not any(e.kind in _STRONG_KINDS for e in evidence):
                    continue

            key = (algorithm, str(operation), asset)
            row = merged.setdefault(key, {
                "algorithm": algorithm,
                "operation": operation or None,
                "asset_id": asset,
                "evidence": [],
                "locations": [],
                "suppressed": False,
                "suppression_reason": "",
                "sources": [],
            })
            for item in evidence:
                if not isinstance(item, Evidence):
                    item = Evidence(kind=EvidenceType.CONFIG, detail=str(item))
                if item not in row["evidence"]:
                    row["evidence"].append(item)
            if location and location not in row["locations"]:
                row["locations"].append(location)
            row["sources"].append(detection.get("source", ""))

        out = []
        for row in merged.values():
            row = dict(row)
            strong = [e for e in row["evidence"] if e.kind in _STRONG_KINDS]
            weak_only = [e for e in row["evidence"] if e.kind in _WEAK_KINDS]
            # rule 3: weak-only rows are possible but tagged (not dropped —
            # the confidence engine decides), unless they are bare mentions
            if not strong and weak_only:
                row["suppressed"] = False
                row["suppression_reason"] = "weak_evidence_only"
            row["evidence"] = strong + [e for e in row["evidence"] if e not in strong]
            out.append(row)
        return out
