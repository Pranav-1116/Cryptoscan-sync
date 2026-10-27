"""Validate unhashed evidence sidecars before they reach provenance JSON.

The finding content hash does not cover record-level provenance or integrity.
Never copy arbitrary sidecar fields into the database under a verified chain.
"""

from __future__ import annotations

from collections.abc import Mapping


_INTEGRITY = {
    "hash_algorithm": "SHA-256",
    "canonical_form": "sorted-json-utf8",
    "hash_includes": ["finding"],
    "hash_excludes": ["evidence_id", "created_at"],
}
_PROVENANCE_FIELDS = frozenset({"scanner_id", "scanner_version", "scanner_ids"})


def checked_provenance(rec: Mapping, finding: Mapping) -> dict | None:
    """Accept only the fixed integrity descriptor or scanner attribution in the finding.

    These sidecars are not part of the content commitment. Reject an unexpected
    field/value instead of quietly projecting it or blessing it with a PASS log.
    """
    integrity = rec.get("integrity")
    if integrity is not None and integrity != _INTEGRITY:
        raise ValueError("unsupported integrity metadata")

    provenance = rec.get("provenance")
    if provenance is None:
        return integrity
    if not isinstance(provenance, dict) or provenance.keys() - _PROVENANCE_FIELDS:
        raise ValueError("unsupported provenance metadata")
    for key in ("scanner_id", "scanner_version"):
        if key in provenance and (not isinstance(provenance[key], str)
                                  or provenance[key] != finding.get(key)):
            raise ValueError("unsupported provenance metadata")
    if "scanner_ids" in provenance and (
        not isinstance(provenance["scanner_ids"], list)
        or provenance["scanner_ids"] != [finding.get("scanner_id")]
        or not isinstance(finding.get("scanner_id"), str)
    ):
        raise ValueError("unsupported provenance metadata")
    return provenance
