"""Evidence classification (gap analysis §A: "every record shows evidence
classification"; roadmap: the five evidence levels, never confused).

    Capability / Static reference / Configuration / Runtime observed /
    Network negotiated.

A record's classification describes **how it was evidenced**, not what it
claims. The rules only read recorded fields — an explicit ``evidence_level``
wins, then the collector source, then the record's shape — and when nothing
records the level, the answer is ``UNCLASSIFIED``: a record whose evidence
level is not recorded is never promoted by assumption. Static evidence never
becomes runtime evidence because it "probably" ran.
"""

from __future__ import annotations

from typing import Any, Mapping

CLASSIFICATION_SCHEMA = "cryptoscan.evidence-classification/1"

CAPABILITY = "CAPABILITY"
STATIC_REFERENCE = "STATIC_REFERENCE"
CONFIGURATION = "CONFIGURATION"
RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
NETWORK_NEGOTIATED = "NETWORK_NEGOTIATED"
UNCLASSIFIED = "UNCLASSIFIED"

LEVELS: tuple[str, ...] = (CAPABILITY, STATIC_REFERENCE, CONFIGURATION,
                           RUNTIME_OBSERVED, NETWORK_NEGOTIATED, UNCLASSIFIED)

_LEVEL_MEANING: dict[str, str] = {
    CAPABILITY: "the artifact can do this — support, not use",
    STATIC_REFERENCE: "named in source or a build artifact — referenced, not run",
    CONFIGURATION: "declared in a configuration — configured, not observed",
    RUNTIME_OBSERVED: "observed in a running process — measured use",
    NETWORK_NEGOTIATED: "seen on the wire in a negotiated session — measured agreement",
    UNCLASSIFIED: "the evidence level is not recorded: unknown, never promoted",
}

_NETWORK_HINTS = ("network", "tls", "handshake", "pcap", "negotiat", "wire")
_RUNTIME_HINTS = ("runtime", "live", "process", "observed", "memory", "trace")
_CONFIG_HINTS = ("config", "conf", "cfg", "cnf", "settings", "properties",
                 "yaml", "yml", "toml", "ini", "xml", "policy")


def classify_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one evidence record by how it was evidenced.

    Order of authority (first match wins):

    1. an explicit ``evidence_level`` field on the record;
    2. the collector/source name (network → negotiated, runtime/live →
       observed);
    3. the record's shape — a configuration file path → CONFIGURATION, any
       other file path with a line number → STATIC_REFERENCE;
    4. otherwise UNCLASSIFIED, with the reason that the level is not recorded.
    """
    explicit = str(record.get("evidence_level") or "").upper()
    if explicit in LEVELS[:-1]:
        return _result(explicit, record, "the record states its evidence level")
    if explicit:
        return _result(UNCLASSIFIED, record,
                       f"recorded evidence level {explicit!r} is not one of "
                       f"the five levels")

    source = " ".join(
        str(record.get(k) or "") for k in
        ("source", "collector", "origin", "scan_type")).lower()
    if any(h in source for h in _NETWORK_HINTS):
        return _result(NETWORK_NEGOTIATED, record,
                       f"collector source {source.strip()!r} observed the wire")
    if any(h in source for h in _RUNTIME_HINTS):
        return _result(RUNTIME_OBSERVED, record,
                       f"collector source {source.strip()!r} observed a "
                       f"running system")

    path = str(record.get("file_path") or "").lower()
    if path:
        if any(path.endswith("." + ext) or ("." + ext + ".") in path
               for ext in _CONFIG_HINTS[1:]) or "config" in path:
            return _result(CONFIGURATION, record,
                           "found in a configuration file: declared, not run")
        if record.get("line_number") is not None:
            return _result(STATIC_REFERENCE, record,
                           "named in source at a line: referenced, not run")
    return _result(UNCLASSIFIED, record,
                   "the evidence level is not recorded: unknown, never "
                   "promoted by assumption")


def _result(level: str, record: Mapping[str, Any], rule: str) -> dict[str, Any]:
    return {
        "schema": CLASSIFICATION_SCHEMA,
        "level": level,
        "meaning": _LEVEL_MEANING[level],
        "rule": rule,
        "evidence_ref": (str(record.get("id") or record.get("content_hash")
                             or record.get("evidence_id") or "")) or None,
    }


def classify_records(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify a record set and summarise. Never merges levels upward.

    The summary counts each level and names the weakest claim the set
    supports: a set that only holds STATIC_REFERENCE evidence may not be
    described as observed use.
    """
    rows = [classify_evidence(r) for r in records]
    counts = {level: 0 for level in LEVELS}
    for row in rows:
        counts[row["level"]] += 1
    order = [CAPABILITY, STATIC_REFERENCE, CONFIGURATION, RUNTIME_OBSERVED,
             NETWORK_NEGOTIATED]
    strongest = next((level for level in reversed(order) if counts[level]),
                     UNCLASSIFIED)
    return {
        "schema": CLASSIFICATION_SCHEMA,
        "records": rows,
        "counts": counts,
        "strongest_level": strongest,
        "note": ("levels never merge upward: static reference is not "
                 "configuration, configuration is not observed use, and an "
                 "unclassified record is unknown"),
    }
