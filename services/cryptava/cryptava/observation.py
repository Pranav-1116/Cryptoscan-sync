"""Build one observation in the platform's ingestion contract.

The contract (``POST /api/v1/ingestion/observations``):

* an **asset** is ``{ref, type, name, identity, attributes, source}``; the platform turns
  ``identity`` into the canonical id, so two planes describing the same thing merge;
* an **evidence** record targets an asset ``ref`` and carries the observed ``facts``;
  facts with ``algorithm``/``protocol`` (or an ``algorithms`` list) become CBOM entries;
* a **relationship** must cite evidence — the platform refuses an edge without it, so
  :meth:`Observation.relate` refuses one too, before it is ever sent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptava import __version__

COLLECTOR = "cryptava"

ASSET_TYPES = {
    "SYSTEM", "APPLICATION", "SERVICE", "HOST", "PROCESS", "CONTAINER", "IMAGE", "PACKAGE",
    "LIBRARY", "NETWORK_ENDPOINT", "DATABASE", "MESSAGE_BROKER", "HSM", "CERTIFICATE", "CA",
    "VENDOR", "HARDWARE", "FIRMWARE", "KEY_METADATA", "CRYPTO_ASSET", "UNKNOWN",
}
EVIDENCE_TYPES = {
    "RUNTIME_OBSERVED", "NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED", "STATIC_OBSERVED",
    "CERTIFICATE_OBSERVED", "CONFIGURED", "VENDOR_DECLARED", "IMPORTED", "INFERRED",
}
LAYERS = {"APPLICATION", "NETWORK_TRANSPORT", "STORAGE", "HSM", "KMS", "PLATFORM", "UNKNOWN"}
BASES = {"CONFIGURATION", "RUNTIME_OBSERVATION", "NETWORK_OBSERVATION", "DEPLOYMENT_CONFIG",
         "APPROVED_MAPPING", "IMPORTED"}
PLANE_STATUSES = {"COMPLETE", "PARTIAL", "FAILED", "NOT_ATTEMPTED"}
#: what happened to one source a plane reads — shown per BOM as "how this was collected"
SOURCE_STATES = {"READ", "EMPTY", "ABSENT", "DENIED", "UNAVAILABLE", "DISABLED", "NOT_CONFIGURED"}
MAX_SOURCES = 24


def source(where: str, reads: str, state: str, found: int | None = None, note: str | None = None) -> dict[str, Any]:
    """One row of a plane's provenance: *where* was read, *what* it yields, and what happened.

    ``state`` is what this run saw — READ (data came back), EMPTY (readable, nothing in it),
    ABSENT (not on this host), DENIED (present but not readable with the agent's rights),
    UNAVAILABLE (tool missing or failed), DISABLED (turned off in config), NOT_CONFIGURED
    (an input the bank has to supply, e.g. the asset register).
    """
    kind = state.upper()
    if kind not in SOURCE_STATES:
        raise ValueError(f"unknown source state {state!r}")
    row: dict[str, Any] = {"source": str(where)[:160], "reads": str(reads)[:160], "state": kind}
    if found is not None:
        row["found"] = max(0, int(found))
    if note:
        row["note"] = str(note)[:200]
    return row


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Observation:
    host_label: str = "host"
    observed_at: str = field(default_factory=_now)
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    relationships: dict[str, dict[str, Any]] = field(default_factory=dict)
    planes: dict[str, dict[str, Any]] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)

    # -- nodes ---------------------------------------------------------------- #
    def asset(self, ref: str, asset_type: str, name: str, *, identity: dict[str, Any],
              attributes: dict[str, Any] | None = None, source: str = COLLECTOR,
              environment: str | None = None) -> str:
        kind = asset_type.upper()
        if kind not in ASSET_TYPES:
            raise ValueError(f"unknown asset type {asset_type!r}")
        identity = {k: str(v) for k, v in identity.items() if v not in (None, "")}
        attrs = {k: v for k, v in (attributes or {}).items() if v not in (None, "", [], {})}
        existing = self.assets.get(ref)
        if existing is not None:
            if existing["type"] != kind:
                raise ValueError(f"asset ref {ref!r} declared as {existing['type']} and {kind}")
            for key, value in attrs.items():
                existing["attributes"].setdefault(key, value)
            return ref
        record: dict[str, Any] = {"ref": ref, "type": kind, "name": str(name)[:300],
                                  "identity": identity, "attributes": attrs, "source": source}
        if environment:
            record["environment"] = environment
        self.assets[ref] = record
        return ref

    def has(self, ref: str) -> bool:
        return ref in self.assets

    # -- evidence ------------------------------------------------------------- #
    def observe(self, target: str, evidence_type: str, facts: dict[str, Any], *,
                layer: str = "PLATFORM", source: str = "cryptava") -> str:
        """Attach one evidence record; returns its label for relationships to cite."""
        if target not in self.assets:
            raise ValueError(f"evidence targets undeclared asset {target!r}")
        kind = evidence_type.upper()
        if kind not in EVIDENCE_TYPES:
            raise ValueError(f"unknown evidence type {evidence_type!r}")
        layer = layer.upper()
        if layer not in LAYERS:
            raise ValueError(f"unknown layer {layer!r}")
        clean_facts = _clean_facts(facts)
        material = json.dumps([target, kind, layer, source, clean_facts], sort_keys=True, default=str)
        label = "ev-" + hashlib.sha256(material.encode()).hexdigest()[:20]
        if label not in self.evidence:
            self.evidence[label] = {
                "ref": label,
                "source": source,
                "evidence_type": kind,
                "target": target,
                "facts": clean_facts,
                "layer": layer,
                "observed_at": self.observed_at,
                "collector": COLLECTOR,
                "collector_version": __version__,
            }
        return label

    # -- edges ---------------------------------------------------------------- #
    def relate(self, subject: str, predicate: str, obj: str, *, basis: str,
               evidence: Iterable[str]) -> None:
        refs = [item for item in evidence if item]
        if not refs:
            raise ValueError(f"{subject} {predicate} {obj}: an edge without evidence is refused")
        for ref in refs:
            if ref not in self.evidence:
                raise ValueError(f"{subject} {predicate} {obj}: cites unknown evidence {ref!r}")
        for node in (subject, obj):
            if node not in self.assets:
                raise ValueError(f"{subject} {predicate} {obj}: undeclared asset {node!r}")
        if basis not in BASES:
            raise ValueError(f"unknown basis {basis!r}")
        if subject == obj:
            return
        key = f"{subject}|{predicate}|{obj}"
        existing = self.relationships.get(key)
        if existing is not None:
            for ref in refs:
                if ref not in existing["evidence_refs"]:
                    existing["evidence_refs"].append(ref)
            return
        self.relationships[key] = {"subject": subject, "predicate": predicate, "object": obj,
                                   "basis": basis, "evidence_refs": refs}

    # -- plane outcomes ------------------------------------------------------- #
    def plane(self, name: str, status: str, reason: str, *, expected: int = 1,
              collected: int | None = None, details: dict[str, Any] | None = None,
              sources: list[dict[str, Any]] | None = None) -> None:
        state = status.upper()
        if state not in PLANE_STATUSES:
            raise ValueError(f"unknown plane status {status!r}")
        if collected is None:
            collected = expected if state == "COMPLETE" else 0
        self.planes[name] = {"plane": name, "status": state, "reason": reason[:500],
                             "expected": max(0, int(expected)), "collected": max(0, int(collected))}
        if details:
            self.planes[name]["details"] = details
        if sources:
            self.planes[name]["sources"] = list(sources)[:MAX_SOURCES]

    def cover(self, target: str, expected: int, collected: int, reason: str | None = None) -> None:
        row = {"target": target, "expected": max(0, int(expected)), "collected": max(0, int(collected))}
        if reason:
            row["reason"] = reason[:300]
        self.coverage.append(row)

    # -- output --------------------------------------------------------------- #
    def payload(self, *, estate: str, scope: str | None, contributor: str | None) -> dict[str, Any]:
        collectors = [
            {key: value for key, value in plane.items() if key != "details"}
            for plane in self.planes.values()
        ]
        document: dict[str, Any] = {
            "schema": "cryptoscan.live-observation/1",
            "estate": estate,
            "scope": scope,
            "inventory_id": "default",
            "observed_at": self.observed_at,
            "assets": sorted(self.assets.values(), key=lambda item: item["ref"]),
            "evidence": sorted(self.evidence.values(), key=lambda item: item["ref"]),
            "relationships": sorted(self.relationships.values(),
                                    key=lambda item: (item["subject"], item["predicate"], item["object"])),
            "collectors": collectors,
            "coverage": list(self.coverage),
        }
        if contributor:
            document["contributor"] = contributor
        return document

    def counts(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for asset in self.assets.values():
            by_type[asset["type"]] = by_type.get(asset["type"], 0) + 1
        return {"assets": len(self.assets), "evidence": len(self.evidence),
                "relationships": len(self.relationships), "asset_types": dict(sorted(by_type.items()))}


def _clean_facts(facts: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in facts.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, (set, tuple)):
            value = sorted(value)
        out[str(key)] = value
    return out


def state_hash(document: dict[str, Any]) -> str:
    """Hash of what the observation *says* — not when it was taken."""
    material = {
        "assets": document.get("assets"),
        "evidence": [
            {k: v for k, v in record.items() if k not in {"observed_at"}}
            for record in document.get("evidence") or []
        ],
        "relationships": document.get("relationships"),
        "collectors": document.get("collectors"),
        "coverage": document.get("coverage"),
        "contributor": document.get("contributor"),
        "estate": document.get("estate"),
        "scope": document.get("scope"),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()
