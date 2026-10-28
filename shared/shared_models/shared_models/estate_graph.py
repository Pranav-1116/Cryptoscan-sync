"""One estate evidence graph that projects six BOMs (spec 93).

Design spec: ``docs/bank-environment/93-estate-evidence-graph-and-six-bom-projections.md``.

The product rule this module implements:

> Do not build six scanners. Build one evidence-discovery engine, then project six
> BOMs from the **same** evidence graph.

Concretely:

* **Evidence is the source of truth.** Assets and relationships only exist with
  evidence attached, and every projected component cites the evidence ids behind
  it. A BOM cannot invent a fact that no evidence supports.
* **One identity system.** ``asset_id`` is derived deterministically from the asset
  type plus its normalized identity keys, so the same host seen by the static,
  runtime and network planes is *one* node instead of three.
* **Relationships need a basis.** ``Payment API`` and ``HSM-01`` existing in the
  same environment never becomes ``Payment API uses HSM-01``. Without a basis the
  edge is recorded in ``unresolved_relationships`` as ``UNKNOWN``.
* **Capability is not usage.** ``usage_state`` separates ``SUPPORTED`` (declared),
  ``CONFIGURED``, ``NEGOTIATED`` (handshake) and ``OBSERVED`` (runtime). A vendor
  document can never produce an ``OBSERVED`` artefact.
* **Coverage is attempt coverage.** ``coverage()`` reports attempted/expected per
  target class. It is never a claim about how much crypto was discovered, and a
  failed collector is ``FAILED`` with an impact statement — never "none".
* **Six projections, one snapshot.** ``project_all()`` stamps every BOM with the
  same ``projection_id``, so contradictory BOMs become a diff, not an argument.

The module is dependency-free (plain dicts) so every service can import it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.estate-graph/1"
PROJECTION_SCHEMA = "cryptoscan.estate-bom-projection/1"
COVERAGE_SCHEMA = "cryptoscan.estate-coverage/1"
UNKNOWN_SCHEMA = "cryptoscan.estate-unknown-inventory/1"
IDENTITY_VERSION = "estate:v1"

#: §19 — the version of the *rules* this build applies to evidence: the confidence table,
#: the identity keys, the conflict fields and the usage-state mapping. A snapshot records it
#: so that "the same evidence, read by a newer policy" is distinguishable from "the estate
#: changed" — the projection id identifies the evidence, this identifies the reading of it.
POLICY_VERSION = "estate-policy:v1"

#: entity kinds the estate graph understands (the canonical asset model, §6)
ASSET_TYPES: tuple[str, ...] = (
    "SYSTEM",
    "APPLICATION",
    "SERVICE",
    "HOST",
    "PROCESS",
    "CONTAINER",
    "IMAGE",
    "VM",
    "POD",
    "NAMESPACE",
    "CLUSTER",
    "PACKAGE",
    "LIBRARY",
    "NETWORK_ENDPOINT",
    "LOAD_BALANCER",
    "API_GATEWAY",
    "FIREWALL",
    "VPN",
    "DATABASE",
    "MESSAGE_BROKER",
    "HSM",
    "KMS_KEY",
    "CERTIFICATE",
    "CA",
    "VENDOR",
    "HARDWARE",
    "FIRMWARE",
    "CLOUD_RESOURCE",
    "PRODUCT",
    "CRYPTO_ASSET",
    "KEY_METADATA",
    "UNKNOWN",
)

BOM_KINDS: tuple[str, ...] = ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM")

#: §24 evidence taxonomy. The strongest evidence a fact can carry is what it says.
EVIDENCE_TYPES: tuple[str, ...] = (
    "RUNTIME_OBSERVED",
    "NETWORK_ACTIVE_OBSERVED",
    "NETWORK_PASSIVE_OBSERVED",
    "STATIC_OBSERVED",
    "CERTIFICATE_OBSERVED",
    "AUDIT_OBSERVED",
    "CONFIGURED",
    "VENDOR_DECLARED",
    "IMPORTED",
    "INFERRED",
    "UNKNOWN",
)

CONFIDENCE_LEVELS: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

#: default confidence per evidence type — declared and inferred evidence is weaker
EVIDENCE_CONFIDENCE: dict[str, str] = {
    "RUNTIME_OBSERVED": "HIGH",
    "NETWORK_ACTIVE_OBSERVED": "HIGH",
    "NETWORK_PASSIVE_OBSERVED": "MEDIUM",
    "STATIC_OBSERVED": "MEDIUM",
    "CERTIFICATE_OBSERVED": "HIGH",
    # a provider's own audit record of an API call: this key *was* used, by this
    # principal, at this time — the strongest evidence of use that exists short of
    # instrumenting the process
    "AUDIT_OBSERVED": "HIGH",
    "CONFIGURED": "MEDIUM",
    "VENDOR_DECLARED": "LOW",
    "IMPORTED": "LOW",
    "INFERRED": "LOW",
    "UNKNOWN": "UNKNOWN",
}

#: §12 — layers never merge: a TLS suite is not the application's cipher
CRYPTO_LAYERS: tuple[str, ...] = (
    "APPLICATION",
    "NETWORK_TRANSPORT",
    "STORAGE",
    "HSM",
    "KMS",
    "PLATFORM",
    "UNKNOWN",
)

#: §21 — SUPPORTED ≠ CONFIGURED ≠ NEGOTIATED ≠ OBSERVED
USAGE_STATES: tuple[str, ...] = ("SUPPORTED", "CONFIGURED", "NEGOTIATED", "OBSERVED")

#: relationship vocabulary (§7)
RELATIONSHIP_PREDICATES: tuple[str, ...] = (
    "contains",
    "part_of",
    "runs_on",
    "deployed_as",
    "built_from",
    "uses",
    "uses_hsm",
    "uses_kms",
    "uses_key",
    "uses_certificate",
    "uses_crypto_library",
    "uses_algorithm",
    "encrypts_with",
    "signs_with",
    "authenticates_with",
    "connects_to",
    "routes_to",
    "exposes",
    "protected_by",
    "terminates_tls_for",
    "re_encrypts",
    "passthrough",
    "depends_on",
    "signed_by",
    "issued_by",
    "verified_by",
    "hosted_on",
    "owned_by",
    "managed_by",
    "provided_by",
    "manages",
    "backs_with",
)

#: predicates that assert *use*, and therefore need a usage basis (spec 94 §8)
USE_PREDICATES: frozenset[str] = frozenset(
    {
        "uses",
        "uses_hsm",
        "uses_kms",
        "uses_key",
        "uses_crypto_library",
        "uses_algorithm",
        "encrypts_with",
        "signs_with",
    }
)

#: bases that can establish an edge (§11). Co-location and inference are absent on
#: purpose: they describe the environment, not a relationship.
RELATIONSHIP_BASES: tuple[str, ...] = (
    "CONFIGURATION",
    "PKCS11_REFERENCE",
    "KMS_REFERENCE",
    "RUNTIME_OBSERVATION",
    "NETWORK_OBSERVATION",
    "DEPLOYMENT_CONFIG",
    "APPROVED_MAPPING",
    "IMPORTED",
)

#: bases that may establish *use* — a co-location or an inference never can
USAGE_BASES = frozenset(
    {
        "CONFIGURATION",
        "PKCS11_REFERENCE",
        "KMS_REFERENCE",
        "RUNTIME_OBSERVATION",
        "DEPLOYMENT_CONFIG",
        "APPROVED_MAPPING",
    }
)

#: identity keys per asset type, in priority order (first present wins for the id)
IDENTITY_KEYS: dict[str, tuple[str, ...]] = {
    "HOST": ("machine_id", "hostname", "ip_address"),
    "IMAGE": ("digest", "image_ref"),
    "CONTAINER": ("container_id", "image_digest", "name"),
    "POD": ("namespace", "name"),
    "NAMESPACE": ("cluster", "name"),
    "CLUSTER": ("name", "endpoint"),
    "CERTIFICATE": ("fingerprint_sha256", "serial_number", "subject"),
    "CA": ("fingerprint_sha256", "subject"),
    "KMS_KEY": ("provider", "key_id"),
    "HSM": ("vendor", "serial_number", "partition"),
    "NETWORK_ENDPOINT": ("host", "port", "protocol"),
    "LOAD_BALANCER": ("management_address", "name"),
    "API_GATEWAY": ("name", "management_address"),
    "DATABASE": ("host", "port", "engine"),
    "MESSAGE_BROKER": ("host", "port", "engine"),
    "VENDOR": ("name", "product"),
    "HARDWARE": ("serial_number", "asset_tag", "model"),
    "FIRMWARE": ("vendor", "version", "component"),
    "PACKAGE": ("name", "version", "ecosystem"),
    "LIBRARY": ("name", "version", "path"),
    "PROCESS": ("host", "pid", "executable_digest"),
    "APPLICATION": ("name", "system"),
    "SERVICE": ("name", "host"),
    "SYSTEM": ("name",),
    "CLOUD_RESOURCE": ("provider", "resource_id"),
    "UNKNOWN": ("name",),
}

#: fields whose disagreement across sources is a real conflict (§20 conflict detection)
CONFLICT_FIELDS: tuple[str, ...] = (
    "version",
    "tls_version",
    "algorithm",
    "key_size",
    "mode",
    "public_key_algorithm",
    "public_key_bits",
    "signature_algorithm",
    "firmware",
    "engine",
    "digest",
)

COVERAGE_STATUSES: tuple[str, ...] = (
    "COMPLETE", "PARTIAL", "FAILED", "NOT_ATTEMPTED", "NOT_OBSERVED", "UNKNOWN"
)

_SEPARATOR = "\x1f"


# --------------------------------------------------------------------------- #
# identity helpers
# --------------------------------------------------------------------------- #


def _field(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm(value: Any) -> str:
    return _field(value).lower()


def asset_id(asset_type: str, keys: Mapping[str, Any] | None = None, *, name: str | None = None) -> str:
    """Deterministic canonical id: ``<type>:<hash of identity keys>``.

    The same real thing discovered by two planes must produce the same id, so the
    hash input is the normalized identity tuple (never a timestamp or a scan id).
    """
    kind = str(asset_type or "UNKNOWN").upper()
    if kind not in ASSET_TYPES:
        raise ValueError(f"unknown asset type {asset_type!r}; expected one of {', '.join(ASSET_TYPES)}")
    keys = dict(keys or {})
    ordered = IDENTITY_KEYS.get(kind, ("name",))
    material = _SEPARATOR.join([IDENTITY_VERSION, kind])
    used = False
    for key in ordered:
        value = _norm(keys.get(key))
        if value:
            material += _SEPARATOR + key + "=" + value
            used = True
    if not used:
        material += _SEPARATOR + "name=" + _norm(name or keys.get("name"))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"{kind.lower()}:{digest}"


def normalize_asset(
    asset_type: str,
    name: str,
    *,
    identity: Mapping[str, Any] | None = None,
    environment: str | None = None,
    owner: str | None = None,
    location: str | None = None,
    source: str | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one canonical asset node (§6)."""
    kind = str(asset_type or "UNKNOWN").upper()
    identity = {key: value for key, value in dict(identity or {}).items() if _field(value)}
    if not identity:
        identity = {"name": name}
    return {
        "asset_id": asset_id(kind, identity, name=name),
        "type": kind,
        "name": _field(name) or "UNKNOWN",
        "environment": environment,
        "owner": owner,
        "location": location,
        "source": source,
        "identity": identity,
        "attributes": dict(attributes or {}),
        "evidence_refs": [],
    }


def _content_evidence_id(
    evidence_type: str,
    target: str,
    facts: Mapping[str, Any] | None,
    layer: str,
    source: Any = None,
    collector: Any = None,
) -> str:
    """Deterministic evidence id: identity is what was observed, not when."""
    material = json.dumps(
        {
            "evidence_type": evidence_type,
            "target": target,
            "layer": layer,
            "source": source,
            "collector": collector,
            "facts": facts or {},
        },
        sort_keys=True,
        default=str,
    )
    return "ev-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def content_evidence_id(
    evidence_type: str,
    target: str,
    facts: Mapping[str, Any] | None,
    layer: str,
    source: Any = None,
    collector: Any = None,
) -> str:
    """The public name for the content address: identity is what was observed, not when.

    Exported because verification has to recompute the id from a stored row, and a verifier
    that re-implements the hash is a verifier that can silently disagree with the writer.
    """
    return _content_evidence_id(evidence_type, target, facts, layer, source, collector)


def make_evidence(
    *,
    source: str,
    evidence_type: str,
    target: str,
    facts: Mapping[str, Any] | None = None,
    layer: str = "UNKNOWN",
    observed_at: str | None = None,
    collector: str | None = None,
    evidence_id: str | None = None,
    collector_version: str | None = None,
    raw_reference: str | None = None,
) -> dict[str, Any]:
    """One normalized evidence record (§1 evidence layer).

    ``collector_version`` and ``raw_reference`` are kept because a provenance question an
    auditor actually asks is "which build of the probe said this, and where is the output it
    came from?" — a collector name alone cannot be reproduced, and a source path alone
    cannot be re-read once the file moves. Neither is part of the content-addressed id:
    upgrading a collector does not change the fact it observed, and re-observing the same
    fact under a newer probe updates these two fields rather than inventing a second record.
    """
    kind = str(evidence_type or "UNKNOWN").upper()
    if kind not in EVIDENCE_TYPES:
        raise ValueError(f"unknown evidence type {evidence_type!r}; expected one of {', '.join(EVIDENCE_TYPES)}")
    layer_name = str(layer or "UNKNOWN").upper()
    if layer_name not in CRYPTO_LAYERS:
        raise ValueError(f"unknown layer {layer!r}; expected one of {', '.join(CRYPTO_LAYERS)}")
    return {
        # content-addressed unless the caller supplies an id: the same fact seen
        # twice is ONE evidence record, and a snapshot id does not change just
        # because the graph was rebuilt from the same stored payload.
        "evidence_id": evidence_id or _content_evidence_id(kind, target, facts, layer_name, source, collector),
        "schema": "cryptoscan.estate-evidence/1",
        "source": source,
        "collector": collector or source,
        "collector_version": collector_version,
        "raw_reference": raw_reference,
        "evidence_type": kind,
        "confidence": EVIDENCE_CONFIDENCE[kind],
        "target": target,
        "layer": layer_name,
        "facts": dict(facts or {}),
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
    }


def collector_outcome(
    plane: str,
    status: str,
    *,
    expected: int = 0,
    collected: int = 0,
    reason: str | None = None,
    impact: str | None = None,
) -> dict[str, Any]:
    """A collector's own result — a failure is a coverage fact, not an absence (§15)."""
    state = str(status or "UNKNOWN").upper()
    if state not in {"COMPLETE", "PARTIAL", "FAILED", "NOT_ATTEMPTED", "UNKNOWN"}:
        raise ValueError(f"unknown collector status {status!r}")
    expected, collected = max(0, int(expected)), max(0, int(collected))
    if state == "FAILED":
        default_impact = (
            "this plane's inventory is UNKNOWN — the BOMs that depend on it are incomplete, "
            "and no statement about missing crypto in this plane is valid"
        )
    elif state == "NOT_ATTEMPTED":
        default_impact = "this plane was not run for this scope; its estate is NOT_OBSERVED"
    elif state == "PARTIAL":
        default_impact = "some targets in this plane were not collected; they are NOT_OBSERVED, not empty"
    else:
        default_impact = None
    return {
        "plane": str(plane or "UNKNOWN").strip(),
        "status": state,
        "expected": expected,
        "collected": collected,
        "reason": reason,
        "impact": impact or default_impact,
        "is_failure": state in {"FAILED", "NOT_ATTEMPTED"},
    }


def coverage_matrix(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """§4 — attempted/expected per target class. Never a "crypto discovered" score."""
    table: list[dict[str, Any]] = []
    for row in rows:
        target = str(row.get("target") or row.get("target_class") or "UNKNOWN")
        expected = max(0, int(row.get("expected") or 0))
        collected = max(0, int(row.get("collected") or 0))
        status = str(row.get("status") or "").upper()
        if status not in COVERAGE_STATUSES:
            if row.get("failed") or row.get("collector_status") == "FAILED":
                status = "FAILED"
            elif expected == 0 and collected == 0:
                status = "NOT_ATTEMPTED"
            elif collected >= expected and expected > 0:
                status = "COMPLETE"
            elif collected > 0:
                status = "PARTIAL"
            else:
                status = "NOT_ATTEMPTED" if not row.get("attempted", True) else "UNKNOWN"
        reason = row.get("reason")
        if status == "COMPLETE" and expected == 0:
            # zero expected targets is not "100% covered". Nothing was asked, so
            # nothing was verified: that is absence of an expectation, not a pass.
            status = "NOT_OBSERVED"
            reason = reason or (
                "0 expected targets — nothing was asked of this source, which is not the same as "
                "nothing being there"
            )
        table.append(
            {
                "target": target,
                "expected": expected,
                "collected": collected,
                "status": status,
                "reason": reason,
                "impact": row.get("impact"),
                "note": row.get("note"),
            }
        )
    total_expected = sum(row["expected"] for row in table)
    total_collected = sum(min(row["collected"], row["expected"] or row["collected"]) for row in table)
    percent = round(100.0 * total_collected / total_expected, 1) if total_expected else None
    return {
        "schema": COVERAGE_SCHEMA,
        "targets": table,
        "summary": {
            "target_classes": len(table),
            "expected": total_expected,
            "collected": total_collected,
            "coverage_percent": percent,
            # None% is not "done": with no expected targets there is no measurement
            "coverage_state": "MEASURED" if total_expected else "NOT_OBSERVED",
            "by_status": {
                status: sum(1 for row in table if row["status"] == status) for status in COVERAGE_STATUSES
            },
            "failed_targets": [row["target"] for row in table if row["status"] in {"FAILED", "NOT_ATTEMPTED"}],
        },
        "meaning": (
            "scan coverage = attempted/expected targets. It is NOT 'percent of crypto discovered'; "
            "a PARTIAL or FAILED row means that estate is NOT_OBSERVED"
        ),
        "not_observed": [row["target"] for row in table if row["status"] != "COMPLETE"],
    }


# --------------------------------------------------------------------------- #
# the graph
# --------------------------------------------------------------------------- #


class EstateGraph:
    """Evidence-backed estate graph; the single source for all six BOMs."""

    def __init__(self, *, estate: str | None = None, scope: str | None = None) -> None:
        self.estate = estate
        self.scope = scope
        self._assets: dict[str, dict[str, Any]] = {}
        self._evidence: dict[str, dict[str, Any]] = {}
        self._relationships: list[dict[str, Any]] = []
        self._unresolved: list[dict[str, Any]] = []
        self._collectors: list[dict[str, Any]] = []
        self._coverage_rows: list[dict[str, Any]] = []
        self._merged: list[dict[str, Any]] = []

    # -- ingestion --------------------------------------------------------- #

    def add_asset(
        self,
        asset_type: str,
        name: str,
        *,
        identity: Mapping[str, Any] | None = None,
        environment: str | None = None,
        owner: str | None = None,
        location: str | None = None,
        source: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> str:
        """Add (or merge into) one canonical asset. Returns its stable id."""
        node = normalize_asset(
            asset_type,
            name,
            identity=identity,
            environment=environment,
            owner=owner,
            location=location,
            source=source,
            attributes=attributes,
        )
        existing = self._assets.get(node["asset_id"])
        if existing is None:
            self._assets[node["asset_id"]] = node
            return node["asset_id"]
        # merge: keep the first declared name, fill gaps, record the merge site
        for key, value in node.items():
            if key in {"asset_id", "name", "attributes", "evidence_refs", "identity"}:
                continue
            if existing.get(key) in (None, "") and value:
                existing[key] = value
        for key, value in node["attributes"].items():
            existing["attributes"].setdefault(key, value)
        for key, value in node["identity"].items():
            existing["identity"].setdefault(key, value)
        self._merged.append(
            {
                "asset_id": node["asset_id"],
                "type": node["type"],
                "from_source": source,
                "reason": "two planes described the same identity keys — one node, not two",
            }
        )
        return node["asset_id"]

    def add_evidence(self, record: Mapping[str, Any]) -> str:
        """Attach one evidence record to an existing asset."""
        target = str(record.get("target") or "")
        if target not in self._assets:
            raise ValueError(
                f"evidence targets unknown asset {target!r} — declare the asset first "
                "(a fact without an asset is not an estate fact)"
            )
        evidence = dict(record)
        evidence.setdefault("evidence_id", f"ev-{uuid.uuid4().hex[:16]}")
        evidence_id = str(evidence["evidence_id"])
        if evidence_id in self._evidence:
            raise ValueError(f"duplicate evidence id {evidence_id!r}")
        self._evidence[evidence_id] = evidence
        self._assets[target]["evidence_refs"].append(evidence_id)
        return evidence_id

    def annotate_raw_reference(self, reference: str) -> int:
        """Point every evidence record at where its raw output lives (§11).

        Called once the run that holds the raw collector output has an id. A record that
        already names its own reference keeps it: a collector that knows where it put the
        artefact is more precise than the run id, and overwriting that would be a downgrade.

        This does not touch ``fingerprint()``: provenance is not evidence content, so
        annotating a graph never changes its projection id.
        """
        if not reference:
            return 0
        touched = 0
        for record in self._evidence.values():
            if not record.get("raw_reference"):
                record["raw_reference"] = reference
                touched += 1
        return touched

    def assert_relationship(
        self,
        subject: str,
        predicate: str,
        obj: str,
        *,
        basis: str | None,
        evidence_ids: Sequence[str] = (),
        confidence: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add an edge **only** when a basis and evidence support it (§11).

        Anything else lands in ``unresolved_relationships`` as ``UNKNOWN``. A
        co-location or an inference can never establish ``uses``.
        """
        verb = str(predicate or "").strip().lower()
        entry: dict[str, Any] = {
            "subject": subject,
            "predicate": verb,
            "object": obj,
            "basis": basis,
            "evidence_ids": [str(item) for item in evidence_ids],
            "attributes": dict(attributes or {}),
        }
        if verb not in RELATIONSHIP_PREDICATES:
            raise ValueError(f"unknown predicate {predicate!r}; expected one of {', '.join(RELATIONSHIP_PREDICATES)}")
        for node in (subject, obj):
            if node not in self._assets:
                raise ValueError(f"relationship references unknown asset {node!r}")

        reason = self._relationship_refusal(entry)
        if reason:
            unresolved = {**entry, "status": "UNKNOWN", "reason": reason}
            self._unresolved.append(unresolved)
            return unresolved

        confidence = confidence or min(
            (self._evidence[item]["confidence"] for item in entry["evidence_ids"] if item in self._evidence),
            key=lambda level: _CONFIDENCE_RANK.get(level, 0),
            default="UNKNOWN",
        )
        edge = {
            **entry,
            "status": "ESTABLISHED",
            "confidence": confidence,
            "from_type": self._assets[subject]["type"],
            "to_type": self._assets[obj]["type"],
        }
        self._relationships.append(edge)
        return edge

    def _relationship_refusal(self, entry: Mapping[str, Any]) -> str | None:
        basis = entry.get("basis")
        if not basis:
            return "no basis stated — co-existence in an environment is not a relationship"
        if basis not in RELATIONSHIP_BASES:
            return (
                f"basis {basis!r} cannot establish a relationship; expected one of "
                f"{', '.join(RELATIONSHIP_BASES)}"
            )
        if not entry.get("evidence_ids"):
            return "no evidence attached — a relationship without evidence is an assumption"
        if entry["predicate"] in USE_PREDICATES and basis not in USAGE_BASES:
            return (
                f"basis {basis} cannot establish *use*: without configuration, a PKCS#11/KMS "
                "reference, a runtime observation or an approved mapping the edge stays UNKNOWN"
            )
        return None

    def add_collector(self, outcome: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(outcome)
        self._collectors.append(record)
        return record

    def add_coverage_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(row)
        self._coverage_rows.append(record)
        return record

    def coverage_rows(self) -> list[dict[str, Any]]:
        """The rows as supplied, before collector outcomes are folded in.

        A snapshot needs these verbatim: ``coverage()`` synthesises the extra rows,
        and re-ingesting those would double-count every plane.
        """
        return [dict(row) for row in self._coverage_rows]

    # -- reads ------------------------------------------------------------- #

    def assets(self) -> list[dict[str, Any]]:
        return list(self._assets.values())

    def asset(self, asset_id_value: str) -> dict[str, Any] | None:
        return self._assets.get(asset_id_value)

    def evidence(self) -> list[dict[str, Any]]:
        return list(self._evidence.values())

    def relationships(self) -> list[dict[str, Any]]:
        return list(self._relationships)

    def unresolved_relationships(self) -> list[dict[str, Any]]:
        return list(self._unresolved)

    def merged_identities(self) -> list[dict[str, Any]]:
        return list(self._merged)

    def by_type(self, *types: str) -> list[dict[str, Any]]:
        wanted = {item.upper() for item in types}
        return [asset for asset in self._assets.values() if asset["type"] in wanted]

    def conflicts(self) -> list[dict[str, Any]]:
        """Same asset, same field, two disagreeing observed values (§20)."""
        observed: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for record in self._evidence.values():
            if record["evidence_type"] not in {
                "RUNTIME_OBSERVED",
                "NETWORK_ACTIVE_OBSERVED",
                "NETWORK_PASSIVE_OBSERVED",
                "STATIC_OBSERVED",
                "CERTIFICATE_OBSERVED",
                "CONFIGURED",
            }:
                continue
            for field, value in record.get("facts", {}).items():
                if field not in CONFLICT_FIELDS or value is None or value == "":
                    continue
                key = (str(record["target"]), field)
                observed.setdefault(key, []).append(
                    {
                        "value": value,
                        "source": record["source"],
                        "evidence_type": record["evidence_type"],
                        "evidence_id": record["evidence_id"],
                        "observed_at": record["observed_at"],
                    }
                )
        conflicts: list[dict[str, Any]] = []
        for (target, field), values in sorted(observed.items()):
            distinct = {json.dumps(item["value"], sort_keys=True, default=str) for item in values}
            if len(distinct) < 2:
                continue
            conflicts.append(
                {
                    "asset_id": target,
                    "asset_name": (self._assets.get(target) or {}).get("name"),
                    "field": field,
                    "values": values,
                    "status": "CONFLICT",
                    "reason": (
                        "two sources observed different values — this is reported, not silently "
                        "resolved; the newest observation does not automatically win"
                    ),
                }
            )
        return conflicts

    # -- crypto artefacts --------------------------------------------------- #

    def crypto_artifacts(self) -> list[dict[str, Any]]:
        """Every cryptographic artefact the evidence supports, with its usage state.

        ``usage_state`` follows the evidence, not the wish: capability evidence is
        ``SUPPORTED``; a declared config is ``CONFIGURED``; a completed handshake is
        ``NEGOTIATED``; a runtime operation is ``OBSERVED``.
        """
        artifacts: list[dict[str, Any]] = []
        for record in self._evidence.values():
            facts = record.get("facts") or {}
            algorithm = facts.get("algorithm")
            role = facts.get("role")
            if not algorithm and not facts.get("protocol"):
                # A capability list ("this library supports AES-128, AES-256, RSA")
                # is cryptographic content too. It is expanded here so capability
                # appears on its own plane instead of silently vanishing, and it is
                # forced to SUPPORTED because a declared list can never be use.
                for supported in _supported_algorithms(facts):
                    artifacts.append(
                        {
                            "artifact_id": f"crypto-{hashlib.sha256((str(record['target']) + '|' + supported + '||' + str(record['layer'])).encode()).hexdigest()[:16]}",
                            "asset_id": record["target"],
                            "asset_name": (self._assets.get(record["target"]) or {}).get("name"),
                            "asset_type": (self._assets.get(record["target"]) or {}).get("type"),
                            "algorithm": supported,
                            "role": "capability",
                            "protocol": None,
                            "key_size": None,
                            "mode": None,
                            "curve": None,
                            "layer": record["layer"],
                            "usage_state": "SUPPORTED",
                            "evidence_type": record["evidence_type"],
                            "confidence": record["confidence"],
                            "evidence_ids": [record["evidence_id"]],
                            "source": record["source"],
                            "observed_at": record["observed_at"],
                        }
                    )
                continue
            usage_state = _usage_state(record["evidence_type"], facts)
            artifacts.append(
                {
                    "artifact_id": f"crypto-{hashlib.sha256((str(record['target']) + '|' + str(algorithm) + '|' + str(role) + '|' + str(record['layer'])).encode()).hexdigest()[:16]}",
                    "asset_id": record["target"],
                    "asset_name": (self._assets.get(record["target"]) or {}).get("name"),
                    "asset_type": (self._assets.get(record["target"]) or {}).get("type"),
                    "algorithm": algorithm,
                    "role": role,
                    "protocol": facts.get("protocol"),
                    "key_size": facts.get("key_size"),
                    "mode": facts.get("mode"),
                    "curve": facts.get("curve"),
                    "layer": record["layer"],
                    "usage_state": usage_state,
                    "evidence_type": record["evidence_type"],
                    "confidence": record["confidence"],
                    "evidence_ids": [record["evidence_id"]],
                    "source": record["source"],
                    "observed_at": record["observed_at"],
                }
            )
        return _merge_artifacts(artifacts)

    def _asset_rollup(self) -> dict[str, dict[str, Any]]:
        """Per-asset evidence summary used by the unknown inventory."""
        rollup: dict[str, dict[str, Any]] = {
            asset_id_value: {
                "asset_id": asset_id_value,
                "name": asset["name"],
                "type": asset["type"],
                "evidence": 0,
                "evidence_types": {},
                "observed": False,
            }
            for asset_id_value, asset in self._assets.items()
        }
        for record in self._evidence.values():
            entry = rollup.get(str(record["target"]))
            if entry is None:
                continue
            entry["evidence"] += 1
            entry["evidence_types"][record["evidence_type"]] = entry["evidence_types"].get(record["evidence_type"], 0) + 1
            if record["evidence_type"] in {
                "RUNTIME_OBSERVED",
                "NETWORK_ACTIVE_OBSERVED",
                "NETWORK_PASSIVE_OBSERVED",
                "STATIC_OBSERVED",
                "CERTIFICATE_OBSERVED",
            }:
                entry["observed"] = True
        return rollup

    # -- coverage / unknown inventory --------------------------------------- #

    def coverage(self) -> dict[str, Any]:
        """Coverage matrix combining explicit rows and collector outcomes (§4, §15)."""
        rows = list(self._coverage_rows)
        known_targets = {str(row.get("target") or row.get("target_class")) for row in rows}
        for collector in self._collectors:
            target = str(collector.get("plane") or "UNKNOWN").strip()
            if target in known_targets:
                continue
            rows.append(
                {
                    "target": target,
                    "expected": collector.get("expected", 0),
                    "collected": collector.get("collected", 0),
                    "status": collector.get("status"),
                    "reason": collector.get("reason"),
                    "impact": collector.get("impact"),
                }
            )
        matrix = coverage_matrix(rows)
        failed = [collector for collector in self._collectors if collector.get("is_failure")]
        matrix["collectors"] = list(self._collectors)
        matrix["failed_collectors"] = failed
        matrix["collector_failures_are_unknown_not_empty"] = bool(failed)
        return matrix

    def unknown_inventory(self) -> dict[str, Any]:
        """§13/§25 — what is established, what is declared, and what is unresolved."""
        rollup = self._asset_rollup()
        artifacts = self.crypto_artifacts()
        by_evidence: dict[str, int] = {}
        for record in self._evidence.values():
            by_evidence[record["evidence_type"]] = by_evidence.get(record["evidence_type"], 0) + 1

        capability_only = [
            artifact
            for artifact in artifacts
            if artifact["usage_state"] == "SUPPORTED"
        ]
        observed_use = [artifact for artifact in artifacts if artifact["usage_state"] == "OBSERVED"]

        return {
            "schema": UNKNOWN_SCHEMA,
            "estate": self.estate,
            "evidence_types": by_evidence,
            "crypto_artifacts": len(artifacts),
            "established": len(artifacts),
            "by_usage_state": {
                state: sum(1 for artifact in artifacts if artifact["usage_state"] == state)
                for state in USAGE_STATES
            },
            "observed_use": len(observed_use),
            "capability_only": len(capability_only),
            "capability_only_note": (
                "declared capability is not observed usage — these artefacts are 'supported' "
                "or 'configured', never 'in use'"
            ),
            "assets": len(rollup),
            "assets_without_evidence": sorted(
                entry["asset_id"] for entry in rollup.values() if entry["evidence"] == 0
            ),
            "assets_not_observed": sorted(
                entry["asset_id"] for entry in rollup.values() if entry["evidence"] and not entry["observed"]
            ),
            "unresolved_relationships": self._unresolved,
            "conflicts": self.conflicts(),
            "failed_collectors": [collector for collector in self._collectors if collector.get("is_failure")],
            "unknown_count": (
                len([entry for entry in rollup.values() if entry["evidence"] == 0])
                + len(self._unresolved)
                + len([collector for collector in self._collectors if collector.get("is_failure")])
            ),
            "note": (
                "UNKNOWN / unresolved is a workflow, not a rounding error: every entry here is a "
                "place where the estate is not described by evidence"
            ),
        }

    # -- PQC readiness ------------------------------------------------------ #

    def pqc_readiness(self) -> dict[str, Any]:
        """Post-quantum exposure **per layer**, with no single score on purpose.

        Three refusals shape this report:

        * an artefact whose algorithm was never observed is ``NOT_OBSERVED`` — not
          "classical", and certainly not "safe";
        * ``SUPPORTED``/``CONFIGURED`` capability is reported in its own bucket, so
          "the library supports ML-KEM" never reads as "the bank uses ML-KEM";
        * layers are never summed. A TLS hybrid handshake says nothing about the
          AES keys the application derives, which says nothing about the HSM's
          internal PQC readiness. One aggregate "PQC score" is exactly the number
          that lets a bank claim readiness it cannot evidence (§27).
        """
        artifacts = self.crypto_artifacts()
        pq_tokens = ("MLKEM", "ML-KEM", "KYBER", "BIKE", "HQC", "FRODO", "SLH-DSA", "SPHINCS", "DILITHIUM",
                     "MLDSA", "ML-DSA", "FALCON", "XMSS", "LMS")
        hybrid_tokens = ("HYBRID", "X25519MLKEM", "X25519KYBER", "SECP256R1MLKEM")
        # Symmetric ciphers are included deliberately: AES-256 keeps ~128-bit
        # strength under Grover and is NOT broken by a quantum computer, but it is
        # still not post-quantum — calling it anything else would be the over-claim
        # this method exists to avoid.
        classical_weak = ("RSA", "DSA", "DH", "ECDH", "ECDSA", "SHA-1", "SHA1", "MD5", "3DES", "RC4",
                          "AES", "CHACHA20", "CAMELLIA", "SM4", "DES", "BLOWFISH", "EC")

        classified: list[dict[str, Any]] = []
        for artifact in artifacts:
            algorithm = str(artifact.get("algorithm") or "").upper()
            protocol = str(artifact.get("protocol") or "").upper()
            material = f"{algorithm} {protocol}"
            if not algorithm and not protocol:
                state, reason = "NOT_OBSERVED", "no algorithm or protocol was observed for this asset"
            elif any(token in material for token in hybrid_tokens):
                state, reason = "POST_QUANTUM_HYBRID", "a hybrid post-quantum construction was observed"
            elif any(token in material for token in pq_tokens):
                state, reason = "POST_QUANTUM", "a post-quantum algorithm was observed"
            elif any(token in material for token in classical_weak):
                state, reason = "CLASSICAL_ONLY", (
                    "only classical cryptography is evidenced here: recorded traffic and stored data are "
                    "harvest-now-decrypt-later exposed"
                )
            else:
                state, reason = "NOT_OBSERVED", (
                    "the observed algorithm is not in the classical or post-quantum registry, so it cannot be "
                    "classified"
                )
            classified.append(
                {
                    "artifact_id": artifact["artifact_id"],
                    "asset_id": artifact["asset_id"],
                    "asset_name": artifact.get("asset_name"),
                    "layer": artifact["layer"],
                    "algorithm": artifact.get("algorithm"),
                    "key_size": artifact.get("key_size"),
                    "usage_state": artifact["usage_state"],
                    "evidence_type": artifact["evidence_type"],
                    "evidence_ids": artifact["evidence_ids"],
                    "pq_state": state,
                    "harvest_now_decrypt_later": state == "CLASSICAL_ONLY"
                    and artifact["usage_state"] in {"OBSERVED", "NEGOTIATED"},
                    "reason": reason,
                    "quantum_safe_claim": False,
                }
            )

        layers: dict[str, dict[str, Any]] = {}
        for item in classified:
            bucket = layers.setdefault(item["layer"], {
                "by_state": {},
                "artifacts": [],
                "capability_only": 0,
                "harvest_now_decrypt_later": 0,
            })
            bucket["by_state"][item["pq_state"]] = bucket["by_state"].get(item["pq_state"], 0) + 1
            if item["harvest_now_decrypt_later"]:
                bucket["harvest_now_decrypt_later"] += 1
            if item["usage_state"] in {"SUPPORTED", "CONFIGURED"}:
                bucket["capability_only"] += 1
            bucket["artifacts"].append(item)

        for layer_name, bucket in layers.items():
            observed = bucket["by_state"].get("POST_QUANTUM", 0) + bucket["by_state"].get("POST_QUANTUM_HYBRID", 0)
            if not bucket["artifacts"]:
                bucket["readiness"] = "NOT_OBSERVED"
            elif observed and bucket["by_state"].get("CLASSICAL_ONLY"):
                bucket["readiness"] = "MIXED"
            elif observed:
                bucket["readiness"] = "POST_QUANTUM_OR_HYBRID"
            elif bucket["by_state"].get("CLASSICAL_ONLY"):
                bucket["readiness"] = "CLASSICAL_ONLY"
            else:
                bucket["readiness"] = "NOT_OBSERVED"
            bucket["capability_only_note"] = (
                "capability evidence is not usage evidence: these artefacts are not in production use"
                if bucket["capability_only"] else None
            )

        return {
            "schema": "cryptoscan.estate-pqc-readiness/1",
            "estate": self.estate,
            "layers": layers,
            "artifacts": classified,
            "counts": {state: sum(1 for item in classified if item["pq_state"] == state)
                       for state in ("POST_QUANTUM", "POST_QUANTUM_HYBRID", "CLASSICAL_ONLY", "NOT_OBSERVED")},
            "harvest_now_decrypt_later": sum(1 for item in classified if item["harvest_now_decrypt_later"]),
            "single_score": None,
            "single_score_refused_because": (
                "a per-layer PQC report cannot be reduced to one number without mixing transport, application, "
                "storage and HSM evidence — the exact over-claim spec 93 §27 forbids"
            ),
            "note": (
                "no artefact is ever reported as quantum safe; capability is not usage, and an unobserved "
                "algorithm is NOT_OBSERVED rather than classical"
            ),
        }

    def unknown_workflow(self) -> dict[str, Any]:
        """§13/§25 — the unknown inventory as a workflow, not a count.

        Every asset lands in exactly one state, from strongest evidence to
        weakest. The point is that ``VENDOR_DECLARED`` and ``INFERRED`` are
        *open work*, not answers: each carries what would move it forward.
        Unresolved relationships and failed collectors are listed separately
        because they are not asset states — they are places where the estate is
        not described at all.
        """
        rollup = self._asset_rollup()
        ranked = (
            ("ESTABLISHED_RUNTIME_OBSERVED", ("RUNTIME_OBSERVED",),
             "observed at runtime — the strongest evidence this engine holds"),
            ("ESTABLISHED_NETWORK_OBSERVED", ("NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED"),
             "observed on the wire — transport crypto only, never application crypto"),
            ("ESTABLISHED_CERTIFICATE_OBSERVED", ("CERTIFICATE_OBSERVED",),
             "certificate metadata observed (public fields only)"),
            ("ESTABLISHED_STATIC_OBSERVED", ("STATIC_OBSERVED",),
             "present in code/artefacts — presence is not usage"),
            ("CONFIGURED", ("CONFIGURED",), "declared by configuration — not proven to run"),
            ("VENDOR_DECLARED", ("VENDOR_DECLARED",), "vendor says so — never proof of bank usage"),
            ("IMPORTED", ("IMPORTED",), "imported from another register — provenance is the register"),
            ("INFERRED", ("INFERRED",), "inferred, not observed — must be promoted or dropped"),
            ("UNKNOWN_UNRESOLVED", (), "no evidence at all — the estate does not describe this asset"),
        )
        buckets: dict[str, list[dict[str, Any]]] = {name: [] for name, _types, _meaning in ranked}
        for entry in rollup.values():
            types = set(entry["evidence_types"])
            state = "UNKNOWN_UNRESOLVED"
            for name, wanted, _meaning in ranked:
                if wanted and types & set(wanted):
                    state = name
                    break
            buckets[state].append(
                {
                    "asset_id": entry["asset_id"],
                    "name": entry["name"],
                    "type": entry["type"],
                    "evidence": entry["evidence"],
                    "evidence_types": entry["evidence_types"],
                }
            )

        stages = [
            {
                "state": name,
                "meaning": meaning,
                "count": len(buckets[name]),
                "assets": buckets[name][:50],
                "truncated": len(buckets[name]) > 50,
                "next_action": (
                    "run a runtime collector inside the approved scope"
                    if name == "UNKNOWN_UNRESOLVED" else
                    "promote with stronger evidence or retire the claim"
                    if name in {"VENDOR_DECLARED", "INFERRED", "IMPORTED"} else
                    "corroborate on a second plane before treating it as established"
                ),
            }
            for name, _types, meaning in ranked
        ]
        unresolved = list(self._unresolved)
        failed = [collector for collector in self._collectors if collector.get("is_failure")]
        return {
            "schema": "cryptoscan.estate-unknown-workflow/1",
            "estate": self.estate,
            "stages": stages,
            "by_state": {stage["state"]: stage["count"] for stage in stages},
            "open_work": len(buckets["UNKNOWN_UNRESOLVED"]) + len(unresolved) + len(failed),
            "unresolved_relationships": unresolved,
            "failed_collectors": failed,
            "note": (
                "UNKNOWN is a workflow state with an owner and a next action, not a rounding error; "
                "IMPORTED/VENDOR_DECLARED/INFERRED are open work, never answers"
            ),
        }

    # -- projections -------------------------------------------------------- #

    def fingerprint(self) -> str:
        """Deterministic snapshot id so all six BOMs share one provenance stamp.

        The id is stamped over the snapshot's **content**, not over its
        bookkeeping: evidence ``evidence_id`` is a per-build uuid and
        ``observed_at`` is the clock at build time, so hashing them would make the
        same stored discovery fingerprint differently every time it is read back.
        That would break the one thing this id is for — proving that two reads,
        and the six BOMs projected from them, are the same snapshot.
        """
        material = {
            "assets": sorted(self._assets),
            "relationships": sorted(
                f"{edge['subject']}|{edge['predicate']}|{edge['object']}|{edge.get('basis')}"
                for edge in self._relationships
            ),
            "evidence": sorted(
                json.dumps(
                    {
                        "source": record.get("source"),
                        "collector": record.get("collector"),
                        "evidence_type": record.get("evidence_type"),
                        "target": record.get("target"),
                        "layer": record.get("layer"),
                        "facts": record.get("facts") or {},
                    },
                    sort_keys=True,
                    default=str,
                )
                for record in self._evidence.values()
            ),
            # Coverage is part of the snapshot's identity. Without it, a run where a
            # plane failed to collect fingerprint identical to a run where it
            # succeeded over the same (smaller) set of facts — so "we stopped
            # looking" would be indistinguishable from "nothing changed", which is
            # the single most dangerous comparison this product can get wrong.
            "coverage_collectors": sorted(
                json.dumps(
                    {
                        "plane": collector.get("plane"),
                        "status": collector.get("status"),
                        "expected": collector.get("expected"),
                        "collected": collector.get("collected"),
                        "reason": collector.get("reason"),
                    },
                    sort_keys=True,
                    default=str,
                )
                for collector in self._collectors
            ),
            "coverage_rows": sorted(
                json.dumps(
                    {
                        "target": row.get("target") or row.get("target_class"),
                        "expected": row.get("expected"),
                        "collected": row.get("collected"),
                        "status": row.get("status"),
                    },
                    sort_keys=True,
                    default=str,
                )
                for row in self._coverage_rows
            ),
            "version": IDENTITY_VERSION,
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:32]

    def project(self, bom: str) -> dict[str, Any]:
        kind = str(bom or "").upper()
        if kind not in BOM_KINDS:
            raise ValueError(f"unknown BOM {bom!r}; expected one of {', '.join(BOM_KINDS)}")
        return _PROJECTORS[kind](self)

    def project_all(self) -> dict[str, Any]:
        projections = {kind: self.project(kind) for kind in BOM_KINDS}
        return {
            "schema": "cryptoscan.estate-bom-set/1",
            "estate": self.estate,
            "projection_id": self.fingerprint(),
            "boms": projections,
            "counts": {kind: len(projections[kind]["components"]) for kind in BOM_KINDS},
            "consistency": {
                "projection_id": self.fingerprint(),
                "all_boms_share_snapshot": True,
                "note": (
                    "all six BOMs are projections of the same evidence graph; a disagreement is a "
                    "diff between views, not a contradiction between scanners"
                ),
            },
        }

    def summary(self) -> dict[str, Any]:
        coverage = self.coverage()
        unknown = self.unknown_inventory()
        return {
            "schema": SCHEMA,
            "estate": self.estate,
            "scope": self.scope,
            "projection_id": self.fingerprint(),
            "identity_version": IDENTITY_VERSION,
            "assets": len(self._assets),
            "assets_by_type": _count(asset["type"] for asset in self._assets.values()),
            "evidence": len(self._evidence),
            "evidence_by_type": unknown["evidence_types"],
            "relationships": len(self._relationships),
            "unresolved_relationships": len(self._unresolved),
            "conflicts": len(unknown["conflicts"]),
            "coverage": coverage["summary"],
            "crypto": {
                "artifacts": unknown["crypto_artifacts"],
                "by_usage_state": unknown["by_usage_state"],
                "capability_only": unknown["capability_only"],
            },
            "unknown": {
                "assets_without_evidence": len(unknown["assets_without_evidence"]),
                "failed_collectors": len(unknown["failed_collectors"]),
                "unknown_count": unknown["unknown_count"],
            },
            "boms": {kind: len(self.project(kind)["components"]) for kind in BOM_KINDS},
        }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[str(value)] = out.get(str(value), 0) + 1
    return dict(sorted(out.items()))


def _usage_state(evidence_type: str, facts: Mapping[str, Any]) -> str:
    explicit = str(facts.get("usage_state") or "").upper()
    if explicit in USAGE_STATES:
        return explicit
    if evidence_type == "RUNTIME_OBSERVED":
        return "OBSERVED"
    if evidence_type == "NETWORK_ACTIVE_OBSERVED":
        return "NEGOTIATED"
    if evidence_type == "CONFIGURED":
        return "CONFIGURED"
    return "SUPPORTED"


def _supported_algorithms(facts: Mapping[str, Any]) -> list[str]:
    """Every algorithm a record declares as *available* (never as *used*)."""
    out: list[str] = []
    for field in ("supported_algorithms", "capabilities", "algorithms"):
        declared = facts.get(field)
        if not declared:
            continue
        if isinstance(declared, str):
            declared = [declared]
        for item in declared:
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
    return out


def _merge_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One artefact per (asset, algorithm, role, layer), with all supporting evidence."""
    merged: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        key = "|".join(
            [
                artifact["asset_id"],
                str(artifact["algorithm"]),
                str(artifact["role"]),
                str(artifact["layer"]),
            ]
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(artifact)
            merged[key]["usage_state"] = artifact["usage_state"]
            continue
        # keep the strongest usage state: observed beats negotiated beats configured
        rank = {"OBSERVED": 3, "NEGOTIATED": 2, "CONFIGURED": 1, "SUPPORTED": 0}
        if rank[artifact["usage_state"]] > rank[existing["usage_state"]]:
            existing["usage_state"] = artifact["usage_state"]
            existing["evidence_type"] = artifact["evidence_type"]
        for evidence_id in artifact["evidence_ids"]:
            if evidence_id not in existing["evidence_ids"]:
                existing["evidence_ids"].append(evidence_id)
        if _CONFIDENCE_RANK.get(artifact["confidence"], 0) > _CONFIDENCE_RANK.get(existing["confidence"], 0):
            existing["confidence"] = artifact["confidence"]
    return [merged[key] for key in sorted(merged)]


def _component(asset: Mapping[str, Any], *, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "bom_ref": f"{asset['type'].lower()}://{asset['asset_id']}",
        "asset_id": asset["asset_id"],
        "type": asset["type"],
        "name": asset["name"],
        "environment": asset.get("environment"),
        "owner": asset.get("owner"),
        "location": asset.get("location"),
        "identity": asset.get("identity"),
        "attributes": asset.get("attributes") or {},
        "evidence_ids": list(asset.get("evidence_refs") or []),
        **(extra or {}),
    }


def _edges_for(graph: EstateGraph, types: set[str]) -> list[dict[str, Any]]:
    return [
        {
            "from": edge["subject"],
            "to": edge["object"],
            "predicate": edge["predicate"],
            "basis": edge["basis"],
            "evidence_ids": edge["evidence_ids"],
            "confidence": edge.get("confidence"),
        }
        for edge in graph.relationships()
        if edge.get("from_type") in types or edge.get("to_type") in types
    ]


def _projection(
    graph: EstateGraph,
    bom: str,
    *,
    components: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    question: str,
    boundary: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_ids = sorted(
        {evidence_id for component in components for evidence_id in component.get("evidence_ids", [])}
        | {evidence_id for edge in edges for evidence_id in edge.get("evidence_ids", [])}
    )
    return {
        "schema": PROJECTION_SCHEMA,
        "bom": bom,
        "question": question,
        "estate": graph.estate,
        "projection_id": graph.fingerprint(),
        "identity_version": IDENTITY_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "components": components,
        "relationships": edges,
        "counts": {
            "components": len(components),
            "relationships": len(edges),
            "evidence": len(evidence_ids),
            "by_type": _count(component.get("type") or "UNKNOWN" for component in components),
        },
        "evidence_refs": evidence_ids,
        "unknowns": {
            "unresolved_relationships": len(graph.unresolved_relationships()),
            "failed_collectors": [item["plane"] for item in graph._collectors if item.get("is_failure")],
        },
        "boundary": boundary,
        **(dict(extra or {})),
    }


def _project_sbom(graph: EstateGraph) -> dict[str, Any]:
    types = {"PACKAGE", "LIBRARY", "IMAGE"}
    components = [_component(asset) for asset in graph.assets() if asset["type"] in types]
    edges = _edges_for(graph, types)
    return _projection(
        graph,
        "SBOM",
        components=components,
        edges=edges,
        question="What software and components exist?",
        boundary=(
            "a package being present is presence only — it is not proof that the library is loaded, "
            "executed or used for crypto"
        ),
        extra={"layer_note": "SBOM answers presence; CBOM answers cryptography"},
    )


def _project_cbom(graph: EstateGraph) -> dict[str, Any]:
    artifacts = graph.crypto_artifacts()
    components: list[dict[str, Any]] = []
    for artifact in artifacts:
        asset = graph.asset(artifact["asset_id"]) or {}
        components.append(
            {
                "bom_ref": f"crypto://{artifact['artifact_id']}",
                "type": "CRYPTO_ARTIFACT",
                "artifact_id": artifact["artifact_id"],
                "asset_id": artifact["asset_id"],
                "asset_name": artifact["asset_name"],
                "asset_type": artifact["asset_type"],
                "algorithm": artifact["algorithm"],
                "role": artifact["role"],
                "protocol": artifact["protocol"],
                "key_size": artifact["key_size"],
                "mode": artifact["mode"],
                "curve": artifact["curve"],
                "layer": artifact["layer"],
                "usage_state": artifact["usage_state"],
                "evidence_type": artifact["evidence_type"],
                "confidence": artifact["confidence"],
                "evidence_ids": artifact["evidence_ids"],
                "source": artifact["source"],
                "observed_at": artifact["observed_at"],
                "location": asset.get("location"),
            }
        )
    certificates = [
        _component(asset, extra={"certificate_role": "certificate"})
        for asset in graph.by_type("CERTIFICATE", "CA")
    ]
    components.extend(certificates)
    edges = [
        {
            "from": artifact["asset_id"],
            "to": artifact["artifact_id"],
            "predicate": "has_crypto",
            "basis": "EVIDENCE",
            "evidence_ids": artifact["evidence_ids"],
            "confidence": artifact["confidence"],
            "layer": artifact["layer"],
            "usage_state": artifact["usage_state"],
        }
        for artifact in artifacts
    ]
    by_layer = _count(artifact["layer"] for artifact in artifacts)
    by_state = {state: sum(1 for item in artifacts if item["usage_state"] == state) for state in USAGE_STATES}
    return _projection(
        graph,
        "CBOM",
        components=components,
        edges=edges,
        question="What cryptographic assets, capabilities and observed usage are established?",
        boundary=(
            "CAPABILITY ≠ CONFIGURED ≠ NEGOTIATED ≠ OBSERVED; layers never merge, so a TLS AES-256-GCM "
            "artefact says nothing about the application's own AES"
        ),
        extra={
            "artifacts": len(artifacts),
            "by_layer": by_layer,
            "by_usage_state": by_state,
            "capability_only": by_state["SUPPORTED"],
            "layer_separation": (
                "each artefact carries exactly one layer; cross-layer comparisons are refused by design"
            ),
        },
    )


def _project_hbom(graph: EstateGraph) -> dict[str, Any]:
    types = {"HARDWARE", "FIRMWARE", "HOST"}
    components = [_component(asset) for asset in graph.assets() if asset["type"] in types]
    edges = _edges_for(graph, {"HARDWARE", "FIRMWARE"})
    return _projection(
        graph,
        "HBOM",
        components=components,
        edges=edges,
        question="What physical and virtual hardware exists?",
        boundary=(
            "hardware presence and firmware version are not crypto capability; a TPM or HSM that was "
            "not queried stays UNKNOWN"
        ),
    )


def _project_nbom(graph: EstateGraph) -> dict[str, Any]:
    types = {"NETWORK_ENDPOINT", "LOAD_BALANCER", "API_GATEWAY", "DATABASE", "MESSAGE_BROKER", "CLOUD_RESOURCE"}
    components = [_component(asset) for asset in graph.assets() if asset["type"] in types]
    edges = _edges_for(graph, types)
    return _projection(
        graph,
        "NBOM",
        components=components,
        edges=edges,
        question="What network-facing assets and connections exist?",
        boundary=(
            "an endpoint in the NBOM is a network fact; whether it terminates TLS, passes it through "
            "or re-originates it is a CBOM fact derived from observations"
        ),
    )


def _project_vbom(graph: EstateGraph) -> dict[str, Any]:
    types = {"VENDOR"}
    components = [_component(asset) for asset in graph.assets() if asset["type"] in types]
    declared: list[dict[str, Any]] = []
    for record in graph.evidence():
        if record["evidence_type"] != "VENDOR_DECLARED":
            continue
        facts = record.get("facts") or {}
        declared.append(
            {
                "vendor_asset_id": record["target"],
                "algorithm": facts.get("algorithm"),
                "protocol": facts.get("protocol"),
                "key_size": facts.get("key_size"),
                "product": facts.get("product"),
                "version": facts.get("version"),
                "support_lifecycle": facts.get("support_lifecycle"),
                "pqc_ready": facts.get("pqc_ready"),
                "evidence_id": record["evidence_id"],
                "source": record["source"],
                "declared_not_observed": True,
            }
        )
    edges = _edges_for(graph, types)
    return _projection(
        graph,
        "VBOM",
        components=components,
        edges=edges,
        question="What vendors, products and declared capabilities exist?",
        boundary=(
            "'the product supports AES-256' is a vendor declaration about a product, never proof that "
            "this bank uses AES-256"
        ),
        extra={"declared_capabilities": declared, "declared_only": True},
    )


def _project_techbom(graph: EstateGraph) -> dict[str, Any]:
    types = {
        "SYSTEM",
        "APPLICATION",
        "SERVICE",
        "CONTAINER",
        "POD",
        "NAMESPACE",
        "CLUSTER",
        "HOST",
        "DATABASE",
        "HSM",
        "KMS_KEY",
        "VENDOR",
        "HARDWARE",
    }
    components = [_component(asset) for asset in graph.assets() if asset["type"] in types]
    edges = _edges_for(graph, types)
    return _projection(
        graph,
        "TECHBOM",
        components=components,
        edges=edges,
        question="What is the technology estate and how is it connected?",
        boundary=(
            "edges exist only where a basis and evidence exist; an unresolved relationship is reported "
            "as UNKNOWN instead of being drawn"
        ),
    )


_PROJECTORS = {
    "SBOM": _project_sbom,
    "CBOM": _project_cbom,
    "HBOM": _project_hbom,
    "NBOM": _project_nbom,
    "VBOM": _project_vbom,
    "TECHBOM": _project_techbom,
}


# --------------------------------------------------------------------------- #
# construction from an API payload
# --------------------------------------------------------------------------- #


def build_graph(payload: Mapping[str, Any]) -> EstateGraph:
    """Build a graph from a discovery payload (API/CLI).

    Expected shape::

        {"estate": "payments", "scope": "production",
         "assets": [{"type": "HOST", "name": "app-01", "identity": {"hostname": "app-01"}, ...}],
         "evidence": [{"source": "...", "evidence_type": "STATIC_OBSERVED",
                       "target": "<asset ref>", "facts": {...}, "layer": "APPLICATION"}],
         "relationships": [{"subject": "...", "predicate": "runs_on", "object": "...",
                            "basis": "DEPLOYMENT_CONFIG", "evidence_ids": ["..."]}],
         "collectors": [{"plane": "HSM", "status": "FAILED", "reason": "API unavailable"}],
         "coverage": [{"target": "Linux hosts", "expected": 120, "collected": 118}]}

    An asset may be referenced by ``asset_id`` or by ``ref`` (a local label resolved
    to the canonical id), so a payload never has to compute hashes by hand.
    """
    graph = EstateGraph(estate=payload.get("estate"), scope=payload.get("scope"))
    refs: dict[str, str] = {}

    for asset in payload.get("assets") or []:
        created = graph.add_asset(
            str(asset.get("type") or "UNKNOWN"),
            str(asset.get("name") or "UNKNOWN"),
            identity=asset.get("identity"),
            environment=asset.get("environment"),
            owner=asset.get("owner"),
            location=asset.get("location"),
            source=asset.get("source"),
            attributes=asset.get("attributes"),
        )
        for key in {asset.get("ref"), asset.get("name"), created}:
            if key:
                refs[str(key)] = created

    def resolve(value: Any) -> str:
        text = str(value or "")
        if text in graph._assets:
            return text
        if text in refs:
            return refs[text]
        raise ValueError(
            f"unknown asset reference {text!r} — declare it in `assets` (with a ref/name) or pass its asset_id"
        )

    for record in payload.get("evidence") or []:
        graph.add_evidence(
            make_evidence(
                source=str(record.get("source") or "unknown"),
                evidence_type=str(record.get("evidence_type") or "UNKNOWN"),
                target=resolve(record.get("target")),
                facts=record.get("facts") or {},
                layer=str(record.get("layer") or "UNKNOWN"),
                observed_at=record.get("observed_at"),
                collector=record.get("collector"),
                evidence_id=record.get("evidence_id"),
                collector_version=record.get("collector_version"),
                raw_reference=record.get("raw_reference"),
            )
        )

    for relationship in payload.get("relationships") or []:
        graph.assert_relationship(
            resolve(relationship.get("subject")),
            str(relationship.get("predicate") or ""),
            resolve(relationship.get("object")),
            basis=relationship.get("basis"),
            evidence_ids=[str(item) for item in relationship.get("evidence_ids") or []],
            confidence=relationship.get("confidence"),
            attributes=relationship.get("attributes"),
        )

    for collector in payload.get("collectors") or []:
        graph.add_collector(
            collector_outcome(
                str(collector.get("plane") or "UNKNOWN"),
                str(collector.get("status") or "UNKNOWN"),
                expected=int(collector.get("expected") or 0),
                collected=int(collector.get("collected") or 0),
                reason=collector.get("reason"),
                impact=collector.get("impact"),
            )
        )

    for row in payload.get("coverage") or []:
        graph.add_coverage_row(row)

    return graph


__all__ = [
    "ASSET_TYPES",
    "BOM_KINDS",
    "CONFIDENCE_LEVELS",
    "COVERAGE_SCHEMA",
    "COVERAGE_STATUSES",
    "CRYPTO_LAYERS",
    "EVIDENCE_CONFIDENCE",
    "EVIDENCE_TYPES",
    "IDENTITY_KEYS",
    "IDENTITY_VERSION",
    "POLICY_VERSION",
    "PROJECTION_SCHEMA",
    "RELATIONSHIP_BASES",
    "RELATIONSHIP_PREDICATES",
    "SCHEMA",
    "UNKNOWN_SCHEMA",
    "USAGE_BASES",
    "USAGE_STATES",
    "USE_PREDICATES",
    "EstateGraph",
    "asset_id",
    "build_graph",
    "collector_outcome",
    "coverage_matrix",
    "make_evidence",
    "normalize_asset",
]
