"""A stored artifact's history, read back from the store rather than from a list.

``sbom_evidence.history`` answers "what moved between these snapshots" for
records a caller already holds. The bank's question is narrower and harder: *what
moved in production for this target, over the artifacts we actually kept?* That
needs the store — the manifests, their timestamps, and the documents behind them.

Everything here is a pure function over manifests and documents; the API layer
supplies them (it is the only place that knows about tenants).
"""

from __future__ import annotations

from datetime import date
from typing import Any, Iterable, Mapping

from devsecops import sbom_evidence as evidence

SCHEMA = "cryptoscan.sbom-timeline/1"

#: Change kinds that are about the artifact rather than a package, so they do not
#: name a component and must not be reported as one.
ARTIFACT_KINDS = frozenset({"ARTIFACT_CHANGED", "DEPLOYMENT_CHANGED"})


def _as_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if isinstance(value, str) and value:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def record_from_document(manifest: Mapping[str, Any], document: Mapping[str, Any]) -> Any:
    """One snapshot from a stored manifest and the BOM it holds.

    The identity is deliberately the *document's*: a stored SBOM is bound to the
    digest of its own bytes, not to an image digest, so correlation with
    deployments is not attempted here. Claiming otherwise would let a timeline
    entry look like a deployment.
    """
    components: list[dict[str, Any]] = []
    if str(document.get("bomFormat") or "").lower() == "cyclonedx":
        rows = document.get("components") or []
        for row in rows:
            if isinstance(row, Mapping) and row.get("name"):
                licences = [str((lic.get("license") or {}).get("id")
                                or (lic.get("license") or {}).get("name")
                                or lic.get("expression") or "")
                            for lic in row.get("licenses") or [] if isinstance(lic, Mapping)]
                components.append({
                    "name": row.get("name"), "version": row.get("version"),
                    "purl": row.get("purl"),
                    "license": next((lic for lic in licences if lic), None),
                    "crypto_relevant": _crypto_relevant(row),
                    "depends_on": row.get("dependsOn") or (),
                })
    else:
        from devsecops.sbom_assurance import spdx_components

        for package in spdx_components(document):
            components.append({
                "name": package.get("name"), "version": package.get("versionInfo"),
                "license": package.get("licenseDeclared"),
                "crypto_relevant": _crypto_relevant(package),
                "depends_on": (),
            })
    artifact = None
    digest = str(manifest.get("sha256") or "")
    if len(digest) == 64:
        artifact = evidence.ArtifactIdentity(str(manifest.get("target") or "artifact"),
                                             f"sha256:{digest}")
    stored_at = str(manifest.get("created_at") or "")
    return evidence.SbomRecord(
        sbom_id=str(manifest.get("artifact_id") or "artifact"),
        artifact=artifact, components=tuple(components),
        created_at=_as_date(stored_at),
        build_id=(manifest.get("provenance") or {}).get("build", {}).get("build_id"),
        sequence=stored_at or None)


def _crypto_relevant(row: Mapping[str, Any]) -> bool:
    """Whether this component is cryptography, by the same rules the scanner uses.

    CycloneDX has ``cryptoProperties`` for it, but a document this platform wrote
    carries the scanner's name-based registry instead, so both are read. Reading
    only the standard field would silently drop every crypto component from the
    twin for documents we produced ourselves.
    """
    if row.get("cryptoProperties"):
        return True
    for prop in row.get("properties") or ():
        if isinstance(prop, Mapping) and str(prop.get("name") or "").lower() in {
                "cryptoscan:crypto-relevant", "cryptoscan:crypto"} and str(
                prop.get("value") or "").lower() in {"true", "yes", "1"}:
            return True
    name = str(row.get("name") or "").strip().lower()
    if not name:
        return False
    from devsecops.sbom_scan import CRYPTO_PACKAGES

    return name in CRYPTO_PACKAGES


def drift_events(timeline: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The timeline's transitions as drift events a drift engine can consume.

    Each event carries the two snapshots it sits between, because "the version
    changed" is unactionable without "from which build to which build".
    """
    events: list[dict[str, Any]] = []
    for transition in timeline.get("transitions") or ():
        for change in transition.get("changes") or ():
            kind = str(change.get("kind") or "")
            events.append({
                "type": kind,
                "component": change.get("component"),
                "from": change.get("from"),
                "to": change.get("to"),
                "from_sbom": transition.get("from"),
                "to_sbom": transition.get("to"),
                "at": transition.get("at"),
                "artifact_level": kind in ARTIFACT_KINDS,
            })
    return events


def timeline(entries: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]], *,
             target: str | None = None, include_events: bool = True) -> dict[str, Any]:
    """The history of one target, from ``(manifest, document)`` pairs.

    A single snapshot is not a timeline: one entry produces zero transitions and
    says so, rather than reporting "no changes" as if drift had been measured.
    """
    records = [record_from_document(manifest, document) for manifest, document in entries]
    report = evidence.history(records)
    events = drift_events(report) if include_events else []
    counts: dict[str, int] = {}
    for event in events:
        counts[event["type"]] = counts.get(event["type"], 0) + 1
    return {
        "schema": SCHEMA,
        "target": target,
        "snapshots": report["snapshots"],
        "transitions": report["transitions"],
        "events": events,
        "event_counts": dict(sorted(counts.items())),
        "components": report["components"],
        "changed_transitions": report["changed_transitions"],
        "gap_days": report["gap_days"],
        "statement": _statement(records, report, target),
    }


def _statement(records: list[Any], report: Mapping[str, Any], target: str | None) -> str:
    """One sentence — and no "no change" for a series of length one.

    "0 transitions, 0 with no change" over a single snapshot reads as a
    measurement. It is not one, so the sentence says so instead.
    """
    where = f" for {target}" if target else ""
    if len(records) < 2:
        return (f"{len(records)} snapshot(s){where}: with fewer than two snapshots nothing has "
                "been compared, so drift is unmeasured")
    return f"{len(records)} snapshot(s){where}: " + report["statement"]
