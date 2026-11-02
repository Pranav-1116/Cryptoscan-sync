"""Turning a cluster and a CMDB into observations, not into claims.

The review's biggest single gap is deployment correlation: an SBOM proves what
was built, and only something that *looked at the running system* proves what is
deployed. Guides 133-135 built the chain and graded it, but every observation in
those guides was supplied by hand. This module is the collector that produces
them:

* :func:`observations_from_kubernetes` reads a pod listing (the JSON a
  ``kubectl get pods -o json`` or an agent snapshot yields) and emits
  :class:`~devsecops.sbom_evidence.DeploymentObservation` records carrying the
  digest the container runtime actually started, the workload, the namespace and
  a timestamp. An image the runtime reports by tag only is **refused**, not
  guessed at: a tag is a pointer and evidence needs an address.
* :func:`register_from_cmdb` reads the application register, so a workload can
  be attributed to an application and a business system instead of floating as
  an unattributed pod.
* :func:`correlate` joins SBOMs, observations and the register, and answers the
  review's question — *where is this package actually deployed?* — using the
  evidence functions rather than a new vocabulary.

All three are pure functions over documents. Fetching the documents (kubectl,
the CMDB export, the agent) is an integration; deciding what they mean is this
module, which is why it can be qualified without a cluster.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

from devsecops import sbom_evidence as evidence

SCHEMA = "cryptoscan.deployment-collectors/1"

#: Workload kinds that actually run containers. A ConfigMap in a pod listing is
#: not a deployment observation.
RUNNABLE_KINDS: tuple[str, ...] = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job",
                                   "CronJob", "ReplicaSet")


def _digest_from_image_reference(value: str) -> str | None:
    """The digest in ``repo@sha256:…`` or ``docker-pullable://repo@sha256:…``."""
    text = str(value or "").strip()
    if "@" not in text:
        return None
    candidate = text.rsplit("@", 1)[1].strip()
    return candidate if evidence._DIGEST.match(candidate) else None  # noqa: SLF001


def _reference_from_image_reference(value: str) -> str | None:
    text = str(value or "").strip()
    for prefix in ("docker-pullable://", "docker://", "containerd://", "cri-o://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if "@" in text:
        return text.rsplit("@", 1)[0]
    if ":" in text.rsplit("/", 1)[-1]:
        return text.rsplit(":", 1)[0]
    return text or None


def observations_from_kubernetes(snapshot: Mapping[str, Any], *, source: str = "kubernetes",
                                 observed_at: date | None = None,
                                 environment: str | None = None,
                                 cluster: str | None = None) -> dict[str, Any]:
    """One observation per running container, from a pod listing.

    ``snapshot`` is either a ``kubectl get pods -o json`` document (``items``) or
    a list of pods under ``pods``. Each container's ``imageID`` — what the
    runtime resolved the tag to — is the identity; ``spec.containers[].image``
    is only used when it already carries a digest.

    A container that is not running (``waiting``/``terminated``) produces no
    observation: a pod in ``ImagePullBackOff`` is a description of an intent, and
    calling it deployed would be the exact confusion this chain exists to stop.
    """
    observed_at = observed_at or datetime.now(timezone.utc).date()
    pods = snapshot.get("items") if isinstance(snapshot.get("items"), list) else snapshot.get("pods")
    if not isinstance(pods, list):
        raise ValueError("a pod listing must carry `items` or `pods`")
    env = str(environment or snapshot.get("environment") or "PRODUCTION").upper()
    observations: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for pod in pods:
        if not isinstance(pod, Mapping):
            continue
        meta = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}
        kind = str(pod.get("kind") or "Pod")
        namespace = str(meta.get("namespace") or "default")
        name = str(meta.get("name") or "")
        if kind not in RUNNABLE_KINDS:
            skipped.append({"workload": name, "reason": f"{kind} does not run containers"})
            continue
        resolved: dict[str, str] = {}
        for container_status in status.get("containerStatuses") or []:
            if not isinstance(container_status, Mapping):
                continue
            image_id = str(container_status.get("imageID") or "")
            digest = _digest_from_image_reference(image_id)
            if digest:
                resolved[str(container_status.get("name") or "")] = digest
        statuses = [row for row in status.get("containerStatuses") or []
                    if isinstance(row, Mapping)]
        # ``{"running": {}}`` is how the API spells "running": the *key* is the
        # state, so testing truthiness of the empty dict says nothing ran
        running = {str(row.get("name")) for row in statuses
                   if "running" in (row.get("state") or {})}
        for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            if not isinstance(container, Mapping):
                continue
            container_name = str(container.get("name") or "")
            image = str(container.get("image") or "")
            digest = resolved.get(container_name) or _digest_from_image_reference(image)
            reference = _reference_from_image_reference(image)
            if not digest:
                refused.append({
                    "workload": f"{namespace}/{name}", "container": container_name,
                    "reason": (f"the runtime reports {image or 'no image'} without a digest, so "
                               "this container has no immutable identity to observe")})
                continue
            if container_name not in running:
                skipped.append({
                    "workload": f"{namespace}/{name}", "container": container_name,
                    "reason": ("the runtime reports no status for this container, so it has not "
                               "started" if not statuses else
                               "the container is not in a running state")})
                continue
            observations.append(evidence.DeploymentObservation(
                deployment=f"{namespace}/{name}",
                environment=env,
                artifact=evidence.ArtifactIdentity(reference or "unknown", digest),
                workload=f"{kind.lower()}/{namespace}/{name}",
                observed_at=observed_at,
                evidence_id=f"K8S-{_short_hash(namespace, name, container_name, digest, str(observed_at))}",
                source=f"{source}:{cluster}" if cluster else source).to_dict())
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()
    return {
        "schema": SCHEMA,
        "source": source,
        "cluster": cluster,
        "environment": env,
        "observed_at": observed_at.isoformat(),
        "snapshot_sha256": digest,
        "observations": observations,
        "refused": refused,
        "skipped": skipped,
        "statement": (
            f"{len(observations)} observation(s) from {len(pods)} workload(s)"
            + (f"; {len(refused)} refused for carrying no digest" if refused else "")
            + (f"; {len(skipped)} skipped as not running" if skipped else "")),
    }


def sbom_record_from_document(document: Mapping[str, Any], *, sbom_id: str = "SBOM",
                              image_reference: str | None = None,
                              image_digest: str | None = None,
                              created_at: date | None = None) -> evidence.SbomRecord:
    """A :class:`SbomRecord` from a CycloneDX or SPDX document.

    The document is bound to an artifact only when the caller supplies the image
    digest. An SBOM on its own — however complete — describes a build, so without
    that digest every component it lists grades ``PRESENT_IN_SBOM_ONLY``, which
    is the honest answer and not a bug to work around.
    """
    components: list[dict[str, Any]] = []
    if str(document.get("bomFormat") or "").lower() == "cyclonedx":
        for comp in document.get("components") or []:
            if isinstance(comp, Mapping) and comp.get("name"):
                components.append({"name": str(comp["name"]),
                                   "version": comp.get("version")})
    else:
        from devsecops.sbom_assurance import spdx_components

        for package in spdx_components(document):
            if package.get("name"):
                components.append({"name": str(package["name"]),
                                   "version": package.get("versionInfo")})
    artifact = None
    if image_digest:
        artifact = evidence.ArtifactIdentity(
            str(image_reference or document.get("metadata", {}).get("component", {}).get("name")
                or "unknown"), str(image_digest))
    return evidence.SbomRecord(sbom_id=sbom_id, artifact=artifact,
                               components=tuple(components), created_at=created_at)


def _short_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12].upper()


def register_from_cmdb(document: Mapping[str, Any]) -> dict[str, Any]:
    """The application register: which workload serves which business system.

    Accepts ``{"applications": [{"name", "business_system", "owner", "criticality",
    "workloads": ["ns/deploy", ...]}]}``. A workload listed twice is an
    attribute conflict, reported rather than silently resolved by order.
    """
    applications = document.get("applications")
    if not isinstance(applications, list):
        raise ValueError("a CMDB export must carry an `applications` list")
    by_workload: dict[str, list[str]] = {}
    rows: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for application in applications:
        if not isinstance(application, Mapping):
            continue
        name = str(application.get("name") or "").strip()
        if not name:
            continue
        workloads = [str(item).strip() for item in (application.get("workloads") or [])
                     if str(item).strip()]
        rows.append({"name": name,
                     "business_system": application.get("business_system"),
                     "owner": application.get("owner"),
                     "criticality": application.get("criticality"),
                     "workloads": workloads})
        for workload in workloads:
            by_workload.setdefault(workload, []).append(name)
    for workload, names in by_workload.items():
        if len(names) > 1:
            conflicts.append({"workload": workload, "applications": names,
                              "reason": ("the register attributes this workload to more than one "
                                         "application, so attributing it to either would be a "
                                         "guess")})
    return {
        "schema": SCHEMA,
        "applications": rows,
        "by_workload": by_workload,
        "conflicts": conflicts,
        "statement": (
            f"{len(rows)} application(s) covering {len(by_workload)} workload(s)"
            + (f"; {len(conflicts)} workload(s) claimed by more than one application"
               if conflicts else "")),
    }


def _iso_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        return date.fromisoformat(value[:10])
    return None


def _observation_from_dict(row: Mapping[str, Any]) -> evidence.DeploymentObservation:
    """Rebuild an observation from :meth:`DeploymentObservation.to_dict` output."""
    artifact = row.get("artifact")
    if isinstance(artifact, Mapping):
        reference, digest = str(artifact.get("reference") or ""), str(artifact.get("digest") or "")
    else:
        reference, digest = str(artifact or ""), str(row.get("digest") or "")
    observed_at = row.get("observed_at")
    return evidence.DeploymentObservation(
        deployment=str(row.get("deployment")),
        environment=str(row.get("environment") or "PRODUCTION"),
        artifact=evidence.ArtifactIdentity(reference, digest),
        workload=str(row.get("workload") or ""),
        observed_at=_iso_date(observed_at),
        evidence_id=str(row.get("evidence_id") or "OBS"),
        source=str(row.get("source") or "collector"))


def correlate(sboms: Iterable[evidence.SbomRecord], observations: Iterable[Mapping[str, Any]],
              *, register: Mapping[str, Any] | None = None,
              components: Iterable[str] | None = None) -> dict[str, Any]:
    """Where is each component actually running?

    Every SBOM is joined to every observation by artifact digest, so the answer
    is ``PRESENT_IN_DEPLOYMENT`` only when something observed that exact digest.
    A component nobody observed is reported as ``PRESENT_IN_ARTIFACT`` or
    ``PRESENT_IN_SBOM_ONLY`` — the difference the review's item 6 is about.
    """
    records = list(sboms)
    rebuilt: list[evidence.DeploymentObservation] = []
    for row in observations:
        if not isinstance(row, Mapping):
            continue
        try:
            rebuilt.append(_observation_from_dict(row))
        except (KeyError, TypeError, ValueError, evidence.IdentityError):
            continue
    wanted = list(components) if components else sorted(
        {str(component.get("name")) for record in records for component in record.components
         if component.get("name")})
    conflicted = {str(row.get("workload")): row for row in (register or {}).get("conflicts", [])
                  if isinstance(row, Mapping)}
    rows: list[dict[str, Any]] = []
    for record in records:
        for name in wanted:
            presence = evidence.presence_in_deployment(record, name, rebuilt)
            if presence["state"] == "NOT_IN_SBOM":
                continue
            workloads = sorted({str(observation.get("workload"))
                                for observation in presence.get("deployments") or ()
                                if observation.get("workload")})
            blocked = [workload for workload in workloads if workload in conflicted]
            applications = sorted({
                application
                for workload in workloads if workload not in conflicted
                for application in (register or {}).get("by_workload", {}).get(workload, [])})
            rows.append({
                "component": name,
                "sbom": record.sbom_id,
                "artifact": record.artifact.reference if record.artifact else None,
                "digest": record.artifact.digest if record.artifact else None,
                "state": presence["state"],
                "environments": presence.get("environments") or [],
                "workloads": workloads,
                "applications": applications,
                "attribution": (
                    "CONFLICT" if blocked and not applications
                    else "PARTIAL" if blocked else "REGISTERED" if applications else "UNREGISTERED"),
                "attribution_conflicts": [conflicted[workload] for workload in blocked],
                "business_systems": sorted({
                    str(application_row.get("business_system"))
                    for application_row in (register or {}).get("applications", [])
                    if application_row.get("name") in applications
                    and application_row.get("business_system")}),
                "evidence_ids": [row.get("evidence_id") for row in presence.get("deployments") or ()],
            })
    deployed = [row for row in rows if row["state"] == "PRESENT_IN_DEPLOYMENT"]
    unattributed = [row for row in deployed if row["attribution"] in ("CONFLICT", "UNREGISTERED")]
    return {
        "schema": SCHEMA,
        "rows": rows,
        "counts": {state: sum(1 for row in rows if row["state"] == state)
                   for state in ("PRESENT_IN_DEPLOYMENT", "PRESENT_IN_ARTIFACT",
                                 "PRESENT_IN_SBOM_ONLY")},
        "deployed": len(deployed),
        "unattributed": len(unattributed),
        "statement": (
            f"{len(deployed)} of {len(rows)} component answer(s) resolve to a running system; "
            f"{len(rows) - len(deployed)} stop at the artifact or the document"
            + (f"; {len(unattributed)} run without a single owning application"
               if unattributed else "")),
    }
