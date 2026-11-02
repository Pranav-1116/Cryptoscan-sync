"""Where evidence lives, and whether one failure can take all of it away.

The review asked for *HA object storage in a separate failure domain*. Two
different claims hide in that sentence, and this module keeps them apart:

* **replication** — the same bytes exist in more than one place, and a write is
  only acknowledged when a quorum of those places has read it back intact;
* **failure-domain separation** — those places do not share a power feed, a
  region, an account or a control plane. Three replicas in one region are three
  copies and one failure.

:func:`placement` refuses a topology that would report HA while sharing a
domain, :class:`ReplicatedStore` performs the replicated writes and verifies
each one by reading it back, and :func:`topology_from_env` reads the operator's
declaration so the artifact manifest can record it rather than assume it.

Nothing here talks to a cloud API: the sites are declarations and the backends
are the store objects this platform already has, so the same code drives a
mounted volume, an S3 wrapper or a test double.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.storage-topology/1"

#: Dimensions along which one event can take out more than one site.
DOMAIN_AXES: tuple[str, ...] = ("provider", "region", "zone", "account", "control_plane")


@dataclass(frozen=True)
class StoreSite:
    """One place evidence is kept, and what a failure there would also remove."""

    name: str
    provider: str = "local"
    region: str | None = None
    zone: str | None = None
    account: str | None = None
    control_plane: str | None = None
    role: str = "PRIMARY"
    endpoint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "provider": self.provider, "region": self.region,
                "zone": self.zone, "account": self.account,
                "control_plane": self.control_plane, "role": self.role,
                "endpoint": self.endpoint}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def shared_domains(left: StoreSite, right: StoreSite) -> list[str]:
    """The axes on which two sites fail together (empty means they are separate)."""
    shared: list[str] = []
    for axis in DOMAIN_AXES:
        a, b = _norm(getattr(left, axis)), _norm(getattr(right, axis))
        if a and b and a == b:
            shared.append(axis)
    return shared


def placement(sites: Iterable[StoreSite], *, min_sites: int = 2,
              require: Sequence[str] | None = None) -> dict[str, Any]:
    """May this set of sites be called highly available?

    ``require`` names the axes that must differ (default: ``region``). Sharing a
    provider is allowed — a bank rarely has two clouds — but sharing a region is
    not, because a regional outage is exactly the event HA is for.
    """
    ordered = list(sites)
    axes = tuple(require or ("region",))
    reasons: list[str] = []
    if len(ordered) < min_sites:
        reasons.append(f"{len(ordered)} site(s) declared; at least {min_sites} are required for "
                       "a replica to survive the loss of the first")
    names = [_norm(site.name) for site in ordered]
    if len(set(names)) != len(names):
        reasons.append("two sites share a name, so a write cannot be attributed to a place")
    pairs: list[dict[str, Any]] = []
    for index, left in enumerate(ordered):
        for right in ordered[index + 1:]:
            shared = shared_domains(left, right)
            offending = [axis for axis in axes if axis in shared]
            # a required axis nobody declared is not separation — it is an
            # unknown, and an unknown failure domain cannot be claimed as a
            # second one
            undeclared = [axis for axis in axes
                          if not (_norm(getattr(left, axis)) and _norm(getattr(right, axis)))]
            pairs.append({"sites": [left.name, right.name], "shared": shared,
                          "offending": offending, "undeclared": undeclared})
            if offending:
                reasons.append(
                    f"{left.name} and {right.name} share {', '.join(offending)}, so one event "
                    "removes both copies")
            elif undeclared:
                reasons.append(
                    f"{left.name} and {right.name} do not both declare "
                    f"{', '.join(undeclared)}, so separation on it cannot be shown")
    if not ordered:
        reasons.append("no site is declared, so there is nothing to replicate to")
    return {
        "schema": SCHEMA,
        "sites": [site.to_dict() for site in ordered],
        "required_axes": list(axes),
        "pairs": pairs,
        "verdict": "REFUSE" if reasons else "ALLOW",
        "reasons": reasons or [f"{len(ordered)} site(s) separated on {', '.join(axes)}"],
        "statement": (
            f"REFUSED: {reasons[0]}" if reasons else
            f"{len(ordered)} site(s), separated on {', '.join(axes)}"),
    }


def site_from_mapping(payload: Mapping[str, Any], *, default_name: str) -> StoreSite:
    return StoreSite(
        name=str(payload.get("name") or default_name),
        provider=str(payload.get("provider") or "local"),
        region=payload.get("region"), zone=payload.get("zone"),
        account=payload.get("account"), control_plane=payload.get("control_plane"),
        role=str(payload.get("role") or "PRIMARY"), endpoint=payload.get("endpoint"))


def topology_from_env(environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The declared site topology, from ``SBOM_STORAGE_SITES`` (JSON array).

    Undeclared is a state, not an error: it is reported as ``UNDECLARED`` so the
    manifest can carry the gap instead of implying replication that was never
    configured.
    """
    env = os.environ if environment is None else environment
    raw = str(env.get("SBOM_STORAGE_SITES") or "").strip()
    if not raw:
        return {"schema": SCHEMA, "declared": False, "verdict": "UNDECLARED",
                "sites": [], "reasons": ["no storage sites are declared, so replication and "
                                         "failure-domain separation cannot be evidenced"],
                "statement": "UNDECLARED: no SBOM_STORAGE_SITES topology is configured"}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"schema": SCHEMA, "declared": True, "verdict": "INVALID", "sites": [],
                "reasons": [f"SBOM_STORAGE_SITES is not valid JSON: {exc}"],
                "statement": "INVALID: the declared topology cannot be read"}
    if isinstance(payload, Mapping):
        payload = payload.get("sites") or []
    sites = [site_from_mapping(item, default_name=f"site-{index}")
             for index, item in enumerate(payload if isinstance(payload, list) else [])
             if isinstance(item, Mapping)]
    result = placement(sites)
    result["declared"] = True
    return result


# --------------------------------------------------------------------------- #
# the replicated writer
# --------------------------------------------------------------------------- #


@dataclass
class ReplicatedStore:
    """Writes every artifact to all sites and acknowledges on a verified quorum.

    The store interface is the one this platform already uses
    (``put``/``get``/``put_manifest``/``list_manifests``), so a site can be a
    mounted volume, an object-store wrapper or an in-memory double. ``put``
    reads each written object back and compares digests: a replica that accepted
    a write and returned different bytes is a failed replica, not a third copy.
    """

    sites: tuple[StoreSite, ...]
    backends: Mapping[str, Any]
    quorum: int | None = None
    _health: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.quorum = self.quorum or (len(self.sites) // 2 + 1)
        for site in self.sites:
            self._health.setdefault(site.name, {"writes": 0, "failures": 0,
                                                "last_error": None, "verified": 0})

    def backend(self, name: str) -> Any:
        backend = self.backends.get(name)
        if backend is None:
            raise KeyError(f"no backend is configured for site {name!r}")
        return backend

    def _write(self, method: str, key: str, payload: Any) -> dict[str, Any]:
        written: list[str] = []
        failed: list[dict[str, str]] = []
        for site in self.sites:
            try:
                getattr(self.backend(site.name), method)(key, payload)
                self._health[site.name]["writes"] += 1
                written.append(site.name)
            except Exception as exc:  # noqa: BLE001 — a site that fails must not stop the others
                self._health[site.name]["failures"] += 1
                self._health[site.name]["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
                failed.append({"site": site.name, "error": f"{type(exc).__name__}: {exc}"[:200]})
        ok = len(written) >= int(self.quorum or 1)
        return {"key": key, "written": written, "failed": failed,
                "quorum": self.quorum, "acknowledged": ok}

    def put(self, key: str, blob: bytes) -> dict[str, Any]:
        result = self._write("put", key, blob)
        digest = hashlib.sha256(blob).hexdigest()
        verified: list[str] = []
        mismatched: list[str] = []
        for name in result["written"]:
            try:
                returned = self.backend(name).get(key)
                if hashlib.sha256(returned).hexdigest() == digest:
                    verified.append(name)
                    self._health[name]["verified"] += 1
                else:
                    mismatched.append(name)
                    # a copy that reads back different is a *failed* site, not a
                    # slow one: the whole point of the digest is to catch this
                    self._health[name]["failures"] += 1
                    self._health[name]["last_error"] = (
                        "read-back digest did not match the written bytes")
            except Exception as exc:  # noqa: BLE001
                mismatched.append(name)
                self._health[name]["failures"] += 1
                self._health[name]["last_error"] = f"read-back failed: {exc}"[:200]
        result.update({"verified": verified, "mismatched": mismatched, "sha256": digest,
                       "acknowledged": len(verified) >= int(self.quorum or 1)})
        if not result["acknowledged"]:
            raise IOError(
                f"write to {key} reached {len(verified)} verified site(s) of "
                f"{len(self.sites)}, below the quorum of {self.quorum}")
        return result

    def put_manifest(self, key: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return self._write("put_manifest", key, manifest)

    def get(self, key: str) -> bytes:
        errors: list[str] = []
        for site in self.sites:
            try:
                return self.backend(site.name).get(key)
            except Exception as exc:  # noqa: BLE001 — try the next replica
                errors.append(f"{site.name}: {type(exc).__name__}")
        raise FileNotFoundError(f"{key} is not readable from any site ({'; '.join(errors)})")

    def list_manifests(self) -> list[dict[str, Any]]:
        for site in self.sites:
            try:
                rows = self.backend(site.name).list_manifests()
            except Exception:  # noqa: BLE001
                continue
            if rows:
                return rows
        return []

    def delete(self, key: str) -> dict[str, Any]:
        return self._write("delete", key, None)

    def health(self) -> dict[str, Any]:
        degraded = [name for name, row in self._health.items() if row["failures"]]
        return {
            "schema": SCHEMA,
            "sites": [site.name for site in self.sites],
            "quorum": self.quorum,
            "health": self._health,
            "degraded": degraded,
            "verdict": "HEALTHY" if not degraded else "DEGRADED",
            "statement": (f"{len(self.sites)} site(s), quorum {self.quorum}, no write failures"
                          if not degraded else
                          f"{len(degraded)} site(s) have failed a write: {', '.join(degraded)}"),
        }
