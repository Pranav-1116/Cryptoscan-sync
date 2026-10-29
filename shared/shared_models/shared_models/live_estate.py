"""Live mode: what an observation is allowed to write, and what a BOM change touches.

The platform's live model is one rule with two consequences:

* **one baseline, then changes only.** The first observation of an estate is stored in
  full. After that, an observation whose canonical state hash equals the stored one is
  *dropped* — it produced no evidence, no run and no BOM revision, because copying an
  unchanged estate is how a live product turns into a nightly batch job with worse
  latency. A changed observation is stored as evidence and projected into the twin;
* **the six BOMs are projections, never stores.** Nothing here writes a BOM. A download
  projects the current twin on demand, which is why "download the current CBOM" needs no
  scan and why two downloads of the same projection are byte-identical.

``bom_impact`` answers the narrower question a change-driven system must answer without
guessing: given the changes between two observations, which projections could have moved?
It is deliberately conservative — when the change makes narrowing impossible (an edge
appears in every projection that contains either endpoint), it says so instead of picking
one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.live-estate/1"

#: the states one observation can be in, relative to the stored twin
FIRST_BASELINE = "FIRST_BASELINE"
CHANGED = "CHANGED"
NO_CHANGE = "NO_CHANGE"

#: connection states. ``LIVE`` is a measurement of the last observation's age, never an
#: assumption that the agent is happy.
CONNECTED = "LIVE"
STALE = "STALE"
NEVER_CONNECTED = "NEVER_CONNECTED"

#: how often the agent is expected to report. Not a promise the platform can enforce: an
#: agent that stops reporting looks exactly like an estate that stopped changing, which is
#: why the age is reported next to the state.
DEFAULT_INTERVAL_SECONDS = 300

#: an observation older than this multiple of the interval is STALE, not LIVE
STALE_MULTIPLE = 2

LIMITS = [
    "NO_CHANGE means the normalised state hash did not move; it does not mean the estate was "
    "observed well, and it does not survive a collector that silently stopped reading a plane",
    "an observation's coverage block is what makes 'nothing changed' honest: a plane that "
    "reported less than before is COVERAGE_DEGRADED, not quiet",
    "the state hash covers normalised assets, evidence and relationships; it cannot see a "
    "change to something no collector reads",
    "the baseline is stored in full exactly once per estate; every later write is a change",
    "the six BOMs are projections of the current twin; they are not stored as separate truth "
    "and they carry the projection id they were computed from",
]

#: projection kinds, in the product's order
BOM_KINDS = ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM")

#: which projections can contain a component of each asset type
ASSET_TYPE_BOMS: dict[str, tuple[str, ...]] = {
    "PACKAGE": ("SBOM", "TECHBOM"),
    "LIBRARY": ("SBOM", "TECHBOM"),
    "IMAGE": ("SBOM", "TECHBOM"),
    "HOST": ("HBOM", "TECHBOM"),
    "HARDWARE": ("HBOM", "TECHBOM"),
    "FIRMWARE": ("HBOM", "TECHBOM"),
    "NETWORK_ENDPOINT": ("NBOM", "TECHBOM"),
    "LOAD_BALANCER": ("NBOM", "TECHBOM"),
    "API_GATEWAY": ("NBOM", "TECHBOM"),
    "DATABASE": ("NBOM", "TECHBOM"),
    "MESSAGE_BROKER": ("NBOM", "TECHBOM"),
    "CLOUD_RESOURCE": ("NBOM", "TECHBOM"),
    "VENDOR": ("VBOM", "TECHBOM"),
    "SYSTEM": ("TECHBOM",),
    "APPLICATION": ("TECHBOM",),
    "SERVICE": ("TECHBOM",),
    "CONTAINER": ("TECHBOM",),
    "POD": ("TECHBOM",),
    "NAMESPACE": ("TECHBOM",),
    "CLUSTER": ("TECHBOM",),
    "HSM": ("TECHBOM",),
    "KMS_KEY": ("TECHBOM",),
}

#: change kinds that move a crypto component
CRYPTO_KINDS = ("CRYPTO_ADDED", "CRYPTO_CHANGED", "CRYPTO_REMOVED", "CRYPTO_DEMOTED", "CRYPTO_PROMOTED")

#: change kinds that move only the unknowns block every projection carries
UNKNOWN_KINDS = (
    "COVERAGE_DEGRADED",
    "COVERAGE_IMPROVED",
    "EVIDENCE_LOST",
    "UNKNOWN_GAINED",
    "UNKNOWN_REDUCED",
    "UNRESOLVED_GAINED",
    "UNRESOLVED_REDUCED",
)


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    if isinstance(moment, datetime):
        moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    return str(moment)


def compare_state(previous_projection_id: str | None, current_projection_id: str) -> dict[str, Any]:
    """Decide whether this observation is worth storing.

    ``previous_projection_id`` is the stored twin's content address. Comparing it with the
    incoming one is the whole change detector: the address is built from normalised assets,
    relationships and evidence, so two collectors that see the same estate produce the same
    address, and a single changed fact produces a different one.
    """
    previous = str(previous_projection_id or "").strip() or None
    current = str(current_projection_id or "").strip()
    if not current:
        raise ValueError("an observation without a projection id cannot be compared or stored")
    if previous is None:
        state = FIRST_BASELINE
    elif previous == current:
        state = NO_CHANGE
    else:
        state = CHANGED
    return {
        "state": state,
        "store": state != NO_CHANGE,
        # a baseline is a full write; a change is an incremental one. Neither is "less" true.
        "full_write": state == FIRST_BASELINE,
        "previous_projection_id": previous,
        "current_projection_id": current,
        "reason": {
            FIRST_BASELINE: "no stored twin for this estate yet, so this observation is the baseline",
            NO_CHANGE: "the normalised state hash equals the stored twin's, so nothing is stored",
            CHANGED: "the normalised state hash moved, so this observation is stored as a change",
        }[state],
    }


def bom_impact(
    changes: Iterable[Mapping[str, Any]],
    *,
    all_kinds: Iterable[str] = BOM_KINDS,
) -> dict[str, Any]:
    """Which of the six projections could have moved, given the named changes.

    Two questions are separated on purpose, because they mean different things to a reader:

    * ``affected`` — projections where a **component** moved (an asset, a crypto artefact, or
      an edge that appears in every projection holding either endpoint). This is the list a
      re-render actually changes;
    * ``unknowns_affected`` — projections whose **unknowns/coverage block** moved. Every
      projection carries that block, so a coverage loss or a gain in unevidenced assets
      touches all six even though no component was added or removed.

    Merging the two is how a download ends up silently stale, so they are reported apart.
    """
    kinds = tuple(all_kinds)
    components: dict[str, list[str]] = {kind: [] for kind in kinds}
    unknowns: dict[str, list[str]] = {kind: [] for kind in kinds}
    unmapped: list[str] = []
    unknown_scope: list[str] = []
    by_change: dict[str, list[str]] = {}

    for change in changes:
        name = str(change.get("kind") or "").upper()
        if not name:
            continue
        touched: set[str] = set()
        unknowns_only = False
        if name.startswith("CRYPTO_") or name in CRYPTO_KINDS:
            touched.update(("CBOM", "TECHBOM"))
        elif name.startswith("ASSET_"):
            asset_type = _asset_type(change)
            touched.update(ASSET_TYPE_BOMS.get(asset_type, ()))
            if not touched:
                unknown_scope.append(name)
                touched.update(kinds)
                unmapped.append(asset_type or "UNKNOWN")
        elif name.startswith("RELATIONSHIP_"):
            # an edge lives in every projection that contains either endpoint, and the
            # change does not say which endpoints — so the whole set is in scope
            unknown_scope.append(name)
            touched.update(kinds)
        elif name in UNKNOWN_KINDS or name.startswith("UNKNOWN_") or name.startswith("UNRESOLVED_"):
            # no component moves, but every projection carries the unknowns block
            unknowns_only = True
            touched.update(kinds)
        else:
            unknown_scope.append(name)
            touched.update(kinds)

        by_change[name] = sorted(touched)
        reason = _reason(name, change)
        bucket = unknowns if unknowns_only else components
        for kind in touched:
            if reason not in bucket.setdefault(kind, []):
                bucket[kind].append(reason)

    affected = [kind for kind in kinds if components.get(kind)]
    unknowns_affected = [kind for kind in kinds if unknowns.get(kind)]
    return {
        "schema": SCHEMA,
        "affected": affected,
        "unknowns_affected": unknowns_affected,
        "unchanged": [kind for kind in kinds if kind not in affected and kind not in unknowns_affected],
        "reasons": {
            kind: [*(components.get(kind) or []), *(unknowns.get(kind) or [])]
            for kind in kinds
            if components.get(kind) or unknowns.get(kind)
        },
        "by_change": by_change,
        "unmapped_asset_types": sorted(set(unmapped)),
        "imprecise": bool(unknown_scope),
        "imprecise_kinds": sorted(set(unknown_scope)),
        "note": (
            "affected = a component moved in that projection; unknowns_affected = only the "
            "unknowns/coverage block moved, which every projection carries. Both are recomputed "
            "for export regardless, so a download always renders the current twin"
        ),
    }


def _asset_type(change: Mapping[str, Any]) -> str:
    """Best available asset type for an ASSET_* change, without inventing one."""
    for key in ("after", "before"):
        value = change.get(key)
        if isinstance(value, Mapping):
            found = str(value.get("type") or "").upper()
            if found:
                return found
        elif isinstance(value, str) and value.upper().isalpha() and value.isupper():
            return value.upper()
    return ""


def _reason(kind: str, change: Mapping[str, Any]) -> str:
    subject = str(change.get("subject") or "unstated subject")
    if kind.startswith("CRYPTO_"):
        return f"{kind} on {subject}"
    if kind.startswith("RELATIONSHIP_"):
        return f"{kind} ({subject}) — an edge appears in any projection holding either endpoint"
    if kind.startswith("ASSET_"):
        return f"{kind} ({subject})"
    return f"{kind} moved no component but changes the unknowns block"


def connection_state(
    last_observation: Any,
    *,
    now: datetime | None = None,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
) -> dict[str, Any]:
    """Is the estate live, and how is that known?

    ``LIVE`` is computed from the age of the last accepted observation against the expected
    interval. An agent that stops reporting therefore becomes ``STALE`` on its own — the
    platform never assumes a connection it has not recently heard from.
    """
    interval = max(1, int(interval_seconds or DEFAULT_INTERVAL_SECONDS))
    threshold = interval * STALE_MULTIPLE
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    last = last_observation
    if isinstance(last, str):
        try:
            last = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError:
            last = None
    if isinstance(last, datetime) and last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)

    if last is None:
        return {
            "schema": SCHEMA,
            "state": NEVER_CONNECTED,
            "last_observation": None,
            "seconds_since": None,
            "interval_seconds": interval,
            "stale_after_seconds": threshold,
            "meaning": (
                "no observation has been accepted for this estate; the twin is NOT_OBSERVED, "
                "which is not an estate without cryptography"
            ),
        }
    seconds = max(0, int((moment - last).total_seconds()))
    state = CONNECTED if seconds <= threshold else STALE
    return {
        "schema": SCHEMA,
        "state": state,
        "last_observation": _iso(last),
        "seconds_since": seconds,
        "interval_seconds": interval,
        "stale_after_seconds": threshold,
        "meaning": (
            "an observation arrived within the expected interval"
            if state == CONNECTED
            else (
                "no observation arrived within the expected interval: the estate below this "
                "timestamp is history, and a quiet estate and a stopped agent look identical "
                "from here"
            )
        ),
    }


def state_hash_report(computed: str, claimed: str | None) -> dict[str, Any]:
    """Compare the agent's own state hash with the one this platform computed.

    An agent that hashes a different normalisation will report NO_CHANGE while the platform
    sees CHANGED (or the reverse). Saying so is the difference between a bug report and a
    silent drift.
    """
    claimed_clean = str(claimed or "").strip() or None
    return {
        "computed": computed,
        "claimed": claimed_clean,
        "agrees": None if claimed_clean is None else claimed_clean == computed,
        "note": (
            "no state hash was claimed by the agent"
            if claimed_clean is None
            else (
                "agent and platform hash the same normalised state"
                if claimed_clean == computed
                else "agent and platform disagree about the state hash — one of the two "
                "normalisers changed; the platform's hash is the stored one"
            )
        ),
    }
