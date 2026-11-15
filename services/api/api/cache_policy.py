"""What may be cached — and what must never be.

The read cache (``api.cache``) answers *how* to cache: bounded, tenant-keyed,
tag-invalidated, TTL-floored. This module answers *what* — and the what is a
policy decision with exactly two lists, stated by the platform's
infrastructure spec and enforced here rather than left to reviewer taste.

**Cacheable** (explicit invalidation or a TTL ceiling is enough — these are
aggregates and reference data whose staleness is bounded and useful):

* dashboard aggregate counts
* technology category summaries
* static policy definitions
* vendor reference metadata
* frequently requested read-only asset summaries
* user interface configuration

**Authoritative — never cached** (they change without warning and a stale
answer is worse than a slow one; the record of truth is the database):

* current evidence status
* certificate expiration
* asset freshness
* risk findings
* user permissions
* Digital Twin state

The one invariant every line of this module exists to keep: **a cached
value must never override an authoritative record.** So ``policy_read`` is
the only sanctioned way to serve a classified read — cacheable classes go
through the ReadCache; everything else (authoritative classes AND any
class this module has never heard of) is computed fresh, every time, and
is never written to the cache. Unknown classes fail toward the truth: a
classification gap must never become a staleness bug.

Every read is counted by class. A cache that hides what it refused to
cache is as dishonest as one that caches too much.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Iterable, TypeVar

from api.cache import ReadCache, get_read_cache

T = TypeVar("T")

#: Aggregate/reference reads whose staleness is bounded by TTL + tag
#: invalidation. Keys use the spec's nouns so the list is auditable.
CACHEABLE: frozenset[str] = frozenset({
    "dashboard_aggregates",        # dashboard aggregate counts
    "category_summaries",          # technology category summaries
    "policy_definitions",          # static policy definitions
    "vendor_reference",            # vendor reference metadata
    "asset_summaries",             # frequently requested read-only asset summaries
    "ui_configuration",            # user interface configuration
})

#: Reads whose only honest source is the record itself. Never stored.
AUTHORITATIVE: frozenset[str] = frozenset({
    "evidence_status",             # current evidence status
    "certificate_expiration",      # certificate expiration
    "asset_freshness",             # asset freshness
    "risk_findings",               # risk findings
    "user_permissions",            # user permissions
    "twin_state",                  # Digital Twin state
})

_lock = threading.Lock()
_stats: dict[str, Any] = {
    "cacheable_reads": 0,
    "cacheable_hits": 0,          # served from cache (set by policy_read on hit)
    "authoritative_reads": 0,
    "refused_unknown_classes": {},  # class -> count: never cached, computed fresh
}


def cacheable_classes() -> frozenset[str]:
    return CACHEABLE


def authoritative_classes() -> frozenset[str]:
    return AUTHORITATIVE


def may_cache(cache_class: str) -> bool:
    """Only a name on the cacheable list may ever be stored.

    Unknown names return False on purpose: an unclassified read is treated
    as authoritative until somebody classifies it on purpose.
    """
    return cache_class in CACHEABLE


def policy_read(cache_class: str, key: str, compute: Callable[[], T],
                *, tags: Iterable[str] = (),
                cache: ReadCache | None = None) -> T:
    """Serve one classified read. The chokepoint: everything that honors
    this module goes through here.

    * cacheable class -> the ReadCache (``get_or_set``; tag invalidation and
      the TTL staleness ceiling apply exactly as documented in api.cache).
    * authoritative class -> ``compute()`` fresh, every call, never stored.
    * anything else -> same as authoritative, and counted as a refusal so
      the classification gap is visible to operators instead of silent.
    """
    if may_cache(cache_class):
        store = cache if cache is not None else get_read_cache()
        key_before = store.get(key)
        if key_before is not None:
            with _lock:
                _stats["cacheable_reads"] += 1
                _stats["cacheable_hits"] += 1
            return key_before  # type: ignore[return-value]
        value = compute()
        store.set(key, value, tags=tags)
        with _lock:
            _stats["cacheable_reads"] += 1
        return value  # type: ignore[return-value]

    with _lock:
        if cache_class in AUTHORITATIVE:
            _stats["authoritative_reads"] += 1
        else:
            refusals = _stats["refused_unknown_classes"]
            refusals[cache_class] = refusals.get(cache_class, 0) + 1
    return compute()


def policy_stats() -> dict[str, Any]:
    with _lock:
        return {
            "cacheable_reads": _stats["cacheable_reads"],
            "cacheable_hits": _stats["cacheable_hits"],
            "authoritative_reads": _stats["authoritative_reads"],
            "refused_unknown_classes": dict(_stats["refused_unknown_classes"]),
        }


def reset_policy_stats() -> None:
    """Tests start from a clean ledger; production never calls this."""
    with _lock:
        _stats["cacheable_reads"] = 0
        _stats["cacheable_hits"] = 0
        _stats["authoritative_reads"] = 0
        _stats["refused_unknown_classes"] = {}
