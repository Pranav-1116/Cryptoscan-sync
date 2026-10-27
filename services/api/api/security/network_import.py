"""Declared / imported network scope candidates (spec 67 §4, §23).

A bank already knows most of its exposure: CMDB exports, load-balancer
inventory, Kubernetes ingress lists, cloud endpoint exports, firewall objects.
CryptoScan can ingest that list — but an imported list is **evidence of a
declaration, not of cryptography**, so:

* import never probes anything and never opens a socket;
* every accepted destination is tagged ``CONFIG_IMPORTED`` with its source and
  import time;
* rows that fail target validation are reported back, never silently dropped;
* an import produces *candidates*. A human still has to approve the scope
  (``PUT /network/crypto-scope``) before any probe is allowed — an import must
  not be able to widen the blast radius of the platform on its own.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable

#: import sources the platform accepts (§4 A)
IMPORT_SOURCES = {
    "CMDB": "configuration-management database export",
    "LOAD_BALANCER": "load balancer / ADC inventory",
    "KUBERNETES": "kubernetes ingress/gateway inventory",
    "CLOUD": "cloud endpoint export",
    "FIREWALL": "firewall object group",
    "DNS": "DNS zone export",
    "MANUAL": "operator-supplied list",
}

#: candidate states — a candidate is never treated as observed crypto
CANDIDATE_STATE = "CONFIG_IMPORTED"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_endpoint(value: Any) -> str:
    """Endpoint text → canonical ``host:port`` (default 443), or "" if empty."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    # tolerate common export decorations: URLs, trailing slashes, quotes
    for prefix in ("https://", "http://", "tls://", "ssl://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].strip().strip('"').strip("'")
    if not raw:
        return ""
    if raw.startswith("["):
        host, _, rest = raw[1:].partition("]")
        port = rest[1:] if rest.startswith(":") and rest[1:].isdigit() else "443"
        return f"[{host}]:{port}"
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return f"{host.rstrip('.')}:{port}"
        return f"{raw.rstrip('.')}:443"
    return f"{raw.rstrip('.')}:443"


def parse_import_payload(*, text: str | None = None, entries: Iterable[Any] | None = None) -> list[str]:
    """Read candidates from a JSON array, CSV/TSV, or newline list.

    Deliberately format-tolerant: a bank's CMDB export is rarely a clean JSON
    array. Anything that yields a ``host``/``endpoint`` column is accepted and
    normalised; nothing is guessed into a port other than the 443 default.
    """
    values: list[str] = []
    if entries is not None:
        for item in entries:
            if isinstance(item, dict):
                for key in ("endpoint", "host", "hostname", "address", "target", "ip", "name"):
                    if item.get(key):
                        port = item.get("port")
                        base = normalize_endpoint(item[key])
                        values.append(base if port is None else f"{base.rsplit(':', 1)[0]}:{int(port)}")
                        break
            else:
                values.append(str(item))
        return [value for value in (normalize_endpoint(item) for item in values) if value]

    if not text or not text.strip():
        return []

    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            for key in ("destinations", "endpoints", "hosts", "targets", "entries"):
                if isinstance(parsed.get(key), list):
                    return parse_import_payload(entries=parsed[key])
        if isinstance(parsed, list):
            return parse_import_payload(entries=parsed)

    # CSV / TSV / newline list
    delimiter = "\t" if "\t" in stripped.splitlines()[0] else ","
    reader = csv.reader(io.StringIO(stripped), delimiter=delimiter)
    rows = [row for row in reader if any(cell.strip() for cell in row)]
    if not rows:
        return []
    header = [cell.strip().lower() for cell in rows[0]]
    has_header = any(name in {"host", "hostname", "endpoint", "ip", "address", "target"} for name in header)
    if has_header:
        return parse_import_payload(entries=[dict(zip(header, row)) for row in rows[1:]])
    # Header-less export: a bare numeric second column is a port, not an owner.
    headerless: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {"host": row[0]}
        if len(row) > 1 and row[1].strip().isdigit():
            item["port"] = int(row[1].strip())
        headerless.append(item)
    return parse_import_payload(entries=headerless)


def build_candidates(
    endpoints: Iterable[str],
    *,
    source: str,
    existing: Iterable[str] = (),
    max_candidates: int = 200,
) -> dict[str, Any]:
    """Validate declared endpoints into scope candidates.

    Validation is the same probe-target check the live scanner uses, so an
    import cannot smuggle in loopback, link-local, multicast, metadata, reserved
    or non-endpoint values that the probe path would refuse later anyway.
    """
    from api.security.target_validation import TargetValidationError, validate_probe_targets

    source_key = str(source or "MANUAL").upper()
    if source_key not in IMPORT_SOURCES:
        raise ValueError(f"unknown import source '{source}'; expected one of {sorted(IMPORT_SOURCES)}")

    known = {normalize_endpoint(item) for item in existing}
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    duplicates: list[str] = []
    seen: set[str] = set()

    for raw in endpoints:
        endpoint = normalize_endpoint(raw)
        if not endpoint:
            continue
        if endpoint in seen or endpoint in known:
            duplicates.append(endpoint)
            continue
        try:
            validate_probe_targets([endpoint])
        except TargetValidationError as exc:
            rejected.append({"endpoint": endpoint, "reason": str(exc)})
            continue
        seen.add(endpoint)
        accepted.append(
            {
                "endpoint": endpoint,
                "evidence_type": CANDIDATE_STATE,
                "source": source_key,
                "source_description": IMPORT_SOURCES[source_key],
                "declared": True,
                "observed": False,
            }
        )
        if len(accepted) >= max_candidates:
            break

    return {
        "schema": "cryptoscan.network-scope-import/1",
        "source": source_key,
        "source_description": IMPORT_SOURCES[source_key],
        "generated_at": _now(),
        "candidates": accepted,
        "accepted_count": len(accepted),
        "rejected": rejected,
        "duplicate_count": len(duplicates),
        "duplicates": duplicates[:50],
        "truncated": len(accepted) >= max_candidates,
        "probing_performed": False,
        "note": (
            "imported destinations are CONFIG_IMPORTED declarations, not observations — "
            "nothing was probed and no crypto is claimed until a scan observes it"
        ),
    }


def merge_candidates(
    *,
    current_destinations: Iterable[str],
    candidates: Iterable[dict[str, Any]],
    max_total: int = 100,
) -> dict[str, Any]:
    """Merge accepted candidates into a scope's destination list.

    Existing destinations are preserved in their original order; imported ones
    are appended until ``max_total``. Overflow is reported, never silently cut.
    """
    existing = [normalize_endpoint(item) for item in current_destinations]
    merged = list(existing)
    added: list[str] = []
    already: list[str] = []
    dropped: list[str] = []
    for candidate in candidates:
        endpoint = normalize_endpoint(candidate.get("endpoint"))
        if not endpoint:
            continue
        if endpoint in merged:
            already.append(endpoint)
            continue
        if len(merged) >= max_total:
            dropped.append(endpoint)
            continue
        merged.append(endpoint)
        added.append(endpoint)
    return {
        "destinations": merged,
        "added": added,
        "already_present": already,
        "dropped_over_limit": dropped,
        "max_total": max_total,
        "total": len(merged),
    }
