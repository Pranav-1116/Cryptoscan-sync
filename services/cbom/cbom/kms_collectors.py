"""KMS and HSM key metadata: three different answers, and never the key itself.

The review's items 11 and 12 are the ones a bank gets audited on:

    supported RSA-4096  !=  RSA-4096 key exists  !=  RSA-4096 actually used

A CBOM that conflates them either over-claims (the HSM *can* do RSA-4096, so the
bank *has* one) or under-claims (a key exists but nobody recorded a use, so the
key vanishes). This module reads key inventory rows into three separate things:

``CONFIGURED``
    a key with these properties exists in the provider — an inventory fact
``RUNTIME_OBSERVED``
    a recorded operation used it — the only one of the three that is usage
``VENDOR_DECLARED``
    (from :func:`cbom.usage_evidence.hsm_evidence`) the module supports an
    algorithm; no key and no operation is implied

Every record is passed through :func:`cbom.usage_evidence.key_metadata`, so a row
carrying key material is an **error**, not a sanitised import. A row with no
``key_ref`` is refused, and a use record for a key nobody inventoried is refused
too — because that usually means the inventory is incomplete, and a CBOM must say
so rather than attach the operation to a guess.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

from cbom import usage_evidence as ue

SCHEMA = "cryptoscan.cbom-kms-collectors/1"

#: Providers a bank's key inventory comes from. Anything else is kept verbatim
#: but marked unknown, rather than being coerced into the nearest match.
PROVIDERS: tuple[str, ...] = (
    "AWS_KMS", "AZURE_KEY_VAULT", "GCP_KMS", "PKCS11", "HSM", "DATABASE", "LOCAL", "UNKNOWN",
)

#: Providers whose inventory rows are declarations until the platform reads the
#: provider's own API; a row that comes from a spreadsheet is still a row.
DECLARED_PROVIDERS: frozenset[str] = frozenset({"UNKNOWN"})

#: Default rotation age a bank's key policy usually states. Overdue is reported,
#: never adjusted: the policy belongs to the bank.
DEFAULT_MAX_AGE_DAYS = 365

#: ``status`` values that mean the key can be used right now.
USABLE_STATUSES: frozenset[str] = frozenset({"ENABLED", "ACTIVE", "AVAILABLE", "IN_USE"})

_ALIASES: dict[str, str] = {
    "key_id": "key_ref",
    "id": "key_ref",
    "arn": "key_ref",
    "key_arn": "key_ref",
    "key_size_bits": "key_size",
    "key_type": "key_type",
    "created": "created_at",
    "creation_time": "created_at",
    "rotated": "rotated_at",
    "rotation_time": "rotated_at",
    "last_rotated": "rotated_at",
    "algorithm_type": "algorithm",
}


def _as_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).date() if value.tzinfo else value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


def _normalize(row: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in row.items():
        normalized[_ALIASES.get(str(key), str(key))] = value
    return normalized


def key_records_from_kms(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Provider inventory rows -> key metadata records, or refusals.

    A record that carries anything that looks like key material raises
    :class:`cbom.usage_evidence.EvidenceRefused`; the caller decides whether that
    fails the request or is reported. Rows without a reference are refused
    individually, because one bad row must not hide the rest of the inventory.
    """
    records: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            refused.append({"row": row, "reason": "a key row must be an object"})
            continue
        normalized = _normalize(row)
        provider = str(normalized.get("provider") or "").strip().upper()
        # An unrecognised provider is kept verbatim and flagged; coercing it into
        # the nearest known provider would be a guess dressed as an inventory.
        unknown_provider = bool(provider) and provider not in PROVIDERS
        normalized["provider"] = provider or "UNKNOWN"
        suspicious = [str(field) for field in normalized
                      if any(marker in str(field).lower() for marker in ue.SECRET_MARKERS)]
        if suspicious:
            refused.append({"key_ref": normalized.get("key_ref"),
                            "reason": "the row carries " + ", ".join(sorted(suspicious))
                                      + "; a CBOM stores key references, never material"})
            continue
        kept = {field: value for field, value in normalized.items()
                if field in ue.KEY_METADATA_FIELDS}
        ignored = sorted(str(field) for field in normalized
                         if field not in ue.KEY_METADATA_FIELDS)
        try:
            record = ue.key_metadata(kept)
        except ue.EvidenceRefused as exc:
            refused.append({"key_ref": normalized.get("key_ref"),
                            "reason": str(exc)})
            continue
        if ignored:
            record["ignored_fields"] = ignored
        record["provider_declared_only"] = record["provider"] in DECLARED_PROVIDERS
        record["provider_unknown"] = unknown_provider
        record["usable"] = str(record.get("status") or "").upper() in USABLE_STATUSES
        records.append(record)
    return {
        "schema": SCHEMA,
        "records": records,
        "refused": refused,
        "providers": sorted({str(record["provider"]) for record in records}),
        "statement": (
            f"{len(records)} key record(s) across {len({r['provider'] for r in records})} "
            "provider(s), metadata only"
            + (f"; {len(refused)} row(s) refused" if refused else "")),
    }


def usage_events_from_keys(records: Iterable[Mapping[str, Any]],
                           uses: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Configured keys and recorded operations, as two separate evidence sets.

    A configured key is ``CONFIGURED``: it exists, nothing says it was used. An
    operation is ``RUNTIME_OBSERVED`` and requires the key to have been
    inventoried, an evidence id and a timestamp — the same rule the runtime
    collector applies, because the reason is the same.
    """
    inventory = {str(record.get("key_ref")): record for record in records}
    events: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for key_ref, record in sorted(inventory.items()):
        if not record.get("usable"):
            refused.append({"key_ref": key_ref,
                            "reason": f"the key is {record.get('status') or 'in an unknown state'}"
                                      ", so it is not a usable configured key"})
            continue
        evidence_id = str(record.get("evidence_id") or "").strip()
        if not evidence_id:
            refused.append({"key_ref": key_ref,
                            "reason": "the inventory row has no evidence id"})
            continue
        events.append({
            "class": "CONFIGURED",
            "evidence_id": evidence_id,
            "algorithm": record.get("algorithm"),
            "parameters": {key: record[key] for key in ("key_size", "curve")
                           if record.get(key)},
            "purpose": record.get("purpose"),
            "layer": "config",
            "location": record.get("location") or record.get("hsm_id") or record.get("kms_id"),
            "observed_at": record.get("created_at"),
            "key_ref": key_ref,
            "provider": record.get("provider"),
        })
    for use in uses:
        if not isinstance(use, Mapping):
            refused.append({"use": use, "reason": "a use record must be an object"})
            continue
        key_ref = str(use.get("key_ref") or "").strip()
        record = inventory.get(key_ref)
        if record is None:
            refused.append({"key_ref": key_ref or None,
                            "reason": "the operation names a key that is not in the inventory; "
                                      "the inventory is incomplete, not the operation"})
            continue
        operation = str(use.get("operation") or "").strip()
        evidence_id = str(use.get("evidence_id") or "").strip()
        observed_at = use.get("observed_at")
        missing = [name for name, value in (("operation", operation),
                                            ("evidence_id", evidence_id),
                                            ("observed_at", observed_at)) if not value]
        if missing:
            refused.append({"key_ref": key_ref,
                            "reason": f"a key operation is missing {', '.join(missing)}"})
            continue
        events.append({
            "class": "RUNTIME_OBSERVED",
            "evidence_id": evidence_id,
            "algorithm": use.get("algorithm") or record.get("algorithm"),
            "parameters": {key: use[key] for key in ("key_size", "mode", "curve")
                           if use.get(key)},
            "purpose": use.get("purpose") or record.get("purpose"),
            "layer": "runtime",
            "location": record.get("location"),
            "observed_at": observed_at,
            "operation": operation.upper(),
            "key_ref": key_ref,
            "provider": record.get("provider"),
        })
    configured = [event for event in events if event["class"] == "CONFIGURED"]
    operated = [event for event in events if event["class"] == "RUNTIME_OBSERVED"]
    return {
        "schema": SCHEMA,
        "events": events,
        "refused": refused,
        "configured": len(configured),
        "operated": len(operated),
        "statement": (
            f"{len(configured)} configured key(s), {len(operated)} recorded operation(s)"
            + ("; a configured key is not usage" if configured and not operated else "")
            + (f"; {len(refused)} row(s) refused" if refused else "")),
    }


def posture(records: Iterable[Mapping[str, Any]], *, as_of: date | None = None,
            max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> dict[str, Any]:
    """Key inventory posture: algorithms, weak sizes, rotation overdue, providers.

    Rotation is reported against the policy age handed in, and a key with no
    recorded creation *or* rotation date is ``UNKNOWN_AGE`` rather than assumed
    fresh — the same rule the rest of the platform applies to missing evidence.
    """
    as_of = as_of or datetime.now(timezone.utc).date()
    rows = list(records)
    by_algorithm: dict[str, int] = {}
    by_provider: dict[str, int] = {}
    by_status: dict[str, int] = {}
    weak: list[dict[str, Any]] = []
    overdue: list[dict[str, Any]] = []
    unknown_age: list[str] = []
    for record in rows:
        algorithm = str(record.get("algorithm") or "UNKNOWN")
        by_algorithm[algorithm] = by_algorithm.get(algorithm, 0) + 1
        provider = str(record.get("provider") or "UNKNOWN")
        by_provider[provider] = by_provider.get(provider, 0) + 1
        status = str(record.get("status") or "UNKNOWN").upper()
        by_status[status] = by_status.get(status, 0) + 1
        size = record.get("key_size")
        if algorithm.upper() in {"RSA", "DSA", "DH"} and isinstance(size, int) and size < 2048:
            weak.append({"key_ref": record.get("key_ref"), "algorithm": algorithm,
                         "key_size": size})
        if algorithm.upper() in {"EC", "ECDSA", "ECDH"} and record.get("curve") in {"P-192",
                                                                                  "P-224"}:
            weak.append({"key_ref": record.get("key_ref"), "algorithm": algorithm,
                         "curve": record.get("curve")})
        anchor = _as_date(record.get("rotated_at")) or _as_date(record.get("created_at"))
        if anchor is None:
            unknown_age.append(str(record.get("key_ref")))
            continue
        age = (as_of - anchor).days
        if age > max_age_days:
            overdue.append({"key_ref": record.get("key_ref"), "age_days": age,
                            "since": anchor.isoformat()})
    return {
        "schema": SCHEMA,
        "keys": len(rows),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "by_provider": dict(sorted(by_provider.items())),
        "by_status": dict(sorted(by_status.items())),
        "weak_keys": sorted(weak, key=lambda row: str(row.get("key_ref"))),
        "rotation_overdue": sorted(overdue, key=lambda row: -int(row["age_days"])),
        "unknown_age": sorted(unknown_age),
        "policy_max_age_days": max_age_days,
        "as_of": as_of.isoformat(),
        "statement": (
            f"{len(rows)} key(s) inventoried across {len(by_algorithm)} algorithm(s); "
            f"{len(weak)} weak, {len(overdue)} past {max_age_days} days without rotation, "
            f"{len(unknown_age)} with no recorded age"),
    }
