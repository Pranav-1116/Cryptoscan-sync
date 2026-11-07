"""CryptoLog deterministic rules and alert lifecycle (docs/cryptolog/
01_PRODUCT_SPEC.md, Phase 5).

"Start with deterministic rules rather than an AI-based detection engine."

Fifteen rules (CL-001..CL-015) evaluate recorded events against recorded
state. The engine's honesty contract, each enforced here:

- severity is calculated from named factors (asset criticality, exposure,
  evidence quality, policy floor) — every adjustment is a driver string,
  never one unexplained number;
- a pattern never automatically becomes a confirmed compromise: alerts open
  as investigations carrying ``what_is_proven`` and ``what_is_not_proven``,
  and the only path to a CONFIRMED_INCIDENT resolution is a named human who
  supplies evidence — exactly like ``finding_lifecycle.confirm_incident``;
- acknowledgment and resolution history is append-only.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

ALERT_SCHEMA = "cryptoscan.cryptolog-alert/1"

# ---- severity ladder and the named factor vocabularies -------------------

INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"
_LADDER = (INFO, LOW, MEDIUM, HIGH, CRITICAL)

INTERNAL = "INTERNAL"
INTERNET_FACING = "INTERNET_FACING"
UNKNOWN_EXPOSURE = "UNKNOWN"

STRONG = "STRONG"
MODERATE = "MODERATE"
WEAK = "WEAK"

_RESOLVE_KINDS = ("BENIGN_EXPLAINED", "CHANGE_APPROVED", "FALSE_POSITIVE",
                  "ESCALATED", "CONFIRMED_INCIDENT")

OPEN = "OPEN"
ACKNOWLEDGED = "ACKNOWLEDGED"
RESOLVED = "RESOLVED"

#: weak-cipher markers (substring, case-insensitive) for CL-002
WEAK_CIPHER_MARKERS: tuple[str, ...] = (
    "NULL", "RC4", "RC2", "3DES", "DES_", "DES-", "EXPORT", "ANON", "MD5",
    "SEED", "IDEA", "CAST")

#: weak-algorithm markers for CL-004
WEAK_ALGORITHMS: frozenset[str] = frozenset({
    "RC4", "RC2", "DES", "3DES", "MD5", "SHA-1", "SHA1", "RSA-512",
    "RSA-1024", "EXPORT", "NULL"})

_TLS_ORDER = {"SSL3": 0, "TLS1.0": 1, "TLS1.1": 2, "TLS1.2": 3, "TLS1.3": 4,
              "TLS1.4": 5}


def _clean(value: Any) -> str:
    return str(value or "").strip()


# ---- the rule registry ----------------------------------------------------

RULES: dict[str, dict[str, str]] = {
    "CL-001": {"detection": "TLS protocol downgrade",
               "suggested_severity": "High",
               "investigation": "compare the connection's negotiated "
                                "protocol with the asset's previous observed "
                                "protocol and check for an approved change"},
    "CL-002": {"detection": "Weak cipher suite observed",
               "suggested_severity": "High",
               "investigation": "identify the endpoint offering the weak "
                                "suite and whether policy permits it"},
    "CL-003": {"detection": "Unexpected certificate replacement",
               "suggested_severity": "Medium/High",
               "investigation": "match the replacement against the approved "
                                "change record and the certificate lifecycle"},
    "CL-004": {"detection": "New weak algorithm configuration",
               "suggested_severity": "High",
               "investigation": "locate the configuration change and its "
                                "originating collector evidence"},
    "CL-005": {"detection": "Unexpected HSM key metadata change",
               "suggested_severity": "Medium/High",
               "investigation": "verify the change against the HSM change "
                                "record and key ceremony provenance"},
    "CL-006": {"detection": "Crypto library version regression",
               "suggested_severity": "Medium",
               "investigation": "identify the deployment that regressed the "
                                "library and its SBOM evidence"},
    "CL-007": {"detection": "Certificate expiry approaching",
               "suggested_severity": "Medium",
               "investigation": "check the renewal workflow and ownership "
                                "for the certificate"},
    "CL-008": {"detection": "Unexpected CA trust change",
               "suggested_severity": "High",
               "investigation": "verify the trust-store change against "
                                "approved change records and PKI ownership"},
    "CL-009": {"detection": "Crypto policy disabled",
               "suggested_severity": "High",
               "investigation": "identify who disabled the policy and "
                                "which assets inherit the effect"},
    "CL-010": {"detection": "PQC configuration removed",
               "suggested_severity": "High",
               "investigation": "check migration plans for reversion and "
                                "whether the removal was approved"},
    "CL-011": {"detection": "HSM connectivity or availability degradation",
               "suggested_severity": "High",
               "investigation": "confirm device state and whether key "
                                "operations are failing over or failing"},
    "CL-012": {"detection": "Collection visibility lost",
               "suggested_severity": "Medium/High",
               "investigation": "distinguish 'found nothing' from 'could "
                                "not look' and restore the collector path"},
    "CL-013": {"detection": "Unapproved cryptographic provider change",
               "suggested_severity": "Medium/High",
               "investigation": "match the provider change against approved "
                                "change records"},
    "CL-014": {"detection": "Unexpected key rotation pattern",
               "suggested_severity": "Medium",
               "investigation": "compare the rotation against the key's "
                                "schedule and lifecycle policy"},
    "CL-015": {"detection": "Conflicting cryptographic observations",
               "suggested_severity": "Investigation",
               "investigation": "reconcile the conflicting observations "
                                "against their evidence before any state is "
                                "treated as true"},
}

#: which rules evaluate a single event against its previous state
_NEEDS_PREVIOUS = frozenset({"CL-001"})


def _bump(severity: str) -> str:
    index = _LADDER.index(severity)
    return _LADDER[min(index + 1, len(_LADDER) - 1)]


def _drop(severity: str) -> str:
    index = _LADDER.index(severity)
    return _LADDER[max(index - 1, 0)]


def _base_severity(rule_id: str) -> str:
    suggested = RULES[rule_id]["suggested_severity"]
    return {"High": HIGH, "Medium/High": MEDIUM, "Medium": MEDIUM,
            "Investigation": MEDIUM}[suggested]


def severity_for(rule_id: str, *, asset_criticality: str | None = None,
                 exposure: str | None = None,
                 evidence_quality: str | None = None,
                 policy_floor: str | None = None) -> dict[str, Any]:
    """Explainable, reproducible severity: every adjustment is a named
    driver, never one unexplained number."""
    if rule_id not in RULES:
        raise ValueError(f"unknown rule {rule_id!r}")
    severity = _base_severity(rule_id)
    drivers = [f"rule {rule_id} base {severity} "
               f"(suggested {RULES[rule_id]['suggested_severity']})"]
    crit = _clean(asset_criticality).upper()
    if crit == "CRITICAL":
        severity = _bump(severity)
        drivers.append("asset criticality CRITICAL raises severity one step")
    expo = _clean(exposure).upper()
    if expo == INTERNET_FACING:
        severity = _bump(severity)
        drivers.append("internet-facing exposure raises severity one step")
    quality = _clean(evidence_quality).upper()
    if quality == WEAK:
        severity = _drop(severity)
        drivers.append("weak evidence lowers severity one step")
    floor = _clean(policy_floor).upper()
    if floor in _LADDER and _LADDER.index(floor) > _LADDER.index(severity):
        drivers.append(f"policy floor {floor} raises severity to the floor")
        severity = floor
    return {"severity": severity, "drivers": drivers,
            "basis": {"rule": rule_id, "asset_criticality": crit or None,
                      "exposure": expo or None,
                      "evidence_quality": quality or None,
                      "policy_floor": floor or None}}


def _weak_cipher(cipher_suite: str) -> bool:
    suite = _clean(cipher_suite).upper()
    return any(marker in suite for marker in WEAK_CIPHER_MARKERS)


def _tls_rank(version: str) -> int | None:
    return _TLS_ORDER.get(_clean(version).upper())


def _matches(rule_id: str, event: Mapping[str, Any],
             previous: Mapping[str, Any] | None) -> tuple[bool, str, str]:
    """(fires, expected, observed) for one rule against one event."""
    etype = _clean(event.get("event_type")).upper()
    ctx = event.get("cryptographic_context") or {}
    attrs = event.get("attributes") or {}
    approval = _clean(event.get("approval_ref")) or _clean(attrs.get("approved_change_ref"))
    observed_version = _clean(ctx.get("protocol_version"))
    cipher = _clean(ctx.get("cipher_suite"))

    if rule_id == "CL-001":
        prev_version = _clean((previous or {}).get("cryptographic_context", {})
                              .get("protocol_version")) if previous else ""
        old_rank, new_rank = _tls_rank(prev_version), _tls_rank(observed_version)
        fires = bool(previous) and old_rank is not None and new_rank is not None \
            and new_rank < old_rank
        return fires, f"{prev_version} remains negotiated", \
            f"{observed_version} negotiated"
    if rule_id == "CL-002":
        fires = bool(cipher) and _weak_cipher(cipher)
        return fires, "a policy-strong cipher suite is negotiated", \
            f"{cipher} negotiated"
    if rule_id == "CL-003":
        fires = etype == "CERTIFICATE_REPLACEMENT" and not approval
        return fires, "certificate replacement carries an approved change", \
            "replacement observed without an approved change reference"
    if rule_id == "CL-004":
        algorithm = _clean(attrs.get("algorithm")).upper()
        fires = etype in ("ALGORITHM_OBSERVED", "CRYPTO_CONFIGURATION_CHANGED") \
            and algorithm in WEAK_ALGORITHMS
        return fires, "no weak algorithm configuration is introduced", \
            f"{algorithm} configuration observed"
    if rule_id == "CL-005":
        fires = etype == "HSM_KEY_METADATA_CHANGE" and not approval
        return fires, "HSM key metadata changes carry an approved change", \
            "key metadata changed without an approved change reference"
    if rule_id == "CL-006":
        fires = etype == "CRYPTO_LIBRARY_REGRESSION"
        return fires, "no library version regression", "library version regression observed"
    if rule_id == "CL-007":
        days = attrs.get("days_until_expiry")
        fires = etype in ("CERTIFICATE_ISSUED", "CERTIFICATE_REPLACEMENT",
                          "CERTIFICATE_EXPIRED") \
            and isinstance(days, (int, float)) and days <= 30
        return fires, "certificate expiry is beyond the 30-day window", \
            f"certificate expires in {days} days"
    if rule_id == "CL-008":
        fires = etype == "CA_TRUST_CHANGED" and not approval
        return fires, "CA trust changes carry an approved change", \
            "CA trust changed without an approved change reference"
    if rule_id == "CL-009":
        fires = etype == "CRYPTO_POLICY_DISABLED"
        return fires, "the crypto policy is enabled", "crypto policy disabled"
    if rule_id == "CL-010":
        action = _clean(attrs.get("action")).upper()
        fires = etype == "PQC_CONFIGURATION_CHANGED" and action in ("REMOVED", "DISABLED")
        return fires, "PQC configuration remains in place", \
            f"PQC configuration {action.lower()}"
    if rule_id == "CL-011":
        availability = _clean(attrs.get("availability")).upper()
        fires = etype == "HSM_AVAILABILITY_CHANGED" and availability in ("DEGRADED", "DOWN", "UNAVAILABLE")
        return fires, "HSM availability is nominal", f"HSM availability {availability.lower()}"
    if rule_id == "CL-012":
        fires = etype == "COLLECTION_VISIBILITY_LOST"
        return fires, "collection visibility holds", "collection visibility lost"
    if rule_id == "CL-013":
        fires = etype == "CRYPTO_PROVIDER_CHANGED" and not approval
        return fires, "provider changes carry an approved change", \
            "provider changed without an approved change reference"
    if rule_id == "CL-014":
        scheduled = attrs.get("scheduled")
        fires = etype == "KEY_ROTATED" and (
            scheduled is False or _clean(scheduled).upper() == "UNEXPECTED")
        return fires, "key rotation follows its schedule", \
            "key rotation outside its schedule"
    raise ValueError(f"{rule_id} is a stream rule; evaluate it over the "
                      "event stream, not a single event")


def _event_evidence(event: Mapping[str, Any]) -> list[str]:
    return [str(e) for e in ((event.get("evidence") or {})
                             .get("evidence_ids") or []) if _clean(e)]


def make_alert(*, rule_id: str, events: Sequence[Mapping[str, Any]],
               expected: str, observed: str,
               severity_info: Mapping[str, Any],
               investigation_status: str = "INVESTIGATION_REQUIRED") -> dict[str, Any]:
    """Assemble the alert the spec requires: triggered rule, supporting
    event and evidence ids, affected assets and business systems, expected
    versus observed, what is proven and what is not, recommended
    investigation, and an append-only acknowledgment/resolution history.
    """
    rows = [dict(e) for e in events]
    if not rows:
        raise ValueError("an alert without supporting events is a guess: "
                         "every alert names its supporting event ids")
    evidence_ids = sorted({eid for e in rows for eid in _event_evidence(e)})
    if not evidence_ids:
        raise ValueError("an alert without supporting evidence is a guess: "
                         "every alert names its supporting evidence ids")
    return {
        "schema": ALERT_SCHEMA,
        "rule": dict(RULES[rule_id]),
        "rule_id": rule_id,
        "severity": severity_info["severity"],
        "severity_drivers": list(severity_info["drivers"]),
        "severity_basis": dict(severity_info["basis"]),
        "supporting_event_ids": [str(e.get("event_id") or "") for e in rows],
        "supporting_evidence_ids": evidence_ids,
        "affected": {
            "asset_ids": sorted({str(e.get("asset_id") or "") for e in rows
                                 if _clean(e.get("asset_id"))}),
            "business_system_ids": sorted({str(e.get("business_system_id") or "")
                                           for e in rows
                                           if _clean(e.get("business_system_id"))}),
        },
        "expected": expected,
        "observed": observed,
        "what_is_proven": (
            f"the recorded observation ({observed}) with supporting "
            f"evidence {', '.join(evidence_ids)}"),
        "what_is_not_proven": (
            "that this is malicious or a compromise: intent and cause are "
            "not established by observation alone, and a pattern never "
            "automatically becomes a confirmed compromise"),
        "recommended_investigation": RULES[rule_id]["investigation"],
        "investigation_status": investigation_status,
        "lifecycle": {"status": OPEN, "history": []},
    }


def evaluate(events: Iterable[Mapping[str, Any]], *,
             previous_by_asset: Mapping[str, Mapping[str, Any]] | None = None,
             assessments: Mapping[str, Mapping[str, Any]] | None = None,
             ) -> list[dict[str, Any]]:
    """Deterministically evaluate the rule set over an ordered event stream.

    ``previous_by_asset`` supplies each asset's previous known state (for
    CL-001 downgrades); ``assessments`` supplies named factors per asset
    ({asset_criticality, exposure, evidence_quality, policy_floor}) for the
    explainable severity calculation. CL-015 compares the stream against
    itself: two observations of the same parameter on one asset that
    disagree are a conflict to reconcile, never a truth to pick.
    """
    stream = [dict(e) for e in events]
    previous_by_asset = previous_by_asset or {}
    assessments = assessments or {}
    alerts: list[dict[str, Any]] = []

    for event in stream:
        asset = _clean(event.get("asset_id"))
        factors = assessments.get(asset, {})
        for rule_id in RULES:
            if rule_id == "CL-015":
                continue
            previous = previous_by_asset.get(asset) if rule_id in _NEEDS_PREVIOUS else None
            if rule_id in _NEEDS_PREVIOUS and previous is None:
                continue
            fires, expected, observed = _matches(rule_id, event, previous)
            if fires:
                info = severity_for(
                    rule_id,
                    asset_criticality=factors.get("asset_criticality"),
                    exposure=factors.get("exposure"),
                    evidence_quality=factors.get("evidence_quality"),
                    policy_floor=factors.get("policy_floor"))
                alerts.append(make_alert(
                    rule_id=rule_id, events=[event] if previous is None
                    else [previous, event],
                    expected=expected, observed=observed,
                    severity_info=info))

    # CL-015: conflicting observations of one parameter on one asset
    for parameter in ("protocol_version", "cipher_suite"):
        by_subject: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        for event in stream:
            value = _clean((event.get("cryptographic_context") or {})
                           .get(parameter))
            asset = _clean(event.get("asset_id"))
            if value and asset:
                by_subject.setdefault((asset, parameter), []).append(event)
        for (asset, _param), rows in sorted(by_subject.items()):
            values = {_clean((e.get("cryptographic_context") or {}).get(_param))
                      for e in rows}
            if len(values) > 1:
                factors = assessments.get(asset, {})
                info = severity_for(
                    "CL-015",
                    asset_criticality=factors.get("asset_criticality"),
                    exposure=factors.get("exposure"),
                    evidence_quality=factors.get("evidence_quality"),
                    policy_floor=factors.get("policy_floor"))
                alerts.append(make_alert(
                    rule_id="CL-015", events=rows,
                    expected=f"one consistent {_param} for {asset}",
                    observed=f"{_param} disagrees: {', '.join(sorted(values))}",
                    severity_info=info))
    return alerts


# ---- alert lifecycle (append-only history) --------------------------------

ACKNOWLEDGE = "ACKNOWLEDGE"
RESOLVE = "RESOLVE"
REOPEN = "REOPEN"


def transition(alert: Mapping[str, Any], *, action: str, actor: str,
               at: str, note: str | None = None,
               resolution: str | None = None,
               evidence_ids: Sequence[str] = ()) -> dict[str, Any]:
    """Move an alert through OPEN / ACKNOWLEDGED / RESOLVED with an
    append-only history.

    The only path to a CONFIRMED_INCIDENT resolution is a named actor
    supplying evidence — the engine can open investigations, never declare
    compromises. Resolution always requires an actor and a note.
    """
    who = _clean(actor)
    if not who:
        raise ValueError("every lifecycle action names its actor")
    act = _clean(action).upper()
    current = str((alert.get("lifecycle") or {}).get("status") or OPEN)
    entry = {"action": act, "actor": who, "at": str(at),
             "note": _clean(note) or None}
    history = list((alert.get("lifecycle") or {}).get("history") or [])
    updated = {**alert, "lifecycle": {**alert.get("lifecycle", {}),
                                      "history": history}}

    if act == ACKNOWLEDGE:
        if current == RESOLVED:
            raise ValueError("a resolved alert is acknowledged by reopening, "
                             "not by acknowledging a closed record")
        status = ACKNOWLEDGED
    elif act == REOPEN:
        status = OPEN
        entry["from"] = current
    elif act == RESOLVE:
        kind = _clean(resolution).upper()
        if kind not in _RESOLVE_KINDS:
            raise ValueError(f"unknown resolution {resolution!r}; expected "
                             f"one of {', '.join(_RESOLVE_KINDS)}")
        if not _clean(note):
            raise ValueError("a resolution carries its note: an unexplained "
                             "resolution is an unexplained claim")
        if kind == "CONFIRMED_INCIDENT":
            ids = [str(e) for e in evidence_ids if _clean(e)]
            if not ids:
                raise ValueError(
                    "CONFIRMED_INCIDENT is the only resolution that names a "
                    "compromise, and it demands evidence: a named actor "
                    "supplies evidence, the engine never declares a "
                    "compromise")
            entry["evidence_ids"] = ids
        entry["resolution"] = kind
        status = RESOLVED
    else:
        raise ValueError(f"unknown action {action!r}; expected one of "
                         f"{', '.join((ACKNOWLEDGE, RESOLVE, REOPEN))}")
    entry["resulting_status"] = status
    history.append(entry)
    updated["lifecycle"] = {"status": status, "history": history}
    return updated
